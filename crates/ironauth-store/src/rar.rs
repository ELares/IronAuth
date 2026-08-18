// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rich authorization requests (RFC 9396): validating an `authorization_details` document
//! against the types a deployment has actually registered (issue #131 criterion 4).
//!
//! # Why unknown types are refused rather than passed through
//!
//! `authorization_details` is a client-supplied document that ends up in an issued token and
//! is echoed back by introspection. A resource server reads it to decide what the token
//! permits. So an unrecognized type is not a harmless extra field: it is an authorization
//! statement nobody in this deployment has defined the meaning of, travelling inside a
//! credential that resource servers trust.
//!
//! Two resource servers can also disagree about an unregistered type -- one ignoring it, one
//! honouring it -- and the issuer has said nothing either way. Refusing by default makes the
//! issuer's silence explicit instead of leaving each reader to guess.
//!
//! The registry is per-deployment configuration rather than a fixed list, because RAR types
//! are domain vocabulary (`payment_initiation`, `account_information`) that only the
//! deployment knows.
//!
//! # What this module does NOT check
//!
//! Whether the client is ENTITLED to what it asks for. That is an authorization decision made
//! against the client's registration and the user's consent, not a shape check. This module
//! establishes only that the document is well formed and speaks a vocabulary the deployment
//! has defined; a well-formed request for something the client may not have is still refused
//! later, and refusing it here would put the same rule in two places.

use serde_json::Value;

/// The most `authorization_details` entries a single request may carry.
///
/// A bound is needed because the document is client-supplied and lands in a token: without
/// one, a client can inflate every token it is issued until the token stops fitting wherever
/// tokens have to fit. 16 is far above any real request and far below a problem.
pub const MAX_AUTHORIZATION_DETAILS: usize = 16;

/// Why an `authorization_details` document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RarError {
    /// The document is not a JSON array. RFC 9396 section 2 requires one.
    NotAnArray,
    /// An entry is not a JSON object.
    EntryNotAnObject {
        /// Which entry, so a client can find it.
        index: usize,
    },
    /// An entry has no `type`, or its `type` is not a string. RFC 9396 makes it mandatory.
    MissingType {
        /// Which entry.
        index: usize,
    },
    /// The entry's `type` is not one this deployment has registered.
    UnknownType {
        /// Which entry.
        index: usize,
        /// The offending type, echoed back so the client learns WHICH one is unknown.
        /// Safe to echo: the client supplied it, so it reveals nothing the client did not
        /// already know, and withholding it would make the error unactionable.
        found: String,
    },
    /// More entries than [`MAX_AUTHORIZATION_DETAILS`].
    TooManyEntries {
        /// How many arrived.
        count: usize,
    },
}

/// Validate an `authorization_details` document against the registered types.
///
/// `registered` is the deployment's vocabulary. An EMPTY registry refuses every entry, which
/// is the correct default rather than an awkward edge case: a deployment that has defined no
/// RAR types has, by definition, defined the meaning of none of them, and the alternative
/// (an empty registry meaning "allow anything") would make the safe configuration the one
/// nobody types.
///
/// A `None` document is valid and yields nothing to check -- RAR is optional.
///
/// # Errors
///
/// [`RarError`] describing the first problem found, with the index so a client can act on it.
pub fn validate_authorization_details(
    document: Option<&Value>,
    registered: &[&str],
) -> Result<(), RarError> {
    let Some(document) = document else {
        return Ok(());
    };
    let Some(entries) = document.as_array() else {
        return Err(RarError::NotAnArray);
    };
    if entries.len() > MAX_AUTHORIZATION_DETAILS {
        return Err(RarError::TooManyEntries {
            count: entries.len(),
        });
    }
    for (index, entry) in entries.iter().enumerate() {
        let Some(object) = entry.as_object() else {
            return Err(RarError::EntryNotAnObject { index });
        };
        let Some(kind) = object.get("type").and_then(Value::as_str) else {
            return Err(RarError::MissingType { index });
        };
        if !registered.contains(&kind) {
            return Err(RarError::UnknownType {
                index,
                found: kind.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const REGISTERED: &[&str] = &["payment_initiation", "account_information"];

    /// A registered document passes, and an absent one is not an error.
    ///
    /// The positive control. Every refusal below is meaningless without it, since a validator
    /// that refused everything would otherwise pass the whole file.
    #[test]
    fn a_registered_document_is_accepted_and_an_absent_one_is_fine() {
        let document = json!([
            {"type": "payment_initiation", "actions": ["initiate"]},
            {"type": "account_information"},
        ]);
        assert_eq!(
            validate_authorization_details(Some(&document), REGISTERED),
            Ok(())
        );
        assert_eq!(validate_authorization_details(None, REGISTERED), Ok(()));
        // An empty array is a well-formed document that asks for nothing.
        assert_eq!(
            validate_authorization_details(Some(&json!([])), REGISTERED),
            Ok(())
        );
    }

    /// An unknown type is refused, and the error names WHICH one (#131 criterion 4).
    ///
    /// Naming it matters. A client told "one of your entries is unknown"
    /// against a five-entry document has to guess; and the value is its own, so echoing it
    /// reveals nothing it did not send.
    #[test]
    fn an_unknown_type_is_refused_by_default_and_is_named() {
        let document = json!([
            {"type": "payment_initiation"},
            {"type": "drain_the_account"},
        ]);
        assert_eq!(
            validate_authorization_details(Some(&document), REGISTERED),
            Err(RarError::UnknownType {
                index: 1,
                found: "drain_the_account".to_owned()
            })
        );
    }

    /// An EMPTY registry refuses everything.
    ///
    /// This is the default-deny property stated directly. A deployment that has registered no
    /// RAR types has defined the meaning of none, so it must accept none -- and the opposite
    /// reading, where an empty registry allows anything, would make the safe configuration
    /// the one an operator has to remember to type.
    #[test]
    fn an_empty_registry_refuses_every_type() {
        let document = json!([{"type": "payment_initiation"}]);
        assert_eq!(
            validate_authorization_details(Some(&document), &[]),
            Err(RarError::UnknownType {
                index: 0,
                found: "payment_initiation".to_owned()
            })
        );
        // ...but an empty DOCUMENT still passes: it asks for nothing, so there is nothing to
        // refuse. The distinction is what stops default-deny from breaking RAR-less clients.
        assert_eq!(
            validate_authorization_details(Some(&json!([])), &[]),
            Ok(())
        );
    }

    /// Every structural malformation is refused, with its index.
    #[test]
    fn structural_malformations_are_refused_with_their_index() {
        assert_eq!(
            validate_authorization_details(
                Some(&json!({"type": "payment_initiation"})),
                REGISTERED
            ),
            Err(RarError::NotAnArray),
            "an object is not a document: RFC 9396 requires an array"
        );
        assert_eq!(
            validate_authorization_details(Some(&json!(["payment_initiation"])), REGISTERED),
            Err(RarError::EntryNotAnObject { index: 0 }),
            "a bare string is not an entry"
        );
        assert_eq!(
            validate_authorization_details(Some(&json!([{"actions": ["initiate"]}])), REGISTERED),
            Err(RarError::MissingType { index: 0 }),
            "type is mandatory"
        );
        assert_eq!(
            validate_authorization_details(Some(&json!([{"type": 7}])), REGISTERED),
            Err(RarError::MissingType { index: 0 }),
            "a non-string type is the same defect as an absent one"
        );
    }

    /// The entry count is bounded, at exactly the documented limit.
    ///
    /// Both sides of the boundary, because an off-by-one here either rejects a legitimate
    /// request or leaves the bound one larger than it says it is.
    #[test]
    fn the_entry_count_is_bounded_exactly_at_the_documented_limit() {
        let at_limit: Vec<Value> = (0..MAX_AUTHORIZATION_DETAILS)
            .map(|_| json!({"type": "payment_initiation"}))
            .collect();
        assert_eq!(
            validate_authorization_details(Some(&json!(at_limit)), REGISTERED),
            Ok(()),
            "exactly the limit must be accepted"
        );

        let over: Vec<Value> = (0..=MAX_AUTHORIZATION_DETAILS)
            .map(|_| json!({"type": "payment_initiation"}))
            .collect();
        assert_eq!(
            validate_authorization_details(Some(&json!(over)), REGISTERED),
            Err(RarError::TooManyEntries {
                count: MAX_AUTHORIZATION_DETAILS + 1
            }),
            "one over the limit must be refused"
        );
    }

    /// The count bound is checked BEFORE the per-entry walk.
    ///
    /// Otherwise a client could send ten thousand entries and have the server validate every
    /// one of them before deciding there were too many, which turns the bound into a cost
    /// rather than a protection.
    #[test]
    fn an_oversized_document_is_refused_before_its_entries_are_examined() {
        // Every entry is ALSO malformed. If the walk ran first, the answer would name the
        // malformation; the count must win.
        let over: Vec<Value> = (0..=MAX_AUTHORIZATION_DETAILS)
            .map(|_| json!("nope"))
            .collect();
        assert_eq!(
            validate_authorization_details(Some(&json!(over)), REGISTERED),
            Err(RarError::TooManyEntries {
                count: MAX_AUTHORIZATION_DETAILS + 1
            })
        );
    }
}
