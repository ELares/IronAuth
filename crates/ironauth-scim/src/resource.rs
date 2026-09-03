// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mapping a SCIM user resource onto IronAuth's identity model (issue #135, criterion 6).
//!
//! The criterion is that a SCIM-created identifier is canonicalized IDENTICALLY to an
//! admin-API-created one, and that duplicate detection proves it. Two provisioning systems
//! writing the same person through different doors must collide, or an operator ends up with
//! two accounts for one human and no way to tell which is real.
//!
//! "Identically" is made structural rather than promised, the same way the filter's is.
//! [`ScimUser::canonical_identifier`] returns a [`CanonicalIdentifier`], which
//! `ironauth-store` documents as producible ONLY by `canonicalize_identifier`. This module
//! therefore cannot invent its own normalization even by accident: to return the type at all
//! it has to call the one function, so "the same rules" is a fact about the call graph rather
//! than a claim in a comment that a later edit could quietly falsify.

use ironauth_store::identifier::{CanonicalIdentifier, IdentifierType, canonicalize_identifier};
use serde::Deserialize;

use crate::schema::ENTERPRISE_USER_SCHEMA;

/// A SCIM 2.0 core user resource, as far as identity mapping reads it.
#[derive(Debug, Clone, Deserialize)]
pub struct ScimUser {
    /// The SCIM `userName`: the login handle.
    #[serde(rename = "userName")]
    pub user_name: String,
    /// The provisioning system's own identifier for this person.
    #[serde(rename = "externalId", default)]
    pub external_id: Option<String>,
    /// Whether the account is enabled.
    #[serde(default = "default_active")]
    pub active: bool,
    /// The Enterprise User extension attributes (RFC 7643 section 4.3), as sent.
    ///
    /// KEYED BY THE URN, which is how SCIM carries an extension: the attributes arrive under
    /// `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`, not at the top level.
    ///
    /// This surface PUBLISHED that extension in `/Schemas` from the day it shipped and parsed
    /// none of it, so an Entra push carrying `employeeNumber` and `department` was answered
    /// `201 Created` with the attributes silently dropped -- the advertise-what-you-do-not-do
    /// defect this crate has now been caught by twice.
    ///
    /// Held as a raw map rather than a struct of the three attributes RFC 7643 names. A struct
    /// would silently drop a fourth, and [`ScimUser::enterprise_traits`] is where the set this
    /// server stores is decided, in one place, rather than by what a type happened to declare.
    /// CASE-INSENSITIVE on the URN, which a serde `rename` is not. RFC 7643 section 2.1 makes
    /// attribute names case-insensitive and the URN is how the extension is named; both PATCH
    /// doors already compared it that way, and a review measured the third door disagreeing:
    /// a create carrying `...enterprise:2.0:user` -- only the final `User` lower-cased --
    /// answered 201 with the extension SILENTLY DROPPED. That is the advertise-then-drop shape
    /// this whole change closes, reintroduced one level up at the URN.
    ///
    /// Captured as a flattened map of everything the resource carries, and resolved by
    /// [`ScimUser::enterprise_traits`], because serde has no case-insensitive `rename`.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_active() -> bool {
    true
}

/// Whether a value matches the type `/Schemas` publishes for an Enterprise User attribute.
///
/// `manager` is the one complex attribute (RFC 7643 section 4.3); the other six are strings.
/// Paired with the published document by `the_enterprise_schema_and_the_model_agree_on_types`,
/// so a document that changed a type without this changing fails rather than drifting.
///
/// A `null` is not type-checked by callers: it means REMOVE on this surface, not a value.
#[must_use]
pub fn enterprise_type_matches(lowered: &str, value: &serde_json::Value) -> bool {
    if lowered == "manager" {
        value.is_object()
    } else {
        value.is_string()
    }
}

/// The canonical SCIM spelling of an Enterprise User attribute, from its lower-cased form.
///
/// PAIRED WITH [`ENTERPRISE_ATTRIBUTES`] by `the_canonical_spelling_covers_every_attribute`,
/// not by inspection. This was a `match` ending in a catch-all, and a review measured what that
/// buys: an eighth attribute added to the list would have been silently stored as
/// `employeeType`. It returns `None` for anything unlisted now, and the caller has already
/// refused those.
#[must_use]
pub fn canonical_enterprise_name(lowered: &str) -> &'static str {
    match lowered {
        "employeenumber" => "employeeNumber",
        "costcenter" => "costCenter",
        "organization" => "organization",
        "division" => "division",
        "department" => "department",
        "manager" => "manager",
        "employeetype" => "employeeType",
        // UNREACHABLE by construction: every caller checks `ENTERPRISE_ATTRIBUTES` first, and
        // the pairing test drives every entry. Returning the input's own meaning is wrong for a
        // name nothing recognises, so this refuses to invent one.
        other => {
            debug_assert!(false, "unlisted enterprise attribute: {other}");
            ""
        }
    }
}

/// The Enterprise User attributes this server stores, lower-cased for matching.
///
/// EXACTLY RFC 7643 section 4.3's list, and a closed one. An extension attribute this server
/// does not store must be REFUSED rather than accepted and dropped, because a provisioning
/// client that reads `201` has been told the value round-trips.
pub const ENTERPRISE_ATTRIBUTES: [&str; 7] = [
    "employeenumber",
    "costcenter",
    "organization",
    "division",
    "department",
    "manager",
    "employeetype",
];

impl ScimUser {
    /// The canonical identifier this resource maps to.
    ///
    /// The TYPE is chosen by shape, not asserted by the caller: a `userName` containing an
    /// `@` is an email and folds its domain too, and anything else is a username. SCIM does
    /// not carry an identifier type, so a mapping that guessed wrong here would canonicalize
    /// one person's handle two different ways depending on which door they arrived through,
    /// which is the exact failure criterion 6 names.
    ///
    /// Deliberately NOT a phone: SCIM carries phone numbers in `phoneNumbers`, never in
    /// `userName`, so treating a numeric handle as one would fold a legitimate username into
    /// E.164 and lose it.
    #[must_use]
    pub fn canonical_identifier(&self) -> CanonicalIdentifier {
        let kind = if self.user_name.contains('@') {
            IdentifierType::Email
        } else {
            IdentifierType::Username
        };
        canonicalize_identifier(kind, &self.user_name)
    }

    /// The Enterprise User extension object this resource carries, found case-insensitively.
    ///
    /// One place that knows how the URN is matched, so the create door and the two PATCH doors
    /// cannot disagree about it again.
    #[must_use]
    pub fn enterprise(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        self.extra
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(ENTERPRISE_USER_SCHEMA))
            .and_then(|(_, value)| value.as_object())
    }

    /// The extension attributes to store, with their SCIM names preserved.
    ///
    /// Returns `Err` naming the first attribute this server does not store. Refusing rather
    /// than dropping is the whole point: `/Schemas` publishes what the extension carries, and a
    /// client that sends an attribute and gets a 201 is entitled to read it back.
    ///
    /// # Errors
    ///
    /// The offending attribute name, when the extension carries one outside
    /// [`ENTERPRISE_ATTRIBUTES`].
    #[allow(
        clippy::missing_errors_doc,
        reason = "the Errors section is immediately above"
    )]
    pub fn enterprise_traits(&self) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        let Some(extension) = self.enterprise() else {
            return Ok(serde_json::Map::new());
        };
        let mut traits = serde_json::Map::new();
        for (name, value) in extension {
            let lowered = name.to_ascii_lowercase();
            if !ENTERPRISE_ATTRIBUTES.contains(&lowered.as_str()) {
                return Err(name.clone());
            }
            // AND THE TYPE THE DOCUMENT PUBLISHES. `/Schemas` says `employeeNumber` is a
            // string and `manager` is complex; a review measured
            // `{"employeeNumber":{"nested":[]},"department":42,"manager":"a bare string"}`
            // answering 201 and round-tripping verbatim. Refusing an unknown attribute NAME and
            // accepting any VALUE is the advertise-what-you-do-not-do shape this crate has been
            // caught by twice already, one level down.
            if !value.is_null() && !enterprise_type_matches(&lowered, value) {
                return Err(name.clone());
            }
            // THE CANONICAL SPELLING, not the caller's. SCIM matches attribute names
            // case-insensitively (RFC 7643 section 2.1) and this is stored as a JSON key, where
            // the match is exact. Inserting `name.clone()` is what an earlier revision did, and
            // a review measured the result: a create sending `EMPLOYEENUMBER` and a later PATCH
            // sending `employeeNumber` produced BOTH keys in one document. The PATCH path
            // canonicalized and the create path did not, which is the two-spellings defect the
            // path parser next door refuses whole paths for.
            traits.insert(
                canonical_enterprise_name(&lowered).to_owned(),
                value.clone(),
            );
        }
        Ok(traits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scim(user_name: &str) -> ScimUser {
        ScimUser {
            extra: serde_json::Map::new(),
            user_name: user_name.to_owned(),
            external_id: None,
            active: true,
        }
    }

    #[test]
    fn a_scim_user_name_canonicalizes_exactly_as_the_admin_api_path_does() {
        // The criterion, asserted directly: the SCIM mapping and a direct call to the shared
        // canonicalizer agree. They cannot disagree by construction, because the mapping HAS
        // to call it to return the type, and this pins the type choice as well.
        for handle in [
            "Alice@Example.COM",
            "alice",
            "ALICE",
            "ad min",
            "Ada.Lovelace@Example.test",
        ] {
            let kind = if handle.contains('@') {
                IdentifierType::Email
            } else {
                IdentifierType::Username
            };
            assert_eq!(
                scim(handle).canonical_identifier(),
                canonicalize_identifier(kind, handle),
                "{handle}"
            );
        }
    }

    #[test]
    fn duplicate_detection_proves_it_for_the_cases_two_doors_actually_differ_on() {
        // What a provisioning system sends and what an operator types differ in exactly these
        // ways: case, surrounding and interior whitespace, and Unicode form. Each pair is ONE
        // person, and a mapping that canonicalized differently would create two accounts.
        let pairs = [
            ("Alice@Example.COM", "alice@example.com"),
            ("  alice  ", "alice"),
            ("ad min", "admin"),
            // NFKC: the fullwidth form a directory export can carry folds onto ASCII.
            ("\u{ff21}LICE", "alice"),
            // A zero-width joiner is invisible and must not make a second account.
            ("ali\u{200d}ce", "alice"),
        ];
        for (left, right) in pairs {
            assert_eq!(
                scim(left).canonical_identifier(),
                scim(right).canonical_identifier(),
                "{left:?} and {right:?} are one person"
            );
        }
    }

    #[test]
    fn genuinely_different_handles_stay_different() {
        // The control. Without it the test above passes on a canonicalizer that mapped
        // everything to the empty string, which would collide every account in the tenant
        // into one and satisfy "duplicate detection" perfectly.
        let distinct = ["alice", "bob", "alice@example.com", "alice@example.test"];
        for (index, left) in distinct.iter().enumerate() {
            for right in &distinct[index + 1..] {
                assert_ne!(
                    scim(left).canonical_identifier(),
                    scim(right).canonical_identifier(),
                    "{left:?} and {right:?} are different people"
                );
            }
        }
    }

    #[test]
    fn an_absent_active_defaults_to_enabled() {
        // SCIM omits `active` for an enabled user, and a mapping that defaulted it to false
        // would deactivate every account a provisioning system created.
        let parsed: ScimUser =
            serde_json::from_str(r#"{"userName":"alice"}"#).expect("a minimal resource");
        assert!(parsed.active);
    }

    /// Every attribute the model accepts has a canonical spelling, and no other does.
    ///
    /// `canonical_enterprise_name` was a `match` ending in a catch-all returning
    /// `"employeeType"`, so an eighth entry added to [`ENTERPRISE_ATTRIBUTES`] would have been
    /// stored under the wrong name -- silently, because nothing paired the two. A review
    /// measured it: rewriting the `costcenter` arm left the whole suite green.
    ///
    /// Both directions. Every listed attribute maps to a distinct non-empty name, so a missing
    /// arm fails; and the mapping is one-to-one, so two attributes sharing a spelling fails too.
    /// Every attribute's canonical spelling is the EXACT one RFC 7643 section 4.3 gives.
    ///
    /// `the_canonical_spelling_covers_every_attribute_exactly_once` asserts only that the
    /// canonical form lower-cases back to the input, which ANY casing satisfies, and the
    /// schema-pairing test lower-cases both sides -- so a review measured
    /// `"manager" => "MANAGER"` surviving the whole crate. The spelling is the one thing
    /// `canonical_enterprise_name` exists to hold, and nothing held it.
    #[test]
    fn the_canonical_spelling_is_the_exact_rfc_7643_one() {
        for (lowered, expected) in [
            ("employeenumber", "employeeNumber"),
            ("costcenter", "costCenter"),
            ("organization", "organization"),
            ("division", "division"),
            ("department", "department"),
            ("manager", "manager"),
            ("employeetype", "employeeType"),
        ] {
            assert_eq!(
                canonical_enterprise_name(lowered),
                expected,
                "{lowered} must be stored under the exact spelling RFC 7643 section 4.3 gives, \
                 because a provisioning client reads the key back"
            );
        }
    }

    /// The model's type rule and the published document agree, attribute by attribute.
    ///
    /// `enterprise_type_matches` is a hand-written rule and `core_schemas` is a hand-written
    /// document; either can move without the other. A `manager` published as a string, or an
    /// `employeeNumber` accepted as an object, is the advertise-what-you-do-not-do shape one
    /// level down from the one this extension already closed.
    #[test]
    fn the_enterprise_schema_and_the_model_agree_on_types() {
        let published = crate::schema::core_schemas()
            .into_iter()
            .find(|schema| schema["id"] == crate::schema::ENTERPRISE_USER_SCHEMA)
            .expect("the enterprise schema is published");
        for attribute in published["attributes"].as_array().expect("attributes") {
            let name = attribute["name"]
                .as_str()
                .expect("a name")
                .to_ascii_lowercase();
            let kind = attribute["type"].as_str().expect("a type");
            let object = serde_json::json!({ "sub": "value" });
            let string = serde_json::json!("value");
            match kind {
                "string" => {
                    assert!(
                        enterprise_type_matches(&name, &string),
                        "{name} is published as a string and the model refuses one"
                    );
                    assert!(
                        !enterprise_type_matches(&name, &object),
                        "{name} is published as a string and the model accepts an object"
                    );
                }
                "complex" => {
                    assert!(
                        enterprise_type_matches(&name, &object),
                        "{name} is published as complex and the model refuses an object"
                    );
                    assert!(
                        !enterprise_type_matches(&name, &string),
                        "{name} is published as complex and the model accepts a string"
                    );
                }
                other => panic!("{name} publishes an unhandled type {other}"),
            }
        }
    }

    #[test]
    fn the_canonical_spelling_covers_every_attribute_exactly_once() {
        let mut spellings: Vec<&str> = ENTERPRISE_ATTRIBUTES
            .iter()
            .map(|lowered| {
                let canonical = canonical_enterprise_name(lowered);
                assert!(
                    !canonical.is_empty(),
                    "{lowered} has no canonical spelling, so it would be stored under an \
                     empty key"
                );
                assert_eq!(
                    canonical.to_ascii_lowercase(),
                    *lowered,
                    "{lowered}'s canonical spelling must be the same attribute"
                );
                canonical
            })
            .collect();
        spellings.sort_unstable();
        let before = spellings.len();
        spellings.dedup();
        assert_eq!(
            spellings.len(),
            before,
            "two attributes share a canonical spelling, so one would overwrite the other"
        );
    }
}
