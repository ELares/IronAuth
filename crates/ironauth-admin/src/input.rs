// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small request-body validation helpers shared by the resource handlers.

use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// Parse a JSON request body, mapping any decode failure to a 400.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if the body is not valid JSON for `T`.
pub fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body)
        .map_err(|error| ApiError::BadRequest(format!("invalid JSON body: {error}")))
}

/// Require a non-empty, non-whitespace display value, mapping absence to a 400.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if `value` is empty or only whitespace.
pub fn require_non_empty(value: &str, field: &str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} must not be empty")));
    }
    Ok(trimmed.to_owned())
}

/// The longest slug the `org_roles_slug_valid` and `org_groups_slug_valid` CHECK
/// constraints accept: one leading character plus up to 62 more.
const SLUG_MAX_LEN: usize = 63;

/// Require a stable-name slug matching the schema's `^[a-z0-9][a-z0-9._-]{0,62}$`
/// CHECK (issue #97), mapping any violation to a 400.
///
/// This is the MANAGEMENT EDGE the store's `NewOrgRole::slug` and
/// `NewOrgGroup::slug` doc comments delegate to. The CHECK constraint is the real
/// guarantee, but a value that reaches it and is refused surfaces as an opaque
/// database error, so validating here is what turns "that slug is not allowed"
/// into a caller-facing message naming the field and the rule.
///
/// The slug is NOT trimmed and NOT case folded, unlike a display name: it is the
/// immutable name a later authorization decision keys on, so accepting `"Admin "`
/// and silently storing `"admin"` would make two visibly different requests
/// collide on the uniqueness index. A value that is not already canonical is
/// refused instead.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if `value` is empty, longer than 63 characters, or
/// contains a character outside the allowed set (or leads with `.`, `-`, or `_`).
pub fn require_slug(value: &str, field: &str) -> Result<String, ApiError> {
    let bad = || {
        ApiError::BadRequest(format!(
            "{field} must be 1 to {SLUG_MAX_LEN} characters matching \
             ^[a-z0-9][a-z0-9._-]{{0,62}}$ (lowercase, no leading punctuation)"
        ))
    };
    if value.is_empty() || value.len() > SLUG_MAX_LEN {
        return Err(bad());
    }
    let mut chars = value.chars();
    let first = chars.next().ok_or_else(bad)?;
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(bad());
    }
    for ch in chars {
        let allowed =
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_' || ch == '-';
        if !allowed {
            return Err(bad());
        }
    }
    Ok(value.to_owned())
}

/// The longest permission slug the `permissions_slug_valid` CHECK accepts. Equal to
/// [`SLUG_MAX_LEN`] because the permission grammar is a STRICT SUBSET of the role and
/// group charset, which is the property that keeps this repository on ONE slug
/// alphabet: every valid permission slug is also a valid role slug, so nothing about
/// migrations 0086 and 0087 changes.
const PERMISSION_SLUG_MAX_LEN: usize = SLUG_MAX_LEN;

/// The fewest segments a permission slug may carry. A permission is NAMESPACED BY
/// CONSTRUCTION rather than by convention, which is one of the three structural
/// refusals this grammar adds on top of the role charset (the other two are a
/// leading or trailing `.` and a doubled `..`).
const PERMISSION_SLUG_MIN_SEGMENTS: usize = 2;

/// Require a namespaced permission slug matching the schema's
/// `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$` CHECK, plus the 63-character
/// bound, mapping any violation to a 400 (issue #98).
///
/// This is the MANAGEMENT EDGE half of the grammar. Migration 0091's
/// `permissions_slug_valid` CHECK is the real guarantee, but a value that reaches it
/// and is refused surfaces as an opaque database error, so validating here is what
/// turns "that permission name is not allowed" into a caller-facing message naming
/// the field and the rule. The two halves are pinned equal, case by case over a
/// seeded corpus, by `crates/ironauth-admin/tests/permission_slug_parity.rs`; that
/// test is the only thing in the tree that would catch them drifting.
///
/// A SEPARATE function rather than a widened [`require_slug`], for a reason about
/// messages rather than about code: `require_slug` names the flat role charset in
/// prose, and one function serving both grammars would produce a message that is
/// wrong for one of its callers.
///
/// The grammar is a strict SUBSET of the role and group charset
/// (`^[a-z0-9][a-z0-9._-]{0,62}$`), so it inherits that charset's exclusions for
/// free: `:` `/` `,` `@` `+` `~` `#` `?`, whitespace, uppercase, and every non-ASCII
/// byte are refused. That is what makes a permission set safe to join on any of
/// those characters, which is what an OAuth `scope` string does with a space. It ADDS
/// three refusals the role charset permits: a leading or trailing `.`, a doubled
/// `..`, and a single-segment slug.
///
/// Like [`require_slug`] the value is NOT trimmed and NOT case folded: it is the
/// immutable name a later authorization decision keys on and that a token claim
/// carries, so accepting `"Billing.Read "` and silently storing `"billing.read"`
/// would make two visibly different requests collide. Acceptance therefore implies
/// BYTE IDENTITY, which the fuzz target asserts directly.
///
/// # Errors
///
/// [`ApiError::BadRequest`] if `value` is empty, longer than 63 characters, carries
/// fewer than two dot-separated segments, has an empty segment (a leading dot, a
/// trailing dot, or a doubled dot), or contains a character outside the allowed set.
pub fn require_permission_slug(value: &str, field: &str) -> Result<String, ApiError> {
    let bad = || {
        ApiError::BadRequest(format!(
            "{field} must be 1 to {PERMISSION_SLUG_MAX_LEN} characters matching \
             ^[a-z0-9][a-z0-9_-]*(\\.[a-z0-9][a-z0-9_-]*)+$ ({PERMISSION_SLUG_MIN_SEGMENTS} \
             or more dot-separated segments, lowercase, no empty segment, no leading \
             punctuation in a segment)"
        ))
    };
    if value.is_empty() || value.len() > PERMISSION_SLUG_MAX_LEN {
        return Err(bad());
    }
    let mut segments = 0_usize;
    // Splitting on the delimiter is what makes the three structural refusals fall
    // out: a leading dot, a trailing dot, and a doubled dot each yield an EMPTY
    // segment, and a slug with no dot at all yields exactly one segment.
    for segment in value.split('.') {
        segments += 1;
        let mut chars = segment.chars();
        let Some(first) = chars.next() else {
            return Err(bad());
        };
        if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
            return Err(bad());
        }
        for ch in chars {
            let allowed = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-';
            if !allowed {
                return Err(bad());
            }
        }
    }
    if segments < PERMISSION_SLUG_MIN_SEGMENTS {
        return Err(bad());
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{ApiError, require_permission_slug, require_slug};

    #[test]
    fn a_slug_matching_the_check_constraint_is_accepted_verbatim() {
        let at_the_bound = "x".repeat(63);
        for raw in ["admin", "a", "0", "team.eu-west_1", &at_the_bound] {
            assert_eq!(
                require_slug(raw, "slug").expect("valid slug"),
                raw,
                "{raw:?} must be accepted unchanged"
            );
        }
    }

    #[test]
    fn a_slug_the_check_constraint_would_refuse_is_a_bad_request() {
        // Each of these is refused by `^[a-z0-9][a-z0-9._-]{0,62}$`. Letting one
        // through would trade a caller-facing 400 for an opaque 500 from the CHECK.
        let one_over_the_bound = "x".repeat(64);
        for raw in [
            "",               // empty
            "Admin",          // uppercase
            ".leading",       // leading punctuation
            "-leading",       //
            "_leading",       //
            "has space",      //
            "has/slash",      //
            "emoji\u{1F600}", // non-ASCII
            " admin",         // an untrimmed value is refused, never silently trimmed
            "admin ",         //
            &one_over_the_bound,
        ] {
            assert!(
                matches!(require_slug(raw, "slug"), Err(ApiError::BadRequest(_))),
                "{raw:?} must be a structured bad request"
            );
        }
    }

    #[test]
    fn a_namespaced_permission_slug_is_accepted_verbatim() {
        // 63 characters exactly, and namespaced: the accepted value AT the bound.
        let at_the_bound = format!("a.{}", "x".repeat(61));
        assert_eq!(at_the_bound.len(), 63);
        for raw in [
            "billing.invoice.read",
            "a.b",
            "0.9",
            "feature.sso",
            "plan.enterprise",
            "billing.invoice_export",
            "team-eu.west-1.read",
            &at_the_bound,
        ] {
            assert_eq!(
                require_permission_slug(raw, "slug").expect("valid permission slug"),
                raw,
                "{raw:?} must be accepted unchanged"
            );
        }
    }

    #[test]
    fn a_permission_slug_the_check_constraint_would_refuse_is_a_bad_request() {
        // Each of these is refused by
        // `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$` or by the 63-character
        // bound. Letting one through would trade a caller-facing 400 for an opaque
        // 500 from the CHECK.
        let one_over_the_bound = format!("a.{}", "x".repeat(62));
        assert_eq!(one_over_the_bound.len(), 64);
        for raw in [
            "",                     // empty
            "billing",              // SINGLE segment: namespacing is structural
            ".leading",             // leading dot
            "trailing.",            // trailing dot
            "double..dot",          // doubled dot
            ".",                    // both, and no real segment
            "Billing.Read",         // uppercase at a segment HEAD
            "billing.reaD",         // uppercase in a segment TAIL, which the head
            "billinG.read",         // rule alone does NOT refuse: the two positions
            "a.bC",                 // are separate rules and need separate cases
            "read:orders",          // the Auth0 spelling: `:` is not the delimiter
            "billing.invoice/read", // slash
            "billing,invoice",      // comma
            "has space.read",       // whitespace
            "billing.read\n",       // a trailing newline is not a delimiter either
            "billing._leading",     // a segment may not lead with punctuation
            "billing.-leading",     //
            "-leading.read",        //
            "emoji.\u{1F600}",      // non-ASCII
            " billing.read",        // an untrimmed value is refused, never trimmed
            "billing.read ",        //
            &one_over_the_bound,
        ] {
            assert!(
                matches!(
                    require_permission_slug(raw, "slug"),
                    Err(ApiError::BadRequest(_))
                ),
                "{raw:?} must be a structured bad request"
            );
        }
    }

    #[test]
    fn every_accepted_permission_slug_is_also_a_valid_role_slug() {
        // The property the whole grammar choice rests on: the permission charset is
        // a STRICT SUBSET of the shipped role and group charset, which is why
        // migrations 0086 and 0087 need no change and why the tree carries one slug
        // alphabet rather than two. If this ever fails, a permission slug has become
        // unwritable as a role slug and the "no breaking change" claim is false.
        for raw in [
            "billing.invoice.read",
            "a.b",
            "0.9",
            "feature.sso",
            "plan.enterprise",
            "billing.invoice_export",
            "team-eu.west-1.read",
        ] {
            assert!(
                require_permission_slug(raw, "slug").is_ok(),
                "{raw:?} is a permission slug"
            );
            assert!(
                require_slug(raw, "slug").is_ok(),
                "{raw:?} is accepted as a permission slug but refused as a role slug; \
                 the permission grammar must stay a strict subset"
            );
        }
        // STRICT: the role charset accepts values this one refuses, so the two are
        // not the same grammar wearing two names. These are exactly the three
        // structural refusals the permission grammar ADDS (a single segment, a
        // trailing dot, and a doubled dot). A LEADING dot is absent from this list
        // on purpose: the role charset already refuses it, because both grammars
        // require the first character to be alphanumeric.
        for raw in ["billing", "trailing.", "double..dot"] {
            assert!(
                require_slug(raw, "slug").is_ok(),
                "{raw:?} is a valid role slug"
            );
            assert!(
                require_permission_slug(raw, "slug").is_err(),
                "{raw:?} must be refused as a permission slug"
            );
        }
    }

    #[test]
    fn the_permission_slug_message_names_the_field_and_the_rule() {
        // The whole reason this validator exists ahead of the CHECK is the message.
        let Err(ApiError::BadRequest(message)) = require_permission_slug("Nope", "permission_slug")
        else {
            panic!("an invalid slug must be a structured bad request");
        };
        assert!(
            message.contains("permission_slug"),
            "the message must name the offending field: {message}"
        );
        assert!(
            message.contains("63"),
            "the message must state the length bound: {message}"
        );
        assert!(
            message.contains("dot-separated"),
            "the message must state the namespacing rule: {message}"
        );
    }
}
