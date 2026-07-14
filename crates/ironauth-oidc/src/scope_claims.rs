// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scope-to-claims mapping (OIDC Core 5.4) and the ONE shared claim-release
//! function every surface uses.
//!
//! A scope value maps to a fixed set of standard claim NAMES: `profile`, `email`,
//! `address`, and `phone` each stand for the Core 5.4 claim set. Requesting a
//! scope requests that its claim set be released. The `openid` scope carries no
//! claim set of its own (its subject is `sub`, which is always present and is
//! derived, never released from stored data).
//!
//! The VALUES come from the user's stored standard-claim document (issue #15's
//! `users.claims`). A claim is released only when the user actually has it: a
//! member the scope maps to but the user lacks is simply omitted (an unsatisfiable
//! voluntary claim is never an error, per Core 5.5).
//!
//! # One release function, two placements
//!
//! [`assemble_claims`] is the single place a scope set plus a `claims`-request
//! member turns into a released claim object. The `UserInfo` endpoint calls it with
//! the `userinfo` member; the (non-conform) `conformIdTokenClaims` override calls
//! it with the `id_token` member. So the two placements share ONE derivation and
//! cannot drift: the same inputs always yield the same released set, wherever it
//! is placed.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::claims_request::ClaimSpec;

/// The `profile` scope's claim set (OIDC Core 5.4).
pub const PROFILE_CLAIMS: &[&str] = &[
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
];

/// The `email` scope's claim set (OIDC Core 5.4).
pub const EMAIL_CLAIMS: &[&str] = &["email", "email_verified"];

/// The `address` scope's claim set (OIDC Core 5.4). `address` is a single JSON
/// object claim.
pub const ADDRESS_CLAIMS: &[&str] = &["address"];

/// The `phone` scope's claim set (OIDC Core 5.4).
pub const PHONE_CLAIMS: &[&str] = &["phone_number", "phone_number_verified"];

/// The standard claim set a single scope value maps to (OIDC Core 5.4). Every
/// scope other than the four claim-bearing ones (including `openid` and any
/// unknown scope) maps to no claims.
#[must_use]
pub fn claims_for_scope(scope: &str) -> &'static [&'static str] {
    match scope {
        "profile" => PROFILE_CLAIMS,
        "email" => EMAIL_CLAIMS,
        "address" => ADDRESS_CLAIMS,
        "phone" => PHONE_CLAIMS,
        _ => &[],
    }
}

/// Every standard claim `UserInfo` can return, `sub` first, then the four scope
/// claim sets in Core 5.4 order, de-duplicated. Discovery advertises these in
/// `claims_supported` so every `UserInfo`-returnable claim is announced.
#[must_use]
pub fn userinfo_standard_claims() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = vec!["sub"];
    for set in [PROFILE_CLAIMS, EMAIL_CLAIMS, ADDRESS_CLAIMS, PHONE_CLAIMS] {
        for &name in set {
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// The claim-bearing scopes, in OIDC Core 5.4 order. Iterating this (rather than a
/// caller's set) keeps the released claim object deterministic regardless of how
/// the granted scopes were ordered.
const CLAIM_BEARING_SCOPES: &[&str] = &["profile", "email", "address", "phone"];

/// The standard claim NAMES a set of granted scopes selects (the union of each
/// granted scope's Core 5.4 set), in a stable order.
fn scope_claim_names(granted_scopes: &BTreeSet<String>) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = Vec::new();
    for scope in CLAIM_BEARING_SCOPES {
        if granted_scopes.contains(*scope) {
            for &name in claims_for_scope(scope) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// Parse a space-separated OAuth `scope` value into the set of scope tokens.
#[must_use]
pub fn parse_scope_set(scope: Option<&str>) -> BTreeSet<String> {
    scope
        .unwrap_or("")
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}

/// Assemble the released standard claims (OIDC Core 5.4 and 5.5), from the user's
/// stored claim `bag`, the `granted_scopes`, and the matching `claims`-request
/// member (`requested`, empty when the request carried no `claims` parameter).
///
/// This is the SINGLE shared release function; `sub` is NOT included (the caller
/// adds the derived `sub` so it is byte-identical to the ID token's). The merge is
/// deterministic and documented:
///
/// 1. The union of the scope-derived claim names (Core 5.4 order) forms the base
///    set; each is released from `bag` if present.
/// 2. Each explicitly `requested` claim name is then considered: it is released
///    from `bag` if present AND, when the request pins a `value`/`values`, the
///    stored value satisfies that filter. A requested claim already released by a
///    scope is filtered the same way (a pinned value can narrow it).
/// 3. A claim absent from `bag`, or present but failing a `value`/`values` filter,
///    is omitted. This holds for voluntary AND essential requests: an unmet
///    voluntary or essential claim is never an error at `UserInfo` (Core 5.5.1).
///
/// `sub` is never released from `bag` even if present there, so the derived
/// subject can never be shadowed by stored data.
#[must_use]
pub fn assemble_claims(
    bag: &Map<String, Value>,
    granted_scopes: &BTreeSet<String>,
    requested: &std::collections::BTreeMap<String, ClaimSpec>,
) -> Map<String, Value> {
    let mut released = Map::new();

    // 1. Scope-derived claims: release each present member (no value filter).
    for name in scope_claim_names(granted_scopes) {
        if name == "sub" {
            continue;
        }
        if let Some(value) = bag.get(name) {
            released.insert(name.to_owned(), value.clone());
        }
    }

    // 2. Explicitly requested claims: release each present member that satisfies
    //    any pinned value/values filter. This can add a claim no scope selected,
    //    or narrow one a scope already released.
    for (name, spec) in requested {
        if name == "sub" {
            continue;
        }
        match bag.get(name) {
            Some(value) if spec.value_matches(value) => {
                released.insert(name.clone(), value.clone());
            }
            // Absent, or present but failing the value/values filter: omit it,
            // and drop any scope-released copy that the filter now excludes.
            _ => {
                if spec.has_value_filter() {
                    released.remove(name);
                }
            }
        }
    }

    released
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bag() -> Map<String, Value> {
        json!({
            "name": "Ada Lovelace",
            "given_name": "Ada",
            "email": "ada@example.test",
            "email_verified": true,
            "phone_number": "+15550100",
            "sub": "attacker-controlled",
        })
        .as_object()
        .cloned()
        .unwrap()
    }

    fn scopes(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(ToString::to_string).collect()
    }

    fn no_request() -> std::collections::BTreeMap<String, ClaimSpec> {
        std::collections::BTreeMap::new()
    }

    #[test]
    fn openid_scope_alone_releases_no_standard_claims() {
        let released = assemble_claims(&bag(), &scopes(&["openid"]), &no_request());
        assert!(
            released.is_empty(),
            "openid alone releases nothing: {released:?}"
        );
    }

    #[test]
    fn email_scope_releases_present_email_claims_only() {
        let released = assemble_claims(&bag(), &scopes(&["openid", "email"]), &no_request());
        assert_eq!(released.get("email"), Some(&json!("ada@example.test")));
        assert_eq!(released.get("email_verified"), Some(&json!(true)));
        // No profile or phone claims leaked in.
        assert!(released.get("name").is_none());
        assert!(released.get("phone_number").is_none());
    }

    #[test]
    fn profile_scope_omits_members_the_user_lacks() {
        let released = assemble_claims(&bag(), &scopes(&["profile"]), &no_request());
        // Present members are released.
        assert_eq!(released.get("name"), Some(&json!("Ada Lovelace")));
        assert_eq!(released.get("given_name"), Some(&json!("Ada")));
        // Absent members (family_name, birthdate, ...) are simply omitted.
        assert!(released.get("family_name").is_none());
        assert!(released.get("birthdate").is_none());
    }

    #[test]
    fn sub_is_never_released_from_the_bag() {
        // Even with a `sub` in the stored bag, no scope or request releases it: the
        // caller supplies the derived subject.
        let released = assemble_claims(&bag(), &scopes(&["profile", "email"]), &no_request());
        assert!(
            released.get("sub").is_none(),
            "sub must never come from stored data"
        );
    }

    #[test]
    fn a_requested_voluntary_claim_absent_from_the_bag_is_omitted() {
        let mut req = std::collections::BTreeMap::new();
        req.insert("website".to_owned(), ClaimSpec::voluntary());
        let released = assemble_claims(&bag(), &scopes(&["openid"]), &req);
        assert!(
            released.get("website").is_none(),
            "unsatisfiable voluntary claim is omitted"
        );
    }

    #[test]
    fn a_requested_claim_adds_a_present_member_no_scope_selected() {
        // Requesting `name` via the claims parameter releases it even though only
        // the `openid` scope was granted (no `profile`).
        let mut req = std::collections::BTreeMap::new();
        req.insert("name".to_owned(), ClaimSpec::essential());
        let released = assemble_claims(&bag(), &scopes(&["openid"]), &req);
        assert_eq!(released.get("name"), Some(&json!("Ada Lovelace")));
    }

    #[test]
    fn a_values_filter_narrows_a_scope_released_claim() {
        // The `email` scope would release the stored email, but a claims request
        // pinning a different value filters it out (deterministic value matching).
        let mut req = std::collections::BTreeMap::new();
        req.insert(
            "email".to_owned(),
            ClaimSpec::with_values(vec![json!("someone-else@example.test")]),
        );
        let released = assemble_claims(&bag(), &scopes(&["email"]), &req);
        assert!(
            released.get("email").is_none(),
            "a values filter the stored value fails excludes the claim"
        );

        // A filter the stored value satisfies keeps it.
        let mut req_ok = std::collections::BTreeMap::new();
        req_ok.insert(
            "email".to_owned(),
            ClaimSpec::with_value(json!("ada@example.test")),
        );
        let released_ok = assemble_claims(&bag(), &scopes(&["email"]), &req_ok);
        assert_eq!(released_ok.get("email"), Some(&json!("ada@example.test")));
    }

    #[test]
    fn userinfo_standard_claims_are_sub_plus_the_four_sets() {
        let all = userinfo_standard_claims();
        assert_eq!(all.first(), Some(&"sub"));
        for &name in PROFILE_CLAIMS
            .iter()
            .chain(EMAIL_CLAIMS)
            .chain(ADDRESS_CLAIMS)
            .chain(PHONE_CLAIMS)
        {
            assert!(all.contains(&name), "{name} advertised");
        }
        // No duplicates.
        let mut seen = std::collections::HashSet::new();
        for name in &all {
            assert!(seen.insert(name), "duplicate {name}");
        }
    }
}
