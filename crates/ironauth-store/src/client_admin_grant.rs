// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client admin consent pre-authorization value types and the pure
//! scope-coverage predicate (issue #88, PR 4).
//!
//! An admin consent pre-authorization is the granular per-scope ESCAPE from the third-party
//! admin-consent gate: a third-party (not first-party) client must be admin-pre-authorized for
//! its requested scope before it can obtain user consent at the authorization endpoint. A
//! pre-authorization covering the requested scope SKIPS the user consent screen (the Microsoft
//! model: the admin grant is the consent of record); an uncovered third-party request is refused
//! with a terminal "requires administrator approval". One row per (tenant, environment, client).
//!
//! This module holds only PURE value logic (no SQL, no clock, no entropy): the typed write/read
//! value types the scoped repository consumes, and the coverage predicate the consent gate calls.
//! The persistence surface (the scoped repository) lives in the repository module. A
//! pre-authorization is RUNTIME per-environment state (never carried in a config snapshot), so a
//! promoted third-party client stays locked in the target environment until pre-authorized there.

use std::collections::BTreeSet;

/// An admin consent pre-authorization to create or overwrite (issue #88, PR 4). One per (tenant,
/// environment, client): a repeat write to the same client overwrites in place and reuses the
/// row id.
#[derive(Debug, Clone, Copy)]
pub struct NewClientAdminGrant<'a> {
    /// The authorize client id this pre-authorization governs (the per-environment natural key).
    pub client_id: &'a str,
    /// The space-separated OAuth scope set the admin pre-authorizes, or [`None`] to pre-authorize
    /// only the empty scope (the secure floor). A request is admitted only when its requested
    /// scope is a SUBSET of this set.
    pub granted_scope: Option<&'a str>,
    /// The opaque actor id string of the admin recording the pre-authorization (an audit
    /// convenience column; never a secret and never PII).
    pub granted_by: &'a str,
}

/// A stored admin consent pre-authorization, read back (issue #88, PR 4).
#[derive(Debug, Clone)]
pub struct ClientAdminGrantRecord {
    /// The `cag_` pre-authorization id.
    pub id: String,
    /// The authorize client id this pre-authorization governs (the per-environment natural key).
    pub client_id: String,
    /// The space-separated OAuth scope set the admin pre-authorized, or [`None`] for the empty
    /// pre-authorization.
    pub granted_scope: Option<String>,
}

/// Whether an admin pre-authorization COVERS a request's scope (issue #88, PR 4): the request's
/// scope token set must be a SUBSET of the pre-authorized set, both split on ASCII whitespace
/// (the OAuth scope grammar, matching the mint's own scope parsing) with an absent value being the
/// empty set. So a pre-authorization for a broad set (`openid profile email`) covers a narrower
/// request (`openid profile`); a pre-authorization for `openid` does NOT cover a broader request
/// (`openid profile`), which is refused with a terminal. An absent pre-authorization ([`None`])
/// covers only the empty request.
#[must_use]
pub fn admin_grant_covers_scope(granted: Option<&str>, requested: Option<&str>) -> bool {
    let requested = parse_scope_set(requested);
    let granted = parse_scope_set(granted);
    requested.is_subset(&granted)
}

/// Parse a space-separated OAuth scope value into its set of scope tokens (issue #88, PR 4). An
/// absent or blank value is the empty set. This mirrors the OIDC crate's `parse_scope_set`
/// byte-for-byte (the store crate cannot depend on the OIDC crate, so the tiny split is repeated
/// here rather than shared).
fn parse_scope_set(scope: Option<&str>) -> BTreeSet<String> {
    scope
        .unwrap_or("")
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::admin_grant_covers_scope;

    #[test]
    fn an_exact_pre_authorization_covers_the_request() {
        assert!(admin_grant_covers_scope(
            Some("openid profile"),
            Some("openid profile")
        ));
    }

    #[test]
    fn a_broader_pre_authorization_covers_a_narrower_request() {
        assert!(admin_grant_covers_scope(
            Some("openid profile email"),
            Some("openid profile")
        ));
        // Token order does not matter (both are split into sets).
        assert!(admin_grant_covers_scope(
            Some("email profile openid"),
            Some("openid email")
        ));
    }

    #[test]
    fn a_narrower_pre_authorization_does_not_cover_a_broader_request() {
        assert!(!admin_grant_covers_scope(
            Some("openid"),
            Some("openid profile")
        ));
        // A wholly disjoint request is not covered.
        assert!(!admin_grant_covers_scope(Some("openid"), Some("payments")));
    }

    #[test]
    fn the_empty_request_is_covered_by_anything_and_an_absent_grant_covers_only_the_empty_request()
    {
        // An empty (or absent) request is the empty set, a subset of every pre-authorization.
        assert!(admin_grant_covers_scope(Some("openid"), None));
        assert!(admin_grant_covers_scope(None, None));
        assert!(admin_grant_covers_scope(None, Some("   ")));
        // An absent pre-authorization covers ONLY the empty request.
        assert!(!admin_grant_covers_scope(None, Some("openid")));
    }
}
