// SPDX-License-Identifier: MIT OR Apache-2.0

//! Federation outbound-login correlation-state value types (issue #75, PR B).
//!
//! These are the persistence-layer inputs and views for the
//! `federation_login_states` table: the short-lived, single-use row that correlates
//! an upstream authorize leg to its callback. The PKCE `code_verifier` is a secret
//! and is SEALED by the repository (the plaintext is passed in on write and returned
//! only from the atomic single-use consume), so a leaked row carries no usable
//! verifier.

/// A federation correlation row to persist for an outbound authorize leg (issue
/// #75). The `code_verifier` is the plaintext the repository seals under the scope's
/// DEK; an empty slice means no PKCE challenge was sent.
#[derive(Debug, Clone, Copy)]
pub struct NewFederationLoginState<'a> {
    /// The opaque `state` handed to the upstream and echoed at the callback (the
    /// single-use consume key, the CSRF defence).
    pub state: &'a str,
    /// The OIDC `nonce` bound into the upstream authorize request.
    pub nonce: &'a str,
    /// The PKCE `code_verifier` plaintext the repository seals; empty for no PKCE.
    pub code_verifier: &'a [u8],
    /// The `cnr_` connector this leg belongs to (rendered id).
    pub connector_id: &'a str,
    /// The pending LOCAL `/authorize?...` resume target.
    pub return_to: &'a str,
    /// The routed `ocn_` org connection this login was bound to at the authorize leg
    /// (issue #77), or [`None`] for a direct federated login not routed to an
    /// organization. The callback reads it back from the CONSUMED row, so the
    /// organization is never influenced by anything the browser sent.
    pub org_connection_id: Option<&'a str>,
    /// The row expiry in microseconds since the epoch (from the clock seam).
    pub expires_at_unix_micros: i64,
}

/// The correlation values recovered by the atomic single-use consume (issue #75):
/// everything the callback needs to complete the exchange and resume the local
/// authorization request. The `code_verifier` is the UNSEALED plaintext (empty when
/// no PKCE was used).
#[derive(Debug, Clone)]
pub struct ConsumedFederationLoginState {
    /// The OIDC `nonce` to check against the upstream ID token.
    pub nonce: String,
    /// The unsealed PKCE `code_verifier` (empty when no PKCE was used).
    pub code_verifier: Vec<u8>,
    /// The `cnr_` connector id this leg belongs to.
    pub connector_id: String,
    /// The pending LOCAL `/authorize?...` resume target.
    pub return_to: String,
    /// The routed `ocn_` org connection this login was bound to at the authorize leg
    /// (issue #77), or [`None`] for a direct federated login. Re-derived here from the
    /// consumed row, never from the callback query.
    pub org_connection_id: Option<String>,
}
