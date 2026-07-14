// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared token-credential classification for the revocation and introspection
//! endpoints (RFC 7009 / RFC 7662, issue #22).
//!
//! Both endpoints accept ANY token IronAuth issues and must route it by its OWN
//! embedded scope, exactly as the opaque `UserInfo` path does (issue #29), because
//! `/revoke` and `/introspect` are GLOBAL (deployment-root) endpoints with no scope
//! in the URL. This module tells the three formats apart by their unforgeable
//! self-describing shape, never by the caller-supplied `token_type_hint` (RFC 7009
//! and RFC 7662 both make the hint a NON-authoritative optimization: the server must
//! still find the token if the hint is wrong or absent). Classification here IS that
//! fall-back-across-types lookup, so a wrong hint changes nothing.
//!
//! - a refresh token carries the `ira_rt_` prefix (issue #21);
//! - an opaque access token carries the `ira_at_` prefix (issue #29);
//! - anything else is treated as a compact `at+jwt` JWS and its `jti` is peeked as a
//!   lookup handle (issue #29), never trusted before it is authenticated downstream.
//!
//! Nothing here authenticates a token. It only classifies the wire shape so the
//! caller can run the SCOPE-BOUND, RLS-forced store resolve for that format; a forged
//! handle, a tampered payload, or a cross-scope credential all fail in that resolve.

use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::client_auth::ClientAuthError;
use crate::error::TokenError;
use crate::tokens::{OPAQUE_ACCESS_TOKEN_PREFIX, OPAQUE_REFRESH_TOKEN_PREFIX};

/// The delimiter between an opaque/refresh token's scope-declaring routing handle
/// and its secret suffix (issue #29/#21): `ira_at_<handle>~<secret>`. Kept local so
/// this module has no cross-module coupling beyond the two public prefixes.
const HANDLE_DELIMITER: char = '~';

/// A defensive cap on the raw token size before the unverified `jti` peek. The
/// hardened verify path caps again; this bounds the cheap pre-parse (mirrors
/// `UserInfo`).
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// The wire format of a presented token, told apart by its self-describing shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentedTokenKind {
    /// A refresh token (`ira_rt_...`), resolved by its whole-token digest (issue #21).
    Refresh,
    /// An opaque access token (`ira_at_...`), resolved by its whole-token digest
    /// (issue #29).
    OpaqueAccess,
    /// A compact `at+jwt` JWS access token, resolved by its embedded `jti` plus the
    /// hardened signature verify (issue #29).
    JwtAccess,
}

/// Map a client-authentication failure to the shared RFC 6749 5.2 error response
/// both the revocation (RFC 7009 section 2.2.1) and introspection (RFC 7662 section
/// 2.3) endpoints return: the opaque `invalid_client` (401, with `WWW-Authenticate`
/// when the client attempted Basic) or an `invalid_request` (400). It reveals
/// NOTHING about any token, so it is not a token-scanning oracle: the only thing it
/// discloses is that client authentication failed, exactly as the token endpoint
/// does.
pub(crate) fn client_auth_error_response(error: &ClientAuthError) -> Response {
    match error {
        ClientAuthError::InvalidRequest(message) => {
            TokenError::InvalidRequest((*message).to_owned()).into_response()
        }
        ClientAuthError::InvalidClient { via_basic } => TokenError::InvalidClient {
            via_basic: *via_basic,
        }
        .into_response(),
    }
}

/// Classify a presented token by its self-describing wire shape. Total: an `ira_rt_`
/// prefix is a refresh token, an `ira_at_` prefix an opaque access token, and
/// anything else is treated as an `at+jwt` (whose `jti` the caller then peeks). The
/// classification is authoritative over any `token_type_hint`.
pub(crate) fn classify(token: &str) -> PresentedTokenKind {
    if token.starts_with(OPAQUE_REFRESH_TOKEN_PREFIX) {
        PresentedTokenKind::Refresh
    } else if token.starts_with(OPAQUE_ACCESS_TOKEN_PREFIX) {
        PresentedTokenKind::OpaqueAccess
    } else {
        PresentedTokenKind::JwtAccess
    }
}

/// The scope-declaring routing handle of an `ira_rt_`/`ira_at_` token: the segment
/// between the product prefix and the `~` secret delimiter. Total: a token without
/// the prefix yields [`None`].
pub(crate) fn opaque_handle<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
    token.strip_prefix(prefix)?.split(HANDLE_DELIMITER).next()
}

/// Read the `jti` from a compact JWS payload WITHOUT verifying it, as a lookup
/// handle (mirrors `UserInfo::peek_jti`). Bounded and total: an oversized token, a
/// non-three-segment shape, a non-base64url payload, non-object claims, or a missing
/// or non-string `jti` all yield [`None`]. Nothing here is trusted; the token is
/// authenticated afterward.
pub(crate) fn peek_jti(token: &str) -> Option<String> {
    peek_claim(token, "jti").and_then(|value| value.as_str().map(str::to_owned))
}

/// Read a single claim from a compact JWS payload WITHOUT verifying it, for deriving
/// a lookup key (the `jti`) or an unverified value the caller re-checks under the
/// signature (the `aud`, used as the verification audience so a tampered value fails
/// the signature). Bounded and total, exactly like [`peek_jti`].
pub(crate) fn peek_claim(token: &str, name: &str) -> Option<Value> {
    if token.len() > MAX_TOKEN_BYTES {
        return None;
    }
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.as_object()?.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_tells_the_three_formats_apart_by_shape() {
        assert_eq!(classify("ira_rt_abc~secret"), PresentedTokenKind::Refresh);
        assert_eq!(
            classify("ira_at_abc~secret"),
            PresentedTokenKind::OpaqueAccess
        );
        // Anything without a product prefix is treated as an at+jwt.
        assert_eq!(classify("aaa.bbb.ccc"), PresentedTokenKind::JwtAccess);
        assert_eq!(classify(""), PresentedTokenKind::JwtAccess);
    }

    #[test]
    fn opaque_handle_extracts_the_routing_segment() {
        assert_eq!(
            opaque_handle("ira_at_tok_xyz~secretpart", OPAQUE_ACCESS_TOKEN_PREFIX),
            Some("tok_xyz")
        );
        assert_eq!(
            opaque_handle("ira_rt_rft_xyz~secretpart", OPAQUE_REFRESH_TOKEN_PREFIX),
            Some("rft_xyz")
        );
        // A prefix mismatch yields None.
        assert_eq!(
            opaque_handle("ira_at_tok~s", OPAQUE_REFRESH_TOKEN_PREFIX),
            None
        );
    }

    #[test]
    fn peek_reads_jti_and_aud_without_verifying() {
        let payload = URL_SAFE_NO_PAD.encode(json!({"jti":"tok_1","aud":"cli_x"}).to_string());
        let token = format!("aaa.{payload}.sig");
        assert_eq!(peek_jti(&token).as_deref(), Some("tok_1"));
        assert_eq!(
            peek_claim(&token, "aud").and_then(|v| v.as_str().map(str::to_owned)),
            Some("cli_x".to_owned())
        );
        // A two-segment (non-JWS) shape yields None.
        assert_eq!(peek_jti("aaa.bbb"), None);
    }
}
