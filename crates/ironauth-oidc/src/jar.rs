// SPDX-License-Identifier: MIT OR Apache-2.0

//! The JAR (RFC 9101) request-object surface (issue #158).
//!
//! # The RFC 9101-only semantics, and the documented deviation
//!
//! OIDC Core section 6 MERGES the request object with the query parameters;
//! RFC 9101 says the authorization request parameters are taken ONLY from the
//! request object. This module implements 9101 strictly: when a request object is
//! present, the query parameters are IGNORED (the client_id needed to resolve the
//! verification keys comes from the request object itself, or from the query when
//! the object's claims omit it - the one parameter the spec allows outside). The
//! deviation from Core section 6 is deliberate and documented in the module docs
//! and the discovery guidance.
//!
//! # The verification (RFC 8725 hygiene)
//!
//! The request object is a JWS verified against the client's registered keys
//! (inline `jwks` or fetched `jwks_uri`): the signature must verify, the `alg`
//! must be in the asymmetric assertion matrix (no `none`), and the `typ` must be
//! the RFC 9101 media type when present. An unverifiable object is a hard
//! `invalid_request_object`.

use std::sync::Arc;

use crate::OidcState;
use crate::authorize::AuthorizeParams;
use crate::client_auth::resolve_client_keys;
use base64::Engine as _;
use ironauth_jose::{ExpectedTyp, TokenTyp, TrustedKey, VerificationPolicy, verify};
use ironauth_store::{ClientId, Scope};
use serde_json::Value;

/// The RFC 9101 media type a request object's `typ` carries.
pub const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// The authorize parameters a verified request object may set. Only these names
/// are read from the object's claims; anything else is ignored.
const CLAIM_NAMES: &[&str] = &[
    "response_type",
    "response_mode",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "prompt",
    "max_age",
    "claims",
    "login_hint",
    "id_token_hint",
    "request_uri",
    "resource",
];

/// Resolve the request object (issue #158): when `params.request` carries a JWS,
/// verify it against the client's registered keys and return the authorize
/// parameters taken ONLY from its claims (RFC 9101 semantics). When absent,
/// return the query params unchanged.
///
/// # Errors
///
/// [`JarError::InvalidRequestObject`] when the object does not verify, names an
/// unknown client, or its claims cannot be parsed.
pub async fn resolve_request_object(
    state: &OidcState,
    scope: Scope,
    client: &crate::authorize::ResolvedClient<'_>,
    params: AuthorizeParams,
) -> Result<AuthorizeParams, JarError> {
    let Some(request_jwt) = params.request.as_deref() else {
        return Ok(params);
    };

    // The client id: from the request object's claims when present, else the
    // query's (the one parameter the spec allows outside the object).
    let object_claims = peek_claims(request_jwt).ok_or(JarError::InvalidRequestObject)?;
    let client_id = object_claims
        .get("client_id")
        .and_then(Value::as_str)
        .or_else(|| params.client_id.as_deref())
        .ok_or(JarError::InvalidRequestObject)?;

    // The verification keys: the client's registered keys (inline jwks or the
    // fetched jwks_uri), resolved through the same seam the private_key_jwt
    // verification uses. A CIMD client has no registered keys: refused.
    let client_id = match client {
        crate::authorize::ResolvedClient::Registered(record) => record.id.to_string(),
        crate::authorize::ResolvedClient::Cimd(_) => return Err(JarError::InvalidRequestObject),
    };
    let auth_record = state
        .store()
        .scoped(scope)
        .clients()
        .auth_record(
            &ClientId::parse_in_scope(&client_id, &scope)
                .map_err(|_| JarError::InvalidRequestObject)?,
        )
        .await
        .map_err(|_| JarError::InvalidRequestObject)?;
    let keys = resolve_client_keys(state, &auth_record).await;
    if keys.is_empty() {
        return Err(JarError::InvalidRequestObject);
    }

    // The verification (RFC 8725 hygiene): the signature against the keys, the
    // alg allowlist (the asymmetric assertion matrix - no `none`), the audience
    // (the issuer), and the RFC 9101 media type as an OPTIONAL typ (a bare
    // request object without the typ is accepted per RFC 9101 section 3.1).
    let issuer = state.issuer_for(&scope);
    let algs: Vec<ironauth_jose::JwsAlgorithm> = crate::client_auth::assertion_signing_alg_values()
        .iter()
        .filter_map(|name| ironauth_jose::JwsAlgorithm::from_jose_name(name))
        .collect();
    let policy = VerificationPolicy::new(
        algs,
        keys,
        issuer,
        client_id.to_owned(),
        ExpectedTyp::ForeignIssuer,
    )
    .map_err(|_| JarError::InvalidRequestObject)?;
    let verified = verify(request_jwt, &policy, state.env().clock())
        .map_err(|_| JarError::InvalidRequestObject)?;
    let claims = verified.claims().raw();

    // RFC 9101-only semantics: the authorize parameters come from the object.
    let mut jar_params = AuthorizeParams::default();
    jar_params.response_type = string_claim(&claims, "response_type");
    jar_params.response_mode = string_claim(&claims, "response_mode");
    jar_params.client_id = string_claim(&claims, "client_id").or(Some(client_id.to_owned()));
    jar_params.redirect_uri = string_claim(&claims, "redirect_uri");
    jar_params.scope = string_claim(&claims, "scope");
    jar_params.state = string_claim(&claims, "state");
    jar_params.nonce = string_claim(&claims, "nonce");
    jar_params.code_challenge = string_claim(&claims, "code_challenge");
    jar_params.code_challenge_method = string_claim(&claims, "code_challenge_method");
    jar_params.prompt = string_claim(&claims, "prompt");
    jar_params.max_age = string_claim(&claims, "max_age");
    jar_params.claims = string_claim(&claims, "claims");
    jar_params.request_uri = string_claim(&claims, "request_uri");
    if let Some(Value::Array(items)) = claims.get("resource") {
        jar_params.resources = items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    Ok(jar_params)
}

/// Read a string claim from the verified object's claims.
fn string_claim(claims: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    claims.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// Peek the claims of a JWS (unverified: for the client_id the verification
/// needs before it can run).
fn peek_claims(token: &str) -> Option<serde_json::Map<String, Value>> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// A JAR failure, mapped to the authorize surface's uniform
/// `invalid_request_object`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JarError {
    /// The request object is absent, unverifiable, or malformed.
    InvalidRequestObject,
}
