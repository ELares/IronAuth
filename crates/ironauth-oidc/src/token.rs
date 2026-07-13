// SPDX-License-Identifier: MIT OR Apache-2.0

//! The token endpoint's `authorization_code` grant (`POST /token`).
//!
//! The exchange is ordered so the one-time code is only ever burned on a request
//! that is going to succeed:
//!
//! 1. Parse the grant type (only `authorization_code`; ROPC and every other grant
//!    are unrepresentable) and recover the `(tenant, environment)` scope from the
//!    code.
//! 2. READ the code's bindings WITHOUT consuming it.
//! 3. Re-check EVERY binding (`client_id`, `redirect_uri`, PKCE `code_challenge`)
//!    against the presented request.
//! 4. Mint (sign) the ID and access tokens.
//! 5. Only now atomically REDEEM the code (the single-use gate), recording the
//!    issued tokens and the redeem audit in the same transaction as the consume.
//!
//! # Why read-then-sign-then-consume
//!
//! Doing the binding re-check and the signing BEFORE the consume means a
//! wrong-binding presentation, or a signing/key failure, never burns the code:
//! it stays live for the legitimate client's retry. A weaker design that consumes
//! first would let anyone holding the code (without the PKCE verifier) destroy it,
//! and would burn the code on a transient signing error.
//!
//! # Binding re-checks (RFC 6749 4.1.3, RFC 9700)
//!
//! The `client_id` re-check is explicit and non-negotiable (the 2026 Zitadel
//! advisory class: a code issued to client A must not be redeemable by client B).
//! Any single mismatch yields `invalid_grant`, and the error is UNIFORM: it never
//! reveals which binding failed, so an attacker cannot probe one parameter at a
//! time.
//!
//! # Reuse revokes the chain; a benign retry does not
//!
//! The atomic redeem is the authority on single use. A second presentation of an
//! already-consumed code within the configured grace window
//! (`oidc.reuse_grace_secs`) is a benign double-submit or immediate retry: it
//! fails with `invalid_grant` and does NOT revoke. Beyond the window it is a
//! genuine reuse: the grant chain is revoked in the same transaction (flipping the
//! observable active state of every token issued from the code), the reuse is
//! audited, and the caller gets the same `invalid_grant`.

use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ActorRef, AuthorizationCodeId, ClientId, CodeBindings, CorrelationId, IssuedTokenRecord,
    RedeemOutcome, Scope, ServiceId, StoreError,
};
use serde::Deserialize;

use crate::error::TokenError;
use crate::pkce::verify_s256;
use crate::registry::GrantType;
use crate::state::OidcState;
use crate::tokens::{self, IssuedTokens, MintRequest};
use crate::util::client_service_actor;

/// Counter: authorization codes presented again after they were already consumed
/// beyond the grace window (a genuine reuse that revoked the grant chain).
const CODE_REUSE_TOTAL: &str = "ironauth_oidc_code_reuse_total";
/// Counter: redeem attempts that failed with a store error (so the revoke, if
/// one was due, did not commit) rather than resolving to a clean outcome.
const REDEEM_ERROR_TOTAL: &str = "ironauth_oidc_redeem_error_total";

/// The token-request parameters (form-encoded).
#[derive(Debug, Deserialize)]
pub struct TokenParams {
    /// The OAuth `grant_type` (must be `authorization_code`).
    pub grant_type: Option<String>,
    /// The authorization code to redeem.
    pub code: Option<String>,
    /// The redirect URI, re-checked against the code's binding.
    pub redirect_uri: Option<String>,
    /// The client identifier, re-checked against the code's binding.
    pub client_id: Option<String>,
    /// The PKCE `code_verifier`, checked against the bound `code_challenge`.
    pub code_verifier: Option<String>,
}

/// `POST /token`.
pub async fn token(State(state): State<OidcState>, Form(params): Form<TokenParams>) -> Response {
    match exchange(&state, params).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn exchange(state: &OidcState, params: TokenParams) -> Result<Response, TokenError> {
    // 1. grant_type: present and exactly authorization_code. ROPC (`password`)
    //    and every other grant are unrepresentable, so they land here as an
    //    unsupported grant type with no handler to route to.
    let grant_type = params
        .grant_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest("grant_type is required".to_owned()))?;
    if GrantType::parse(grant_type) != Some(GrantType::AuthorizationCode) {
        return Err(TokenError::UnsupportedGrantType);
    }

    // 2. code: present, and it declares its own (tenant, environment) scope. A
    //    malformed code is a uniform invalid_grant.
    let code_raw = params
        .code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest("code is required".to_owned()))?;
    let code_id = AuthorizationCodeId::parse_declared_scope(code_raw)
        .map_err(|_| TokenError::InvalidGrant)?;
    let scope = code_id.scope();

    // 3. Read the code's bindings WITHOUT consuming it. Absent (or out of scope)
    //    is a uniform invalid_grant.
    let bindings = state
        .store()
        .scoped(scope)
        .authorization()
        .load_code(&code_id)
        .await
        .map_err(map_store_error)?
        .ok_or(TokenError::InvalidGrant)?;

    // 4. Re-check EVERY binding BEFORE the code is burned. A mismatch is a uniform
    //    invalid_grant and leaves the one-time code live for the real client.
    if !bindings_match(&bindings, &params) {
        return Err(TokenError::InvalidGrant);
    }

    // 5. Mint (sign) the tokens BEFORE the consume, so a missing key or a signing
    //    failure fails closed without burning the code.
    let minted = mint_tokens(state, scope, &bindings)?;
    let records: Vec<IssuedTokenRecord> = minted
        .records()
        .into_iter()
        .map(|(id, kind)| IssuedTokenRecord { id, kind })
        .collect();

    // 6. Atomically redeem: the single-use gate. On the winning call it records
    //    the issued tokens and the redeem audit in the same transaction as the
    //    consume; a miss is classified as a benign grace retry, a genuine reuse
    //    (which revokes the chain), or an expired/absent code. Attribute the audit
    //    to the client the code is for, under a fresh per-request correlation id.
    let actor = client_actor(state, scope, &bindings.client_id);
    let correlation = CorrelationId::generate(state.env());
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .authorization()
        .redeem(
            state.env(),
            &code_id,
            &bindings.grant_id,
            &records,
            state.reuse_grace(),
        )
        .await;

    match outcome {
        // Won the race: hand out the tokens we pre-signed.
        Ok(RedeemOutcome::Consumed) => Ok(token_response(&minted, &bindings)),
        // A benign within-grace retry or an expired/absent code: plain
        // invalid_grant, no revoke.
        Ok(RedeemOutcome::RetryWithinGrace | RedeemOutcome::Invalid) => {
            Err(TokenError::InvalidGrant)
        }
        // A genuine reuse: the grant chain was revoked and audited in the redeem
        // transaction. Meter it and return the uniform invalid_grant.
        Ok(RedeemOutcome::Reused) => {
            metrics::counter!(CODE_REUSE_TOTAL).increment(1);
            tracing::warn!("authorization code reuse detected; grant chain revoked");
            Err(TokenError::InvalidGrant)
        }
        // The redeem itself faulted, so a revoke that was due did NOT commit. Meter
        // it (a dropped revoke must be visible) and fail closed.
        Err(error) => {
            metrics::counter!(REDEEM_ERROR_TOTAL).increment(1);
            Err(map_store_error(error))
        }
    }
}

/// Re-check every binding the code carries against the presented request. All
/// mismatches collapse to a single boolean, so the caller returns the uniform
/// `invalid_grant` without revealing which binding failed. This runs BEFORE the
/// code is consumed, so a mismatch does not burn the one-time code.
fn bindings_match(bindings: &CodeBindings, params: &TokenParams) -> bool {
    let client_ok = params
        .client_id
        .as_deref()
        .is_some_and(|presented| presented == bindings.client_id);
    let redirect_ok = params
        .redirect_uri
        .as_deref()
        .is_some_and(|presented| presented == bindings.redirect_uri);
    let pkce_ok = match &bindings.code_challenge {
        Some(challenge) => params
            .code_verifier
            .as_deref()
            .is_some_and(|verifier| verify_s256(verifier, challenge)),
        None => true,
    };
    client_ok && redirect_ok && pkce_ok
}

/// Mint the ID and access tokens through the signing core. A missing signing key
/// or a signing failure is an opaque `server_error`; because this runs before the
/// consume, that failure leaves the code live for a retry.
fn mint_tokens(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
) -> Result<IssuedTokens, TokenError> {
    let signer = state
        .signer_for(&scope.environment())
        .ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    tokens::mint(
        state,
        signer,
        &MintRequest {
            scope,
            issuer: &issuer,
            subject: &bindings.subject,
            client_id: &bindings.client_id,
            nonce: bindings.nonce.as_deref(),
            oauth_scope: bindings.oauth_scope.as_deref(),
        },
    )
    .map_err(|()| TokenError::ServerError)
}

/// Build the `200 OK` token response (RFC 6749 5.1) from the pre-signed tokens.
fn token_response(minted: &IssuedTokens, bindings: &CodeBindings) -> Response {
    let mut body = serde_json::json!({
        "access_token": minted.access_token,
        "token_type": "Bearer",
        "expires_in": minted.expires_in_secs,
        "id_token": minted.id_token,
    });
    if let Some(oauth_scope) = &bindings.oauth_scope {
        body["scope"] = serde_json::json!(oauth_scope);
    }
    token_ok(&body.to_string())
}

/// The stable audit service-actor for the client the code is bound to. The stored
/// `client_id` was a valid scoped identifier when the code was issued, so it
/// parses here; the fallback to a generated actor is unreachable defense in depth
/// so a malformed stored value never fails an otherwise-valid exchange.
fn client_actor(state: &OidcState, scope: Scope, client_id: &str) -> ActorRef {
    match ClientId::parse_in_scope(client_id, &scope) {
        Ok(id) => client_service_actor(&id),
        Err(_) => ActorRef::service(ServiceId::generate(state.env())),
    }
}

/// A `200 OK` JSON token response with the no-store cache headers.
fn token_ok(body: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        body.to_owned(),
    )
        .into_response()
}

/// Map a store error at redemption: a not-found (out-of-scope code) is a uniform
/// `invalid_grant`; anything else is an opaque server error.
fn map_store_error(error: StoreError) -> TokenError {
    match error {
        StoreError::NotFound => TokenError::InvalidGrant,
        other => {
            tracing::error!(error = %other, "token endpoint store error");
            TokenError::ServerError
        }
    }
}
