// SPDX-License-Identifier: MIT OR Apache-2.0

//! The token endpoint's `authorization_code` grant (`POST /token`).
//!
//! The exchange is: parse the grant type (only `authorization_code`; ROPC and
//! every other grant are unrepresentable), recover the `(tenant, environment)`
//! scope from the code, atomically redeem the code (single use), re-check every
//! binding, and only then mint and record the tokens.
//!
//! # Binding re-checks (RFC 6749 4.1.3, RFC 9700)
//!
//! Every binding the authorization endpoint recorded is re-checked here:
//! `client_id`, `redirect_uri`, and the PKCE `code_challenge`. The `client_id`
//! re-check is explicit and non-negotiable (the 2026 Zitadel advisory class: a
//! code issued to client A must not be redeemable by client B). Any single
//! mismatch yields `invalid_grant`, and the error is UNIFORM: it never reveals
//! which binding failed, so an attacker cannot probe one parameter at a time.
//!
//! # Reuse revokes the chain
//!
//! Redeeming a code that was already consumed is a replay: the grant chain is
//! revoked, so every token already issued from that code becomes inactive, the
//! reuse is audited, and the caller gets the same `invalid_grant`.

use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ActorRef, AuthorizationCodeId, CodeBindings, CorrelationId, GrantId, IssuedTokenRecord,
    RedeemOutcome, Scope, ServiceId, StoreError,
};
use serde::Deserialize;

use crate::error::TokenError;
use crate::pkce::verify_s256;
use crate::registry::GrantType;
use crate::state::OidcState;
use crate::tokens::{self, MintRequest};

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

    // 3. Atomically redeem the code (the single-use gate).
    let actor = ActorRef::service(ServiceId::generate(state.env()));
    let correlation = CorrelationId::generate(state.env());
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .authorization()
        .redeem(state.env(), &code_id)
        .await
        .map_err(map_store_error)?;

    let bindings = match outcome {
        RedeemOutcome::Consumed(bindings) => bindings,
        RedeemOutcome::Replayed { grant_id } => {
            revoke_reused(state, scope, &grant_id).await;
            return Err(TokenError::InvalidGrant);
        }
        RedeemOutcome::Invalid => return Err(TokenError::InvalidGrant),
    };

    // 4. Re-check EVERY binding, then mint and record the tokens.
    if !bindings_match(&bindings, &params) {
        return Err(TokenError::InvalidGrant);
    }
    issue_tokens(state, scope, &bindings).await
}

/// Re-check every binding the code carries against the presented request. All
/// mismatches collapse to a single boolean, so the caller returns the uniform
/// `invalid_grant` without revealing which binding failed. The code is already
/// consumed regardless: a redemption attempt burns the one-time code.
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

/// Mint the ID and access tokens through the signing core, record their `jti`s
/// against the grant, and build the token response (RFC 6749 5.1).
async fn issue_tokens(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
) -> Result<Response, TokenError> {
    let signer = state
        .signer_for(&scope.environment())
        .ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    let minted = tokens::mint(
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
    .map_err(|()| TokenError::ServerError)?;

    let records: Vec<IssuedTokenRecord> = minted
        .records()
        .into_iter()
        .map(|(id, kind)| IssuedTokenRecord { id, kind })
        .collect();
    let actor = ActorRef::service(ServiceId::generate(state.env()));
    let correlation = CorrelationId::generate(state.env());
    state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .authorization()
        .record_issued_tokens(state.env(), &bindings.grant_id, &records)
        .await
        .map_err(|_| TokenError::ServerError)?;

    let mut body = serde_json::json!({
        "access_token": minted.access_token,
        "token_type": "Bearer",
        "expires_in": minted.expires_in_secs,
        "id_token": minted.id_token,
    });
    if let Some(oauth_scope) = &bindings.oauth_scope {
        body["scope"] = serde_json::json!(oauth_scope);
    }
    Ok(token_ok(&body.to_string()))
}

/// A replayed (already consumed) code revokes its grant chain, so every token
/// issued from it becomes inactive and the reuse is audited. A concurrent revoke
/// that already ran is a benign not-found.
async fn revoke_reused(state: &OidcState, scope: Scope, grant_id: &GrantId) {
    let actor = ActorRef::service(ServiceId::generate(state.env()));
    let correlation = CorrelationId::generate(state.env());
    match state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .authorization()
        .revoke_grant_chain(state.env(), grant_id)
        .await
    {
        Ok(()) | Err(StoreError::NotFound) => {}
        Err(error) => {
            tracing::error!(error = %error, "failed to revoke reused grant chain");
        }
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
