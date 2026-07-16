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
//! 3. AUTHENTICATE the client (issue #20): parse the presented `client_secret_basic`
//!    or `client_secret_post` credentials, resolve the client's registered method,
//!    and verify the secret. A failure is the spec-exact `invalid_client`.
//! 4. Re-check EVERY binding (`client_id`, `redirect_uri`, PKCE `code_challenge`)
//!    against the presented request; the `client_id` binding is re-checked against
//!    the AUTHENTICATED client.
//! 5. Mint (sign) the ID and access tokens.
//! 6. Only now atomically REDEEM the code (the single-use gate), recording the
//!    issued tokens and the redeem audit in the same transaction as the consume.
//!
//! Client authentication and the binding re-checks both run BEFORE the consume, so
//! a failed authentication or a wrong binding never burns the one-time code.
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

use std::fmt;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_jose::JwsAlgorithm;
use ironauth_store::{
    ActorRef, AuthorizationCodeId, ClientAuthRecord, ClientId, CodeBindings, CorrelationId,
    IssuedTokenRecord, NewOpaqueAccessToken, NewRefreshFamily, RedeemOutcome, RefreshFamilyId,
    RefreshFamilyOpenOutcome, RefreshRedeem, RefreshRedeemOutcome, RefreshTokenId,
    RefreshTokenResolution, RotatedRefreshToken, Scope, ServiceId, SessionId, StoreError,
    TokenKind,
};
use serde::Deserialize;

use crate::authn;
use crate::claims_request::ClaimsRequest;
use crate::client_auth::{
    self, AuthenticatedClient, ClientAuthError, ClientAuthInputs, ClientAuthMethod,
};
use crate::error::TokenError;
use crate::pkce::verify_s256;
use crate::registry::GrantType;
use crate::resource;
use crate::scope_claims::{assemble_claims, parse_scope_set};
use crate::state::{OidcState, ResourceTargetError};
use crate::step_up;
use crate::tokens::{self, AccessTokenTarget, IssuedTokens, MintRequest, MintedAccessToken};
use crate::util::{client_service_actor, epoch_micros};

/// Counter: authorization codes presented again after they were already consumed
/// beyond the grace window (a genuine reuse that revoked the grant chain).
const CODE_REUSE_TOTAL: &str = "ironauth_oidc_code_reuse_total";
/// Counter: redeem attempts that failed with a store error (so the revoke, if
/// one was due, did not commit) rather than resolving to a clean outcome.
const REDEEM_ERROR_TOTAL: &str = "ironauth_oidc_redeem_error_total";
/// Counter: refresh tokens presented again after they were rotated, beyond the
/// grace window (a genuine reuse that revoked the whole family, issue #21).
const REFRESH_REUSE_TOTAL: &str = "ironauth_oidc_refresh_reuse_total";

/// The OAuth scope value that requests a refresh token surviving RP logout (OIDC
/// Core 11). Its presence in the granted scope makes the issued refresh-token
/// family an OFFLINE family (issue #21).
const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

/// The token-request parameters (form-encoded).
///
/// [`fmt::Debug`] is hand written and redacting: `code` is a single-use bearer
/// credential and `client_secret` is a client credential, so a struct dump or a
/// `tracing` field never spills either.
#[derive(Deserialize)]
pub struct TokenParams {
    /// The OAuth `grant_type` (must be `authorization_code`).
    pub grant_type: Option<String>,
    /// The authorization code to redeem.
    pub code: Option<String>,
    /// The redirect URI, re-checked against the code's binding.
    pub redirect_uri: Option<String>,
    /// The client identifier, re-checked against the code's binding.
    pub client_id: Option<String>,
    /// The client secret for `client_secret_post` authentication (issue #20).
    pub client_secret: Option<String>,
    /// The JWT client assertion for `private_key_jwt` / `client_secret_jwt`
    /// authentication (issue #25).
    pub client_assertion: Option<String>,
    /// The RFC 7521 `client_assertion_type` accompanying `client_assertion`.
    pub client_assertion_type: Option<String>,
    /// The PKCE `code_verifier`, checked against the bound `code_challenge`.
    pub code_verifier: Option<String>,
    /// The refresh token to redeem for the `refresh_token` grant (issue #21). A
    /// single-use rotating bearer credential, so it is redacted from `Debug`.
    pub refresh_token: Option<String>,
    /// The RFC 7521 `assertion` carrying the authorization grant for the JWT bearer
    /// assertion grant (issue #26): the external issuer's JWT. DISTINCT from
    /// `client_assertion` (which authenticates the CLIENT); this one carries the
    /// external SUBJECT the token is mapped to. A bearer credential, so it is
    /// redacted from `Debug`.
    pub assertion: Option<String>,
    /// The requested OAuth `scope` for the `client_credentials` grant (RFC 6749
    /// 4.4.2, issue #23) and the JWT bearer assertion grant (RFC 7521, issue #26).
    /// Optional; when present it is validated/normalized and echoed into the issued
    /// token.
    pub scope: Option<String>,
    /// The device code to poll for the RFC 8628 device grant (issue #24). A bearer
    /// credential the constrained device presents on every poll, so it is redacted
    /// from `Debug` and never logged in plaintext.
    pub device_code: Option<String>,
}

impl fmt::Debug for TokenParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenParams")
            .field("grant_type", &self.grant_type)
            .field("redirect_uri", &self.redirect_uri)
            .field("client_id", &self.client_id)
            .field("has_client_secret", &self.client_secret.is_some())
            .field("has_client_assertion", &self.client_assertion.is_some())
            .field("client_assertion_type", &self.client_assertion_type)
            .field("has_code", &self.code.is_some())
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("has_assertion", &self.assertion.is_some())
            .field("has_device_code", &self.device_code.is_some())
            .finish_non_exhaustive()
    }
}

/// `POST /token`.
///
/// The raw body is taken (rather than a typed `Form<TokenParams>`) so the RFC 8707
/// `resource` parameter, which MAY appear multiple times (issue #28) and cannot be
/// captured by a scalar serde field, is parsed alongside the typed fields from the
/// SAME body: the scalar fields deserialize normally, and every `resource` value is
/// collected separately.
pub async fn token(State(state): State<OidcState>, headers: HeaderMap, body: String) -> Response {
    let params: TokenParams = match serde_urlencoded::from_str(&body) {
        Ok(params) => params,
        Err(_) => {
            return TokenError::InvalidRequest("the request body is malformed".to_owned())
                .into_response();
        }
    };
    let resources = resource::resources_from_encoded(&body);
    match exchange(&state, &headers, params, resources).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn exchange(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
    resources: Vec<String>,
) -> Result<Response, TokenError> {
    // grant_type: present and a serviced grant. ROPC (`password`) and every other
    // grant are unrepresentable, so they land as an unsupported grant type with no
    // handler to route to.
    let grant_type = params
        .grant_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest("grant_type is required".to_owned()))?;
    match GrantType::parse(grant_type) {
        Some(GrantType::AuthorizationCode) => {
            authorization_code_grant(state, headers, params, &resources).await
        }
        Some(GrantType::RefreshToken) => {
            refresh_token_grant(state, headers, params, &resources).await
        }
        // The client-credentials grant does not compose with resource indicators in
        // this issue (there is no prior authorization to downscope from); its
        // audience is the configured default. Any `resource` parameter is ignored.
        Some(GrantType::ClientCredentials) => {
            crate::client_credentials::client_credentials_grant(state, headers, params).await
        }
        Some(GrantType::JwtBearer) => {
            crate::jwt_bearer::jwt_bearer_grant(state, headers, params).await
        }
        Some(GrantType::DeviceCode) => {
            crate::device::device_code_grant(state, headers, params).await
        }
        None => Err(TokenError::UnsupportedGrantType),
    }
}

/// The `authorization_code` grant (issue #12): redeem a single-use code for the ID
/// and access tokens, and (issue #21) open a refresh-token family alongside them.
// The linear redeem flow (load, authenticate, re-check bindings, resolve target,
// step-up re-evaluation, mint-before-consume, atomic redeem) reads best as one
// function; splitting it would scatter the sign-before-consume discipline.
#[allow(clippy::too_many_lines)]
async fn authorization_code_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
    resources: &[String],
) -> Result<Response, TokenError> {
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

    // 4. Authenticate the client (issue #20). The presented credentials (Basic
    //    header or post body) identify the client and prove possession of its
    //    secret under its registered method; a failure is the spec-exact
    //    invalid_client. This runs BEFORE the code is burned, so a client-auth
    //    failure never consumes the one-time code.
    //
    //    Note (issue #25): for a private_key_jwt client this spends the assertion's
    //    single-use jti HERE, before the code-binding re-check (step 5) and the redeem
    //    (step 7). So a subsequent binding/redeem failure does NOT free the jti to be
    //    retried; an assertion is single-use even across a failed exchange. This is
    //    spec-acceptable (RFC 7523 jti is single-use) and is intentional: it favors
    //    replay resistance over a grace-retry of the same assertion.
    let authenticated_client = authenticate_client(state, scope, headers, &params).await?;

    // 5. The authenticated client MUST be the one the code was issued to (the
    //    Zitadel advisory class: a code for client A is not redeemable by client
    //    B). A mismatch is a uniform invalid_grant, kept separate from the
    //    invalid_client above so an unauthenticated caller cannot probe which
    //    binding failed. The remaining bindings (redirect_uri, PKCE) are re-checked
    //    the same way.
    if authenticated_client.client_id != bindings.client_id {
        return Err(TokenError::InvalidGrant);
    }
    if !bindings_match(&bindings, &params) {
        return Err(TokenError::InvalidGrant);
    }

    // 5b. Resolve the RFC 8707 resource indicators (issue #28) into the access-token
    //     target (its audience set, format, and lifetime). The requested resources
    //     must be valid, allowlisted, and a SUBSET of what was approved at
    //     authorization (a downscope, never an expansion); omitting `resource`
    //     defaults to the full approved set, or to the per-client no-resource policy
    //     when none was approved. A violation is a uniform `invalid_target`.
    let target = resolve_code_exchange_target(state, scope, &bindings, resources).await?;

    // 5f. Step-up policy re-evaluation at token issuance (RFC 9470, issue #72). The
    //     per-client and per-scope authentication requirements are re-checked against
    //     the authentication FROZEN onto the code (its recorded methods and
    //     auth_time). This is defense in depth over the authorization-endpoint check:
    //     a policy that tightened after the code was issued, or any path that reached
    //     issuance under-qualified, fails HERE with the RFC 9470 step-up error rather
    //     than minting an under-qualified token.
    if let Some(error) = enforce_step_up_policy(
        state,
        scope,
        &bindings.client_id,
        bindings.oauth_scope.as_deref(),
        &bindings.auth_methods,
        bindings.auth_time_unix_micros,
    )
    .await
    {
        return Err(error);
    }

    // 6. Mint (sign) the tokens BEFORE the consume, so a missing key or a signing
    //    failure fails closed without burning the code. The ID token stays lean by
    //    default (scope claims are served from UserInfo); the extra claims are the
    //    `claims`-parameter id_token member and, only under the non-conform
    //    conformIdTokenClaims override, the scope-derived claims (issue #15).
    let extra_claims = id_token_extra_claims(state, scope, &bindings).await;
    let minted = mint_tokens(state, scope, &bindings, &extra_claims, &target).await?;

    // Build what the redeem transaction records for the minted tokens (issue #29).
    // The ID token is always an issued_tokens row; the access token is an
    // issued_tokens row when it is an at+jwt, or an opaque_access_tokens row (in
    // the SAME redeem transaction as the consume) when it is opaque. So the access
    // token can no more be handed out without its stored row than before.
    let mut records: Vec<IssuedTokenRecord> = vec![IssuedTokenRecord {
        id: minted.id_jti,
        kind: TokenKind::Id,
    }];
    let opaque = match &minted.access {
        MintedAccessToken::Jwt { jti, .. } => {
            records.push(IssuedTokenRecord {
                id: *jti,
                kind: TokenKind::Access,
            });
            None
        }
        MintedAccessToken::Opaque {
            digest,
            jti,
            audiences,
            expires_at_unix_micros,
            ..
        } => Some(NewOpaqueAccessToken {
            token_digest: digest,
            // The grant is the consumed code's grant, bound authoritatively inside
            // redeem (from the atomic consume's RETURNING), so it is left None here.
            grant_id: None,
            // The LOCAL subject (a usr_ id), exactly as issued_tokens carries it via
            // the grant, so introspection (#22) derives the public sub the same way
            // UserInfo does; the opaque token itself carries no sub.
            subject: &bindings.subject,
            client_id: &bindings.client_id,
            // The primary audience (backward-compatible single column) and the full
            // requested-and-allowlisted set (issue #28), so introspection reports the
            // exact audiences the opaque token was minted for.
            audience: audiences.first().map_or("", String::as_str),
            audiences,
            scope: bindings.oauth_scope.as_deref(),
            jti,
            expires_at_unix_micros: *expires_at_unix_micros,
        }),
    };

    // 7. Atomically redeem: the single-use gate. On the winning call it records
    //    the issued tokens (and the opaque access-token row, when opaque) and the
    //    redeem audit in the same transaction as the consume; a miss is classified
    //    as a benign grace retry, a genuine reuse (which revokes the chain), or an
    //    expired/absent code. Attribute the audit to the client the code is for,
    //    under a fresh per-request correlation id.
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
            opaque,
            state.reuse_grace(),
        )
        .await;

    match outcome {
        // Won the race: open a refresh-token family (issue #21) and hand out the
        // tokens we pre-signed plus the refresh token. Refresh issuance runs AFTER
        // the code is consumed, so it never affects single use; a failure to open
        // the family degrades to an access+ID response without a refresh token
        // (logged), rather than failing an otherwise-successful exchange.
        Ok(RedeemOutcome::Consumed) => {
            let refresh = issue_refresh_for_code(state, scope, &bindings).await?;
            Ok(token_response(&minted, &bindings, refresh.as_deref()))
        }
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

/// Re-check the `redirect_uri` and PKCE bindings the code carries against the
/// presented request. All mismatches collapse to a single boolean, so the caller
/// returns the uniform `invalid_grant` without revealing which binding failed. The
/// `client_id` binding is re-checked separately against the AUTHENTICATED client
/// (see the exchange). This runs BEFORE the code is consumed, so a mismatch does
/// not burn the one-time code.
fn bindings_match(bindings: &CodeBindings, params: &TokenParams) -> bool {
    // The redirect_uri re-check is EXACT string against the value bound at
    // authorization (RFC 6749 4.1.3): the code was bound to the specific URI the
    // client used, so no loopback-port latitude applies here (that latitude was
    // already spent when the code was issued against the presented port).
    let redirect_ok = params
        .redirect_uri
        .as_deref()
        .is_some_and(|presented| presented == bindings.redirect_uri);
    // PKCE downgrade prevention in BOTH directions (RFC 7636, RFC 9700):
    // - a code issued WITH a challenge is redeemable ONLY with a verifier that
    //   hashes (S256) to that challenge;
    // - a code issued WITHOUT a challenge is NOT redeemable WITH a verifier (a
    //   presented verifier for a no-challenge code is a downgrade attempt), so the
    //   token request must present none.
    let presented_verifier = params
        .code_verifier
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let pkce_ok = match &bindings.code_challenge {
        Some(challenge) => {
            presented_verifier.is_some_and(|verifier| verify_s256(verifier, challenge))
        }
        None => presented_verifier.is_none(),
    };
    redirect_ok && pkce_ok
}

/// Authenticate the client for a token request through the ONE reusable seam
/// ([`client_auth::authenticate_client`], issues #20 and #25): it parses the
/// presented credentials (Basic header, post body, or a JWT assertion), resolves
/// the client's single registered method within the code's scope, verifies the
/// credentials against it, records any failure out of band, and returns the
/// authenticated client (whose `client_id` the caller re-checks against the code).
/// The introspection and revocation endpoints (#22) will call the same seam, so
/// enforcement is identical across all three.
///
/// # Errors
///
/// A parse problem is an `invalid_request`; an unknown client or a credential that
/// does not satisfy the registered method is the spec-exact, opaque `invalid_client`
/// (401, with `WWW-Authenticate: Basic` when the client attempted Basic).
async fn authenticate_client(
    state: &OidcState,
    scope: Scope,
    headers: &HeaderMap,
    params: &TokenParams,
) -> Result<AuthenticatedClient, TokenError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };
    client_auth::authenticate_client(state, scope, inputs)
        .await
        .map_err(|error| match error {
            ClientAuthError::InvalidRequest(message) => {
                TokenError::InvalidRequest(message.to_owned())
            }
            ClientAuthError::InvalidClient { via_basic } => TokenError::InvalidClient { via_basic },
        })
}

/// Mint the ID and access tokens through the signing core. A missing signing key
/// or a signing failure is an opaque `server_error`; because this runs before the
/// consume, that failure leaves the code live for a retry.
///
/// Resolve the per-client `sid` (issue #32) for a code exchange from the code's
/// authenticating SSO session, and, in doing so, ENFORCE that the SSO session is still
/// LIVE at redemption.
///
/// # Why the liveness check lives here
///
/// An authorization code is minted at the authorize endpoint and redeemed later at the
/// token endpoint. A session revoke (a logout, an operator revoke) can land IN BETWEEN.
/// Without this check the exchange would mint a brand-new LIVE refresh family, and a
/// fresh `sid`, bound to a session that is already DEAD: no cascade would ever reach
/// them (they hang off a session nothing revokes twice), so a logout would silently
/// fail to revoke the tokens minted right after it. So the code's `session_ref` is
/// resolved through the SAME authoritative read guard the authentication path uses
/// (revoked / ended / superseded / expired all refuse), BEFORE anything is minted, and
/// a session that no longer resolves is a uniform `invalid_grant`.
///
/// # Fail CLOSED
///
/// A store error is a `server_error`, never a silently session-less ID token. Dropping
/// the `sid` on a store hiccup would emit an ID token that a relying party cannot
/// correlate to any OP session, which quietly breaks back-channel logout for that
/// token while looking like a success.
///
/// A grant with NO `session_ref` at all (not an interactive code flow) legitimately has
/// no SSO session and resolves to [`None`]: no session to check, no `sid` to emit.
async fn resolve_code_exchange_sid(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
) -> Result<Option<String>, TokenError> {
    let Some(session_ref) = bindings.session_ref.as_deref() else {
        return Ok(None);
    };
    // A session_ref that does not parse in the exchange scope names no session we could
    // ever resolve: the grant is not redeemable.
    let session_id =
        SessionId::parse_in_scope(session_ref, &scope).map_err(|_| TokenError::InvalidGrant)?;
    let now_micros = epoch_micros(state.now());
    let idle_ttl = i64::try_from(state.session_idle_ttl().as_micros()).unwrap_or(i64::MAX);
    let session = state
        .store()
        .scoped(scope)
        .sessions()
        .get(&session_id, now_micros, idle_ttl)
        .await
        .map_err(|_| TokenError::ServerError)?;
    if session.is_none() {
        // Revoked, logged out, rotated away, or expired since the code was issued.
        return Err(TokenError::InvalidGrant);
    }
    let sid = state
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(state.env(), &session_id, &bindings.client_id, now_micros)
        .await
        .map_err(|_| TokenError::ServerError)?;
    Ok(Some(sid))
}

/// Resolves the environment's issuer entry (its signer and algorithm policy)
/// through the shared registry, then hands the borrowed signer and policy into the
/// pure, synchronous [`tokens::mint`]: the async key resolution is confined here,
/// the crypto stays pure.
async fn mint_tokens(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
    extra_claims: &serde_json::Map<String, serde_json::Value>,
    target: &AccessTokenTarget,
) -> Result<IssuedTokens, TokenError> {
    // Resolve the per-client `sid` (issue #32) from the code's authenticating SSO
    // session BEFORE signing, so the ID token carries a `sid` that is stable per
    // (client, session) and distinct across clients. This ALSO enforces that the SSO
    // session is still live: a code minted before a revoke and redeemed after it is an
    // invalid_grant, never a live token bound to a dead session.
    let sid = resolve_code_exchange_sid(state, scope, bindings).await?;
    let sid = sid.as_deref();
    let entry = state
        .issuer_entry(&scope)
        .await
        .ok_or(TokenError::ServerError)?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    // Honor the client's negotiated `id_token_signed_response_alg` (issue #30): sign
    // THIS client's ID token with the environment key of the algorithm DCR recorded
    // and echoed at registration, so the recorded algorithm is the algorithm the ID
    // token is actually signed under. A client with no per-client preference (every
    // non-DCR client) resolves to `None` and keeps the environment default signer.
    // The negotiation constrained the recorded algorithm to the environment's
    // actually-signable set, so a key is normally present; if one is unexpectedly
    // gone the ID token falls back to the environment default (which still verifies
    // against the published JWKS), never failing the exchange.
    let id_token_signer = client_id_token_alg(state, scope, &bindings.client_id)
        .await
        .and_then(|alg| entry.keyset().active_signer_for(state.now(), alg));
    let issuer = state.issuer_for(&scope);
    // Resolve the `sub` through the ONE shared subject-derivation function, so the
    // ID token's subject can never diverge from what `UserInfo`/introspection would
    // return for the same client and user (OIDC Core 8.1). Public today; the
    // per-client pairwise configuration is client-registration state a later issue
    // persists (see OidcState::resolve_public_subject).
    let subject = state.resolve_public_subject(&bindings.subject);
    // The access-token target (format, audience set, and lifetime) was resolved from
    // the RFC 8707 resource indicators by the caller (issue #28/#29). No resource
    // resolves to the environment default (the client id as audience), keeping the
    // existing at+jwt/UserInfo behavior intact.
    tokens::mint(
        state,
        signer,
        entry.policy(),
        &MintRequest {
            scope,
            issuer: &issuer,
            subject: &subject,
            client_id: &bindings.client_id,
            nonce: bindings.nonce.as_deref(),
            oauth_scope: bindings.oauth_scope.as_deref(),
            // acr/amr/auth_time derive from the authentication event frozen onto
            // the code at issuance, never from the token request.
            auth_methods: &bindings.auth_methods,
            auth_time_unix_micros: bindings.auth_time_unix_micros,
            // The per-client `sid` (issue #32), resolved from the authenticating SSO
            // session through the per-client session store: stable per (client,
            // session), distinct across clients.
            sid,
            // A token-endpoint ID token never carries at_hash, and the code flow
            // never carries c_hash; the front-channel/hybrid path (#17) supplies
            // them. Both are absent here by construction.
            at_hash: None,
            c_hash: None,
            extra_claims,
            id_token_signer,
        },
        target,
    )
    .map_err(|()| TokenError::ServerError)
}

/// Resolve the RFC 8707 access-token target for a code exchange (issue #28) from the
/// resources named on the token request and the resources approved at authorization
/// (frozen onto the code as `bindings.granted_resources`).
///
/// The rules (RFC 8707 section 2, RFC 9700): a named resource must be a valid
/// absolute URI, on the client's allowlist, and a SUBSET of the approved set (a
/// downscope, never an expansion); omitting `resource` uses the FULL approved set,
/// or, when NONE was approved, the per-client no-resource policy (the default
/// client-id audience, or a `refuse` that requires an explicit resource). Every
/// violation is a uniform `invalid_target`.
async fn resolve_code_exchange_target(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
    resources: &[String],
) -> Result<AccessTokenTarget, TokenError> {
    let client_id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(&bindings.client_id)
        .map_err(map_store_error)?;
    let policy = state
        .store()
        .scoped(scope)
        .clients()
        .resource_policy(&client_id)
        .await
        .map_err(map_store_error)?;
    // Every NAMED resource must be a valid indicator and on the client's allowlist.
    if !resource::resources_permitted(resources, &policy) {
        return Err(TokenError::InvalidTarget);
    }
    let effective = effective_exchange_resources(resources, &bindings.granted_resources, &policy)?;
    state
        .resolve_access_token_target(&scope, &effective, &bindings.client_id)
        .await
        .map_err(map_resource_error)
}

/// Compute the effective resource set for a code exchange or refresh (issue #28)
/// from the requested resources, the resources granted at authorization, and the
/// client's no-resource policy.
///
/// A NAMED set must be a subset of the granted set (downscope, never expansion). An
/// EMPTY named set defaults to the full granted set; if NOTHING was granted, a
/// `refuse` policy rejects (a resource is required) and otherwise it resolves to the
/// default (client-id) audience. Every violation is `invalid_target`.
fn effective_exchange_resources(
    requested: &[String],
    granted: &[String],
    policy: &ironauth_store::ClientResourcePolicy,
) -> Result<Vec<String>, TokenError> {
    if requested.is_empty() {
        if granted.is_empty() {
            if policy.require_resource_indicator {
                return Err(TokenError::InvalidTarget);
            }
            return Ok(Vec::new());
        }
        return Ok(granted.to_vec());
    }
    if !resource::is_subset(requested, granted) {
        return Err(TokenError::InvalidTarget);
    }
    Ok(requested.to_vec())
}

/// Map a resource-target resolution failure (issue #28) to the token-endpoint error:
/// an unknown/format-conflicting resource is the RFC 8707 `invalid_target`; a store
/// fault is an opaque `server_error` (fail closed).
fn map_resource_error(error: ResourceTargetError) -> TokenError {
    match error {
        ResourceTargetError::InvalidTarget => TokenError::InvalidTarget,
        ResourceTargetError::ServerError => TokenError::ServerError,
    }
}

/// The `JwsAlgorithm` the client `client_id` negotiated as its
/// `id_token_signed_response_alg` at dynamic registration (issue #30), or `None`
/// when it expressed no per-client preference (every non-DCR client, whose column
/// is NULL), the stored value is not a representable algorithm, or the client is
/// absent. `None` leaves the mint on the environment default signer.
async fn client_id_token_alg(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
) -> Option<JwsAlgorithm> {
    let id = state
        .store()
        .scoped(scope)
        .clients()
        .parse_id(client_id)
        .ok()?;
    let name = state
        .store()
        .scoped(scope)
        .clients()
        .id_token_signing_alg(&id)
        .await
        .ok()??;
    JwsAlgorithm::from_jose_name(&name)
}

/// Build the extra standard claims to place in the ID token (issue #15).
///
/// The spec-conform default keeps the ID token lean: scope-derived claims are
/// served from `UserInfo`, so nothing is added unless the request explicitly asked
/// for ID-token claims through the `claims` parameter's `id_token` member, or the
/// environment sets the non-conform `conformIdTokenClaims`. When neither applies,
/// this returns an empty map WITHOUT reading the store.
///
/// When something is due, it reads the user's stored claim document once and
/// releases claims through the ONE shared [`assemble_claims`] function, exactly as
/// `UserInfo` does, so the two placements can never derive a different set:
///
/// - the `id_token` claims-member is always honored (its explicitly requested
///   claims), and
/// - under `conformIdTokenClaims`, the granted scope's claim set is additionally
///   copied in (the documented non-conform legacy placement).
///
/// A store read failure is fail-open (an empty extra set, logged): the ID token
/// simply omits the scope/requested claims rather than failing issuance, which
/// only ever under-claims (the authoritative copy is still at `UserInfo`).
async fn id_token_extra_claims(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
) -> serde_json::Map<String, serde_json::Value> {
    let claims_request = bindings
        .claims_request
        .as_deref()
        .and_then(|raw| ClaimsRequest::parse(raw).ok())
        .unwrap_or_default();
    let conform = state.conform_id_token_claims();
    // Nothing to add: no id_token claims-member and not in the copy-in mode.
    if !conform && claims_request.id_token().is_empty() {
        return serde_json::Map::new();
    }
    let bag = match state
        .store()
        .scoped(scope)
        .users()
        .claims_for_subject(&bindings.subject)
        .await
    {
        Ok(Some(raw)) => serde_json::from_str(&raw).unwrap_or_default(),
        // No user record, or an unreadable/malformed claim document: under-claim
        // rather than fail issuance. The authoritative claims are at UserInfo.
        Ok(None) => serde_json::Map::new(),
        Err(error) => {
            tracing::warn!(%error, "could not read user claims for the ID token; omitting them");
            serde_json::Map::new()
        }
    };
    // Scope-derived claims are copied in ONLY under the non-conform override; the
    // id_token claims-member is always honored. Passing an empty scope set when the
    // override is off keeps the spec-conform ID token free of scope-derived claims.
    let granted = if conform {
        parse_scope_set(bindings.oauth_scope.as_deref())
    } else {
        std::collections::BTreeSet::new()
    };
    assemble_claims(&bag, &granted, claims_request.id_token())
}

/// Build the `200 OK` token response (RFC 6749 5.1) from the pre-minted tokens,
/// including the refresh token (issue #21) when one was issued.
fn token_response(
    minted: &IssuedTokens,
    bindings: &CodeBindings,
    refresh_token: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({
        "access_token": minted.access.token(),
        "token_type": "Bearer",
        "expires_in": minted.expires_in_secs,
        "id_token": minted.id_token,
    });
    if let Some(oauth_scope) = &bindings.oauth_scope {
        body["scope"] = serde_json::json!(oauth_scope);
    }
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = serde_json::json!(refresh_token);
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
pub(crate) fn token_ok(body: &str) -> Response {
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
pub(crate) fn map_store_error(error: StoreError) -> TokenError {
    match error {
        StoreError::NotFound => TokenError::InvalidGrant,
        other => {
            tracing::error!(error = %other, "token endpoint store error");
            TokenError::ServerError
        }
    }
}

// ===========================================================================
// The refresh-token grant (RFC 6749 6, RFC 9700 2.2.2, OAuth 2.1, issue #21).
// ===========================================================================

/// Open a refresh-token family for a just-consumed code (issue #21), returning the
/// plaintext refresh token to hand to the client. Returns `Ok(None)` when the
/// environment does not issue refresh tokens, or (fail-soft) when opening the
/// family faulted: such a fault only costs the client a refresh token on this
/// exchange, never the whole exchange, so it is logged and swallowed.
///
/// The family is OFFLINE when the granted scope carried `offline_access` (so it
/// survives RP logout, OIDC Back-Channel Logout 2.7); otherwise it is
/// session-bound (revoked when the RP session is logged out). `offline_access` is
/// honored here because the code grant IS the flow that returns an authorization
/// code; the consent for it was enforced at the authorization endpoint.
///
/// A session-bound open is REFUSED (issue #32) when the SSO session it would hang
/// off was revoked in the window between the redeem's liveness read and this open:
/// no family is created and this returns `Err(TokenError::InvalidGrant)`, so a
/// logout that already cascaded cannot be outlived by a family opened just after
/// it. That is a hard failure, not a fail-soft, because a session-bound token that
/// escaped its logout is the exact invariant this milestone protects.
/// Re-evaluate the per-client and per-scope step-up authentication policy at token
/// issuance and on refresh (RFC 9470, issue #72), against the authentication FROZEN
/// on the code or the refresh family (its recorded methods and `auth_time`).
///
/// Returns [`Some`] with the RFC 9470 step-up error (carrying the `acr_values` and
/// `max_age` the client must request on the retry) when the frozen authentication
/// does not satisfy the requirement, and [`None`] when it does or no requirement
/// applies. A missing `auth_time` against a max-age policy fails closed (the
/// [`step_up::evaluate`] rule), so a refresh can never silently extend a lapsed
/// window. A client that no longer resolves, or a store fault while assembling the
/// requirement, is treated as "no requirement" so this check never turns a
/// transient read fault into a spurious step-up (the authorization-endpoint check
/// is the primary gate).
async fn enforce_step_up_policy(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    oauth_scope: Option<&str>,
    auth_methods: &str,
    auth_time_unix_micros: Option<i64>,
) -> Option<TokenError> {
    let Ok(id) = ClientId::parse_in_scope(client_id, &scope) else {
        return None;
    };
    // FAIL CLOSED (issue #72 INFO): a transient store fault while assembling the
    // requirement must NOT be read as "no requirement", or a step-up policy added AFTER
    // the code or refresh family was issued could be silently skipped on a store blip and
    // an under-evaluated token minted. A genuinely absent client carries no policy (no
    // requirement); any other store fault denies with a server error. Authorize stays the
    // primary gate.
    let client = match state.store().scoped(scope).clients().get(&id).await {
        Ok(client) => client,
        Err(StoreError::NotFound) => return None,
        Err(_) => return Some(TokenError::ServerError),
    };
    let (requirement, policy_read_faulted) =
        step_up::requirement_for_request(state, scope, &client, oauth_scope, None, None).await;
    if policy_read_faulted {
        return Some(TokenError::ServerError);
    }
    if requirement.is_empty() {
        return None;
    }
    let order = state.acr_order();
    let achieved = authn::achieved_acr(&authn::parse_methods(auth_methods));
    let now_micros = epoch_micros(state.now());
    match step_up::evaluate(
        &requirement,
        achieved,
        auth_time_unix_micros,
        now_micros,
        &order,
    ) {
        step_up::Satisfaction::Satisfied => None,
        step_up::Satisfaction::NeedsStepUp { .. } => {
            Some(TokenError::InsufficientUserAuthentication {
                acr_values: requirement.min_acr,
                max_age: requirement.max_auth_age_secs,
            })
        }
    }
}

async fn issue_refresh_for_code(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
) -> Result<Option<String>, TokenError> {
    if !state.issue_refresh_tokens() {
        return Ok(None);
    }
    let offline = scope_contains(bindings.oauth_scope.as_deref(), OFFLINE_ACCESS_SCOPE);
    let minted = tokens::mint_refresh_token(state, &scope);
    let family_id = RefreshFamilyId::generate(state.env(), &scope);
    let now = state.now();
    let created = epoch_micros(now);
    let idle_expires = epoch_micros(
        now.checked_add(state.refresh_idle_ttl(offline))
            .unwrap_or(now),
    );
    let absolute_expires = epoch_micros(
        now.checked_add(state.refresh_max_lifetime(offline))
            .unwrap_or(now),
    );
    let actor = client_actor(state, scope, &bindings.client_id);
    let correlation = CorrelationId::generate(state.env());
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .refresh()
        .issue(
            state.env(),
            NewRefreshFamily {
                family_id: &family_id,
                token_jti: &minted.jti,
                token_digest: &minted.digest,
                grant_id: &bindings.grant_id,
                subject: &bindings.subject,
                client_id: &bindings.client_id,
                scope: bindings.oauth_scope.as_deref(),
                auth_methods: &bindings.auth_methods,
                // Freeze the code's recorded auth_time onto the family so a refresh
                // can re-evaluate a step-up max-age window without a new
                // authentication (RFC 9470, issue #72).
                auth_time_unix_micros: bindings.auth_time_unix_micros,
                offline,
                created_at_unix_micros: created,
                idle_expires_at_unix_micros: idle_expires,
                absolute_expires_at_unix_micros: absolute_expires,
            },
        )
        .await;
    match result {
        Ok(RefreshFamilyOpenOutcome::Opened) => Ok(Some(minted.token)),
        // The bound SSO session was revoked in the open window, so no session-bound
        // family was created: fail the exchange closed rather than hand back a token
        // no logout could ever reach.
        Ok(RefreshFamilyOpenOutcome::SessionNotLive) => Err(TokenError::InvalidGrant),
        Err(error) => {
            tracing::warn!(%error, "could not open a refresh-token family; issuing without a refresh token");
            Ok(None)
        }
    }
}

/// Re-check a refresh token subject's USER LIFECYCLE state before minting (issue
/// #52, fence completeness). The lifecycle machine says a blocked/disabled/deleted
/// user cannot authenticate, and block/disable cascades the user's sessions and
/// non-offline refresh families; but an `offline_access` family DELIBERATELY survives
/// that cascade (issue #21), so without this re-check a user fenced AFTER the family
/// was opened could keep minting fresh access tokens through the surviving token, and
/// the account would not actually be fenced. This is the authoritative single-point
/// fence: the invariant is that after block/disable/delete a user obtains NO new
/// tokens by ANY path (authorize, refresh, or an existing offline token).
///
/// Fails CLOSED (`invalid_grant`) when the subject is not authenticatable (blocked,
/// disabled, pending-verification) or is absent/deleted, and treats a store fault as
/// fail-closed too, never fail-open. A NORMAL active (or scheduled-offboarding) user
/// is authenticatable, so an ordinary refresh is unaffected.
async fn ensure_subject_can_authenticate(
    state: &OidcState,
    scope: Scope,
    subject: &str,
) -> Result<(), TokenError> {
    match state
        .store()
        .scoped(scope)
        .users()
        .state_for_subject(subject)
        .await
    {
        Ok(Some(user_state)) if user_state.can_authenticate() => Ok(()),
        Ok(_) => Err(TokenError::InvalidGrant),
        Err(error) => Err(map_store_error(error)),
    }
}

/// The `refresh_token` grant (RFC 6749 6, issue #21): exchange a rotating refresh
/// token for a fresh access token, applying the graduated rotation policy and
/// reuse detection.
///
/// The refresh token declares its own `(tenant, environment)` scope through its
/// embedded `rft_` routing handle, so the GLOBAL `/token` endpoint recovers the
/// scope and runs the RLS-scoped resolve. The client is authenticated the same way
/// as the code grant and MUST be the family's client. A narrowing `scope` request
/// parameter is not honored: the original granted scope is refreshed (RFC 6749 6
/// permits refreshing the originally granted scope). The single-use, rotation, and
/// reuse decision is the store's atomic [`ActingRefreshRepo::redeem`]; this handler
/// only pre-mints the access token and the successor, then maps the outcome.
// The linear refresh flow (resolve, authenticate, lifecycle re-check, rotation
// decision, resource downscope, step-up re-evaluation, mint, atomic redeem) reads
// best as one function.
#[allow(clippy::too_many_lines)]
async fn refresh_token_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
    resources: &[String],
) -> Result<Response, TokenError> {
    // 1. refresh_token: present, and it declares its own scope through its handle.
    let presented = params
        .refresh_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest("refresh_token is required".to_owned()))?;
    let scope = parse_refresh_scope(presented).ok_or(TokenError::InvalidGrant)?;

    // 2. Authenticate the client through the shared seam.
    let authenticated_client = authenticate_client(state, scope, headers, &params).await?;

    // 3. Resolve the presented token's live state (read only). Absent is a uniform
    //    invalid_grant.
    let resolution = state
        .store()
        .scoped(scope)
        .refresh()
        .load(presented)
        .await
        .map_err(map_store_error)?
        .ok_or(TokenError::InvalidGrant)?;

    // 4. The authenticated client MUST be the family's client, and the family and
    //    its grant must be live. A revoked family (a prior reuse, an RP logout, or a
    //    grant revoke) is a uniform invalid_grant; the reuse event, if one was due,
    //    was already emitted when the family was revoked.
    if authenticated_client.client_id != resolution.client_id || !resolution.active {
        return Err(TokenError::InvalidGrant);
    }

    // 4b. Re-check the token subject's USER LIFECYCLE state (issue #52) before minting
    //     anything: a user blocked, disabled, or deleted AFTER a SURVIVING
    //     offline_access family was opened (issue #21) must not keep minting. Fail
    //     closed (including on a store fault); a normal active user is unaffected.
    ensure_subject_can_authenticate(state, scope, &resolution.subject).await?;

    // 5. Resolve the client's posture and rotation override to decide whether a live
    //    token rotates (public/unbound: always; confidential/bound: past the TTL
    //    threshold).
    let client_id = ClientId::parse_in_scope(&resolution.client_id, &scope)
        .map_err(|_| TokenError::InvalidGrant)?;
    let record = state
        .store()
        .scoped(scope)
        .clients()
        .auth_record(&client_id)
        .await
        .map_err(map_store_error)?;
    let now_micros = epoch_micros(state.now());
    let rotate = decide_rotate(state, &record, &resolution, now_micros);

    // 5c. Resolve the RFC 8707 resource indicators for this refresh (issue #28). A
    //     refresh may DOWNSCOPE to a subset of the resources approved at the original
    //     authorization but can NEVER expand beyond them; omitting `resource` keeps
    //     the full approved set. A violation is a uniform `invalid_target`.
    let target = resolve_refresh_target(state, scope, &client_id, &resolution, resources).await?;

    // 5d. Step-up policy re-evaluation on refresh (RFC 9470, issue #72). A refresh
    //     that would mint an access token for a scope whose auth-age window has
    //     LAPSED (or whose recorded acr is below the required floor) triggers the
    //     step-up requirement rather than silently succeeding with a stale
    //     acr/auth_time. The requirement is evaluated against the authentication
    //     FROZEN onto the family (its recorded methods and auth_time); a family that
    //     carried no auth_time fails closed against a max-age policy (no silent
    //     extend). The client must re-authorize with the carried acr_values/max_age.
    if let Some(error) = enforce_step_up_policy(
        state,
        scope,
        &resolution.client_id,
        resolution.scope.as_deref(),
        &resolution.auth_methods,
        resolution.auth_time_unix_micros,
    )
    .await
    {
        return Err(error);
    }

    // 6. Mint the refreshed access token. No ID token is re-minted: no new
    //    authentication happened, so the ID token stays with the code exchange.
    let (minted, expires_in) = mint_refresh_access(state, scope, &resolution, &target).await?;

    // 7. Pre-generate the successor refresh token, used when rotating or on a
    //    within-grace concurrent refresh.
    let successor = tokens::mint_refresh_token(state, &scope);
    let now = state.now();
    let successor_idle = epoch_micros(
        now.checked_add(state.refresh_idle_ttl(resolution.offline))
            .unwrap_or(now),
    );
    let next_gen = i32::try_from(resolution.generation.saturating_add(1)).unwrap_or(i32::MAX);

    // 8. Build the access-token records to persist against the grant.
    let (access_records, opaque) = refresh_access_records(&minted, &resolution);

    // 9. Atomically redeem: the authoritative single-use, rotation, and reuse gate.
    let actor = client_actor(state, scope, &resolution.client_id);
    let correlation = CorrelationId::generate(state.env());
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .refresh()
        .redeem(
            state.env(),
            RefreshRedeem {
                presented_token: presented,
                rotate,
                successor: RotatedRefreshToken {
                    jti: &successor.jti,
                    token_digest: &successor.digest,
                    generation: next_gen,
                    idle_expires_at_unix_micros: successor_idle,
                },
                access_records: &access_records,
                opaque,
                grace: state.refresh_rotation_grace(),
            },
        )
        .await;

    match outcome {
        // Rotated (policy): the atomic-rotate winner. Return the fresh access token
        // AND the newly minted successor refresh token.
        Ok(RefreshRedeemOutcome::Rotated) => Ok(refresh_response(
            &minted,
            expires_in,
            resolution.scope.as_deref(),
            Some(&successor.token),
        )),
        // A within-grace benign concurrent refresh (a loser of the atomic rotate, a
        // multi-tab retry, or a lost rotation response): return ONLY a fresh access
        // token. No new refresh leaf was minted (the family's single live leaf is the
        // winner's successor A, which the well-behaved client already holds or reads
        // from shared storage), so per RFC 6749 5.1 the OPTIONAL refresh_token field
        // is OMITTED rather than forking the family. A client that ENTIRELY lost the
        // winner's response never receives A and must re-authenticate: an accepted,
        // documented limitation of an AC7-respecting design (no replayable material at
        // rest, so no cache-and-replay).
        Ok(RefreshRedeemOutcome::RefreshedWithinGrace) => Ok(refresh_response(
            &minted,
            expires_in,
            resolution.scope.as_deref(),
            None,
        )),
        // Not rotated (a confidential/bound client under the threshold): a fresh
        // access token and the SAME refresh token.
        Ok(RefreshRedeemOutcome::NotRotated) => Ok(refresh_response(
            &minted,
            expires_in,
            resolution.scope.as_deref(),
            Some(presented),
        )),
        // A genuine reuse revoked the whole family (audited once in the redeem
        // transaction). Meter it and return the uniform invalid_grant.
        Ok(RefreshRedeemOutcome::Reused) => {
            metrics::counter!(REFRESH_REUSE_TOTAL).increment(1);
            tracing::warn!("refresh token reuse detected; family revoked");
            Err(TokenError::InvalidGrant)
        }
        // Absent, expired, or a revoked family/grant: plain invalid_grant.
        Ok(RefreshRedeemOutcome::Invalid) => Err(TokenError::InvalidGrant),
        // The redeem itself faulted, so a revoke that was due did NOT commit. Meter
        // it and fail closed.
        Err(error) => {
            metrics::counter!(REDEEM_ERROR_TOTAL).increment(1);
            Err(map_store_error(error))
        }
    }
}

/// Recover the `(tenant, environment)` scope a refresh token declares through its
/// embedded `rft_` routing handle (issue #21). The wire form is
/// `ira_rt_<rft_...>~<secret>`: strip the product prefix, take the handle up to the
/// delimiter, and parse its declared scope. A malformed token yields [`None`],
/// which the caller maps to a uniform `invalid_grant`. A forged handle recovers
/// nothing usable: the whole-token digest still binds the handle to the secret, so
/// a token cannot be relocated to another scope.
fn parse_refresh_scope(token: &str) -> Option<Scope> {
    let rest = token.strip_prefix(tokens::OPAQUE_REFRESH_TOKEN_PREFIX)?;
    let handle = rest.split(tokens::OPAQUE_ACCESS_TOKEN_DELIMITER).next()?;
    RefreshTokenId::parse_declared_scope(handle)
        .ok()
        .map(|id| id.scope())
}

/// Decide whether a LIVE (non-superseded) refresh token rotates (issue #21).
///
/// A per-client override wins: `always` rotates on every refresh, `threshold`
/// rotates only past the configured fraction of TTL. With no override the policy is
/// derived from the client's posture: a PUBLIC (sender-unbound) client always
/// rotates; a CONFIDENTIAL client rotates only once the token has passed the
/// threshold fraction of its idle TTL. There is no sender-constrained (DPoP/mTLS)
/// binding in this build, so every client is sender-unbound and the posture split
/// is public-versus-confidential.
fn decide_rotate(
    state: &OidcState,
    record: &ClientAuthRecord,
    resolution: &RefreshTokenResolution,
    now_micros: i64,
) -> bool {
    let use_threshold = match record.refresh_rotation.as_deref() {
        // An explicit override.
        Some("always") => false,
        Some("threshold") => true,
        // Derived from posture: a public client always rotates; a confidential one
        // uses the threshold. An unrecognized stored value derives the same way.
        _ => record.auth_method != ClientAuthMethod::None.as_str(),
    };
    if !use_threshold {
        return true;
    }
    // Rotate once the token has passed the threshold fraction of its idle TTL.
    let span = resolution
        .idle_expires_at_unix_micros
        .saturating_sub(resolution.issued_at_unix_micros);
    let percent = i64::try_from(state.refresh_rotation_threshold_percent()).unwrap_or(70);
    let advance = span.saturating_mul(percent) / 100;
    let threshold_instant = resolution.issued_at_unix_micros.saturating_add(advance);
    now_micros >= threshold_instant
}

/// Mint the refreshed access token (issue #21) through the same signing core and
/// format selection as the code exchange, so a refreshed access token is shaped
/// identically to a freshly issued one. The `acr`/`auth_methods` derive from the
/// authentication event frozen onto the family at issuance (never re-derived).
async fn mint_refresh_access(
    state: &OidcState,
    scope: Scope,
    resolution: &RefreshTokenResolution,
    target: &AccessTokenTarget,
) -> Result<(MintedAccessToken, i64), TokenError> {
    let entry = state
        .issuer_entry(&scope)
        .await
        .ok_or(TokenError::ServerError)?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    let subject = state.resolve_public_subject(&resolution.subject);
    let extra_claims = serde_json::Map::new();
    tokens::mint_access_token(
        state,
        signer,
        entry.policy(),
        &MintRequest {
            scope,
            issuer: &issuer,
            subject: &subject,
            client_id: &resolution.client_id,
            nonce: None,
            oauth_scope: resolution.scope.as_deref(),
            auth_methods: &resolution.auth_methods,
            auth_time_unix_micros: None,
            // The refresh path mints only an access token (no ID token), so `sid`
            // (issue #32, an ID-token claim) is inert here.
            sid: None,
            at_hash: None,
            c_hash: None,
            extra_claims: &extra_claims,
            // The refresh path mints only an access token (no ID token), so the
            // per-client id_token signer (#30) is inert here; mint_access_token
            // never reads it.
            id_token_signer: None,
        },
        target,
    )
    .map_err(|()| TokenError::ServerError)
}

/// Resolve the RFC 8707 access-token target for a refresh (issue #28) from the
/// resources named on the refresh request and the resources approved at the original
/// authorization (read from the family's grant as `resolution.granted_resources`).
///
/// A refresh may DOWNSCOPE to a subset of the approved resources but can NEVER expand
/// beyond them (RFC 8707 / RFC 9700); omitting `resource` keeps the full approved
/// set, or falls to the per-client no-resource policy when none was approved. Every
/// violation is a uniform `invalid_target`.
async fn resolve_refresh_target(
    state: &OidcState,
    scope: Scope,
    client_id: &ClientId,
    resolution: &RefreshTokenResolution,
    resources: &[String],
) -> Result<AccessTokenTarget, TokenError> {
    let policy = state
        .store()
        .scoped(scope)
        .clients()
        .resource_policy(client_id)
        .await
        .map_err(map_store_error)?;
    if !resource::resources_permitted(resources, &policy) {
        return Err(TokenError::InvalidTarget);
    }
    let effective =
        effective_exchange_resources(resources, &resolution.granted_resources, &policy)?;
    state
        .resolve_access_token_target(&scope, &effective, &resolution.client_id)
        .await
        .map_err(map_resource_error)
}

/// Build what the redeem transaction records for the refreshed access token: an
/// `at+jwt` is an `issued_tokens` row (its `jti`), an opaque token an
/// `opaque_access_tokens` row (digest and metadata), exactly as the code exchange
/// does, so grant-chain revocation reaches a refreshed access token too (issue #21).
fn refresh_access_records<'a>(
    minted: &'a MintedAccessToken,
    resolution: &'a RefreshTokenResolution,
) -> (Vec<IssuedTokenRecord>, Option<NewOpaqueAccessToken<'a>>) {
    match minted {
        MintedAccessToken::Jwt { jti, .. } => (
            vec![IssuedTokenRecord {
                id: *jti,
                kind: TokenKind::Access,
            }],
            None,
        ),
        MintedAccessToken::Opaque {
            digest,
            jti,
            audiences,
            expires_at_unix_micros,
            ..
        } => (
            Vec::new(),
            Some(NewOpaqueAccessToken {
                token_digest: digest,
                // Bound to the family's grant inside redeem (grant_text), so this is
                // left None, exactly as the code exchange does.
                grant_id: None,
                subject: &resolution.subject,
                client_id: &resolution.client_id,
                audience: audiences.first().map_or("", String::as_str),
                audiences,
                scope: resolution.scope.as_deref(),
                jti,
                expires_at_unix_micros: *expires_at_unix_micros,
            }),
        ),
    }
}

/// Build the `200 OK` refresh-response (RFC 6749 5.1) for the refresh grant (issue
/// #21): the fresh access token, its lifetime, an OPTIONAL refresh token, and the
/// granted scope. `refresh_token` is [`Some`] for a policy rotation (the new
/// successor) or an unchanged confidential-under-threshold token, and [`None`] for a
/// within-grace benign concurrent refresh, which mints no new leaf and so omits the
/// optional field rather than forking the family.
fn refresh_response(
    minted: &MintedAccessToken,
    expires_in: i64,
    scope: Option<&str>,
    refresh_token: Option<&str>,
) -> Response {
    let mut body = serde_json::json!({
        "access_token": minted.token(),
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = serde_json::json!(refresh_token);
    }
    if let Some(scope) = scope {
        body["scope"] = serde_json::json!(scope);
    }
    token_ok(&body.to_string())
}

/// Whether a space-separated OAuth scope value contains `needle`.
fn scope_contains(scope: Option<&str>, needle: &str) -> bool {
    scope.is_some_and(|value| value.split_whitespace().any(|token| token == needle))
}
