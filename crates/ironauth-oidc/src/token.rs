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

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_jose::{Confirmation, DpopExpectations, JwsAlgorithm, validate_dpop_proof};
use ironauth_store::{
    ActorRef, AuthorizationCodeId, ClientAuthRecord, ClientId, CodeBindings, CorrelationId,
    IssuedTokenRecord, NewOpaqueAccessToken, NewRefreshFamily, OrganizationId, RedeemOutcome,
    RefreshFamilyId, RefreshFamilyOpenOutcome, RefreshRedeem, RefreshRedeemOutcome, RefreshTokenId,
    RefreshTokenResolution, RotatedRefreshToken, Scope, ServiceId, SessionId, StoreError,
    StoredClientId, TokenKind, TokenSizeReason, UserId,
};
use serde::Deserialize;

use crate::authn;
use crate::claims_request::ClaimsRequest;
// The `DPoP` proof header and the `POST` `htm` token are defined ONCE in `crate::dpop`
// and shared with `/userinfo` and the authorization challenge endpoint, so the three
// readers cannot drift onto different literals.
use crate::client_auth::{
    self, AuthenticatedClient, ClientAuthError, ClientAuthInputs, ClientAuthMethod,
};
use crate::dpop::{DPOP_HEADER, DPOP_HTM_POST, token_type_for_dpop};
use crate::error::TokenError;
use crate::issuer::{IssuerEntry, IssuerResolution};
use crate::permission_budget::{
    PermissionBudget, PermissionBudgetOutcome, PermissionWithheldReason,
};
use crate::pkce::verify_s256;
use crate::policy_trace::PermissionBudgetEvent;
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
    /// The CIBA `auth_req_id` (issue #131), presented by a client polling for the tokens its
    /// backchannel authentication request will produce once the user approves. A bearer
    /// credential, so it is redacted from `Debug`.
    pub auth_req_id: Option<String>,
    /// The requested OAuth `scope` for the `client_credentials` grant (RFC 6749
    /// 4.4.2, issue #23) and the JWT bearer assertion grant (RFC 7521, issue #26).
    /// Optional; when present it is validated/normalized and echoed into the issued
    /// token.
    pub scope: Option<String>,
    /// The device code to poll for the RFC 8628 device grant (issue #24). A bearer
    /// credential the constrained device presents on every poll, so it is redacted
    /// from `Debug` and never logged in plaintext.
    pub device_code: Option<String>,
    /// The RFC 8693 section 2.1 `subject_token`: the token being exchanged, representing
    /// the identity the issued token will act for (issue #125). A bearer credential, so it
    /// is redacted from `Debug`.
    pub subject_token: Option<String>,
    /// The RFC 8693 `subject_token_type`, identifying what `subject_token` is. REQUIRED
    /// with it: the spec makes the type explicit rather than sniffed, so a caller cannot
    /// have one kind of token read as another.
    pub subject_token_type: Option<String>,
    /// The RFC 8693 `actor_token`: who is acting on the subject's behalf, present only for
    /// delegation. A bearer credential, so it is redacted from `Debug`.
    pub actor_token: Option<String>,
    /// The RFC 8693 `actor_token_type`, REQUIRED whenever `actor_token` is present.
    pub actor_token_type: Option<String>,
    /// The RFC 8693 `requested_token_type`: what the client wants back. Optional; omitted
    /// means the client's configured default access-token format.
    pub requested_token_type: Option<String>,
    /// The RFC 8693 `audience`: the logical name of the target service the issued token is
    /// for. Narrowing only, never widening.
    pub audience: Option<String>,
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
            // The CIBA `auth_req_id` is a live bearer credential: presence only. It was
            // safe by OMISSION for one release (this impl ends
            // `finish_non_exhaustive`), which is the kind of safety a later edit removes
            // without tripping anything, so it is now stated rather than inferred.
            .field("has_auth_req_id", &self.auth_req_id.is_some())
            // Both exchange tokens are bearer credentials: presence only, never the value.
            .field("has_subject_token", &self.subject_token.is_some())
            .field("subject_token_type", &self.subject_token_type)
            .field("has_actor_token", &self.actor_token.is_some())
            .field("actor_token_type", &self.actor_token_type)
            .field("requested_token_type", &self.requested_token_type)
            .field("audience", &self.audience)
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
        // CIBA does not compose with resource indicators in this issue, for the same reason
        // the client-credentials grant does not: the approval carries no resource ceiling to
        // downscope from. Issue #937 is where that ceiling gets built.
        Some(GrantType::Ciba) => crate::ciba_grant::ciba_grant(state, headers, params).await,
        // The RFC 8693 exchange DOES compose with resource indicators: `resource` and the
        // RFC 8693 `audience` parameter both name a target service, and the handler unions
        // them so naming one cannot silently widen past the other.
        Some(GrantType::TokenExchange) => {
            crate::token_exchange::token_exchange_grant(state, headers, params, &resources).await
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

    // 4-bis. The ONE shared grant-restriction seam (issue #763), FIRST among the
    //        post-authentication checks. Placed here rather than later so a client that
    //        may not use this grant is refused before any grant-specific work: a late
    //        placement makes the reported error depend on which validation happens to
    //        fail first, which is how `every_grant_handler_consults_the_shared_seam`
    //        caught it sitting after the code load.
    enforce_registered_grant_for(state, &authenticated_client, GrantType::AuthorizationCode)?;

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

    // 5g. Resolve any DPoP proof (RFC 9449, issue #368) BEFORE minting or consuming.
    //     A valid proof binds the issued tokens to its key (the at+jwt gets a `cnf`
    //     claim, the opaque token and the refresh family store the jkt); no proof is
    //     the unchanged bearer path. A present-but-invalid or replayed proof is a
    //     uniform invalid_dpop_proof that never burns the code. Binding is
    //     opportunistic: a client that sent a proof gets a bound token or this error,
    //     never a silent bearer token.
    let dpop_confirmation = resolve_dpop_binding(state, headers)?;
    // 5g-bis. The DPoP-by-default posture (issue #124): a PUBLIC client must have
    //         produced a binding above unless its registration is explicitly relaxed.
    //         Placed after the opportunistic resolve so a client that DID send a valid
    //         proof passes here without a second check, and before the code is
    //         consumed so a refusal leaves the code live for the client's retry.
    enforce_public_client_dpop(&authenticated_client, dpop_confirmation.as_ref())?;
    let dpop_jkt = dpop_confirmation.as_ref().map(Confirmation::value);

    // 5h. A code that is itself SENDER-CONSTRAINED (issue #368) narrows 5g's opportunistic
    //     rule to a mandatory one: the proof must be present and must be for the exact key
    //     frozen onto the code. Only the browserless first-party challenge sets that
    //     binding, and only from an `auth_session` that was device-bound, so this is a no-op
    //     for every browser code and for an unbound browserless one.
    enforce_code_dpop_binding(bindings.dpop_jkt.as_deref(), dpop_jkt)?;

    // 6. Mint (sign) the tokens BEFORE the consume, so a missing key or a signing
    //    failure fails closed without burning the code. The ID token stays lean by
    //    default (scope claims are served from UserInfo); the extra claims are the
    //    `claims`-parameter id_token member and, only under the non-conform
    //    conformIdTokenClaims override, the scope-derived claims (issue #15).
    let mut extra_claims = id_token_extra_claims(state, scope, &bindings).await;
    //    Plus the claims an external policy decision point or FGA contributes (issue #100).
    //    Merged HERE and not inside `id_token_extra_claims`, because that function returns
    //    early when the client asked for no `claims` member: these claims are the
    //    OPERATOR's configuration, not the client's request, and a client that asks for
    //    nothing must still receive them.
    merge_enriched_claims(state, scope, &bindings, &mut extra_claims).await;
    //    Then the client's DECLARATIVE MAPPING (issue #113 criterion 4), which is the last thing
    //    to touch these claims and the only one that may REMOVE any. It runs after enrichment
    //    deliberately: an operator who filters `groups` means the groups that reached the token,
    //    whichever layer contributed them, and a mapping that ran first would filter a set the
    //    enrichment then refilled.
    let access_extra_claims = apply_claims_mapping(
        state,
        scope,
        &bindings.client_id,
        // The wire value, from the registry, not a literal beside it. Issue #113 asks the
        // grant to be identified in the payload, and a hook that gates on it is reading
        // this string: a door with its own copy can hand a guest a grant name the
        // endpoint does not accept, and only a test comparing two literals would notice.
        crate::registry::GrantType::AuthorizationCode.as_str(),
        Some(&bindings.subject),
        &mut extra_claims,
    )
    .await?;
    let minted = mint_tokens(
        state,
        scope,
        &bindings,
        &extra_claims,
        &access_extra_claims,
        &target,
        dpop_confirmation.as_ref(),
    )
    .await?;

    // Record a token size (claim bloat) event for the M9 warnings read, best effort and off
    // the mint path (issue #91): only a token whose serialized size crosses the bloat
    // threshold is recorded, and the token itself is never captured (only its byte size and
    // claim count). The minted token below is returned unchanged regardless of this capture.
    crate::policy_trace::record_token_size_event(
        state,
        scope,
        &bindings.client_id,
        &minted.id_token,
    )
    .await;

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
            // The DPoP key thumbprint when a valid proof bound this exchange (issue
            // #368), else None for a plain bearer token. Stored so a resource-server
            // verify (a follow-up) can require a matching proof.
            dpop_jkt,
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
            let refresh = issue_refresh_for_code(state, scope, &bindings, dpop_jkt).await?;
            Ok(token_response(
                &minted,
                &bindings,
                refresh.as_deref(),
                dpop_jkt.is_some(),
            ))
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

/// Read and validate a `DPoP` proof (RFC 9449) presented with the token request,
/// returning the confirmation to bind the issued tokens to.
///
/// Binding is OPPORTUNISTIC (issue #368): with NO `DPoP` header this returns
/// `Ok(None)` and the exchange issues a plain bearer token, byte-identical to
/// before. With a proof present it is validated against the token endpoint's
/// expectations (`htm = POST`, the normalized `htu` derived from the per-environment
/// issuer, the freshness window) and checked for `jti` replay; on success it returns
/// `Ok(Some(Confirmation::Jkt(..)))` so the caller binds the at+jwt (`cnf`), the
/// opaque access token, and the refresh family to that proof key.
///
/// The response is never a client oracle. EVERY failure collapses to one uniform
/// [`TokenError::InvalidDpopProof`] (a malformed or unverifiable proof, a wrong
/// `htm`/`htu`/`typ`, a stale or future `iat`, a missing or replayed `jti`, or MORE
/// THAN ONE `DPoP` header all map to it), and the granular reason is logged
/// server-side only. A client that DID present a proof therefore always gets a bound
/// token or this error, never a silent downgrade to a bearer token.
///
/// This runs BEFORE the code is consumed, so a bad proof never burns the one-time
/// code (it stays live for the legitimate client's retry).
fn resolve_dpop_binding(
    state: &OidcState,
    headers: &HeaderMap,
) -> Result<Option<Confirmation>, TokenError> {
    // RFC 9449: exactly one DPoP header. Zero is the bearer path; more than one is
    // malformed and rejected uniformly.
    let mut proofs = headers.get_all(DPOP_HEADER).iter();
    let Some(first) = proofs.next() else {
        return Ok(None);
    };
    if proofs.next().is_some() {
        tracing::warn!("rejecting a token request that carried more than one DPoP header");
        return Err(TokenError::InvalidDpopProof);
    }
    let Ok(proof_jws) = first.to_str() else {
        tracing::warn!("rejecting a DPoP header that is not valid text");
        return Err(TokenError::InvalidDpopProof);
    };

    // htu is normalized to the token endpoint's scheme+authority+path with no query
    // or fragment (RFC 9449 section 4.3); the core does exact string-equality on it,
    // so this normalization is the whole contract.
    let now = state.now();
    let htu = crate::dpop::normalized_htu_for_token_endpoint(state);
    let expected = DpopExpectations {
        htm: DPOP_HTM_POST,
        htu: &htu,
        iat_leeway: crate::dpop::DPOP_IAT_LEEWAY,
        iat_skew: crate::dpop::DPOP_IAT_SKEW,
        // ath binding is the resource-server follow-up, so it stays absent here.
        ath: None,
        // The nonce is NOT checked by the core here, and that is not an oversight.
        // The core compares against a nonce the caller already knows; this server
        // does not know which of its outstanding nonces this client holds, so it
        // RECOGNISES the one the proof carries instead (below, against the issued
        // store). Passing the proof's own nonce back as the expectation would make
        // the core's check compare a value against itself.
        nonce: None,
    };
    let proof = validate_dpop_proof(proof_jws, &expected, now).map_err(|error| {
        // Log the granular variant (value-free) for diagnostics; the client sees only
        // the uniform error, so it cannot probe which check failed.
        tracing::warn!(%error, "rejecting an invalid DPoP proof at the token endpoint");
        TokenError::InvalidDpopProof
    })?;

    // RFC 9449 section 8, when this deployment requires a server-issued nonce: the
    // proof must echo one this instance handed out and has not aged out. A proof
    // minted before the challenge cannot, which is the whole point: it moves
    // freshness from the client's `iat` clock to the server's own assertion.
    //
    // Checked BEFORE the replay record so a challenged request does not burn a `jti`
    // the client is about to abandon anyway (its retry carries a new proof).
    if state.require_dpop_nonce() {
        let acceptable = proof
            .nonce
            .as_deref()
            .is_some_and(|nonce| state.dpop_nonces().is_acceptable(nonce, now));
        if !acceptable {
            // Absent and stale are answered IDENTICALLY, with a fresh challenge. They
            // are the same situation from the client's side ("you need a nonce you do
            // not have"), and the remedy is the same, so splitting them would add an
            // oracle for which nonces this instance still holds and buy nothing.
            let nonce = state.dpop_nonces().issue(state.env().entropy(), now);
            tracing::debug!("challenging a token request for a server-issued DPoP nonce");
            return Err(TokenError::UseDpopNonce { nonce });
        }
    }

    // Replay: a (jkt, jti) already recorded inside the freshness window is refused,
    // the same uniform error, and never rebinds.
    if !state
        .dpop_replay()
        .check_and_record(&proof.jkt, &proof.jti, now)
    {
        tracing::warn!("rejecting a replayed DPoP proof jti at the token endpoint");
        return Err(TokenError::InvalidDpopProof);
    }
    Ok(Some(Confirmation::Jkt(proof.jkt)))
}

/// Whether `grant_types` (the client's registered space-separated allowlist) permits
/// `grant`.
///
/// Split on whitespace and compared as exact wire values, which is how RFC 7591 defines
/// the metadata and how the device grant has always read this column.
#[must_use]
pub(crate) fn registered_for(grant_types: &str, grant: GrantType) -> bool {
    grant_types
        .split_whitespace()
        .any(|token| token == grant.as_str())
}

/// THE shared client grant-restriction seam (issue #763).
///
/// # The failure this closes
///
/// `clients.grant_types` documents itself as "the list of OAuth grant types the client
/// is permitted", and until this existed exactly ONE handler honoured it: the device
/// grant. A client registered for `authorization_code` alone could still obtain tokens
/// through `client_credentials`, `jwt_bearer`, and `refresh_token`. That is the Dex
/// `AllowedConnectors` shape: a restriction enforced in some grant handlers and not
/// others, where the gap is discovered by whoever uses it.
///
/// # One seam, called by every handler
///
/// Every grant handler calls THIS function and no other, so the rule cannot diverge
/// between grants. `every_grant_handler_consults_the_shared_seam` drives all of
/// [`GrantType::ALL`] end to end against a client registered for none of them, so a
/// grant added without a call here fails a test that enumerates the variants rather
/// than silently skipping the check.
///
/// # Off by default
///
/// Migration 0021 defaults the column to `authorization_code` for every pre-existing
/// client, so unconditional enforcement is a flag day rather than an upgrade. The
/// `grant_types_would_refuse` admin diagnostics name the clients that would be refused,
/// so an operator can widen those registrations BEFORE turning this on.
///
/// # Errors
///
/// [`TokenError::UnauthorizedClient`]: RFC 6749 5.2 defines it as "the authenticated
/// client is not authorized to use this authorization grant type", which is exactly
/// this condition, and it is what the device grant already returns for the same reason.
pub(crate) fn enforce_registered_grant_for(
    state: &OidcState,
    client: &AuthenticatedClient,
    grant: GrantType,
) -> Result<(), TokenError> {
    if !state.enforce_client_grant_types() || registered_for(&client.grant_types, grant) {
        return Ok(());
    }
    tracing::warn!(
        grant = grant.as_str(),
        "refusing a grant the client is not registered for"
    );
    Err(TokenError::UnauthorizedClient)
}

/// Enforce the `DPoP`-by-default posture for PUBLIC clients (issue #124).
///
/// IronAuth's stated posture is that `DPoP` is the default for a public client and
/// bearer is the exception. A public client is one that cannot keep a secret, so its
/// tokens are the ones a theft most directly monetizes, and sender-constraining them
/// is what turns a stolen token into one an attacker cannot present.
///
/// # Why only public clients
///
/// A confidential client authenticates on every token request. The sender constraint
/// a proof adds is therefore not the control protecting it, and requiring one would
/// impose a round trip and a key-management burden to defend something already
/// defended. The posture is aimed exactly where the gap is.
///
/// # Why the escape hatch is per client
///
/// Some public clients cannot mint proofs at all: an embedded or TV runtime with no
/// `WebCrypto`, a vendor SDK the operator does not control, a native app shipped before
/// the operator adopted this posture. Without a way out, those deployments would have
/// to abandon the posture wholesale, which is strictly worse than naming the two
/// clients that need bearer and constraining every other one. A deployment-wide
/// switch would have to be set for the WEAKEST client and would then silently relax
/// every other client with it, which is the accident this shape prevents.
///
/// # Errors
///
/// [`TokenError::InvalidDpopProof`], the same uniform error a bad proof draws. A
/// public client that sent no proof to a deployment expecting one is in the same
/// position as one whose proof failed: it must present a valid proof to proceed, and
/// the remedy is identical, so a separate code would only tell an attacker which
/// clients are relaxed.
fn enforce_public_client_dpop(
    client: &AuthenticatedClient,
    confirmation: Option<&Confirmation>,
) -> Result<(), TokenError> {
    if client.auth_method != ClientAuthMethod::None || client.allow_bearer_tokens {
        return Ok(());
    }
    if confirmation.is_some() {
        return Ok(());
    }
    tracing::warn!(
        "rejecting a bearer token request from a public client that is not allowed bearer tokens"
    );
    Err(TokenError::InvalidDpopProof)
}

/// Enforce a SENDER-CONSTRAINED authorization code's `DPoP` binding at redemption
/// (RFC 9449, issue #368).
///
/// `code_jkt` is the thumbprint frozen onto the code at issuance
/// (`authorization_codes.dpop_jkt`), or [`None`] for a code that is not key-bound.
/// `presented_jkt` is what [`resolve_dpop_binding`] already validated off this request,
/// so this function re-checks only the BINDING and never the proof: the proof's
/// signature, `htm`, `htu`, freshness, and `jti` replay were all settled there, and
/// duplicating any of it here would be a second answer to the same question.
///
/// The rule is the same narrowing the refresh grant applies
/// ([`enforce_refresh_dpop`]): an unbound code keeps the opportunistic behavior, a
/// bound code requires the matching key.
///
/// - `code_jkt` is [`None`]: unchanged. A presented proof still binds the issued
///   tokens (that is 5g's job), and an absent one still yields bearer tokens.
/// - `code_jkt` is [`Some`] and the presented key MATCHES: proceed, and the tokens
///   bind to that same key.
/// - `code_jkt` is [`Some`] and the proof is ABSENT or for another key: the uniform
///   [`TokenError::InvalidDpopProof`].
///
/// Why the absent case matters most: without it, a code intercepted between the
/// challenge response and the token request could be redeemed by anyone, for plain
/// bearer tokens, and the device binding that protected every step of the login would
/// have protected nothing at the one moment it was cashed in.
///
/// Comparing thumbprints in variable time is fine: a `jkt` is derived from a public
/// key that the proof itself carries in clear, so a timing side channel discloses
/// nothing an attacker cannot already compute.
///
/// Called BEFORE the code is consumed, so a refusal leaves the code live for the
/// legitimate client's retry.
fn enforce_code_dpop_binding(
    code_jkt: Option<&str>,
    presented_jkt: Option<&str>,
) -> Result<(), TokenError> {
    let Some(code_jkt) = code_jkt else {
        return Ok(());
    };
    if presented_jkt == Some(code_jkt) {
        return Ok(());
    }
    if presented_jkt.is_none() {
        tracing::warn!("rejecting redemption of a DPoP-bound code presented with no proof");
    } else {
        tracing::warn!("rejecting redemption of a DPoP-bound code under a different proof key");
    }
    Err(TokenError::InvalidDpopProof)
}

/// Enforce a refresh-token family's `DPoP` binding (RFC 9449 section 5, issue #368
/// PR3) before it is rotated. `family_jkt` is the thumbprint recorded on the family
/// at issuance (`refresh_families.dpop_jkt`), or [`None`] for an unbound (bearer)
/// family.
///
/// The asymmetry vs the code-exchange path is deliberate. At the code exchange
/// ([`resolve_dpop_binding`]) a present proof is OPPORTUNISTIC: no header means a
/// plain bearer token. Here, on a BOUND family, a valid proof for the SAME key is
/// REQUIRED to rotate: a bound family is already sender-constrained, so an absent
/// header, a proof for a different key, or a replayed `jti` must all be refused. The
/// core proof validation and the `jti` replay record are the same
/// [`resolve_dpop_binding`] helper; only the treatment of its `Ok(None)` (no-header)
/// result differs (there it falls through to bearer, here it is the uniform error).
///
/// Returns:
/// - `Ok(None)` for an unbound family: the `DPoP` header is NOT consulted and the
///   rotated tokens stay bearer, so a presented proof can never retroactively bind a
///   family whose earlier tokens were bearer.
/// - `Ok(Some(conf))` for a bound family that presented a valid proof for the exact
///   bound key: the caller re-binds the rotated access token to it (`cnf`).
/// - `Err(TokenError::InvalidDpopProof)` for a bound family with no proof, a proof
///   for a different key, or an otherwise invalid or replayed proof. Uniform, no
///   oracle. The rejection happens BEFORE the atomic redeem, so it neither rotates
///   nor revokes the family: a legitimate holder retries with a proper proof.
fn enforce_refresh_dpop(
    state: &OidcState,
    headers: &HeaderMap,
    family_jkt: Option<&str>,
) -> Result<Option<Confirmation>, TokenError> {
    let Some(expected) = family_jkt else {
        // Unbound family: bearer path, do not consult the DPoP header and do not bind.
        return Ok(None);
    };
    // Bound family: a valid proof is REQUIRED (no header is the same uniform error,
    // not a bearer fall through). resolve_dpop_binding validates htm/htu/iat and
    // records the jti in the replay cache.
    let Some(conf) = resolve_dpop_binding(state, headers)? else {
        tracing::warn!("rejecting a bound refresh with no DPoP proof");
        return Err(TokenError::InvalidDpopProof);
    };
    // The proof must prove possession of the SAME key the family is bound to; a valid
    // proof for a different key is refused.
    if conf.value() != expected {
        tracing::warn!("rejecting a bound refresh whose DPoP proof key does not match the family");
        return Err(TokenError::InvalidDpopProof);
    }
    Ok(Some(conf))
}

/// Re-check the `redirect_uri` and PKCE bindings the code carries against the
/// presented request. All mismatches collapse to a single boolean, so the caller
/// returns the uniform `invalid_grant` without revealing which binding failed. The
/// `client_id` binding is re-checked separately against the AUTHENTICATED client
/// (see the exchange). This runs BEFORE the code is consumed, so a mismatch does
/// not burn the one-time code.
fn bindings_match(bindings: &CodeBindings, params: &TokenParams) -> bool {
    // The redirect_uri re-check in BOTH directions, symmetric with the PKCE rule below (issue
    // #93, Bet 3, FORK A):
    // - a BROWSER code (the shipped default) was bound to the specific URI the client used, so it
    //   is redeemable ONLY with that EXACT presented redirect_uri (RFC 6749 4.1.3); no loopback-port
    //   latitude applies here (that latitude was already spent when the code was issued against the
    //   presented port). An absent presented value is a mismatch. This is BYTE-IDENTICAL to before.
    // - a BROWSERLESS first-party challenge code carries NO redirect_uri, so the token request must
    //   present NONE: an absent (or empty) presented value is accepted and a present one is REJECTED
    //   as a mismatch, exactly mirroring how a no-challenge code rejects a presented PKCE verifier.
    let redirect_ok = if bindings.browserless {
        // No redirect_uri was bound: the request must present none. An empty/whitespace value is
        // treated as absent (accepted); any real presented URI is a mismatch (rejected).
        params
            .redirect_uri
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    } else {
        // The shipped browser rule, UNCHANGED: an exact-string match of the presented value against
        // the bound URI, with an absent presented value a mismatch.
        params
            .redirect_uri
            .as_deref()
            .is_some_and(|presented| presented == bindings.redirect_uri)
    };
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
/// A grant with NO `session_ref` at all has no SSO session and emits no `sid`, but it is
/// NOT unchecked (issue #241). Every code this build mints carries one: `issue_code_core`
/// passes `session_ref: Some(resolved.session_ref)` and `Resolved::session_ref` is a
/// non-optional `&str`, on the browser path and the browserless first-party challenge
/// path alike. So [`None`] here is reachable only for a code ROW persisted by an older
/// build and redeemed across a rolling upgrade, inside the short code TTL.
///
/// That narrow window used to be the code exchange's blind spot, and on an
/// `offline_access` exchange it was total: the doc above counts the whole fence for that
/// scope as the two reads in THIS function, and both of them are downstream of the `else`
/// this comment sits on. A legacy-shaped code for a blocked subject would have minted an
/// access token, an ID token, and an offline refresh family that deliberately survives
/// the session cascade. So the branch asks the user directly instead:
/// [`ensure_subject_can_authenticate`] is the SAME read the refresh grant is fenced by,
/// and it fails closed on a blocked, disabled, deleted, or absent subject and on a store
/// fault. "No session to check" now means "checked the user instead", never "checked
/// nothing".
async fn resolve_code_exchange_sid(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
) -> Result<CodeExchangeSession, TokenError> {
    let Some(session_ref) = bindings.session_ref.as_deref() else {
        ensure_subject_can_authenticate(state, scope, &bindings.subject).await?;
        return Ok(CodeExchangeSession::default());
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
    let Some(session) = session else {
        // Revoked, logged out, rotated away, or expired since the code was issued. Since
        // issue #101 that read also refuses a session whose IMPERSONATION has lapsed, so an
        // exchange past the cap fails here rather than minting one more token.
        return Err(TokenError::InvalidGrant);
    };
    let sid = state
        .store()
        .scoped(scope)
        .client_sessions()
        .ensure_sid(state.env(), &session_id, &bindings.client_id, now_micros)
        .await
        .map_err(|_| TokenError::ServerError)?;
    Ok(CodeExchangeSession {
        sid: Some(sid),
        impersonation: session.impersonation,
    })
}

/// What the code-exchange session read answers (issues #32 and #101).
///
/// Both fields come out of ONE store read. The impersonation was already being fetched and
/// discarded, so carrying it costs no query; fetching it separately at the mint site would
/// have added one to the hot path and, worse, could disagree with the liveness check that
/// happens here.
#[derive(Debug, Default)]
struct CodeExchangeSession {
    /// The front-channel `sid`, absent when the grant has no SSO session.
    sid: Option<String>,
    /// The impersonation the session was started under, absent on an ordinary session.
    impersonation: Option<ironauth_store::SessionImpersonation>,
}

/// The subject's effective organization roles at THIS issuance (issue #97), resolved
/// FRESH from the store rather than replayed from the code or the grant.
///
/// This is deliberately the OPPOSITE of `org_id` (issue #94), which freezes onto the
/// session and then the grant so it is stable for the life of a refresh family. A role
/// is an AUTHORIZATION input: a role granted or revoked after the code was issued must
/// be reflected on the next token, so it is re-resolved on every code exchange AND
/// every refresh. The cost is one bounded query per issuance; the alternative
/// (freezing) would make a role revocation invisible for the whole family lifetime,
/// which is not an acceptable property for an authorization claim.
///
/// `subject` must be the LOCAL user id the grant recorded, never the public subject
/// the token carries: resolution is a store read keyed by the real user, and a
/// pairwise `sub` names no `users` row. The two are the same string TODAY only
/// because [`OidcState::resolve_public_subject`] hard-codes the public subject type
/// while per-client pairwise configuration is unpersisted client-registration state
/// (issue #19). Both call sites therefore resolve roles BEFORE deriving the public
/// subject, so there is no `subject` binding in scope to pass here by mistake; the
/// issue that persists the pairwise configuration must keep it that way, or every
/// pairwise client with an organization context starts failing closed at the mint.
///
/// Returns [`None`] when there is no organization context, symmetric with `org_id`: a
/// role is org-scoped, so with no org there is no set to resolve and the claim is
/// ABSENT rather than empty. An empty [`Some`] is distinct and DOES emit an empty
/// array; it means the resolution ran and found nothing, which covers a member
/// holding no roles, a subject who is not a member at all, and an organization that
/// is no longer live and active.
///
/// # The organization's own lifecycle is fenced in the STORE, not here
///
/// A DISABLED or soft-DELETED organization resolves to the EMPTY set, because
/// [`ironauth_store::OrgGroupRepo::effective_roles`] fences the membership seed of
/// its shared closure on the organization being live and active. It has to live
/// there rather than here, and this call site is exactly why: NEITHER mint hook is
/// in a position to check it. The refresh path never runs the authorize-time
/// organization resolution at all (it reads the org context frozen onto the family's
/// grant), and on a code exchange that resolution returns EARLY for an
/// already-bound session, so its disabled-organization refusal never runs either. A
/// check added here would also cover only this claim, leaving the admin
/// effective-roles view disagreeing with the token about the same organization.
///
/// Note that `org_id` itself is still EMITTED for a disabled organization: the grant
/// really is bound to it, and the honest wire answer is "this token is scoped to that
/// organization and carries no roles in it" rather than a silently org-less token.
///
/// # Fails CLOSED
///
/// A store fault is a `server_error`, never a role-less token: silently omitting roles
/// reads downstream as a successful authorization DOWNGRADE, which is a real security
/// bug rather than a cosmetic omission. This is also why roles do NOT ride the ID
/// token's `extra_claims` bag, which is deliberately fail-OPEN (under-claim rather
/// than fail issuance). A frozen `org_id` that no longer parses in this scope, or a
/// recorded subject that does not, is a store-integrity problem and fails closed for
/// the same reason.
///
/// # Errors
///
/// [`TokenError::ServerError`] on a store fault or an unparsable recorded identifier.
async fn resolve_effective_roles(
    state: &OidcState,
    scope: Scope,
    subject: &str,
    org_id: Option<&str>,
) -> Result<Option<BTreeSet<String>>, TokenError> {
    let Some(org_id) = org_id else {
        return Ok(None);
    };
    let Ok(organization_id) = OrganizationId::parse_in_scope(org_id, &scope) else {
        return Err(TokenError::ServerError);
    };
    let Ok(user_id) = UserId::parse_in_scope(subject, &scope) else {
        return Err(TokenError::ServerError);
    };
    state
        .store()
        .scoped(scope)
        .org_groups()
        .effective_roles(&organization_id, &user_id, state.max_group_depth())
        .await
        .map(Some)
        .map_err(|_| TokenError::ServerError)
}

/// The subject's effective PERMISSION set for THIS issuance (issue #98), resolved
/// fresh from the store in the organization context frozen onto the grant.
///
/// The exact sibling of [`resolve_effective_roles`], deliberately: it is called from
/// the same two hooks, on the same line as that one, with the same freshness rule,
/// the same fail-closed rule, and the same absent-versus-empty distinction. Read that
/// function's doc comment; everything it says applies here unchanged, including that
/// the ORGANIZATION'S OWN LIFECYCLE is fenced in the store's shared closure because
/// neither mint hook is in a position to check it.
///
/// The ONE thing this adds is `emits_claim`, which both hooks pass as
/// [`AccessTokenTarget::emits_permission_claims`]: the audiences UNANIMOUSLY opted in
/// AND the selected format is one that carries claims. It is checked FIRST, before the
/// organization context and before any store read, which buys three things worth
/// naming. It makes a target that cannot carry the claim cost exactly zero extra round
/// trips, which matters because that is the overwhelmingly common case on the hottest
/// path in the product. It makes the mixed-opt-in suppression reach the wire through
/// the very same [`None`] that "no organization context" reaches it through, so the two
/// are indistinguishable to a resource server BY CONSTRUCTION rather than by two code
/// paths agreeing to emit the same thing. And, through the FORMAT half, it keeps the
/// `opaque` plus opted-in combination genuinely inert: that combination is reachable
/// through a config promotion, and without the format check this function would run a
/// resolution whose result the opaque mint discards, so a fault in that read would turn
/// a documented no-op into a 500 the same request without the opt-in survives.
///
/// Returns [`None`] when the target cannot carry the claim OR when there is no
/// organization context: the claim is then ABSENT, and no `permissions_status` is
/// emitted either, because neither is an overflow. An empty [`Some`] is distinct and
/// DOES emit an empty array.
///
/// # Fails CLOSED
///
/// A store fault is a `server_error`, never a permission-less token, for a stronger
/// version of the argument [`resolve_effective_roles`] makes: a permission names an
/// API capability, so a silently dropped set is an authorization DOWNGRADE that looks
/// exactly like a subject who legitimately holds nothing. Under the `roles_only`
/// overflow mode it is worse still, because the resource server falls back to `roles`
/// and grants SOMETHING, so the request succeeds with the wrong authority rather than
/// failing loudly. This is also why permissions do not ride the ID token's
/// deliberately fail-OPEN `extra_claims` bag.
///
/// # Errors
///
/// [`TokenError::ServerError`] on a store fault.
///
/// The two identifier-parse arms below also answer [`TokenError::ServerError`], and
/// this doc does NOT claim they enforce anything, because on both mint hooks they are
/// UNREACHABLE: [`resolve_effective_roles`] runs first, on the same line, with the same
/// `scope`, `subject`, and `org_id`, and refuses the whole exchange on exactly those
/// two parses. They are kept as a local fail-closed default rather than deleted (this
/// function must not be sound only by virtue of its caller's ordering), and
/// `a_recorded_identifier_that_is_out_of_scope_fails_closed_on_both_branches` in
/// `crates/ironauth-oidc/tests/org_roles_claim.rs` is what actually measures the
/// refusal, one function up.
async fn resolve_effective_permissions(
    state: &OidcState,
    scope: Scope,
    subject: &str,
    org_id: Option<&str>,
    emits_claim: bool,
) -> Result<Option<BTreeSet<String>>, TokenError> {
    if !emits_claim {
        return Ok(None);
    }
    let Some(org_id) = org_id else {
        return Ok(None);
    };
    let Ok(organization_id) = OrganizationId::parse_in_scope(org_id, &scope) else {
        return Err(TokenError::ServerError);
    };
    let Ok(user_id) = UserId::parse_in_scope(subject, &scope) else {
        return Err(TokenError::ServerError);
    };
    state
        .store()
        .scoped(scope)
        .org_groups()
        .effective_permissions(&organization_id, &user_id, state.max_group_depth())
        .await
        .map(Some)
        .map_err(|_| TokenError::ServerError)
}

/// Record what the permission budget decided for one mint (issue #98), from EITHER
/// mint hook.
///
/// One function for both hooks so the code exchange and the refresh grant cannot
/// report the same verdict differently. Recording from the refresh hook is NEW
/// observability rather than a duplicate: refresh is the highest-volume grant and
/// this sink has never seen it.
///
/// # What is and is not recorded
///
/// A verdict that emitted the complete set and is nowhere near a threshold writes
/// NOTHING. An event per successful mint would be a write on the hot path of the
/// hottest endpoint in the product, for a row saying that nothing happened. Every
/// verdict that an operator could act on IS recorded:
///
/// * [`PermissionBudgetOutcome::Emitted`] with `approaching` set: the early warning.
/// * [`PermissionBudgetOutcome::Withheld`]: the overflow, with the reason that
///   distinguishes an element overflow (nothing was serialized, so the size reported
///   is the token that SHIPPED) from a byte overflow (the size reported is the token
///   that was withheld).
/// * A SECOND row, [`TokenSizeReason::RolesOnlyStillOversize`], when the token that
///   actually ships is itself over the byte budget. Two rows and not one, because the
///   reason a set was withheld and the fact that withholding it did not help are
///   different facts and an operator needs both. Nothing acts on the second: the role
///   set is uncapped by covenant (issue #97), so there is nothing further to withhold,
///   and the design records that case rather than hiding it.
///
/// Best effort, exactly like every other recorder in `policy_trace`: a write failure
/// is logged and the token is returned unchanged. The covenant does not depend on this
/// write landing, because the token itself carries `permissions_status`.
async fn record_budget_outcome(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    target: &AccessTokenTarget,
    org_id: Option<&str>,
    outcome: PermissionBudgetOutcome,
) {
    // A verdict exists only where a permission set was in play, and a permission set
    // exists only in an organization context, so a verdict with no organization is not
    // a thing this can observe. Nothing is recorded rather than a placeholder written.
    let Some(organization_id) = org_id else {
        return;
    };
    // ONE verdict is reached for the whole TOKEN, so it is attributable to a single
    // audience only when the token targets exactly one. On a multi-audience token the
    // event carries no audience rather than mislabelling the verdict as belonging to
    // one of them.
    let audience = match target.audiences.as_slice() {
        [single] => Some(single.as_str()),
        _ => None,
    };
    let (reason, token_bytes, permission_count, permission_status, roles_only_bytes) = match outcome
    {
        PermissionBudgetOutcome::NotApplicable
        | PermissionBudgetOutcome::Emitted {
            approaching: false, ..
        } => return,
        PermissionBudgetOutcome::Emitted {
            token_bytes, count, ..
        } => (
            TokenSizeReason::BudgetApproaching,
            token_bytes,
            count,
            None,
            None,
        ),
        PermissionBudgetOutcome::Withheld {
            reason,
            roles_only_token_bytes,
            count,
            status,
        } => {
            let (reason, token_bytes) = match reason {
                PermissionWithheldReason::CountExceeded => {
                    (TokenSizeReason::BudgetOverflowCount, roles_only_token_bytes)
                }
                PermissionWithheldReason::ByteExceeded { token_bytes } => {
                    (TokenSizeReason::BudgetOverflowBytes, token_bytes)
                }
            };
            (
                reason,
                token_bytes,
                count,
                Some(status),
                Some(roles_only_token_bytes),
            )
        }
    };
    crate::policy_trace::record_permission_budget_event(
        state,
        scope,
        client_id,
        PermissionBudgetEvent {
            reason,
            token_bytes,
            permission_count,
            audience,
            organization_id,
            permission_status,
        },
    )
    .await;
    // The fallback is itself oversize: a distinct, second fact about the SAME mint.
    let budget = PermissionBudget::from_config(state.token_claims());
    if let Some(bytes) = roles_only_bytes.filter(|bytes| *bytes > budget.max_token_bytes) {
        crate::policy_trace::record_permission_budget_event(
            state,
            scope,
            client_id,
            PermissionBudgetEvent {
                reason: TokenSizeReason::RolesOnlyStillOversize,
                token_bytes: bytes,
                permission_count,
                audience,
                organization_id,
                permission_status,
            },
        )
        .await;
    }
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
    access_extra_claims: &crate::claims_mapping_at_issuance::MappedAccessClaims,
    target: &AccessTokenTarget,
    confirmation: Option<&Confirmation>,
) -> Result<IssuedTokens, TokenError> {
    // Resolve the per-client `sid` (issue #32) from the code's authenticating SSO
    // session BEFORE signing, so the ID token carries a `sid` that is stable per
    // (client, session) and distinct across clients. This ALSO enforces that the SSO
    // session is still live: a code minted before a revoke and redeemed after it is an
    // invalid_grant, never a live token bound to a dead session.
    let session = resolve_code_exchange_sid(state, scope, bindings).await?;
    let sid = session.sid;
    let sid = sid.as_deref();
    // Resolve the effective organization roles (issue #97) FRESH from the store, in
    // the org context frozen onto the grant. Fresh, not frozen: unlike `org_id` this
    // is re-read at every issuance, so a role granted or withdrawn since the code was
    // minted is reflected here. Fails closed (server_error), never a role-less token.
    let roles =
        resolve_effective_roles(state, scope, &bindings.subject, bindings.org_id.as_deref())
            .await?;
    // The effective PERMISSIONS (issue #98), on the same terms and the same line: fresh
    // at every issuance, fail closed, and additionally gated on the target being able
    // to CARRY the claim at all (unanimous opt-in and an at+jwt format), which is what
    // makes this cost nothing for the overwhelming majority of exchanges.
    let permissions = resolve_effective_permissions(
        state,
        scope,
        &bindings.subject,
        bindings.org_id.as_deref(),
        target.emits_permission_claims(),
    )
    .await?;
    let entry = grant_issuer_entry(state, scope).await?;
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
    let minted = tokens::mint(
        state,
        signer,
        entry.policy(),
        &MintRequest {
            // The `act` claim comes from the SESSION, never from the request (issue #101).
            // It rides the same read that proved the session live, so a token cannot claim
            // an impersonation the liveness check did not agree with.
            actor: session
                .impersonation
                .as_ref()
                .map(|imp| tokens::TokenActor {
                    subject: &imp.impersonator,
                    reason_code: &imp.reason_code,
                }),
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
            // The DURABLE organization context (issue #94, PR-B1) frozen onto the
            // grant at authorization and read back here, emitted as the `org_id` claim
            // on both tokens. None when the session resolved no org.
            org_id: bindings.org_id.as_deref(),
            // The effective organization roles (issue #97), resolved FRESH above and
            // emitted on the ACCESS token only. None when there is no org context.
            roles: roles.as_ref(),
            // The effective organization permissions (issue #98), resolved FRESH above
            // and emitted on the ACCESS token only. None when there is no org context
            // OR when the target's audiences did not unanimously opt in.
            permissions: permissions.as_ref(),
            // A token-endpoint ID token never carries at_hash, and the code flow
            // never carries c_hash; the front-channel/hybrid path (#17) supplies
            // them. Both are absent here by construction.
            at_hash: None,
            c_hash: None,
            extra_claims,
            id_token_signer,
            // Bind the at+jwt to the DPoP proof key when one accompanied the exchange
            // (issue #368): the `cnf` claim is issuer-set only, so a client cannot
            // self-assert it. None leaves a plain bearer access token.
            confirmation,
            // The client's declarative mapping (issue #113), resolved by the caller. Empty
            // when no mapping is configured, which is every client until an operator writes
            // one. Fenced by the CHANNEL: `MintRequest::access_extra_claims` drops a protected
            // name whatever writes into it.
            access_extra_claims,
        },
        target,
    )
    .map_err(|()| TokenError::ServerError)?;
    // The budget verdict, recorded AFTER the mint and off its critical path (issue
    // #98). Best effort: a failed write never affects the token, which already carries
    // `permissions_status` if anything was withheld.
    record_budget_outcome(
        state,
        scope,
        &bindings.client_id,
        target,
        bindings.org_id.as_deref(),
        minted.permission_budget,
    )
    .await;
    Ok(minted)
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
        .resource_policy(StoredClientId::Registered(&client_id))
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

/// Merge the claims-enrichment hook's contribution into the ID token's extra-claims bag
/// (issue #100).
///
/// # It can only fill EMPTY names
///
/// A contributed claim whose name is already present is DROPPED, not merged and not
/// overwritten. Two fences already stand in front of this (config load refuses to allowlist
/// a reserved name, and the hook filters the response against the allowlist), and this is
/// the third and the only one that can see the assembled token: it is what stops an
/// enrichment service replacing a claim the `claims` parameter or the scope mapping just
/// resolved, which neither of the other two knows about.
///
/// # Fail-open, deliberately
///
/// No hook installed, or a hook that contributes nothing, leaves the bag exactly as it was
/// and the token is issued. The hook itself never returns an error; see its module note for
/// why an FGA outage must not take every login down with it.
async fn merge_enriched_claims(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
    extra_claims: &mut serde_json::Map<String, serde_json::Value>,
) {
    let Some(hook) = state.claims_enrichment_hook() else {
        return;
    };
    let contributed = hook
        .enrich(scope, &bindings.subject, &bindings.client_id)
        .await;
    for (name, value) in contributed {
        if extra_claims.contains_key(&name) {
            tracing::warn!(
                claim = %name,
                "the claims-enrichment hook returned a claim that is already present; \
                 keeping the value IronAuth resolved"
            );
            continue;
        }
        extra_claims.insert(name, value);
    }
}

/// Apply this client's stored declarative mapping to the claims about to be minted.
///
/// Rewrites `extra_claims` into the ID-token set and RETURNS the access-token set, because a
/// mapping's whole job includes deciding which token a claim goes in (issue #113 criterion 4:
/// "ID-versus-access-token placement with no custom code"). Before this seam existed the access
/// token had no configured claims at all and `MintRequest::access_extra_claims` had no
/// production writer.
///
/// # Why a fault here fails the whole issuance
///
/// Unlike `merge_enriched_claims` above, which is deliberately fail-open, a mapping is as likely
/// to REMOVE a claim as to add one: `filter_list` exists so a token does not carry three thousand
/// group names. Ignoring a mapping that could not be read would issue the UNFILTERED set, which
/// is MORE than the operator configured. See `claims_mapping_at_issuance`'s header.
///
/// # Errors
///
/// [`TokenError::ServerError`] when the mapping cannot be read or applied. The reason is logged;
/// a client is told nothing beyond the failure, because which mapping a client has is not
/// something a client gets to probe.
pub(crate) async fn apply_claims_mapping(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    grant_type: &str,
    subject: Option<&str>,
    extra_claims: &mut serde_json::Map<String, serde_json::Value>,
) -> Result<crate::claims_mapping_at_issuance::MappedAccessClaims, TokenError> {
    crate::claims_mapping_at_issuance::apply_to_with_hook(
        state.store(),
        state.hook_engine(),
        scope,
        client_id,
        grant_type,
        subject,
        extra_claims,
    )
    .await
    .map_err(|_| TokenError::ServerError)
}

/// Build the `200 OK` token response (RFC 6749 5.1) from the pre-minted tokens,
/// including the refresh token (issue #21) when one was issued.
pub(crate) fn token_response(
    minted: &IssuedTokens,
    bindings: &CodeBindings,
    refresh_token: Option<&str>,
    dpop_bound: bool,
) -> Response {
    // RFC 9449 section 5: a token sender-constrained by a DPoP proof is advertised as
    // `DPoP`, so the client presents it as `Authorization: DPoP` with a fresh proof
    // rather than as a plain bearer. An unbound exchange stays `Bearer`.
    let token_type = token_type_for_dpop(dpop_bound);
    let mut body = serde_json::json!({
        "access_token": minted.access.token(),
        "token_type": token_type,
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
        Ok(id) => client_service_actor(StoredClientId::Registered(&id)),
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

/// Resolve the environment's issuer entry for a TOKEN-ENDPOINT grant (issue #433).
///
/// EVERY grant that signs something goes through here, so the shape of a refusal is
/// decided once rather than five times. The two conditions the registry used to
/// collapse into one `None` are separated:
///
/// - [`IssuerResolution::Fenced`]: an operator SUSPENDED or offboarded this
///   environment. A deliberate administrative state, so it renders 503
///   `temporarily_unavailable` with a `Retry-After` rather than claiming a fault the
///   server did not suffer, and rather than a 4xx that would tell a conforming client
///   to throw away a credential that is still perfectly valid.
/// - [`IssuerResolution::Absent`]: no provisioned signing key, an environment named
///   under the wrong tenant, a scope that never existed, or a fence the store could
///   not be read for. A server that cannot sign IS a fault, so this keeps the 500
///   `server_error` it has always answered. Widening the 503 to cover this arm would
///   hide real outages behind "try again later", which is strictly worse than the
///   defect issue #433 set out to correct.
///
/// Called AFTER the presented credential has been validated on every grant, which is
/// what keeps the 503 from becoming an environment-existence oracle (see the
/// `crate::error` module documentation).
pub(crate) async fn grant_issuer_entry(
    state: &OidcState,
    scope: Scope,
) -> Result<Arc<IssuerEntry>, TokenError> {
    match state.issuer_resolution(&scope).await {
        IssuerResolution::Ready(entry) => Ok(entry),
        IssuerResolution::Fenced => Err(TokenError::TemporarilyUnavailable),
        IssuerResolution::Absent => Err(TokenError::ServerError),
    }
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
    let assembled = step_up::requirement_for_request(
        state,
        scope,
        &crate::authorize::ResolvedClient::Registered(&client),
        oauth_scope,
        None,
        None,
    )
    .await;
    if assembled.policy_read_faulted {
        return Some(TokenError::ServerError);
    }
    let requirement = assembled.requirement;
    let methods = authn::parse_methods(auth_methods);
    // The tenant baseline MFA floor (issue #71) is satisfied at the token endpoint by a
    // GENUINE second factor on the frozen event OR by the frozen TRUSTED-DEVICE
    // contribution the authorize gate recorded (the device was validated server-side at
    // authorize; there is no cookie to re-check here, so the frozen `trusted_device`
    // method IS the honest attestation). A frozen event that carries neither must
    // re-authenticate a second factor.
    let mfa_baseline_unmet = assembled.mfa_baseline_required
        && !authn::performed_second_factor(&methods)
        && !authn::includes_trusted_device(&methods);
    if requirement.is_empty() && !mfa_baseline_unmet {
        return None;
    }
    let order = state.acr_order();
    let achieved = authn::achieved_acr(&methods);
    let now_micros = epoch_micros(state.now());
    let explicit_needs_step_up = !requirement.is_empty()
        && matches!(
            step_up::evaluate(
                &requirement,
                achieved,
                auth_time_unix_micros,
                now_micros,
                &order,
            ),
            step_up::Satisfaction::NeedsStepUp { .. }
        );
    if explicit_needs_step_up {
        return Some(TokenError::InsufficientUserAuthentication {
            acr_values: requirement.min_acr,
            max_age: requirement.max_auth_age_secs,
        });
    }
    if mfa_baseline_unmet {
        // The tenant baseline MFA floor is unmet: the client must retry after proving a
        // second factor (its acr is the multi-factor level).
        return Some(TokenError::InsufficientUserAuthentication {
            acr_values: Some(authn::acr_for_mfa().to_owned()),
            max_age: None,
        });
    }
    None
}

async fn issue_refresh_for_code(
    state: &OidcState,
    scope: Scope,
    bindings: &CodeBindings,
    dpop_jkt: Option<&str>,
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
                // Bind the refresh family to the DPoP proof key when the exchange was
                // bound (issue #368), so PR3 can require a matching proof to rotate
                // it. None leaves an unbound (bearer) family, unchanged.
                dpop_jkt,
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
/// the account would not actually be fenced.
///
/// # What this function is, and what fences the OTHER grant (issue #406)
///
/// The invariant is that after block/disable/delete a user obtains NO new tokens by ANY
/// path (authorize, refresh, or an existing offline token). This function is NOT the
/// single point that delivers it, and an earlier version of this comment called itself
/// "the authoritative single-point fence", which was false in the way that matters:
/// there is exactly ONE call site, [`refresh_token_grant`], so the sentence described
/// a fence covering the refresh grant as though it covered the code exchange too. The
/// invariant does hold on the code exchange, but by a DIFFERENT and unrelated
/// mechanism, and a reader who did not know that could either add a redundant read to
/// the hottest path in the product or, worse, remove the real fence believing this one
/// covered them.
///
/// What actually fences the CODE EXCHANGE is the SESSION cascade: delete, block, and
/// disable each revoke every one of the subject's `sessions` rows, and the
/// `client_sessions` derived from them, in the same audited transaction as the
/// lifecycle write. How many reads of that revoked state stand between a fenced
/// subject and a token DEPENDS ON THE REQUESTED SCOPE, which is the part that is easy
/// to get wrong and that an earlier version of this comment did get wrong (it said
/// "three", on every scope).
///
/// On an ordinary `openid` exchange there are FOUR:
///
///   1. [`resolve_code_exchange_sid`]'s session liveness read, which refuses
///      `invalid_grant` BEFORE the mint resolves any role or permission.
///   2. `ClientSessionRepo::ensure_sid`, called from that SAME function: its INSERT
///      selects from `sessions` under the same liveness guard and answers `NotFound`
///      for a dead session, which maps to `server_error`, still before the mint. Rungs
///      1 and 2 are therefore NOT independent; ONE edit deletes both.
///   3. `RefreshFamilyRepo::issue`'s `FOR UPDATE` `lock_bound_session_live`.
///   4. The session EXISTS predicate on that same statement's `INSERT ... SELECT`.
///
/// Rungs 3 and 4 each refuse on their own, measured: with rungs 1, 2 and 3 neutered the
/// exchange is still refused, and so it is with rungs 1, 2 and 4 neutered. Only with
/// all four gone does a token reach the client, and it was measured doing so, a `200`
/// carrying an access token, an ID token and a refresh token for a soft-deleted
/// subject.
///
/// On an `offline_access` exchange there are TWO. An offline family deliberately
/// survives the session cascade (issue #21), so `issue` skips the lock under
/// `if !family.offline && ...` and its INSERT predicate
/// `AND ($9 OR g.session_ref IS NULL OR EXISTS(...))` is satisfied outright by
/// `$9 = family.offline`. Rungs 3 and 4 do not run at all, and the WHOLE fence is the
/// two reads inside [`resolve_code_exchange_sid`], one edit apart.
///
/// # The rung counts above assume the grant HAS a session, and all four do (issue #241)
///
/// Every count in this comment is conditioned on `session_ref` being present, and each
/// rung is separately conditioned on it, which is easy to miss because they are in three
/// different places. Rungs 1 and 2 sit behind [`resolve_code_exchange_sid`]'s
/// `let Some(session_ref) = .. else`. Rung 3, `lock_bound_session_live`, returns `Ok(true)`
/// outright for a NULL `session_ref` ("not session-bound: open unconditionally"). Rung 4's
/// `INSERT ... SELECT` predicate is `AND ($9 OR g.session_ref IS NULL OR EXISTS(..))` and
/// the middle disjunct satisfies it.
///
/// So for a grant with NO session the ladder was not shorter, it was ABSENT, on the
/// `openid` scope as much as on `offline_access`: a blocked or soft-deleted subject's code
/// minted an access token, an ID token, and a refresh family. That is reachable only for a
/// code row an older build persisted and a rolling upgrade redeems inside the code TTL, so
/// it is narrow, but it was the widest of the three holes issue #241 closed. The `else`
/// branch now calls [`ensure_subject_can_authenticate`] directly, and
/// `a_fenced_user_cannot_exchange_a_session_less_authorization_code` in
/// `crates/ironauth-oidc/tests/refresh.rs` is what keeps it there.
///
/// Both scopes are pinned, separately, by
/// `a_fenced_user_cannot_exchange_an_outstanding_authorization_code` and
/// `a_fenced_user_cannot_exchange_an_offline_access_authorization_code` in
/// `crates/ironauth-oidc/tests/refresh.rs`. Separately, because the `openid` test alone
/// is VACUOUS for the edit that matters: with [`resolve_code_exchange_sid`] neutered
/// the ENTIRE `ironauth-oidc` suite stayed green, measured, and the `offline_access`
/// variant is the one test that turns that mutant red.
///
/// Rungs 3 and 4 are not equivalent to rungs 1 and 2 even where they do run, because
/// they fire AFTER the atomic redeem: they DISCARD a token that was already minted and
/// recorded rather than preventing the mint. Measured on the `openid` path, a refused
/// exchange on the shipped tree leaves the code's `consumed_at` UNSET and writes zero
/// `issued_tokens` rows, zero `refresh_families`, zero `token_size_events` and no
/// `authorization_code.redeem` audit row; under a mutant where only rung 3 fires the
/// SAME refusal leaves `consumed_at` SET, two `issued_tokens` rows and one
/// `authorization_code.redeem` audit row asserting a successful redemption. The client
/// is refused either way. The store is not in the same state, and the audit trail
/// records the opposite thing.
///
/// # The residual, stated rather than argued from a rung count
///
/// The choice NOT to add an explicit lifecycle read to the code exchange is still the
/// right one, but not for the "already true three times over" reason the earlier
/// version of this comment gave. It rests on this: the two reads that fence the offline
/// path both run before anything is minted, both fail closed, and both are now pinned
/// by a test on the exact scope where nothing else backs them up. The residual is that
/// those two live in ONE function, so a single careless edit removes the entire
/// code-exchange fence for an `offline_access` grant, and one test is what stands
/// between that edit and a merge. That margin is thinner than the refresh grant's, and
/// it belongs in the open rather than behind a number.
///
/// The two grants are therefore fenced by two different mechanisms, deliberately. The
/// refresh grant NEEDS this explicit check precisely because an `offline_access` family
/// survives the session cascade by design (issue #21), so the mechanism that covers the
/// code exchange cannot reach it.
///
/// Fails CLOSED (`invalid_grant`) when the subject is not authenticatable (blocked,
/// disabled, pending-verification) or is absent/deleted, and treats a store fault as
/// fail-closed too, never fail-open. A NORMAL active (or scheduled-offboarding) user
/// is authenticatable, so an ordinary refresh is unaffected.
pub(crate) async fn ensure_subject_can_authenticate(
    state: &OidcState,
    scope: Scope,
    subject: &str,
) -> Result<(), TokenError> {
    match subject_can_authenticate(state, scope, subject).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(TokenError::InvalidGrant),
        Err(error) => Err(map_store_error(error)),
    }
}

/// THE user-lifecycle read, the one place in this crate that asks the store whether a
/// user-bound subject may still obtain tokens (issue #52, extended by issue #241).
///
/// Three callers need three DIFFERENT wire answers from the same question, so the read
/// is separated from the mapping rather than copied: [`ensure_subject_can_authenticate`]
/// renders it as `invalid_grant` for the refresh grant, the code exchange, and the
/// device grant; [`crate::jwt_bearer`] renders it as that grant's uniform `invalid_grant`
/// PLUS an out-of-band `principal_not_authenticatable` diagnostic. A copied read would be
/// three places for a future edit to miss two of.
///
/// Returns `Ok(false)`, meaning FENCED, for every non-authenticatable outcome the store can
/// report: a blocked, disabled, or pending-verification user, and equally an absent,
/// soft-deleted, cross-scope, or corrupt-state row, all of which
/// [`ironauth_store::UserRepo::state_for_subject`] collapses to [`None`]. Active and
/// scheduled-offboarding are the two states that answer `Ok(true)`.
///
/// # Errors
///
/// [`ironauth_store::StoreError`] on a persistence failure. Every caller treats it as
/// fail CLOSED; the error is returned rather than swallowed so each can pick its own
/// closed answer (`server_error` for the grants that map store faults that way).
pub(crate) async fn subject_can_authenticate(
    state: &OidcState,
    scope: Scope,
    subject: &str,
) -> Result<bool, StoreError> {
    Ok(state
        .store()
        .scoped(scope)
        .users()
        .state_for_subject(subject)
        .await?
        .is_some_and(|user_state| user_state.can_authenticate()))
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

    // The shared grant-restriction seam (issue #763), before the family is touched, for
    // the same reason as the code path.
    enforce_registered_grant_for(state, &authenticated_client, GrantType::RefreshToken)?;

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

    // 4a-bis. Enforce the IMPERSONATION cap (issue #101) before minting anything.
    //
    // An impersonation LAPSE fires no session event, so the cascade that revokes a family when
    // its session ends never runs for one. Without this an operator who impersonated a user
    // for a justified ten minutes could keep refreshing indefinitely.
    //
    // Read off the FAMILY, not the session: a refresh holds a grant and may have no live
    // session, offline families are designed to outlive theirs, and an RFC 8693 exchange will
    // be in the same position. The bound was copied from the session when the family was
    // minted, so it cannot be pushed out afterwards.
    if let Some(impersonation) = resolution.impersonation.as_ref() {
        if epoch_micros(state.now()) >= impersonation.expires_at_unix_micros {
            return Err(TokenError::InvalidGrant);
        }
    }

    // 4b. Re-check the token subject's USER LIFECYCLE state (issue #52) before minting
    //     anything: a user blocked, disabled, or deleted AFTER a SURVIVING
    //     offline_access family was opened (issue #21) must not keep minting. Fail
    //     closed (including on a store fault); a normal active user is unaffected.
    ensure_subject_can_authenticate(state, scope, &resolution.subject).await?;

    // 4c. Enforce the family's DPoP binding (RFC 9449 section 5, issue #368 PR3)
    //     BEFORE minting or the atomic redeem. A family issued DPoP-bound can ONLY be
    //     rotated by a request carrying a valid proof for the SAME key; an unbound
    //     family stays bearer (its DPoP header, if any, is ignored). A bound family
    //     with no proof, a wrong-key proof, or a replayed jti is the uniform
    //     invalid_dpop_proof, and because this runs before the redeem it neither
    //     rotates nor revokes the family (no DoS on a legitimate holder).
    let dpop_confirmation = enforce_refresh_dpop(state, headers, resolution.dpop_jkt.as_deref())?;
    // The DPoP-by-default posture (issue #124) on the refresh path too. An UNBOUND
    // family reaches `enforce_refresh_dpop`'s permissive branch, so without this a
    // public client could sidestep the posture entirely by refreshing a family it had
    // obtained before the posture was turned on: the exchange would be constrained
    // and every renewal after it would not.
    enforce_public_client_dpop(&authenticated_client, dpop_confirmation.as_ref())?;

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
    //    authentication happened, so the ID token stays with the code exchange. A
    //    bound family re-binds the rotated access token to the SAME DPoP key (cnf),
    //    so the binding is never lost across a rotation.
    let (minted, expires_in) = mint_refresh_access(
        state,
        scope,
        &resolution,
        &target,
        dpop_confirmation.as_ref(),
    )
    .await?;

    // 7. Pre-generate the successor refresh token, used when rotating or on a
    //    within-grace concurrent refresh.
    let successor = tokens::mint_refresh_token(state, &scope);
    let now = state.now();
    let successor_idle = epoch_micros(
        now.checked_add(state.refresh_idle_ttl(resolution.offline))
            .unwrap_or(now),
    );
    let next_gen = i32::try_from(resolution.generation.saturating_add(1)).unwrap_or(i32::MAX);

    // 8. Build the access-token records to persist against the grant. A bound family
    //    re-records the DPoP thumbprint on an opaque rotated token, exactly as the
    //    code exchange does, so an opaque access token stays sender-constrained too.
    let dpop_jkt = dpop_confirmation.as_ref().map(Confirmation::value);
    let (access_records, opaque) = refresh_access_records(&minted, &resolution, dpop_jkt);

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
            dpop_confirmation.is_some(),
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
            dpop_confirmation.is_some(),
        )),
        // Not rotated (a confidential/bound client under the threshold): a fresh
        // access token and the SAME refresh token.
        Ok(RefreshRedeemOutcome::NotRotated) => Ok(refresh_response(
            &minted,
            expires_in,
            resolution.scope.as_deref(),
            Some(presented),
            dpop_confirmation.is_some(),
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
///
/// The one thing this does NOT replay from the family is the effective organization
/// role set (issue #97): it is re-resolved here, from the store, on every refresh.
/// That hook is load-bearing rather than incidental. Refresh is the highest-volume
/// grant, so a role change that only took effect on a NEW code exchange would be
/// invisible for the entire refresh-family lifetime; re-resolving here is what caps
/// the exposure at ONE ACCESS TOKEN LIFETIME. Do not "optimize" it into a frozen
/// `resolution` field.
async fn mint_refresh_access(
    state: &OidcState,
    scope: Scope,
    resolution: &RefreshTokenResolution,
    target: &AccessTokenTarget,
    confirmation: Option<&Confirmation>,
) -> Result<(MintedAccessToken, i64), TokenError> {
    // FRESH at every refresh (issue #97, #98), in the org context frozen onto the family's
    // grant. Fails closed: a store fault refuses the refresh rather than rotating out
    // an access token whose missing roles read as a successful authorization downgrade.
    let roles = resolve_effective_roles(
        state,
        scope,
        &resolution.subject,
        resolution.org_id.as_deref(),
    )
    .await?;
    // The effective PERMISSIONS (issue #98), re-resolved here for the same reason and
    // never replayed from the family. This hook is also where the budget event first
    // observes the refresh grant at all: the sink it writes to has only ever seen code
    // exchanges, so the highest-volume grant has been invisible to it until now.
    let permissions = resolve_effective_permissions(
        state,
        scope,
        &resolution.subject,
        resolution.org_id.as_deref(),
        target.emits_permission_claims(),
    )
    .await?;
    let entry = grant_issuer_entry(state, scope).await?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    let subject = state.resolve_public_subject(&resolution.subject);
    // The client's declarative mapping (issue #113 criterion 4), applied on REFRESH as well as
    // on the code exchange, and that is not symmetry for its own sake. Refresh is the
    // highest-volume grant, so a mapping that only shaped the code exchange would be bypassed by
    // any client that simply refreshes: an operator's `filter_list` on `groups` would hold for
    // one token and be gone for the rest of the family's life.
    //
    // The source is EMPTY here, and that is a KNOWN LIMITATION rather than the correct answer.
    // An earlier version of this comment called it correct; review measured otherwise, and the
    // measurement is worth writing down.
    //
    // `static` rules act. A `rename`, a `filter_list`, or a `place` naming a claim the SERVER
    // resolved has nothing to work on, because the refresh path mints no ID token and replays
    // no `claims` parameter -- so `place email -> access_token` puts `email` in the first
    // access token and NOT in the refreshed one. A resource server authorizing on a mapped
    // claim breaks on the client's first refresh, silently.
    //
    // Fixing it means re-resolving the user's scope-derived claims on refresh, which changes
    // what a refreshed access token carries well beyond the mapping and is a decision about
    // what refresh REPLAYS -- not one to make inside the change that adds a mapping reader.
    // Filed on #113.
    //
    // The mapping is still applied here rather than skipped, and that is not for symmetry: a
    // `static` rule works, and skipping the door entirely would let a client reach an unmapped
    // token by refreshing, which is a documented way around the control rather than a gap in
    // it. A fault still fails the refresh, for the reason `claims_mapping_at_issuance` gives.
    let mut extra_claims = serde_json::Map::new();
    let access_extra_claims = apply_claims_mapping(
        state,
        scope,
        &resolution.client_id,
        crate::registry::GrantType::RefreshToken.as_str(),
        Some(&resolution.subject),
        &mut extra_claims,
    )
    .await?;
    let minted = tokens::mint_access_token(
        state,
        signer,
        entry.policy(),
        &MintRequest {
            // The `act` claim rides the FAMILY (issue #101), copied from the session when
            // the family was minted. The bound checked earlier means a family past its cap
            // never reaches here, so a token carrying this claim is one the impersonation
            // still authorizes.
            actor: resolution
                .impersonation
                .as_ref()
                .map(|imp| tokens::TokenActor {
                    subject: &imp.impersonator,
                    reason_code: &imp.reason_code,
                }),
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
            // The DURABLE organization context (issue #94, PR-B1), read from the
            // family's grant, so a refreshed access token keeps the same `org_id` the
            // code exchange minted. None when the grant carried no org.
            org_id: resolution.org_id.as_deref(),
            // The effective organization roles (issue #97), re-resolved above rather
            // than replayed: THIS is what makes a role change visible one access-token
            // lifetime after it happens instead of one refresh-family lifetime.
            roles: roles.as_ref(),
            // The effective organization permissions (issue #98), re-resolved above
            // rather than replayed, for the same reason and one step more sharply: a
            // permission names an API capability.
            permissions: permissions.as_ref(),
            at_hash: None,
            c_hash: None,
            extra_claims: &extra_claims,
            // The refresh path mints only an access token (no ID token), so the
            // per-client id_token signer (#30) is inert here; mint_access_token
            // never reads it.
            id_token_signer: None,
            // Re-bind the rotated access token to the family's DPoP key (RFC 9449,
            // issue #368 PR3). [`Some`] only when the family is bound and a matching
            // proof was presented (enforced in [`enforce_refresh_dpop`]); [`None`]
            // leaves an unbound family's rotated token bearer, byte identical.
            confirmation,
            // The client's declarative mapping (issue #113), resolved above. Empty when no
            // mapping is configured. Fenced by the CHANNEL, so a protected name is dropped
            // whatever writes into it.
            access_extra_claims: &access_extra_claims,
        },
        target,
    )
    .map_err(|()| TokenError::ServerError)?;
    // The budget verdict from the REFRESH hook (issue #98), recorded through the same
    // one function the code exchange records through, so the two grants can never
    // report the same verdict differently.
    record_budget_outcome(
        state,
        scope,
        &resolution.client_id,
        target,
        resolution.org_id.as_deref(),
        minted.permission_budget,
    )
    .await;
    Ok((minted.access, minted.expires_in_secs))
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
        .resource_policy(StoredClientId::Registered(client_id))
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
    dpop_jkt: Option<&'a str>,
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
                // Re-record the family's DPoP thumbprint on the rotated opaque token
                // (RFC 9449, issue #368 PR3) so it stays sender-constrained across
                // rotations; [`None`] for an unbound family leaves it bearer.
                dpop_jkt,
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
    dpop_bound: bool,
) -> Response {
    // RFC 9449 section 5: a refresh of a DPoP-bound family re-binds the rotated access
    // token to the same key, so the response advertises `DPoP` and the client presents
    // the token with a fresh proof. An unbound family stays `Bearer`, byte identical.
    let token_type = token_type_for_dpop(dpop_bound);
    let mut body = serde_json::json!({
        "access_token": minted.token(),
        "token_type": token_type,
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
