// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CIBA poll grant at the token endpoint (CIBA Core 1.0 section 11, issue #131).
//!
//! A client that started a backchannel authentication holds an `auth_req_id` and polls here
//! until the user decides on their own device. This is the half that turns the store methods
//! into a flow a client can actually use.
//!
//! # Poll first, then redeem
//!
//! The shape mirrors the device grant deliberately, and the reason is written into
//! `BackchannelAuthRepo::redeem_approved`'s own documentation: `poll` maps each state to the
//! error code CIBA Core section 11 requires, so redemption is reached ONLY for a request the
//! user has approved. A caller that skipped the poll and redeemed directly would get
//! `Ok(false)` for six different reasons and have to guess which applied, and answering
//! `invalid_grant` to a request the user has not yet decided would stop a conforming client
//! polling before they answer (RFC 8628 section 3.5, which CIBA imports).
//!
//! With the poll in front, `Ok(false)` from the redemption means one thing: another
//! redemption won the race. `invalid_grant` is right for that.

use axum::http::HeaderMap;
use axum::response::Response;
use ironauth_store::{
    BackchannelAuthRequestId, BackchannelPoll, BackchannelRedemption, IssuedTokenRecord,
    NewOpaqueAccessToken, RedeemedBackchannelRequest, Scope, TokenKind,
};

use crate::device::{authenticate_token_client, device_token_response};
use crate::error::TokenError;
use crate::registry::GrantType;
use crate::state::OidcState;
use crate::token::TokenParams;
use crate::tokens::{self, IssuedTokens, MintRequest, MintedAccessToken};
use crate::util::epoch_micros;

/// The prefix and delimiter shape `mint_auth_req_id` produces. Recovering the scope from the
/// presented credential is what lets this run before any scoped store handle exists, exactly
/// as `device_code_scope` does for the device grant.
fn auth_req_id_scope(auth_req_id: &str) -> Option<Scope> {
    let rest = auth_req_id.strip_prefix(crate::ciba::AUTH_REQ_ID_PREFIX)?;
    let handle = rest
        .split(crate::tokens::OPAQUE_ACCESS_TOKEN_DELIMITER)
        .next()?;
    BackchannelAuthRequestId::parse_declared_scope(handle)
        .ok()
        .map(|id| id.scope())
}

/// Exchange an approved `auth_req_id` for tokens.
///
/// # Errors
///
/// Every CIBA Core section 11 code, mapped from the poll: `authorization_pending` while the
/// user has not answered, `slow_down` when the client polled faster than its interval,
/// `access_denied` on refusal, `expired_token` past the TTL, and `invalid_grant` for an
/// `auth_req_id` that is unknown, belongs to another client, or has already been redeemed.
pub async fn ciba_grant(
    state: &OidcState,
    headers: &HeaderMap,
    params: TokenParams,
) -> Result<Response, TokenError> {
    let auth_req_id = params
        .auth_req_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TokenError::InvalidRequest("auth_req_id is required".to_owned()))?;
    let scope = auth_req_id_scope(auth_req_id).ok_or(TokenError::InvalidGrant)?;

    // Authenticate BEFORE touching poll state, so an unauthenticated caller cannot advance a
    // flow or move its interval. The device grant orders it the same way and for the same
    // reason.
    let authenticated = authenticate_token_client(state, scope, headers, &params).await?;
    crate::token::enforce_registered_grant_for(state, &authenticated, GrantType::Ciba)?;

    let digest = crate::ciba::auth_req_id_digest(auth_req_id);
    let now_micros = epoch_micros(state.now());
    let slow_down_increment =
        i32::try_from(state.device_slow_down_increment_secs()).unwrap_or(i32::MAX);

    let outcome = state
        .store()
        .scoped(scope)
        .backchannel_auth()
        .poll(
            &digest,
            &authenticated.client_id,
            now_micros,
            slow_down_increment,
        )
        .await
        .map_err(crate::token::map_store_error)?;

    match outcome {
        BackchannelPoll::Pending => Err(TokenError::AuthorizationPending),
        BackchannelPoll::SlowDown { .. } => Err(TokenError::SlowDown),
        BackchannelPoll::Denied => Err(TokenError::AccessDenied),
        BackchannelPoll::Expired => Err(TokenError::ExpiredToken),
        // An unknown request, another client's request, and one in another scope are one
        // answer here on purpose: distinguishing them would make polling an existence oracle
        // over other clients' requests. CIBA Core section 11 makes `invalid_grant` a MUST for
        // the first two.
        BackchannelPoll::NotFound => Err(TokenError::InvalidGrant),
        BackchannelPoll::Approved => {
            issue_ciba_tokens(state, scope, &digest, &authenticated.client_id).await
        }
    }
}

async fn issue_ciba_tokens(
    state: &OidcState,
    scope: Scope,
    digest: &str,
    client_id: &str,
) -> Result<Response, TokenError> {
    let now_micros = epoch_micros(state.now());
    let approved = state
        .store()
        .scoped(scope)
        .backchannel_auth()
        .approved_details(digest, client_id, now_micros)
        .await
        .map_err(crate::token::map_store_error)?
        .ok_or(TokenError::InvalidGrant)?;

    // MINTED BEFORE THE CONSUME, exactly as the device and authorization-code grants order
    // it: a signing failure must not burn an approval the person gave on another device.
    let minted = mint_ciba_tokens(state, scope, client_id, &approved).await?;

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
            grant_id: None,
            subject: &approved.subject,
            client_id,
            audience: audiences.first().map_or("", String::as_str),
            audiences,
            scope: approved.requested_scope.as_deref(),
            jti,
            expires_at_unix_micros: *expires_at_unix_micros,
            dpop_jkt: None,
        }),
    };

    // The client is the actor, as it is for the device grant: this issuance is the client
    // presenting its own credential, not a human acting.
    let ciba_client = ironauth_store::ClientId::parse_in_scope(client_id, &scope)
        .map_err(|_| TokenError::ServerError)?;
    let actor =
        crate::util::client_service_actor(ironauth_store::StoredClientId::Registered(&ciba_client));
    let correlation = ironauth_store::CorrelationId::generate(state.env());
    let redeemed = state
        .store()
        .scoped(scope)
        .backchannel_auth()
        .redeem_approved(
            state.env(),
            &ironauth_store::ActingContext::new(actor, correlation),
            BackchannelRedemption {
                auth_req_id_digest: digest,
                presenting_client_id: client_id,
                now_micros,
                grant_id: &approved.grant_id,
                tokens: &records,
                opaque,
            },
        )
        .await
        .map_err(crate::token::map_store_error)?;

    // `false` means the flip matched no row, and with the poll in front of us the only way
    // that happens is another redemption winning the race. Every other cause was already
    // answered with its own code above.
    if !redeemed {
        return Err(TokenError::InvalidGrant);
    }

    Ok(device_token_response(
        &minted,
        approved.requested_scope.as_deref(),
        None,
    ))
}

/// Mint the ID and access tokens for an approved backchannel request.
///
/// The approval already froze everything an honest ID token needs, which is why
/// `approved_details` returns it: `auth_methods` is the `amr` and `auth_time` is the
/// `auth_time`. A grant that invented either would be asserting something about an
/// authentication it did not witness.
///
/// `sid` is `None`, deliberately and visibly. The device grant resolves one because a device
/// approval happens through a (client, session) row the code flow also uses; a CIBA approval
/// arrives from whatever surface the user answered on, and the request row records no session
/// reference. Inventing one would make `backchannel_logout_session_supported` claim a session
/// that no logout could target. Wiring a real one belongs with the approval surface.
async fn mint_ciba_tokens(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    approved: &RedeemedBackchannelRequest,
) -> Result<IssuedTokens, TokenError> {
    let entry = crate::token::grant_issuer_entry(state, scope).await?;
    let signer = entry.signer(state.now()).ok_or(TokenError::ServerError)?;
    let issuer = state.issuer_for(&scope);
    let subject = state.resolve_public_subject(&approved.subject);
    let client_id = client_id.to_owned();
    let target = state
        .resolve_access_token_target(&scope, &[], &client_id)
        .await
        .map_err(|_| TokenError::ServerError)?;
    let extra_claims = serde_json::Map::new();
    tokens::mint(
        state,
        signer,
        entry.policy(),
        &MintRequest {
            actor: None,
            scope,
            issuer: &issuer,
            subject: &subject,
            client_id: &client_id,
            nonce: None,
            oauth_scope: approved.requested_scope.as_deref(),
            auth_methods: approved.auth_methods.as_deref().unwrap_or(""),
            auth_time_unix_micros: approved.auth_time_unix_micros,
            sid: None,
            org_id: None,
            roles: None,
            permissions: None,
            at_hash: None,
            c_hash: None,
            extra_claims: &extra_claims,
            id_token_signer: None,
            confirmation: None,
        },
        &target,
    )
    .map_err(|()| TokenError::ServerError)
}
