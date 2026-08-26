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
//! `Ok(false)` for seven different reasons and have to guess which applied, and answering
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
/// `auth_req_id` that is unknown or belongs to another client.
///
/// NOT for one in another SCOPE, which the previous version of this sentence claimed and
/// which is measurably false: `auth_req_id_scope` recovers the DECLARED scope from the
/// credential, so `authenticate_token_client` runs in that scope, does not find the caller's
/// client there, and answers `401 invalid_client`. Another scope is therefore always
/// distinguishable from unknown. That does not weaken the oracle argument on the `NotFound`
/// arm below, which is about not distinguishing an unknown request from ANOTHER CLIENT'S
/// request within one scope, but the two had been written as though they were the same
/// claim. An ABSENT or blank `auth_req_id` is `invalid_request`, because the request itself
/// is malformed. A PRESENT but unusable one, from which no scope can be recovered, is
/// `invalid_grant`: the request is well formed and the grant is not. That is the split this
/// grant's own test drives, and the third consecutive version of this paragraph to state it
/// wrongly. The previous one said "malformed or absent" was `invalid_request` while a test
/// two files away asserted `invalid_grant` for the malformed half.
///
/// An ALREADY REDEEMED `auth_req_id` is deliberately not in that list, because it does not
/// answer `invalid_grant`. `poll` evaluates the interval before the status, so a spent
/// request polled inside its interval answers `slow_down` and outside it `expired_token`.
/// Neither is wrong for a client (both are terminal-or-retry codes it already handles), but
/// the earlier version of this paragraph promised a code the endpoint does not send, and a
/// spent request answering `slow_down` is worth knowing about: `slow_down` is defined as a
/// variant of `authorization_pending`, so a client that redeemed once and asks again is told
/// to keep polling something it has already spent. Bounded by the request TTL.
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

    // THE user-lifecycle fence. Neither mechanism that fences this crate's other mints
    // reaches a CIBA request, so this grant has to ask directly.
    //
    // The session cascade cannot: `cascade_user_sessions_ended` ends `sessions`,
    // `client_sessions` and `refresh_families`, and a backchannel request row records no
    // session at all (`decide` inserts its grant with `session_ref = NULL`). Grant
    // revocation cannot either: `verify_redemption_grant`'s only liveness term is
    // `revoked_at IS NULL`, and `cascade_families_for_subject` revokes a grant only under
    // `hard_kill` and only when a `refresh_families` row names it. This grant issues no
    // refresh token, so it has no family, so even `delete_user` leaves the approval live.
    //
    // Without this call a blocked, disabled, or soft-deleted user's outstanding approval
    // still mints a full ID and access token for the whole request TTL. Measured, before it
    // was added: 200 with live tokens for both a Blocked and a soft-deleted user.
    //
    // How recoverable that is depends on a deployment setting, and an earlier version of
    // this comment asserted the worse half as though it were the only one. Under
    // `oidc.default_access_token_format = at_jwt` (the default), the access token is
    // self-contained and nothing takes it back before its own expiry. Under `opaque` this
    // grant mints an `ira_at_` reference token, recorded against the authoritative grant id,
    // and `resolve_opaque_access_token` filters on `g.revoked_at IS NULL`, so revoking the
    // grant does revoke it. The ID token carries no `sid` in either configuration, so
    // back-channel logout has nothing to target either way.
    //
    // Unconditional rather than gated on the subject's SHAPE, for the reason
    // `resolve_device_sid` gives for its own session-less branch: a CIBA `subject` is a
    // `usr_` id by construction, copied from the `users` row that `ciba.rs` resolved the
    // `login_hint` to. Nothing operator-authored reaches here, so there is no workload
    // identity to exempt.
    crate::token::ensure_subject_can_authenticate(state, scope, &approved.subject).await?;

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
    // FAIL CLOSED on a missing `amr`, rather than passing `""` through.
    //
    // `authn::parse_methods("")` does not return "no methods": its `if methods.is_empty()`
    // fallback returns `vec![AuthMethod::Password]`, and `achieved_acr` on that set returns
    // the password ACR. So `unwrap_or("")` here made the server sign `amr: ["pwd"]` and a
    // password `acr` for an authentication it never witnessed, which is precisely what the
    // paragraph above says this grant must not do. Measured, before this guard: an approval
    // stored with `auth_methods: None` minted `{"acr":"urn:ironauth:acr:pwd","amr":["pwd"]}`.
    //
    // The state is reachable: `BackchannelApprovalLinkage::auth_methods` is an `Option`
    // defaulting to `None`, `decide` binds it straight through, and
    // `approval_linkage_is_usable` checks only the grant. An approval that recorded no
    // method cannot be turned into an honest assertion by this layer, so it is refused as
    // an unusable grant instead of being guessed at.
    // The check is on RECOGNITION, not on emptiness. An earlier version of this guard
    // rejected only `None` and blank-after-trim, which closed one door and left the wider
    // one open: `parse_methods` filters to tokens it recognizes AND that are currently
    // active, and falls back to `[AuthMethod::Password]` whenever THAT set comes out empty.
    // So any non-blank string of unrecognized spellings landed in exactly the same
    // fallback. Measured against the narrower guard: `Some("smartcard")` and
    // `Some("pwd,otp")` (a comma, where the parser splits on whitespace) both minted
    // `acr: "urn:ironauth:acr:pwd"` and `amr: ["pwd"]`.
    //
    // The wider door is the more reachable one. `BackchannelApprovalLinkage::auth_methods`
    // is a free-form `Option<&str>` that `decide` binds through with no validation, and the
    // approval surface that will eventually populate it passes a string: one wrong spelling
    // ("webauthn" for the token this crate actually uses) silently asserts a password
    // authentication that never happened.
    //
    // Every OTHER `parse_methods` caller reads a value written by `methods_token`, so it
    // round-trips by construction and cannot reach the fallback. CIBA is the only caller
    // whose input crosses a trust boundary this layer does not own, so the check belongs
    // here rather than inside `parse_methods`, whose under-claiming fallback is correct for
    // the callers it was written for.
    //
    // What it does NOT close, said plainly because the trust-boundary argument above applies
    // to it just as well: a wrong spelling naming a RECOGNIZED but stronger method still
    // asserts more than happened. `Some("attested_passkey")` mints the top-ranked `acr`, and
    // `Some("trusted_device")` mints the remembered-MFA `acr` with an empty `amr`. This
    // guard only stops an unrecognized string from becoming `pwd`; bounding what an approval
    // may claim belongs with the surface that writes it.
    //
    // And a THIRD residual, the widest of them: `authn`'s reserved `fedamr:` token carries an
    // upstream `amr` through verbatim. A value like `"pwd fedamr:<base64>"` passes this guard
    // on its `pwd` token, and the decoded payload is then appended to the signed `amr` as-is,
    // so an approval could assert arbitrary upstream method strings. Same deferral and the
    // same reason as the two above: `auth_methods` has no production writer today, because
    // `decide` has no non-test caller. All three want bounding where the approval surface
    // lands, and they are enumerated here so that work does not have to rediscover them.
    let auth_methods = approved
        .auth_methods
        .as_deref()
        .map(str::trim)
        .filter(|methods| !methods.is_empty())
        .ok_or(TokenError::InvalidGrant)?;
    if !auth_methods
        .split_whitespace()
        .filter_map(crate::authn::AuthMethod::from_token)
        .any(crate::authn::AuthMethod::is_active)
    {
        return Err(TokenError::InvalidGrant);
    }

    let mut extra_claims = serde_json::Map::new();
    // The client's declarative mapping (issue #113 criterion 4), applied on EVERY door that
    // mints a token for this client, not only the ones an operator is likely to test. A mapping
    // can REMOVE a claim -- `filter_list` exists so a token does not carry three thousand group
    // names -- so a door that skipped it would issue MORE than the operator configured, and
    // whichever door that is becomes the one to use. A fault fails the issuance, for the reason
    // `claims_mapping_at_issuance`'s header gives.
    let access_extra_claims = crate::claims_mapping_at_issuance::apply_to_with_hook(
        state.store(),
        state.hook_engine(),
        scope,
        &client_id,
        "urn:openid:params:grant-type:ciba",
        Some(&approved.subject),
        &mut extra_claims,
    )
    .await
    .map_err(|_| TokenError::ServerError)?;
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
            auth_methods,
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
            // The client's declarative mapping (issue #113), resolved above. Empty when no
            // mapping is configured. Fenced by the CHANNEL, so a protected name is dropped
            // whatever writes into it.
            access_extra_claims: &access_extra_claims,
        },
        &target,
    )
    .map_err(|()| TokenError::ServerError)
}
