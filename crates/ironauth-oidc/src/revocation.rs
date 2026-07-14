// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OAuth 2.0 Token Revocation endpoint (`POST /revoke`, RFC 7009).
//!
//! Revocation lets a client invalidate a token it holds. Every edge here is a
//! privacy or a cascade decision:
//!
//! - **Any token, any format, routed by its own scope.** The endpoint accepts a
//!   refresh token (`ira_rt_`), an opaque access token (`ira_at_`), or a compact
//!   `at+jwt`, and (once issue #23 lands) a client-credentials access token, told
//!   apart by the token's OWN self-describing shape, never by the advisory
//!   `token_type_hint` (RFC 7009 makes the hint an optimization: the lookup falls
//!   back across types, which classification here IS). The token declares its own
//!   `(tenant, environment)` scope, exactly as the opaque `UserInfo` path does.
//! - **No existence oracle.** Once the client is authenticated, EVERY token outcome
//!   returns `200` with an empty body: an unknown token, a malformed one, an expired
//!   or already-revoked one, and a token belonging to a DIFFERENT client all look
//!   identical (RFC 7009 section 2.2), so a client cannot probe which tokens exist.
//! - **Confidential clients authenticate; a foreign token is unknown.** RFC 7009
//!   section 2.1 does not strictly require client auth for a public client, but a
//!   confidential client SHOULD authenticate. This endpoint authenticates the client
//!   through the SAME suite the token endpoint uses (a public `none` client
//!   authenticates by presenting its `client_id`), then revokes ONLY the client's OWN
//!   tokens: a token owned by another client is treated as unknown (still `200`, no
//!   effect). Authentication also fixes the `(tenant, environment)` scope from the
//!   client's own id, so a cross-tenant token can never be revoked here.
//! - **Revocation cascades through the grant.** The append-only `issued_tokens` /
//!   `opaque_access_tokens` rows derive their active state ONLY from
//!   `grants.revoked_at`, so revoking a token revokes its grant chain. Revoking a
//!   REFRESH token additionally revokes its whole FAMILY (reusing the #21 spine) AND
//!   the grant, so every access token derived from that refresh token immediately
//!   introspects as `active:false` (RFC 7009 section 2.1).
//!
//! # The internal revocation-event seam (external fan-out is M4)
//!
//! Every SUCCESSFUL revocation publishes a typed [`RevocationEvent`] on the internal
//! [`RevocationEventSink`] seam, so an in-process cache or a resource-server bridge
//! can react. Only the [`NoopRevocationSink`] ships now; the EXTERNAL fan-out (a
//! webhook / bus publish) is M4 and slots in as a new sink through
//! [`OidcState::with_revocation_sink`](crate::OidcState::with_revocation_sink)
//! WITHOUT touching this endpoint. The DURABLE record of every revocation is the
//! audit row the store writes in the SAME transaction as the state change
//! (`token.revoke` for an access token, `refresh_family.revoke` for a refresh token),
//! so the event seam is a reactive notification, never the system of record.

use std::sync::Arc;

use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ClientId, CorrelationId, GrantId, GrantOwner, IssuedTokenId, RefreshTokenId, Scope, StoreError,
};
use serde::{Deserialize, Serialize};

use crate::client_auth::{ClientAuthInputs, authenticate_client_self_scoped};
use crate::error::TokenError;
use crate::state::OidcState;
use crate::token_credential::{
    self, PresentedTokenKind, client_auth_error_response, opaque_handle, peek_jti,
};
use crate::tokens::{OPAQUE_ACCESS_TOKEN_PREFIX, OPAQUE_REFRESH_TOKEN_PREFIX};
use crate::util::client_service_actor;

/// The kind of token a [`RevocationEvent`] reports, so a consumer can react
/// differently to an access-token versus a refresh-token (family) revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokedTokenType {
    /// An access token (an at+jwt or an opaque reference token). Its grant chain was
    /// revoked.
    AccessToken,
    /// A refresh token. Its whole family AND its grant chain were revoked.
    RefreshToken,
}

/// A typed internal revocation event, published on every successful revocation
/// (issue #22).
///
/// This is the STABLE, shape-locked payload a cache or a resource-server bridge
/// consumes off the internal [`RevocationEventSink`], and the shape the M4 external
/// fan-out will serialize. Its schema is pinned by a snapshot test, so a field rename
/// or reorder is a deliberate, reviewed change (the reuse-event snapshot pattern from
/// issue #21). It names WHAT was revoked (never any token secret): the scope, the
/// owning client, the token kind, and the revoked grant (and family, for a refresh
/// token), all non-secret scoped identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationEvent {
    /// The tenant the revocation happened in.
    pub tenant: String,
    /// The environment the revocation happened in.
    pub environment: String,
    /// The client that owns the revoked token (and that requested the revocation).
    pub client_id: String,
    /// Whether an access token or a refresh token was revoked.
    pub token_type: RevokedTokenType,
    /// The grant whose chain was revoked (the revocation spine every derived token
    /// resolves its active state from).
    pub grant_id: String,
    /// The refresh-token family that was revoked, present ONLY for a refresh-token
    /// revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_id: Option<String>,
}

/// Why a session lifecycle signal fired (issue #32), so a consumer can tell a
/// session ENDING apart from a session-fixation ROTATION.
///
/// This is the crux of the "a rotation must not look like a terminal revoke to a
/// naive consumer" requirement: a [`SessionSignalCause::Rotated`] event is NOT a
/// terminal end (a successor session succeeds it, carried in
/// [`SessionLifecycleEvent::successor_session_id`]), while every other cause IS a
/// terminal end. [`SessionSignalCause::is_terminal`] answers that in one call, so a
/// naive consumer never mistakes a rotation for a logout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSignalCause {
    /// The session identifier was ROTATED at a privilege transition (login, and the
    /// future MFA / step-up seam). NOT a terminal end: a successor session exists.
    Rotated,
    /// The session was ended by the end user's RP logout.
    LoggedOut,
    /// The session was revoked by an operator (a single-session revoke).
    Revoked,
    /// The session was revoked as one item of a bulk revocation.
    BulkRevoked,
    /// The session was revoked by a revoke-everything-for-a-user.
    UserRevokedAll,
}

impl SessionSignalCause {
    /// Whether this cause is a TERMINAL end of the session. A rotation is NOT
    /// terminal (a fresh session succeeds it); every revoke/logout cause is.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        !matches!(self, SessionSignalCause::Rotated)
    }
}

/// A typed session lifecycle signal (issue #32), published whenever a session is
/// rotated or ended, so the durable session-ended fan-out (#35) can later be built on
/// this seam without touching the emit sites. Its schema is shape-locked by a
/// snapshot test (the reuse-event pattern from #21), so a rename or reorder is a
/// deliberate, reviewed change. It names WHAT happened to WHICH session (never any
/// bearer secret): the scope, the session id, the cause, and (for a rotation only)
/// the successor session id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionLifecycleEvent {
    /// The tenant the session belongs to.
    pub tenant: String,
    /// The environment the session belongs to.
    pub environment: String,
    /// The session that was rotated or ended (a `ses_` id).
    pub session_id: String,
    /// Why the signal fired: a rotation (non-terminal) or an end (terminal).
    pub cause: SessionSignalCause,
    /// The successor session id, present ONLY for a rotation (so a consumer knows a
    /// fresh session succeeded this one and this is NOT a terminal end).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successor_session_id: Option<String>,
}

/// The internal seam a successful revocation is published on (issue #22).
///
/// The endpoint publishes a [`RevocationEvent`] here for every revocation that
/// actually flipped state, so an in-process cache or resource-server bridge can
/// react. The EXTERNAL fan-out (a durable webhook / bus publish) is M4; it lands as a
/// new implementor wired through
/// [`OidcState::with_revocation_sink`](crate::OidcState::with_revocation_sink),
/// leaving this endpoint untouched. Implementors MUST be cheap and non-blocking (they
/// run on the request path); the durable record is the store audit row, not the sink.
pub trait RevocationEventSink: Send + Sync {
    /// React to a successful token revocation.
    fn publish(&self, event: &RevocationEvent);

    /// React to a session lifecycle signal (issue #32): a rotation or an end. The
    /// DEFAULT is a no-op, so an existing token-revocation sink keeps compiling and
    /// simply ignores session signals; the durable session-ended fan-out (#35)
    /// overrides it. A rotation is distinguishable from a terminal end by the event's
    /// [`SessionSignalCause`], so a naive consumer never mistakes the two.
    fn publish_session(&self, event: &SessionLifecycleEvent) {
        let _ = event;
    }
}

/// The default revocation-event sink: it logs at debug and does NOT fan out
/// (external fan-out is M4). Installed on every state that did not wire a custom sink.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopRevocationSink;

impl RevocationEventSink for NoopRevocationSink {
    fn publish(&self, event: &RevocationEvent) {
        tracing::debug!(
            client_id = %event.client_id,
            token_type = ?event.token_type,
            "token revocation event on the internal seam (external fan-out is M4)"
        );
    }
}

/// The default (no-op) revocation sink, shared by every state that did not install a
/// custom one.
#[must_use]
pub(crate) fn default_sink() -> Arc<dyn RevocationEventSink> {
    Arc::new(NoopRevocationSink)
}

/// The revocation request parameters (form-encoded, RFC 7009 section 2.1).
///
/// `client_secret` is a client credential, so it is redacted from `Debug`.
#[derive(Deserialize)]
pub struct RevokeParams {
    /// The token to revoke (REQUIRED).
    pub token: Option<String>,
    /// An optional NON-authoritative hint at the token type; the actual format is
    /// determined from the token's own shape, so a wrong hint changes nothing.
    pub token_type_hint: Option<String>,
    /// The client identifier (for `client_secret_post` / public clients).
    pub client_id: Option<String>,
    /// The client secret for `client_secret_post` authentication.
    pub client_secret: Option<String>,
    /// The JWT client assertion for `private_key_jwt` authentication.
    pub client_assertion: Option<String>,
    /// The RFC 7521 `client_assertion_type` accompanying `client_assertion`.
    pub client_assertion_type: Option<String>,
}

impl std::fmt::Debug for RevokeParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevokeParams")
            .field("has_token", &self.token.is_some())
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .field("has_client_secret", &self.client_secret.is_some())
            .field("has_client_assertion", &self.client_assertion.is_some())
            .finish_non_exhaustive()
    }
}

/// `POST /revoke` (RFC 7009).
pub async fn revoke(
    State(state): State<OidcState>,
    headers: HeaderMap,
    Form(params): Form<RevokeParams>,
) -> Response {
    // 1. Authenticate the client (RFC 7009 section 2.1). The scope is recovered from
    //    the authenticated client's own id, so a token is only ever revoked within
    //    the client's tenant/environment. A public `none` client authenticates by
    //    presenting its client_id; a confidential client must present its secret.
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: params.client_id.as_deref(),
        client_secret: params.client_secret.as_deref(),
        client_assertion: params.client_assertion.as_deref(),
        client_assertion_type: params.client_assertion_type.as_deref(),
    };
    let (client, scope) = match authenticate_client_self_scoped(&state, inputs).await {
        Ok(authenticated) => authenticated,
        Err(error) => return client_auth_error_response(&error),
    };

    // 2. token is REQUIRED. Its absence is a request error (not a token oracle).
    let Some(token) = params
        .token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return TokenError::InvalidRequest("token is required".to_owned()).into_response();
    };

    // 3. Revoke the client's OWN token, if the presented token is one. Every token
    //    outcome (unknown, malformed, expired, already-revoked, foreign) collapses to
    //    the SAME 200 empty response (RFC 7009 section 2.2, no existence oracle); only
    //    a store fault (token-independent) surfaces as a server error.
    match revoke_token(&state, scope, &client.client_id, token).await {
        Ok(()) => success(),
        Err(RevokeError::Store(error)) => {
            // A store fault means a revocation that was due may NOT have committed, so
            // it must be visible rather than falsely reported as a 200 success. It is
            // token-independent (the query runs the same regardless of the token), so
            // it is not an oracle.
            tracing::error!(%error, "revocation endpoint store error");
            TokenError::ServerError.into_response()
        }
    }
}

/// Why the revocation could not be completed. A token-state outcome is never an
/// error (it is the uniform 200); only a store fault is.
enum RevokeError {
    /// A persistence fault: the revocation that was due may not have committed.
    Store(StoreError),
}

impl From<StoreError> for RevokeError {
    fn from(error: StoreError) -> Self {
        RevokeError::Store(error)
    }
}

/// Revoke the AUTHENTICATED client's token, if the presented credential is one of its
/// live tokens. Returns `Ok(())` for EVERY token-state outcome (revoked, unknown,
/// foreign, malformed, already-revoked): they are indistinguishable by construction.
/// Only a store fault returns [`RevokeError::Store`].
async fn revoke_token(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    token: &str,
) -> Result<(), RevokeError> {
    match token_credential::classify(token) {
        PresentedTokenKind::Refresh => revoke_refresh(state, scope, client_id, token).await,
        PresentedTokenKind::OpaqueAccess => revoke_opaque(state, scope, client_id, token).await,
        PresentedTokenKind::JwtAccess => revoke_jwt(state, scope, client_id, token).await,
    }
}

/// Revoke a refresh token: revoke its whole family AND its grant chain (issue #21
/// family spine plus the RFC 7009 cascade), so every derived access token becomes
/// inactive. A foreign or unknown token is a silent no-op (still 200).
async fn revoke_refresh(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    token: &str,
) -> Result<(), RevokeError> {
    // Confirm the token's declared scope is the client's before the digest lookup;
    // a foreign-scope token never resolves and is a silent no-op.
    let Some(handle) = opaque_handle(token, OPAQUE_REFRESH_TOKEN_PREFIX) else {
        return Ok(());
    };
    if RefreshTokenId::parse_in_scope(handle, &scope).is_err() {
        return Ok(());
    }
    let Some(resolution) = state.store().scoped(scope).refresh().load(token).await? else {
        return Ok(());
    };
    // A token belonging to a different client is treated as unknown (RFC 7009): no
    // revocation, still 200.
    if resolution.client_id != client_id {
        return Ok(());
    }
    let (actor, correlation) = revoke_actor(state, scope, client_id);
    let flipped = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .refresh()
        .revoke_family(state.env(), &resolution.family_id, &resolution.grant_id)
        .await?;
    if flipped {
        publish_event(
            state,
            &scope,
            client_id,
            RevokedTokenType::RefreshToken,
            &resolution.grant_id,
            Some(&resolution.family_id.to_string()),
        );
    }
    Ok(())
}

/// Revoke an opaque access token by revoking its grant chain. A foreign, unknown, or
/// grant-less token is a silent no-op (still 200).
async fn revoke_opaque(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    token: &str,
) -> Result<(), RevokeError> {
    let Some(handle) = opaque_handle(token, OPAQUE_ACCESS_TOKEN_PREFIX) else {
        return Ok(());
    };
    if IssuedTokenId::parse_in_scope(handle, &scope).is_err() {
        return Ok(());
    }
    let Some(owner) = state
        .store()
        .scoped(scope)
        .authorization()
        .grant_for_opaque_token(token)
        .await?
    else {
        return Ok(());
    };
    revoke_grant_owner(state, scope, client_id, &owner).await
}

/// Revoke an `at+jwt` access token by revoking its grant chain. A foreign or unknown
/// token is a silent no-op (still 200).
async fn revoke_jwt(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    token: &str,
) -> Result<(), RevokeError> {
    let Some(jti_raw) = peek_jti(token) else {
        return Ok(());
    };
    let Ok(jti) = IssuedTokenId::parse_in_scope(&jti_raw, &scope) else {
        return Ok(());
    };
    let Some(owner) = state
        .store()
        .scoped(scope)
        .authorization()
        .grant_for_access_token(&jti)
        .await?
    else {
        return Ok(());
    };
    revoke_grant_owner(state, scope, client_id, &owner).await
}

/// Revoke an access token's grant chain, given its located owner. Enforces the
/// foreign-client check (a token owned by a different client is a silent no-op) and
/// handles a grant-less token (nothing to revoke via the grant spine).
async fn revoke_grant_owner(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    owner: &GrantOwner,
) -> Result<(), RevokeError> {
    if owner.client_id != client_id {
        return Ok(());
    }
    let Some(grant_id) = &owner.grant_id else {
        // A token minted outside the authorization-code flow with no grant spine (a
        // grant_id-NULL opaque row). The current mint never produces one; once issue
        // #23 lands a client-credentials grant, its access token carries a grant and
        // is revoked exactly like the code-flow tokens here. Nothing to revoke today.
        tracing::warn!("revocation: a grant-less token has no grant chain to revoke");
        return Ok(());
    };
    let (actor, correlation) = revoke_actor(state, scope, client_id);
    let flipped = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .authorization()
        .revoke_grant(state.env(), grant_id)
        .await?;
    if flipped {
        publish_event(
            state,
            &scope,
            client_id,
            RevokedTokenType::AccessToken,
            grant_id,
            None,
        );
    }
    Ok(())
}

/// Build the audit actor and a fresh correlation id for a revocation, attributing it
/// to the CLIENT that requested it (the same stable service actor the token endpoint
/// uses). A malformed stored client id is unreachable (the client just authenticated),
/// but falls back to a generated service actor rather than failing the revocation.
fn revoke_actor(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
) -> (ironauth_store::ActorRef, CorrelationId) {
    let actor = match ClientId::parse_in_scope(client_id, &scope) {
        Ok(id) => client_service_actor(&id),
        Err(_) => {
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(state.env()))
        }
    };
    (actor, CorrelationId::generate(state.env()))
}

/// Publish the internal revocation event for a successful revocation.
fn publish_event(
    state: &OidcState,
    scope: &Scope,
    client_id: &str,
    token_type: RevokedTokenType,
    grant_id: &GrantId,
    family_id: Option<&str>,
) {
    let event = RevocationEvent {
        tenant: scope.tenant().to_string(),
        environment: scope.environment().to_string(),
        client_id: client_id.to_owned(),
        token_type,
        grant_id: grant_id.to_string(),
        family_id: family_id.map(str::to_owned),
    };
    state.revocation_sink().publish(&event);
}

/// The RFC 7009 section 2.2 success response: a `200` with an empty body and no-store
/// caching. The SAME response is returned for a revoked token and for every
/// no-effect outcome, so there is no existence oracle.
fn success() -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recording sink, for asserting the endpoint publishes on every revocation.
    #[derive(Default)]
    pub(crate) struct RecordingSink {
        events: Mutex<Vec<RevocationEvent>>,
    }

    impl RecordingSink {
        pub(crate) fn events(&self) -> Vec<RevocationEvent> {
            self.events.lock().expect("lock").clone()
        }
    }

    impl RevocationEventSink for RecordingSink {
        fn publish(&self, event: &RevocationEvent) {
            self.events.lock().expect("lock").push(event.clone());
        }
    }

    #[test]
    fn revocation_event_schema_is_shape_locked() {
        // Shape-lock (the reuse-event snapshot pattern from #21): the internal event
        // schema is pinned so a field rename/reorder is a deliberate, reviewed change.
        // A refresh-token event carries family_id; an access-token event omits it.
        let refresh = RevocationEvent {
            tenant: "ten_abc".to_owned(),
            environment: "env_def".to_owned(),
            client_id: "cli_xyz".to_owned(),
            token_type: RevokedTokenType::RefreshToken,
            grant_id: "grt_123".to_owned(),
            family_id: Some("rff_456".to_owned()),
        };
        assert_eq!(
            serde_json::to_string(&refresh).expect("serialize"),
            r#"{"tenant":"ten_abc","environment":"env_def","client_id":"cli_xyz","token_type":"refresh_token","grant_id":"grt_123","family_id":"rff_456"}"#
        );

        let access = RevocationEvent {
            tenant: "ten_abc".to_owned(),
            environment: "env_def".to_owned(),
            client_id: "cli_xyz".to_owned(),
            token_type: RevokedTokenType::AccessToken,
            grant_id: "grt_123".to_owned(),
            family_id: None,
        };
        assert_eq!(
            serde_json::to_string(&access).expect("serialize"),
            r#"{"tenant":"ten_abc","environment":"env_def","client_id":"cli_xyz","token_type":"access_token","grant_id":"grt_123"}"#
        );
    }

    #[test]
    fn session_signal_distinguishes_rotation_from_a_terminal_end() {
        // The crux of issue #32's signal requirement: a rotation must NOT look like a
        // terminal revoke. The shape is pinned (the reuse-event snapshot pattern): a
        // rotation carries cause `rotated` AND a successor_session_id and is NON
        // terminal; every end cause omits the successor and IS terminal.
        let rotated = SessionLifecycleEvent {
            tenant: "ten_abc".to_owned(),
            environment: "env_def".to_owned(),
            session_id: "ses_old".to_owned(),
            cause: SessionSignalCause::Rotated,
            successor_session_id: Some("ses_new".to_owned()),
        };
        assert!(!rotated.cause.is_terminal(), "a rotation is not terminal");
        assert_eq!(
            serde_json::to_string(&rotated).expect("serialize"),
            r#"{"tenant":"ten_abc","environment":"env_def","session_id":"ses_old","cause":"rotated","successor_session_id":"ses_new"}"#
        );

        let ended = SessionLifecycleEvent {
            tenant: "ten_abc".to_owned(),
            environment: "env_def".to_owned(),
            session_id: "ses_gone".to_owned(),
            cause: SessionSignalCause::Revoked,
            successor_session_id: None,
        };
        assert!(ended.cause.is_terminal(), "a revoke is terminal");
        assert_eq!(
            serde_json::to_string(&ended).expect("serialize"),
            r#"{"tenant":"ten_abc","environment":"env_def","session_id":"ses_gone","cause":"revoked"}"#
        );
        // Every end cause is terminal; only a rotation is not.
        for cause in [
            SessionSignalCause::LoggedOut,
            SessionSignalCause::Revoked,
            SessionSignalCause::BulkRevoked,
            SessionSignalCause::UserRevokedAll,
        ] {
            assert!(cause.is_terminal(), "{cause:?} must be terminal");
        }
    }

    #[test]
    fn recording_sink_captures_published_events() {
        // The trait seam is functional: a sink receives exactly the events published.
        let sink = RecordingSink::default();
        let event = RevocationEvent {
            tenant: "ten_a".to_owned(),
            environment: "env_b".to_owned(),
            client_id: "cli_c".to_owned(),
            token_type: RevokedTokenType::AccessToken,
            grant_id: "grt_d".to_owned(),
            family_id: None,
        };
        sink.publish(&event);
        assert_eq!(sink.events(), vec![event]);
    }
}
