// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin user-invitation CRUD (issue #60).
//!
//! The management-plane surface over the `user_invitations` entity: create an
//! invitation for a new identity (which provisions a `pending_verification` user
//! through the #52 audited management repo and mints a single-use, expiring,
//! unguessable token), list and inspect invitations, revoke a pending one, and
//! resend (rotate the token on) a pending one. The token-authenticated ACCEPT that
//! redeems an invitation is NOT here: it is an invitee action on the public data
//! plane (`ironauth-oidc`), because the invitee is not an authenticated admin.
//!
//! Every surface holds the three management-plane properties: it is scope-fenced
//! (an invitation id is parsed under the caller's OWN scope, so a foreign
//! invitation is the uniform not-found), it is audited in the same transaction as
//! the data change, and every POST honors the Idempotency-Key.
//!
//! # The one-time token
//!
//! The raw `ira_inv_...` token is returned EXACTLY ONCE, at create and at resend,
//! for out-of-band delivery to the invitee (compose the accept link by presenting
//! it to the public invitation-accept endpoint). Only the token's SHA-256 digest is
//! ever stored, so a management read (and a database dump) yields nothing
//! replayable, and an idempotent replay of the create/resend POST returns the
//! invitation WITHOUT the token (the token is shown only at the original creation).
//! Deep-linkable enrollment (the Zitadel passkey-first pattern) is expressed by the
//! invitation's `credential_type`: a `passkey` invitation provisions no password.
//!
//! # Delivery
//!
//! This surface ships the out-of-band delivery path: the caller receives the token
//! and composes/sends the link itself. Delivery via a configured messaging channel
//! (email/SMS templates and provider wiring) is M11's messaging issue and is
//! infra-gated; it is deliberately NOT claimed here.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, InvitationCredentialType, InvitationId, InvitationListFilter,
    InvitationState, MintedInvitationToken, NewAdminUser, NewInvitation, Scope, StoreError,
    UserState, mint_invitation_token, mint_invitation_token_for,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::pagination::{ListQuery, Pagination};
use crate::response::json;
use crate::state::AdminState;
use crate::views::{
    CreateInvitationRequest, InvitationCreatedView, InvitationCredentialTypeView, InvitationList,
    InvitationStateChangeView, InvitationStateView, InvitationView,
};

/// The default invitation token lifetime (seconds) when the caller supplies none:
/// seven days, a safe bounded default. The caller may override it per request with
/// `expires_in_secs` (the configurable-TTL knob), clamped to
/// `[MIN_TTL_SECS, MAX_TTL_SECS]` so an invite link can never be effectively
/// immortal or already-dead.
const DEFAULT_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// The floor on a caller-supplied invitation TTL (one minute): shorter is refused
/// up to this, so a positive but tiny value never yields an immediately-stale link.
const MIN_TTL_SECS: u64 = 60;
/// The ceiling on a caller-supplied invitation TTL (thirty days): a bounded life is
/// a threat-model requirement (an invite link is a credential in transit).
const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// The invitation list search filter: by lifecycle state. The environment dimension
/// is the scope itself (it is in the path).
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct InvitationFilterQuery {
    /// Only invitations in this lifecycle state.
    pub state: Option<InvitationStateView>,
}

/// Resolve and authorize the `(tenant, environment)` scope from the path. The
/// operator passes; a management key must be scoped to exactly this environment. A
/// malformed tenant or environment id is the uniform not-found.
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ironauth_store::ActorRef), ApiError> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)?;
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Parse an invitation id under this scope, mapping a malformed or cross-scope id to
/// the uniform not-found.
fn parse_invitation_id(scope: Scope, raw: &str) -> Result<InvitationId, ApiError> {
    InvitationId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// The invitation view for a state-change (revoke) post-condition, built without a
/// re-read so the Idempotency-Key replay body is byte-identical.
fn state_change_body(id: &InvitationId, state: InvitationStateView) -> Result<String, ApiError> {
    let view = InvitationStateChangeView {
        id: id.to_string(),
        state,
    };
    serde_json::to_string(&view).map_err(|_| ApiError::Internal)
}

/// Create an invitation for a new identity.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
    operation_id = "createInvitation",
    tag = "invitations",
    request_body = CreateInvitationRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response (WITHOUT the one-time token) \
         without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created; the one-time token is returned once", body = InvitationCreatedView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 409, description = "The invited identifier is already in use", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
#[allow(clippy::too_many_lines)]
pub async fn create_invitation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Containment: the parent environment must exist and be live. A foreign or
    // soft-deleted environment reads as a uniform not-found.
    state
        .store()
        .management()
        .environments(scope.tenant())
        .get(&scope.environment())
        .await?;

    let request: CreateInvitationRequest = parse_json(&body)?;
    let identifier = require_non_empty(&request.identifier, "identifier")?;
    let credential_view = request
        .credential_type
        .unwrap_or(InvitationCredentialTypeView::Password);
    let credential_type: InvitationCredentialType = credential_view.into();
    let org_context = match request.org_context.as_deref() {
        Some(value) => Some(require_non_empty(value, "org_context")?),
        None => None,
    };
    let ttl_secs = request
        .expires_in_secs
        .unwrap_or(DEFAULT_TTL_SECS)
        .clamp(MIN_TTL_SECS, MAX_TTL_SECS);

    let created_at_micros = state.now_unix_micros();
    let ttl_micros = i64::try_from(ttl_secs)
        .unwrap_or(i64::MAX / 1_000_000)
        .saturating_mul(1_000_000);
    let expires_at_micros = created_at_micros.saturating_add(ttl_micros);

    // Mint the single-use token (256 bits from the entropy seam); its `inv_` handle
    // is the invitation row id. Only the digest is ever stored.
    let MintedInvitationToken { token, digest, id } = mint_invitation_token(state.env(), &scope);

    // One shared correlation id ties the pending-user creation and the invitation
    // creation into one traceable operation across their two audit rows.
    let correlation = CorrelationId::generate(state.env());

    // Provision the pending_verification user this invitation activates on accept,
    // through the #52 audited management repo. No credential is set now; the accept
    // sets it. An identifier already in use is a 409.
    let user_id = match state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .users()
        .admin_create(
            state.env(),
            NewAdminUser {
                id: None,
                identifier: &identifier,
                password_hash: None,
                claims_json: None,
                external_id: None,
                state: UserState::PendingVerification,
                // The invitation create surface (issue #60) sets no foreign
                // credential; the streaming bulk import path (issue #55) is where an
                // imported foreign hash enters.
                foreign_password_hash: None,
                foreign_password_algo: None,
                traits_json: None,
                traits_schema_version: None,
            },
            created_at_micros,
            None,
        )
        .await
    {
        Ok(user_id) => user_id,
        Err(StoreError::Conflict) => {
            return Err(ApiError::Conflict(
                "a user or invitation with this identifier already exists in this environment"
                    .to_owned(),
            ));
        }
        Err(error) => return Err(error.into()),
    };

    // The durable invitation view (NO token): both the LIVE 201 body (with the token
    // added) and the stored Idempotency-Key body (without it) derive from this one
    // value, so a replay returns the same invitation minus the one-time token.
    let invitation = InvitationView {
        id: id.to_string(),
        tenant_id: scope.tenant().to_string(),
        environment_id: scope.environment().to_string(),
        user_id: user_id.to_string(),
        target_identifier: identifier.clone(),
        credential_type: credential_view,
        state: InvitationStateView::Pending,
        org_context: org_context.clone(),
        expires_at_unix_ms: expires_at_micros / 1000,
        created_at_unix_ms: created_at_micros / 1000,
        updated_at_unix_ms: created_at_micros / 1000,
        accepted_at_unix_ms: None,
        revoked_at_unix_ms: None,
    };
    // The stored body carries no token (only the digest is ever persisted).
    let stored_view = InvitationCreatedView {
        invitation: invitation.clone(),
        token: None,
    };
    let stored_body = serde_json::to_string(&stored_view).map_err(|_| ApiError::Internal)?;
    // The live body reveals the one-time token exactly once.
    let live_view = InvitationCreatedView {
        invitation,
        token: Some(token),
    };
    let live_body = serde_json::to_string(&live_view).map_err(|_| ApiError::Internal)?;

    let result = state
        .store()
        .scoped(scope)
        .acting(actor, correlation)
        .invitations()
        .create(
            state.env(),
            NewInvitation {
                id: &id,
                user_id: &user_id,
                target_identifier: &identifier,
                token_digest: &digest,
                credential_type,
                org_context: org_context.as_deref(),
                expires_at_unix_micros: expires_at_micros,
            },
            created_at_micros,
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &stored_body,
            }),
        )
        .await;

    match result {
        Ok(_) => Ok(json(StatusCode::CREATED, live_body)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // A 256-bit-entropy digest collision is astronomically unlikely and is not a
        // caller fault: surface it as an opaque server error, not a 409.
        Err(StoreError::Conflict) => Err(ApiError::Internal),
        Err(error) => Err(error.into()),
    }
}

/// List invitations under an environment (cursor paginated), filterable by state.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
    operation_id = "listInvitations",
    tag = "invitations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        InvitationFilterQuery,
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of invitations", body = InvitationList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_invitations(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(filter): Query<InvitationFilterQuery>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .invitations()
        .list(
            InvitationListFilter {
                state: filter.state.map(InvitationState::from),
            },
            page.fetch_limit(),
            page.after(),
        )
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = InvitationList {
        items: rows.into_iter().map(InvitationView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one invitation.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}",
    operation_id = "getInvitation",
    tag = "invitations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("invitation_id" = String, Path, description = "The invitation identifier (inv_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The invitation", body = InvitationView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_invitation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, invitation_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let id = parse_invitation_id(scope, &invitation_id)?;
    let record = state.store().scoped(scope).invitations().get(&id).await?;
    let body = serde_json::to_string(&InvitationView::from_record(record))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Revoke a pending invitation (its token becomes unredeemable).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/revoke",
    operation_id = "revokeInvitation",
    tag = "invitations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("invitation_id" = String, Path, description = "The invitation identifier (inv_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The invitation is revoked", body = InvitationStateChangeView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, not pending, or in another scope)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn revoke_invitation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, invitation_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    // This transition carries no request body, so the fingerprint is over the empty
    // body: the same (method, path, key) is the same request.
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id = parse_invitation_id(scope, &invitation_id)?;
    let body_string = state_change_body(&id, InvitationStateView::Revoked)?;
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .invitations()
        .revoke(
            state.env(),
            &id,
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &body_string,
            }),
        )
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

/// Resend a pending invitation: invalidate the prior token and issue a fresh one.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/resend",
    operation_id = "resendInvitation",
    tag = "invitations",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("invitation_id" = String, Path, description = "The invitation identifier (inv_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response (WITHOUT the fresh token) \
         without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A fresh token was issued; it is returned once", body = InvitationCreatedView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, not pending, or in another scope)", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn resend_invitation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, invitation_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;

    let key = idempotency::required_key(&headers)?;
    // This transition carries no request body, so the fingerprint is over the empty
    // body.
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id = parse_invitation_id(scope, &invitation_id)?;

    // Read the current invitation to build the response and reset the expiry from the
    // configured default. An absent, terminal, or cross-scope invitation is the
    // uniform not-found (the store `resend` re-guards the pending state atomically).
    let record = state.store().scoped(scope).invitations().get(&id).await?;

    let now_micros = state.now_unix_micros();
    let expires_at_micros = now_micros.saturating_add(
        i64::try_from(DEFAULT_TTL_SECS)
            .unwrap_or(i64::MAX / 1_000_000)
            .saturating_mul(1_000_000),
    );

    // Mint a fresh token for the SAME invitation id (rotating the digest invalidates
    // the prior token). Only the fresh digest is stored.
    let MintedInvitationToken { token, digest, .. } = mint_invitation_token_for(state.env(), id);

    let mut invitation = InvitationView::from_record(record);
    invitation.expires_at_unix_ms = expires_at_micros / 1000;
    invitation.updated_at_unix_ms = now_micros / 1000;
    let stored_view = InvitationCreatedView {
        invitation: invitation.clone(),
        token: None,
    };
    let stored_body = serde_json::to_string(&stored_view).map_err(|_| ApiError::Internal)?;
    let live_view = InvitationCreatedView {
        invitation,
        token: Some(token),
    };
    let live_body = serde_json::to_string(&live_view).map_err(|_| ApiError::Internal)?;

    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .invitations()
        .resend(
            state.env(),
            &id,
            &digest,
            expires_at_micros,
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &stored_body,
            }),
        )
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, live_body)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // A digest collision is not a caller fault: opaque server error.
        Err(StoreError::Conflict) => Err(ApiError::Internal),
        Err(error) => Err(error.into()),
    }
}
