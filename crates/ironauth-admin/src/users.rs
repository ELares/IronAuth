// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admin user CRUD, lifecycle transitions, and external-id linkage (issue #52).
//!
//! This is the management-plane surface over the `users` entity: create (with an
//! optional caller-supplied id and an external id), read, list (cursor paginated,
//! filterable by state / `external_id` / identifier), update (RFC 7396 partial
//! profile patch), delete (a soft-delete offboarding that cascades sessions), the
//! explicit lifecycle state transitions, and external-id link/unlink.
//!
//! Every surface holds the three management-plane properties: it is scope-fenced
//! (a user id is parsed under the caller's OWN scope, so a foreign user is the
//! uniform not-found, and every surface registers an `IsolationProbe` with the #6
//! IDOR harness), it is audited in the same transaction as the data change, and
//! the session-ending transitions (block, disable, delete) cascade to the user's
//! sessions and non-offline refresh families and publish to the unified
//! session-ended fan-out (issue #35), which delivers back-channel logout to
//! affected relying parties.
//!
//! The user PII (the login handle, the claim document, the external id) is
//! envelope-encrypted at rest (issue #48): the create seals it and the reads open
//! it, so the control-plane store carries the platform master key exactly as the
//! data plane does. A management response NEVER returns the password hash (the #11
//! secret lesson).

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewAdminUser, NewUserTraits, Scope, StoreError, TraitSchema,
    TraitWriteVisibility, UserId, UserListFilter, UserState,
};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty};
use crate::org_context::{EnvironmentAccess, require_live_environment, resolve_user};
use crate::pagination::{ListQuery, Pagination};
use crate::response::{json, no_content};
use crate::state::AdminState;
use crate::views::{
    CreateUserRequest, LinkExternalIdRequest, SetUserStateRequest, UpdateUserRequest,
    UserExternalIdView, UserList, UserStateChangeView, UserStateView, UserTraitsView, UserView,
};

/// The user list search filters: by lifecycle state, by external id, and by login
/// handle. The environment dimension is the scope itself (it is in the path).
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UserFilterQuery {
    /// Only users in this lifecycle state.
    pub state: Option<UserStateView>,
    /// Only the user whose external id equals this value.
    pub external_id: Option<String>,
    /// Only the user whose login handle equals this value.
    pub identifier: Option<String>,
}

/// Whether a session-ending mutation also kills the user's `offline_access`
/// families. Off by default (they survive), like every other fleet operation.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HardKillQuery {
    /// Kill the `offline_access` refresh families too (default false).
    #[serde(default)]
    pub hard_kill: bool,
}

/// Resolve and authorize the `(tenant, environment)` scope from the path. The
/// operator passes; a management key must be scoped to exactly this environment
/// (otherwise the LOUD wrong-scope error). A malformed tenant or environment id is
/// the uniform not-found.
async fn resolve_scope(
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
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    // Issue #185: the caller's OPERATOR fences the pair. `tenants` and `environments`
    // sit ABOVE row-level security (RLS fences the pair these tables define), so without
    // this a caller naming another operator's tenant reached that tenant's environments
    // and everything under them: measured returning another operator's organization
    // document in full.
    //
    // ADDRESSABILITY, not liveness. A soft-deleted environment must stay readable (see
    // `EnvironmentAccess`), so this asks only whether the pair exists under this
    // operator; whether it is live is each endpoint's own question.
    if !state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .exists_in_any_state(&environment)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::NotFound);
    }
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// Validate a submitted identity-traits document against the environment's ACTIVE trait
/// schema (issue #53), returning the canonical JSON text to persist and the schema version
/// it validated against.
///
/// This is the create-and-PATCH half of the acceptance criterion, and it lives in ONE
/// function reached by BOTH writers on purpose: a validation rule enforced on the create and
/// not on the PATCH would read as enforced while the PATCH walked around it. The store's
/// `set_traits` seam enforces the same contract for the flow-driven writers, so there is no
/// path into the `traits_sealed` column that skips the active schema except the deliberate
/// import/restore one (`NewAdminUser::traits_json`, which is documented as verbatim because a
/// fresh scope being restored into has not registered a schema yet).
///
/// Failures come back per FIELD, each with its RFC 6901 JSON Pointer, as
/// [`ApiError::TraitsInvalid`] (a 422 carrying the structured `trait_errors` list), never a
/// flattened string. An environment with NO active schema cannot validate anything, so a
/// request carrying traits there is a legible 422 rather than an unvalidated write.
async fn validated_traits(
    state: &AdminState,
    scope: Scope,
    traits: &serde_json::Value,
) -> Result<(String, i32), ApiError> {
    let active = state
        .store()
        .scoped(scope)
        .trait_schemas()
        .active()
        .await?
        .ok_or_else(|| {
            ApiError::Unprocessable(
                "the environment has no active trait schema, so traits cannot be validated; \
                 create and activate a trait-schema version first"
                    .to_owned(),
            )
        })?;
    // A STORED schema is proved well formed on write, so a compile fault is a persistence
    // corruption and never a caller fault.
    let schema = TraitSchema::compile(&active.schema_json).map_err(|_| ApiError::Internal)?;
    let failures = schema.validate(traits);
    if !failures.is_empty() {
        return Err(ApiError::TraitsInvalid(failures));
    }
    let traits_json = serde_json::to_string(traits).map_err(|_| ApiError::Internal)?;
    Ok((traits_json, active.version))
}

/// Parse a CALLER-SUPPLIED id for a user this request is about to MINT, mapping a
/// malformed or cross-scope id to the uniform not-found.
///
/// This is the one place on the surface where a user id is parsed without addressing an
/// existing row, and it is why it survives issue #451's fold. Every route that ADDRESSES
/// a user goes through [`crate::org_context::resolve_user`], which performs the
/// environment fence for a write; `create_user` proves the environment live itself, one
/// line above, and then reads this optional id out of the body as the identity to give
/// the row it is creating.
fn parse_user_id(scope: Scope, raw: &str) -> Result<UserId, ApiError> {
    UserId::parse_in_scope(raw, &scope).map_err(|_| ApiError::NotFound)
}

/// Mint the `user.created` event this create announces (issues #105, #108).
///
/// The id is minted ONCE, before the write, and travels through the fan-out to become the
/// `webhook-id` header of every delivery. Minting it inside a retry would present a
/// receiver the same event twice under two ids, which is exactly what that header exists to
/// prevent.
fn user_created_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    user_id: &ironauth_store::UserId,
    user_state: ironauth_store::UserState,
    created_at_micros: i64,
) -> crate::events::PendingEvent {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = crate::events::envelope(
        &id,
        crate::events::USER_CREATED,
        scope,
        created_at_micros / 1000,
        &serde_json::json!({
            "user_id": user_id.to_string(),
            "state": user_state.as_str(),
        }),
    );
    crate::events::PendingEvent {
        id,
        subject: user_id.to_string(),
        envelope,
    }
}

/// The event a management PATCH emits for ONE written field (issue #108).
///
/// One per write rather than one per request: the PATCH runs claims and traits as two
/// separate audited transactions, and an event must be transactional with the write it
/// announces. A single event after both could not be -- if the traits write failed after the
/// claims write committed, a real change would go unannounced.
fn user_updated_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    user_id: &ironauth_store::UserId,
    field: &str,
    updated_at_micros: i64,
) -> crate::events::PendingEvent {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = crate::events::envelope(
        &id,
        crate::events::USER_UPDATED,
        scope,
        updated_at_micros / 1000,
        &serde_json::json!({
            "user_id": user_id.to_string(),
            "fields": [field],
        }),
    );
    crate::events::PendingEvent {
        id,
        subject: user_id.to_string(),
        envelope,
    }
}

/// The event a management delete emits (issue #108).
///
/// `hard_kill` is carried because it changes what the delete DID: a soft delete leaves the
/// offline refresh families alive and a hard kill revokes them. A receiver reconciling its
/// own copy cannot ask afterwards -- the user reads as absent either way.
fn user_deleted_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    user_id: &ironauth_store::UserId,
    hard_kill: bool,
    deleted_at_micros: i64,
) -> crate::events::PendingEvent {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = crate::events::envelope(
        &id,
        crate::events::USER_DELETED,
        scope,
        deleted_at_micros / 1000,
        &serde_json::json!({
            "user_id": user_id.to_string(),
            "hard_kill": hard_kill,
        }),
    );
    crate::events::PendingEvent {
        id,
        // The SUBJECT is the user, so a create and a delete of one user are exploded in the
        // order they happened rather than concurrently.
        subject: user_id.to_string(),
        envelope,
    }
}

/// Create a user under an environment.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users",
    operation_id = "createUser",
    tag = "users",
    request_body = CreateUserRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created", body = UserView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 409, description = "The id, login handle, or external id is already taken", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
// One line over clippy's bound after gaining the entry-path extractor, and allowed rather than
// split: this handler is one linear sequence -- authorize, replay-check, validate, write, record
// -- and cutting it in half to satisfy a line count would put the idempotency replay in a
// different function from the write it replays.
#[allow(clippy::too_many_lines)]
pub async fn create_user(
    State(state): State<AdminState>,
    principal: Principal,
    // How the caller says this arrived (issue #123 criterion 5). Named in the signature rather
    // than read from `headers` below, so "which handlers record the entry path" is a question
    // the compiler answers.
    entry_path: crate::entry_path::DeclaredEntryPath,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): this operation is classified
    // `management.write_users` in the permission pin, and this is where that
    // declaration becomes enforcement. An UNRESTRICTED credential (every key minted
    // before migration 0118) passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

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
    //
    // This used to be an inline copy of the two-line read (issue #443). It is the
    // shared [`require_live_environment`] now, which is the same function every OTHER
    // user route reaches through [`resolve_user`]: a create that refused a deleted
    // environment while `updateUser`, `setUserState`, `deleteUser` and
    // `unlinkUserExternalId` all accepted one was the split issue #451 closed, and one
    // copy of the check is what keeps the halves from drifting apart again. The create
    // cannot go through `resolve_user` itself, because it MINTS the user rather than
    // addressing one.
    require_live_environment(&state, &scope).await?;

    let request: CreateUserRequest = parse_json(&body)?;
    let identifier = require_non_empty(&request.identifier, "identifier")?;
    let view_state = request.state.unwrap_or(UserStateView::Active);
    let user_state: UserState = view_state.into();
    if !user_state.is_creatable() {
        return Err(ApiError::BadRequest(
            "state is not a valid initial state (scheduled_offboarding needs a timestamp)"
                .to_owned(),
        ));
    }
    // An optional caller-supplied id must be a user id in THIS scope.
    let supplied_id = match request.id.as_deref() {
        Some(raw) => Some(parse_user_id(scope, raw)?),
        None => None,
    };
    let external_id = match request.external_id.as_deref() {
        Some(value) => Some(require_non_empty(value, "external_id")?),
        None => None,
    };
    let claims_string = request.claims.as_ref().map(ToString::to_string);
    let password_hash = match request.password_hash.as_deref() {
        Some(value) => Some(require_non_empty(value, "password_hash")?),
        None => None,
    };
    // Traits are validated against the ACTIVE schema BEFORE anything is written, so a
    // violating document creates NO user (issue #53). A valid one is persisted together with
    // the schema version it validated against, which is what `traits_schema_version` is for
    // and what lets a later migration job select the identities still on an older version.
    let traits = match request.traits.as_ref() {
        Some(value) => Some(validated_traits(&state, scope, value).await?),
        None => None,
    };

    let created_at_micros = state.now_unix_micros();
    let user_id = supplied_id.unwrap_or_else(|| UserId::generate(state.env(), &scope));
    let view = UserView {
        id: user_id.to_string(),
        tenant_id: scope.tenant().to_string(),
        environment_id: scope.environment().to_string(),
        identifier: identifier.clone(),
        state: view_state,
        external_id: external_id.clone(),
        scheduled_offboarding_at_unix_ms: None,
        created_at_unix_ms: created_at_micros / 1000,
        updated_at_unix_ms: created_at_micros / 1000,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let event = user_created_event(&state, scope, &user_id, user_state, created_at_micros);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .via(entry_path.0)
        .users()
        .admin_create_emitting(
            state.env(),
            NewAdminUser {
                id: Some(&user_id),
                identifier: &identifier,
                password_hash: password_hash.as_deref(),
                claims_json: claims_string.as_deref(),
                external_id: external_id.as_deref(),
                state: user_state,
                // The management create surface (issue #52) sets no foreign
                // credential; the streaming bulk import path (issue #55) is where an
                // imported foreign hash enters.
                foreign_password_hash: None,
                foreign_password_algo: None,
                // Already validated against the active schema above; `admin_create` seals
                // the document verbatim, which is why the validation has to be here. The
                // ADMIN visibility class (issue #53): this is the management plane, which
                // is precisely where admin-only metadata is written, so the split does not
                // apply and the submitted document is authoritative over every field.
                traits: traits.as_ref().map(|(json, version)| NewUserTraits {
                    traits_json: json.as_str(),
                    schema_version: Some(*version),
                    visibility: TraitWriteVisibility::Admin,
                }),
            },
            created_at_micros,
            Some(write),
            Some(&event.domain_event()),
        )
        .await;

    match result {
        Ok(_) => Ok(json(StatusCode::CREATED, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a user with this id, login handle, or external id already exists".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// List users under an environment (cursor paginated), filterable by state,
/// external id, and identifier.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users",
    operation_id = "listUsers",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        UserFilterQuery,
        ListQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of users", body = UserList),
        (status = 400, description = "Malformed cursor", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_users(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(filter): Query<UserFilterQuery>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // A read is still an authority: listing users is how an operator learns who
    // exists, so a credential restricted away from it must not be able to enumerate
    // them. An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let page = Pagination::resolve(&query, state.default_page_size(), state.max_page_size())?;
    let rows = state
        .store()
        .scoped(scope)
        .users()
        .list(
            UserListFilter {
                state: filter.state.map(UserState::from),
                external_id: filter.external_id.as_deref(),
                identifier: filter.identifier.as_deref(),
            },
            page.fetch_limit(),
            page.after(),
        )
        .await?;
    let (rows, next_cursor) = page.finish(rows, |record| {
        (record.created_at_unix_micros, record.id.to_string())
    });
    let list = UserList {
        items: rows.into_iter().map(UserView::from_record).collect(),
        next_cursor,
    };
    let body = serde_json::to_string(&list).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one user.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    operation_id = "getUser",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The user", body = UserView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_user(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // A read is still an authority: listing users is how an operator learns who
    // exists, so a credential restricted away from it must not be able to enumerate
    // them. An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Read).await?;
    let record = state.store().scoped(scope).users().get(&id).await?;
    let body =
        serde_json::to_string(&UserView::from_record(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Get one user's identity-traits document.
///
/// A MANAGEMENT read, so it is the FULL document, admin-only metadata included. There is no
/// self-service counterpart of this route on this plane; a self-service surface reads the
/// REDACTED projection (`UserRepo::traits_user_visible`), which strips every field the active
/// schema annotates `visibility: admin`.
//
// WHY THIS READ WRITES NO AUDIT ROW, while `exportIdentities` does. A `//` comment rather
// than a doc comment on purpose: utoipa renders the doc comment into the published spec,
// and this is an internal verdict, not something an API consumer needs.
//
// The asymmetry is deliberate and it is not about which route decrypts PII: `getUser`
// already returns the decrypted standard-claim document with no audit row, and so does
// every other single-identity management read on this plane. The audited one is the BULK
// EXTRACTION, and what it audits is not "PII was decrypted" but "a whole environment was
// drained": `record_export_audit` targets the ENVIRONMENT and records the identity COUNT,
// which is a fact about an egress event, not about a lookup. Auditing every single-identity
// read would produce a row per console page view, which is how an audit log stops being
// read at all. If per-read attribution is later wanted it belongs as one decision across
// every management read, not as one route quietly holding a different rule.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/traits",
    operation_id = "getUserTraits",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The user's traits and the schema version they validated against", body = UserTraitsView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_user_traits(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Read).await?;
    // The user must exist, or a trait-free identity and an ABSENT one would answer alike and
    // the route would be a silent existence oracle in the wrong direction (200 for a user
    // that is not there).
    state.store().scoped(scope).users().get(&id).await?;
    let traits = state.store().scoped(scope).users().traits(&id).await?;
    let view = UserTraitsView {
        id: id.to_string(),
        traits: traits.as_ref().map(|(_, value)| value.clone()),
        // `None` for BOTH "no traits at all" and "traits whose source recorded no schema
        // version" (an import). They serialize alike, and the field beside it separates
        // them: `traits` is null in the first case and a document in the second.
        schema_version: traits.as_ref().and_then(|(version, _)| *version),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Update a user's profile (RFC 7396 partial patch of the standard claims and the
/// identity-traits document).
#[utoipa::path(
    patch,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    operation_id = "updateUser",
    tag = "users",
    request_body = UpdateUserRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The updated user", body = UserView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn update_user(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    let request: UpdateUserRequest = parse_json(&body)?;
    // BOTH documents are validated before EITHER is written. A patch carrying valid claims
    // and an invalid traits document must land nothing at all, or a caller retrying the whole
    // patch after fixing the traits would be applying the claims twice; and a partial 422 is
    // exactly the state an operator cannot reason about.
    //
    // The two writes below are two audited transactions, not one, and that is deliberate
    // rather than the issue #247 split. That defect is specific to a handler behind an
    // `Idempotency-Key`: the key's record commits with ONE of the writes, so a failure between
    // them leaves a partial state the replay store cannot see and the retry replays a response
    // for work that never finished. This PATCH carries no key (`scripts/idempotent-write-audit.sh`
    // therefore does not list it), and BOTH writes are whole-document REPLACEMENTS, so a
    // failure between them leaves a state a plain retry of the identical request converges out
    // of. They also want separate audit rows: a claims change and a traits change are different
    // facts about the identity and an operator reads them separately.
    let traits = match request.traits.as_ref() {
        Some(value) => Some(validated_traits(&state, scope, value).await?),
        None => None,
    };
    if let Some(claims) = request.claims.as_ref() {
        let claims_json = claims.to_string();
        let claims_event =
            user_updated_event(&state, scope, &id, "claims", state.now_unix_micros());
        state
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .users()
            .update_claims(
                state.env(),
                &id,
                &claims_json,
                Some(&claims_event.domain_event()),
            )
            .await?;
    }
    if let Some((traits_json, _)) = traits.as_ref() {
        let traits_event =
            user_updated_event(&state, scope, &id, "traits", state.now_unix_micros());
        // The ADMIN visibility class: this is the management plane, which is precisely where
        // admin-only metadata is written. `set_traits` re-validates against the active schema
        // and records the version, so the write path is the same one every flow-driven writer
        // uses and cannot drift from it.
        state
            .store()
            .scoped(scope)
            .acting(actor, CorrelationId::generate(state.env()))
            .users()
            .set_traits_with_visibility(
                state.env(),
                &id,
                traits_json,
                ironauth_store::TraitWriteVisibility::Admin,
                Some(&traits_event.domain_event()),
            )
            .await?;
    }
    if request.claims.is_none() && request.traits.is_none() {
        // No mutable field supplied: still confirm the user exists (a not-found is
        // the uniform 404), so an empty patch of an absent user is not a silent 200.
        state.store().scoped(scope).users().get(&id).await?;
    }
    let record = state.store().scoped(scope).users().get(&id).await?;
    let body =
        serde_json::to_string(&UserView::from_record(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Delete a user (a soft-delete offboarding that cascades sessions).
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    operation_id = "deleteUser",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        HardKillQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deleted (sessions cascaded, session-ended events published)"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, already deleted, or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn delete_user(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    Query(hard): Query<HardKillQuery>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): this operation is classified
    // `management.write_users` in the permission pin, and this is where that
    // declaration becomes enforcement. An UNRESTRICTED credential (every key minted
    // before migration 0118) passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    let event = user_deleted_event(&state, scope, &id, hard.hard_kill, state.now_unix_micros());
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .delete(
            state.env(),
            &id,
            hard.hard_kill,
            None,
            Some(&event.domain_event()),
        )
        .await?;
    Ok(no_content())
}

/// Transition a user's lifecycle state.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/state",
    operation_id = "setUserState",
    tag = "users",
    request_body = SetUserStateRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The user's new state", body = UserStateChangeView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 409, description = "The transition is not valid from the user's current state", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn set_user_state(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Addressed BEFORE the body is validated, which is where every sibling
    // environment-scoped write puts its parent-existence precondition. What that ordering
    // buys is stated exactly here, because the obvious claim about it is the wrong way
    // round. It does NOT make a live environment and a decommissioned one answer alike:
    // MEASURED with a malformed body, a live environment answers 400 and a soft-deleted
    // one answers 404, and under the OLD ordering both answered 400, so this ordering
    // CREATES that difference rather than removing it.
    //
    // What it buys is the other property, and it is the one worth having: a
    // decommissioned environment answers the uniform not-found to EVERYTHING that reaches
    // this fence, well formed or not. No request shape gets a body-level answer out of an
    // environment an operator believes is gone, and in particular no 400 confirms that
    // the body was readable there.
    //
    // The cost is a wire change at a LIVE environment too, small but real and recorded
    // rather than discovered later: a request carrying BOTH an unaddressable user id and
    // a malformed body used to be answered 400 and is now answered 404. The address wins,
    // which is the precedence `set_client_allowed_scopes` and `update_permission` already
    // use for the same anti-oracle reason.
    //
    // It sits AFTER the idempotency replay for the reason `resolve_live_org` records: a
    // genuine replay still returns the original response even if the environment went
    // away in between, so a retry of a request that ALREADY SUCCEEDED never becomes a 404
    // the client cannot tell from "my write never landed". The replay's own precondition
    // stays ahead of the fence with it, so a request with NO Idempotency-Key is still
    // answered 400 "the Idempotency-Key header is required on POST" at a decommissioned
    // environment (MEASURED). That 400 is deliberate and predates this fence (issue
    // #411); it is a statement about the request, not about the environment, and every
    // environment answers it identically.
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;

    let request: SetUserStateRequest = parse_json(&body)?;
    let target: UserState = request.state.into();
    // A scheduled-offboarding target needs an instant; every other target must not
    // carry one. Reject the mismatch as a clean 400.
    let scheduled_micros = match (target, request.scheduled_offboarding_at_unix_ms) {
        (UserState::ScheduledOffboarding, Some(ms)) => Some(ms.saturating_mul(1000)),
        (UserState::ScheduledOffboarding, None) => {
            return Err(ApiError::BadRequest(
                "scheduled_offboarding requires scheduled_offboarding_at_unix_ms".to_owned(),
            ));
        }
        (_, Some(_)) => {
            return Err(ApiError::BadRequest(
                "scheduled_offboarding_at_unix_ms is only valid for the scheduled_offboarding state"
                    .to_owned(),
            ));
        }
        (_, None) => None,
    };

    let view = UserStateChangeView {
        id: id.to_string(),
        state: request.state,
        hard_kill: request.hard_kill,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let wake = crate::offboarding_worker::wake_payload(&id.to_string(), &actor);
    let pending = user_state_changed_event(&state, scope, &id, target, request.hard_kill);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .set_state_with_event(
            state.env(),
            &id,
            target,
            ironauth_store::OffboardingSchedule {
                at_unix_micros: scheduled_micros,
                // The wake-up that will EXECUTE this schedule, enqueued in the same
                // transaction as the state change. Without it the scheduled instant is a
                // column nothing ever reads again, which is what it was: the executor
                // existed and had no caller anywhere in the tree.
                wake_payload: Some(&wake),
            },
            request.hard_kill,
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &body_string,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;

    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "the requested state transition is not valid from the user's current state".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// Link an external id to a user.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
    operation_id = "linkUserExternalId",
    tag = "users",
    request_body = LinkExternalIdRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The linked external id", body = UserExternalIdView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the user is absent or in another scope", body = ErrorBody),
        (status = 409, description = "The external id is already claimed by another user", body = ErrorBody)
    )
)]
pub async fn link_user_external_id(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    // The PARENT-EXISTENCE precondition (issue #409). `resolve_scope` proves only that
    // the two path segments PARSE. An external id is PII, so linking one SEALS it, and
    // the seal resolves the scope's envelope key BEFORE it looks the user up, which is
    // why this route alone among the user routes could not fall through to the user's
    // own not-found. An environment that does not exist has no envelope key and can be
    // given none (the key tables carry the same composite foreign key to
    // `environments`), and the MEASURED answer was the store's envelope failure
    // rendered as an opaque 500. There is no Idempotency-Key on this PUT, so nothing
    // orders ahead of it.
    //
    // It was a bare `require_live_environment` call here, and it is
    // [`crate::org_context::resolve_user`] that carries it now (issue #451): the same
    // fence, reached through the same function every other user-addressed write reaches,
    // so this route can no longer be the only one on the surface that has it.
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    let request: LinkExternalIdRequest = parse_json(&body)?;
    let external_id = require_non_empty(&request.external_id, "external_id")?;
    let pending = external_id_linked_event(&state, scope, &id, Some(&external_id));
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .link_external_id_with_event(
            state.env(),
            &id,
            &external_id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await;
    match result {
        Ok(()) => {
            let view = UserExternalIdView {
                id: id.to_string(),
                external_id: Some(external_id),
            };
            let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::OK, body))
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "the external id is already claimed by another user in this environment".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// Unlink a user's external id.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
    operation_id = "unlinkUserExternalId",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The external id was unlinked", body = UserExternalIdView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn unlink_user_external_id(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    let pending = external_id_linked_event(&state, scope, &id, None);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .users()
        .unlink_external_id_with_event(
            state.env(),
            &id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    let view = UserExternalIdView {
        id: id.to_string(),
        external_id: None,
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// The event a user state change emits (issue #108).
///
/// `hard_kill` rides along because it changes what the change DID -- it decides whether the
/// offline refresh families were revoked too, and a receiver cannot infer that afterwards.
fn user_state_changed_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    user_id: &ironauth_store::UserId,
    to: ironauth_store::UserState,
    hard_kill: bool,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = user_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "user.state_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "user_id": subject,
            "state": to.as_str(),
            "hard_kill": hard_kill,
        }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event linking or unlinking a user's external id emits (issue #108).
///
/// `external_id` present means a LINK, absent means an UNLINK -- and the asymmetry is forced
/// rather than chosen. The link is given the identifier, and a receiver reconciling against an
/// upstream directory needs BOTH sides or it cannot update its mapping. The unlink is given
/// only the user, because the store clears whatever was there, so nothing knows the outgoing
/// value when the envelope is built -- exactly as with `organization.default_role_cleared`.
///
/// The external id is the OPERATOR'S OWN identifier for this person, supplied through the
/// management API: not a credential and not a secret. Withholding it would make the link event
/// unusable for the one job it exists to do.
fn external_id_linked_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    user_id: &ironauth_store::UserId,
    external_id: Option<&str>,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = user_id.to_string();
    let (event_type, payload) = match external_id {
        Some(external) => (
            "user.external_id_linked",
            serde_json::json!({ "user_id": subject, "external_id": external }),
        ),
        None => (
            "user.external_id_unlinked",
            serde_json::json!({ "user_id": subject }),
        ),
    };
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
