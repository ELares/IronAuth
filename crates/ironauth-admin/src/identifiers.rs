// SPDX-License-Identifier: MIT OR Apache-2.0

//! Login identifier management (issue #54, epic #514).
//!
//! #54 delivered the canonicalization seam and the persistent half: `user_identifiers`,
//! the per-tenant blind index, and the three uniqueness modes migration 0041 describes.
//! What it did not deliver, because its title scopes it to the seam, is anything that
//! WRITES a row on a production path. Measured before this module existed:
//! `ActingUserIdentifierRepo::add` is the only writer of the table anywhere, and it had
//! zero callers outside tests, so `user_identifiers` was empty in every real deployment.
//!
//! That made three shipped readers inert rather than wrong. `federation.rs` resolves a
//! local account by identifier to decide the #78 account-linking table; `recovery.rs` and
//! `account.rs` list a user's identifiers for display. Against an empty table the
//! federation lookup always answered "no local account", so the linking table always took
//! its new-account branch. That fails SAFE, since it never auto-links a federated identity
//! into an account it should not, but the feature does nothing.
//!
//! This module is the first production writer, and with it the `[identifiers]` config
//! section has its first reader (issue #459): the mode installed by the boot path rides
//! into every `add` as the row's uniqueness discriminator, so an operator who writes
//! `non_unique` now gets non-unique behaviour instead of the environment-wide default.
//!
//! One limitation stated plainly rather than papered over: `org_scoped` still resolves to
//! the environment scope, because the org discriminator is app-supplied and no store
//! lookup maps a user to an owning organization. That is migration 0041's and the store's
//! own documented M10 caveat, not a new one this module introduces, and passing `None`
//! here is the documented membership-free fallback rather than a guess.

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use ironauth_config::IdentifierUniqueness;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, IdentifierCollision, IdentifierType, NewUserIdentifier,
    StoreError, UserIdentifierId, UserIdentifierRecord,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    auth::{ManagementPermission, Principal},
    error::{ApiError, ErrorBody},
    idempotency,
    input::parse_json,
    org_context::{EnvironmentAccess, require_live_environment, resolve_scope, resolve_user},
    response::{json, no_content},
    state::{AdminState, uniqueness_mode, uniqueness_setting},
    sudo,
};

/// One typed login identifier on a user.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentifierView {
    /// The identifier row id (`uid_...`).
    pub id: String,
    /// The identifier kind: `email`, `username` or `phone`.
    #[serde(rename = "type")]
    pub identifier_type: String,
    /// The raw value as it was submitted, decrypted for display.
    pub value: String,
    /// Whether this identifier has been verified.
    pub verified: bool,
}

impl From<UserIdentifierRecord> for IdentifierView {
    fn from(record: UserIdentifierRecord) -> Self {
        Self {
            id: record.id.to_string(),
            identifier_type: record.identifier_type.as_str().to_owned(),
            value: record.raw,
            verified: record.verified,
        }
    }
}

/// A user's login identifiers.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentifierList {
    /// The identifiers, ordered deterministically by `(type, id)`.
    pub items: Vec<IdentifierView>,
}

/// Add a typed login identifier to a user.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddIdentifierRequest {
    /// The identifier kind: `email`, `username` or `phone`.
    #[serde(rename = "type")]
    pub identifier_type: String,
    /// The raw identifier. Canonicalized once at the store seam, sealed for display and
    /// blind-indexed for lookup; the plaintext never lands on a column.
    pub value: String,
    /// The initial verification state. Defaults to false, which is the safe answer: M7
    /// owns the ceremonies that flip it, and an operator asserting a verified identifier
    /// is making a claim this API cannot check.
    #[serde(default)]
    pub verified: bool,
}

/// List a user's login identifiers.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers",
    operation_id = "listUserIdentifiers",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The user's login identifiers", body = IdentifierList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The user is absent or in another scope", body = ErrorBody)
    )
)]
pub async fn list_user_identifiers(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    // A READ, so a soft-deleted environment stays readable: an operator auditing a
    // decommissioned environment needs to see what login handles it held.
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Read).await?;
    // The user must exist, or an identifier-free user and an ABSENT one would answer
    // alike and this route would be an existence oracle in the wrong direction, the same
    // reasoning `get_user_traits` carries.
    state.store().scoped(scope).users().get(&id).await?;
    let records = state
        .store()
        .scoped(scope)
        .user_identifiers()
        .list_for_user(&id)
        .await?;
    let view = IdentifierList {
        items: records.into_iter().map(IdentifierView::from).collect(),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Add a login identifier to a user.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers",
    operation_id = "addUserIdentifier",
    tag = "users",
    request_body = AddIdentifierRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The added identifier", body = IdentifierView),
        (status = 400, description = "Malformed request, unknown kind, or an identifier that canonicalizes to nothing", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the user is absent or in another scope", body = ErrorBody),
        (status = 409, description = "The canonical identifier is already taken within the configured uniqueness scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn add_user_identifier(
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
    sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    // Replay BEFORE any body validation, so a genuine replay returns the original
    // response rather than re-deciding anything about the request.
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // A WRITE, so `resolve_user` carries the environment liveness fence (issue #451)
    // rather than this route spelling one out for itself. It sits AFTER the replay
    // because a genuine replay must return the original response even if the user or the
    // environment went away meanwhile.
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    // The PARENT-EXISTENCE precondition, and it earns its query. `resolve_user` proves
    // only that the id PARSES in scope; `user_identifiers` carries
    // `FOREIGN KEY (user_id) REFERENCES users (id)`, so a well-formed id naming a user
    // that does not exist would otherwise reach the INSERT, fail that constraint, and
    // surface as an opaque 500 for an input the caller controls. Measured: the
    // `absent_environment` sweep drove exactly that and got a 500. Resolving it here
    // gives the uniform not-found, the same answer a MALFORMED id already gets, so the
    // two are indistinguishable and neither is an existence oracle.
    //
    // It sits AFTER the replay for the reason `permissions.rs` records: a genuine replay
    // must return the original response even if the user went away meanwhile.
    state.store().scoped(scope).users().get(&id).await?;
    let request: AddIdentifierRequest = parse_json(&body)?;
    // The kind vocabulary is the store's, read through its own parser, so this surface
    // holds no second copy of the closed set that could drift from the CHECK constraint
    // migration 0041 pins.
    let kind = IdentifierType::from_wire(&request.identifier_type).ok_or_else(|| {
        ApiError::BadRequest("type must be one of email, username, phone".to_owned())
    })?;
    // Minted HERE, not inside the store, so the response body is knowable before the
    // write and the `Idempotency-Key` record can ride into the same transaction as the
    // row. Splitting them would be two store writes behind one key, which is exactly
    // what `scripts/idempotent-write-audit.sh` exists to catch.
    let record_id = UserIdentifierId::generate(state.env(), &scope);
    let view = IdentifierView {
        id: record_id.to_string(),
        identifier_type: kind.as_str().to_owned(),
        // The value as SUBMITTED, which is what the store seals for display. The
        // canonical form is deliberately not returned: it is the blind-index input, and
        // publishing it would hand a caller the comparison key the whole scheme keeps
        // out of reach.
        value: request.value.clone(),
        verified: request.verified,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 201,
        response_body: &body_string,
    };
    let pending = identifier_event(&state, scope, &id, &record_id, Some(kind.as_str()));
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .user_identifiers()
        .add_with_event(
            state.env(),
            NewUserIdentifier {
                id: &record_id,
                user_id: &id,
                identifier_type: kind,
                raw: &request.value,
                verified: request.verified,
                // The CONFIGURED mode (issue #459), not a constant. This is the value
                // that decides the row's uniqueness discriminator, so a hardcoded
                // default here would leave the operator's setting inert exactly as it
                // was before.
                mode: state.identifier_uniqueness(),
                // No store lookup maps a user to an owning organization, so this is the
                // documented membership-free fallback rather than a guess: under
                // `org_scoped` the row takes the environment key, precisely as the store
                // documents until M10 membership resolution lands.
                org: None,
            },
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::Conflict(
                "that identifier is already in use within the configured uniqueness scope"
                    .to_owned(),
            ),
            other => other.into(),
        })?;
    Ok(json(StatusCode::CREATED, body_string))
}

/// Remove a login identifier from a user.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/identifiers/{identifier_id}",
    operation_id = "removeUserIdentifier",
    tag = "users",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("user_id" = String, Path, description = "The user identifier (usr_...)"),
        ("identifier_id" = String, Path, description = "The identifier row id (uid_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The identifier was removed"),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent, in another scope, or owned by a different user). The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody)
    )
)]
pub async fn remove_user_identifier(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, user_id, identifier_id)): Path<(
        String,
        String,
        String,
        String,
    )>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_users`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteUsers)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;
    // A WRITE, so `resolve_user` carries the environment liveness fence (issue #451).
    let id = resolve_user(&state, scope, &user_id, EnvironmentAccess::Write).await?;
    // Four addressing failures collapse to ONE answer: a malformed id and one minted in
    // another `(tenant, environment)` fail to parse here, and an absent one or one owned
    // by a DIFFERENT user is the store's own not-found, because the DELETE is keyed on
    // the owning user as well as the row. A caller therefore cannot use this route to
    // learn that some other user holds a given identifier row.
    let record_id =
        UserIdentifierId::parse_in_scope(&identifier_id, &scope).map_err(|_| ApiError::NotFound)?;
    // No parent-existence probe, and that is deliberate rather than an omission: unlike
    // the add, this statement writes no foreign key and reads no sealed value, so an
    // absent user simply removes zero rows and lands on the same not-found. A probe here
    // would be a second query that could only agree with the one below.
    let pending = identifier_event(&state, scope, &id, &record_id, None);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .user_identifiers()
        .remove_with_event(
            state.env(),
            &id,
            &record_id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// The uniqueness mode to evaluate, defaulting to the configured one.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct UniquenessQuery {
    /// `environment_wide`, `org_scoped` or `non_unique`. Omitted means the CONFIGURED
    /// mode, which is the question an operator asks before an apply.
    #[param(value_type = Option<String>)]
    pub mode: Option<IdentifierUniqueness>,
}

/// One post-canonicalization collision a mode would enforce.
#[derive(Debug, Serialize, ToSchema)]
pub struct CollisionView {
    /// The identifier kind the collision is within.
    #[serde(rename = "type")]
    pub identifier_type: String,
    /// How many identifier rows share this canonical form in the scope.
    pub count: i64,
}

impl From<IdentifierCollision> for CollisionView {
    fn from(collision: IdentifierCollision) -> Self {
        Self {
            identifier_type: collision.identifier_type.as_str().to_owned(),
            count: collision.count,
        }
    }
}

/// What a uniqueness mode would enforce in this environment.
#[derive(Debug, Serialize, ToSchema)]
pub struct UniquenessView {
    /// The mode this deployment is configured with, from `[identifiers] uniqueness`.
    #[schema(value_type = String)]
    pub configured_mode: IdentifierUniqueness,
    /// The mode that was evaluated. Equal to `configured_mode` unless `mode` was given.
    #[schema(value_type = String)]
    pub evaluated_mode: IdentifierUniqueness,
    /// The collisions the evaluated mode would enforce. Empty means an apply is safe.
    /// Reports the kind and a count, never a plaintext identifier.
    pub collisions: Vec<CollisionView>,
}

/// Report what an identifier uniqueness mode would enforce in this environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/identifier-uniqueness",
    operation_id = "getIdentifierUniqueness",
    tag = "identifiers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        UniquenessQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The configured mode and what the evaluated mode would enforce", body = UniquenessView),
        (status = 400, description = "Unknown mode", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Tenant or environment not found", body = ErrorBody)
    )
)]
pub async fn get_identifier_uniqueness(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<UniquenessQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let configured = uniqueness_setting(state.identifier_uniqueness());
    // A READ, so a soft-deleted environment answers as if live, like every other read on
    // this surface: an operator deciding whether a decommissioned environment can be
    // resurrected needs to see what its identifiers would collide on.
    let evaluated = query.mode.unwrap_or(configured);
    let collisions = state
        .store()
        .scoped(scope)
        .user_identifiers()
        .collisions_for_mode(uniqueness_mode(evaluated))
        .await?;
    let view = UniquenessView {
        configured_mode: configured,
        evaluated_mode: evaluated,
        collisions: collisions.into_iter().map(CollisionView::from).collect(),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Recompute this environment's identifier uniqueness keys under the configured mode.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/identifier-uniqueness/apply",
    operation_id = "applyIdentifierUniqueness",
    tag = "identifiers",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Every identifier row now carries the configured mode's discriminator"),
        (status = 400, description = "Missing Idempotency-Key", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 409, description = "A collision the configured mode would enforce still exists; nothing was changed", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn apply_identifier_uniqueness(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // CONFIG rather than user authority: applying a uniqueness mode recomputes keys
    // across the WHOLE environment, so it changes the rule every identifier obeys, not
    // one person's data.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    sudo::require_fresh_privilege(&state, scope, actor).await?;

    // This request carries NO body: the mode comes from the deployment config and the
    // environment from the path, so method and path ARE the whole request and the
    // fingerprint over them is complete rather than partial.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }
    require_live_environment(&state, &scope).await?;

    // The CONFIGURED mode, never a caller-supplied one, and that is the safety property
    // of this route rather than a limitation. New writes take their discriminator from
    // the boot config, so recomputing existing rows under any OTHER mode would leave the
    // stored rows and the next write disagreeing about what uniqueness means, which is
    // the exact state migration 0041 describes as producing a "unique" three-way
    // collision. An operator previews a candidate with `GET ?mode=`, changes the config,
    // and then applies, so the two halves cannot diverge.
    let mode = state.identifier_uniqueness();
    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 204,
        response_body: "",
    };
    let pending = identifier_uniqueness_applied_event(&state, scope, mode);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .user_identifiers()
        .apply_uniqueness_mode_with_event(
            state.env(),
            mode,
            Some(write),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::Conflict(
                "a collision the configured mode would enforce still exists; nothing was \
                 changed. Resolve the collisions this environment's identifier-uniqueness \
                 read reports, then retry"
                    .to_owned(),
            ),
            other => other.into(),
        })?;
    Ok(no_content())
}

/// The event adding or removing a user identifier emits (issue #108).
///
/// `identifier_type` present means an ADD, absent means a REMOVE: the add knows the kind it
/// is writing, and the remove is given only a row id.
///
/// NEVER THE IDENTIFIER VALUE. An identifier is an email address or a phone number -- PII,
/// sealed at rest, and the reason this store keeps blind indexes rather than plaintext
/// columns. A webhook is a wider audience than the management read surface, so the same
/// refusal holds. The TYPE is carried on the add because "an email was added" and "a phone
/// was added" are different facts to a receiver deciding whether to re-verify.
fn identifier_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    user_id: &ironauth_store::UserId,
    identifier_id: &ironauth_store::UserIdentifierId,
    identifier_type: Option<&str>,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = user_id.to_string();
    let (event_type, payload) = match identifier_type {
        Some(kind) => (
            "user.identifier_added",
            serde_json::json!({
                "user_id": subject,
                "identifier_id": identifier_id.to_string(),
                "identifier_type": kind,
            }),
        ),
        None => (
            "user.identifier_removed",
            serde_json::json!({
                "user_id": subject,
                "identifier_id": identifier_id.to_string(),
            }),
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
        // The USER is the subject: identifier changes for one person stay ordered.
        subject,
        envelope,
    })
}

/// The event applying an identifier-uniqueness mode emits (issue #108).
///
/// ONE event for the environment, not one per identifier. Applying a mode recomputes the
/// discriminator on EVERY identifier in the environment at once, so there is no single
/// subject to name -- and a per-row fan-out would be a storm that says less than this one
/// line does.
///
/// The MODE is the payload: a receiver mirroring identity policy needs to know which rule now
/// holds, whether an address may repeat across organizations.
fn identifier_uniqueness_applied_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    mode: ironauth_store::identifier::UniquenessMode,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "environment.identifier_uniqueness_applied",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "mode": mode.as_str() }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        // The ENVIRONMENT is the subject: successive policy applications stay ordered.
        subject: scope.environment().to_string(),
        envelope,
    })
}
