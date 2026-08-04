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
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use ironauth_store::{
    CorrelationId, IdempotencyWrite, IdentifierType, NewUserIdentifier, StoreError,
    UserIdentifierId, UserIdentifierRecord,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    auth::Principal,
    error::{ApiError, ErrorBody},
    idempotency,
    input::parse_json,
    org_context::{EnvironmentAccess, resolve_scope, resolve_user},
    response::json,
    state::AdminState,
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
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
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
        ("user_id" = String, Path, description = "The user identifier (usr_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The added identifier", body = IdentifierView),
        (status = 400, description = "Malformed request, unknown kind, or an identifier that canonicalizes to nothing", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the user is absent or in another scope", body = ErrorBody),
        (status = 409, description = "The canonical identifier is already taken within the configured uniqueness scope", body = ErrorBody)
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
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
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
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .user_identifiers()
        .add(
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
