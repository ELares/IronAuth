// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment identity trait-schema version management (issue #53).
//!
//! The management surface over the versioned trait-schema registry: create a new immutable
//! version, list an environment's versions, get one by number, read the ACTIVE served
//! version (the introspection endpoint a form generator reads), and ACTIVATE a candidate as
//! the served default (the cutover). A trait schema is a DATA-plane scoped resource
//! (`trait_schemas`), reachable by the operator OR by a management key scoped to exactly this
//! environment, the same authorization as the environment reads, exactly like locales, signup
//! forms, and journey versions.
//!
//! The shape is deliberately the one `flow_versions` (issue #92) established, because it is the
//! same shape of thing: an append-only registry of IMMUTABLE versions with one active pointer.
//! A version is never overwritten and never deleted (a change is a new version), so there is no
//! PUT and no DELETE; the only mutation of the pointer is the activate. Both mutations are POSTs,
//! so both REQUIRE an `Idempotency-Key` and store their response under it in the SAME transaction
//! as the write, both are sudo gated (which schema an environment serves decides what every
//! identity write is validated against, and which fields are admin-only, so it is as
//! security-relevant a config surface as a journey artifact), and both prove the environment LIVE
//! through the one shared `require_live_environment`.
//!
//! ## The cutover rule, and what this PR does about it
//!
//! The issue says a version cannot become the active default while unresolved invalid identities
//! remain. That gate is NOT deferred to the dry-run and migration jobs: `activate_version` already
//! refuses on an AUTHORITATIVE LIVE SCAN, opening every identity's sealed traits inside the
//! activation transaction and counting the ones the target schema rejects. A non-zero count is
//! [`StoreError::CutoverBlocked`], which this surface renders as a 422 naming the count, and
//! NOTHING moves.
//!
//! That is the STRONGER of the two available gates and it is what ships here, rather than a gate
//! on job state. A job report is a claim about a moment that has passed: an identity written after
//! the dry-run finished would satisfy a report-based gate while still failing the schema. The live
//! scan cannot go stale, because it runs in the transaction that moves the pointer.
//!
//! The later jobs PR therefore TIGHTENS this rather than replacing it. It adds the operator
//! ERGONOMICS the issue asks for (which identities failed, and why, per field, before the operator
//! attempts a cutover at all) and may add a second precondition on top; it cannot loosen the live
//! scan, because activation is refused by the scan whatever any job says.
//!
//! ## What this surface deliberately does NOT have
//!
//! There is no LIST of identities by their traits, and no per-trait search. That is a decision,
//! not an omission: the bulk read of trait documents is `exportIdentities`, which already serves
//! the whole decrypted set, is cursor paginated, and writes a `user.export` audit row precisely
//! because a bulk read of identity data is an egress event worth recording. A second bulk path
//! here would either duplicate that surface without its audit row, or need its own, and a
//! trait-valued FILTER would need a queryable projection of a column that is sealed at rest,
//! which is the one thing the encryption design (issue #48) does not offer. A single identity's
//! document is read through `getUserTraits`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, Scope, StoreError, TraitSchema, TraitSchemaId,
    TraitSchemaVersion,
};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::response::json;
use crate::state::AdminState;
use crate::views::{CreateTraitSchemaRequest, TraitSchemaVersionView};

/// Resolve and authorize the `(tenant, environment)` scope from the path (issue #53). The operator
/// passes; a management key must be scoped to exactly this environment (otherwise the LOUD
/// wrong-scope error). A malformed tenant or environment id is the uniform not-found.
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

/// Normalize the `{version}` path parameter to a positive version number, or the uniform not-found
/// for a malformed or non-positive value (it names no version). Mirrors `flow_versions`.
fn parse_version(raw: &str) -> Result<i32, ApiError> {
    match raw.parse::<i32>() {
        Ok(version) if version >= 1 => Ok(version),
        _ => Err(ApiError::NotFound),
    }
}

/// Build the API view of a STORED version. A stored schema is proved well formed on write, so a
/// compile fault here is a persistence corruption and never a caller fault: it is an internal
/// error, not a 400.
///
/// A SUBMITTED schema must NOT reach this. It goes through [`validated_schema`] first, which is
/// the same compile with the opposite verdict on failure. Getting that the wrong way round is not
/// a hypothetical: the first cut of this file built the response view straight off the submitted
/// document, so a malformed schema answered 500 (MEASURED) instead of the 400 the store's typed
/// `SchemaMalformed` was already carrying, and the store's precise reason never reached the
/// operator at all.
fn view_of(record: &TraitSchemaVersion) -> Result<TraitSchemaVersionView, ApiError> {
    TraitSchemaVersionView::from_version(record).map_err(|_| ApiError::Internal)
}

/// Compile the SUBMITTED schema document, returning the canonical JSON text to persist. This is
/// the SAME well-formedness gate the store applies on write, run here first so the operator gets
/// the precise reason (an RFC 6901 pointer into the schema document and a stable message), and so
/// the response view below is only ever built from a document that compiles.
///
/// A malformed schema is a loud 400 naming the offending LOCATION, never a caller value; a schema
/// document declares field shapes and carries no secret, so the reason is safe to return.
fn validated_schema(request: &CreateTraitSchemaRequest) -> Result<String, ApiError> {
    let schema_json = serde_json::to_string(&request.schema).map_err(|_| ApiError::Internal)?;
    TraitSchema::compile(&schema_json)
        .map_err(|error| ApiError::BadRequest(format!("trait schema is malformed: {error}")))?;
    Ok(schema_json)
}

/// Create a new immutable trait-schema version.
///
/// This is a POST, not a PUT: it APPENDS a new immutable version with a server-assigned monotonic
/// version number. Per the codebase convention it REQUIRES an `Idempotency-Key`, wired through the
/// shared idempotency path: a retry with the same key REPLAYS the stored response (the SAME version
/// number), so a client or network retry never silently appends a duplicate version. A key reused
/// with a different body is a 422.
///
/// A new version is created as a CANDIDATE. It changes nothing about what identity writes are
/// validated against until it is activated, which is a separate, cutover-guarded call.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas",
    operation_id = "createTraitSchemaVersion",
    tag = "trait-schemas",
    request_body = CreateTraitSchemaRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response (the same version) without appending a \
         duplicate.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The created candidate version", body = TraitSchemaVersionView),
        (status = 400, description = "A malformed schema document, naming the offending location", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 409, description = "A concurrent create took the next version; retry", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_trait_schema_version(
    State(state): State<AdminState>,
    principal: Principal,
    uri: Uri,
    headers: HeaderMap,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Authoring a schema version decides what every later identity write is validated against and
    // which of its fields are admin-only, so it demands fresh privilege exactly like the other
    // environment-scoped management writes (locales, signup forms, journey versions).
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The environment must exist and be live (issues #443, #451): the one shared expression of the
    // parent-existence precondition, AFTER the replay so a genuine retry of a write that already
    // succeeded still returns its original response.
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: CreateTraitSchemaRequest = parse_json(&body)?;
    // Store ONLY a schema that COMPILES: a malformed document is a loud 400 naming the offending
    // location, and nothing is written.
    let schema_json = validated_schema(&request)?;

    // Resolve the id and the next version BEFORE the write so the response is fully known, then
    // store it under the Idempotency-Key IN THE SAME transaction as the version and its audit row.
    let id = TraitSchemaId::generate(state.env(), &scope);
    let version = state
        .store()
        .scoped(scope)
        .trait_schemas()
        .next_version()
        .await?;
    let created_at_micros = state.now_unix_micros();
    let view = view_of(&TraitSchemaVersion {
        id,
        version,
        schema_json: schema_json.clone(),
        // A freshly created version is a CANDIDATE, never the active default.
        active: false,
        created_at_unix_micros: created_at_micros,
    })?;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .trait_schemas()
        .create_version_at(
            state.env(),
            &id,
            &schema_json,
            version,
            created_at_micros,
            Some(write),
        )
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        // A concurrent create took the next version: retriable, not a duplicate or overwrite.
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "a concurrent create took the next trait-schema version; retry".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// List every trait-schema version of an environment (ascending by version).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas",
    operation_id = "listTraitSchemaVersions",
    tag = "trait-schemas",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's trait-schema versions", body = [TraitSchemaVersionView]),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody)
    )
)]
pub async fn list_trait_schema_versions(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let records = state
        .store()
        .scoped(scope)
        .trait_schemas()
        .list_versions()
        .await?;
    // Uncapped and uncursored, matching listFlowVersions: a schema version registry is
    // operator-authored and bounded by how many times a team has evolved its identity model, not
    // by an end-user-driven population. There is nothing here a client can grow.
    let views = records
        .iter()
        .map(view_of)
        .collect::<Result<Vec<_>, ApiError>>()?;
    let body_string = serde_json::to_string(&views).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get the environment's ACTIVE trait schema (the schema introspection endpoint).
///
/// This is the version every identity write is validated against, served with its parsed behavior
/// annotations (login identifiers, verification addresses, recovery channels, and the admin-only
/// set), so a form generator reads the schema and its contract from one response.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/active",
    operation_id = "getActiveTraitSchema",
    tag = "trait-schemas",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The active version and its behavior annotations", body = TraitSchemaVersionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment has no active trait schema", body = ErrorBody)
    )
)]
pub async fn get_active_trait_schema(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let record = state
        .store()
        .scoped(scope)
        .trait_schemas()
        .active()
        .await?
        .ok_or(ApiError::NotFound)?;
    let body_string = serde_json::to_string(&view_of(&record)?).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Get one trait-schema version by its version number.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/{version}",
    operation_id = "getTraitSchemaVersion",
    tag = "trait-schemas",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("version" = i32, Path, description = "The version number")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The version", body = TraitSchemaVersionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Not found (absent or in another scope)", body = ErrorBody)
    )
)]
pub async fn get_trait_schema_version(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, version)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let version = parse_version(&version)?;
    let record = state
        .store()
        .scoped(scope)
        .trait_schemas()
        .get_version(version)
        .await?
        .ok_or(ApiError::NotFound)?;
    let body_string = serde_json::to_string(&view_of(&record)?).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Activate a trait-schema version as the environment's served default (the cutover).
///
/// GATED. The activation is REFUSED, and nothing moves, while any existing identity's traits fail
/// the target schema: the store counts them on a live scan INSIDE the activation transaction, and a
/// non-zero count answers 422 naming the count. See this module's header for why the live scan
/// rather than a job report is the gate that ships, and why the later dry-run and migration jobs
/// tighten it rather than replace it.
///
/// A mutating POST, so per the codebase convention it REQUIRES an `Idempotency-Key`: a retry with
/// the same key REPLAYS the stored response without re-running the scan (and activation is
/// naturally idempotent on the target version anyway).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/{version}/activate",
    operation_id = "activateTraitSchemaVersion",
    tag = "trait-schemas",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("version" = i32, Path, description = "The version number to activate"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The now-active version", body = TraitSchemaVersionView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The version does not exist in this scope. The environment must be live too: an absent or soft-deleted one answers this same not-found", body = ErrorBody),
        (status = 422, description = "The cutover is BLOCKED (identities fail the target schema), or the Idempotency-Key was reused with a different request", body = ErrorBody)
    )
)]
pub async fn activate_trait_schema_version(
    State(state): State<AdminState>,
    principal: Principal,
    uri: Uri,
    headers: HeaderMap,
    Path((tenant_id, environment_id, version)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // Moving the active pointer changes what every identity write is validated against, so it
    // demands fresh privilege exactly like a version create.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let version = parse_version(&version)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The parent-existence precondition, through the ONE expression of it (issues #443, #451). A
    // `trait_schemas` row survives its environment's soft delete, so without this the activation
    // would land inside a decommissioned environment. It sits AFTER the idempotency replay for the
    // reason `resolve_live_org` records: a genuine replay must still return the original response
    // even if the environment went away in between.
    crate::org_context::require_live_environment(&state, &scope).await?;

    // Resolve the target version BEFORE the activation so the response is fully known and can be
    // stored under the Idempotency-Key in the SAME transaction as the pointer move. A version's
    // schema document is immutable, so reading it before the activation gives the correct body.
    let record = state
        .store()
        .scoped(scope)
        .trait_schemas()
        .get_version(version)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut view = view_of(&record)?;
    view.active = true;
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let write = IdempotencyWrite {
        credential_ref: &credential_ref,
        key: &key,
        request_fingerprint: &fingerprint,
        response_status: 200,
        response_body: &body_string,
    };
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .trait_schemas()
        .activate_version_idempotent(state.env(), version, Some(write))
        .await;
    match result {
        Ok(()) => Ok(json(StatusCode::OK, body_string)),
        Err(StoreError::IdempotencyConflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(error) => Err(error.into()),
    }
}

// A trait-schema version is IMMUTABLE and never deleted (a change is a new version), so the
// append-only registry deliberately exposes no update and no delete surface, exactly like the
// journey-version registry.

#[cfg(test)]
mod tests {
    use super::parse_version;
    use crate::error::ApiError;

    #[test]
    fn a_positive_version_parses_and_a_non_positive_or_malformed_one_is_a_uniform_not_found() {
        assert_eq!(parse_version("1").expect("valid"), 1);
        assert_eq!(parse_version("42").expect("valid"), 42);
        assert!(matches!(parse_version("0"), Err(ApiError::NotFound)));
        assert!(matches!(parse_version("-3"), Err(ApiError::NotFound)));
        assert!(matches!(parse_version("nope"), Err(ApiError::NotFound)));
        // The `/active` literal is a SIBLING path, matched by the router as a static segment
        // before it ever reaches this parser. Should the ranking ever change, "active" is a
        // uniform not-found here rather than a 500 or a version-0 read.
        assert!(matches!(parse_version("active"), Err(ApiError::NotFound)));
    }
}

/// Start a trait migration or dry-run job.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTraitMigrationRequest {
    /// `dry_run` validates every identity against the target version and writes nothing;
    /// `migrate` transforms and writes.
    pub kind: String,
    /// The schema version identities are migrated or validated FROM.
    pub from_version: i32,
    /// The candidate schema version identities are migrated or validated TO.
    pub to_version: i32,
    /// The declarative transform program, a JSON array. Omitted means the empty program,
    /// which is what a dry-run uses and what a migrate that only re-validates uses.
    #[serde(default)]
    pub transform: Option<serde_json::Value>,
}

/// One identity that failed validation, with the fields that failed.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordFailureView {
    /// The failing identity's subject (a `usr_` id).
    pub subject: String,
    /// The per-field failures, each an RFC 6901 JSON Pointer and a reason.
    pub failures: Vec<serde_json::Value>,
}

/// A migration job's definition, progress and failure report.
#[derive(Debug, Serialize, ToSchema)]
pub struct TraitMigrationJobView {
    /// The `tmj_` identifier.
    pub id: String,
    /// `dry_run` or `migrate`.
    pub kind: String,
    /// The version migrated FROM.
    pub from_version: i32,
    /// The version migrated TO.
    pub to_version: i32,
    /// `pending`, `running`, `completed` or `failed`.
    pub status: String,
    /// How many identities the job set out to process.
    pub total_count: i64,
    /// How many have been processed so far.
    pub processed_count: i64,
    /// How many were migrated. Always zero for a dry-run, which writes nothing.
    pub migrated_count: i64,
    /// How many failed validation.
    pub failure_count: i64,
    /// The per-record failure report.
    pub failures: Vec<RecordFailureView>,
}

/// Project a stored job into its wire view.
fn job_view(job: &ironauth_store::TraitMigrationJob) -> Result<TraitMigrationJobView, ApiError> {
    let failures = job
        .failures
        .iter()
        .map(|failure| {
            Ok(RecordFailureView {
                subject: failure.subject.clone(),
                failures: failure
                    .failures
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| ApiError::Internal)?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(TraitMigrationJobView {
        id: job.id.to_string(),
        kind: job.kind.as_str().to_owned(),
        from_version: job.from_version,
        to_version: job.to_version,
        status: job.status.as_str().to_owned(),
        total_count: job.total_count,
        processed_count: job.processed_count,
        migrated_count: job.migrated_count,
        failure_count: job.failure_count,
        failures,
    })
}

/// Start a trait migration or dry-run job.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/migrations",
    operation_id = "createTraitMigrationJob",
    tag = "trait-schemas",
    request_body = CreateTraitMigrationRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 202, description = "The job was created and its first batch queued", body = TraitMigrationJobView),
        (status = 400, description = "Malformed request, an unknown kind, or a transform program that does not parse", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_trait_migration_job(
    State(state): State<AdminState>,
    principal: Principal,
    uri: Uri,
    headers: HeaderMap,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    // A migrate job REWRITES every identity's traits, which is the largest data mutation
    // this surface offers, so it demands fresh privilege exactly as a cutover does.
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }
    // AFTER the replay, for the reason every other write on this surface records: a
    // genuine replay must still return its original response even if the environment went
    // away in between. And BEFORE the body is parsed, which the whole-surface sweep
    // enforces: validating the body first makes a malformed request answer 400 at a
    // soft-deleted environment, which tells an unauthorized caller the environment is
    // there. The uniform not-found has to come first.
    crate::org_context::require_live_environment(&state, &scope).await?;

    let request: CreateTraitMigrationRequest = parse_json(&body)?;
    let kind = ironauth_store::TraitJobKind::from_wire(&request.kind)
        .ok_or_else(|| ApiError::BadRequest("kind must be one of dry_run | migrate".to_owned()))?;
    // Serialized here rather than passed through, so a transform that is not a JSON ARRAY
    // is refused at the edge with a precise message instead of reaching the store's parse.
    let transform = match &request.transform {
        None => None,
        Some(value) if value.is_array() => {
            Some(serde_json::to_string(value).map_err(|_| ApiError::Internal)?)
        }
        Some(_) => {
            return Err(ApiError::BadRequest(
                "transform must be a JSON array".to_owned(),
            ));
        }
    };

    // The id is minted HERE so the first batch's payload, the job row and the stored
    // idempotent response are all knowable before the single write that commits them.
    let job_id = ironauth_store::TraitMigrationJobId::generate(state.env(), &scope);
    let payload = crate::trait_migration_worker::batch_payload(&job_id, &actor);

    // The response describes the job as CREATED: pending, nothing processed. A count would
    // be a lie, since the first batch has not run, so this answers 202 and the caller polls
    // the GET below. Knowing it up front is also what lets the whole create be one write.
    let view = TraitMigrationJobView {
        id: job_id.to_string(),
        kind: kind.as_str().to_owned(),
        from_version: request.from_version,
        to_version: request.to_version,
        status: ironauth_store::TraitJobStatus::Pending.as_str().to_owned(),
        // Unknown until the write counts the population, and deliberately reported as zero
        // rather than guessed: the GET returns the real denominator once the row exists.
        total_count: 0,
        processed_count: 0,
        migrated_count: 0,
        failure_count: 0,
        failures: Vec::new(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .trait_migration_jobs()
        .create_with_id(
            state.env(),
            &job_id,
            ironauth_store::NewTraitMigrationJob {
                kind,
                from_version: request.from_version,
                to_version: request.to_version,
                transform_json: transform.as_deref(),
            },
            state.now_unix_micros(),
            ironauth_store::TraitMigrationStart {
                first_batch_payload: &payload,
                idempotency: Some(IdempotencyWrite {
                    credential_ref: &credential_ref,
                    key: &key,
                    request_fingerprint: &fingerprint,
                    response_status: 202,
                    response_body: &body_string,
                }),
            },
        )
        .await?;
    Ok(json(StatusCode::ACCEPTED, body_string))
}

/// Read a trait migration job's progress and failure report.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas/migrations/{job_id}",
    operation_id = "getTraitMigrationJob",
    tag = "trait-schemas",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("job_id" = String, Path, description = "The job identifier (tmj_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The job's progress and failure report", body = TraitMigrationJobView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such job in this scope", body = ErrorBody)
    )
)]
pub async fn get_trait_migration_job(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, job_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ, matching every other read across this surface.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let id = ironauth_store::TraitMigrationJobId::parse_in_scope(&job_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    let job = state
        .store()
        .scoped(scope)
        .trait_migration_jobs()
        .get(&id)
        .await?;
    let body_string = serde_json::to_string(&job_view(&job)?).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}
