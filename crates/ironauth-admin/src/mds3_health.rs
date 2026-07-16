// SPDX-License-Identifier: MIT OR Apache-2.0

//! The FIDO MDS3 metadata cache health endpoint (issue #66 PR B).
//!
//! `GET .../webauthn/mds3/health` reports the state of an environment's verified
//! FIDO Metadata Service snapshot: the cached BLOB's sequence number, when it was
//! last verified, its `nextUpdate`, how many authenticator entries it holds, and a
//! FRESH/STALE verdict computed against the `env.clock()` instant. A `direct`
//! attestation deployment watches this to catch a stale snapshot (revocation is
//! deferred for v1, so `nextUpdate` staleness is the operator's freshness signal).
//!
//! Authorization is environment-scoped, exactly like the migration-progress read:
//! the operator plane or the environment's own management key may read it. It reads
//! only cache metadata (a blob sequence number and timestamps), so it decrypts no
//! PII.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{Scope, TenantId};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;

/// An environment's FIDO MDS3 cache health (issue #66 PR B).
#[derive(Serialize, ToSchema)]
pub struct Mds3HealthView {
    /// Whether a verified MDS3 snapshot has been cached for this environment.
    pub cached: bool,
    /// The cached BLOB's `no` sequence number, or null when none is cached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_no: Option<i64>,
    /// When the cached BLOB's signature chain was last verified, unix microseconds,
    /// or null when none is cached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at_unix_micros: Option<i64>,
    /// The cached BLOB's own `nextUpdate`, unix microseconds, or null when none is
    /// cached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_update_unix_micros: Option<i64>,
    /// How many authenticator entries the cached snapshot holds, or null when none is
    /// cached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_count: Option<usize>,
    /// The freshness verdict against the current clock: `fresh` when the snapshot is
    /// still within its `nextUpdate` window, `stale` when it has lapsed (an operator
    /// should trigger a resync), or `missing` when nothing is cached.
    pub verdict: &'static str,
}

/// Resolve the `(tenant, environment)` scope from the path.
fn scope_from_path(
    state: &AdminState,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(TenantId, Scope), ApiError> {
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
    Ok((tenant, Scope::new(tenant, environment)))
}

/// Report the environment's FIDO MDS3 cache health.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webauthn/mds3/health",
    operation_id = "getMds3Health",
    tag = "webauthn",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's FIDO MDS3 cache health: the cached \
         BLOB sequence number, when it was last verified, its nextUpdate, the entry count, \
         and a fresh/stale/missing verdict against the current clock.", body = Mds3HealthView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn get_mds3_health(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Environment-scoped read: the operator plane, or the environment's own management
    // key, may read its MDS3 cache health.
    principal.require_environment(tenant, scope.environment())?;

    let cache = state
        .store()
        .scoped(scope)
        .mds3_blob_cache()
        .get()
        .await
        .map_err(|_| ApiError::Internal)?;

    let view = match cache {
        None => Mds3HealthView {
            cached: false,
            blob_no: None,
            verified_at_unix_micros: None,
            next_update_unix_micros: None,
            entry_count: None,
            verdict: "missing",
        },
        Some(cache) => {
            // Fresh while the current clock is still within the cached nextUpdate window.
            let verdict = if state.now_unix_micros() <= cache.next_update_unix_micros {
                "fresh"
            } else {
                "stale"
            };
            let entry_count = cache
                .payload_jsonb
                .get("entries")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len);
            Mds3HealthView {
                cached: true,
                blob_no: Some(cache.blob_no),
                verified_at_unix_micros: Some(cache.verified_at_unix_micros),
                next_update_unix_micros: Some(cache.next_update_unix_micros),
                entry_count,
                verdict,
            }
        }
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
