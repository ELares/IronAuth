// SPDX-License-Identifier: MIT OR Apache-2.0

//! The in-admin Argon2id tuning-probe endpoint (issue #62).
//!
//! `POST .../password-hashing/probe` runs a MEASURED Argon2id probe on the host
//! serving the request and returns a parameter recommendation plus the projected
//! logins/s per core, the same [`ironauth_oidc::run_probe`] core the `ironauth
//! hash-probe` CLI wraps. It closes the acceptance gap that the tuning helper ship
//! "in both admin UI and CLI": the admin plane now exposes the identical probe.
//!
//! Correct Argon2id parameters are hardware-dependent, so an operator tunes them
//! against the real machine rather than shipping fixed values. The probe is a
//! READ-ONLY measurement (it changes no stored state), so it is safe to replay and
//! carries only an OPTIONAL Idempotency-Key.
//!
//! Authorization is environment-scoped: the operator plane, or the environment's
//! OWN management key, may run it (the same `require_environment` gate the other
//! per-environment reads use). The probe hashes only a fixed throwaway plaintext,
//! so it reads and decrypts no PII.
//!
//! The Argon2id work runs on a blocking thread (via [`tokio::task::spawn_blocking`]),
//! never inline on the async request thread, mirroring issue #62's core rule that
//! hashing never blocks protocol I/O.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_config::{
    PASSWORD_HASHING_MAX_PROBE_TARGET_LATENCY_MS, PASSWORD_HASHING_MIN_PROBE_TARGET_LATENCY_MS,
};
use ironauth_oidc::ProbeReport;
use ironauth_store::{Scope, TenantId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::response::json;
use crate::state::AdminState;

/// The default target per-hash latency (ms) the probe tunes around when the request
/// does not specify one. Mirrors `PasswordHashingConfig`'s shipped default (`250`),
/// a common interactive-login budget.
const DEFAULT_PROBE_TARGET_LATENCY_MS: u64 = 250;

/// The optional tuning inputs for a probe run. Both fields default, so an empty
/// body runs the probe at the shipped default target and a host-derived memory
/// budget.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordHashingProbeRequest {
    /// The target per-hash latency in milliseconds the probe aims for. Clamped to
    /// the configured bounds (`PASSWORD_HASHING_MIN/MAX_PROBE_TARGET_LATENCY_MS`);
    /// defaults to 250 when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_latency_ms: Option<u64>,
    /// The per-hash memory budget in KiB to cap candidates at. Defaults to a
    /// fraction of total host RAM (issue #62) when omitted, so the probe can
    /// explore the full ladder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_budget_kib: Option<u64>,
}

/// A parameter recommendation produced from a host-measured probe (issue #62).
#[derive(Debug, Serialize, ToSchema)]
pub struct PasswordHashingProbeReport {
    /// Recommended Argon2id memory cost in KiB.
    pub memory_kib: u32,
    /// Recommended Argon2id iteration (time) cost.
    pub iterations: u32,
    /// Recommended Argon2id parallelism (lanes).
    pub parallelism: u32,
    /// The measured per-hash latency of the recommendation, in milliseconds.
    pub measured_latency_ms: f64,
    /// The target per-hash latency the probe aimed for, in milliseconds.
    pub target_latency_ms: u64,
    /// Whether the recommendation met the target (`measured <= target`). False on a
    /// host too slow to hit the target even at the memory floor.
    pub within_target: bool,
    /// Projected logins per second a single core sustains at the recommendation.
    pub projected_logins_per_sec_per_core: f64,
    /// Projected logins per second the whole host sustains.
    pub projected_logins_per_sec_total: f64,
    /// The host parallelism the total projection multiplies by.
    pub host_threads: usize,
    /// The host's available memory in KiB, when measurable, else null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_memory_kib: Option<u64>,
    /// The per-hash memory budget the probe capped candidates at, in KiB.
    pub memory_budget_kib: u64,
}

impl From<&ProbeReport> for PasswordHashingProbeReport {
    fn from(report: &ProbeReport) -> Self {
        Self {
            memory_kib: report.recommended.memory_kib(),
            iterations: report.recommended.iterations(),
            parallelism: report.recommended.parallelism(),
            measured_latency_ms: report.measured_latency_ms,
            target_latency_ms: report.target_latency_ms,
            within_target: report.within_target,
            projected_logins_per_sec_per_core: report.projected_logins_per_sec_per_core,
            projected_logins_per_sec_total: report.projected_logins_per_sec_total,
            host_threads: report.host_threads,
            available_memory_kib: report.available_memory_kib,
            memory_budget_kib: report.memory_budget_kib,
        }
    }
}

/// Resolve the `(tenant, environment)` scope from the path, parsing both ids
/// through the management repositories (a malformed id is the uniform not-found).
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

/// Run the Argon2id tuning probe on this host and return a recommendation.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/password-hashing/probe",
    operation_id = "probePasswordHashing",
    tag = "password-hashing",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Optional. A probe is a \
         read-only host measurement that changes nothing, so a replay is inherently safe.")
    ),
    request_body(content = PasswordHashingProbeRequest, description = "Optional tuning inputs \
        (target latency, memory budget); an empty body uses the shipped default target and a \
        host-derived memory budget.", content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The measured recommendation: the Argon2id parameters whose \
         measured hash met the target latency, the measured latency, whether the target was met, \
         and the projected logins/s per core and across the host.", body = PasswordHashingProbeReport),
        (status = 400, description = "The request body is invalid", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn probe_password_hashing(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (tenant, scope) = scope_from_path(&state, &tenant_id, &environment_id)?;
    // Environment-scoped: the operator plane, or the environment's own management
    // key, may run the probe.
    principal.require_environment(tenant, scope.environment())?;
    // The environment must exist (a clean 404 rather than a probe on nothing).
    state
        .store()
        .management()
        .environments(tenant)
        .get(&scope.environment())
        .await?;

    let request: PasswordHashingProbeRequest = if body.is_empty() {
        PasswordHashingProbeRequest::default()
    } else {
        parse_json(&body)?
    };
    let target = request
        .target_latency_ms
        .unwrap_or(DEFAULT_PROBE_TARGET_LATENCY_MS)
        .clamp(
            PASSWORD_HASHING_MIN_PROBE_TARGET_LATENCY_MS,
            PASSWORD_HASHING_MAX_PROBE_TARGET_LATENCY_MS,
        );
    let budget = request
        .memory_budget_kib
        .unwrap_or_else(ironauth_oidc::default_memory_budget_kib);

    // The probe spends real Argon2id CPU; run it on a blocking thread so it never
    // blocks the async request thread (issue #62's core rule).
    let env = state.env().clone();
    let report =
        tokio::task::spawn_blocking(move || ironauth_oidc::run_probe(&env, target, budget))
            .await
            .map_err(|_| ApiError::Internal)?;

    let view = PasswordHashingProbeReport::from(&report);
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}
