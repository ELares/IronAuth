// SPDX-License-Identifier: MIT OR Apache-2.0

//! Credential-abuse ban management under an environment (issue #64).
//!
//! The management-plane parity for the CLI ban commands: place, lift, and list durable
//! credential-abuse bans over an environment. Every endpoint is scoped to a
//! `(tenant, environment)` pair (reachable by the operator OR a management key scoped to
//! exactly that environment) and writes through the SAME audited store repository the CLI
//! uses, so the two surfaces are true parity.
//!
//! A ban subject is PII (an identifier is an email/username/phone; an IP is personal
//! data): the store SEALS it and blind-indexes it, and a listing OPENS it for the
//! authorized operator, exactly as the users PII path does. An identifier subject is
//! CANONICALIZED through the #54 seam so a CLI/admin ban matches the exact form the login
//! path checks.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{
    AbuseSubject, AbuseSubjectKind, ActorRef, AuthPath, CorrelationId, NewBan, Scope, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::Principal;
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;

/// Resolve and authorize the `(tenant, environment)` scope from the path (the operator
/// passes; a management key must be scoped to exactly this environment).
fn resolve_scope(
    state: &AdminState,
    principal: &Principal,
    tenant_id: &str,
    environment_id: &str,
) -> Result<(Scope, ActorRef), ApiError> {
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

/// The request body to place a ban.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateBanRequest {
    /// The regulated dimension: `ip`, `account`, or `identifier`.
    pub subject_kind: String,
    /// The subject value (an IP, a `usr_` id, or a login identifier; an identifier is
    /// canonicalized to match the login path).
    pub subject: String,
    /// The authentication path the ban governs: `password`, `passkey`, `recovery`,
    /// `register`, or `all`. A per-path ban is the account-DoS safeguard.
    pub auth_path: String,
    /// An operator-safe reason (optional).
    #[serde(default)]
    pub reason: Option<String>,
    /// Seconds until the ban auto-expires (optional; omitted = permanent).
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
}

/// The request body to lift a ban.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct LiftBanRequest {
    /// The regulated dimension: `ip`, `account`, or `identifier`.
    pub subject_kind: String,
    /// The subject value (an identifier is canonicalized to match the ban).
    pub subject: String,
    /// The authentication path the ban governs.
    pub auth_path: String,
}

/// A single ban, subject opened for the authorized operator.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BanView {
    /// The `abn_` ban id.
    pub id: String,
    /// The regulated dimension.
    pub subject_kind: String,
    /// The opened subject value.
    pub subject: String,
    /// The authentication path the ban governs.
    pub auth_path: String,
    /// The operator-safe reason.
    pub reason: String,
    /// The auto-expiry instant in Unix milliseconds, or null for a permanent ban.
    pub expires_at_unix_ms: Option<i64>,
    /// When the ban was placed, in Unix milliseconds.
    pub created_at_unix_ms: i64,
}

/// A page of bans.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BanList {
    /// The active bans, newest first.
    pub bans: Vec<BanView>,
}

/// The result of a lift.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LiftBanView {
    /// Whether an active ban was actually removed (false = nothing matched, idempotent).
    pub lifted: bool,
}

/// Parse a subject-kind wire tag, mapping an unknown value to a clean 400.
fn parse_subject_kind(raw: &str) -> Result<AbuseSubjectKind, ApiError> {
    AbuseSubjectKind::from_wire(raw).ok_or_else(|| {
        ApiError::BadRequest("subject_kind must be ip, account, or identifier".into())
    })
}

/// Parse an auth-path wire tag, mapping an unknown value to a clean 400.
fn parse_auth_path(raw: &str) -> Result<AuthPath, ApiError> {
    AuthPath::from_wire(raw).ok_or_else(|| {
        ApiError::BadRequest(
            "auth_path must be password, passkey, recovery, register, second_factor, or all".into(),
        )
    })
}

/// Build the regulated subject, canonicalizing an identifier through the login seam.
fn build_subject(kind: AbuseSubjectKind, raw: &str) -> AbuseSubject {
    let value = match kind {
        AbuseSubjectKind::Identifier => ironauth_oidc::canonical_login_identifier(raw)
            .as_str()
            .to_owned(),
        AbuseSubjectKind::Ip | AbuseSubjectKind::Account => raw.to_owned(),
    };
    AbuseSubject { kind, value }
}

/// Place a durable credential-abuse ban.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans",
    operation_id = "createBan",
    tag = "abuse",
    request_body = CreateBanRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Ban placed", body = BanView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody),
        (status = 409, description = "The subject is already banned on this path", body = ErrorBody)
    )
)]
pub async fn create_ban(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let request: CreateBanRequest = crate::input::parse_json(&body)?;
    let kind = parse_subject_kind(&request.subject_kind)?;
    let path = parse_auth_path(&request.auth_path)?;
    if request.subject.trim().is_empty() {
        return Err(ApiError::BadRequest("subject must not be empty".into()));
    }
    let subject = build_subject(kind, request.subject.trim());
    let reason = request
        .reason
        .as_deref()
        .unwrap_or("operator ban (admin API)");
    let now = state.now_unix_micros();
    let expires = request
        .expires_in_secs
        .filter(|secs| *secs > 0)
        .map(|secs| now.saturating_add(secs.saturating_mul(1_000_000)));
    let id = ironauth_store::AbuseBanId::generate(state.env(), &scope);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .abuse()
        .ban(
            state.env(),
            NewBan {
                id: &id,
                subject: &subject,
                auth_path: path,
                reason,
                expires_at_unix_micros: expires,
            },
            now,
        )
        .await;
    match result {
        Ok(id) => {
            let view = BanView {
                id: id.to_string(),
                subject_kind: kind.as_str().to_owned(),
                subject: subject.value,
                auth_path: path.as_str().to_owned(),
                reason: reason.to_owned(),
                expires_at_unix_ms: expires.map(|micros| micros / 1000),
                created_at_unix_ms: now / 1000,
            };
            let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
            Ok(json(StatusCode::CREATED, body_string))
        }
        Err(StoreError::Conflict) => Err(ApiError::Conflict(
            "the subject is already banned on this path".to_owned(),
        )),
        Err(error) => Err(error.into()),
    }
}

/// Lift a credential-abuse ban.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans/lift",
    operation_id = "liftBan",
    tag = "abuse",
    request_body = LiftBanRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Lift processed (idempotent)", body = LiftBanView),
        (status = 400, description = "Malformed request", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn lift_ban(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;
    let request: LiftBanRequest = crate::input::parse_json(&body)?;
    let kind = parse_subject_kind(&request.subject_kind)?;
    let path = parse_auth_path(&request.auth_path)?;
    if request.subject.trim().is_empty() {
        return Err(ApiError::BadRequest("subject must not be empty".into()));
    }
    let subject = build_subject(kind, request.subject.trim());
    let lifted = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .abuse()
        .lift(state.env(), &subject, path)
        .await?;
    let view = LiftBanView { lifted };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// List the active credential-abuse bans under an environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/abuse/bans",
    operation_id = "listBans",
    tag = "abuse",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The active bans", body = BanList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Environment not found", body = ErrorBody)
    )
)]
pub async fn list_bans(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id)?;
    let bans = state
        .store()
        .scoped(scope)
        .abuse()
        .list_active(state.now_unix_micros())
        .await?;
    let view = BanList {
        bans: bans
            .into_iter()
            .map(|ban| BanView {
                id: ban.id.to_string(),
                subject_kind: ban.subject_kind.as_str().to_owned(),
                subject: ban.subject,
                auth_path: ban.auth_path.as_str().to_owned(),
                reason: ban.reason,
                expires_at_unix_ms: ban.expires_at_unix_micros.map(|micros| micros / 1000),
                created_at_unix_ms: ban.created_at_unix_micros / 1000,
            })
            .collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}
