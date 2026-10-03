// SPDX-License-Identifier: MIT OR Apache-2.0

//! The security-advisory management surface (issue #163): the banner projection
//! and the offline bundle import.
//!
//! The banner surface (`GET /security/advisories`) lists the ACCEPTED advisories.
//! Every row was verified before insertion, so the surface never renders an
//! unverified advisory. The offline import (`POST /security/advisories/import`)
//! takes the SAME signed bundle the online poll consumes: the single verification
//! path runs, a bundle that fails verification is rejected ENTIRELY and the
//! security event is logged, and the verified set replaces the accepted rows.
//! Air-gapped deployments without egress get the same banners through this path.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One advisory, as the banner surface renders it.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdvisoryView {
    /// The stable advisory identifier.
    pub id: String,
    /// The human-facing title.
    pub title: String,
    /// The severity tier.
    pub severity: String,
    /// The affected version ranges.
    pub affected_versions: Vec<String>,
    /// The banner summary.
    pub summary: String,
    /// The advisory's published date (unix seconds).
    pub published_at: i64,
}

/// The accepted advisories.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdvisoryListView {
    /// The accepted advisories, newest first.
    pub advisories: Vec<AdvisoryView>,
}

/// The offline bundle import request: the SAME signed feed the online poll
/// consumes.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AdvisoryImportRequest {
    /// The signed feed document (the `feed` + `signature` members).
    pub feed: String,
}

/// List the accepted advisories (the admin SPA's banner surface).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/security/advisories",
    operation_id = "listSecurityAdvisories",
    tag = "security",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The accepted security advisories", body = AdvisoryListView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or not in this scope", body = ErrorBody)
    )
)]
pub async fn list_security_advisories(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (_scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;
    let rows = state
        .store()
        .security_advisories()
        .list()
        .await
        .map_err(ApiError::from)?;
    let body = serde_json::to_string(&AdvisoryListView {
        advisories: rows
            .iter()
            .map(|row| AdvisoryView {
                id: row.id.clone(),
                title: row.title.clone(),
                severity: row.severity.as_str().to_owned(),
                affected_versions: row.affected_versions.clone(),
                summary: row.summary.clone(),
                published_at: row.published_at,
            })
            .collect(),
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Import the signed advisory bundle (the offline path; the online poll uses the
/// SAME verification).
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/security/advisories/import",
    operation_id = "importSecurityAdvisories",
    tag = "security",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    request_body = AdvisoryImportRequest,
    responses(
        (status = 204, description = "The verified advisories replaced the accepted set"),
        (status = 400, description = "The bundle failed verification or does not parse", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or not in this scope", body = ErrorBody)
    )
)]
pub async fn import_security_advisories(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;
    require_live_environment(&state, &scope).await?;
    let request: AdvisoryImportRequest = parse_json(&body)?;

    let Some(verification_key) = state.advisory_verification_key() else {
        return Err(ApiError::BadRequest(
            "the advisory feed is disabled: [security].advisory_verification_key is unset"
                .to_owned(),
        ));
    };
    let verified =
        crate::advisory_feed::verify_feed(&request.feed, &verification_key).map_err(|error| {
            match error {
                crate::advisory_feed::FeedError::BadSignature => {
                    // A rejected feed is a SECURITY EVENT: an operator imported a bundle
                    // whose signature did not verify. The endpoint answers 400; the log
                    // carries the attempt.
                    tracing::error!(
                        actor = %actor,
                        "security-advisory feed REJECTED: the signature did not verify"
                    );
                    ApiError::BadRequest(
                        "the advisory bundle failed signature verification".to_owned(),
                    )
                }
                crate::advisory_feed::FeedError::Malformed => {
                    ApiError::BadRequest("the advisory bundle does not parse".to_owned())
                }
            }
        })?;
    let records: Vec<ironauth_store::advisory::AdvisoryRecord> = verified
        .advisories
        .iter()
        .map(|advisory| ironauth_store::advisory::AdvisoryRecord {
            id: advisory.id.clone(),
            title: advisory.title.clone(),
            severity: match advisory.severity {
                crate::advisory_feed::AdvisorySeverity::Critical => {
                    ironauth_store::advisory::AdvisorySeverity::Critical
                }
                crate::advisory_feed::AdvisorySeverity::High => {
                    ironauth_store::advisory::AdvisorySeverity::High
                }
                crate::advisory_feed::AdvisorySeverity::Medium => {
                    ironauth_store::advisory::AdvisorySeverity::Medium
                }
                crate::advisory_feed::AdvisorySeverity::Low => {
                    ironauth_store::advisory::AdvisorySeverity::Low
                }
            },
            affected_versions: advisory.affected_versions.clone(),
            summary: advisory.summary.clone(),
            published_at: advisory.published_at,
        })
        .collect();
    state
        .store()
        .security_advisories()
        .replace_all(&records, "offline-import")
        .await
        .map_err(ApiError::from)?;
    Ok(no_content())
}
