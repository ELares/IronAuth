// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `AuthZEN` Authorization API 1.0 policy decision point (issue #100).
//!
//! Answers runtime authorization checks from `IronAuth`'s OWN organizations, groups, roles and
//! permissions, over the same resolution the token claims are built from. That sameness is a
//! criterion rather than an implementation detail: a claim check and a `PDP` check must never
//! disagree for the same state, so both go through `effective_permissions` and neither has its
//! own copy of the closure walk.
//!
//! # What this deliberately is not
//!
//! Not a `Zanzibar` engine. Relationship-based authorization is a product, and the issue names
//! the evidence: `OpenFGA` spent a year fixing correctness in a rewrite of its own check
//! algorithm, and Ory Keto never shipped consistency tokens. `IronAuth` answers what it already
//! indexes and offers seams to an external FGA for what it does not.
//!
//! # Mapping a resource and an action onto a permission slug
//!
//! `AuthZEN` names a `resource.type` and an `action.name`; `IronAuth` grants permission SLUGS. The
//! mapping is `"{resource.type}.{action.name}"`, so type `billing.invoice` with action `read`
//! asks about `billing.invoice.read`.
//!
//! # Why a DELETED environment stops deciding
//!
//! Every other read on this surface stays served for a soft-deleted environment, because an
//! operator auditing a decommissioned environment needs to see what was in it. An evaluation is
//! not that kind of read. It returns a DECISION a `PEP` acts on, so an environment that kept
//! answering would keep admitting traffic after an operator deleted it, and deleting an
//! environment would revoke nothing at the point where it matters.
//!
//! So the two evaluation endpoints fence a soft-deleted environment and the discovery document,
//! which returns no decision, does not. The fence runs BEFORE the body is parsed: a deleted
//! environment that answered 400 to a malformed body and not-found to a well formed one would
//! be refusing only the requests that were already correct, and would still be telling a prober
//! which shape of request it recognises.
//!
//! It is a pure string join with no normalisation, and that is the point. Lowercasing or
//! trimming here would make the `PDP` answer for a slug the grant path would never have written,
//! and a permission that is granted under one spelling and checked under another is the exact
//! disagreement this endpoint exists to be free of.
//!
//! # Where the organization comes from
//!
//! Permissions are organization scoped and `AuthZEN` 1.0 has no field for that, so it is read
//! from `context.organization_id`. A request without one is refused rather than answered
//! against some default: guessing an organization is the one error whose result looks exactly
//! like a correct allow.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use ironauth_store::{OrganizationId, ServiceAccountId, UserId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::input::parse_json;
use crate::org_context::{
    EnvironmentAccess, require_live_environment, resolve_live_org, resolve_scope,
};
use crate::response::json;
use crate::state::AdminState;

/// The `AuthZEN` subject: who is asking.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthzenSubject {
    /// `user` or `service_account`. Any other type is refused rather than treated as a user.
    #[serde(rename = "type")]
    pub subject_type: String,
    /// The `usr_` or `sva_` identifier, matching the declared type.
    pub id: String,
}

/// The `AuthZEN` resource: what is being reached.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthzenResource {
    /// The resource type, the first half of the permission slug.
    #[serde(rename = "type")]
    pub resource_type: String,
    /// The instance identifier. Accepted because `AuthZEN` 1.0 defines it and a `PEP` will
    /// send it, and NOT consulted: `IronAuth` grants permissions per organization, not per
    /// instance, so a decision that varied by instance would be answering a question this
    /// model cannot decide.
    ///
    /// The allow is the honest spelling of that. Reading the field into a discard to quiet the
    /// lint would read like the value participates in something.
    #[allow(dead_code)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// The `AuthZEN` action: what is being done.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthzenAction {
    /// The action name, the second half of the permission slug.
    pub name: String,
}

/// One evaluation request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthzenEvaluationRequest {
    /// Who is asking.
    pub subject: AuthzenSubject,
    /// What they are reaching.
    pub resource: AuthzenResource,
    /// What they are doing.
    pub action: AuthzenAction,
    /// Free-form context. `IronAuth` reads exactly one key, `organization_id`.
    #[serde(default)]
    pub context: serde_json::Value,
}

/// One evaluation decision.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthzenDecision {
    /// Whether the subject holds the mapped permission in the named organization.
    pub decision: bool,
}

/// A batch of evaluations.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthzenEvaluationsRequest {
    /// Defaults shared by every entry, so a caller need not repeat the subject.
    #[serde(default)]
    pub subject: Option<AuthzenSubject>,
    /// Shared resource default.
    #[serde(default)]
    pub resource: Option<AuthzenResource>,
    /// Shared action default.
    #[serde(default)]
    pub action: Option<AuthzenAction>,
    /// Shared context default.
    #[serde(default)]
    pub context: serde_json::Value,
    /// The evaluations, each overriding the defaults above where it names a value.
    pub evaluations: Vec<AuthzenBatchItem>,
    /// Evaluation options.
    #[serde(default)]
    pub options: AuthzenOptions,
}

/// One entry in a batch, with every field optional so it can inherit a default.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthzenBatchItem {
    /// Overrides the shared subject.
    #[serde(default)]
    pub subject: Option<AuthzenSubject>,
    /// Overrides the shared resource.
    #[serde(default)]
    pub resource: Option<AuthzenResource>,
    /// Overrides the shared action.
    #[serde(default)]
    pub action: Option<AuthzenAction>,
    /// Overrides the shared context.
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// Batch evaluation options.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct AuthzenOptions {
    /// Stop at the first `false` and return the decisions so far.
    ///
    /// The remaining entries are ABSENT rather than reported as denied. A caller that received
    /// `false` for an evaluation nothing performed could not tell a real deny from an early
    /// exit, and would cache the wrong answer.
    #[serde(default)]
    pub deny_on_first_deny: bool,
}

/// A batch of decisions.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthzenDecisions {
    /// One decision per evaluation performed, in request order. Shorter than the request when
    /// `deny_on_first_deny` stopped it early.
    pub evaluations: Vec<AuthzenDecision>,
}

/// The `PDP` discovery document.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthzenConfiguration {
    /// The `PDP` root these endpoints hang off.
    pub policy_decision_point: String,
    /// The single Access Evaluation endpoint.
    pub access_evaluation_endpoint: String,
    /// The batch Access Evaluations endpoint.
    pub access_evaluations_endpoint: String,
    /// Search APIs are deferred (issue #100), so the document says so rather than omitting
    /// them: a `PEP` that discovers no key cannot tell "not supported" from "older document".
    pub subject_search_endpoint: Option<String>,
    /// Deferred, as above.
    pub resource_search_endpoint: Option<String>,
    /// Deferred, as above.
    pub action_search_endpoint: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/.well-known/authzen-configuration",
    operation_id = "getAuthzenConfiguration",
    tag = "authzen",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The PDP metadata for this environment", body = AuthzenConfiguration),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such scope", body = ErrorBody)
    )
)]
pub async fn get_authzen_configuration(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (_scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): READ. The document names endpoints and nothing
    // about who holds what, but it is still a map of this environment's authorization surface
    // and the issue is explicit that unauthenticated evaluation is never served.
    principal.require_permission(ManagementPermission::Read)?;

    // Scoped rather than at the host root, which RFC 8615 would suggest. A root document
    // cannot name a tenant or an environment, and IronAuth has no single PDP: it has one per
    // scope, answering from that scope's organizations. A PEP is configured per environment
    // anyway, so it discovers the one it was pointed at.
    let base = format!("/v1/tenants/{tenant_id}/environments/{environment_id}");
    let document = AuthzenConfiguration {
        policy_decision_point: base.clone(),
        access_evaluation_endpoint: format!("{base}/access/v1/evaluation"),
        access_evaluations_endpoint: format!("{base}/access/v1/evaluations"),
        subject_search_endpoint: None,
        resource_search_endpoint: None,
        action_search_endpoint: None,
    };
    let body = serde_json::to_string(&document).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/access/v1/evaluation",
    operation_id = "authzenEvaluation",
    tag = "authzen",
    request_body = AuthzenEvaluationRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The decision", body = AuthzenDecision),
        (status = 400, description = "Malformed request, an unknown subject type, or no context.organization_id", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is soft-deleted, or the organization is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn authzen_evaluation(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): READ. An evaluation reveals whether a principal
    // holds a permission, which is the same class of fact the role listings expose.
    principal.require_permission(ManagementPermission::Read)?;
    // Before the body, deliberately. See the module note: a deleted environment must stop
    // deciding, and it must stop for a malformed request too.
    require_live_environment(&state, &scope).await?;
    let request: AuthzenEvaluationRequest = parse_json(&body)?;

    let organization = organization_from_context(&request.context)?;
    let org_id = resolve_live_org(
        &state,
        &principal,
        scope,
        &organization,
        // READ, and that is not a slip. The environment fence is UPSTREAM and explicit, so
        // this argument speaks only about the ORGANIZATION, which is what the call resolves.
        // Saying `Write` here would name a fence that already ran, and an argument whose
        // value cannot change any answer is worse than a truthful one: the next reader would
        // believe it is what holds the deleted environment out.
        EnvironmentAccess::Read,
    )
    .await?;
    let decision = decide(
        &state,
        scope,
        &org_id,
        &request.subject,
        &request.resource,
        &request.action,
    )
    .await?;
    let body =
        serde_json::to_string(&AuthzenDecision { decision }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/access/v1/evaluations",
    operation_id = "authzenEvaluations",
    tag = "authzen",
    request_body = AuthzenEvaluationsRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The decisions, in request order, shorter than the request when deny_on_first_deny stopped it", body = AuthzenDecisions),
        (status = 400, description = "Malformed request, an entry missing a required field after defaults, an unknown subject type, or no organization", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is soft-deleted, or the organization is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn authzen_evaluations(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): READ, matching the single evaluation. A batch is
    // the same question asked repeatedly, and a batch endpoint that demanded less than its
    // singular form would be the way around it.
    principal.require_permission(ManagementPermission::Read)?;
    // As above, and for the same reason: before the body.
    require_live_environment(&state, &scope).await?;
    let request: AuthzenEvaluationsRequest = parse_json(&body)?;

    // The bound BEFORE the loop and before the allocation. Refused rather than truncated:
    // a short decision list is indistinguishable from `deny_on_first_deny` stopping early,
    // so a truncating endpoint would tell a PEP that entries were denied when they were
    // never sent to it. See `admin.max_authzen_batch`.
    let limit = state.max_authzen_batch() as usize;
    if request.evaluations.len() > limit {
        return Err(bad(
            "batch_too_large",
            &format!(
                "this deployment evaluates at most {limit} evaluations per request; split \
                 the batch"
            ),
        ));
    }
    let mut decisions = Vec::with_capacity(request.evaluations.len());
    for item in &request.evaluations {
        let subject = item
            .subject
            .as_ref()
            .or(request.subject.as_ref())
            .ok_or_else(|| bad("subject_required", "every evaluation needs a subject"))?;
        let resource = item
            .resource
            .as_ref()
            .or(request.resource.as_ref())
            .ok_or_else(|| bad("resource_required", "every evaluation needs a resource"))?;
        let action = item
            .action
            .as_ref()
            .or(request.action.as_ref())
            .ok_or_else(|| bad("action_required", "every evaluation needs an action"))?;
        let context = item.context.as_ref().unwrap_or(&request.context);
        let organization = organization_from_context(context)?;
        // Resolved per entry rather than once: a batch may span organizations, and hoisting
        // this would silently answer every entry against the first one's.
        let org_id = resolve_live_org(
            &state,
            &principal,
            scope,
            &organization,
            // READ, as in the singular endpoint and for the reason stated there.
            EnvironmentAccess::Read,
        )
        .await?;
        let decision = decide(&state, scope, &org_id, subject, resource, action).await?;
        decisions.push(AuthzenDecision { decision });
        if request.options.deny_on_first_deny && !decision {
            break;
        }
    }

    let body = serde_json::to_string(&AuthzenDecisions {
        evaluations: decisions,
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// The one decision, shared by both endpoints so they cannot answer differently.
async fn decide(
    state: &AdminState,
    scope: ironauth_store::Scope,
    org_id: &OrganizationId,
    subject: &AuthzenSubject,
    resource: &AuthzenResource,
    action: &AuthzenAction,
) -> Result<bool, ApiError> {
    // The slug is a pure join. See the module note: normalising here would answer for a slug
    // the grant path would never write.
    let slug = format!("{}.{}", resource.resource_type, action.name);
    let groups = state.store().management().org_groups(scope);
    let depth = state.max_group_depth();

    // The SAME resolution the token claims use. Not a reimplementation: a second closure walk
    // is a second set of answers, and the criterion is that a claim check and a PDP check
    // never disagree for the same state.
    let held = match subject.subject_type.as_str() {
        "user" => {
            let id = UserId::parse_in_scope(&subject.id, &scope).map_err(|_| {
                bad(
                    "subject_unknown",
                    "the subject id is not a user of this scope",
                )
            })?;
            groups
                .effective_permissions(org_id, &id, depth)
                .await
                .map_err(|_| ApiError::Internal)?
        }
        "service_account" => {
            let id = ServiceAccountId::parse_in_scope(&subject.id, &scope).map_err(|_| {
                bad(
                    "subject_unknown",
                    "the subject id is not a service account of this scope",
                )
            })?;
            groups
                .effective_permissions_for_service_account(org_id, &id, depth)
                .await
                .map_err(|_| ApiError::Internal)?
        }
        // Refused, not defaulted. Treating an unrecognised type as a user would answer a
        // question about somebody else, and a PDP that guesses is worse than one that says no.
        _ => {
            return Err(bad(
                "subject_type_unsupported",
                "subject.type must be `user` or `service_account`",
            ));
        }
    };
    Ok(held.contains(&slug))
}

/// The organization the evaluation is scoped to, from `context.organization_id`.
///
/// Absent is an error rather than a default. Permissions are organization scoped, so an
/// evaluation with no organization has no answer, and inventing one produces a decision
/// indistinguishable from a correct allow.
fn organization_from_context(context: &serde_json::Value) -> Result<String, ApiError> {
    context
        .get("organization_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(std::borrow::ToOwned::to_owned)
        .ok_or_else(|| {
            bad(
                "organization_required",
                "permissions are organization scoped; set context.organization_id",
            )
        })
}

/// A 400 naming the rule, so a `PEP` author is told which field is wrong.
fn bad(code: &str, message: &str) -> ApiError {
    ApiError::BadRequest(format!("{code}: {message}"))
}
