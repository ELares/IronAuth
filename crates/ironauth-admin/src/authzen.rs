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
use ironauth_store::{AgentPrincipalId, OrganizationId, ServiceAccountId, UserId};
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

/// The resource type an agent tool check asks about (issue #133).
///
/// ONE spelling, referenced both by the arm that requires it and by the slug the linked user's
/// permission is looked up under, so "the resource type this profile answers for" and "the
/// first segment of the permission it checks" cannot drift apart. The first version claimed
/// that and then built the slug from `resource.resource_type`, which is the caller's string:
/// equal to the constant only because the arm above had just refused everything else.
const AGENT_TOOL_RESOURCE_TYPE: &str = "tool";

/// The `AuthZEN` subject: who is asking.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthzenSubject {
    /// `user` or `service_account`. Any other type is refused rather than treated as a user.
    ///
    /// A deployment that has acknowledged the `authzen-agent-profile` prototype (issue #133)
    /// also decides `agent`, which asks whether an agent may call a named tool. It is
    /// deliberately absent from this sentence's list because the CONTRACT does not offer it:
    /// it is off in every deployment that has not opted in, and a published description naming
    /// a type most servers refuse would be worse than one that stops where support is
    /// universal. See `docs/experimental/authzen-agent-profile.md`.
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
    /// The instance identifier. Not consulted for a `user` or `service_account` subject:
    /// `IronAuth` grants permissions per organization, not per instance, so a decision that
    /// varied by instance would be answering a question this model cannot decide.
    ///
    /// CONSULTED for the agent tool profile (issue #133), where it names the TOOL. That is not
    /// an exception smuggled in: `tool/deploy` and `tool/destroy` are two resources rather than
    /// one resource with two ids, and a profile that ignored the id could only ever answer
    /// "may this agent call SOME tool". The sentence above stays true of the two subject types
    /// it describes, and this one says where it stops.
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
    #[schema(value_type = Object)]
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
    #[schema(value_type = Object)]
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
    #[schema(value_type = Option<Object>)]
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
        // THE AGENT TOOL PROFILE (issue #133, PROTOTYPE). Behind the experimental flag, so a
        // deployment that has not acknowledged the draft sees the same refusal it saw before
        // this existed rather than a new subject type appearing in its PDP.
        "agent" if state.agent_tool_profile_enabled() => {
            return decide_agent_tool(state, scope, org_id, subject, resource, action).await;
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

/// May THIS AGENT call THIS TOOL (issue #133, the `AuthZEN` MCP tool-authorization profile).
///
/// # Why this is not the ordinary permission lookup with a different id
///
/// An agent is not a principal that holds permissions. It is a principal that acts FOR a
/// person, with a narrower set of tools than that person could reach, and both halves have to
/// hold for a call to be allowed:
///
/// - the AGENT must declare the tool. An agent's `tool_scopes` is the operator's statement of
///   what this machine may do, and a tool outside it is refused however privileged its human
///   is.
/// - the LINKED USER must hold the mapped permission. An agent cannot exceed the person it
///   acts for, so the human's effective permissions in this organization are the ceiling, and
///   they are resolved through the SAME `effective_permissions` the token claims and the other
///   two subject types use. A second copy of that walk would be a second set of answers.
///
/// The decision is the INTERSECTION. Either half alone is a different and wrong question:
/// checking only the declared set lets a revoked human's agent keep working, and checking only
/// the human lets an agent call every tool its person could.
///
/// # Where the tool name comes from
///
/// `resource.id`, with `resource.type` required to be `tool`. That is the one place on this
/// surface where `resource.id` is consulted, and the field's own documentation says it is
/// deliberately not -- so this profile says so explicitly rather than quietly making the
/// sentence next door false. It is read here because the tool IS the instance: `tool/deploy`
/// and `tool/destroy` are two resources, not one resource with two ids, and a profile that
/// ignored the id could only ever answer "may this agent call SOME tool".
///
/// # Errors
///
/// [`ApiError::BadRequest`] for a malformed subject id, a resource type that is not `tool`, or
/// a missing tool name; [`ApiError::Internal`] on a store failure.
async fn decide_agent_tool(
    state: &AdminState,
    scope: ironauth_store::Scope,
    org_id: &OrganizationId,
    subject: &AuthzenSubject,
    resource: &AuthzenResource,
    action: &AuthzenAction,
) -> Result<bool, ApiError> {
    if resource.resource_type != AGENT_TOOL_RESOURCE_TYPE {
        return Err(bad(
            "resource_type_unsupported",
            "an agent subject asks about resource.type `tool`",
        ));
    }
    let tool = resource
        .id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            bad(
                "resource_id_required",
                "resource.id names the tool, and an agent check without one has no answer",
            )
        })?;

    let id = AgentPrincipalId::parse_in_scope(&subject.id, &scope).map_err(|_| {
        bad(
            "subject_unknown",
            "the subject id is not an agent of this scope",
        )
    })?;
    let agent = match state.store().scoped(scope).agents().get(&id).await {
        Ok(agent) => agent,
        // An agent that does not exist is a DENY, not an error. A PDP that distinguished
        // "no such agent" from "not allowed" would answer a question about existence to a
        // caller that is only entitled to a decision.
        Err(ironauth_store::StoreError::NotFound) => return Ok(false),
        Err(_) => return Err(ApiError::Internal),
    };

    // Confined to the organization the evaluation named, exactly as every other read on this
    // surface is. Without it a PEP in organization A could ask about organization B's agent and
    // get an answer computed from B's grants.
    if &agent.organization_id != org_id {
        return Ok(false);
    }
    // Suspended and revoked agents are DENIED while staying listable and auditable, which is
    // the same split #130 criterion 5 draws at the token door.
    //
    // Through the RECORD's own predicates, not inline literals. `can_obtain_tokens`'s doc says
    // "a caller that had to remember which states were live would eventually forget one", and
    // an inline `state != "active"` here was exactly that caller; `declares_tool` carries the
    // exact-membership rule (never a prefix, or `files` would grant `files.delete`).
    if !agent.can_obtain_tokens() || !agent.declares_tool(tool) {
        return Ok(false);
    }

    // THE PERSON must be able to authenticate. Found by review: the effective-permission
    // closure filters `users.deleted_at IS NULL` and an ACTIVE membership, and reads
    // `users.state` nowhere -- so an operator who BLOCKED or DISABLED someone left that
    // person's agent fully authorized here, and "an agent cannot outlive the revocation of the
    // person it acts for" was true only of deletion and of membership removal.
    //
    // `can_authenticate` rather than `== Active`, because it is the same predicate the login
    // path fences on, and a second spelling of "which states are live" is the drift the
    // paragraph above is about. It admits scheduled-offboarding, which is correct: that person
    // can still sign in, so their agent may still act until the worker offboards them.
    let human = match state
        .store()
        .scoped(scope)
        .users()
        .get(&agent.linked_user_id)
        .await
    {
        Ok(record) => record,
        // Deleted between the agent read and this one, or never there. A deny, for the same
        // reason an absent agent is: a PDP answers decisions, not questions about existence.
        Err(ironauth_store::StoreError::NotFound) => return Ok(false),
        Err(_) => return Err(ApiError::Internal),
    };
    if !human.state.can_authenticate() {
        return Ok(false);
    }

    // The CEILING: what the person this agent acts for can do WITH THIS TOOL.
    //
    // PER TOOL, and the first version was not: it joined `{resource.type}.{action.name}`, the
    // same mapping the other two subject types use, which for a profile that requires
    // `resource.type == "tool"` is the constant `tool.{action}` for every tool there is. So the
    // human's half could not distinguish `deploy` from `destroy`, only `tool_scopes` could, and
    // the "declared but not permitted" case this profile exists to deny was not expressible.
    // The intersection was an intersection with a constant.
    //
    // The tool is the resource INSTANCE, so it belongs in the slug: `tool.deploy.call` is a
    // different permission from `tool.destroy.call`, which is what lets an operator grant a
    // person one and not the other. That is a longer slug than the other subject types produce
    // and deliberately so -- they ask about a resource TYPE, this asks about an instance.
    let slug = format!("{}.{tool}.{}", AGENT_TOOL_RESOURCE_TYPE, action.name);
    let held = state
        .store()
        .management()
        .org_groups(scope)
        .effective_permissions(org_id, &agent.linked_user_id, state.max_group_depth())
        .await
        .map_err(|_| ApiError::Internal)?;
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
