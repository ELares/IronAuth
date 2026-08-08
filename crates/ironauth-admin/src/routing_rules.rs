// SPDX-License-Identifier: MIT OR Apache-2.0

//! The management surface for enterprise inbound routing rules (issue #96).
//!
//! Migration 0059 shipped `routing_rules`, the store shipped create, list and the
//! verification write, and the data plane has routed on them since. NONE of it was
//! reachable over HTTP: the committed contract published zero paths containing
//! `routing-rules`, so an operator could not create a rule, could not see one, and could
//! not learn the DNS token to publish. That is the defect class this project keeps
//! producing, the same one #514 named.
//!
//! # The domain rule is the whole point, and it starts unusable on purpose
//!
//! A domain rule is created `pending` with a token the operator publishes as a DNS TXT
//! record. Until something verifies that record the rule routes NOTHING: `by_domain`
//! selects only `verified` rules. So creating a rule is deliberately not the same as
//! arming it, and the response says so by carrying the token and the state rather than
//! reporting a bare success.
//!
//! The verification step itself is NOT here. It needs a DNS resolver the workspace does
//! not have, and inventing an endpoint that flips the state without performing the lookup
//! would be strictly worse than the gap: it would look like proof of domain control while
//! proving nothing. What ships here is everything that does not require the resolver.
//!
//! # Why there is no delete
//!
//! The store has no delete for a routing rule, and this module does not invent one.
//! Adding one is a schema question (a rule is referenced by nothing, but withdrawing a
//! route silently changes where logins land) rather than a plumbing question, and an
//! endpoint whose store method does not exist is how a surface acquires a hole.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, NewRoutingRule, OrgConnectionId, RoutingRuleId, RoutingSelector, StoreError,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::resolve_scope;
use crate::response::json;
use crate::state::AdminState;

/// A routing rule to create.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoutingRuleRequest {
    /// The selector kind: `domain`, `app`, or `user`.
    pub kind: String,
    /// The selector value: an email domain, a client id, or a login identifier,
    /// according to `kind`. A `user` value is blind-indexed by the store and never
    /// stored in plaintext.
    pub value: String,
    /// The `ocn_` organization connection a matching login routes to.
    pub org_connection_id: String,
    /// Evaluation priority; lower is considered first.
    #[serde(default)]
    pub priority: i32,
    /// Whether the rule is enabled. A domain rule that is enabled still routes nothing
    /// until its domain is verified.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

const fn default_enabled() -> bool {
    true
}

/// A routing rule as returned to a caller.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoutingRuleView {
    /// The rule identifier (`rrl_...`).
    pub id: String,
    /// The selector kind (`domain`, `app`, or `user`).
    pub kind: String,
    /// The normalized email domain, present only for a `domain` rule.
    pub domain: Option<String>,
    /// The client id, present only for an `app` rule.
    pub client_id: Option<String>,
    /// The organization connection a matching login routes to.
    pub org_connection_id: String,
    /// Evaluation priority.
    pub priority: i32,
    /// Whether the rule is enabled.
    pub enabled: bool,
    /// The domain verification state (`pending`, `verified`, `failed`), present only for
    /// a `domain` rule. Routing consults only `verified`.
    pub domain_verification_state: Option<String>,
    /// The value to publish as a DNS TXT record on the domain, present only for a
    /// `domain` rule. Public by design: publishing it IS the proof of control.
    pub domain_verification_token: Option<String>,
    /// Creation time in milliseconds since the epoch.
    pub created_at_unix_ms: i64,
}

/// A page of routing rules.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoutingRuleListView {
    /// Every rule in this environment, by evaluation priority.
    pub items: Vec<RoutingRuleView>,
}

impl RoutingRuleView {
    fn from_record(record: ironauth_store::RoutingRuleRecord) -> Self {
        Self {
            id: record.id.to_string(),
            kind: record.rule_kind,
            domain: record.domain_norm,
            client_id: record.client_id,
            org_connection_id: record.org_connection_id,
            priority: record.priority,
            enabled: record.enabled,
            domain_verification_state: record.domain_verification_state,
            domain_verification_token: record.domain_verification_token,
            created_at_unix_ms: record.created_at_unix_micros / 1000,
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/routing-rules",
    operation_id = "listRoutingRules",
    tag = "connectors",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Every routing rule in this environment, by evaluation priority", body = RoutingRuleListView),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is not a live row of this scope", body = ErrorBody)
    )
)]
pub async fn list_routing_rules(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;

    let records = state
        .store()
        .scoped(scope)
        .routing_rules()
        .list_all()
        .await
        .map_err(|_| ApiError::Internal)?;
    let view = RoutingRuleListView {
        items: records
            .into_iter()
            .map(RoutingRuleView::from_record)
            .collect(),
    };
    let body = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/routing-rules",
    operation_id = "createRoutingRule",
    tag = "connectors",
    request_body = CreateRoutingRuleRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "Created. A DOMAIN rule is created pending and routes nothing until its token is published in DNS and verified", body = RoutingRuleView),
        (status = 400, description = "Malformed request, or an unknown selector kind", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment or the organization connection is not a live row of this scope", body = ErrorBody),
        (status = 409, description = "That domain or client is already routed in this environment", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_routing_rule(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // Routing decides where a login is sent, which is environment configuration rather
    // than organization membership.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    // A WRITE requires a LIVE environment. `resolve_scope` proves the pair is
    // ADDRESSABLE (issue #185), which deliberately admits a soft-deleted environment so
    // reads keep working there; a write must not inherit that. Without this the create
    // answered 201 into a decommissioned environment, which `live_surface` caught.
    crate::org_context::require_live_environment(&state, &scope).await?;
    crate::sudo::require_fresh_privilege(&state, scope, actor).await?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let request: CreateRoutingRuleRequest = parse_json(&body)?;
    let connection = OrgConnectionId::parse_in_scope(&request.org_connection_id, &scope)
        .map_err(|_| ApiError::NotFound)?;
    // The selector kind is a CLOSED set. An unknown kind is the caller's error and is
    // named, rather than silently defaulting to one of the three, because defaulting
    // would route logins somewhere the caller did not ask for.
    let selector = match request.kind.as_str() {
        "domain" => RoutingSelector::Domain(&request.value),
        "app" => RoutingSelector::App(&request.value),
        "user" => RoutingSelector::User(&request.value),
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown routing selector kind {other:?}; expected domain, app, or user"
            )));
        }
    };

    let created_at_micros = state.now_unix_micros();
    let id = RoutingRuleId::generate(state.env(), &scope);
    let result = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .routing_rules()
        .create(
            state.env(),
            &id,
            created_at_micros,
            NewRoutingRule {
                selector,
                org_connection_id: &connection,
                priority: request.priority,
                enabled: request.enabled,
            },
        )
        .await;
    match result {
        Ok(()) => {}
        Err(StoreError::Conflict) => {
            return Err(ApiError::Conflict(
                "that domain or client is already routed in this environment".to_owned(),
            ));
        }
        Err(StoreError::NotFound) => return Err(ApiError::NotFound),
        Err(_) => return Err(ApiError::Internal),
    }

    // Read the row back rather than composing the response from the request. The store
    // decides the verification state and mints the token, and a hand-built body would be
    // the place those two drift apart: it would report a token the row does not carry.
    let records = state
        .store()
        .scoped(scope)
        .routing_rules()
        .list_all()
        .await
        .map_err(|_| ApiError::Internal)?;
    let created = records
        .into_iter()
        .find(|record| record.id == id)
        .ok_or(ApiError::Internal)?;
    let body_string = serde_json::to_string(&RoutingRuleView::from_record(created))
        .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::CREATED, body_string))
}
