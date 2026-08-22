// SPDX-License-Identifier: MIT OR Apache-2.0

//! Registering HTTP flow targets (issue #112).
//!
//! An operator registers an endpoint IronAuth calls out to at a point in a flow. Until this
//! surface existed the table granted INSERT to `ironauth_control` only and nothing mounted a
//! route, so the dispatcher was reachable by nothing an operator could do: a control that
//! ships its enforcement and not its granting path is a control nobody can turn on.
//!
//! ## What a listing must never return
//!
//! The signing secret, in any form. `flow_targets` holds the NAME of an environment secret
//! and never its bytes, and this view carries that name unresolved, so there is no path from
//! this endpoint to a secret value.
//!
//! ## What the CONFIG must never be
//!
//! Code. Issue #112 names Ory's base64-embedded Jsonnet as the ergonomic failure this design
//! exists to avoid, so `config` is plain JSON, stored and returned verbatim, and nothing here
//! ever evaluates it.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_store::flow_target::{FailurePolicy, Invocation, TargetClass, Timing};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::parse_json;
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// One registered target, as an operator reads it.
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowTargetView {
    /// The `ftg_` identifier.
    pub id: String,
    /// The operator-facing name, unique among live targets in the environment.
    pub name: String,
    /// Which class of flow point invokes it: `request`, `response`, `function`, or `event`.
    pub target_class: String,
    /// Whether the flow waits: `sync` or `async`.
    pub invocation: String,
    /// When it runs relative to the write: `pre_persist` or `post_persist`.
    pub timing: String,
    /// Where it POSTs.
    pub endpoint: String,
    /// The bound on a sync call, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i32>,
    /// What to do when a sync target does not answer: `fail_open` or `fail_closed`.
    pub failure_policy: String,
    /// Plain JSON, returned verbatim. Never code.
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    /// The NAME of the environment secret this target's payloads are signed with, never its
    /// value, and [`None`] when the target is deliberately unsigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_secret_name: Option<String>,
    /// Whether the dispatcher will call it. A DISABLED target is listed, not hidden: one
    /// missing from the listing would read as deregistered.
    pub enabled: bool,
}

/// Register or reconfigure a target.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetFlowTargetRequest {
    /// The operator-facing name, unique among live targets in the environment.
    pub name: String,
    /// `request`, `response`, `function`, or `event`.
    pub target_class: String,
    /// `sync` or `async`.
    pub invocation: String,
    /// `pre_persist` or `post_persist`.
    pub timing: String,
    /// Where it POSTs. Reached through the outbound policy, so a private or link-local
    /// address is refused at call time.
    pub endpoint: String,
    /// The bound on a sync call, in milliseconds. Required for a sync target and refused
    /// above the ceiling.
    ///
    /// Refused ENTIRELY on an async target: an async delivery is bounded by
    /// `flow_targets.delivery_timeout_secs` and nothing reads a per-target value, so accepting
    /// one here would store a setting that never applies.
    #[serde(default)]
    pub timeout_ms: Option<i32>,
    /// `fail_open` or `fail_closed`.
    pub failure_policy: String,
    /// Plain JSON. Never code.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub config: Option<serde_json::Value>,
    /// The NAME of an environment secret, never a secret value.
    #[serde(default)]
    pub signing_secret_name: Option<String>,
    /// Whether the dispatcher calls it. Defaults to true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// The identifier a registration returns.
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowTargetCreated {
    /// The `ftg_` identifier.
    pub id: String,
}

/// Every registered target in the environment.
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowTargetList {
    /// The targets, by name.
    pub targets: Vec<FlowTargetView>,
}

fn view(listing: ironauth_store::flow_target::FlowTargetListing) -> FlowTargetView {
    let record = listing.record;
    FlowTargetView {
        id: record.id.to_string(),
        name: record.name,
        target_class: class_wire(record.target_class).to_owned(),
        invocation: match record.invocation {
            Invocation::Sync => "sync",
            Invocation::Async => "async",
        }
        .to_owned(),
        timing: match record.timing {
            Timing::PrePersist => "pre_persist",
            Timing::PostPersist => "post_persist",
        }
        .to_owned(),
        endpoint: record.endpoint,
        timeout_ms: record.timeout_ms,
        failure_policy: match record.failure_policy {
            FailurePolicy::FailOpen => "fail_open",
            FailurePolicy::FailClosed => "fail_closed",
        }
        .to_owned(),
        config: record.config,
        signing_secret_name: record.signing_secret_name,
        enabled: listing.enabled,
    }
}

fn class_wire(class: TargetClass) -> &'static str {
    match class {
        TargetClass::Request => "request",
        TargetClass::Response => "response",
        TargetClass::Function => "function",
        TargetClass::Event => "event",
    }
}

/// Parse the four closed vocabularies HERE rather than leaving them to the table's CHECK
/// constraints, so an unknown value is a 400 naming what was wrong instead of a 500 from a
/// constraint violation.
fn parse_enums(
    request: &SetFlowTargetRequest,
) -> Result<(TargetClass, Invocation, Timing, FailurePolicy), ApiError> {
    let class = match request.target_class.as_str() {
        "request" => TargetClass::Request,
        "response" => TargetClass::Response,
        "function" => TargetClass::Function,
        "event" => TargetClass::Event,
        _ => {
            return Err(ApiError::BadRequest(
                "target_class must be request, response, function, or event".to_owned(),
            ));
        }
    };
    let invocation = match request.invocation.as_str() {
        "sync" => Invocation::Sync,
        "async" => Invocation::Async,
        _ => {
            return Err(ApiError::BadRequest(
                "invocation must be sync or async".to_owned(),
            ));
        }
    };
    let timing = match request.timing.as_str() {
        "pre_persist" => Timing::PrePersist,
        "post_persist" => Timing::PostPersist,
        _ => {
            return Err(ApiError::BadRequest(
                "timing must be pre_persist or post_persist".to_owned(),
            ));
        }
    };
    let policy = match request.failure_policy.as_str() {
        "fail_open" => FailurePolicy::FailOpen,
        "fail_closed" => FailurePolicy::FailClosed,
        _ => {
            return Err(ApiError::BadRequest(
                "failure_policy must be fail_open or fail_closed".to_owned(),
            ));
        }
    };
    Ok((class, invocation, timing, policy))
}

/// Refuse a registration the dispatcher could not honour as written.
///
/// The ceiling is enforced HERE, at the only place a target can be registered, because a
/// per-request timeout only ever SHORTENS the fetcher's bound: a target accepted above the
/// ceiling would be silently truncated to it and the operator's stated bound would be quietly
/// false. Refusing at registration is the difference between a bound and a suggestion.
fn validate(
    request: &SetFlowTargetRequest,
    invocation: Invocation,
    timing: Timing,
) -> Result<(), ApiError> {
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".to_owned()));
    }
    // The migration refuses an ASYNC target that is not post-persist, and refuses any
    // non-positive timeout. Both were reachable from the wire and surfaced as a 500 from a
    // constraint violation, which is the outcome parsing at the boundary exists to prevent.
    if matches!(invocation, Invocation::Async) && !matches!(timing, Timing::PostPersist) {
        return Err(ApiError::BadRequest(
            "an async target must be post_persist: the flow does not wait for it, so it \
             cannot observe anything before the write"
                .to_owned(),
        ));
    }
    if let Some(timeout) = request.timeout_ms {
        if timeout <= 0 {
            return Err(ApiError::BadRequest(
                "timeout_ms must be greater than zero".to_owned(),
            ));
        }
    }
    // An ASYNC target must not carry a per-call timeout. The delivery consumer bounds every
    // POST with `flow_targets.delivery_timeout_secs` and never reads `timeout_ms`, so a value
    // set here would round-trip through this API, appear in the listing, and do nothing --
    // the accepted-and-ignored shape the enqueue guard refuses one layer down, on the
    // grounds that it is indistinguishable from working.
    //
    // The migration's CHECK only REQUIRES a timeout on sync; it does not forbid one on async.
    // So this rule lives here, at the boundary, rather than being assumed from the schema.
    if matches!(invocation, Invocation::Async) && request.timeout_ms.is_some() {
        return Err(ApiError::BadRequest(
            "an async target must not set timeout_ms: an async delivery is bounded by \
             flow_targets.delivery_timeout_secs, so a per-target value would be accepted \
             here and never applied"
                .to_owned(),
        ));
    }
    if matches!(invocation, Invocation::Sync) {
        let Some(timeout) = request.timeout_ms else {
            return Err(ApiError::BadRequest(
                "a sync target requires timeout_ms: a target with no bound to exceed cannot \
                 trigger its failure policy"
                    .to_owned(),
            ));
        };
        // Positivity is already refused above, for every invocation. Only the ceiling is
        // sync-specific, because only a sync target sits on a live signup.
        if timeout > ironauth_oidc::flow::FLOW_TARGET_MAX_SYNC_TIMEOUT_MS {
            return Err(ApiError::BadRequest(format!(
                "timeout_ms must not exceed {}: a sync target sits on a live signup, and a \
                 larger bound would be silently shortened to this one rather than honoured",
                ironauth_oidc::flow::FLOW_TARGET_MAX_SYNC_TIMEOUT_MS
            )));
        }
    }
    // A secret must be NAMED, never inlined. Refusing here keeps the one rule this table
    // rests on at the boundary: it never holds a secret value.
    if let Some(config) = &request.config {
        if let Some(key) = secret_shaped_key(config) {
            return Err(ApiError::BadRequest(format!(
                "config must not carry a secret (found `{key}`); name an environment secret \
                 with signing_secret_name"
            )));
        }
    }
    Ok(())
}

/// The first secret-shaped key anywhere in `config`, or [`None`].
///
/// Recursive, and over a VOCABULARY rather than two names. The first version checked
/// `secret` and `signing_secret` at the top level only, which stored `{"auth":{"secret":..}}`,
/// `[{"secret":..}]`, `api_key`, `token`, and every case variant. That guard was theatre: it
/// refused the spelling an honest operator would use by accident and passed every other one.
///
/// This cannot be airtight, and is not meant to be: `config` is opaque operator JSON and a
/// determined caller can always name a field something else. It exists so that a secret
/// pasted in by mistake is caught at the boundary, because `config` travels further than the
/// table -- it is returned by the listing at `management.read` and sent to the target in
/// every dispatch payload.
fn secret_shaped_key(value: &serde_json::Value) -> Option<String> {
    const SHAPES: &[&str] = &[
        "secret",
        "signing_secret",
        "credential",
        "password",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
        "authorization",
    ];
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                let folded = key.to_ascii_lowercase().replace('-', "_");
                if SHAPES.contains(&folded.as_str()) {
                    return Some(key.clone());
                }
                if let Some(found) = secret_shaped_key(nested) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(items) => items.iter().find_map(secret_shaped_key),
        _ => None,
    }
}

fn flow_target_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &str,
    name: &str,
    set: Option<(TargetClass, Invocation, Timing)>,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    // The ENDPOINT deliberately does not travel, matching the catalog's own note: it is
    // operator-configured infrastructure detail, often an internal address, and a webhook is
    // a wider audience than the management surface that returns it.
    let (event_type, payload) = match set {
        Some((class, invocation, timing)) => (
            "flow_target.set",
            serde_json::json!({
                "flow_target_id": id,
                "name": name,
                "target_class": class_wire(class),
                "invocation": match invocation {
                    Invocation::Sync => "sync",
                    Invocation::Async => "async",
                },
                "timing": match timing {
                    Timing::PrePersist => "pre_persist",
                    Timing::PostPersist => "post_persist",
                },
            }),
        ),
        None => (
            "flow_target.deleted",
            serde_json::json!({ "flow_target_id": id, "name": name }),
        ),
    };
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject: id.to_owned(),
        envelope,
    })
}

/// List every registered HTTP flow target in the environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/flow-targets",
    operation_id = "listFlowTargets",
    tag = "flow-targets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The registered targets", body = FlowTargetList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody)
    )
)]
pub async fn list_flow_targets(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    // No liveness fence on a READ: a soft-deleted environment stays readable across this
    // surface and only writes refuse it. The two siblings this route was modelled on say so
    // in as many words, and the live-surface sweep requires every GET to answer the live
    // control's status.

    let targets = state
        .store()
        .scoped(scope)
        .flow_targets()
        .list()
        .await?
        .into_iter()
        .map(view)
        .collect();
    let body =
        serde_json::to_string(&FlowTargetList { targets }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Register an HTTP flow target.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/flow-targets",
    operation_id = "createFlowTarget",
    tag = "flow-targets",
    request_body = SetFlowTargetRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The registered target", body = FlowTargetCreated),
        (status = 400, description = "Malformed request, an unknown vocabulary value, a sync target without a bound, or a bound above the ceiling", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_flow_target(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: SetFlowTargetRequest = parse_json(&body)?;
    let (class, invocation, timing, policy) = parse_enums(&request)?;
    validate(&request, invocation, timing)?;

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // NO pre-read. An earlier revision resolved the id by name first, and that introduced a
    // 500: deletes are SOFT, so a tombstone keeps its primary key, while the name uniqueness
    // the upsert arbitrates on is a PARTIAL index excluding tombstones. A delete committing
    // between the read and the write meant `ON CONFLICT` did not fire, the INSERT branch ran
    // with the tombstone's id, and Postgres raised a primary-key violation. A freshly minted
    // candidate cannot collide with anything.
    //
    // Nothing needs the id up front. The response, the audit target, the stored replay and
    // now the event are all rendered from what `RETURNING id` gave back.
    let candidate = ironauth_store::FlowTargetId::generate(state.env(), &scope);
    let config = request
        .config
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let live_id = state
        .store()
        .scoped(scope)
        .acting(
            principal.actor(),
            ironauth_store::CorrelationId::generate(state.env()),
        )
        .flow_targets()
        .set_with_event(
            state.env(),
            &candidate,
            state.now_unix_micros(),
            ironauth_store::NewFlowTarget {
                name: &request.name,
                target_class: class,
                invocation,
                timing,
                endpoint: &request.endpoint,
                timeout_ms: request.timeout_ms,
                failure_policy: policy,
                config: &config,
                signing_secret_name: request.signing_secret_name.as_deref(),
                enabled: request.enabled,
            },
            Some(ironauth_store::ResolvedIdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                // Rendered from what the write RESOLVED, inside its own transaction, so the
                // stored response and the row it names commit together. A body built up front
                // would be stored for every replay of this key forever after, so it has to
                // describe what was persisted rather than what was requested.
                response_body: &|resolved: &ironauth_store::FlowTargetId| {
                    serde_json::to_string(&FlowTargetCreated {
                        id: resolved.to_string(),
                    })
                },
            }),
            // Built from the LIVE id too. The event announces which integration is now
            // registered, so a subject naming a row that does not exist is worse than no
            // event: a consumer would act on it.
            Some(&|resolved: &ironauth_store::FlowTargetId| {
                flow_target_event(
                    &state,
                    scope,
                    &resolved.to_string(),
                    &request.name,
                    Some((class, invocation, timing)),
                )
                .map(|pending| ironauth_store::OwnedDomainEvent {
                    id: pending.id,
                    subject: pending.subject,
                    envelope: pending.envelope,
                })
            }),
        )
        .await?;

    let body_string = serde_json::to_string(&FlowTargetCreated {
        id: live_id.to_string(),
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::CREATED, body_string))
}

/// Deregister an HTTP flow target.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/flow-targets/{target_id}",
    operation_id = "deleteFlowTarget",
    tag = "flow-targets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("target_id" = String, Path, description = "The flow target identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "Deregistered"),

        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "No such target, or the environment is absent or deleted", body = ErrorBody)
    )
)]
pub async fn delete_flow_target(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, target_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let id = ironauth_store::FlowTargetId::parse_in_scope(&target_id, &scope)
        .map_err(|_| ApiError::NotFound)?;

    // The name rides the event, and it can only be read BEFORE the delete. A consumer that
    // received `flow_target.deleted` without one would have to hold its own mapping from id
    // to name to know which integration stopped.
    let name = state
        .store()
        .scoped(scope)
        .flow_targets()
        .list()
        .await?
        .into_iter()
        .find(|listing| listing.record.id == id)
        .map(|listing| listing.record.name);

    // No Idempotency-Key: the write is keyed by id and carries no payload, so a replay is
    // the same act. Deregistering an ABSENT target is a 404 rather than a no-op success,
    // because the store guards on rows affected; the sibling comment this was adapted from
    // belongs to a delete that has no such guard.
    let pending = name
        .as_ref()
        .and_then(|name| flow_target_event(&state, scope, &target_id, name, None));
    state
        .store()
        .scoped(scope)
        .acting(
            principal.actor(),
            ironauth_store::CorrelationId::generate(state.env()),
        )
        .flow_targets()
        .delete_with_event(
            state.env(),
            &id,
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(no_content())
}

/// One dead-lettered async delivery, with what an operator needs to decide whether replaying
/// it is worth anything.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeadLetteredFlowDelivery {
    /// The queue message id.
    pub id: String,
    /// The `webhook-id` this delivery carried, and will carry again if replayed. Stable
    /// across every attempt and across a replay, which is what lets a receiver deduplicate.
    pub webhook_id: String,
    /// How many attempts were made before it was given up on.
    pub attempts: i32,
    /// The last failure reason, a bounded non-secret token.
    ///
    /// Load-bearing for this listing rather than decoration. Some of these dead letters
    /// cannot be fixed by replaying: a malformed payload or an unparseable target id will
    /// fail the same way on every attempt. Others are exactly what replay is for: a receiver
    /// that was down, a target that was switched off, a signing secret that was missing. This
    /// field is what separates them before an operator acts.
    pub last_error: Option<String>,
    /// When it was enqueued, milliseconds since the Unix epoch. This is the value a
    /// replay-since bound is compared against.
    pub enqueued_at_unix_ms: i64,
    /// When it was given up on, milliseconds since the Unix epoch.
    pub dead_lettered_at_unix_ms: Option<i64>,
}

/// A target's dead-lettered deliveries, oldest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowDeadLetterList {
    /// The deliveries, in the order a replay would redeliver them.
    pub items: Vec<DeadLetteredFlowDelivery>,
    /// Whether the cap was reached, so there may be more than are shown.
    ///
    /// The cap is applied in SQL, so without this an exactly-full page is indistinguishable
    /// from a truncated one, and an operator reading a full page would have no way to know
    /// their backlog is larger than their screen. The webhook listing omits this; the
    /// log-stream listing added it, and this follows the later one.
    pub truncated: bool,
}

/// Replay a target's dead-lettered deliveries.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplayFlowDeadLettersRequest {
    /// Replay only deliveries enqueued at or after this instant, milliseconds since the Unix
    /// epoch. Omitted means every dead letter this target has.
    #[serde(default)]
    pub since_unix_ms: Option<i64>,
}

/// The acknowledgement that a replay was QUEUED.
///
/// Deliberately not a count. The management plane enqueues a command and the data plane
/// executes it, so no number this response could carry would still be true when a caller read
/// it. What the caller can rely on is durability: the request is a queue row committed in the
/// same transaction as its audit row.
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowReplayAccepted {
    /// The bound the replay was requested with, echoed back. `null` means every dead letter.
    pub since_unix_ms: Option<i64>,
}

/// How many dead letters one listing returns at most.
const FLOW_DEAD_LETTER_LIMIT: i64 = 200;

/// List a target's dead-lettered async deliveries.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/flow-targets/{target_id}/dead-letters",
    operation_id = "listFlowTargetDeadLetters",
    tag = "flow-targets",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("target_id" = String, Path, description = "The target identifier (ftg_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The dead-lettered deliveries, oldest first", body = FlowDeadLetterList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, or the target is in another scope", body = ErrorBody)
    )
)]
pub async fn list_flow_target_dead_letters(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, target_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ, matching the target listing: a soft-deleted environment
    // stays readable across this surface and only writes refuse it.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    principal.require_permission(ManagementPermission::Read)?;
    let id = ironauth_store::FlowTargetId::parse_in_scope(&target_id, &scope)
        .map_err(|_| ApiError::NotFound)?;

    // The DELIVERY consumer's dead letters, narrowed by ordering key -- which IS the target
    // id, so the generic queue read expresses a per-target view without the queue knowing
    // anything about flow targets. The REPLAY consumer's own queue holds commands, not
    // deliveries; reading that one here would always return an empty list.
    // The target must EXIST, for the reason the replay route checks and the log-stream
    // listing checks: an operator who mistypes one character of an id would otherwise read an
    // empty backlog and conclude the queue is clean, unable to tell that from a target with
    // nothing outstanding. An earlier revision of this handler answered 200 with an empty list
    // for any parseable in-scope id, which also made the two routes disagree -- the replay
    // 404s a deregistered target while the listing happily showed its dead letters.
    if !state
        .store()
        .scoped(scope)
        .flow_targets()
        .exists(&id)
        .await?
    {
        return Err(ApiError::NotFound);
    }
    // ONE MORE than the cap is fetched, so a full page can be told from a truncated one.
    // Comparing `len() >= cap` against a SQL `LIMIT cap` reports truncation for a backlog of
    // exactly cap, which is the same confusion the flag exists to remove, one off.
    let mut messages = state
        .store()
        .scoped(scope)
        .outbox()
        .dead_lettered(
            ironauth_store::FLOW_TARGET_DELIVERY_CONSUMER,
            Some(&id.to_string()),
            FLOW_DEAD_LETTER_LIMIT + 1,
        )
        .await?;
    let truncated = i64::try_from(messages.len()).unwrap_or(i64::MAX) > FLOW_DEAD_LETTER_LIMIT;
    messages.truncate(usize::try_from(FLOW_DEAD_LETTER_LIMIT).unwrap_or(usize::MAX));
    let view = FlowDeadLetterList {
        items: messages
            .into_iter()
            .map(|message| DeadLetteredFlowDelivery {
                id: message.id,
                webhook_id: message.idempotency_key,
                attempts: message.attempts,
                last_error: message.last_error,
                enqueued_at_unix_ms: message.enqueued_at_unix_micros / 1000,
                dead_lettered_at_unix_ms: message
                    .dead_lettered_at_unix_micros
                    .map(|micros| micros / 1000),
            })
            .collect(),
        truncated,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Mint the `flow_target.replay_requested` event a replay announces.
///
/// Its OWN builder rather than a third arm on [`flow_target_event`], which takes a `name` and
/// puts it in both of its payloads. This route addresses a target by id and never reads its
/// name; adding an arm would mean either a second database read whose only purpose is to
/// satisfy a schema, or passing an empty string -- which the catalog's `minLength: 1` rejects,
/// loudly under the `testing` feature and SILENTLY in a release build, where the fan-out drops
/// the event as failing catalog validation and nothing is ever announced.
fn flow_target_replay_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    id: &str,
    since_unix_ms: Option<i64>,
) -> Option<crate::events::PendingEvent> {
    let event_id = format!(
        "evt_{}",
        ironauth_store::CorrelationId::generate(state.env())
    );
    let envelope = ironauth_store::event_catalog::envelope(
        &event_id,
        "flow_target.replay_requested",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "flow_target_id": id, "since_unix_ms": since_unix_ms }),
    )?;
    Some(crate::events::PendingEvent {
        id: event_id,
        subject: id.to_owned(),
        envelope,
    })
}

/// Replay a target's dead-lettered async deliveries.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/flow-targets/{target_id}/replay",
    operation_id = "replayFlowTargetDeadLetters",
    tag = "flow-targets",
    request_body = ReplayFlowDeadLettersRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("target_id" = String, Path, description = "The target identifier (ftg_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying the same key returns the original response.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 202, description = "The replay was queued. The data plane executes it; watch the queue depth for `flow_target.replay` to see it drain.", body = FlowReplayAccepted),
        (status = 400, description = "Malformed request, or an unknown field", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope, or sudo required", body = ErrorBody),
        (status = 404, description = "The environment is absent, or the target is deregistered or in another scope", body = ErrorBody),
        (status = 409, description = "The Idempotency-Key was reused with a different request", body = ErrorBody),
        (status = 422, description = "Missing Idempotency-Key", body = ErrorBody)
    )
)]
pub async fn replay_flow_target_dead_letters(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, target_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;
    let id = ironauth_store::FlowTargetId::parse_in_scope(&target_id, &scope)
        .map_err(|_| ApiError::NotFound)?;

    // An empty body is the "replay everything" form, so it is accepted rather than rejected as
    // malformed: a caller that sends nothing means the same as one that sends `{}`.
    let request: ReplayFlowDeadLettersRequest = if body.is_empty() {
        ReplayFlowDeadLettersRequest {
            since_unix_ms: None,
        }
    } else {
        parse_json(&body)?
    };

    // The key is fingerprinted over the BODY as well as the path, so replaying "everything"
    // and replaying "since noon" are different requests under one key rather than one
    // replaying as the other. This is also why `since` is a body field and not a query
    // parameter: `fingerprint` takes `uri.path()`, which EXCLUDES the query, so a query-bound
    // bound would make the two indistinguishable and the second request would return the
    // first's stored 202 without ever enqueueing.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Knowable BEFORE the write, because a replay request is a COMMAND rather than the revive
    // itself: what this call produces is "accepted", not a count.
    let view = FlowReplayAccepted {
        since_unix_ms: request.since_unix_ms,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let pending = flow_target_replay_event(&state, scope, &id.to_string(), request.since_unix_ms);
    state
        .store()
        .scoped(scope)
        .acting(actor, ironauth_store::CorrelationId::generate(state.env()))
        .flow_targets()
        .request_dead_letter_replay_with_event(
            state.env(),
            &id,
            // MILLISECONDS in, MICROSECONDS on the wire and in the queue. The multiply is the
            // whole conversion and getting it wrong is silent in both directions: dropping it
            // makes the bound a thousand times too early and revives everything, while
            // applying it to a value that was already micros makes it a thousand times too
            // late and revives nothing. Both answer 202.
            request.since_unix_ms.map(|ms| ms.saturating_mul(1000)),
            Some(ironauth_store::IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 202,
                response_body: &body_string,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(json(StatusCode::ACCEPTED, body_string))
}
