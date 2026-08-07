// SPDX-License-Identifier: MIT OR Apache-2.0

//! Queue depth for the environment's async work (issue #104).
//!
//! `OutboxRepo::depth` shipped with the outbox and its own documentation recorded that it
//! had no production caller: "this method has no production caller, so the sentence above
//! is the intent rather than the state". This is that caller.
//!
//! It matters because the outbox is where every async path in the product now lives:
//! webhook delivery and its replays, back-channel logout, trait migration batches, and
//! scheduled offboardings. Without this an operator can see individual outcomes (a
//! delivery's attempt history, a job's progress) but has no way to answer the first
//! question anyone asks, which is whether anything is backing up.
//!
//! ## Why an API read and not a metrics gauge
//!
//! #104 asks for depth "exposed as metrics", and the tree has a Prometheus surface, so the
//! obvious move is a gauge. It is not done here, deliberately.
//!
//! A gauge would have to be labelled by tenant, environment AND consumer to say anything
//! useful, and that is unbounded label cardinality: one series per scope per consumer,
//! growing with every tenant the platform ever signs. That is the classic way a metrics
//! backend is taken down by the system it monitors. Exporting a platform-wide total
//! instead is bounded but answers nobody's question, since a backlog in one tenant is
//! invisible against everyone else's throughput.
//!
//! Choosing between those is an operator decision about their own monitoring, so it is
//! left open rather than settled here. The scoped read below is bounded by construction:
//! it costs one query per request an operator actually makes, and it is the surface #106
//! asks for by name for dead-letter depth.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::org_context::resolve_scope;
use crate::response::json;
use crate::state::AdminState;

/// One consumer's queue depth.
#[derive(Debug, Serialize, ToSchema)]
pub struct QueueDepthView {
    /// The registered consumer name this queue belongs to.
    pub consumer: String,
    /// Messages DUE and not currently leased: the backlog a worker would claim right now.
    /// This is consumer lag.
    pub ready: i64,
    /// Messages currently held under an unexpired lease, so being worked on.
    pub in_flight: i64,
    /// Messages whose retry backoff has not elapsed yet.
    pub scheduled: i64,
    /// Messages given up on. The number to alert on: a dead letter is work that will never
    /// happen unless an operator replays it.
    pub dead_lettered: i64,
    /// Delivered and retired messages still awaiting retention.
    pub completed: i64,
}

/// Every consumer's queue depth in this environment.
#[derive(Debug, Serialize, ToSchema)]
pub struct QueueDepthList {
    /// One entry per consumer that has messages in this environment, by name.
    pub items: Vec<QueueDepthView>,
}

/// Report queue depth for every consumer in the environment.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/queues",
    operation_id = "listQueueDepths",
    tag = "diagnostics",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Queue depth per consumer, by consumer name", body = QueueDepthList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent", body = ErrorBody)
    )
)]
pub async fn list_queue_depths(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ, matching every other read across this surface. A
    // soft-deleted environment's queue depth is precisely what an operator wants to see
    // while deciding whether anything was still in flight when it went away.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let queue = state.store().scoped(scope);
    // The consumers that actually have rows here, rather than a hard-coded list of the
    // names this binary happens to register. A hand-written list would silently omit any
    // consumer added later, and would also hide a queue left behind by a consumer this
    // deployment no longer runs, which is exactly the backlog worth seeing.
    let consumers = queue.outbox().consumers_in_scope().await?;
    let lease = state.outbox_visibility_timeout();
    let mut items = Vec::with_capacity(consumers.len());
    for consumer in consumers {
        let depth = queue.outbox().depth(state.env(), &consumer, lease).await?;
        items.push(QueueDepthView {
            consumer,
            ready: depth.ready,
            in_flight: depth.in_flight,
            scheduled: depth.scheduled,
            dead_lettered: depth.dead_lettered,
            completed: depth.completed,
        });
    }
    let body_string =
        serde_json::to_string(&QueueDepthList { items }).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}
