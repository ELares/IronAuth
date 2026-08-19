// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-tenant usage export (issue #107).
//!
//! #107 wants metering "computed asynchronously off the stream ... with export via API",
//! and the asynchronously matters as much as the numbers: nothing here runs during a login.
//! The tally is folded from the event feed on request, so an operator asking for usage
//! costs a feed read and no work at all on the authentication path.
//!
//! # It exports numbers, it never prices them
//!
//! #107's own non-goals say metering "exports numbers, it never prices them", and the
//! response shape holds to that. There is no currency, no rate, no total. A billing system
//! reads these and decides what they are worth; putting a price here would put a commercial
//! decision inside the authentication server, where it could not be changed without a
//! release.

use axum::extract::{Path, State};
use axum::response::Response;
use ironauth_store::{ActorRef, CorrelationId, EventCursor, EventPage, Scope, UsageTally};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;

/// How many events one export folds at most.
///
/// A bound rather than a preference: an unbounded fold over a long-retained feed is a
/// request that gets slower every day until it times out, and it would do so first for the
/// busiest tenant, which is the one most likely to be asking.
const EXPORT_FOLD_LIMIT: i64 = 10_000;

/// A tenant's usage for the retained window.
#[derive(Debug, Serialize, ToSchema)]
pub struct UsageExport {
    /// Distinct users seen active. A user active forty times is one.
    pub monthly_active_users: u64,
    /// Tokens issued. NOT deduplicated by user: this counts issuance, not people.
    pub tokens_issued: u64,
    /// Connections opened.
    pub connections: u64,
    /// Whether the fold stopped at its limit rather than reaching the end of the feed.
    /// When true these numbers are a LOWER BOUND, and saying so is the point: a silently
    /// truncated usage figure is the one number a customer would never think to question.
    pub truncated: bool,
}

/// Fold the whole feed into a tally, stopping at `limit` events.
///
/// Split out from the handler and taking `limit` as a parameter so the TRUNCATION path is
/// reachable from a test. With the limit baked in as a constant, exercising it meant
/// seeding ten thousand events, so it went untested and a mutation that never set the flag
/// survived. A flag whose whole job is to admit the number is a lower bound is the last one
/// that should be unverified.
///
/// Returns the tally and whether it stopped early.
///
/// # Errors
///
/// [`ApiError::Internal`] if the feed reports an aged-out cursor, which cannot happen from
/// the beginning and therefore means the retention rule changed underneath the read.
pub async fn fold_usage(
    outbox: &ironauth_store::OutboxRepo<'_>,
    limit: i64,
) -> Result<(UsageTally, bool), ApiError> {
    let mut tally = UsageTally::new();
    let mut cursor = EventCursor::beginning();
    let mut folded = 0_i64;

    loop {
        let events = match outbox.events_page_after(cursor, 1000).await? {
            EventPage::Page(events) => events,
            // Reading from the beginning cannot age out: the beginning IS the oldest
            // retained position. If this fires, the retention rule changed underneath us,
            // and reporting zero usage would be worse than refusing.
            EventPage::Gone { .. } => return Err(ApiError::Internal),
        };
        if events.is_empty() {
            return Ok((tally, false));
        }
        cursor = events
            .last()
            .map_or(cursor, |m| EventCursor::after_sequence(m.sequence));
        folded += i64::try_from(events.len()).unwrap_or(i64::MAX);
        tally.absorb(&events);
        if folded >= limit {
            return Ok((tally, true));
        }
    }
}

/// Export a tenant's usage (issue #107).
///
/// # Errors
///
/// [`ApiError`] for an unresolvable scope, a caller without `management.read`, or a
/// persistence fault.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/usage",
    operation_id = "exportUsage",
    tag = "usage",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Usage for the retained window", body = UsageExport),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Unknown tenant or environment", body = ErrorBody)
    )
)]
pub async fn export_usage(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`. The export
    // folds the same feed, so it is the same authority over the same facts.
    principal.require_permission(ManagementPermission::Read)?;

    let (tally, truncated) =
        fold_usage(&state.store().scoped(scope).outbox(), EXPORT_FOLD_LIMIT).await?;

    let body = serde_json::to_string(&UsageExport {
        monthly_active_users: tally.monthly_active_users(),
        tokens_issued: tally.tokens_issued(),
        connections: tally.connections(),
        truncated,
    })
    .map_err(|_| ApiError::Internal)?;
    Ok(json(axum::http::StatusCode::OK, body))
}

/// Resolve the (tenant, environment) pair, fenced by the caller's OPERATOR.
async fn resolve_scope(
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
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)?;
    if !state
        .store()
        .management()
        .environments(state.bootstrap_operator_id(), tenant)
        .exists_in_any_state(&environment)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        return Err(ApiError::NotFound);
    }
    let actor = principal.require_environment(tenant, environment)?;
    Ok((Scope::new(tenant, environment), actor))
}

/// `POST /v1/tenants/{tenant_id}/environments/{environment_id}/usage/publish`
///
/// Fold the retained feed and PUBLISH the result as a `usage.reported` event, so metering
/// reaches a billing pipeline by webhook and not only by polling this API (issue #107
/// criterion 4).
///
/// # Why publishing is an explicit action
///
/// It could have been emitted as a side effect of [`export_usage`], and that would be wrong:
/// reporting would then be driven by whoever happens to poll, so a dashboard refresh would
/// bill a customer and a quiet week would bill nobody. A snapshot is something an operator or
/// a scheduler decides to take, so it gets its own verb.
///
/// # Authority
///
/// `management.write_config`, NOT the `management.read` the export needs. Publishing appends
/// to the event feed every webhook subscriber receives, which is a write to shared state even
/// though the numbers it carries are read-only. A caller who may only READ usage must not be
/// able to make every subscriber receive a billing record.
///
/// # Errors
///
/// [`ApiError`] for an unknown scope, a caller without `management.write`, or a store fault.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/usage/publish",
    operation_id = "publishUsage",
    tag = "usage",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The published snapshot", body = UsageExport),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Unknown tenant or environment", body = ErrorBody)
    )
)]
pub async fn publish_usage(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::WriteConfig)?;

    let (tally, truncated) =
        fold_usage(&state.store().scoped(scope).outbox(), EXPORT_FOLD_LIMIT).await?;
    let export = UsageExport {
        monthly_active_users: tally.monthly_active_users(),
        tokens_issued: tally.tokens_issued(),
        connections: tally.connections(),
        truncated,
    };

    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "usage.reported",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({
            "monthly_active_users": export.monthly_active_users,
            "tokens_issued": export.tokens_issued,
            "connections": export.connections,
            "truncated": export.truncated,
        }),
    )
    .ok_or(ApiError::Internal)?;

    state
        .store()
        .scoped(scope)
        .outbox()
        .append_event(
            state.env(),
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                // The EVENT id, so two publishes are two events while a retried enqueue of
                // the same one is a conflict rather than a duplicate invoice line.
                idempotency_key: &id,
                // Ordered per SCOPE: two snapshots of one environment must reach a billing
                // consumer in the order they were taken, or it books the older numbers last.
                ordering_key: &format!("{}/{}", scope.tenant(), scope.environment()),
                payload: envelope,
            },
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    let body = serde_json::to_string(&export).map_err(|_| ApiError::Internal)?;
    Ok(json(axum::http::StatusCode::OK, body))
}
