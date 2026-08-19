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
use axum::http::{HeaderMap, Uri};
use axum::response::Response;
use ironauth_store::{
    ActorRef, CorrelationId, EventCursor, EventPage, IdempotencyWrite, Scope, UsageTally,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::org_context::require_live_environment;
use crate::response::json;
use crate::state::AdminState;

/// The event type this endpoint publishes.
///
/// Named once and used by both the producer and the fold, because the fold has to
/// recognise its OWN output to keep from metering itself. Two spellings of the same string
/// would let one of them drift and turn the exclusion below silently off.
pub(crate) const USAGE_REPORTED: &str = "usage.reported";

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

/// How many rows one export may READ, however few of them it can meter.
///
/// The `limit` below bounds the METERABLE events a fold counts, and this bounds the total
/// work regardless. Without a second bound, excluding a type from the count (see
/// [`fold_usage`]) would turn "stop after 10,000" into "keep reading until 10,000
/// meterable ones turn up", which on a feed dominated by non-meterable events is not a
/// bound at all.
const EXPORT_SCAN_LIMIT: i64 = 100_000;

/// What a publish returns: the snapshot, and the id of the event it caused.
///
/// The id is not decoration. A caller that publishes and then watches its webhook endpoint
/// has two halves of one transaction and, without it, no way to match them except by
/// timestamp -- which is exactly the correlation that breaks when two publishes land in the
/// same second, and the case where getting it wrong means reconciling the wrong invoice.
#[derive(Debug, Serialize, ToSchema)]
pub struct UsagePublished {
    /// The id of the `usage.reported` event this request appended.
    pub event_id: String,
    /// The snapshot that was published, byte for byte what the event carries.
    #[serde(flatten)]
    pub usage: UsageExport,
}

/// Fold the whole feed into a tally, stopping at `limit` METERABLE events.
///
/// Split out from the handler and taking `limit` as a parameter so the TRUNCATION path is
/// reachable from a test. With the limit baked in as a constant, exercising it meant
/// seeding ten thousand events, so it went untested and a mutation that never set the flag
/// survived. A flag whose whole job is to admit the number is a lower bound is the last one
/// that should be unverified.
///
/// # Why `usage.reported` does not count against the limit
///
/// [`publish_usage`] appends its snapshot to the SAME per-scope feed this reads, because
/// that is the feed every webhook subscriber is fed from. `events_page_after` filters on
/// tenant, environment and sequence only, so those rows come back here too.
///
/// Counting them would close a loop with the wrong sign. Every publish would bring the
/// NEXT export one row closer to its limit, and passing the limit sets `truncated`, which
/// means the numbers are a LOWER BOUND. So publishing usage would, over time, make the
/// usage this endpoint reports smaller: an operator who reports diligently would
/// under-bill, and would under-bill precisely because they reported. [`UsageTally::absorb`]
/// already ignores the type, so the figures were never inflated; the BUDGET was the leak.
///
/// The rows are still READ, and still counted against [`EXPORT_SCAN_LIMIT`], because work
/// has to stay bounded whatever the feed contains. What they can no longer do is push a
/// tenant into truncation on their own.
///
/// Returns the tally and whether it stopped early. `truncated` is true for EITHER bound:
/// both mean the same thing to a reader, that these numbers are a floor.
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
    let mut metered = 0_i64;
    let mut scanned = 0_i64;

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
        let self_published = events
            .iter()
            .filter(|m| {
                m.payload.get("type").and_then(serde_json::Value::as_str) == Some(USAGE_REPORTED)
            })
            .count();
        scanned += i64::try_from(events.len()).unwrap_or(i64::MAX);
        metered += i64::try_from(events.len().saturating_sub(self_published)).unwrap_or(i64::MAX);
        tally.absorb(&events);
        if metered >= limit || scanned >= EXPORT_SCAN_LIMIT {
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
/// [`ApiError`] for an unknown scope, a soft-deleted environment, a caller without
/// `management.write_config`, a missing or reused `Idempotency-Key`, or a store fault.
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
        (status = 200, description = "The published snapshot", body = UsagePublished),
        (status = 400, description = "Missing Idempotency-Key", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "Unknown tenant or environment", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused for a different request", body = ErrorBody)
    )
)]
pub async fn publish_usage(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`, NOT the
    // `management.read` the export needs. An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    // A soft-deleted environment accepts no writes, and this is a write: it appends to the
    // feed every webhook subscriber is fed from. `resolve_scope` alone resolves a
    // soft-deleted environment on purpose, because the READ half of this file has to keep
    // working for a deleted environment during offboarding. The write half must not.
    require_live_environment(&state, &scope).await?;

    // This route carries no request body, so the fingerprint is over an empty one. That
    // still binds the key to the method and PATH, so one key reused against a DIFFERENT
    // environment is the 422 rather than a replay of another tenant's usage figures.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let (tally, truncated) =
        fold_usage(&state.store().scoped(scope).outbox(), EXPORT_FOLD_LIMIT).await?;
    let occurred_at_unix_ms = state.now_unix_micros() / 1000;
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let published = UsagePublished {
        // The caller learns WHICH event its request caused, so it can correlate the 200
        // with the delivery that shows up at its webhook endpoint. Without it a client
        // watching both sides has to guess by timestamp.
        event_id: id.clone(),
        usage: UsageExport {
            monthly_active_users: tally.monthly_active_users(),
            tokens_issued: tally.tokens_issued(),
            connections: tally.connections(),
            truncated,
        },
    };

    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        USAGE_REPORTED,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        occurred_at_unix_ms,
        &serde_json::json!({
            "monthly_active_users": published.usage.monthly_active_users,
            "tokens_issued": published.usage.tokens_issued,
            "connections": published.usage.connections,
            "truncated": published.usage.truncated,
        }),
    )
    .ok_or(ApiError::Internal)?;

    let body = serde_json::to_string(&published).map_err(|_| ApiError::Internal)?;

    let ordering_key = format!("{}/{}", scope.tenant(), scope.environment());
    let append = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .usage()
        .publish_snapshot(
            state.env(),
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                // The EVENT id. It is minted fresh per call, so it collides with nothing
                // and dedupes nothing: the outbox key is the queue's OWN uniqueness, and
                // the RETRY that actually happens is an HTTP one. The Idempotency-Key
                // above is what makes a retried POST replay instead of billing twice, and
                // it is written in this same transaction so the two cannot disagree.
                idempotency_key: &id,
                // Ordered per SCOPE: two snapshots of one environment must reach a billing
                // consumer in the order they were taken, or it books the older numbers last.
                ordering_key: &ordering_key,
                payload: envelope,
            },
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &body,
            }),
        )
        .await;

    match append {
        Ok(_) => Ok(json(axum::http::StatusCode::OK, body)),
        // Another request stored the same key first. Re-read and replay ITS response
        // rather than reporting a failure for a request that has effectively succeeded.
        Err(ironauth_store::StoreError::Conflict) => {
            idempotency::replay_after_conflict(&state, &credential_ref, &key, &fingerprint).await
        }
        Err(_) => Err(ApiError::Internal),
    }
}
