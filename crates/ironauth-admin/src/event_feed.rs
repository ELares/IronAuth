// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ordered, cursor-paginated event feed (issue #107).
//!
//! This is the READ surface over the log `ironauth-store` orders. It is not the webhook
//! fan-out in `events.rs`: that pushes one delivery per event to an endpoint the customer
//! operates, and this lets a customer pull the whole ordered log at their own pace. #107
//! recommends this one for data synchronisation, and `docs/EVENTS-VS-WEBHOOKS.md` says why.
//!
//! # An aged-out cursor is `410 Gone`, not an empty page
//!
//! The status code is the contract here. A consumer whose cursor has been pruned past must
//! not receive `200` with an empty list, because it will read that as "nothing new", store
//! the same cursor, and never learn that events it had not seen were deleted underneath it.
//! `410` is what HTTP already means by "this existed and does not any more", and the body
//! carries the oldest cursor that still resolves, so a consumer reconciles from a known
//! point rather than guessing or starting over.

use axum::extract::{Path, Query, State};
use axum::response::Response;
use ironauth_store::{ActorRef, EventCursor, EventPage, Scope};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::response::json;
use crate::state::AdminState;

/// How many events a page may carry when the caller does not say.
const DEFAULT_EVENT_PAGE: i64 = 100;

/// The most a caller may ask for in one page.
const MAX_EVENT_PAGE: i64 = 1000;

/// The feed query.
#[derive(Debug, Deserialize, IntoParams)]
pub struct FeedQuery {
    /// The opaque cursor from a previous page. Omitted means "from the beginning of what
    /// is retained".
    #[param(example = "evc_42")]
    pub cursor: Option<String>,
    /// How many events to return, capped at 1000.
    pub limit: Option<i64>,
}

/// One event on the feed.
#[derive(Debug, Serialize, ToSchema)]
pub struct FeedEvent {
    /// The event id.
    pub id: String,
    /// The cursor to send back to resume AFTER this event. Opaque: store it, do not parse
    /// it or do arithmetic on it.
    pub cursor: String,
    /// The event body.
    #[schema(value_type = Object)]
    pub payload: serde_json::Value,
}

/// A page of the feed.
#[derive(Debug, Serialize, ToSchema)]
pub struct EventFeedPage {
    /// The events, in order.
    pub events: Vec<FeedEvent>,
    /// The cursor to resume from. Present even when `events` is empty, so a caller always
    /// has somewhere to continue.
    pub next_cursor: String,
}

/// What a caller gets when its cursor has aged out of the retention window.
#[derive(Debug, Serialize, ToSchema)]
pub struct FeedGone {
    /// The stable machine-readable code. Branch on this, never on `message`.
    pub code: String,
    /// What happened, for a human reading a log.
    pub message: String,
    /// The oldest cursor that still resolves. Resume here after reconciling, and treat
    /// everything between your old cursor and this one as unknown rather than unchanged.
    pub oldest_cursor: String,
}

/// Resolve the (tenant, environment) pair, fenced by the caller's OPERATOR.
///
/// The operator fence is not optional here even though the feed is read-only. `tenants`
/// and `environments` sit above row-level security, so without it a caller naming another
/// operator's tenant reaches that tenant's environments, and this endpoint would hand back
/// their event log.
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

/// Read the ordered event feed (issue #107).
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/events",
    operation_id = "readEventFeed",
    tag = "events",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        FeedQuery
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "A page of events in order", body = EventFeedPage),
        (status = 400, description = "Malformed cursor or limit", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 410, description = "The cursor aged out of the retention window", body = FeedGone)
    )
)]
pub async fn read_event_feed(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<FeedQuery>,
) -> Result<Response, ApiError> {
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    principal.require_permission(ManagementPermission::Read)?;

    // A malformed cursor is refused, never silently read as "from the beginning". Starting
    // over would replay the whole retained feed at a caller that sent a typo.
    let cursor = match query.cursor.as_deref() {
        None => EventCursor::beginning(),
        Some(wire) => EventCursor::from_wire(wire).ok_or_else(|| {
            ApiError::BadRequest("the cursor is not a cursor this feed issued".to_owned())
        })?,
    };

    let limit = match query.limit {
        None => DEFAULT_EVENT_PAGE,
        Some(asked) if (1..=MAX_EVENT_PAGE).contains(&asked) => asked,
        Some(_) => {
            return Err(ApiError::BadRequest(
                "limit must be between 1 and 1000".to_owned(),
            ));
        }
    };

    match state
        .store()
        .scoped(scope)
        .outbox()
        .events_page_after(cursor, limit)
        .await?
    {
        EventPage::Page(messages) => {
            // The next cursor is the LAST event on this page, or the caller's own cursor
            // when the page is empty. Returning the beginning on an empty page would send a
            // caller back to the start of the feed every time it caught up.
            let next = messages
                .last()
                .map_or(cursor, |m| EventCursor::after_sequence(m.sequence));
            let events = messages
                .into_iter()
                .map(|m| FeedEvent {
                    id: m.id,
                    cursor: EventCursor::after_sequence(m.sequence).to_wire(),
                    payload: m.payload,
                })
                .collect();
            let body = serde_json::to_string(&EventFeedPage {
                events,
                next_cursor: next.to_wire(),
            })
            .map_err(|_| ApiError::Internal)?;
            Ok(json(axum::http::StatusCode::OK, body))
        }
        EventPage::Gone { oldest_retained } => {
            let body = serde_json::to_string(&FeedGone {
                code: "cursor_expired".to_owned(),
                message: "the cursor is older than the retention window; events you had \
                          not read have been deleted"
                    .to_owned(),
                // The cursor that resumes JUST BEFORE the oldest surviving event, so a
                // reconciling consumer receives that event rather than skipping it.
                oldest_cursor: EventCursor::after_sequence(oldest_retained - 1).to_wire(),
            })
            .map_err(|_| ApiError::Internal)?;
            Ok(json(axum::http::StatusCode::GONE, body))
        }
    }
}
