// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standard Webhooks endpoint registration under an environment (issue #105).
//!
//! The management surface over the endpoints the deliverer will POST to. The signing
//! contract itself is `ironauth_jose::webhooks` (shipped in #554); this is where the
//! secret that contract signs with is minted, sealed and listed.
//!
//! ## Reveal once, and only once
//!
//! Creation returns the `whsec_` secret in the response and NEVER again. The stored form
//! is sealed under the scope's DEK, not hashed, because the deliverer has to recover it
//! to compute an HMAC over every delivery; but no read path returns it, and the listing
//! query does not even select the column. That is the `mak_` management-key lesson from
//! #11 applied to a secret that cannot be hashed.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use ironauth_jose::webhooks::WebhookSecret;
use ironauth_store::{
    CorrelationId, IdempotencyWrite, NewWebhookEndpoint, ResolvedIdempotencyWrite,
    WebhookEndpointId,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{ManagementPermission, Principal};
use crate::error::{ApiError, ErrorBody};
use crate::idempotency;
use crate::input::{parse_json, require_non_empty, require_plausible_since_unix_ms};
use crate::org_context::{require_live_environment, resolve_scope};
use crate::response::{json, no_content};
use crate::state::AdminState;

/// How many bytes of entropy a generated signing secret carries.
///
/// Thirty two, matching the HMAC-SHA256 block the `v1` scheme signs with: a shorter
/// secret would weaken the MAC and a longer one buys nothing against it.
const SECRET_BYTES: usize = 32;

/// A registered endpoint, without its secret.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointView {
    /// The `whe_` identifier.
    pub id: String,
    /// The HTTPS destination deliveries POST to.
    pub url: String,
    /// The operator's label for this endpoint.
    pub description: String,
    /// Whether deliveries are dispatched.
    pub active: bool,
    /// When the SYSTEM disabled this endpoint after sustained failure, milliseconds since
    /// the Unix epoch. `null` on a live endpoint and on one an operator paused by hand, so
    /// an operator can tell which happened.
    pub auto_disabled_at_unix_ms: Option<i64>,
    /// Why the system disabled it: a bounded internal label, never anything derived from a
    /// receiver's response.
    pub disabled_reason: Option<String>,
    /// The event types this endpoint receives, or `null` for every type.
    pub event_types: Option<Vec<String>>,
    /// Creation time, milliseconds since the Unix epoch.
    pub created_at_unix_ms: i64,
}

/// Every registered endpoint in the environment.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointList {
    /// The endpoints, oldest first.
    pub items: Vec<WebhookEndpointView>,
}

/// The creation response, which carries the signing secret exactly once.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointCreated {
    /// The registered endpoint.
    #[serde(flatten)]
    pub endpoint: WebhookEndpointView,
    /// The Standard Webhooks signing secret, in `whsec_` form. Shown ONCE: it is sealed
    /// at rest and no read path returns it again.
    pub secret: String,
}

/// Register a delivery endpoint.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWebhookEndpointRequest {
    /// The HTTPS destination deliveries POST to.
    pub url: String,
    /// An optional human label.
    #[serde(default)]
    pub description: Option<String>,
}

/// List the environment's registered webhook endpoints.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints",
    operation_id = "listWebhookEndpoints",
    tag = "webhooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The environment's webhook endpoints", body = WebhookEndpointList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent", body = ErrorBody)
    )
)]
pub async fn list_webhook_endpoints(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ: a soft-deleted environment stays readable across this
    // surface and only writes refuse it, which the whole-surface sweep enforces.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let endpoints = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .list()
        .await?;
    let view = WebhookEndpointList {
        items: endpoints.into_iter().map(into_view).collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Register a delivery endpoint and mint its signing secret.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints",
    operation_id = "createWebhookEndpoint",
    tag = "webhooks",
    request_body = CreateWebhookEndpointRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 201, description = "The endpoint, with its signing secret shown once", body = WebhookEndpointCreated),
        (status = 400, description = "Malformed request, or a url that is not https", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn create_webhook_endpoint(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;

    let request: CreateWebhookEndpointRequest = parse_json(&body)?;
    let url = require_non_empty(&request.url, "url")?;
    // HTTPS only, refused HERE rather than by a CHECK constraint: the same judgement has
    // to reject a loopback or otherwise internal destination, and that belongs to the
    // SSRF-hardened fetcher the deliverer rides, not to the schema.
    if !url.starts_with("https://") {
        return Err(ApiError::BadRequest(
            "url must be an https:// destination".to_owned(),
        ));
    }
    let description = request.description.unwrap_or_default();

    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let id = WebhookEndpointId::generate(state.env(), &scope);
    let mut secret_bytes = vec![0_u8; SECRET_BYTES];
    state.env().entropy().fill_bytes(&mut secret_bytes);
    let secret = WebhookSecret::from_bytes(secret_bytes.clone());
    let created_at_micros = state.now_unix_micros();

    // Knowable BEFORE the write: the id is minted here and every other field either
    // echoes the request or is fixed at creation, so this carries the plain idempotency
    // form and the SAME bytes are stored and returned. A retry therefore replays the
    // secret rather than minting a second endpoint, which is the whole reason a
    // reveal-once response must be idempotent.
    let view = WebhookEndpointCreated {
        endpoint: WebhookEndpointView {
            id: id.to_string(),
            url: url.clone(),
            description: description.clone(),
            active: true,
            auto_disabled_at_unix_ms: None,
            disabled_reason: None,
            // A newly registered endpoint subscribes to everything, which is the only
            // default that cannot silently drop events an operator expected.
            event_types: None,
            created_at_unix_ms: created_at_micros / 1000,
        },
        secret: secret.to_transport_string(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let pending = webhook_endpoint_created_event(&state, scope, &id, &url);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .webhook_endpoints()
        .create_with_event(
            state.env(),
            NewWebhookEndpoint {
                id: &id,
                url: &url,
                description: &description,
                secret: &secret_bytes,
                created_at_micros,
            },
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 201,
                response_body: &body_string,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(json(StatusCode::CREATED, body_string))
}

/// The rotation response, which carries the incoming secret exactly once.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookSecretRotated {
    /// The endpoint whose secret rotated.
    pub id: String,
    /// The NEW signing secret, in `whsec_` form. Shown once, like the original.
    pub secret: String,
    /// When the outgoing secret stops being accepted, milliseconds since the Unix epoch.
    /// Until then a delivery carries a signature under both, so a consumer holding either
    /// verifies.
    pub previous_expires_at_unix_ms: i64,
}

/// How long the outgoing secret keeps verifying after a rotation.
///
/// Twenty four hours: long enough for a consumer to pick up the new secret through an
/// ordinary deploy cycle, short enough that a rotation prompted by a suspected leak
/// actually shortens exposure. A fixed window rather than a setting for now, and the
/// EXPIRY is stored on the row rather than derived, so making it configurable later
/// cannot retroactively strand a rotation already in flight.
const ROTATION_OVERLAP_SECS: i64 = 24 * 60 * 60;

/// Rotate an endpoint's signing secret, opening the overlap window.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/rotate-secret",
    operation_id = "rotateWebhookEndpointSecret",
    tag = "webhooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The new signing secret, shown once, and when the old one stops verifying", body = WebhookSecretRotated),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the endpoint is in another scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn rotate_webhook_endpoint_secret(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;
    let id = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .parse_id(&endpoint_id)?;

    // This route carries no request body, so the fingerprint is over an empty one. That
    // still binds the key to the method and PATH, so the same key reused against a
    // DIFFERENT endpoint is the 422 rather than a replay of another endpoint's secret,
    // which would be the worst possible thing to replay.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    let mut secret_bytes = vec![0_u8; SECRET_BYTES];
    state.env().entropy().fill_bytes(&mut secret_bytes);
    let secret = WebhookSecret::from_bytes(secret_bytes.clone());
    let previous_expires_at_micros = state
        .now_unix_micros()
        .saturating_add(ROTATION_OVERLAP_SECS.saturating_mul(1_000_000));

    let view = WebhookSecretRotated {
        id: id.to_string(),
        secret: secret.to_transport_string(),
        previous_expires_at_unix_ms: previous_expires_at_micros / 1000,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;

    let pending =
        webhook_endpoint_simple_event(&state, scope, &id, "webhook_endpoint.secret_rotated");
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .webhook_endpoints()
        .rotate_secret_with_event(
            state.env(),
            &id,
            &secret_bytes,
            previous_expires_at_micros,
            Some(IdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &body_string,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    Ok(json(StatusCode::OK, body_string))
}

/// Remove a delivery endpoint.
#[utoipa::path(
    delete,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}",
    operation_id = "deleteWebhookEndpoint",
    tag = "webhooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 204, description = "The endpoint is gone. Removing an absent one is a no-op success"),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the endpoint is in another scope", body = ErrorBody)
    )
)]
pub async fn delete_webhook_endpoint(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;
    // Parsed under the CALLER's scope, so an endpoint id from another environment is the
    // uniform not-found before any mutating repository is reached.
    let id = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .parse_id(&endpoint_id)?;

    // No Idempotency-Key: DELETE is the idempotent removal here as everywhere else, and
    // removing an absent endpoint is a no-op success.
    let pending = webhook_endpoint_deleted_event(&state, scope, &id);
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .webhook_endpoints()
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

/// One dead-lettered delivery, with the attempt history an operator debugs from.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeadLetteredDelivery {
    /// The queue message id.
    pub id: String,
    /// The `webhook-id` this delivery carried, and will carry again if replayed. Stable
    /// across every attempt, which is what lets a receiver deduplicate a redelivery.
    pub webhook_id: String,
    /// How many delivery attempts were made before it was given up on.
    pub attempts: i32,
    /// The last failure reason, a bounded non-secret token.
    pub last_error: Option<String>,
    /// When it was enqueued, milliseconds since the Unix epoch. This is the value a
    /// recover-from-timestamp replay is bounded by.
    pub enqueued_at_unix_ms: i64,
    /// When it was given up on, milliseconds since the Unix epoch.
    pub dead_lettered_at_unix_ms: Option<i64>,
}

/// An endpoint's dead-lettered deliveries, oldest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeadLetterList {
    /// The deliveries, in the order a replay would redeliver them.
    pub items: Vec<DeadLetteredDelivery>,
}

/// Replay an endpoint's dead-lettered deliveries.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReplayDeadLettersRequest {
    /// Replay only deliveries enqueued at or after this instant, milliseconds since the
    /// Unix epoch. Omitted means every dead letter this endpoint has.
    #[serde(default)]
    pub since_unix_ms: Option<i64>,
}

/// The acknowledgement that a replay was QUEUED.
///
/// Deliberately not a count. The management plane enqueues a command and the delivery
/// worker executes it, so no number this response could carry would be true by the time a
/// caller read it. What the caller can rely on is that the request is durable: it is a
/// queue row committed in the same transaction as its audit row.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReplayAccepted {
    /// The bound the replay was requested with, echoed back. `null` means every dead
    /// letter this endpoint has.
    pub since_unix_ms: Option<i64>,
}

/// How many dead letters one listing returns at most.
///
/// A fixed cap rather than a cursor, because this list is a debugging tail rather than a
/// data-sync surface: the operation an operator performs on it is REPLAY, which acts on
/// the whole backlog by timestamp and never has to page through it.
const DEAD_LETTER_LIMIT: i64 = 200;

/// One recorded delivery attempt.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryAttemptView {
    /// The `wha_` identifier.
    pub id: String,
    /// The `webhook-id` the attempt carried, which is what a receiver deduplicated on.
    pub webhook_id: String,
    /// Which attempt of its delivery this was, starting at 1.
    pub attempt_number: i32,
    /// When it was made, milliseconds since the Unix epoch.
    pub attempted_at_unix_ms: i64,
    /// The status the receiver returned. `null` means it never answered: the destination
    /// was refused, the attempt timed out, or the transport failed. `error` says which.
    pub status_code: Option<i32>,
    /// The round trip in milliseconds.
    pub latency_ms: i64,
    /// `null` on a success; otherwise a bounded, non-secret failure label.
    pub error: Option<String>,
}

/// An endpoint's delivery attempt history, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeliveryAttemptList {
    /// The attempts, most recent first.
    pub items: Vec<DeliveryAttemptView>,
}

/// How many attempts one listing returns at most. A debugging tail, like the dead-letter
/// view, so it is a fixed cap rather than a cursor.
const ATTEMPT_LIMIT: i64 = 200;

/// List an endpoint's delivery attempt history.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/attempts",
    operation_id = "listWebhookDeliveryAttempts",
    tag = "webhooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The delivery attempts, newest first", body = DeliveryAttemptList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, or the endpoint is in another scope", body = ErrorBody)
    )
)]
pub async fn list_webhook_delivery_attempts(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ, matching every other read across this surface.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let id = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .parse_id(&endpoint_id)?;
    let attempts = state
        .store()
        .scoped(scope)
        .webhook_delivery_attempts()
        .for_endpoint(&id, ATTEMPT_LIMIT)
        .await?;
    let view = DeliveryAttemptList {
        items: attempts
            .into_iter()
            .map(|attempt| DeliveryAttemptView {
                id: attempt.id.to_string(),
                webhook_id: attempt.webhook_id,
                attempt_number: attempt.attempt_number,
                attempted_at_unix_ms: attempt.attempted_at_unix_micros / 1000,
                status_code: attempt.status_code,
                latency_ms: attempt.latency_ms,
                error: attempt.error,
            })
            .collect(),
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// List an endpoint's dead-lettered deliveries.
#[utoipa::path(
    get,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/dead-letters",
    operation_id = "listWebhookDeadLetters",
    tag = "webhooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The dead-lettered deliveries, oldest first", body = DeadLetterList),
        (status = 401, description = "Missing or invalid credential", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent, or the endpoint is in another scope", body = ErrorBody)
    )
)]
pub async fn list_webhook_dead_letters(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    // No liveness fence on a READ, matching the endpoint listing: a soft-deleted
    // environment stays readable across this surface and only writes refuse it.
    let (scope, _actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.read`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::Read)?;
    let id = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .parse_id(&endpoint_id)?;
    // The deliverer's ordering key IS the endpoint id, so narrowing the generic queue read
    // by ordering key is what makes this a PER-ENDPOINT view without the queue knowing
    // anything about webhooks.
    let messages = state
        .store()
        .scoped(scope)
        .outbox()
        .dead_lettered(
            ironauth_store::WEBHOOK_DELIVERY_CONSUMER,
            Some(&id.to_string()),
            DEAD_LETTER_LIMIT,
        )
        .await?;
    let view = DeadLetterList {
        items: messages
            .into_iter()
            .map(|message| DeadLetteredDelivery {
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
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// Replay an endpoint's dead-lettered deliveries.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/replay",
    operation_id = "replayWebhookDeadLetters",
    tag = "webhooks",
    request_body = ReplayDeadLettersRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 202, description = "The replay was queued. A worker performs it; poll the dead-letter listing to watch it drain", body = ReplayAccepted),
        (status = 400, description = "Malformed request, or a since_unix_ms earlier than 2001-09-09 (which is a seconds value in a milliseconds field)", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the endpoint is in another scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn replay_webhook_dead_letters(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;
    let id = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .parse_id(&endpoint_id)?;
    // An empty body is the "replay everything" form, so it is accepted rather than
    // rejected as malformed. A caller that sends nothing means the same as one that sends
    // `{}`, and refusing one of those would be a distinction with no meaning behind it.
    let request: ReplayDeadLettersRequest = if body.is_empty() {
        ReplayDeadLettersRequest {
            since_unix_ms: None,
        }
    } else {
        parse_json(&body)?
    };
    // The same floor the flow-target replay applies (issue #958). Both routes take a
    // milliseconds bound and both drain to a third party, so a seconds value here replays the
    // whole retained backlog while the API answers 202.
    require_plausible_since_unix_ms(request.since_unix_ms, "endpoint")?;

    // The key is fingerprinted over the BODY as well as the path, so replaying "everything"
    // and replaying "since noon" are different requests under one key rather than one
    // replaying as the other.
    let key = idempotency::required_key(&headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &body);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(&state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // The response is knowable BEFORE the write, because a replay request is now a
    // command rather than the revive itself: what this call produces is "accepted", not a
    // count. That is the honest shape as well as the required one. The count could only
    // ever have described the instant the statement ran, and a retry of the same request
    // would have reported zero because the first call had already revived everything.
    let view = ReplayAccepted {
        since_unix_ms: request.since_unix_ms,
    };
    let body_string = serde_json::to_string(&view).map_err(|_| ApiError::Internal)?;
    let pending =
        webhook_endpoint_simple_event(&state, scope, &id, "webhook_endpoint.replay_requested");
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .webhook_endpoints()
        .request_dead_letter_replay_with_event(
            state.env(),
            &id,
            request.since_unix_ms.map(|ms| ms.saturating_mul(1000)),
            Some(IdempotencyWrite {
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

/// Set or clear an endpoint's event-type subscription.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetEventTypesRequest {
    /// The event types to receive, or an explicit `null` to receive EVERY type. The field
    /// is required so that "everything" is stated rather than inferred from an omission.
    pub event_types: Option<Vec<String>>,
}

/// Subscribe an endpoint to a set of event types.
#[utoipa::path(
    put,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/event-types",
    operation_id = "setWebhookEventTypes",
    tag = "webhooks",
    request_body = SetEventTypesRequest,
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The endpoint, with the subscription it committed", body = WebhookEndpointView),
        (status = 400, description = "Malformed request, a body omitting event_types, or an empty list", body = ErrorBody),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the endpoint is in another scope", body = ErrorBody)
    )
)]
pub async fn set_webhook_event_types(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
    body: axum::body::Bytes,
) -> Result<Response, ApiError> {
    let (scope, actor) = resolve_scope(&state, &principal, &tenant_id, &environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // An UNRESTRICTED credential passes unchanged.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(&state, scope, principal.actor()).await?;
    require_live_environment(&state, &scope).await?;
    let id = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .parse_id(&endpoint_id)?;

    let request: SetEventTypesRequest = parse_json(&body)?;
    // An empty list is refused at the EDGE with a precise message rather than reaching the
    // 0116 CHECK, which would surface as a fault. "Subscribed to nothing" is nearly always
    // a client that serialized an empty list by accident.
    if request.event_types.as_ref().is_some_and(Vec::is_empty) {
        return Err(ApiError::BadRequest(
            "event_types must name at least one type, or be null to receive every type".to_owned(),
        ));
    }

    let pending =
        webhook_endpoint_subscription_event(&state, scope, &id, request.event_types.as_deref());
    state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .webhook_endpoints()
        .set_event_types_with_event(
            state.env(),
            &id,
            request.event_types.as_deref(),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;

    // Re-read through the SAME address so the response reports what was stored.
    let endpoints = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .list()
        .await?;
    let record = endpoints
        .into_iter()
        .find(|record| record.id == id)
        .ok_or(ApiError::NotFound)?;
    let body_string = serde_json::to_string(&into_view(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body_string))
}

/// The request shape both endpoint state toggles share, grouped so the shared body stays
/// inside the argument budget.
struct StateToggle<'a> {
    tenant_id: &'a str,
    environment_id: &'a str,
    endpoint_id: &'a str,
    active: bool,
    uri: &'a Uri,
    headers: &'a HeaderMap,
}

/// Set an endpoint's delivery state: the shared body of the pause and resume actions.
///
/// Pausing is NOT a delete. The endpoint and its sealed signing secret survive, so
/// resuming needs no re-registration and no consumer has to adopt a new secret. That is
/// the difference an operator wants when a destination is misbehaving rather than gone.
async fn set_endpoint_state(
    state: &AdminState,
    principal: &Principal,
    toggle: StateToggle<'_>,
) -> Result<Response, ApiError> {
    let StateToggle {
        tenant_id,
        environment_id,
        endpoint_id,
        active,
        uri,
        headers,
    } = toggle;
    let (scope, actor) = resolve_scope(state, principal, tenant_id, environment_id).await?;
    // Delegated administration (issue #102): classified `management.write_config`.
    // Enforced in the SHARED body, so `pause_webhook_endpoint` and
    // `resume_webhook_endpoint` carry the same requirement by construction rather than
    // by two edits staying in agreement.
    principal.require_permission(ManagementPermission::WriteConfig)?;
    crate::sudo::require_fresh_privilege(state, scope, principal.actor()).await?;
    require_live_environment(state, &scope).await?;
    let id = state
        .store()
        .scoped(scope)
        .webhook_endpoints()
        .parse_id(endpoint_id)?;

    // No request body, so the fingerprint is over an empty one. It still binds the key to
    // the method and PATH, so the same key reused against a different endpoint, or against
    // the OPPOSITE toggle, is a 422 rather than a replay of the wrong answer.
    let key = idempotency::required_key(headers)?;
    let fingerprint = idempotency::fingerprint("POST", uri.path(), &[]);
    let credential_ref = principal.credential_ref();
    if let Some(replay) =
        idempotency::replay_if_stored(state, &credential_ref, &key, &fingerprint).await?
    {
        return Ok(replay);
    }

    // Rendered from what the write RESOLVED, inside its own transaction, so the response
    // describes the state this request committed rather than whatever a later read saw.
    let render = |resolved: &ironauth_store::WebhookEndpointRecord| {
        serde_json::to_string(&into_view(resolved.clone()))
    };
    let pending = webhook_endpoint_active_changed_event(state, scope, &id, active);
    let record = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .webhook_endpoints()
        .set_active_with_event(
            state.env(),
            &id,
            active,
            Some(ResolvedIdempotencyWrite {
                credential_ref: &credential_ref,
                key: &key,
                request_fingerprint: &fingerprint,
                response_status: 200,
                response_body: &render,
            }),
            pending
                .as_ref()
                .map(crate::events::PendingEvent::domain_event)
                .as_ref(),
        )
        .await?;
    let body = serde_json::to_string(&into_view(record)).map_err(|_| ApiError::Internal)?;
    Ok(json(StatusCode::OK, body))
}

/// Pause deliveries to an endpoint without destroying it or its signing secret.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/pause",
    operation_id = "pauseWebhookEndpoint",
    tag = "webhooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The paused endpoint", body = WebhookEndpointView),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the endpoint is in another scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn pause_webhook_endpoint(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    set_endpoint_state(
        &state,
        &principal,
        StateToggle {
            tenant_id: &tenant_id,
            environment_id: &environment_id,
            endpoint_id: &endpoint_id,
            active: false,
            uri: &uri,
            headers: &headers,
        },
    )
    .await
}

/// Resume deliveries to a paused endpoint, under the secret it already had.
#[utoipa::path(
    post,
    path = "/v1/tenants/{tenant_id}/environments/{environment_id}/webhook-endpoints/{endpoint_id}/resume",
    operation_id = "resumeWebhookEndpoint",
    tag = "webhooks",
    params(
        ("tenant_id" = String, Path, description = "The tenant identifier"),
        ("environment_id" = String, Path, description = "The environment identifier"),
        ("endpoint_id" = String, Path, description = "The endpoint identifier (whe_...)"),
        ("Idempotency-Key" = String, Header, description = "Required. Replaying a POST \
         with the same key returns the original response without re-executing.")
    ),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The resumed endpoint", body = WebhookEndpointView),
        (status = 401, description = "Missing or invalid credential, or fresh privilege required", body = ErrorBody),
        (status = 403, description = "Wrong plane or scope", body = ErrorBody),
        (status = 404, description = "The environment is absent or deleted, or the endpoint is in another scope", body = ErrorBody),
        (status = 422, description = "Idempotency-Key reused with a different request", body = ErrorBody)
    )
)]
pub async fn resume_webhook_endpoint(
    State(state): State<AdminState>,
    principal: Principal,
    Path((tenant_id, environment_id, endpoint_id)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    set_endpoint_state(
        &state,
        &principal,
        StateToggle {
            tenant_id: &tenant_id,
            environment_id: &environment_id,
            endpoint_id: &endpoint_id,
            active: true,
            uri: &uri,
            headers: &headers,
        },
    )
    .await
}

/// Project a stored endpoint into its wire view.
fn into_view(record: ironauth_store::WebhookEndpointRecord) -> WebhookEndpointView {
    WebhookEndpointView {
        id: record.id.to_string(),
        url: record.url,
        description: record.description,
        active: record.active,
        auto_disabled_at_unix_ms: record
            .auto_disabled_at_unix_micros
            .map(|micros| micros / 1000),
        disabled_reason: record.disabled_reason,
        event_types: record.event_types,
        created_at_unix_ms: record.created_at_unix_micros / 1000,
    }
}

/// The event a webhook-endpoint delete emits (issue #108).
///
/// The removed endpoint does not receive this: the fan-out lists the live endpoints after the
/// delete commits, so it is already gone. The remaining endpoints do, which is the point --
/// their delivery topology just changed.
fn webhook_endpoint_deleted_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    endpoint_id: &ironauth_store::WebhookEndpointId,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = endpoint_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "webhook_endpoint.deleted",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "webhook_endpoint_id": subject }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event a webhook-endpoint registration emits (issue #108).
///
/// The id and the URL. The URL is the endpoint's identity to an operator -- what they
/// recognise in a console and check against their own infrastructure -- and it is not a
/// secret: they supplied it.
///
/// NEVER the signing secret. This is the sharpest case of that rule in the whole registry,
/// because the secret it would leak is the one that authenticates the very deliveries this
/// event travels on: a subscriber holding it could forge deliveries to that endpoint.
fn webhook_endpoint_created_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    endpoint_id: &ironauth_store::WebhookEndpointId,
    url: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = endpoint_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "webhook_endpoint.created",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "webhook_endpoint_id": subject, "url": url }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event pausing or resuming a webhook endpoint emits (issue #108).
///
/// ONE type with a state, not a `paused` and a `resumed`. Unlike the create/update pairs
/// elsewhere in this registry these are the SAME transition in two directions over one
/// boolean, and a consumer mirroring "is this endpoint delivering" wants one subscription
/// with a field to read rather than two subscriptions to correlate.
fn webhook_endpoint_active_changed_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    endpoint_id: &ironauth_store::WebhookEndpointId,
    active: bool,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = endpoint_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "webhook_endpoint.active_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "webhook_endpoint_id": subject, "active": active }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event a webhook-endpoint change with nothing safe to describe emits (issue #108).
///
/// Used by the secret rotation and the replay request. A rotation's whole content is a NEW
/// SECRET, which is exactly what may not travel, so what remains to say is that the signing
/// material changed and an operator should expect the new key. The overlap window is not
/// carried either: it is deployment policy a subscriber cannot act on, and carrying it would
/// invite treating this event as the authority on when the old secret dies.
fn webhook_endpoint_simple_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    endpoint_id: &ironauth_store::WebhookEndpointId,
    event_type: &str,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = endpoint_id.to_string();
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &serde_json::json!({ "webhook_endpoint_id": subject }),
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}

/// The event a subscription change emits (issue #108).
///
/// `event_types` is OMITTED when the endpoint subscribes to everything, mirroring the column
/// (NULL means no filter) rather than inventing an empty-list encoding that would collide
/// with "subscribed to nothing" -- a state the management surface refuses outright.
fn webhook_endpoint_subscription_event(
    state: &AdminState,
    scope: ironauth_store::Scope,
    endpoint_id: &ironauth_store::WebhookEndpointId,
    event_types: Option<&[String]>,
) -> Option<crate::events::PendingEvent> {
    let id = format!("evt_{}", CorrelationId::generate(state.env()));
    let subject = endpoint_id.to_string();
    let mut payload = serde_json::json!({ "webhook_endpoint_id": subject });
    if let Some(types) = event_types {
        payload["event_types"] = serde_json::json!(types);
    }
    let envelope = ironauth_store::event_catalog::envelope(
        &id,
        "webhook_endpoint.subscription_changed",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        state.now_unix_micros() / 1000,
        &payload,
    )?;
    Some(crate::events::PendingEvent {
        id,
        subject,
        envelope,
    })
}
