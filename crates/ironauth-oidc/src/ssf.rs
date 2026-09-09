// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared Signals stream management and discovery (issue #143).
//!
//! The receiver-facing half of the transmitter: a receiver creates a stream, reads it back,
//! changes its status, and deletes it. SSF 1.0 leaves the paths to the transmitter and has the
//! discovery document name them, so these hang off the per-environment issuer path the OIDC
//! surface already uses.
//!
//! # The receiver authenticates as a confidential client
//!
//! Through [`authenticate_client_self_scoped`], the same door
//! [`crate::global_revocation`] uses, so the (tenant, environment) comes from the CREDENTIAL
//! rather than from the URL. The path carries the scope too, because discovery has to publish
//! per-environment endpoints, and the two are COMPARED: a credential for one environment
//! presented at another's path is the uniform 401, not a cross-scope write.
//!
//! A public (`none`) client is refused outright. A `client_id` is not a secret, so a stream --
//! which decides where this environment's security events are sent -- must never be creatable
//! by presenting one.
//!
//! # Every answer is the receiver's own
//!
//! The store's reads take the receiver as a parameter and its writes take it as a conjunct
//! (migration 0216 and `SsfStreamRepo`), so nothing here has to remember to filter. What this
//! module adds is the uniform refusal: a stream that belongs to another receiver answers
//! exactly as one that does not exist, so a receiver cannot probe for the existence of
//! somebody else's.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use ironauth_store::{
    ClientId, CorrelationId, NewSsfStream, SSF_DELIVERY_POLL, SSF_DELIVERY_PUSH, Scope,
    SsfDelivery, SsfStream, SsfStreamId, SsfStreamStatus, SsfSubjectFormat, StoreError,
};
use serde::Deserialize;

use crate::client_auth::{ClientAuthInputs, ClientAuthMethod, authenticate_client_self_scoped};
use crate::error::TokenError;
use crate::ssf_set::EVENTS_SUPPORTED;
use crate::state::OidcState;
use crate::util::client_service_actor;

/// The stream-management (configuration) endpoint, per environment.
pub const STREAMS_PATH: &str = "/t/{tenant_id}/e/{environment_id}/ssf/streams";
/// The stream-status endpoint, per environment.
pub const STATUS_PATH: &str = "/t/{tenant_id}/e/{environment_id}/ssf/status";
/// The discovery document, per environment, in the RFC 8414 host-inserted form the rest of
/// this surface uses.
pub const CONFIGURATION_PATH: &str =
    "/.well-known/ssf-configuration/t/{tenant_id}/e/{environment_id}";

/// `?stream_id=` on the reads, the delete, and the status read.
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    /// The stream to address. Absent on the listing.
    stream_id: Option<String>,
}

/// The body a receiver POSTs to create a stream.
#[derive(Debug, Deserialize)]
struct CreateStreamRequest {
    delivery: DeliveryRequest,
    #[serde(default)]
    events_requested: Vec<String>,
    #[serde(default)]
    aud: Vec<String>,
    format: Option<String>,
    description: Option<String>,
}

/// SSF 1.0's delivery object: the method URN and, for push, where to send.
#[derive(Debug, Deserialize)]
struct DeliveryRequest {
    method: String,
    endpoint_url: Option<String>,
    /// Names an `environment_secrets` row holding the bearer the receiver wants presented.
    /// Push only, and optional even then: the SET's signature is the authentication.
    authorization_secret_name: Option<String>,
}

/// The body a receiver POSTs to change a stream's status.
#[derive(Debug, Deserialize)]
struct StatusRequest {
    stream_id: String,
    status: String,
    reason: Option<String>,
}

/// The delivery method and the subject format a create request asks for, or the 400 that says
/// why not.
///
/// Split out of the handler because it sits against the crate's hundred-line ceiling, which a
/// targeted test does not see and only clippy does.
fn validate(
    request: &CreateStreamRequest,
) -> Result<(SsfDelivery, SsfSubjectFormat), Box<Response>> {
    let delivery = match request.delivery.method.as_str() {
        SSF_DELIVERY_PUSH => {
            let Some(endpoint) = request.delivery.endpoint_url.clone() else {
                return Err(Box::new(invalid_request(
                    "a push stream must carry delivery.endpoint_url",
                )));
            };
            // HTTPS ONLY, refused here rather than at the CHECK. A receiver that asked for
            // plaintext delivery would otherwise be told by a 500, and the events on this
            // stream describe this environment's users.
            if !endpoint.starts_with("https://") {
                return Err(Box::new(invalid_request(
                    "delivery.endpoint_url must be an https URL",
                )));
            }
            SsfDelivery::Push {
                endpoint_url: endpoint,
                secret_name: request.delivery.authorization_secret_name.clone(),
            }
        }
        SSF_DELIVERY_POLL => {
            if request.delivery.endpoint_url.is_some() {
                return Err(Box::new(invalid_request(
                    "a poll stream names no endpoint: the receiver fetches from this transmitter",
                )));
            }
            SsfDelivery::Poll
        }
        _ => {
            return Err(Box::new(invalid_request(
                "delivery.method must be urn:ietf:rfc:8935 (push) or urn:ietf:rfc:8936 (poll)",
            )));
        }
    };

    let format = match request.format.as_deref() {
        None => SsfSubjectFormat::IssSub,
        Some(raw) => SsfSubjectFormat::parse(raw).ok_or_else(|| {
            Box::new(invalid_request(
                "format must be one of the RFC 9493 formats this transmitter renders: \
                 email, iss_sub, opaque",
            ))
        })?,
    };

    if request.aud.is_empty() {
        return Err(Box::new(invalid_request(
            "aud must name at least one audience",
        )));
    }
    Ok((delivery, format))
}

/// `POST {issuer}/ssf/streams`.
pub async fn create_stream(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some((client_id, scope)) =
        authenticated(&state, &headers, &tenant_id, &environment_id).await
    else {
        return unauthorized();
    };

    let Ok(request) = serde_json::from_slice::<CreateStreamRequest>(&body) else {
        return invalid_request("the request body must be a JSON stream configuration");
    };

    let (delivery, format) = match validate(&request) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };

    // WHAT THIS TRANSMITTER AGREED TO SEND is the intersection with what it can emit, and it
    // is computed here rather than echoed back: a receiver that asked for an event type this
    // build does not produce must be able to SEE that it is not coming. Today
    // `EVENTS_SUPPORTED` is empty (the CAEP and RISC vocabularies are the next issue), so this
    // is the empty set for every stream, which is the honest answer and not a bug.
    let delivered: Vec<String> = request
        .events_requested
        .iter()
        .filter(|requested| EVENTS_SUPPORTED.contains(&requested.as_str()))
        .cloned()
        .collect();

    // THE CEILING IS CHECKED BEFORE THE WRITE, and reaching it REFUSES rather than evicting:
    // a receiver silently losing the stream it has been polling is a delivery gap it cannot
    // detect.
    let existing = state
        .store()
        .scoped(scope)
        .ssf_streams()
        .list_for_client(
            &client_id,
            i64::from(state.ssf_max_streams_per_client()) + 1,
            None,
        )
        .await;
    let Ok(existing) = existing else {
        return server_error();
    };
    if existing.len() >= state.ssf_max_streams_per_client() as usize {
        return (
            StatusCode::CONFLICT,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "error": "conflict",
                "error_description": "this receiver already holds the most streams this \
                                      environment allows",
            })
            .to_string(),
        )
            .into_response();
    }

    let id = SsfStreamId::generate(state.env(), &scope);
    let actor = client_service_actor(ironauth_store::StoredClientId::Registered(&client_id));
    let outcome = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .ssf_streams()
        .create(
            state.env(),
            NewSsfStream {
                id: &id,
                client_id: &client_id,
                delivery: &delivery,
                events_requested: &request.events_requested,
                events_delivered: &delivered,
                subject_format: format,
                audience: &request.aud,
                description: request.description.as_deref(),
            },
        )
        .await;
    match outcome {
        Ok(()) => {}
        Err(StoreError::Conflict) => return invalid_request("that stream already exists"),
        // A CHECK the validators above did not anticipate lands here rather than as a 500 with
        // no explanation: every bound 0216 declares is one a receiver can hit with a legal-
        // looking body (an over-long description, an audience entry that is not a string).
        Err(StoreError::Database(_)) => {
            return invalid_request("the stream configuration was refused by a stored constraint");
        }
        Err(_) => return server_error(),
    }

    match state
        .store()
        .scoped(scope)
        .ssf_streams()
        .get_for_client(&id, &client_id)
        .await
    {
        Ok(stream) => json(StatusCode::CREATED, &render_stream(&state, scope, &stream)),
        Err(_) => server_error(),
    }
}

/// `GET {issuer}/ssf/streams` -- one stream with `?stream_id=`, or every stream this receiver
/// owns without it.
pub async fn read_streams(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<StreamQuery>,
    headers: HeaderMap,
) -> Response {
    let Some((client_id, scope)) =
        authenticated(&state, &headers, &tenant_id, &environment_id).await
    else {
        return unauthorized();
    };
    let repo = state.store().scoped(scope);
    if let Some(raw) = query.stream_id {
        let Ok(id) = SsfStreamId::parse_in_scope(&raw, &scope) else {
            return not_found();
        };
        match repo.ssf_streams().get_for_client(&id, &client_id).await {
            Ok(stream) => json(StatusCode::OK, &render_stream(&state, scope, &stream)),
            Err(StoreError::NotFound) => not_found(),
            Err(_) => server_error(),
        }
    } else {
        let limit = i64::from(state.ssf_max_streams_per_client()) + 1;
        match repo
            .ssf_streams()
            .list_for_client(&client_id, limit, None)
            .await
        {
            Ok(streams) => {
                let rendered: Vec<serde_json::Value> = streams
                    .iter()
                    .map(|stream| render_stream(&state, scope, stream))
                    .collect();
                json(StatusCode::OK, &serde_json::Value::Array(rendered))
            }
            Err(_) => server_error(),
        }
    }
}

/// `DELETE {issuer}/ssf/streams?stream_id=`.
pub async fn delete_stream(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<StreamQuery>,
    headers: HeaderMap,
) -> Response {
    let Some((client_id, scope)) =
        authenticated(&state, &headers, &tenant_id, &environment_id).await
    else {
        return unauthorized();
    };
    let Some(raw) = query.stream_id else {
        return invalid_request("stream_id is required");
    };
    let Ok(id) = SsfStreamId::parse_in_scope(&raw, &scope) else {
        return not_found();
    };
    let actor = client_service_actor(ironauth_store::StoredClientId::Registered(&client_id));
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .ssf_streams()
        .delete(state.env(), &id, &client_id)
        .await
    {
        Ok(()) => no_content(),
        Err(StoreError::NotFound) => not_found(),
        Err(_) => server_error(),
    }
}

/// `GET {issuer}/ssf/status?stream_id=`.
pub async fn read_status(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<StreamQuery>,
    headers: HeaderMap,
) -> Response {
    let Some((client_id, scope)) =
        authenticated(&state, &headers, &tenant_id, &environment_id).await
    else {
        return unauthorized();
    };
    let Some(raw) = query.stream_id else {
        return invalid_request("stream_id is required");
    };
    let Ok(id) = SsfStreamId::parse_in_scope(&raw, &scope) else {
        return not_found();
    };
    match state
        .store()
        .scoped(scope)
        .ssf_streams()
        .get_for_client(&id, &client_id)
        .await
    {
        Ok(stream) => json(StatusCode::OK, &render_status(&stream)),
        Err(StoreError::NotFound) => not_found(),
        Err(_) => server_error(),
    }
}

/// `POST {issuer}/ssf/status`.
pub async fn update_status(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some((client_id, scope)) =
        authenticated(&state, &headers, &tenant_id, &environment_id).await
    else {
        return unauthorized();
    };
    let Ok(request) = serde_json::from_slice::<StatusRequest>(&body) else {
        return invalid_request("the request body must carry stream_id and status");
    };
    let Some(status) = SsfStreamStatus::parse(&request.status) else {
        return invalid_request("status must be one of: enabled, paused, disabled");
    };
    let Ok(id) = SsfStreamId::parse_in_scope(&request.stream_id, &scope) else {
        return not_found();
    };
    let actor = client_service_actor(ironauth_store::StoredClientId::Registered(&client_id));
    match state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()))
        .ssf_streams()
        .set_status(
            state.env(),
            &id,
            &client_id,
            status,
            request.reason.as_deref(),
        )
        .await
    {
        Ok(()) => match state
            .store()
            .scoped(scope)
            .ssf_streams()
            .get_for_client(&id, &client_id)
            .await
        {
            Ok(stream) => json(StatusCode::OK, &render_status(&stream)),
            Err(_) => server_error(),
        },
        Err(StoreError::NotFound) => not_found(),
        Err(StoreError::Database(_)) => {
            invalid_request("the status change was refused by a stored constraint")
        }
        Err(_) => server_error(),
    }
}

/// `GET /.well-known/ssf-configuration/t/{tenant}/e/{environment}`.
///
/// UNAUTHENTICATED, like every other discovery document here: it names endpoints and
/// capabilities and no stream.
pub async fn configuration(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return not_found();
    };
    // AN UNPROVISIONED ENVIRONMENT HAS NO DOCUMENT, the same answer OIDC discovery gives for
    // the same reason (issue #194): a document naming a `jwks_uri` for an environment with no
    // keys tells a receiver to fetch a key set that will never exist.
    if state
        .issuers()
        .entry_for(&scope, state.env().clock().now_utc())
        .await
        .is_none()
    {
        return not_found();
    }
    let issuer = state.issuers().issuer_for(&scope);
    let base = format!("{issuer}/ssf");
    // IT ADVERTISES ONLY WHAT IS MOUNTED. SSF 1.0 also defines add-subject, remove-subject and
    // verification endpoints; this slice serves none of them, so naming them would tell a
    // receiver to call a 404. They appear here in the slice that mounts them.
    json(
        StatusCode::OK,
        &serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            "configuration_endpoint": format!("{base}/streams"),
            "status_endpoint": format!("{base}/status"),
            "delivery_methods_supported": [SSF_DELIVERY_PUSH, SSF_DELIVERY_POLL],
            // EMPTY UNTIL SOMETHING EMITS. See `ssf_set::EVENTS_SUPPORTED`: advertising a type
            // nothing produces tells a receiver to request a signal it will never be sent.
            "events_supported": EVENTS_SUPPORTED,
            "authorization_schemes": [{ "spec_urn": "urn:ietf:rfc:6749" }],
        }),
    )
}

/// The SSF 1.0 stream configuration object.
fn render_stream(state: &OidcState, scope: Scope, stream: &SsfStream) -> serde_json::Value {
    let mut delivery = serde_json::Map::new();
    delivery.insert(
        "method".to_owned(),
        serde_json::Value::String(stream.delivery.method_urn().to_owned()),
    );
    match &stream.delivery {
        SsfDelivery::Push { endpoint_url, .. } => {
            delivery.insert(
                "endpoint_url".to_owned(),
                serde_json::Value::String(endpoint_url.clone()),
            );
        }
        // THE POLL ENDPOINT IS OURS, so the receiver is told where to fetch from rather than
        // being handed back a field it supplied.
        SsfDelivery::Poll => {
            delivery.insert(
                "endpoint_url".to_owned(),
                serde_json::Value::String(format!(
                    "{}/ssf/poll",
                    state.issuers().issuer_for(&scope)
                )),
            );
        }
    }
    // THE PUSH CREDENTIAL'S NAME IS NOT ECHOED. The receiver supplied it and can look it up;
    // putting it in a response body only widens where it appears.
    serde_json::json!({
        "stream_id": stream.id.to_string(),
        "iss": state.issuers().issuer_for(&scope),
        "aud": stream.audience,
        "delivery": serde_json::Value::Object(delivery),
        "events_supported": EVENTS_SUPPORTED,
        "events_requested": stream.events_requested,
        "events_delivered": stream.events_delivered,
        "format": stream.subject_format.as_str(),
        "description": stream.description,
    })
}

/// The SSF 1.0 stream status object.
fn render_status(stream: &SsfStream) -> serde_json::Value {
    serde_json::json!({
        "stream_id": stream.id.to_string(),
        "status": stream.status.as_str(),
        "reason": stream.status_reason,
    })
}

/// Authenticate the receiver and require its scope to be the one the path names.
///
/// Returns `None` for every failure, which the callers turn into ONE uniform 401: a missing
/// credential, a bad one, a public client, and a credential for another environment are
/// indistinguishable from outside.
async fn authenticated(
    state: &OidcState,
    headers: &HeaderMap,
    tenant_id: &str,
    environment_id: &str,
) -> Option<(ClientId, Scope)> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let inputs = ClientAuthInputs {
        authorization,
        client_id: None,
        client_secret: None,
        client_assertion: None,
        client_assertion_type: None,
    };
    let (client, scope) = authenticate_client_self_scoped(state, inputs).await.ok()?;
    // A PUBLIC CLIENT IS REFUSED. A `client_id` is not a secret, and a stream decides where
    // this environment's security events are sent.
    if client.auth_method == ClientAuthMethod::None {
        return None;
    }
    // THE PATH AND THE CREDENTIAL MUST AGREE. The scope comes from the credential -- the path
    // is what discovery publishes -- so a credential for one environment presented at
    // another's path is refused rather than silently acting in its own.
    let addressed = parse_scope(tenant_id, environment_id)?;
    if addressed != scope {
        return None;
    }
    // PARSED HERE, ONCE. Every store call below takes a scope-typed `ClientId`, so the parse
    // cannot be forgotten at one of them, and a stored id that does not parse in the scope it
    // just authenticated in is refused rather than falling back to some other actor.
    let client_id = ClientId::parse_in_scope(&client.client_id, &scope).ok()?;
    Some((client_id, scope))
}

fn parse_scope(tenant_id: &str, environment_id: &str) -> Option<Scope> {
    Some(Scope::new(
        ironauth_store::TenantId::parse(tenant_id).ok()?,
        ironauth_store::EnvironmentId::parse(environment_id).ok()?,
    ))
}

fn json(status: StatusCode, body: &serde_json::Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

fn no_content() -> Response {
    (
        StatusCode::NO_CONTENT,
        [(header::CACHE_CONTROL, "no-store")],
    )
        .into_response()
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({ "error": "not_found" }).to_string(),
    )
        .into_response()
}

fn invalid_request(message: &str) -> Response {
    TokenError::InvalidRequest(message.to_owned()).into_response()
}

fn server_error() -> Response {
    TokenError::ServerError.into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::WWW_AUTHENTICATE,
                "Basic realm=\"ironauth\", charset=\"UTF-8\"",
            ),
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({ "error": "invalid_client" }).to_string(),
    )
        .into_response()
}
