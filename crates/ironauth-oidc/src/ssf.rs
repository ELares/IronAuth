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
//! # Two deliberate deviations, named here rather than discovered
//!
//! SSF 1.0 section 8.1.1 marks `aud` a Transmitter-Supplied member. This surface takes it from
//! the receiver's create request instead, because a transmitter has no registered audience
//! identifier for a receiver in this deployment's model -- the receiver is an OAuth client and
//! its audience is whatever its own infrastructure answers to. It is validated and bounded like
//! any other receiver input, and the day clients carry a registered audience this should read
//! it from there.
//!
//! And only `client_secret_basic` reaches these endpoints, because that is what the shared
//! client-authentication door reads from the Authorization header. Discovery advertises exactly
//! that rather than an unqualified RFC 6749, so a `private_key_jwt` receiver is not told to try
//! a body parameter nothing reads.
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

/// The namespace ONE receiver's push credential must live in.
///
/// `delivery.authorization_secret_name` is supplied by the RECEIVER, and the delivery worker
/// opens it and presents it as a Bearer to a URL the same receiver chose. Two escapes have to
/// be closed, not one:
///
/// - an environment-wide namespace stops a receiver naming the LDAP bind password or an
///   outbound SCIM credential, which is what `ldap_connectors::BIND_SECRET_PREFIX` does for its
///   own subsystem;
/// - but a namespace shared by every receiver stops nothing between them. Receiver A names the
///   secret receiver B registered and has this deployment POST B's bearer to A's endpoint. The
///   prefix therefore carries the OWNING CLIENT.
///
/// Enforced in the two places `ldap_connectors` enforces its own, for the same reason: at the
/// door so a receiver cannot ask, and again at the READ, because a row written before this rule
/// existed or restored by a config import never passed the door. The read compares against the
/// stream's OWN `client_id`, which the row carries, so a stream cannot be made to open a
/// credential belonging to a different receiver even if its name was written directly.
#[must_use]
pub fn push_secret_prefix(client_id: &ClientId) -> String {
    format!("ssf_push_{client_id}_")
}

/// The delivery methods this deployment can actually perform.
///
/// ONE list, read by both [`validate`] and [`configuration`]. It held both SSF methods while
/// NEITHER delivery path was mounted, so discovery advertised poll, a poll stream could be
/// created, and the configuration handed the receiver a `{issuer}/ssf/poll` URL that nothing
/// served -- three sites free to disagree, and all three wrong. It then held push alone until
/// RFC 8936 was served. Poll is back because [`poll`] now mounts it, which is the only way a
/// method gets on this list.
pub const DELIVERY_METHODS_SUPPORTED: &[&str] = &[SSF_DELIVERY_PUSH, SSF_DELIVERY_POLL];

/// The stream-management (configuration) endpoint, per environment.
pub const STREAMS_PATH: &str = "/t/{tenant_id}/e/{environment_id}/ssf/streams";
/// The stream-status endpoint, per environment.
pub const STATUS_PATH: &str = "/t/{tenant_id}/e/{environment_id}/ssf/status";

/// The RFC 8936 poll endpoint, per STREAM.
///
/// Per stream rather than per environment: the URL is what identifies which stream a receiver
/// is collecting for, so a credential holding several poll streams names the one it means
/// instead of the transmitter guessing.
pub const POLL_PATH: &str = "/t/{tenant_id}/e/{environment_id}/ssf/poll/{stream_id}";
/// The SSF 1.0 section 7.1.4 verification endpoint, per environment.
///
/// Per environment rather than per stream, unlike the poll endpoint, because the request body
/// names the stream: section 7.1.4 makes `stream_id` a REQUIRED member, so putting it in the
/// path as well would give a receiver two places to say it and this surface two to disagree.
pub const VERIFICATION_PATH: &str = "/t/{tenant_id}/e/{environment_id}/ssf/verify";
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
    client_id: &ClientId,
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
                    "a poll stream names no endpoint: the receiver collects from THIS \
                     transmitter, and the address is published in the stream configuration",
                )));
            }
            SsfDelivery::Poll
        }
        _ => {
            return Err(Box::new(invalid_request(
                "delivery.method must be one of the methods \
                 delivery_methods_supported advertises",
            )));
        }
    };
    debug_assert!(
        DELIVERY_METHODS_SUPPORTED.contains(&delivery.method_urn()),
        "a delivery method was accepted that discovery does not advertise"
    );

    let format = match request.format.as_deref() {
        None => SsfSubjectFormat::IssSub,
        Some(raw) => SsfSubjectFormat::parse(raw).ok_or_else(|| {
            Box::new(invalid_request(
                "format must be one of the RFC 9493 formats this transmitter renders: \
                 email, iss_sub, opaque",
            ))
        })?,
    };

    // EVERY BOUND 0216 DECLARES IS MIRRORED HERE, and that is what lets the handler treat a
    // `StoreError::Database` as a FAULT rather than as bad input. It used to answer 400 for any
    // database error, which turned a dropped connection into "your request was invalid".
    bounded(&request.aud, MAX_AUDIENCES, "aud")?;
    bounded(
        &request.events_requested,
        MAX_EVENTS_REQUESTED,
        "events_requested",
    )?;
    if request.aud.is_empty() {
        return Err(Box::new(invalid_request(
            "aud must name at least one audience",
        )));
    }
    if let Some(description) = request.description.as_deref() {
        if description.trim().is_empty() || description.len() > MAX_TEXT_BYTES {
            return Err(Box::new(invalid_request(
                "description must be non-empty and at most 252 bytes",
            )));
        }
    }
    if let SsfDelivery::Push {
        endpoint_url,
        secret_name,
    } = &delivery
    {
        if endpoint_url.len() > MAX_ENDPOINT_BYTES {
            return Err(Box::new(invalid_request(
                "delivery.endpoint_url is longer than this transmitter stores",
            )));
        }
        if let Some(name) = secret_name {
            if name.trim().is_empty() || name.len() > MAX_TEXT_BYTES {
                return Err(Box::new(invalid_request(
                    "delivery.authorization_secret_name must be non-empty and at most 252 bytes",
                )));
            }
            // THE NAMESPACE, and it names THIS receiver. See `push_secret_prefix`.
            let prefix = push_secret_prefix(client_id);
            if !name.starts_with(&prefix) {
                return Err(Box::new(invalid_request(&format!(
                    "invalid_authorization_secret_name: it must begin with {prefix:?}, which is \
                     the namespace this receiver's own push credentials live in"
                ))));
            }
        }
    }
    Ok((delivery, format))
}

/// The most streams one listing returns.
///
/// Deliberately NOT `max_streams_per_client`: that bounds what a receiver may CREATE, and
/// reusing it for the read meant an operator lowering the config made existing streams
/// invisible -- and a stream a receiver cannot see is one it cannot delete. Well above any
/// plausible ceiling, so the listing is complete in practice; a cursor lands with the first
/// deployment that needs one.
const MAX_STREAMS_LISTED: u32 = 1000;

/// The most audiences one stream's SETs may name.
///
/// `aud` is copied verbatim into EVERY SET this stream carries, so an unbounded list is a
/// receiver-chosen multiplier on the size of every signal the environment produces.
const MAX_AUDIENCES: usize = 8;

/// The most event types one stream may ask for. Bounded for the same reason.
const MAX_EVENTS_REQUESTED: usize = 64;

/// The longest operator-facing string 0216 stores (`description`, `push_secret_name`).
const MAX_TEXT_BYTES: usize = 252;

/// The longest receiver endpoint 0216 stores.
const MAX_ENDPOINT_BYTES: usize = 2048;

/// Refuse a list that is too long, or one whose entries are.
fn bounded(values: &[String], max: usize, what: &str) -> Result<(), Box<Response>> {
    if values.len() > max {
        return Err(Box::new(invalid_request(&format!(
            "{what} names more than {max} entries"
        ))));
    }
    if let Some(entry) = values.iter().find(|entry| entry.len() > MAX_TEXT_BYTES) {
        return Err(Box::new(invalid_request(&format!(
            "an entry in {what} is longer than {MAX_TEXT_BYTES} bytes: {} bytes",
            entry.len()
        ))));
    }
    Ok(())
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

    let (delivery, format) = match validate(&request, &client_id) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };

    // WHAT THIS TRANSMITTER AGREED TO SEND is the intersection with what it can emit, and it
    // is computed here rather than echoed back: a receiver that asked for an event type this
    // build does not produce must be able to SEE that it is not coming.
    //
    // THE INTERSECTION IS NO LONGER ALWAYS EMPTY. This comment said it was, which was true
    // while `EVENTS_SUPPORTED` was, and the verification endpoint changed that: a receiver
    // asking for SSF's verification event now gets it back in `events_delivered`. The CAEP and
    // RISC vocabularies are still the next issue's, so every other request is still refused by
    // omission. The `a_receiver_is_told_which_of_its_requested_events_will_arrive` test drives
    // both halves.
    let delivered: Vec<String> = request
        .events_requested
        .iter()
        .filter(|requested| EVENTS_SUPPORTED.contains(&requested.as_str()))
        .cloned()
        .collect();

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
            state.ssf_max_streams_per_client(),
            None,
        )
        .await;
    match outcome {
        Ok(()) => {}
        Err(StoreError::Conflict) => return invalid_request("that stream already exists"),
        // THE CEILING, enforced as a conjunct of the INSERT rather than by a count this handler
        // took first: N concurrent creates cannot all see the same under-limit count and all
        // commit. Reaching it REFUSES rather than evicting -- a receiver silently losing the
        // stream it has been polling is a delivery gap it cannot detect.
        Err(StoreError::QuotaExceeded) => return quota_exceeded(),
        // A DATABASE ERROR IS A FAULT, not a bad request. `validate` mirrors every bound 0216
        // declares, so a rejected write here is a disagreement between this code and the schema,
        // or a transport failure -- neither of which the receiver caused or can fix by editing
        // its request. This used to answer 400, which reported a dropped connection as the
        // receiver's mistake.
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
        // BOUNDED INDEPENDENTLY OF THE WRITE CEILING. Reading at `max_streams_per_client + 1`
        // meant lowering the config hid streams a receiver already owned -- rows it could then
        // neither see nor delete. This cap is fixed, so the listing shows what exists.
        let limit = i64::from(MAX_STREAMS_LISTED);
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
        Err(_) => server_error(),
    }
}

/// The RFC 8936 poll request body.
///
/// Every member is optional, which is section 2.4's shape: a receiver that sends `{}` is asking
/// for whatever is owed, and one that sends only `ack` is acknowledging without collecting.
#[derive(Debug, Deserialize)]
struct PollRequest {
    /// The most SETs to return. Clamped to the transmitter's own ceiling; `0` means "none",
    /// which is how a receiver acknowledges without collecting.
    #[serde(rename = "maxEvents")]
    max_events: Option<u32>,
    /// When false -- which RFC 8936 section 2.2 makes the DEFAULT -- the receiver is asking the
    /// transmitter to hold the request open until an event arrives.
    ///
    /// THIS TRANSMITTER NEVER HOLDS, and the value is read and discarded. A held request
    /// occupies a connection for a benefit a receiver polling on its own schedule already has.
    ///
    /// AND THE RESPONSE DOES NOT SAY SO. An earlier version of this comment claimed it did; it
    /// does not. Section 2.3 gives the response exactly two members, `sets` and `moreAvailable`,
    /// and `moreAvailable` reports the backlog rather than the hold policy, so a receiver that
    /// asked to be held and got an empty page cannot tell that from a long poll that timed out
    /// empty. There is no field in the protocol to tell it otherwise, so the policy is published
    /// where a receiver can actually read it before it depends on it: `long_poll_supported` is
    /// `false` in the SSF configuration document.
    #[serde(rename = "returnImmediately")]
    return_immediately: Option<bool>,
    /// The `jti`s the receiver has processed. Acknowledged BEFORE the new page is chosen, so
    /// one round trip both clears the last page and collects the next.
    #[serde(default)]
    ack: Vec<String>,
    /// SETs the receiver could not accept, by `jti`. Read and NOT acted on; see the handler.
    #[serde(rename = "setErrs", default)]
    set_errs: serde_json::Map<String, serde_json::Value>,
}

/// `POST {issuer}/ssf/poll/{stream_id}` -- RFC 8936 poll delivery.
///
/// One round trip acknowledges the previous page and collects the next, which is the shape
/// section 2.4 describes and the reason `ack` is processed first.
pub async fn poll(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, stream_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some((client_id, scope)) =
        authenticated(&state, &headers, &tenant_id, &environment_id).await
    else {
        return unauthorized();
    };
    // AN EMPTY BODY IS A VALID POLL. RFC 8936's members are all optional, and a receiver that
    // sends nothing is asking for whatever is owed.
    let request: PollRequest = if body.is_empty() {
        PollRequest {
            max_events: None,
            return_immediately: None,
            ack: Vec::new(),
            set_errs: serde_json::Map::new(),
        }
    } else {
        match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return invalid_request("the request body must be an RFC 8936 poll request"),
        }
    };

    let Ok(id) = SsfStreamId::parse_in_scope(&stream_id, &scope) else {
        return not_found();
    };
    // THE STREAM IS RESOLVED THROUGH THE FENCED READ, which is what proves this receiver owns
    // it. Everything below addresses the stream by handle alone, and this is the only thing
    // standing between a receiver and another's queue.
    let stream = match state
        .store()
        .scoped(scope)
        .ssf_streams()
        .get_for_client(&id, &client_id)
        .await
    {
        Ok(stream) => stream,
        Err(StoreError::NotFound) => return not_found(),
        Err(_) => return server_error(),
    };
    // A PUSH STREAM IS NOT POLLED. Its events are delivered to it; letting it also collect
    // would hand the same SET out twice under two delivery methods.
    if !matches!(stream.delivery, SsfDelivery::Poll) {
        return invalid_request("this stream is delivered by push; it has nothing to collect");
    }
    // A STREAM THAT IS NOT DELIVERING DOES NOT DELIVER HERE EITHER, and this is checked BEFORE
    // the acknowledgement so a stopped stream cannot be drained by one.
    //
    // POLL IS DELIVERY. The push consumer has always refused a non-delivering stream; this
    // surface did not, so `paused` handed its whole backlog over on the next poll and
    // `disabled` -- documented as retaining nothing -- both served its queue AND let the caller
    // destroy it with an `ack`. The same status word enforced on one delivery method and
    // ignored on the other is worse than either answer applied to both.
    if !stream.status.delivers() {
        return not_delivering(stream.status);
    }

    let sets = state.store().scoped(scope).ssf_stream_sets();
    if !request.ack.is_empty() {
        // BOUNDED. An unbounded `ack` array is a receiver-chosen amount of work on a request
        // path, and no honest one exceeds the page it was just given.
        if request.ack.len() > MAX_POLL_EVENTS as usize {
            return invalid_request("ack names more events than one page can contain");
        }
        if sets.acknowledge(&id, &request.ack).await.is_err() {
            return server_error();
        }
    }
    // `setErrs` IS READ AND NOT ACTED ON, and that is a decision rather than an oversight.
    // Section 2.4 lets a receiver report a SET it could not accept; deleting one on that basis
    // would let a receiver discard its own security events by claiming it could not parse them,
    // and re-minting cannot fix a SET the transmitter believes is correct. It is logged so an
    // operator sees a receiver rejecting events, and the SET stays owed.
    if !request.set_errs.is_empty() {
        tracing::warn!(
            stream = %id,
            count = request.set_errs.len(),
            "a Shared Signals receiver reported SETs it could not accept; they remain owed"
        );
    }

    let wanted = request
        .max_events
        .unwrap_or(MAX_POLL_EVENTS)
        .min(MAX_POLL_EVENTS);
    let Ok(owed) = sets.owed(&id, i64::from(wanted)).await else {
        return server_error();
    };
    let Ok(remaining) = sets.owed_count(&id).await else {
        return server_error();
    };

    let mut collected = serde_json::Map::new();
    for set in &owed {
        collected.insert(
            set.jti.clone(),
            serde_json::Value::String(set.set_jws.clone()),
        );
    }
    // `moreAvailable` COUNTS WHAT IS STILL OWED AFTER THIS PAGE, which is what tells a receiver
    // to poll again immediately rather than wait out its interval.
    let more = remaining > i64::try_from(owed.len()).unwrap_or(i64::MAX);
    // READ AND DISCARDED. See `PollRequest::return_immediately`: this transmitter never holds a
    // request open, and RFC 8936 section 2.3 gives the response no member that could say so, so
    // the policy is advertised in the configuration document instead of being implied here.
    let _ = request.return_immediately;
    json(
        StatusCode::OK,
        &serde_json::json!({ "sets": collected, "moreAvailable": more }),
    )
}

/// What a receiver posts to ask for a verification event.
///
/// SSF 1.0 section 7.1.4. `stream_id` is REQUIRED and `state` is OPTIONAL; there are no other
/// members, and an unknown one is ignored rather than refused, because a receiver built against
/// a later revision of the spec must not be locked out by a member this build has not learned.
#[derive(Debug, Deserialize)]
struct VerificationRequest {
    stream_id: String,
    /// An opaque value the receiver chose, echoed back inside the event.
    ///
    /// The receiver's way of matching the SET it collects to the request it made, which matters
    /// because the answer to the request itself is a bare 204 that names nothing.
    #[serde(default)]
    state: Option<String>,
}

/// `POST {issuer}/ssf/verify` -- SSF 1.0 section 7.1.4 stream verification.
///
/// # 204, and what it does and does not promise
///
/// Section 7.1.4 is explicit that a success "does not indicate that the Verification Event was
/// transmitted successfully, only that the Event Transmitter has transmitted the event or will
/// do so at some point in the future". So this returns 204 once the SET is DURABLE -- queued for
/// a poll receiver, or enqueued on the outbox for a push one -- and never waits for delivery.
///
/// # The subject is the stream, and it is always opaque
///
/// Section 7.1.4 requires the top-level `sub_id` of a verification event to be an `opaque`
/// identifier whose `id` is the stream being verified, REGARDLESS of the subject format that
/// stream negotiated. A verification event is about the stream rather than about a person, so
/// rendering it as the stream's `email` format would name a subject that does not exist.
///
/// # A disabled stream is refused
///
/// The spec does not say to, and this does. A 204 promises the transmitter has transmitted the
/// event "or will do so at some point in the future", and a `disabled` stream can do neither:
/// 0216 defines it as delivering nothing and retaining nothing, so the SET would be dropped on
/// the floor or, worse, left as a row the stream is documented not to hold. A `paused` stream is
/// ACCEPTED, because retaining is exactly what it does and the receiver collects on resume.
///
/// # Rate limited, because the work is not the request
///
/// One small POST mints a signed SET and either queues a row or enqueues an outbox message.
/// Section 7.1.4 anticipates this, defining 429 and naming `min_verification_interval` as the
/// advertised floor. The slot is taken ATOMICALLY, so a burst of concurrent requests cannot all
/// pass the same stale instant.
pub async fn verification(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let Some((client, scope)) = authenticated(&state, &headers, &tenant_id, &environment_id).await
    else {
        return unauthorized();
    };
    let Ok(request) = serde_json::from_str::<VerificationRequest>(&body) else {
        return invalid_request("the verification request is not a JSON object with a stream_id");
    };
    let Ok(id) = SsfStreamId::parse_in_scope(&request.stream_id, &scope) else {
        return not_found();
    };
    // THE RECEIVER FENCE, and everything below addresses the stream by handle alone. Section
    // 7.1.4 gives 404 for "stream not found for this receiver", which is the same answer an
    // absent stream gets, so a client cannot probe for another receiver's streams.
    let stream = match state
        .store()
        .scoped(scope)
        .ssf_streams()
        .get_for_client(&id, &client)
        .await
    {
        Ok(stream) => stream,
        Err(StoreError::NotFound) => return not_found(),
        Err(_) => return server_error(),
    };
    if !stream.status.retains() {
        return not_delivering(stream.status);
    }

    // EVERY REFUSAL THAT COSTS NOTHING COMES FIRST. An earlier version claimed the rate-limit
    // slot before validating `state`, so a receiver sending an over-long value got a 400 AND
    // lost its interval, for a request that minted and queued nothing.
    let mut payload = serde_json::Map::new();
    if let Some(echoed) = &request.state {
        // ECHOED VERBATIM AND BOUNDED. Section 7.1.4 says the transmitter returns the value the
        // receiver supplied, so it is not interpreted; it is bounded because it lands inside a
        // signed token this transmitter stores and delivers.
        if echoed.len() > MAX_TEXT_BYTES {
            return invalid_request("state is longer than this transmitter will echo");
        }
        payload.insert(
            "state".to_owned(),
            serde_json::Value::String(echoed.clone()),
        );
    }

    // THE BUDGET THE RECEIVER CANNOT RESET, claimed BEFORE the per-stream slot.
    //
    // The per-stream floor below is keyed on a column of `ssf_streams`, a row the receiver
    // deletes at will: `create -> verify -> delete -> create` gives a stream whose
    // `last_verification_at` is NULL and passes immediately, so on its own that floor bounds
    // nothing. This one is keyed on the CLIENT and survives the churn. It is claimed first so a
    // receiver that has exhausted it has spent nothing else.
    //
    // THE ALLOWANCE IS THE STREAM CEILING: a receiver may hold that many streams and verify
    // each once per interval, so that count is exactly the honest maximum.
    match state
        .store()
        .scoped(scope)
        .ssf_streams()
        .claim_client_verification(
            &client,
            state.ssf_min_verification_interval_secs(),
            state.ssf_max_streams_per_client(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return too_many_verifications(state.ssf_min_verification_interval_secs()),
        Err(_) => return server_error(),
    }

    // THE PER-STREAM SLOT, which is the floor a receiver can act on: it names THIS stream, so a
    // receiver polling several knows which one to back off. Taken atomically, so a burst cannot
    // all pass one stale instant.
    match state
        .store()
        .scoped(scope)
        .ssf_streams()
        .claim_verification(&id, &client, state.ssf_min_verification_interval_secs())
        .await
    {
        Ok(true) => {}
        Ok(false) => return too_many_verifications(state.ssf_min_verification_interval_secs()),
        Err(_) => return server_error(),
    }
    let event = crate::ssf_set::SecurityEvent {
        event_type: crate::ssf_set::VERIFICATION_EVENT_TYPE.to_owned(),
        payload,
    };
    // OPAQUE, AND THE STREAM. Not `stream.subject_format`: see the doc above.
    let subject = crate::ssf_set::SubjectIdentifier::Opaque { id: id.to_string() };
    let jti = verification_jti(state.env());

    let queued = match deliver_verification(&state, scope, &stream, &id, &jti, &subject, &event)
        .await
    {
        Ok(queued) => queued,
        Err(response) => return response,
    };
    let _ = queued;
    no_content()
}

/// Make the verification SET durable by the method its stream negotiated.
///
/// THE TWO METHODS STORE DIFFERENT THINGS, which is why this is a match rather than one call.
/// Poll stores the SIGNED TOKEN, because RFC 8936 redelivers an unacknowledged SET and a
/// receiver comparing two deliveries must see the same bytes; push stores the INGREDIENTS on the
/// outbox, which is the shape `enqueue_push` already had.
///
/// The `Err` arm is a response rather than an error type because every failure here has exactly
/// one right answer and the caller would only re-derive it.
#[allow(clippy::too_many_arguments)]
async fn deliver_verification(
    state: &OidcState,
    scope: Scope,
    stream: &SsfStream,
    id: &SsfStreamId,
    jti: &str,
    subject: &crate::ssf_set::SubjectIdentifier,
    event: &crate::ssf_set::SecurityEvent,
) -> Result<bool, Response> {
    match &stream.delivery {
        SsfDelivery::Poll => {
            let Ok(token) = crate::ssf_set::mint_set(
                state.issuers(),
                state.env(),
                scope,
                &crate::ssf_set::SetToMint {
                    audience: &stream.audience,
                    jti,
                    subject,
                    event,
                },
            )
            .await
            else {
                return Err(server_error());
            };
            state
                .store()
                .scoped(scope)
                .ssf_stream_sets()
                .queue(
                    state.env(),
                    id,
                    jti,
                    &token,
                    state.ssf_max_owed_sets_per_stream(),
                )
                .await
                .map(|()| true)
                .map_err(|error| queue_refusal(&error))
        }
        SsfDelivery::Push { .. } => crate::ssf_push::enqueue_push(
            state.store(),
            state.env(),
            scope,
            &crate::ssf_push::QueuedPush {
                stream_id: id,
                jti,
                subject,
                event,
            },
        )
        .await
        .map_err(|error| queue_refusal(&error)),
    }
}

/// Turn a queue failure into the answer it deserves.
///
/// A FULL QUEUE IS NOT A SERVER FAULT. It means the receiver has stopped collecting, so it gets
/// the same 429 the rate limit gives rather than a 500 that would send an operator looking at
/// the transmitter.
fn queue_refusal(error: &StoreError) -> Response {
    match error {
        StoreError::QuotaExceeded => owed_queue_full(),
        _ => server_error(),
    }
}

/// A fresh `jti` for one verification event.
///
/// FROM ENTROPY, not from the stream or the clock. The `jti` is what a receiver deduplicates on
/// and what an acknowledgement names, so two verification requests for one stream must not
/// collide: deriving it from the stream would make the second request a `Conflict` against the
/// first, and deriving it from the clock would do the same for two within one tick.
fn verification_jti(env: &ironauth_env::Env) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0_u8; 16];
    env.entropy().fill_bytes(&mut bytes);
    format!("evt_verify_{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// The stream already holds every unacknowledged SET this environment will keep for it.
///
/// 429 AND NOT 500, because this is a receiver that has stopped collecting rather than a
/// transmitter fault: sending a 500 would put an operator to work on the wrong side. It is a
/// DIFFERENT 429 from the rate limit and says so, since the two are fixed by different actions
/// -- wait, versus collect what you are already owed.
fn owed_queue_full() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({
            "error": "too_many_requests",
            "error_description":
                "this stream already holds every SET it may be owed; acknowledge what you have \
                 been given before asking for more",
        })
        .to_string(),
    )
        .into_response()
}

/// The receiver asked for a verification event again too soon.
fn too_many_verifications(min_interval_secs: u32) -> Response {
    // RETRY-AFTER NAMES THE INTERVAL. It said `0`, which is the one value that makes the header
    // worse than absent: a receiver obeying it retries immediately and is refused again, so the
    // header turned a rate limit into an invitation to spin.
    let retry_after = min_interval_secs.to_string();
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::RETRY_AFTER, retry_after.as_str()),
        ],
        serde_json::json!({
            "error": "too_many_requests",
            "error_description": format!(
                "this stream may be verified once every {min_interval_secs} seconds"
            ),
        })
        .to_string(),
    )
        .into_response()
}

/// The most SETs one poll returns, and the most `jti`s one may acknowledge.
///
/// A receiver may ask for fewer. It may not ask for more: `maxEvents` is receiver-chosen work
/// on a request path, and a page this size is already far beyond what a receiver polling on any
/// sane interval accumulates.
const MAX_POLL_EVENTS: u32 = 100;

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
    // IT ADVERTISES ONLY WHAT IS MOUNTED. SSF 1.0 also defines add-subject and remove-subject
    // endpoints; this build serves neither, so naming them would tell a receiver to call a 404.
    // They appear here in the slice that mounts them, which is what just happened to
    // `verification_endpoint`.
    json(
        StatusCode::OK,
        &serde_json::json!({
            "issuer": issuer,
            // THE HELPER, not a hand-written path. This said
            // `{issuer}/.well-known/jwks.json`, which nothing mounts: the served route is
            // `{issuer}/jwks.json`. A receiver bootstraps from this document to fetch the keys
            // that verify a SET, so the one wrong field made the transmitter unusable to
            // anyone who followed it.
            "jwks_uri": state.issuers().jwks_uri_for(&scope),
            "configuration_endpoint": format!("{base}/streams"),
            "status_endpoint": format!("{base}/status"),
            "verification_endpoint": format!("{base}/verify"),
            // `min_verification_interval` IS NOT HERE, and that is a correction. It was, and
            // SSF 1.0 does not define it as transmitter metadata: it is a read-only STREAM
            // configuration property, so a conformant receiver reads it off its own stream and
            // would never have found it in this document. `render_stream` carries it now.
            "delivery_methods_supported": DELIVERY_METHODS_SUPPORTED,
            // WHAT A POLL RECEIVER CANNOT LEARN FROM A RESPONSE. RFC 8936 defaults
            // `returnImmediately` to false, meaning "hold the request open", and this
            // transmitter never does. The response carries only `sets` and `moreAvailable`, so
            // a receiver that asked to be held and got an empty page cannot distinguish that
            // from a long poll that timed out. Publishing it here is the only place it can
            // learn the policy BEFORE it builds a client around waiting.
            "long_poll_supported": false,
            // EXACTLY WHAT THIS BUILD EMITS. See `ssf_set::EVENTS_SUPPORTED`: it was empty
            // while nothing produced a SET, and it names SSF's own verification event now that
            // the verification endpoint does. Advertising a type nothing produces would tell a
            // receiver to request a signal it will never be sent.
            "events_supported": EVENTS_SUPPORTED,
            // NARROWED TO WHAT IS ACCEPTED. `authenticate_client_self_scoped` reads the
            // Authorization header, so `client_secret_basic` is the method that reaches these
            // endpoints; an unqualified RFC 6749 advertisement would tell a `private_key_jwt`
            // receiver to try a body parameter no handler reads. The other methods land with
            // the change that accepts them.
            "authorization_schemes": [{
                "spec_urn": "urn:ietf:rfc:6749",
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            }],
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
        // THE POLL ENDPOINT IS THE TRANSMITTER'S, and it is per stream: the receiver proves
        // which stream it is collecting for by the URL it calls, so one credential holding
        // several poll streams cannot drain the wrong one by omission. An earlier version
        // synthesised `{issuer}/ssf/poll`, which named no stream and which nothing served.
        SsfDelivery::Poll => {
            delivery.insert(
                "endpoint_url".to_owned(),
                serde_json::Value::String(format!(
                    "{}/ssf/poll/{}",
                    state.issuers().issuer_for(&scope),
                    stream.id
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
        // TRANSMITTER-SUPPLIED AND READ-ONLY, which is what SSF 1.0 makes it: the receiver
        // cannot set it, and it is here rather than in the discovery document because the
        // stream configuration object is where the spec defines it and therefore the only
        // place a conformant receiver looks. Publishing it is what lets a receiver pace itself
        // instead of discovering the floor by being refused.
        "min_verification_interval": state.ssf_min_verification_interval_secs(),
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

/// The receiver already holds the most streams this environment allows.
fn quota_exceeded() -> Response {
    (
        StatusCode::CONFLICT,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({
            "error": "conflict",
            "error_description":
                "this receiver already holds the most streams this environment allows",
        })
        .to_string(),
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

/// The stream exists and belongs to the caller, and it is not delivering.
///
/// NOT the uniform not-found the receiver fence uses, and deliberately: this receiver owns the
/// stream, so telling it the state it set itself reveals nothing it does not already know, and
/// an operator debugging a silent poll needs to be told the difference between "your stream is
/// paused" and "your stream is gone".
fn not_delivering(status: SsfStreamStatus) -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({
            "error": "access_denied",
            "error_description": format!(
                "this stream is {} and is not delivering; set it to enabled to collect",
                status.as_str()
            ),
        })
        .to_string(),
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
