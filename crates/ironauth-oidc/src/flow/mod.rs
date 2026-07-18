// SPDX-License-Identifier: MIT OR Apache-2.0

//! The headless flow API (issue #84): one machine readable flow object served identically
//! to the browser and native JSON transports, in front of the EXISTING security choke
//! points.
//!
//! Architecture (the one sentence thesis): the flow engine is a thin state machine plus a
//! typed renderer. It owns exactly three new things: the persisted `flows` row
//! ([`ironauth_store::FlowRepo`]), the typed flow object contract ([`model`]) plus its JSON
//! Schema ([`schema`]), and the numeric message id registry ([`message`]). It owns NO new
//! security logic: every login transition calls INTO
//! [`verify_password`](crate::state::OidcState::verify_password) /
//! [`verify_absent`](crate::state::OidcState::verify_absent) and the ONE session mint
//! [`establish_session`](crate::interaction::establish_session), and the identifier step
//! reuses the #64 uniform response recipe (see [`login`]).
//!
//! Two transports, ONE object (FORK C): the state machine, node rendering, message ids,
//! error shaping, and the anti enumeration recipe are shared byte for byte. The transports
//! ([`transport`]) differ in EXACTLY two mechanical places: submission ingestion (form
//! urlencoded plus the [`same_origin_ok`](crate::interaction::same_origin_ok) CSRF check vs
//! `application/json` plus a per flow submit token) and continuation (a 303 redirect
//! setting the session cookie vs a 200 JSON envelope). Everything else is [`drive`].
//!
//! Behind the `flows.enabled` gate (FORK D): the routes answer a uniform 404 when off, and
//! the bootstrap `/login`, `/consent`, `/register` pages are untouched (their cutover onto
//! this engine is deferred to issue #85).

pub mod message;
pub mod model;
pub mod schema;

mod login;
mod transport;

pub use schema::{flow_messages_snapshot, flow_object_schema};
pub use transport::{
    FLOW_API_SUBMIT_PATH, FLOW_BROWSER_PATH, FLOW_CREATE_API_PATH, flow_api_create,
    flow_api_submit, flow_browser_get, flow_browser_post,
};

use std::collections::BTreeMap;
use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_store::{FlowId, FlowRecord, NewFlow, Scope};
use serde::{Deserialize, Serialize};

use self::message::{Message, MessageId};
use self::model::{CONTRACT_VERSION, Flow, FlowStateTag, Journey, Node, Transport, Ui};
use crate::interaction::{self, SessionCookies};
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The flow row time to live (issue #84): a flow must be completed within this window from
/// creation, computed off the app clock seam so expiry is deterministic under a manual
/// clock. Short lived and bounded, like the federation correlation state.
const FLOW_TTL_SECS: u64 = 900;

/// The response header mirroring the flow object's `contract_version` (issue #84, FORK B).
pub const FLOW_CONTRACT_HEADER: &str = "x-ironauth-flow-contract";

/// The entropy width of the API transport submit token, in bytes.
const SUBMIT_TOKEN_BYTES: usize = 32;

/// A typed flow error (issue #84). Every one renders to a WELL DEFINED HTTP response on
/// BOTH transports; the ONLY 500 is [`Store`](FlowError::Store), a genuine persistence
/// fault. Expiry, completion, an invalid submission, and a malformed transient payload are
/// typed flow errors, never a 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    /// The flow has expired (410 Gone).
    Expired,
    /// The flow is already completed, the single use latch tripped (410 Gone).
    AlreadyCompleted,
    /// No such flow in scope (404, a uniform not found for an unknown or cross scope id).
    NotFound,
    /// The submission was not valid: a malformed node payload or a submit token mismatch
    /// (400).
    InvalidSubmission,
    /// The transient payload was not well formed JSON or exceeded the size cap (400).
    MalformedTransientPayload,
    /// A genuine persistence fault (500 neutral, the ONLY 500). Mirrors
    /// `EstablishSessionError::Store`: a store fault is neutral, never an oracle.
    Store,
}

impl FlowError {
    /// The HTTP status this error renders to on both transports.
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            FlowError::Expired | FlowError::AlreadyCompleted => StatusCode::GONE,
            FlowError::NotFound => StatusCode::NOT_FOUND,
            FlowError::InvalidSubmission | FlowError::MalformedTransientPayload => {
                StatusCode::BAD_REQUEST
            }
            FlowError::Store => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The flow level message id this error carries (issue #84), so a client keys its copy
    /// on a stable number. [`Store`](FlowError::Store) has no client facing message (it is
    /// the neutral server error).
    #[must_use]
    pub fn message_id(self) -> Option<MessageId> {
        match self {
            FlowError::Expired => Some(message::FLOW_EXPIRED),
            FlowError::AlreadyCompleted => Some(message::FLOW_ALREADY_COMPLETED),
            FlowError::NotFound => Some(message::FLOW_NOT_FOUND),
            FlowError::InvalidSubmission => Some(message::FLOW_INVALID_SUBMISSION),
            FlowError::MalformedTransientPayload => Some(message::FLOW_MALFORMED_TRANSIENT_PAYLOAD),
            FlowError::Store => None,
        }
    }
}

/// A transport neutral decoded submission (issue #84): the node values plus the optional
/// transient payload. The browser decoder fills it from urlencoded form fields; the API
/// decoder from JSON. This is the ONLY transport fork inside the engine.
#[derive(Debug, Clone, Default)]
pub struct Submission {
    /// The submitted node values keyed by node name.
    pub node_values: BTreeMap<String, serde_json::Value>,
    /// The arbitrary client supplied transient payload, or [`None`].
    pub transient_payload: Option<serde_json::Value>,
}

/// How the transport authenticated the submission (issue #84, the CSRF IO edge). The API
/// presents its per flow submit token (matched against the row); the browser has already
/// passed the [`same_origin_ok`](crate::interaction::same_origin_ok) check plus its cookie.
pub enum TransportAuth {
    /// Browser: the same origin gate ran at the handler edge.
    Browser,
    /// API: the submit token the client presented in the JSON body.
    Api {
        /// The presented submit token, matched against the row's current token.
        presented_submit_token: String,
    },
}

/// The result of a transition (issue #84): re-render the flow (rotating the API submit
/// token) or complete it (mint the session through the ONE choke point).
pub enum Continuation {
    /// Re-render the same flow (a validation error or the uniform authentication failure).
    Render {
        /// The re-rendered flow object.
        flow: Box<Flow>,
        /// The rotated API submit token to hand back to a native client.
        submit_token: String,
    },
    /// The flow completed: the minted session cookies and the resume target.
    Complete {
        /// The session cookies from the ONE session mint.
        session: Box<SessionCookies>,
        /// The `/authorize` resume target, or [`None`].
        return_to: Option<String>,
    },
}

/// The serialized state machine position stored in the `flows.state` column (issue #84).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    /// The current state machine step.
    step: FlowStateTag,
}

/// A fresh API transport submit token minted from the entropy seam (issue #84), base64url
/// with no padding. Modeled on the recovery cancel token: 256 bits of CSPRNG entropy from
/// the env seam, never the crate's own RNG.
fn generate_submit_token(state: &OidcState) -> String {
    let mut bytes = [0_u8; SUBMIT_TOKEN_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A constant time equality check for the submit token, so a token comparison never leaks
/// its prefix through timing (defense in depth; the token is high entropy).
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The submission target for a transport (issue #84). The browser posts back to its scoped
/// GET/POST path; the API posts to the scoped submit endpoint.
fn submit_action(scope: Scope, transport: Transport, journey: Journey) -> String {
    match transport {
        Transport::Browser => format!(
            "/t/{}/e/{}/flow/{}",
            scope.tenant(),
            scope.environment(),
            journey.as_str()
        ),
        Transport::Api => format!(
            "/t/{}/e/{}/flow/api/submit",
            scope.tenant(),
            scope.environment()
        ),
    }
}

/// Validate and normalize a transient payload (issue #84): it must be well formed JSON
/// within a size cap, else [`FlowError::MalformedTransientPayload`] (400, never a 500).
/// Returns the serialized JSON to store, or [`None`] when absent.
fn normalize_transient_payload(
    payload: Option<&serde_json::Value>,
) -> Result<Option<String>, FlowError> {
    /// The maximum serialized transient payload size (bytes). A generous cap that still
    /// bounds a hostile payload.
    const MAX_BYTES: usize = 8 * 1024;
    match payload {
        None => Ok(None),
        Some(value) => {
            if value.is_null() {
                return Ok(None);
            }
            let serialized =
                serde_json::to_string(value).map_err(|_| FlowError::MalformedTransientPayload)?;
            if serialized.len() > MAX_BYTES {
                return Err(FlowError::MalformedTransientPayload);
            }
            Ok(Some(serialized))
        }
    }
}

/// Build the flow object from a row, state tag, and node set (issue #84). Applies the
/// deterministic node ordering and stamps the contract version, so the object is byte
/// identical across transports.
fn build_flow(
    scope: Scope,
    record: &FlowRecord,
    transport: Transport,
    journey: Journey,
    state_tag: FlowStateTag,
    nodes: Vec<Node>,
    flow_messages: Vec<Message>,
) -> Flow {
    let ui = Ui::new(
        submit_action(scope, transport, journey),
        "POST".to_owned(),
        nodes,
        flow_messages,
    );
    Flow {
        contract_version: CONTRACT_VERSION,
        id: record.id.clone(),
        journey,
        state: state_tag,
        transport,
        expires_at: record.expires_at_unix_micros / 1_000_000,
        request_url: record.return_to.clone(),
        ui,
    }
}

/// Create a new login flow (issue #84): mint the id and the submit token, seed the start
/// state, persist the row (carrying the transient payload, which lives ONLY here), and
/// return the id, the submit token, and the initial flow object. Used by both transports'
/// creation edge.
///
/// # Errors
///
/// [`FlowError::MalformedTransientPayload`] when the transient payload is not well formed
/// JSON or exceeds the size cap; [`FlowError::Store`] on a persistence fault.
pub async fn create_login_flow(
    state: &OidcState,
    scope: Scope,
    transport: Transport,
    return_to: Option<&str>,
    transient_payload: Option<&serde_json::Value>,
) -> Result<(FlowId, String, Flow), FlowError> {
    let transient = normalize_transient_payload(transient_payload)?;
    let flow_id = FlowId::generate(state.env(), &scope);
    let submit_token = generate_submit_token(state);
    let now = state.now();
    let expires_at_micros = epoch_micros(
        now.checked_add(Duration::from_secs(FLOW_TTL_SECS))
            .unwrap_or(now),
    );

    let persisted = PersistedState {
        step: FlowStateTag::IdentifierPassword,
    };
    let state_json = serde_json::to_string(&persisted).map_err(|_| FlowError::Store)?;

    state
        .store()
        .scoped(scope)
        .flows()
        .create(
            &flow_id,
            NewFlow {
                journey: Journey::Login.as_str(),
                transport: transport.as_str(),
                state: &state_json,
                submit_token: &submit_token,
                transient_payload: transient.as_deref(),
                return_to,
                contract_version: i32::try_from(CONTRACT_VERSION).unwrap_or(1),
                expires_at_unix_micros: expires_at_micros,
            },
        )
        .await
        .map_err(|_| FlowError::Store)?;

    // Build the initial flow object from an in memory record (no extra round trip).
    let record = FlowRecord {
        id: flow_id.to_string(),
        journey: Journey::Login.as_str().to_owned(),
        transport: transport.as_str().to_owned(),
        state: state_json,
        submit_token: submit_token.clone(),
        transient_payload: transient,
        return_to: return_to.map(str::to_owned),
        contract_version: i32::try_from(CONTRACT_VERSION).unwrap_or(1),
        consumed_at_unix_micros: None,
        expires_at_unix_micros: expires_at_micros,
    };
    let nodes = login::start_nodes(transport, &record.id);
    let flow = build_flow(
        scope,
        &record,
        transport,
        Journey::Login,
        FlowStateTag::IdentifierPassword,
        nodes,
        Vec::new(),
    );
    Ok((flow_id, submit_token, flow))
}

/// Drive one submission through the shared engine (issue #84): load the row (scope forced),
/// enforce the single use and expiry latches, run the transport CSRF edge, dispatch the
/// journey transition, and either re-render (rotating the API submit token) or complete
/// (trip the completion latch, then mint the session through the ONE choke point). This is
/// the ONE code path both transports share; the forks are the two IO edges in
/// [`transport`].
///
/// # Errors
///
/// A typed [`FlowError`]: [`Expired`](FlowError::Expired) /
/// [`AlreadyCompleted`](FlowError::AlreadyCompleted) on a closed row,
/// [`NotFound`](FlowError::NotFound) on an unknown, cross scope, or cross transport id,
/// [`InvalidSubmission`](FlowError::InvalidSubmission) on a submit token mismatch, and
/// [`Store`](FlowError::Store) on a genuine persistence fault (the ONLY 500).
// One flat state machine driver; splitting it would scatter the single shared code path the
// two transports fork from.
#[allow(clippy::too_many_lines)]
pub async fn drive(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    auth: TransportAuth,
    submission: Submission,
    headers: &axum::http::HeaderMap,
) -> Result<Continuation, FlowError> {
    let record = state
        .store()
        .scoped(scope)
        .flows()
        .load(flow_id)
        .await
        .map_err(|_| FlowError::Store)?
        .ok_or(FlowError::NotFound)?;

    // The transport is immutable: a browser flow is never driven via the API edge, nor the
    // reverse (a uniform not found, so cross transport misuse discloses nothing).
    if record.transport != transport.as_str() {
        return Err(FlowError::NotFound);
    }

    let now = state.now();
    let now_micros = epoch_micros(now);
    if record.is_expired(now_micros) {
        return Err(FlowError::Expired);
    }
    if record.is_completed() {
        return Err(FlowError::AlreadyCompleted);
    }

    // The CSRF IO edge. The API matches its per flow submit token against the row (single
    // use per step, rotated on each transition below); the browser already passed the same
    // origin gate at the handler edge.
    if let TransportAuth::Api {
        presented_submit_token,
    } = &auth
    {
        if !constant_time_eq(presented_submit_token, &record.submit_token) {
            return Err(FlowError::InvalidSubmission);
        }
    }

    let journey = Journey::parse(&record.journey).ok_or(FlowError::NotFound)?;
    // PR1 ships the login journey; the other journeys land in later PRs and are a typed not
    // found until then (never a 500).
    if journey != Journey::Login {
        return Err(FlowError::NotFound);
    }

    let step = login::advance_login(state, scope, &record, &submission).await?;
    match step {
        login::LoginStep::Render { nodes } => {
            // Rotate the submit token and persist the (possibly unchanged) state on every
            // transition, so a captured API token is single use per step.
            let new_token = generate_submit_token(state);
            let persisted = PersistedState {
                step: login::render_state_tag(),
            };
            let state_json = serde_json::to_string(&persisted).map_err(|_| FlowError::Store)?;
            let advanced = state
                .store()
                .scoped(scope)
                .flows()
                .advance(flow_id, &state_json, &new_token, now_micros)
                .await
                .map_err(|_| FlowError::Store)?;
            if !advanced {
                // A concurrent completion or expiry raced us to the row.
                return Err(FlowError::AlreadyCompleted);
            }
            let flow = build_flow(
                scope,
                &record,
                transport,
                journey,
                login::render_state_tag(),
                nodes,
                Vec::new(),
            );
            Ok(Continuation::Render {
                flow: Box::new(flow),
                submit_token: new_token,
            })
        }
        login::LoginStep::Complete {
            subject,
            actor,
            event,
        } => {
            // Trip the single use completion latch FIRST (atomic), so a replayed completion
            // mints no second session. Then mint the session through the ONE choke point.
            let consumed = state
                .store()
                .scoped(scope)
                .flows()
                .consume(flow_id, now_micros)
                .await
                .map_err(|_| FlowError::Store)?;
            if !consumed {
                return Err(FlowError::AlreadyCompleted);
            }
            match interaction::establish_session(state, scope, &subject, &event, actor, headers)
                .await
            {
                Ok(session) => Ok(Continuation::Complete {
                    session: Box::new(session),
                    return_to: record.return_to.clone(),
                }),
                Err(interaction::EstablishSessionError::NotAuthenticatable) => {
                    // The central lifecycle fence refused a fenced but correct login. The
                    // flow is already consumed; the response stays the UNIFORM authentication
                    // failure (never a 500, never an existence or state oracle).
                    let nodes = login::uniform_incorrect_render(transport, &record.id);
                    let flow = build_flow(
                        scope,
                        &record,
                        transport,
                        journey,
                        FlowStateTag::IdentifierPassword,
                        nodes,
                        Vec::new(),
                    );
                    Ok(Continuation::Render {
                        flow: Box::new(flow),
                        submit_token: record.submit_token.clone(),
                    })
                }
                Err(interaction::EstablishSessionError::Store) => Err(FlowError::Store),
            }
        }
    }
}
