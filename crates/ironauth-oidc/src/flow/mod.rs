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
//! error shaping, and the anti enumeration recipe are ONE type, ONE state machine, ONE
//! code path. The rendered object is NOT literally byte identical across transports (the
//! transport tag, the `ui.action`, and the browser only hidden `flow` node differ by
//! design); the load bearing equality is that a FOUND and an UNKNOWN identifier are
//! indistinguishable WITHIN a transport, which holds. The transports
//! ([`transport`]) differ in EXACTLY two mechanical places: submission ingestion (form
//! urlencoded plus the [`same_origin_ok`](crate::interaction::same_origin_ok) CSRF check vs
//! `application/json` plus a per flow submit token) and continuation (a 303 redirect
//! setting the session cookie vs a 200 JSON envelope). Everything else is [`drive`].
//!
//! Behind the `flows.enabled` gate (FORK D): the routes answer a uniform 404 when off, and
//! the bootstrap `/login`, `/consent`, `/register` pages are untouched (their cutover onto
//! this engine is deferred to issue #85).

pub mod golden;
pub mod inspect;
pub mod localize;
pub mod message;
pub mod model;
pub mod schema;

mod builtin_artifacts;
mod consent;
mod eval_ctx;
mod federation;
mod login;
mod mfa;
mod orchestration;
mod profiling;
mod recovery;
mod registration;
mod render;
mod signup_fields;
mod transport;
mod wire_identity;

pub use golden::{GoldenFlow, golden_corpus, golden_flows};
pub use localize::{
    LanguageTag, LocaleBundle, ResolvedLocale, TextDirection, localize, resolve_locale,
};
#[cfg(any(test, feature = "testing"))]
pub use orchestration::EmbeddedJourneySource;
pub use orchestration::{
    CompiledJourneySource, FlowVersionJourneySource, ResolveForCreationFuture, ResolveFuture,
};
pub use schema::{flow_messages_snapshot, flow_object_schema};
pub use transport::{
    FLOW_API_SUBMIT_PATH, FLOW_BRAND_ASSET_PATH, FLOW_BROWSER_PATH, FLOW_CREATE_API_PATH,
    FLOW_STYLESHEET_PATH, flow_api_create, flow_api_submit, flow_brand_asset, flow_browser_get,
    flow_browser_post, flow_stylesheet,
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
    /// The flow hands off to an EXTERNAL browser leg (issue #84, the federation launcher): the
    /// client is redirected to `url` (the existing outbound federation authorize route). This
    /// is NOT a completion (no session is minted here and the flow is NOT consumed); the
    /// existing federation callback finalizes the login through its own cookie/redirect path.
    /// The browser transport issues a 303 to `url`; the API transport returns it as a
    /// `continue_with.redirect_to` affordance the native client opens in a browser.
    Redirect {
        /// The URL to redirect to (a same origin path to the existing federation authorize leg).
        url: String,
    },
    /// A consent decision resolved (issue #88): the flow has been consumed and the browser is
    /// redirected to `redirect_to`. On an ALLOW (`allow == true`) the grant was recorded and
    /// `redirect_to` is the `/authorize` resume that issues the code; on a DENY it routes back
    /// through `/authorize` carrying the internal deny marker so `access_denied` is returned to
    /// the client. No session is minted here (the subject is already authenticated); the
    /// browser transport issues a 303 to `redirect_to` and the API transport returns it as a
    /// `continue_with.redirect_to` affordance.
    ConsentDecision {
        /// Whether the subject allowed the request (informational for the API envelope).
        allow: bool,
        /// The `/authorize` URL to redirect to (the resume, or the deny-marker URL).
        redirect_to: String,
    },
}

/// The serialized state machine position stored in the `flows.state` column (issue #84).
///
/// Beyond the current `step`, it carries the SERVER SIDE scratch a multi step journey needs
/// between submissions: the subject the primary factor authenticated (for the MFA states,
/// written by the server after a genuine password verify, NEVER a client value), the primary
/// auth method tokens proven so far (so the MFA completion mints an HONEST combined amr), and
/// the pending TOTP credential id being enrolled. None of this is client controllable: the
/// client only ever supplies node values and its submit token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedState {
    /// The current state machine step.
    step: FlowStateTag,
    /// The subject (a `usr_` id string) the primary factor authenticated, for the MFA states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    /// The primary auth method tokens proven so far (for example `["pwd"]`), so the MFA
    /// completion builds the honest combined authentication event.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    methods: Vec<String>,
    /// The pending `tot_` credential id being enrolled during the MFA enroll state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enroll_credential: Option<String>,
    /// The recovery identifier (stored server side at the recovery initiation so the verify
    /// step checks the one time code against it WITHOUT echoing it back to the client, keeping
    /// the anti enumeration render clean). Never a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identifier: Option<String>,
    /// The federation connector slug the launcher redirects to (the "continue with {provider}"
    /// choice), stored so the redirect target is server side, never a client controllable field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connector: Option<String>,
    /// The concrete compiled step id a custom (declarative) journey flow is on (issue #92, PR 4),
    /// or [`None`] for every built-in journey. The wire `state` stays the FLAT
    /// [`FlowStateTag::Custom`] for every custom step; the precise step lives HERE, server side.
    /// `skip_serializing_if` keeps a built-in row's serialized `state` BYTE-IDENTICAL (a built-in
    /// never sets it), so the default path is unperturbed and the flow goldens are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custom_step: Option<String>,
}

impl PersistedState {
    /// A single step state (the login/registration/recovery start and render states).
    fn step(step: FlowStateTag) -> Self {
        Self {
            step,
            subject: None,
            methods: Vec::new(),
            enroll_credential: None,
            identifier: None,
            connector: None,
            custom_step: None,
        }
    }
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
    submit_action_for(scope.tenant(), scope.environment(), transport, journey)
}

/// The submission target for a transport, from the raw scope parts (issue #84). The ONE
/// source of truth for the `ui.action` shape, so the live engine and the golden corpus
/// ([`golden`]) build it identically.
pub(super) fn submit_action_for(
    tenant: impl std::fmt::Display,
    environment: impl std::fmt::Display,
    transport: Transport,
    journey: Journey,
) -> String {
    match transport {
        Transport::Browser => {
            format!("/t/{tenant}/e/{environment}/flow/{}", journey.as_str())
        }
        Transport::Api => {
            format!(
                "/t/{tenant}/e/{environment}/flow/api/{}/submit",
                journey.as_str()
            )
        }
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

/// Validate a submission's transient payload (issue #84, §8): it must be well formed JSON
/// within the size cap, else [`FlowError::MalformedTransientPayload`] (400, never a 500).
/// Returns the payload to carry, or [`None`] when absent or JSON null. Shared by every ingest
/// edge, so the cap is enforced on submit as it is on create.
fn validate_submission_transient_payload(
    payload: Option<&serde_json::Value>,
) -> Result<Option<serde_json::Value>, FlowError> {
    match payload {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => {
            // Reuse the create path validator: it enforces "well formed JSON within the cap".
            normalize_transient_payload(Some(value))?;
            Ok(Some(value.clone()))
        }
    }
}

/// The decoded API submission envelope (issue #84): the flow id, the presented submit token,
/// and the transport neutral [`Submission`]. Produced by [`parse_api_submission`].
pub struct ParsedApiSubmission {
    /// The flow id to advance (validated against the scope downstream).
    pub id: String,
    /// The per flow submit token the client presented (the API CSRF handle).
    pub submit_token: String,
    /// The transport neutral decoded submission (node values plus the transient payload).
    pub submission: Submission,
}

/// The raw JSON shape of an API submit body (issue #84). One decode struct, shared by the live
/// API submit handler ([`transport::flow_api_submit`]) and the submission parse fuzz target, so
/// the fuzzer exercises the REAL decode path, never a divergent copy.
#[derive(serde::Deserialize)]
struct ApiSubmitEnvelope {
    /// The flow id to advance.
    id: String,
    /// The per flow submit token (the API CSRF handle).
    submit_token: String,
    /// The submitted node values keyed by node name.
    #[serde(default)]
    nodes: BTreeMap<String, serde_json::Value>,
    /// Arbitrary client context (never persisted on the identity).
    #[serde(default)]
    transient_payload: Option<serde_json::Value>,
}

/// Parse a raw JSON API submission body into the transport neutral pieces (issue #84, the
/// fuzz target's subject): the node values decode plus the transient payload validation, with
/// NO IO and NO state. Arbitrary bytes NEVER panic; a malformed envelope is a typed
/// [`FlowError::InvalidSubmission`] and an oversized or malformed transient payload is a typed
/// [`FlowError::MalformedTransientPayload`] (both 400), never a 500. This is the pure core the
/// live API submit handler routes through, so the parser has exactly one implementation.
///
/// # Errors
///
/// [`FlowError::InvalidSubmission`] when the body is not a well formed submit envelope;
/// [`FlowError::MalformedTransientPayload`] when the transient payload is not well formed JSON
/// or exceeds the size cap.
pub fn parse_api_submission(raw: &[u8]) -> Result<ParsedApiSubmission, FlowError> {
    let envelope: ApiSubmitEnvelope =
        serde_json::from_slice(raw).map_err(|_| FlowError::InvalidSubmission)?;
    let transient_payload =
        validate_submission_transient_payload(envelope.transient_payload.as_ref())?;
    Ok(ParsedApiSubmission {
        id: envelope.id,
        submit_token: envelope.submit_token,
        submission: Submission {
            node_values: envelope.nodes,
            transient_payload,
        },
    })
}

/// Parse a browser transport transient payload field (issue #84): the raw form field is a JSON
/// STRING the client set, decoded to a value and validated within the size cap. Arbitrary
/// input NEVER panics; a non JSON or oversized value is a typed
/// [`FlowError::MalformedTransientPayload`] (400, never a 500). Shared by the browser submit
/// handler and the submission parse fuzz target.
///
/// # Errors
///
/// [`FlowError::MalformedTransientPayload`] when the field is not well formed JSON or exceeds
/// the size cap.
pub fn parse_form_transient_payload(
    raw: Option<&str>,
) -> Result<Option<serde_json::Value>, FlowError> {
    match raw {
        None => Ok(None),
        Some(raw) => {
            let value = serde_json::from_str::<serde_json::Value>(raw)
                .map_err(|_| FlowError::MalformedTransientPayload)?;
            validate_submission_transient_payload(Some(&value))
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

/// The start state (persisted position + nodes) for a journey (issue #84). The login,
/// registration, and recovery journeys each seed their own first state; the federation launcher
/// seeds its connector on the persisted state (server side, never a client field). The MFA
/// states are never a creation entry (they are reached FROM the login journey after the primary
/// factor), so a `Mfa` creation is rejected by the caller. A federation creation without a
/// connector slug is also rejected.
fn start_state(
    journey: Journey,
    transport: Transport,
    flow_id: &str,
    connector: Option<&str>,
) -> Option<(PersistedState, Vec<Node>)> {
    // The start state is the FIRST position in the journey's shared PLAN
    // ([`Journey::plan`]), the ONE transition table the read only flow inspector also
    // projects, so the engine's entry point and the inspector's plan can never diverge. A
    // journey with no creation plan (the MFA states are reached FROM a login flow, never a
    // creation entry) has an empty plan, so `first()` is [`None`] and the creation is a
    // typed not found.
    let start = *journey.plan().first()?;
    match journey {
        Journey::Login => Some((
            PersistedState::step(start),
            login::start_nodes(transport, flow_id),
        )),
        Journey::Registration => Some((
            PersistedState::step(start),
            registration::start_nodes(transport, flow_id),
        )),
        Journey::Recovery => Some((
            PersistedState::step(start),
            recovery::start_nodes(transport, flow_id),
        )),
        Journey::Federation => {
            let connector = connector?;
            let mut persisted = PersistedState::step(start);
            persisted.connector = Some(connector.to_owned());
            Some((
                persisted,
                federation::start_nodes(transport, flow_id, connector),
            ))
        }
        // The consent prompt renders DYNAMIC client-identity and requested-scope nodes from the
        // flow's persisted authorize context, which needs an async store read; `create_flow`
        // appends them via [`consent::consent_start_nodes`] (like the registration signup
        // fields), so the synchronous start state seeds only the position with no nodes.
        Journey::Consent => Some((PersistedState::step(start), Vec::new())),
        // Neither the MFA pseudo journey nor a custom (declarative) journey is seeded here: both
        // have an empty `plan()`, so `plan().first()` above already returned `None` and these arms
        // are unreachable. An MFA state is reached FROM a login flow; a custom flow's creation runs
        // through `orchestration::create_custom_flow`, which seeds the entry step from the compiled
        // table. The arms exist only for match exhaustiveness.
        Journey::Mfa | Journey::Custom => None,
    }
}

/// Create a new flow for a journey (issue #84): mint the id and the submit token, seed the
/// start state, persist the row (carrying the transient payload, which lives ONLY here), and
/// return the id, the submit token, and the initial flow object. Used by both transports'
/// creation edge. The MFA and recovery journeys are not a creation entry (a login flow
/// transitions INTO the MFA states; recovery lands in a later PR), so they are a typed not
/// found.
///
/// `headers` carry the request's session cookie, read ONLY by the Consent journey (issue #88) to
/// resolve the authenticated subject for its render-time scope diff (rendering only the scopes an
/// active prior grant does not already cover). The other journeys ignore it.
///
/// # Errors
///
/// [`FlowError::NotFound`] for a journey that is not a creation entry;
/// [`FlowError::MalformedTransientPayload`] when the transient payload is not well formed
/// JSON or exceeds the size cap; [`FlowError::Store`] on a persistence fault.
// Each argument is an independent piece of the creation context (state, scope, transport,
// journey, and the four per-request inputs: resume target, transient payload, connector, and
// the headers the Consent journey reads); grouping them into a struct would only rename the same
// fields the two transports already assemble inline.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn create_flow(
    state: &OidcState,
    scope: Scope,
    transport: Transport,
    journey: Journey,
    return_to: Option<&str>,
    transient_payload: Option<&serde_json::Value>,
    connector: Option<&str>,
    headers: &axum::http::HeaderMap,
) -> Result<(FlowId, String, Flow), FlowError> {
    // The federation launcher REQUIRES a resume target: the whole point is to resume a pending
    // local `/authorize` after the federated login, and the existing authorize leg refuses an
    // absent one. Reject at creation with a typed error rather than mint a dead flow.
    if journey == Journey::Federation && return_to.is_none() {
        return Err(FlowError::InvalidSubmission);
    }
    // A consent flow likewise REQUIRES a resume target: the whole point is to resume the pending
    // `/authorize` after the decision, and the client and scopes are read from it. Reject an
    // absent one at creation rather than mint a consent flow with no context.
    if journey == Journey::Consent && return_to.is_none() {
        return Err(FlowError::InvalidSubmission);
    }
    // Open redirect fix (issue #84, inherited from PR 1): a PRESENT `return_to` is validated
    // at creation the SAME way the bootstrap `/login` and `/recover` validate theirs, via
    // [`interaction::parse_resume`]. It must be a LOCAL `/authorize?...` resume target whose
    // client id resolves into THIS flow's scope; an absolute or scheme relative external URL,
    // a non `/authorize` local path, or a cross scope target is rejected here with a typed
    // 400 (never stored). Because the check is at creation, EVERY completion (the browser 303
    // and the API `continue_with.redirect_to`, across the login, registration, and recovery
    // journeys) can only ever target a validated local resume. An ABSENT `return_to` is left
    // as is: those journeys complete on the default landing (a hardened success notice), never
    // a redirect, so there is nothing to validate.
    if let Some(raw) = return_to {
        match interaction::parse_resume(Some(raw)) {
            Some(resume) if resume.scope == scope => {}
            _ => return Err(FlowError::InvalidSubmission),
        }
    }
    let transient = normalize_transient_payload(transient_payload)?;
    let flow_id = FlowId::generate(state.env(), &scope);
    let (persisted, mut nodes) = start_state(journey, transport, &flow_id.to_string(), connector)
        .ok_or(FlowError::NotFound)?;
    // A registration flow appends the client's configured signup field nodes (issue #87) to
    // the initial details form, so the very NEXT flow created after a management write to the
    // form reflects the change with no redeploy (the immediacy the flow contract diff test
    // pins). Any absence (no client, no form, no active schema) collects nothing.
    if journey == Journey::Registration {
        nodes.extend(registration::signup_start_nodes(state, scope, return_to).await);
    }
    // A consent flow appends the client-identity and requested-scope nodes (issue #88) built
    // from its PERSISTED authorize context (`return_to`), so the render reflects the exact
    // client and scopes the pending `/authorize` request named. Any absence (no resume,
    // cross-scope, or an unreadable client) renders nothing.
    if journey == Journey::Consent {
        nodes.extend(
            consent::consent_start_nodes(
                state,
                scope,
                transport,
                &flow_id.to_string(),
                return_to,
                headers,
            )
            .await,
        );
    }
    let start_step = persisted.step;
    let submit_token = generate_submit_token(state);
    let now = state.now();
    let expires_at_micros = epoch_micros(
        now.checked_add(Duration::from_secs(FLOW_TTL_SECS))
            .unwrap_or(now),
    );

    let state_json = serde_json::to_string(&persisted).map_err(|_| FlowError::Store)?;

    state
        .store()
        .scoped(scope)
        .flows()
        .create(
            &flow_id,
            NewFlow {
                journey: journey.as_str(),
                transport: transport.as_str(),
                state: &state_json,
                submit_token: &submit_token,
                transient_payload: transient.as_deref(),
                return_to,
                contract_version: i32::try_from(CONTRACT_VERSION).unwrap_or(1),
                flow_version_id: None, // A built-in journey carries no version pin.
                expires_at_unix_micros: expires_at_micros,
            },
        )
        .await
        .map_err(|_| FlowError::Store)?;

    // Build the initial flow object from an in memory record (no extra round trip).
    let record = FlowRecord {
        id: flow_id.to_string(),
        journey: journey.as_str().to_owned(),
        transport: transport.as_str().to_owned(),
        state: state_json,
        submit_token: submit_token.clone(),
        transient_payload: transient,
        return_to: return_to.map(str::to_owned),
        contract_version: i32::try_from(CONTRACT_VERSION).unwrap_or(1),
        flow_version_id: None,
        consumed_at_unix_micros: None,
        expires_at_unix_micros: expires_at_micros,
    };
    let flow = build_flow(
        scope,
        &record,
        transport,
        journey,
        start_step,
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
// A flat per-journey dispatch match: the length reflects the journey count (each arm is a short
// call into that journey's driver), so the line lint is allowed here.
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

    let now_micros = epoch_micros(state.now());
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
    let persisted: PersistedState =
        serde_json::from_str(&record.state).map_err(|_| FlowError::Store)?;

    match journey {
        // The built-in login journey (issue #92, PR 8b): re-expressed as the embedded login
        // artifact and driven through the SAME compiled-table engine a custom journey uses, byte-
        // identically to the retired imperative `drive_login`. The flip subsumes the in-flow MFA
        // challenge / enroll and progressive-profiling holds, because they are substates of the
        // login state machine (not separate journeys). The imperative `drive_login` and its helpers
        // stay in the tree (unused, `#[allow(dead_code)]`, retired in PR 8e) so a revert is this one
        // dispatch line.
        Journey::Login => {
            orchestration::drive_via_table(
                state,
                scope,
                flow_id,
                transport,
                &record,
                &persisted,
                &submission,
                headers,
                now_micros,
                Journey::Login,
            )
            .await
        }
        // The built-in registration journey (issue #92, PR 8c): re-expressed as the embedded
        // registration artifact (a two-step guard-free machine: details form, then a terminal mint)
        // and driven through the SAME compiled-table engine, byte-identically to the retired
        // imperative `drive_registration`. The uniform acknowledgment is a render-override the
        // register executor emits while the flow stays OPEN, not a routed step. The imperative
        // `drive_registration` stays in the tree (unused, `#[allow(dead_code)]`, retired in PR 8e)
        // so a revert is this one dispatch line.
        Journey::Registration => {
            orchestration::drive_via_table(
                state,
                scope,
                flow_id,
                transport,
                &record,
                &persisted,
                &submission,
                headers,
                now_micros,
                Journey::Registration,
            )
            .await
        }
        Journey::Recovery => {
            drive_recovery(
                state,
                scope,
                flow_id,
                transport,
                &record,
                &persisted,
                &submission,
                headers,
                now_micros,
            )
            .await
        }
        Journey::Federation => drive_federation(scope, &record, &persisted),
        Journey::Consent => {
            drive_consent(
                state,
                scope,
                flow_id,
                transport,
                &record,
                &persisted,
                &submission,
                headers,
                now_micros,
            )
            .await
        }
        // The MFA states are reached FROM a login flow, never a creation entry. Typed not
        // found, never a 500.
        Journey::Mfa => Err(FlowError::NotFound),
        // A custom (declarative) journey is driven by its compiled transition table through the
        // ADDITIVE parallel path, reusing the SAME login / MFA / profiling executor cores.
        Journey::Custom => {
            orchestration::drive_custom(
                state,
                scope,
                flow_id,
                transport,
                &record,
                &persisted,
                &submission,
                headers,
                now_micros,
            )
            .await
        }
    }
}

/// Rotate the submit token and persist the next state atomically (issue #84), then return a
/// re-render continuation. The advance is gated on the OLD token (strict single winner
/// rotation): a stale or already rotated token advances nothing, and two concurrent submits
/// carrying the same token can never both rotate. The flow stays OPEN, so a re-render is
/// never a completion oracle.
#[allow(clippy::too_many_arguments)]
async fn persist_and_render(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    journey: Journey,
    record: &FlowRecord,
    next: &PersistedState,
    nodes: Vec<Node>,
    messages: Vec<Message>,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    let new_token = generate_submit_token(state);
    let state_json = serde_json::to_string(next).map_err(|_| FlowError::Store)?;
    let advanced = state
        .store()
        .scoped(scope)
        .flows()
        .advance(
            flow_id,
            &state_json,
            &new_token,
            &record.submit_token,
            now_micros,
        )
        .await
        .map_err(|_| FlowError::Store)?;
    if !advanced {
        // A concurrent completion or expiry raced us to the row.
        return Err(FlowError::AlreadyCompleted);
    }
    let flow = build_flow(
        scope, record, transport, journey, next.step, nodes, messages,
    );
    Ok(Continuation::Render {
        flow: Box::new(flow),
        submit_token: new_token,
    })
}

/// Trip the single use completion latch (issue #84, consume ONLY on a genuine outcome) then
/// mint the session through the ONE choke point. A replayed or concurrent completion mints
/// no second session (the latch is an atomic single winner). On the rare TOCTOU where the
/// central fence refuses the session after the latch tripped, re-render `fenced_nodes`
/// UNIFORMLY (never a 500, never an existence or state oracle).
#[allow(clippy::too_many_arguments)]
async fn consume_and_complete(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    journey: Journey,
    record: &FlowRecord,
    subject: &str,
    actor: ironauth_store::ActorRef,
    event: &crate::authn::AuthenticationEvent,
    fenced_nodes: Vec<Node>,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
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
    match interaction::establish_session(state, scope, subject, event, actor, headers).await {
        Ok(session) => Ok(Continuation::Complete {
            session: Box::new(session),
            return_to: record.return_to.clone(),
        }),
        Err(interaction::EstablishSessionError::NotAuthenticatable) => {
            // The central lifecycle fence refused the mint after the latch tripped (a rare
            // TOCTOU). The response stays the UNIFORM failure; the flow is consumed (the latch
            // gates the mint), so a resubmit is `AlreadyCompleted`, never an oracle.
            let flow = build_flow(
                scope,
                record,
                transport,
                journey,
                persisted_step_for(&record.state),
                fenced_nodes,
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

/// The current step tag recorded on a row's serialized state (used only to re-render the
/// uniform fenced failure on the state the row is on). A parse fault falls back to the login
/// first factor state (the safe default; the row is consumed regardless).
fn persisted_step_for(state_json: &str) -> FlowStateTag {
    serde_json::from_str::<PersistedState>(state_json)
        .map_or(FlowStateTag::IdentifierPassword, |persisted| persisted.step)
}

/// Drive the login journey one step (issue #84), including its composition with the MFA
/// challenge and enrollment states. The primary factor funnels through
/// [`login::advance_login`]; on a genuine primary success the MFA plan (reusing the SAME
/// step up machinery the `/authorize` gate uses) decides whether to complete straight away
/// or transition to an in flow second factor. The MFA states funnel through the SAME
/// [`totp::verify_second_factor`] / enroll ceremonies, and completion mints the honest
/// combined amr/acr.
// PR8e: retire. Dead after the PR 8b table flip (the `Journey::Login` arm now drives through
// `orchestration::drive_via_table`). Kept in the tree so a revert is one dispatch line; deleted in
// PR 8e once every mint-family journey has converged.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn drive_login(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    match persisted.step {
        FlowStateTag::IdentifierPassword => {
            match login::advance_login(state, scope, record, submission, headers).await? {
                login::LoginStep::Render { nodes } => {
                    persist_and_render(
                        state,
                        scope,
                        flow_id,
                        transport,
                        Journey::Login,
                        record,
                        &PersistedState::step(login::render_state_tag()),
                        nodes,
                        Vec::new(),
                        now_micros,
                    )
                    .await
                }
                login::LoginStep::Complete(success) => {
                    complete_primary_or_step_up(
                        state, scope, flow_id, transport, record, &success, headers, now_micros,
                    )
                    .await
                }
            }
        }
        FlowStateTag::MfaChallenge => {
            drive_mfa_challenge(
                state, scope, flow_id, transport, record, persisted, submission, headers,
                now_micros,
            )
            .await
        }
        FlowStateTag::MfaEnroll => {
            drive_mfa_enroll(
                state, scope, flow_id, transport, record, persisted, submission, headers,
                now_micros,
            )
            .await
        }
        FlowStateTag::ProgressiveProfiling => {
            drive_profiling(
                state, scope, flow_id, transport, record, persisted, submission, headers,
                now_micros,
            )
            .await
        }
        // A login row on a registration/recovery/federation/consent/completed/ack state is
        // corrupt; a uniform not found.
        FlowStateTag::RegistrationDetails
        | FlowStateTag::RegistrationAck
        | FlowStateTag::RecoveryStart
        | FlowStateTag::RecoveryAck
        | FlowStateTag::FederationStart
        | FlowStateTag::ConsentPrompt
        | FlowStateTag::Custom
        | FlowStateTag::Completed => Err(FlowError::NotFound),
    }
}

/// Handle a genuine PRIMARY factor success (issue #84): run the SAME post success credential
/// abuse follow through the bootstrap `login_post` does (the password was genuinely correct),
/// then consult the MFA plan. When no in flow second factor is required, complete now; when a
/// challenge or enrollment is required, transition to that state WITHOUT minting a session or
/// consuming the flow (the single mint happens once, at the MFA completion, with the honest
/// combined amr).
// PR8e: retire (dead after the PR 8b table flip; see `drive_login`).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn complete_primary_or_step_up(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    success: &login::LoginSuccess,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    let primary_methods = vec![crate::authn::AuthMethod::Password];
    match mfa::plan_after_primary(state, scope, &success.user_id, &primary_methods).await {
        // No in flow second factor: complete now, running the PR1 post success follow through
        // AFTER a successful mint (exactly as the bootstrap `login_post` / the PR1 flow login).
        mfa::MfaPlan::Complete => {
            // Progressive profiling (issue #87 PR3): when the client's active form has a missing
            // required later-login field, HOLD the mint for a skippable profiling step (like the
            // MFA challenge hold), running the PR1 follow through NOW (the primary genuinely
            // verified) and transitioning WITHOUT minting or consuming. The single mint happens
            // once, at the profiling completion, with the honest primary amr. When there is
            // nothing to collect (`plan` is None), the path below stays BYTE IDENTICAL to before.
            if let Some(plan) =
                profiling::plan(state, scope, &success.user_id, record.return_to.as_deref()).await
            {
                login_follow_through(state, scope, success, headers).await;
                let next = PersistedState {
                    step: FlowStateTag::ProgressiveProfiling,
                    subject: Some(success.subject.clone()),
                    methods: method_tokens(&primary_methods),
                    enroll_credential: None,
                    identifier: None,
                    connector: None,
                    custom_step: None,
                };
                let nodes = profiling::start_nodes(transport, &record.id, &plan);
                return persist_and_render(
                    state,
                    scope,
                    flow_id,
                    transport,
                    Journey::Login,
                    record,
                    &next,
                    nodes,
                    Vec::new(),
                    now_micros,
                )
                .await;
            }
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
            match interaction::establish_session(
                state,
                scope,
                &success.subject,
                &success.event,
                success.actor,
                headers,
            )
            .await
            {
                Ok(session) => {
                    login_follow_through(state, scope, success, headers).await;
                    Ok(Continuation::Complete {
                        session: Box::new(session),
                        return_to: record.return_to.clone(),
                    })
                }
                Err(interaction::EstablishSessionError::NotAuthenticatable) => {
                    // The central fence refused the mint after the latch tripped (a rare
                    // TOCTOU). The response stays the UNIFORM authentication failure; the flow
                    // is consumed, so a resubmit is `AlreadyCompleted`, never an oracle.
                    let flow = build_flow(
                        scope,
                        record,
                        transport,
                        Journey::Login,
                        FlowStateTag::IdentifierPassword,
                        login::uniform_incorrect_render(transport, &record.id),
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
        // A second factor is required: run the primary follow through NOW (the password
        // genuinely verified, exactly as `login_post` records the pwd login BEFORE the
        // `/authorize` gate forces step up), then transition to the MFA state WITHOUT minting a
        // session or consuming the flow. The single mint happens once, at the MFA completion,
        // with the honest combined amr.
        mfa::MfaPlan::Challenge => {
            login_follow_through(state, scope, success, headers).await;
            let next = PersistedState {
                step: mfa::challenge_state_tag(),
                subject: Some(success.subject.clone()),
                methods: method_tokens(&primary_methods),
                enroll_credential: None,
                identifier: None,
                connector: None,
                custom_step: None,
            };
            let nodes = mfa::challenge_start_nodes(transport, &record.id);
            persist_and_render(
                state,
                scope,
                flow_id,
                transport,
                Journey::Login,
                record,
                &next,
                nodes,
                Vec::new(),
                now_micros,
            )
            .await
        }
        mfa::MfaPlan::Enroll => {
            login_follow_through(state, scope, success, headers).await;
            let begin = mfa::begin_enroll(state, scope, &success.user_id).await?;
            let next = PersistedState {
                step: mfa::enroll_state_tag(),
                subject: Some(success.subject.clone()),
                methods: method_tokens(&primary_methods),
                enroll_credential: Some(begin.credential_id.clone()),
                identifier: None,
                connector: None,
                custom_step: None,
            };
            let nodes = mfa::enroll_nodes(transport, &record.id, &begin, false);
            persist_and_render(
                state,
                scope,
                flow_id,
                transport,
                Journey::Login,
                record,
                &next,
                nodes,
                Vec::new(),
                now_micros,
            )
            .await
        }
    }
}

/// The PR1 post success credential abuse follow through for a genuine PRIMARY factor (issue
/// #84), exactly as the bootstrap `login_post`: relax THIS attempt's failure counters (so a
/// user who fumbled before the correct password is not throttled for the rest of the window),
/// then persist the audited risk decision (and, on a new device, notify). All best effort.
///
/// When the primary factor genuinely succeeded on an imported FOREIGN hash (issue #298 / #55),
/// this ALSO lands the verify-then-rehash lazy migration through the SAME
/// [`crate::login::rehash_foreign_credential`] primitive the bootstrap `login_post` uses,
/// upgrading the credential to native Argon2id and retiring the foreign hash so the NEXT login
/// is an ordinary native verify. Best effort (the login has already succeeded): a failure just
/// leaves the foreign hash to upgrade on the next foreign login. This runs on the genuine
/// primary success (before any in flow second factor), matching where `login_post` upgrades.
async fn login_follow_through(
    state: &OidcState,
    scope: Scope,
    success: &login::LoginSuccess,
    headers: &axum::http::HeaderMap,
) {
    state.reset_after_success(&success.ctx).await;
    if let Some(password) = &success.foreign_rehash {
        crate::login::rehash_foreign_credential(state, scope, &success.user_id, password).await;
    }
    let user_agent = login::user_agent_of(headers);
    let risk_ctx = crate::risk::RiskContext {
        ip: success.ctx.ip.as_deref(),
        user_agent: &user_agent,
        headers,
    };
    crate::risk::after_successful_login(
        state,
        scope,
        &success.user_id,
        &success.risk_decision,
        &risk_ctx,
        &success.identifier,
    )
    .await;
}

/// The `auth_methods` token strings for a set of methods (the honest amr source).
fn method_tokens(methods: &[crate::authn::AuthMethod]) -> Vec<String> {
    methods
        .iter()
        .map(|method| method.as_token().to_owned())
        .collect()
}

/// Resolve the subject and the primary methods carried on the MFA state, or a uniform not
/// found when the row is malformed (a login row on an MFA step MUST carry them).
fn mfa_context(
    scope: Scope,
    persisted: &PersistedState,
) -> Result<(ironauth_store::UserId, Vec<crate::authn::AuthMethod>), FlowError> {
    let subject = persisted.subject.as_deref().ok_or(FlowError::NotFound)?;
    let subject_id =
        ironauth_store::UserId::parse_in_scope(subject, &scope).map_err(|_| FlowError::NotFound)?;
    let methods = persisted
        .methods
        .iter()
        .filter_map(|token| crate::authn::AuthMethod::from_token(token))
        .collect();
    Ok((subject_id, methods))
}

/// Drive the MFA challenge state (issue #84): verify the second factor and, on a genuine
/// proof, complete with the honest combined amr.
// PR8e: retire (dead after the PR 8b table flip; see `drive_login`).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn drive_mfa_challenge(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    let (subject_id, primary_methods) = mfa_context(scope, persisted)?;
    match mfa::advance_challenge(state, scope, record, &subject_id, submission, headers).await? {
        mfa::MfaStep::Render { nodes, messages } => {
            persist_and_render(
                state,
                scope,
                flow_id,
                transport,
                Journey::Login,
                record,
                persisted,
                nodes,
                messages,
                now_micros,
            )
            .await
        }
        mfa::MfaStep::Complete { new_method } => {
            complete_with_second_factor(
                state,
                scope,
                flow_id,
                transport,
                record,
                &subject_id,
                &primary_methods,
                new_method,
                headers,
                now_micros,
            )
            .await
        }
    }
}

/// Drive the MFA enrollment state (issue #84): confirm the enrollment code (activating the
/// factor through the shared ceremony) and, on success, complete with the honest combined amr.
// PR8e: retire (dead after the PR 8b table flip; see `drive_login`).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn drive_mfa_enroll(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    let (subject_id, primary_methods) = mfa_context(scope, persisted)?;
    let credential_id = persisted
        .enroll_credential
        .as_deref()
        .ok_or(FlowError::NotFound)?;
    match mfa::advance_enroll(state, scope, record, &subject_id, credential_id, submission).await? {
        mfa::MfaStep::Render { nodes, messages } => {
            persist_and_render(
                state,
                scope,
                flow_id,
                transport,
                Journey::Login,
                record,
                persisted,
                nodes,
                messages,
                now_micros,
            )
            .await
        }
        mfa::MfaStep::Complete { new_method } => {
            complete_with_second_factor(
                state,
                scope,
                flow_id,
                transport,
                record,
                &subject_id,
                &primary_methods,
                new_method,
                headers,
                now_micros,
            )
            .await
        }
    }
}

/// Mint the session for a completed login plus second factor (issue #84): combine the primary
/// factor with the factor the REAL ceremony just proved and record the event at the CURRENT
/// instant, so the token's amr/acr HONESTLY reflects what happened (never a fabricated `mfa`).
// PR8e: retire (dead after the PR 8b table flip; see `drive_login`).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn complete_with_second_factor(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    subject_id: &ironauth_store::UserId,
    primary_methods: &[crate::authn::AuthMethod],
    new_method: crate::authn::AuthMethod,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    let mut methods = primary_methods.to_vec();
    if !methods.contains(&new_method) {
        methods.push(new_method);
    }
    // Progressive profiling (issue #87 PR3): when the client's active form has a missing required
    // later-login field, HOLD the mint for a skippable profiling step, carrying the HONEST
    // combined method tokens (primary plus the just-proven second factor) on the state so the
    // final mint's amr reflects everything that genuinely happened. The second factor was already
    // genuinely proven (its abuse counters were relaxed on the proof), so a held profiling step
    // never re-challenges. When there is nothing to collect, the mint below is UNCHANGED.
    if let Some(plan) = profiling::plan(state, scope, subject_id, record.return_to.as_deref()).await
    {
        let next = PersistedState {
            step: FlowStateTag::ProgressiveProfiling,
            subject: Some(subject_id.to_string()),
            methods: method_tokens(&methods),
            enroll_credential: None,
            identifier: None,
            connector: None,
            custom_step: None,
        };
        let nodes = profiling::start_nodes(transport, &record.id, &plan);
        return persist_and_render(
            state,
            scope,
            flow_id,
            transport,
            Journey::Login,
            record,
            &next,
            nodes,
            Vec::new(),
            now_micros,
        )
        .await;
    }
    let event = crate::authn::AuthenticationEvent::from_methods(&methods, now_micros);
    let actor = interaction::user_actor(subject_id);
    let subject = subject_id.to_string();
    // On the rare fence at the mint, re-render the challenge uniformly (the flow is consumed).
    let fenced = mfa::challenge_start_nodes(transport, &record.id);
    consume_and_complete(
        state,
        scope,
        flow_id,
        transport,
        Journey::Login,
        record,
        &subject,
        actor,
        &event,
        fenced,
        headers,
        now_micros,
    )
    .await
}

/// Drive the progressive profiling state (issue #87 PR3): collect the held later-login fields
/// and, on completion (a skip, a valid collection, or nothing left to collect), mint the session
/// with the HONEST amr the login already earned (the primary plus any genuinely proven second
/// factor, carried on the state). A non-empty invalid value re-renders the profiling nodes with
/// the flow OPEN, so the profiling step is never a completion oracle; the step is always
/// SKIPPABLE, so a blank submit mints.
// PR8e: retire (dead after the PR 8b table flip; see `drive_login`).
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn drive_profiling(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    let (subject_id, methods) = mfa_context(scope, persisted)?;
    match profiling::advance(state, scope, record, &subject_id, submission).await? {
        profiling::ProfilingStep::Render { nodes, messages } => {
            persist_and_render(
                state,
                scope,
                flow_id,
                transport,
                Journey::Login,
                record,
                persisted,
                nodes,
                messages,
                now_micros,
            )
            .await
        }
        profiling::ProfilingStep::Complete => {
            let event = crate::authn::AuthenticationEvent::from_methods(&methods, now_micros);
            let actor = interaction::user_actor(&subject_id);
            let subject = subject_id.to_string();
            // On the rare fence at the mint, re-render the profiling step uniformly (the flow is
            // consumed). The plan may have emptied by now (nothing left to collect); an empty
            // fenced node set is then correct.
            let fenced =
                match profiling::plan(state, scope, &subject_id, record.return_to.as_deref()).await
                {
                    Some(plan) => profiling::start_nodes(transport, &record.id, &plan),
                    None => Vec::new(),
                };
            consume_and_complete(
                state,
                scope,
                flow_id,
                transport,
                Journey::Login,
                record,
                &subject,
                actor,
                &event,
                fenced,
                headers,
                now_micros,
            )
            .await
        }
    }
}

/// Drive the registration journey one step (issue #84): the details funnel through
/// [`registration::advance_registration`] (reusing the SAME #64/#80/#82 defenses the
/// bootstrap `register_post` uses); a genuine account create consumes the flow and mints the
/// first session; the uniform acknowledgment (closed mode anti enum, or waitlist pending)
/// re-renders the ack state with the flow OPEN, so it is never a completion or enumeration
/// oracle.
// PR8e: retire. Dead after the PR 8c table flip (the `Journey::Registration` arm now drives through
// `orchestration::drive_via_table`). Kept in the tree so a revert is one dispatch line; deleted in
// PR 8e once every mint-family journey has converged.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn drive_registration(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    match registration::advance_registration(state, scope, record, submission, headers).await? {
        registration::RegistrationStep::Render { nodes, messages } => {
            persist_and_render(
                state,
                scope,
                flow_id,
                transport,
                Journey::Registration,
                record,
                &PersistedState::step(registration::render_state_tag()),
                nodes,
                messages,
                now_micros,
            )
            .await
        }
        registration::RegistrationStep::Ack { message_id } => {
            persist_and_render(
                state,
                scope,
                flow_id,
                transport,
                Journey::Registration,
                record,
                &PersistedState::step(FlowStateTag::RegistrationAck),
                registration::ack_nodes(),
                vec![Message::of(message_id)],
                now_micros,
            )
            .await
        }
        registration::RegistrationStep::Complete(success) => {
            let fenced = registration::start_nodes(transport, &record.id);
            consume_and_complete(
                state,
                scope,
                flow_id,
                transport,
                Journey::Registration,
                record,
                &success.subject,
                success.actor,
                &success.event,
                fenced,
                headers,
                now_micros,
            )
            .await
        }
    }
}

/// Drive the recovery journey one step (issue #84): the identifier initiation funnels through
/// [`recovery::advance_start`] (the #64 anti enumeration mirror of the bootstrap `/recover`,
/// creating the #81 case and delivering the one time code uniformly); the code verification
/// funnels through [`recovery::advance_verify`] (the EXISTING `email_otp::verify_email_code`
/// core), and a genuine verification consumes the flow and mints the honest email factor
/// session. The uniform acknowledgment and every non completing outcome leave the flow OPEN, so
/// recovery is never a completion or enumeration oracle. The #81 `hold_until` delay and
/// downgrade invariant are UNCHANGED and live downstream at factor removal (see [`recovery`]).
#[allow(clippy::too_many_arguments)]
async fn drive_recovery(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    match persisted.step {
        FlowStateTag::RecoveryStart => {
            match recovery::advance_start(state, scope, record, submission, headers).await? {
                recovery::RecoveryStartStep::Render { nodes } => {
                    persist_and_render(
                        state,
                        scope,
                        flow_id,
                        transport,
                        Journey::Recovery,
                        record,
                        &PersistedState::step(recovery::start_state_tag()),
                        nodes,
                        Vec::new(),
                        now_micros,
                    )
                    .await
                }
                recovery::RecoveryStartStep::Ack { identifier } => {
                    // Transition to the uniform ack plus code entry, storing the identifier
                    // server side so the verify step checks the code against it (never echoed).
                    let mut next = PersistedState::step(FlowStateTag::RecoveryAck);
                    next.identifier = Some(identifier);
                    persist_and_render(
                        state,
                        scope,
                        flow_id,
                        transport,
                        Journey::Recovery,
                        record,
                        &next,
                        recovery::ack_nodes(transport, &record.id, false),
                        vec![Message::of(message::RECOVERY_ACK)],
                        now_micros,
                    )
                    .await
                }
            }
        }
        FlowStateTag::RecoveryAck => {
            let identifier = persisted.identifier.as_deref().ok_or(FlowError::NotFound)?;
            match recovery::advance_verify(state, scope, record, identifier, submission, headers)
                .await?
            {
                recovery::RecoveryVerifyStep::Render { nodes, messages } => {
                    persist_and_render(
                        state,
                        scope,
                        flow_id,
                        transport,
                        Journey::Recovery,
                        record,
                        persisted,
                        nodes,
                        messages,
                        now_micros,
                    )
                    .await
                }
                recovery::RecoveryVerifyStep::Complete(success) => {
                    let fenced = recovery::ack_nodes(transport, &record.id, false);
                    let continuation = consume_and_complete(
                        state,
                        scope,
                        flow_id,
                        transport,
                        Journey::Recovery,
                        record,
                        &success.subject,
                        success.actor,
                        &success.event,
                        fenced,
                        headers,
                        now_micros,
                    )
                    .await?;
                    // Relax the recovery path counters on a genuine mint (best effort), exactly
                    // as the hosted `/otp/verify` does through `establish_and_respond`.
                    if matches!(continuation, Continuation::Complete { .. }) {
                        state.reset_after_success(&success.ctx).await;
                    }
                    Ok(continuation)
                }
            }
        }
        // A recovery row on a non recovery state is corrupt; a uniform not found.
        FlowStateTag::IdentifierPassword
        | FlowStateTag::RegistrationDetails
        | FlowStateTag::RegistrationAck
        | FlowStateTag::MfaChallenge
        | FlowStateTag::MfaEnroll
        | FlowStateTag::ProgressiveProfiling
        | FlowStateTag::FederationStart
        | FlowStateTag::ConsentPrompt
        | FlowStateTag::Custom
        | FlowStateTag::Completed => Err(FlowError::NotFound),
    }
}

/// Drive the federation launcher (issue #84): produce the [`Continuation::Redirect`] to the
/// EXISTING outbound federation authorize leg, threading the flow's `return_to`. The flow is
/// NOT consumed (a redirect is not a completion; the existing `federation_callback` finalizes
/// the login through its own honest [`AuthMethod::Federated`](crate::authn::AuthMethod) session,
/// the #78 link decision, and the #77 overlay), and NO federation security is reimplemented
/// here. A federation row on a non launcher state, or one missing its connector, is a uniform
/// not found.
fn drive_federation(
    scope: Scope,
    record: &FlowRecord,
    persisted: &PersistedState,
) -> Result<Continuation, FlowError> {
    if persisted.step != FlowStateTag::FederationStart {
        return Err(FlowError::NotFound);
    }
    let connector = persisted.connector.as_deref().ok_or(FlowError::NotFound)?;
    // The launcher requires a resume target (enforced at creation); an absent one is a corrupt
    // row, a typed error rather than a dead redirect.
    let return_to = record
        .return_to
        .as_deref()
        .ok_or(FlowError::InvalidSubmission)?;
    let url = federation::authorize_url(scope, connector, return_to);
    Ok(Continuation::Redirect { url })
}

/// Drive the consent prompt one step (issue #88): record the subject's decision through
/// [`consent::advance_consent`] (server authoritative, from the flow's persisted authorize
/// context, never the submission), then CONSUME the single-use flow and hand back the redirect.
/// An ALLOW recorded the grant and resumes `/authorize` (which then issues the code); a DENY
/// recorded nothing and routes back through `/authorize` for `access_denied`. No session is
/// minted here (the subject is already authenticated). A consent row on any other state, or one
/// whose consume was raced, is a uniform typed error, never a 500.
#[allow(clippy::too_many_arguments)]
async fn drive_consent(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    _transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    // A consent row is only ever on the single consent prompt state; any other is corrupt.
    if persisted.step != FlowStateTag::ConsentPrompt {
        return Err(FlowError::NotFound);
    }
    // Decide the transition WITHOUT writing the grant, so a validation failure (a lapsed session,
    // a bad decision) leaves the flow un-consumed and retryable.
    let step = consent::advance_consent(state, scope, record, submission, headers).await?;
    // The decision is terminal: consume the single-use flow FIRST so a replayed or concurrent
    // submit is a uniform `AlreadyCompleted`, never a second grant or a second denial. Only the
    // consume winner records the grant, so a lost consume race persists nothing. If the grant
    // write then faults, the flow is already spent and the subject restarts (fail closed).
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
    let (allow, redirect_to) = match step {
        consent::ConsentStep::Allow { redirect_to, grant } => {
            consent::commit_grant(state, scope, grant).await?;
            (true, redirect_to)
        }
        consent::ConsentStep::Deny { redirect_to } => (false, redirect_to),
    };
    Ok(Continuation::ConsentDecision { allow, redirect_to })
}
