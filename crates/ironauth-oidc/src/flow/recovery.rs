// SPDX-License-Identifier: MIT OR Apache-2.0

//! The recovery journey (issue #84): account recovery as a flow state machine, at PARITY
//! with the bootstrap `POST /recover` (`recover.rs`). Like every other journey, the engine
//! owns NO new security logic; each transition calls INTO an EXISTING choke point:
//!
//! - **initiation** mirrors `recover.rs:68-185` exactly: [`OidcState::regulate_before`] on
//!   the INDEPENDENT [`AuthPath::Recovery`] counters, then for a known identifier
//!   [`crate::recovery::initiate_recovery`] (the #81 case: risk score, per account cooldown,
//!   the possibly delay held flow, and the channel notifications) or for an unknown one
//!   [`crate::recovery::decoy_recovery_work`] (the SAME store round trips, suppressed send),
//!   plus the recovery one time code delivery through [`crate::email_otp::issue_email_code`]
//!   (a known recipient gets a fresh code, an unknown one burns the SAME single Argon2 spend
//!   with the send suppressed). BOTH branches converge on ONE uniform acknowledgment render,
//!   so an existing and an unknown identifier are INDISTINGUISHABLE in body, status, and
//!   Argon2 op timing on either transport;
//!
//! - **completion** funnels through the EXISTING [`crate::email_otp::verify_email_code`]
//!   (purpose [`EmailFactorPurpose::Recovery`]), the SAME core the hosted `/otp/verify`
//!   endpoint drives, which mints an ordinary email factor session (`amr = [otp]`). The flow
//!   consumes its single use latch ONLY on that genuine mint (never on a validation, throttle,
//!   or wrong code), so the recovery is never a completion or enumeration oracle.
//!
//! # The #81 `hold_until` delay and downgrade invariant are UNCHANGED and live DOWNSTREAM
//!
//! The shipped #81 design gates a security reducing recovery at FACTOR REMOVAL, not at the
//! session mint: [`crate::recovery::gate_factor_removal`] (keyed on the presence of a pending
//! recovery flow) BLOCKS removing a stronger factor until the notified `hold_until` delay
//! elapses OR a fresh equal or stronger factor is re-verified. This flow recovery is at parity
//! with the bootstrap: it establishes an email factor session (through the existing verify
//! core) and does NOT wire `hold_until` into that mint, because no such gated completion
//! exists in #81. The initiation still creates the #81 recovery flow, so the downgrade
//! invariant still applies to any later factor removal exactly as before (proven in the flow
//! recovery tests, which drive `gate_factor_removal` after a flow initiation). A session level
//! delay gated recovery completion would be a SEPARATE #81 enhancement, not part of this
//! engine.

use ironauth_store::{
    ActorRef, AuthPath, EmailFactorPurpose, FlowRecord, RecoveryEntryPoint, RecoveryMethod, Scope,
};

use super::message::{self, Message};
use super::model::{
    Autocomplete, FlowStateTag, InputType, Node, NodeAttributes, NodeGroup, Transport,
};
use super::{FlowError, Submission};
use crate::authn::AuthenticationEvent;
use crate::email_otp::{self, EmailCodeOutcome};
use crate::interaction;
use crate::recovery::{self, RecoveryFactor};
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The outcome of the recovery INITIATE transition (issue #84).
pub(super) enum RecoveryStartStep {
    /// Stay on the identifier entry state and re-render (an empty identifier validation error).
    /// Existence INDEPENDENT, so it is never an enumeration oracle.
    Render {
        /// The nodes to render (already carrying their node level messages).
        nodes: Vec<Node>,
    },
    /// The uniform acknowledgment: transition to the [`RecoveryAck`](FlowStateTag::RecoveryAck)
    /// state, which carries the code entry. The #81 case creation, the decoy, and the code
    /// delivery all ran (or were suppressed) uniformly; a known and an unknown identifier are
    /// INDISTINGUISHABLE here. `identifier` is stored server side on the flow row so the verify
    /// step checks the code against it without echoing it back to the client.
    Ack {
        /// The submitted identifier, stored on the flow row for the verify step (never echoed).
        identifier: String,
    },
}

/// The outcome of the recovery code VERIFY transition (issue #84).
pub(super) enum RecoveryVerifyStep {
    /// Stay on the ack/code state and re-render (an empty code, a wrong or expired code, or a
    /// throttle rendered as the SAME uniform incorrect code failure). The flow stays OPEN.
    Render {
        /// The nodes to render (already carrying their node level messages).
        nodes: Vec<Node>,
        /// The flow level messages (the uniform acknowledgment stays present).
        messages: Vec<Message>,
    },
    /// The recovery code GENUINELY verified; the driver consumes the single use latch and mints
    /// the email factor session through the ONE choke point. The ONLY branch that consumes.
    Complete(Box<RecoverySuccess>),
}

/// A genuinely completing recovery (issue #84): everything the driver needs to mint the email
/// factor session and relax the recovery path counters, exactly as the hosted `/otp/verify`.
pub(super) struct RecoverySuccess {
    /// The recovered subject (a `usr_` id string).
    pub subject: String,
    /// The audit actor for the session mint.
    pub actor: ActorRef,
    /// The recorded authentication event (an email one time code login at the current instant).
    pub event: AuthenticationEvent,
    /// The recovery path abuse context, so a successful mint relaxes the SAME counters.
    pub ctx: crate::abuse::AttemptContext,
}

/// The transport a loaded flow row was created on.
fn transport_of(record: &FlowRecord) -> Transport {
    if record.transport == Transport::Api.as_str() {
        Transport::Api
    } else {
        Transport::Browser
    }
}

/// Build the recovery identifier entry nodes in the deterministic contract order (issue #84):
/// the identifier field (Default group) plus the submit control (Default group). On the browser
/// transport a hidden `flow` node carries the flow id back on the form post.
fn identifier_nodes(
    transport: Transport,
    flow_id: &str,
    id_error: Option<message::MessageId>,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut identifier = Node::input(
        NodeGroup::Default,
        0,
        NodeAttributes::Input {
            name: "identifier".to_owned(),
            input_type: InputType::Text,
            value: None,
            required: true,
            autocomplete: Some(Autocomplete::Username),
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::RECOVERY_IDENTIFIER_LABEL)),
    );
    if let Some(id) = id_error {
        identifier.messages.push(Message::of(id));
    }
    nodes.push(identifier);
    nodes.push(Node::input(
        NodeGroup::Default,
        10,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("recover".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::RECOVERY_SUBMIT_LABEL)),
    ));
    push_flow_hidden(&mut nodes, transport, flow_id);
    nodes
}

/// The initial recovery nodes for a freshly created flow (issue #84): the identifier entry with
/// no error.
#[must_use]
pub(super) fn start_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    identifier_nodes(transport, flow_id, None)
}

/// The recovery acknowledgment plus code entry nodes (issue #84): the one time code field
/// (`EmailOtp` group) plus submit. The uniform acknowledgment copy is a FLOW LEVEL message the
/// driver attaches, IDENTICAL for a known and an unknown identifier, so the rendered object
/// never distinguishes existence. `code_error` attaches the uniform incorrect code message.
pub(super) fn ack_nodes(transport: Transport, flow_id: &str, code_error: bool) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut code = Node::input(
        NodeGroup::EmailOtp,
        0,
        NodeAttributes::Input {
            name: "code".to_owned(),
            input_type: InputType::Text,
            value: None,
            required: true,
            autocomplete: Some(Autocomplete::OneTimeCode),
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::RECOVERY_CODE_LABEL)),
    );
    if code_error {
        code.messages
            .push(Message::of(message::RECOVERY_CODE_INCORRECT));
    }
    nodes.push(code);
    nodes.push(Node::input(
        NodeGroup::EmailOtp,
        10,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("recover_verify".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::RECOVERY_VERIFY_LABEL)),
    ));
    push_flow_hidden(&mut nodes, transport, flow_id);
    nodes
}

/// The code entry nodes with a REQUIRED validation error on the code node (an empty submit).
fn code_required_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    let mut nodes = ack_nodes(transport, flow_id, false);
    if let Some(code) = nodes.first_mut() {
        code.messages
            .push(Message::of(message::RECOVERY_CODE_REQUIRED));
    }
    nodes
}

/// Push the browser only hidden `flow` node carrying the flow id back on the form post.
fn push_flow_hidden(nodes: &mut Vec<Node>, transport: Transport, flow_id: &str) {
    if matches!(transport, Transport::Browser) {
        nodes.push(Node::input(
            NodeGroup::Default,
            5,
            NodeAttributes::Input {
                name: "flow".to_owned(),
                input_type: InputType::Hidden,
                value: Some(flow_id.to_owned()),
                required: true,
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            None,
        ));
    }
}

/// The state tag a recovery identifier render stays on (issue #84).
#[must_use]
pub(super) fn start_state_tag() -> FlowStateTag {
    FlowStateTag::RecoveryStart
}

/// Advance the recovery INITIATE one step (issue #84), mirroring the bootstrap `recover_post`
/// in the SAME order so the flow recovery is NO WEAKER than `/recover`:
///
/// 1. per node validation (an empty identifier is existence INDEPENDENT, never an oracle);
/// 2. [`OidcState::regulate_before`] on the recovery path counters (a throttle renders the
///    SAME uniform acknowledgment, no send, so it is never an enumeration oracle);
/// 3. the CONVERGENT anti enumeration work: a known identifier runs
///    [`crate::recovery::initiate_recovery`] (the #81 case, held per the downgrade rule) and an
///    unknown one runs [`crate::recovery::decoy_recovery_work`] (the SAME store round trips,
///    no writes), and BOTH deliver the recovery code through
///    [`crate::email_otp::issue_email_code`] (a known recipient gets a code, an unknown one
///    burns the SAME single Argon2 spend, suppressed), then BOTH render the SAME uniform ack.
pub(super) async fn advance_start(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
) -> Result<RecoveryStartStep, FlowError> {
    let transport = transport_of(record);
    let flow_id = record.id.as_str();

    let identifier = submission
        .node_values
        .get("identifier")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim();
    if identifier.is_empty() {
        return Ok(RecoveryStartStep::Render {
            nodes: identifier_nodes(
                transport,
                flow_id,
                Some(message::RECOVERY_IDENTIFIER_REQUIRED),
            ),
        });
    }

    // Proof of work gate (issue #80), at PARITY with the bootstrap `recover_post`. CONDITIONED
    // on the #79 risk level, keyed on the challenge and the peer IP (NEVER on whether the
    // identifier resolves), so it never becomes an enumeration oracle. On an unsolved or absent
    // challenge it renders the SAME uniform acknowledgment a successful initiation renders,
    // performing NO recovery and NO code send, so a known and an unknown identifier stay
    // INDISTINGUISHABLE. The pow fields ride the submission node values on both transports (the
    // browser form and the API `nodes` map), exactly like the registration journey.
    let peer_ip = crate::abuse::resolved_client_ip(headers);
    if crate::pow_gate::challenge_required(state, peer_ip.as_deref(), false) {
        let node_str = |name: &str| {
            submission
                .node_values
                .get(name)
                .and_then(|value| value.as_str())
        };
        let solution = crate::pow_gate::PresentedSolution {
            challenge_id: node_str("pow_challenge_id"),
            nonce: node_str("pow_nonce"),
            context: node_str("pow_context").unwrap_or_default(),
            token: node_str("pow_token"),
            remote_ip: peer_ip.as_deref(),
        };
        if !crate::pow_gate::verify_solution(
            state,
            scope,
            crate::pow_gate::ENDPOINT_RECOVER,
            &solution,
        )
        .await
        {
            return Ok(RecoveryStartStep::Ack {
                identifier: identifier.to_owned(),
            });
        }
    }

    // Recovery path regulation (issue #64), keyed on the canonical identifier and the resolved
    // peer IP, INDEPENDENTLY of the password path. A throttle renders the SAME uniform ack (no
    // send, no #81 case), existence independent, so it is never an enumeration oracle. Every
    // processed attempt is recorded, so recovery request spam climbs the throttle.
    let ctx = crate::abuse::AttemptContext {
        path: AuthPath::Recovery,
        scope,
        ip: crate::abuse::resolved_client_ip(headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id: None,
        client_id: None,
    };
    if state.regulate_before(&ctx).await.is_throttled() {
        return Ok(RecoveryStartStep::Ack {
            identifier: identifier.to_owned(),
        });
    }

    // The convergent anti enumeration work. The lookup runs for both present and absent
    // identifiers; a known account creates the #81 recovery case (through the SAME
    // `initiate_recovery` the bootstrap uses, so the delay/downgrade rule applies), an unknown
    // one runs the decoy (the SAME store round trips, no writes). The RecoveryFactor is the
    // email one time code this surface delivers through, the method is Standard, and the entry
    // point is a lost password, exactly as `recover_post`.
    let client_ip = crate::abuse::resolved_client_ip(headers);
    let resolved = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await;
    if let Ok(Some(user)) = resolved {
        let _ = recovery::initiate_recovery(
            state,
            scope,
            &user.id,
            RecoveryEntryPoint::LostPassword,
            RecoveryFactor::EmailOtp,
            identifier,
            client_ip.as_deref(),
            RecoveryMethod::Standard,
        )
        .await;
    } else {
        recovery::decoy_recovery_work(
            state,
            scope,
            RecoveryEntryPoint::LostPassword,
            RecoveryFactor::EmailOtp,
            identifier,
            client_ip.as_deref(),
        )
        .await;
    }

    // Deliver the recovery one time code through the SAME anti enumeration send core the hosted
    // `/otp/send` uses: a known recipient gets a fresh single active code, an unknown one burns
    // the SAME single Argon2 spend with the send suppressed. This is what the completion verify
    // step later checks, and it keeps the known and unknown Argon2 op counts identical.
    email_otp::issue_email_code(state, scope, EmailFactorPurpose::Recovery, identifier).await;

    Ok(RecoveryStartStep::Ack {
        identifier: identifier.to_owned(),
    })
}

/// Advance the recovery code VERIFY one step (issue #84): verify the presented one time code
/// through the EXISTING [`crate::email_otp::verify_email_code`] core (purpose Recovery), the
/// SAME core the hosted `/otp/verify` drives. On a genuine verification the driver combines it
/// with the completion latch and mints the honest email factor session; a wrong, expired, or
/// throttled code re-renders the SAME uniform incorrect code failure with the flow OPEN.
pub(super) async fn advance_verify(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    identifier: &str,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
) -> Result<RecoveryVerifyStep, FlowError> {
    let transport = transport_of(record);
    let flow_id = record.id.as_str();

    let code = submission
        .node_values
        .get("code")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim();
    if code.is_empty() {
        return Ok(RecoveryVerifyStep::Render {
            nodes: code_required_nodes(transport, flow_id),
            messages: vec![Message::of(message::RECOVERY_ACK)],
        });
    }

    match email_otp::verify_email_code(
        state,
        scope,
        EmailFactorPurpose::Recovery,
        identifier,
        code,
        headers,
    )
    .await
    {
        EmailCodeOutcome::Verified { subject, ctx } => {
            Ok(RecoveryVerifyStep::Complete(Box::new(RecoverySuccess {
                subject: subject.to_string(),
                actor: interaction::user_actor(&subject),
                event: AuthenticationEvent::email_otp(epoch_micros(state.now())),
                ctx,
            })))
        }
        // A wrong/expired/absent code, or a throttle, both render the SAME uniform incorrect
        // code failure with the flow OPEN (existence independent, never an oracle).
        EmailCodeOutcome::Invalid | EmailCodeOutcome::Throttled(_) => {
            Ok(RecoveryVerifyStep::Render {
                nodes: ack_nodes(transport, flow_id, true),
                messages: Vec::new(),
            })
        }
        // A saturated pool or a store fault: the neutral store error (never a 500 to the
        // client, mapped by the driver/transport), never a wrong code oracle.
        EmailCodeOutcome::Rejected(_) | EmailCodeOutcome::ServerError => Err(FlowError::Store),
    }
}
