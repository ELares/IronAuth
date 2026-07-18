// SPDX-License-Identifier: MIT OR Apache-2.0

//! The login journey (issue #84): the identifier plus password first factor as a flow
//! state machine. Every security decision is delegated to an EXISTING choke point, never
//! re-derived here:
//!
//! - the password verify and the anti enumeration dummy spend go through
//!   [`OidcState::verify_password`] / [`OidcState::verify_absent`] (state.rs, issue #62),
//!   the SAME admission controlled primitives the bootstrap login path uses;
//! - the credential abuse layer (issue #64 / #79) is the SAME one the bootstrap
//!   `login_post` runs, in the SAME order: [`OidcState::regulate_before`] (the durable
//!   operator/auto ban check plus the per identifier/IP failure escalation) BEFORE the
//!   verify, [`crate::risk::record_attempt`] plus [`crate::risk::evaluate`] with a
//!   `RiskAction::Block` short circuiting to the uniform failure before any mint, and
//!   [`OidcState::reset_after_success`] on a genuine completion. So the flow login is NO
//!   WEAKER than `/login`: a ban, a throttle, and a risk block all defeat guessing here
//!   too, and every attempt feeds the SAME shared counters;
//! - the session mint goes through [`crate::interaction::establish_session`] (the ONE
//!   session mint and lifecycle fence, issue #80), called by the driver after the single
//!   use completion latch trips.
//!
//! The anti enumeration crux (issue #64, this issue's security bar): the found, the
//! unknown, the fenced, the banned/throttled, and the risk blocked branches ALL CONVERGE
//! on ONE flow building expression ([`uniform_incorrect_nodes`]) and the SAME single
//! Argon2 spend where a verify is applicable, so a per node validation error, a ban, a
//! throttle, or a block never discloses whether the identifier exists, on either
//! transport. A ban/throttle/block renders as the uniform incorrect nodes (byte identical
//! to a wrong password), so it is never an enumeration oracle -- stronger than `/login`,
//! which surfaces a distinguishable 429 onset.
//!
//! Deferred (issue #55): an account imported with only a FOREIGN password hash (not yet
//! migrated) cannot log in through this flow yet -- [`spend_verify`] has no foreign verify
//! arm and routes the sentinel native hash through the dummy spend, so such an account
//! reads as a wrong password here. This is a journey completeness gap, not a security
//! weakness (the bootstrap `/login` still migrates them, and the flow is flag off); the
//! foreign verify arm lands with the journey follow up.

use ironauth_store::{FlowRecord, Scope, UserId, UserRecord};

use super::message::{self, Message};
use super::model::{
    Autocomplete, FlowStateTag, InputType, Node, NodeAttributes, NodeGroup, Transport,
};
use super::{FlowError, Submission};
use crate::authn::AuthenticationEvent;
use crate::interaction;
use crate::risk::RiskDecision;
use crate::state::OidcState;
use crate::util::epoch_micros;
use ironauth_store::{ActorRef, AuthPath};

/// The outcome of one login transition (issue #84). The driver turns [`Render`] into a
/// re-rendered flow (rotating the API submit token) and [`Complete`] into the single use
/// completion latch plus the [`establish_session`](crate::interaction::establish_session)
/// mint.
pub(super) enum LoginStep {
    /// Stay on the identifier plus password state and re-render (a validation error, the
    /// uniform authentication failure, or a ban/throttle/block rendered as that SAME
    /// uniform failure). The nodes already carry any node level messages, and the flow
    /// stays OPEN (never consumed), so this branch is never a completion oracle.
    Render {
        /// The nodes to render (already carrying their node level messages).
        nodes: Vec<Node>,
    },
    /// The first factor GENUINELY succeeded (a correct credential AND an authenticatable
    /// account AND no risk block); the driver consumes the single use latch and mints the
    /// session. This is the ONLY branch that consumes the flow.
    Complete(Box<LoginSuccess>),
}

/// A genuinely completing login (issue #84): everything the driver needs to mint the
/// session AND run the post success credential abuse follow through
/// ([`OidcState::reset_after_success`] plus [`crate::risk::after_successful_login`]) after
/// the mint, exactly as the bootstrap `login_post` does.
pub(super) struct LoginSuccess {
    /// The authenticated subject (a `usr_` id string).
    pub subject: String,
    /// The authenticated subject as a typed id (for the risk follow through).
    pub user_id: UserId,
    /// The audit actor for the session mint.
    pub actor: ActorRef,
    /// The recorded authentication event (a password login at the current instant).
    pub event: AuthenticationEvent,
    /// The credential abuse attempt context, so a successful mint RESETS the SAME failure
    /// counters the pre verify [`OidcState::regulate_before`] recorded.
    pub ctx: crate::abuse::AttemptContext,
    /// The risk decision to persist (and, on a new device, notify) after the mint.
    pub risk_decision: RiskDecision,
    /// The submitted identifier, the recipient for a new device notice.
    pub identifier: String,
}

/// Build the identifier plus password nodes in the deterministic contract order (issue
/// #84). `identifier_prefill` seeds the identifier field (never a secret); `id_error` and
/// `pw_error` attach a node level message to the identifier or password node. On the
/// browser transport a hidden `flow` node carries the flow id back on the form post.
fn identifier_password_nodes(
    transport: Transport,
    flow_id: &str,
    identifier_prefill: &str,
    id_error: Option<message::MessageId>,
    pw_error: Option<message::MessageId>,
) -> Vec<Node> {
    let mut nodes = Vec::new();

    // Default group: the identifier field.
    let mut identifier = Node::input(
        NodeGroup::Default,
        0,
        NodeAttributes::Input {
            name: "identifier".to_owned(),
            input_type: InputType::Text,
            value: if identifier_prefill.is_empty() {
                None
            } else {
                Some(identifier_prefill.to_owned())
            },
            required: true,
            autocomplete: Some(Autocomplete::Username),
            disabled: false,
        },
        Some(Message::of(message::LOGIN_IDENTIFIER_LABEL)),
    );
    if let Some(id) = id_error {
        identifier.messages.push(Message::of(id));
    }
    nodes.push(identifier);

    // Password group: the password field and the submit control.
    let mut password = Node::input(
        NodeGroup::Password,
        0,
        NodeAttributes::Input {
            name: "password".to_owned(),
            input_type: InputType::Password,
            value: None,
            required: true,
            autocomplete: Some(Autocomplete::CurrentPassword),
            disabled: false,
        },
        Some(Message::of(message::LOGIN_PASSWORD_LABEL)),
    );
    if let Some(id) = pw_error {
        password.messages.push(Message::of(id));
    }
    nodes.push(password);

    nodes.push(Node::input(
        NodeGroup::Password,
        10,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("password".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
        },
        Some(Message::of(message::LOGIN_SUBMIT_LABEL)),
    ));

    // The browser transport carries the flow id back on the form post through a hidden
    // field; the API transport puts the id in the JSON body instead, so this node is
    // browser only (the ONE structural transport difference in node assembly).
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
            },
            None,
        ));
    }

    nodes
}

/// The initial login nodes for a freshly created flow (issue #84): the identifier plus
/// password form with no errors and no prefill.
#[must_use]
pub(super) fn start_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    identifier_password_nodes(transport, flow_id, "", None, None)
}

/// The UNIFORM authentication failure render (issue #84, the anti enumeration crux): the
/// identifier plus password form re-rendered with the SAME node level "incorrect
/// identifier or password" message on the password node, regardless of whether the
/// identifier exists. This is the ONE flow building expression the found and unknown
/// branches both return, so the rendered object is BYTE IDENTICAL between them. The
/// identifier is deliberately NOT echoed back (no prefill), so the uniform render reveals
/// nothing, not even the typed input, and the found and unknown UIs are indistinguishable.
#[must_use]
fn uniform_incorrect_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    identifier_password_nodes(
        transport,
        flow_id,
        "",
        None,
        Some(message::LOGIN_IDENTIFIER_OR_PASSWORD_INCORRECT),
    )
}

/// The uniform incorrect render exposed to the driver (used when the lifecycle fence
/// refuses a session AFTER the completion latch tripped, so the response stays the uniform
/// authentication failure rather than a 500).
#[must_use]
pub(super) fn uniform_incorrect_render(transport: Transport, flow_id: &str) -> Vec<Node> {
    uniform_incorrect_nodes(transport, flow_id)
}

/// Spend the ONE Argon2 op for a resolved account (issue #84), returning whether the
/// native hash verified. When the account carries a usable native hash this is the real
/// verify; otherwise it routes through the SAME dummy [`verify_absent`] spend the unknown
/// branch uses, so a passkey only / not yet migrated account stays timing uniform with an
/// absent account (issue #66 LOW-2) and never verifies. The flow has no foreign hash arm
/// (issue #55, deferred), so a foreign only account reads as a wrong password here.
async fn spend_verify(
    state: &OidcState,
    scope: &Scope,
    password: &str,
    user: &UserRecord,
) -> Result<bool, FlowError> {
    if user.has_usable_password_hash() {
        state
            .verify_password(scope, password, &user.password_hash)
            .await
            .map_err(|_| FlowError::Store)
    } else {
        state
            .verify_absent(scope, password)
            .await
            .map_err(|_| FlowError::Store)?;
        Ok(false)
    }
}

/// The observed User-Agent for a risk evaluation (issue #79), or `"unknown"` when absent,
/// mirroring the bootstrap `login_post`. Shared with the driver's post success follow
/// through so both read the SAME header.
#[must_use]
pub(super) fn user_agent_of(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| "unknown".to_owned(), str::to_owned)
}

/// Advance the login journey one step (issue #84). Returns the transition outcome; the
/// driver handles persistence, the completion latch, and the session mint.
///
/// This reproduces the bootstrap `login_post` credential abuse sequence in the SAME order
/// so the flow login is NO WEAKER than `/login`:
///
/// 1. look the account up, then run [`OidcState::regulate_before`] (the ban check plus the
///    per identifier/IP failure escalation) on the SAME existence independent dimensions;
///    a ban/throttle renders the uniform failure (no verify spent, flow OPEN);
/// 2. accumulate the risk velocity ([`crate::risk::record_attempt`]);
/// 3. the CONVERGENT verify spend (the anti enumeration crux): the found, unknown, and
///    fenced branches ALL spend exactly one Argon2 op and ALL return the SAME
///    [`uniform_incorrect_nodes`] render on a failure, so no branch adds or removes a node
///    or message based on existence;
/// 4. a fenced (non authenticatable) account is treated EXACTLY like a wrong password
///    (uniform render, flow OPEN, no consume), so a correct password against a fenced
///    account is never a completion oracle (the MEDIUM-2 fix) -- and
///    [`establish_session`](crate::interaction::establish_session) still re checks the
///    SAME fence at the mint (defense in depth);
/// 5. [`crate::risk::evaluate`] before any mint, a `RiskAction::Block` short circuiting to
///    the uniform failure (no session), exactly as `login_post`.
// The linear credential-abuse sequence (lookup, regulate, record, verify, fence, risk)
// reads best as one function; splitting it would scatter the anti-enumeration and
// no-weaker-than-/login invariants across helpers, so the length lint is allowed here
// (mirroring the bootstrap `login_post`).
#[allow(clippy::too_many_lines)]
pub(super) async fn advance_login(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
) -> Result<LoginStep, FlowError> {
    let transport = if record.transport == Transport::Api.as_str() {
        Transport::Api
    } else {
        Transport::Browser
    };
    let flow_id = record.id.as_str();

    let identifier = submission
        .node_values
        .get("identifier")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim();
    let password = submission
        .node_values
        .get("password")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    // Per node validation. An empty field is NOT an enumeration oracle (it does not depend
    // on whether the identifier exists) and is not a credential guess, so it returns the
    // required message on the offending node before any lookup or regulation.
    let id_error = identifier
        .is_empty()
        .then_some(message::LOGIN_IDENTIFIER_REQUIRED);
    let pw_error = password
        .is_empty()
        .then_some(message::LOGIN_PASSWORD_REQUIRED);
    if id_error.is_some() || pw_error.is_some() {
        return Ok(LoginStep::Render {
            nodes: identifier_password_nodes(transport, flow_id, identifier, id_error, pw_error),
        });
    }

    // The account lookup. Kept ahead of the throttle so a present and an absent identifier
    // pay the SAME lookup work before any regulation, exactly as `login_post`.
    let Ok(user) = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
    else {
        return Err(FlowError::Store);
    };

    // The credential abuse context, keyed on the SAME existence independent dimensions the
    // bootstrap login uses: the CANONICAL identifier (the #54 seam) and the non forgeable
    // resolved peer IP (the #31 lesson). The account id is threaded in when the identifier
    // resolved, so a manual per account ban applies; the throttle escalation itself keys
    // only on the identifier + IP dimensions, so it never distinguishes present from absent.
    let account_id = user.as_ref().map(|user| user.id.to_string());
    let ctx = crate::abuse::AttemptContext {
        path: AuthPath::Password,
        scope,
        ip: crate::abuse::resolved_client_ip(headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id,
        client_id: None,
    };

    // 1. Regulate BEFORE the verify: the durable ban check plus the failure escalation. A
    //    ban or an over threshold escalation renders the SAME uniform incorrect nodes as a
    //    wrong password (byte identical, existence independent, no verify spent), so it is
    //    never an enumeration oracle -- stronger than `/login`'s distinguishable 429.
    if state.regulate_before(&ctx).await.is_throttled() {
        return Ok(LoginStep::Render {
            nodes: uniform_incorrect_nodes(transport, flow_id),
        });
    }

    // 2. Risk velocity accumulation (issue #79): count this attempt so a flood accrues on
    //    the SAME shared counters. Inert unless the risk engine + velocity signal are on.
    let risk_subject = user.as_ref().map(|user| user.id);
    crate::risk::record_attempt(state, risk_subject.as_ref(), ctx.ip.as_deref());

    match user {
        // A fenced (blocked/disabled/pending/waitlisted) account: spend the ONE Argon2 op
        // for timing uniformity, then the SAME uniform failure -- and the flow stays OPEN
        // (no consume). So a correct password against a fenced account is
        // indistinguishable from a wrong one AND is never a completion oracle: a second
        // submit behaves identically to a wrong password's second submit (the MEDIUM-2
        // fix). The central fence in `establish_session` still re checks this at the mint.
        Some(user) if !user.state.can_authenticate() => {
            let _ = spend_verify(state, &scope, password, &user).await?;
            Ok(LoginStep::Render {
                nodes: uniform_incorrect_nodes(transport, flow_id),
            })
        }
        Some(user) => {
            // 3. The convergent verify spend.
            let native_ok = spend_verify(state, &scope, password, &user).await?;
            if !native_ok {
                return Ok(LoginStep::Render {
                    nodes: uniform_incorrect_nodes(transport, flow_id),
                });
            }
            // 5. Risk evaluation BEFORE the mint: a BLOCK yields the SAME uniform failure a
            //    wrong password does (anti enumeration), with NO session created. The
            //    decision is still recorded (detached) so a block is reconstructable.
            let user_agent = user_agent_of(headers);
            let risk_ctx = crate::risk::RiskContext {
                ip: ctx.ip.as_deref(),
                user_agent: &user_agent,
                headers,
            };
            let risk_decision = crate::risk::evaluate(state, scope, &user.id, &risk_ctx).await;
            if matches!(risk_decision.action, crate::risk::RiskAction::Block) {
                crate::risk::record_decision_detached(state, scope, &user.id, &risk_decision);
                return Ok(LoginStep::Render {
                    nodes: uniform_incorrect_nodes(transport, flow_id),
                });
            }
            Ok(LoginStep::Complete(Box::new(LoginSuccess {
                subject: user.id.to_string(),
                user_id: user.id,
                actor: interaction::user_actor(&user.id),
                event: AuthenticationEvent::password(epoch_micros(state.now())),
                ctx,
                risk_decision,
                identifier: identifier.to_owned(),
            })))
        }
        None => {
            // One Argon2 op on the unknown branch (the sentinel spend), then the SAME
            // uniform render as the found-but-wrong branch above.
            state
                .verify_absent(&scope, password)
                .await
                .map_err(|_| FlowError::Store)?;
            Ok(LoginStep::Render {
                nodes: uniform_incorrect_nodes(transport, flow_id),
            })
        }
    }
}

/// The state tag a login render stays on (issue #84): the identifier plus password state.
#[must_use]
pub(super) fn render_state_tag() -> FlowStateTag {
    FlowStateTag::IdentifierPassword
}
