// SPDX-License-Identifier: MIT OR Apache-2.0

//! The MFA journeys (issue #84): the second factor CHALLENGE and ENROLLMENT as flow states
//! reachable from the login journey after the primary factor succeeds. Like login and
//! registration, every security decision is DELEGATED to the SAME choke point the bootstrap
//! step up (`login.rs` / `totp.rs`) uses, never re-derived here:
//!
//! - the DECISION of whether a second factor is required reuses the SAME tenant baseline
//!   credential class floor ([`crate::step_up::required_credential_class`]) and the SAME
//!   remediation machinery ([`crate::step_up::decide_remediation`]) the `/authorize` step up
//!   gate (issue #72) uses; the engine only renders the challenge/enroll nodes the
//!   remediation asked for, it NEVER decides "is MFA satisfied";
//! - the CHALLENGE verify goes through [`crate::totp::verify_second_factor`], the SAME shared
//!   primitive the hosted `/login/mfa` challenge drives (single use TOTP with drift resync,
//!   then a one time recovery code), on the INDEPENDENT [`ironauth_store::AuthPath::SecondFactor`]
//!   abuse path (issue #64/#72), so an online guess storm is throttled exactly as the hosted
//!   challenge;
//! - the ENROLLMENT goes through [`crate::totp::flow_enroll_begin`] / [`crate::totp::flow_enroll_verify`],
//!   which reuse the SAME store enroll primitives the account surface uses (a factor is NOT
//!   active until a valid current code proves possession);
//! - the amr/acr HONESTY (issues #14/#71/#72): a factor appears in the token amr ONLY because
//!   a REAL ceremony ran. On completion the driver mints the session through
//!   [`crate::interaction::establish_session`] with an [`AuthenticationEvent::from_methods`]
//!   built from the primary factor PLUS the factor just genuinely proven, so the token
//!   reflects what ACTUALLY happened, never a fabricated `mfa`.

use ironauth_store::{FlowRecord, Scope, UserId};

use super::message::{self, Message};
use super::model::{
    Autocomplete, FlowStateTag, InputType, Node, NodeAttributes, NodeGroup, Transport,
};
use super::{FlowError, Submission};
use crate::authn::{self, AuthMethod, CredentialClass};
use crate::state::OidcState;
use crate::totp::{self, SecondFactorOutcome};

/// What the login journey must do after the primary factor succeeds (issue #84): complete
/// straight away, or transition to an in flow second factor challenge or enrollment.
pub(super) enum MfaPlan {
    /// No in flow second factor is required: complete the login as it stands.
    Complete,
    /// Challenge an already enrolled second factor (a live TOTP or recovery code).
    Challenge,
    /// Enroll a TOTP second factor (the subject has none but tenant policy allows it).
    Enroll,
}

/// The outcome of one MFA transition (issue #84).
pub(super) enum MfaStep {
    /// Stay on the challenge/enroll state and re-render (a per node validation error, the
    /// uniform incorrect code failure, or a throttle rendered as that same uniform failure).
    /// The flow stays OPEN (never consumed), so this branch is never a completion oracle.
    Render {
        /// The nodes to render (already carrying their node level messages).
        nodes: Vec<Node>,
        /// The flow level messages.
        messages: Vec<Message>,
    },
    /// The second factor was GENUINELY proven; the driver combines it with the primary
    /// factor, consumes the single use latch, and mints the session with the honest amr/acr.
    /// This is the ONLY branch that consumes the flow. `new_method` is the factor the real
    /// ceremony proved (never fabricated).
    Complete {
        /// The second factor genuinely proven (TOTP or recovery code).
        new_method: AuthMethod,
    },
}

/// Decide, after the primary factor succeeded, whether an in flow second factor is required
/// (issue #84), reusing the SAME tenant baseline floor and remediation machinery the
/// `/authorize` step up gate (issue #72) uses.
pub(super) async fn plan_after_primary(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    methods: &[AuthMethod],
) -> MfaPlan {
    // Only the tenant BASELINE MFA credential class floor triggers an in flow second factor.
    // Stronger passkey/attested floors and explicit per request acr step up remain the
    // `/authorize` gate's job (a native passkey ceremony is out of the flow's JSON scope);
    // they are enforced when the completed primary session resumes `/authorize`, which never
    // issues an over qualified token.
    if crate::step_up::required_credential_class(state, scope).await != CredentialClass::Mfa {
        return MfaPlan::Complete;
    }
    // A GENUINE second factor already performed (a real TOTP/recovery code or a user
    // verified passkey) satisfies the baseline with no extra prompt (the conditional
    // credential skip, issue #71).
    if authn::performed_second_factor(methods) {
        return MfaPlan::Complete;
    }
    // Route through the SAME remediation the step up gate uses, with a synthetic mfa floor.
    let requirement = crate::step_up::AuthnRequirement {
        min_acr: Some(authn::acr_for_mfa().to_owned()),
        max_auth_age_secs: None,
    };
    match crate::step_up::decide_remediation(state, scope, subject, &requirement, true, false).await
    {
        crate::step_up::Remediation::SecondFactor => MfaPlan::Challenge,
        // Enrollment is offered only where the flow can actually drive it (TOTP). A tenant
        // that only offers passkey enrollment falls through to Complete (native passkey is
        // out of the flow's JSON scope; the `/authorize` gate remediates).
        crate::step_up::Remediation::Enroll if state.totp_enabled() => MfaPlan::Enroll,
        // PasskeyReauth / FullReauth / Fail / passkey only enroll: complete the honest
        // primary session and let the `/authorize` gate remediate.
        crate::step_up::Remediation::Enroll
        | crate::step_up::Remediation::PasskeyReauth
        | crate::step_up::Remediation::FullReauth
        | crate::step_up::Remediation::Fail => MfaPlan::Complete,
    }
}

/// The MFA challenge nodes (issue #84): a single authentication code field (a TOTP code OR a
/// one time recovery code, both accepted by [`totp::verify_second_factor`]) plus the submit
/// control. On the browser transport a hidden `flow` node carries the flow id back.
fn challenge_nodes(transport: Transport, flow_id: &str, code_error: bool) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut code = Node::input(
        NodeGroup::Totp,
        0,
        NodeAttributes::Input {
            name: "code".to_owned(),
            input_type: InputType::Text,
            value: None,
            required: true,
            autocomplete: Some(Autocomplete::OneTimeCode),
            disabled: false,
        },
        Some(Message::of(message::MFA_CODE_LABEL)),
    );
    if code_error {
        code.messages.push(Message::of(message::MFA_CODE_INCORRECT));
    }
    nodes.push(code);
    nodes.push(Node::input(
        NodeGroup::Totp,
        10,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("totp".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
        },
        Some(Message::of(message::MFA_SUBMIT_LABEL)),
    ));
    push_flow_hidden(&mut nodes, transport, flow_id);
    nodes
}

/// The challenge nodes with a REQUIRED validation error on the code node (an empty submit).
fn challenge_required_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    let mut nodes = challenge_nodes(transport, flow_id, false);
    if let Some(code) = nodes.first_mut() {
        code.messages.push(Message::of(message::MFA_CODE_REQUIRED));
    }
    nodes
}

/// Build the MFA challenge nodes for the driver's transition INTO the challenge state.
#[must_use]
pub(super) fn challenge_start_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    challenge_nodes(transport, flow_id, false)
}

/// The MFA enrollment nodes (issue #84): the provisioning material to add the factor (the
/// `otpauth://` URI and the grouped secret, as display only fields a client renders as a QR
/// or manual entry), plus the confirmation code field and submit control. The secret is
/// rebuilt from the sealed pending row on every render; it never lands on the flow row.
pub(super) fn enroll_nodes(
    transport: Transport,
    flow_id: &str,
    begin: &totp::FlowEnrollBegin,
    code_error: bool,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    nodes.push(Node {
        group: NodeGroup::Default,
        attributes: NodeAttributes::Text {
            message: Message::of(message::MFA_ENROLL_INSTRUCTIONS),
        },
        label: None,
        messages: Vec::new(),
        sequence: 0,
    });
    // Display only provisioning fields (disabled, so a browser never submits them).
    nodes.push(Node::input(
        NodeGroup::Totp,
        0,
        NodeAttributes::Input {
            name: "otpauth_uri".to_owned(),
            input_type: InputType::Text,
            value: Some(begin.otpauth_uri.clone()),
            required: false,
            autocomplete: None,
            disabled: true,
        },
        None,
    ));
    nodes.push(Node::input(
        NodeGroup::Totp,
        1,
        NodeAttributes::Input {
            name: "totp_secret".to_owned(),
            input_type: InputType::Text,
            value: Some(begin.secret.clone()),
            required: false,
            autocomplete: None,
            disabled: true,
        },
        None,
    ));
    let mut code = Node::input(
        NodeGroup::Totp,
        2,
        NodeAttributes::Input {
            name: "code".to_owned(),
            input_type: InputType::Text,
            value: None,
            required: true,
            autocomplete: Some(Autocomplete::OneTimeCode),
            disabled: false,
        },
        Some(Message::of(message::MFA_CODE_LABEL)),
    );
    if code_error {
        code.messages.push(Message::of(message::MFA_CODE_INCORRECT));
    }
    nodes.push(code);
    nodes.push(Node::input(
        NodeGroup::Totp,
        3,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("totp".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
        },
        Some(Message::of(message::MFA_SUBMIT_LABEL)),
    ));
    push_flow_hidden(&mut nodes, transport, flow_id);
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
            },
            None,
        ));
    }
}

/// The submitted code from the challenge/enroll form.
fn submitted_code(submission: &Submission) -> String {
    submission
        .node_values
        .get("code")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_owned()
}

/// Advance the MFA challenge one step (issue #84): verify the presented second factor through
/// the SAME shared primitive the hosted `/login/mfa` challenge uses, on the INDEPENDENT
/// second factor abuse path. On a genuine verification, return the factor for the driver to
/// combine with the primary and mint the honest session; otherwise re-render the uniform
/// failure with the flow OPEN.
pub(super) async fn advance_challenge(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    subject: &UserId,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
) -> Result<MfaStep, FlowError> {
    let transport = transport_of(record);
    let flow_id = record.id.as_str();
    let code = submitted_code(submission);
    if code.is_empty() {
        return Ok(MfaStep::Render {
            nodes: challenge_required_nodes(transport, flow_id),
            messages: Vec::new(),
        });
    }

    // Second factor abuse regulation (issue #64/#72) on the INDEPENDENT SecondFactor path
    // BEFORE any code is verified. A throttle renders the SAME uniform incorrect code failure
    // a wrong code renders (existence independent), so it is never an oracle. A throttled
    // attempt spends NO verification.
    let ctx = crate::abuse::second_factor_attempt_context(scope, subject, headers);
    if state.regulate_before(&ctx).await.is_throttled() {
        return Ok(MfaStep::Render {
            nodes: challenge_nodes(transport, flow_id, true),
            messages: Vec::new(),
        });
    }

    let new_method = match totp::verify_second_factor(state, scope, subject, &code).await {
        SecondFactorOutcome::Totp => AuthMethod::Totp,
        SecondFactorOutcome::Recovery => AuthMethod::RecoveryCode,
        SecondFactorOutcome::Invalid => {
            return Ok(MfaStep::Render {
                nodes: challenge_nodes(transport, flow_id, true),
                messages: Vec::new(),
            });
        }
        // A retryable server condition or a store fault: the neutral store error, never a
        // wrong code signal (never a 500 to the client, mapped by the driver/transport).
        SecondFactorOutcome::Unavailable | SecondFactorOutcome::Error => {
            return Err(FlowError::Store);
        }
    };
    // A proven second factor relaxes THIS path's failure counters (issue #64), best effort.
    state.reset_after_success(&ctx).await;
    Ok(MfaStep::Complete { new_method })
}

/// Begin a TOTP enrollment for the transition INTO the enroll state (issue #84): mint the
/// pending factor through the shared ceremony and return the provisioning material to render
/// plus the pending credential id to carry on the flow row.
pub(super) async fn begin_enroll(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
) -> Result<totp::FlowEnrollBegin, FlowError> {
    totp::flow_enroll_begin(state, scope, subject)
        .await
        .map_err(|()| FlowError::Store)
}

/// Advance the MFA enrollment one step (issue #84): confirm the presented code against the
/// pending seed through the SAME store enroll ceremony the account surface uses. On a valid
/// code the factor is activated (the just proven code is a GENUINE second factor) and the
/// driver completes with the honest amr/acr; a wrong code re-renders the SAME provisioning
/// material with the flow OPEN.
pub(super) async fn advance_enroll(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    subject: &UserId,
    credential_id: &str,
    submission: &Submission,
) -> Result<MfaStep, FlowError> {
    let transport = transport_of(record);
    let flow_id = record.id.as_str();
    let code = submitted_code(submission);

    // Rebuild the provisioning material for a re-render (the pending row still holds the
    // sealed seed), so the secret is shown consistently and never stored on the flow row.
    let rerender = |code_error: bool, begin: &totp::FlowEnrollBegin| MfaStep::Render {
        nodes: enroll_nodes(transport, flow_id, begin, code_error),
        messages: Vec::new(),
    };

    if code.is_empty() {
        let Some(begin) = totp::flow_enroll_material(state, scope, subject, credential_id).await
        else {
            return Err(FlowError::Store);
        };
        let mut nodes = enroll_nodes(transport, flow_id, &begin, false);
        if let Some(code_node) = nodes.iter_mut().find(
            |node| matches!(&node.attributes, NodeAttributes::Input { name, .. } if name == "code"),
        ) {
            code_node
                .messages
                .push(Message::of(message::MFA_CODE_REQUIRED));
        }
        return Ok(MfaStep::Render {
            nodes,
            messages: Vec::new(),
        });
    }

    match totp::flow_enroll_verify(state, scope, subject, credential_id, &code).await {
        totp::FlowEnrollOutcome::Activated { recovery_codes } => {
            // The recovery codes are minted and stored by the shared ceremony (available on
            // the account surface); the just proven code is a genuine TOTP second factor.
            let _ = recovery_codes;
            Ok(MfaStep::Complete {
                new_method: AuthMethod::Totp,
            })
        }
        totp::FlowEnrollOutcome::Invalid => {
            let Some(begin) =
                totp::flow_enroll_material(state, scope, subject, credential_id).await
            else {
                return Err(FlowError::Store);
            };
            Ok(rerender(true, &begin))
        }
        // The pending enrollment vanished (expired/consumed) or a store fault: the neutral
        // store error, never a 500 to the client.
        totp::FlowEnrollOutcome::NotFound | totp::FlowEnrollOutcome::Error => Err(FlowError::Store),
    }
}

/// The transport a loaded flow row was created on.
fn transport_of(record: &FlowRecord) -> Transport {
    if record.transport == Transport::Api.as_str() {
        Transport::Api
    } else {
        Transport::Browser
    }
}

/// The state tag an MFA challenge render stays on.
#[must_use]
pub(super) fn challenge_state_tag() -> FlowStateTag {
    FlowStateTag::MfaChallenge
}

/// The state tag an MFA enroll render stays on.
#[must_use]
pub(super) fn enroll_state_tag() -> FlowStateTag {
    FlowStateTag::MfaEnroll
}
