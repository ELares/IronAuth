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
//!   active until a valid current code proves possession), and the recovery codes that ceremony
//!   mints are rendered SHOW ONCE (issue #311) on the interstitial
//!   [`FlowStateTag::MfaRecoveryCodes`](super::model::FlowStateTag::MfaRecoveryCodes) state, exactly
//!   as the direct account `enroll_verify` returns them in its response body, so an in flow
//!   enroller sees their codes at the moment they are created instead of having to go find them;
//! - the amr/acr HONESTY (issues #14/#71/#72): a factor appears in the token amr ONLY because
//!   a REAL ceremony ran. On completion the driver mints the session through
//!   [`crate::interaction::establish_session`] with an [`AuthenticationEvent::from_methods`]
//!   built from the primary factor PLUS the factor just genuinely proven, so the token
//!   reflects what ACTUALLY happened, never a fabricated `mfa`.
//!
//! ## Two things the imperative surface has that this one does not
//!
//! Recorded here plainly, pre-existing, and filed separately rather than changed under issue #311.
//! Both make a flow engine login WEAKER or more tedious than the same login through the hosted
//! pages, which is the opposite of what the convergence is for.
//!
//! - NO trusted device. `crate::trusted_device::remember_device` is live and NOT dead code: the
//!   hosted `/login/mfa` page renders a real "remember this device" checkbox (`pages.rs`) and
//!   `login.rs` acts on it. The narrow true statement is that the symbol `remember_device` has ZERO
//!   references anywhere under `src/flow/`, so a user who completes MFA through the flow engine
//!   never gets a trusted device cookie even when `trusted_devices_enabled` is on, and is
//!   re-challenged on every login.
//! - NO passkey group. [`super::model::NodeGroup::Passkey`] exists and
//!   [`super::render`] is fully wired to render it as the WebAuthn ceremony under a nonce CSP, but
//!   no node builder in this module or its siblings ever emits a node in that group outside tests.
//!   A flow login therefore cannot offer the phishing resistant factor at all, while the bootstrap
//!   login page can.

use ironauth_store::{FlowRecord, Scope, UserId};

use super::message::{self, Message, MessageContext};
use super::model::{Autocomplete, InputType, Node, NodeAttributes, NodeGroup, Transport};
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
    /// The SHOW ONCE recovery codes interstitial (issue #311): the enrollment activated the
    /// factor and the shared ceremony minted a fresh recovery code set, so render it ONCE on the
    /// [`FlowStateTag::MfaRecoveryCodes`](super::model::FlowStateTag::MfaRecoveryCodes) wire state
    /// and hold the flow OPEN until the user acknowledges. Also the arm the acknowledgment step
    /// re-renders through when the acknowledgment is missing, which is why the nodes are carried
    /// (the codes are NOT: a re-render has no source for them, by construction).
    RecoveryCodes {
        /// The nodes to render (the codes on the minting render, the acknowledgment alone on any
        /// later one).
        nodes: Vec<Node>,
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
    match crate::step_up::decide_remediation(
        state,
        scope,
        subject,
        &requirement,
        true,
        false,
        false,
    )
    .await
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
            constraints: None,
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
            constraints: None,
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
            constraints: None,
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
            constraints: None,
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
            constraints: None,
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
            constraints: None,
        },
        Some(Message::of(message::MFA_SUBMIT_LABEL)),
    ));
    push_flow_hidden(&mut nodes, transport, flow_id);
    nodes
}

/// The form field name of the show once recovery codes acknowledgment checkbox (issue #311).
pub(crate) const RECOVERY_CODES_ACK_FIELD: &str = "recovery_codes_acknowledged";

/// The node `sequence` the acknowledgment checkbox takes inside the recovery code group (issue
/// #311). Above any code node's sequence: the code count is config bounded to `8..=16`
/// (`oidc.totp_recovery_code_count`), and the codes take sequences `1..=count`, so the
/// acknowledgment and the continue control always sort last within the group.
const RECOVERY_CODES_ACK_SEQUENCE: u16 = 100;

/// The SHOW ONCE recovery code nodes (issue #311): the codes an in flow TOTP enrollment just
/// minted, as DISPLAY ONLY fields (disabled, so a browser never posts them back), plus the
/// acknowledgment checkbox and the continue control that let the login finish.
///
/// `codes` is `Some` on EXACTLY ONE render: the response to the submission whose valid
/// confirmation code activated the factor, built straight from the transient mint result. Every
/// later render of this state (a back navigation, a replay, a resumed flow, the read only flow
/// inspector) passes `None`, because there is nowhere to read them back from: the flow row never
/// held them and the store keeps only their Argon2 hashes. That `None` render carries the
/// [`message::MFA_RECOVERY_CODES_UNAVAILABLE`] notice and NO code node, so show once is a property
/// of the data flow, not a rule this function is trusted to follow.
pub(super) fn recovery_codes_nodes(
    transport: Transport,
    flow_id: &str,
    codes: Option<&[String]>,
    ack_error: bool,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    match codes {
        Some(codes) => {
            nodes.push(Node {
                group: NodeGroup::RecoveryCode,
                attributes: NodeAttributes::Text {
                    message: Message::with_context(
                        message::MFA_RECOVERY_CODES_INSTRUCTIONS,
                        MessageContext::one("count", &codes.len().to_string()),
                    ),
                },
                label: None,
                messages: Vec::new(),
                sequence: 0,
            });
            for (index, code) in codes.iter().enumerate() {
                let ordinal = index.saturating_add(1);
                nodes.push(Node::input(
                    NodeGroup::RecoveryCode,
                    u16::try_from(ordinal).unwrap_or(u16::MAX),
                    NodeAttributes::Input {
                        name: format!("recovery_code_{ordinal}"),
                        input_type: InputType::Text,
                        value: Some(code.clone()),
                        required: false,
                        autocomplete: None,
                        disabled: true,
                        constraints: None,
                    },
                    Some(Message::of(message::MFA_RECOVERY_CODE_LABEL)),
                ));
            }
        }
        // No codes to render: say so plainly rather than render an empty list that reads as
        // "you were issued nothing".
        None => nodes.push(Node {
            group: NodeGroup::RecoveryCode,
            attributes: NodeAttributes::Text {
                message: Message::of(message::MFA_RECOVERY_CODES_UNAVAILABLE),
            },
            label: None,
            messages: Vec::new(),
            sequence: 0,
        }),
    }
    let mut ack = Node::input(
        NodeGroup::RecoveryCode,
        RECOVERY_CODES_ACK_SEQUENCE,
        NodeAttributes::Input {
            name: RECOVERY_CODES_ACK_FIELD.to_owned(),
            input_type: InputType::Checkbox,
            value: None,
            required: true,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::MFA_RECOVERY_CODES_ACK_LABEL)),
    );
    if ack_error {
        ack.messages
            .push(Message::of(message::MFA_RECOVERY_CODES_ACK_REQUIRED));
    }
    nodes.push(ack);
    nodes.push(Node::input(
        NodeGroup::RecoveryCode,
        RECOVERY_CODES_ACK_SEQUENCE.saturating_add(1),
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("recovery_codes_ack".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::MFA_RECOVERY_CODES_CONTINUE_LABEL)),
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
                constraints: None,
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
            // The just proven code is a genuine TOTP second factor, and the shared ceremony
            // minted a fresh recovery code set alongside it. Issue #311: render that set HERE,
            // on this one response, and hold the flow OPEN for the acknowledgment. This is the
            // only moment the plaintext exists (the store keeps Argon2 hashes), so the codes go
            // straight from the transient mint result into the rendered nodes and are dropped
            // when this call returns; nothing writes them to the flow row, the audit trail, or a
            // log line.
            Ok(MfaStep::RecoveryCodes {
                nodes: recovery_codes_nodes(transport, flow_id, Some(&recovery_codes), false),
            })
        }
        totp::FlowEnrollOutcome::AlreadyEnrolled => {
            // The subject already holds an active authenticator, so nothing was enrolled and
            // NOTHING was minted (issue #471). The acknowledgment step renders with no codes:
            // showing a set here would be showing codes that were never stored, and minting
            // one would destroy the set they already hold. Their existing factor already
            // satisfies the step-up, so the flow continues rather than stranding them.
            Ok(MfaStep::RecoveryCodes {
                nodes: recovery_codes_nodes(transport, flow_id, None, false),
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

/// Advance the SHOW ONCE recovery codes acknowledgment one step (issue #311). PURE: the factor is
/// already active and the codes are already stored, so there is nothing left to verify, read, or
/// write. An acknowledgment completes the enrollment leg (the second factor the previous hop
/// genuinely proved is TOTP); anything else re-renders the acknowledgment with its required error
/// and the flow OPEN.
///
/// The re-render passes `None` codes, so it renders the acknowledgment ALONE. That is not a policy
/// choice made here: this function is never given the codes, and no caller can supply them, because
/// the only place they ever existed was the mint result the activating call already consumed.
pub(super) fn advance_recovery_codes_ack(record: &FlowRecord, submission: &Submission) -> MfaStep {
    let transport = transport_of(record);
    let flow_id = record.id.as_str();
    if acknowledged(submission) {
        return MfaStep::Complete {
            new_method: AuthMethod::Totp,
        };
    }
    MfaStep::RecoveryCodes {
        nodes: recovery_codes_nodes(transport, flow_id, None, true),
    }
}

/// Whether the submission carries the recovery codes acknowledgment (issue #311). A browser posts
/// a checked box as the string `on`; an API client posts a JSON boolean or one of the same
/// affirmative strings. An absent field, an explicit `false`, and any other value are all "not
/// acknowledged".
fn acknowledged(submission: &Submission) -> bool {
    match submission.node_values.get(RECOVERY_CODES_ACK_FIELD) {
        Some(serde_json::Value::Bool(flag)) => *flag,
        Some(serde_json::Value::String(raw)) => {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "on" | "true" | "yes" | "1"
            )
        }
        _ => false,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const FLOW_ID: &str = "flw_test000000000000000000000a";

    fn submission_of(values: &[(&str, serde_json::Value)]) -> Submission {
        let mut node_values: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        for (name, value) in values {
            node_values.insert((*name).to_owned(), value.clone());
        }
        Submission {
            node_values,
            transient_payload: None,
        }
    }

    /// Every string a render would put on the wire, so a scan for a leaked code is total over the
    /// node set (both the display values and every message's default text).
    fn rendered_strings(nodes: &[Node]) -> Vec<String> {
        let mut out = Vec::new();
        for node in nodes {
            match &node.attributes {
                NodeAttributes::Input { name, value, .. } => {
                    out.push(name.clone());
                    if let Some(value) = value {
                        out.push(value.clone());
                    }
                }
                NodeAttributes::Text { message } => out.push(message.text.clone()),
            }
            if let Some(label) = &node.label {
                out.push(label.text.clone());
            }
            for message in &node.messages {
                out.push(message.text.clone());
            }
        }
        out
    }

    #[test]
    fn the_minting_render_shows_every_code_once_as_a_display_only_node() {
        let codes: Vec<String> = (1..=10).map(|n| format!("SHOW-ONCE-{n:04}")).collect();
        let nodes = recovery_codes_nodes(Transport::Api, FLOW_ID, Some(&codes), false);
        for code in &codes {
            let occurrences = nodes
                .iter()
                .filter(|node| {
                    matches!(
                        &node.attributes,
                        NodeAttributes::Input { value: Some(rendered), .. } if rendered == code
                    )
                })
                .count();
            assert_eq!(occurrences, 1, "{code} renders exactly once");
        }
        // Display ONLY: a browser must not post a recovery code back as a node value.
        for node in &nodes {
            if let NodeAttributes::Input {
                name,
                value: Some(value),
                disabled,
                ..
            } = &node.attributes
            {
                if codes.iter().any(|code| code == value) {
                    assert!(*disabled, "{name} carrying a code is disabled");
                }
            }
        }
        // The count rides the structured context, the flow's parity with the direct account API's
        // `recovery_codes_remaining` field.
        let intro = nodes
            .iter()
            .find_map(|node| match &node.attributes {
                NodeAttributes::Text { message }
                    if message.id == message::MFA_RECOVERY_CODES_INSTRUCTIONS =>
                {
                    Some(message)
                }
                _ => None,
            })
            .expect("the instructions node renders");
        assert_eq!(
            intro.context.0.get("count").map(String::as_str),
            Some("10"),
            "the code count rides the message context"
        );
    }

    #[test]
    fn a_later_render_of_the_same_state_carries_no_code_and_says_so() {
        let codes: Vec<String> = (1..=10).map(|n| format!("SHOW-ONCE-{n:04}")).collect();
        let later = recovery_codes_nodes(Transport::Api, FLOW_ID, None, false);
        for code in &codes {
            assert!(
                !rendered_strings(&later).iter().any(|text| text == code),
                "{code} is absent from a later render"
            );
        }
        assert!(
            !later.iter().any(|node| matches!(
                &node.attributes,
                NodeAttributes::Input { name, .. } if name.starts_with("recovery_code_")
            )),
            "a later render carries no recovery code node at all"
        );
        assert!(
            later.iter().any(|node| matches!(
                &node.attributes,
                NodeAttributes::Text { message }
                    if message.id == message::MFA_RECOVERY_CODES_UNAVAILABLE
            )),
            "a later render explains why the codes are not shown again"
        );
        // The acknowledgment is still offered, so a user who lost the page still finishes the login.
        assert!(
            later.iter().any(|node| matches!(
                &node.attributes,
                NodeAttributes::Input { name, .. } if name == RECOVERY_CODES_ACK_FIELD
            )),
            "the acknowledgment survives a later render"
        );
    }

    #[test]
    fn the_acknowledgment_error_rides_the_acknowledgment_node_only() {
        let nodes = recovery_codes_nodes(Transport::Api, FLOW_ID, None, true);
        let ack = nodes
            .iter()
            .find(|node| {
                matches!(
                    &node.attributes,
                    NodeAttributes::Input { name, .. } if name == RECOVERY_CODES_ACK_FIELD
                )
            })
            .expect("the acknowledgment node renders");
        assert!(
            ack.messages
                .iter()
                .any(|message| message.id == message::MFA_RECOVERY_CODES_ACK_REQUIRED),
            "the required error rides the acknowledgment node"
        );
        assert!(
            recovery_codes_nodes(Transport::Api, FLOW_ID, None, false)
                .iter()
                .all(|node| node.messages.is_empty()),
            "no node carries the error when there is none"
        );
    }

    #[test]
    fn only_an_affirmative_acknowledgment_counts() {
        for affirmative in [
            serde_json::json!(true),
            serde_json::json!("on"),
            serde_json::json!("true"),
            serde_json::json!("YES"),
            serde_json::json!(" 1 "),
        ] {
            assert!(
                acknowledged(&submission_of(&[(
                    RECOVERY_CODES_ACK_FIELD,
                    affirmative.clone()
                )])),
                "{affirmative} acknowledges"
            );
        }
        for refusal in [
            serde_json::json!(false),
            serde_json::json!("off"),
            serde_json::json!(""),
            serde_json::json!("maybe"),
            serde_json::json!(0),
            serde_json::json!(null),
        ] {
            assert!(
                !acknowledged(&submission_of(&[(
                    RECOVERY_CODES_ACK_FIELD,
                    refusal.clone()
                )])),
                "{refusal} does not acknowledge"
            );
        }
        // An absent field is not an acknowledgment, and neither is a look-alike field name.
        assert!(!acknowledged(&submission_of(&[])));
        assert!(!acknowledged(&submission_of(&[(
            "acknowledged",
            serde_json::json!(true)
        )])));
    }
}
