// SPDX-License-Identifier: MIT OR Apache-2.0

//! The login journey (issue #84): the identifier plus password first factor as a flow
//! state machine. Every security decision is delegated to an EXISTING choke point, never
//! re-derived here:
//!
//! - the password verify and the anti enumeration dummy spend go through
//!   [`OidcState::verify_password`] / [`OidcState::verify_absent`] (state.rs, issue #62),
//!   the SAME admission controlled primitives the bootstrap login path uses;
//! - the session mint goes through [`crate::interaction::establish_session`] (the ONE
//!   session mint and lifecycle fence, issue #80), called by the driver after the single
//!   use completion latch trips.
//!
//! The anti enumeration crux (issue #64, this issue's security bar): the found and the
//! unknown identifier branches CONVERGE on ONE flow building expression
//! ([`uniform_incorrect_nodes`]) and ONE verify spend (one Argon2 op), so a per node
//! validation error never discloses whether the identifier exists, on either transport.

use ironauth_store::{FlowRecord, Scope};

use super::message::{self, Message};
use super::model::{
    Autocomplete, FlowStateTag, InputType, Node, NodeAttributes, NodeGroup, Transport,
};
use super::{FlowError, Submission};
use crate::authn::AuthenticationEvent;
use crate::interaction;
use crate::state::OidcState;
use crate::util::epoch_micros;
use ironauth_store::ActorRef;

/// The outcome of one login transition (issue #84). The driver turns [`Render`] into a
/// re-rendered flow (rotating the API submit token) and [`Complete`] into the single use
/// completion latch plus the [`establish_session`](crate::interaction::establish_session)
/// mint.
pub(super) enum LoginStep {
    /// Stay on the identifier plus password state and re-render (a validation error or the
    /// uniform authentication failure). The nodes already carry any node level messages.
    Render {
        /// The nodes to render (already carrying their node level messages).
        nodes: Vec<Node>,
    },
    /// The first factor succeeded; the driver mints the session for `subject`.
    Complete {
        /// The authenticated subject (a `usr_` id string).
        subject: String,
        /// The audit actor for the session mint.
        actor: ActorRef,
        /// The recorded authentication event (a password login at the current instant).
        event: AuthenticationEvent,
    },
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

/// Advance the login journey one step (issue #84). Returns the transition outcome; the
/// driver handles persistence, the completion latch, and the session mint.
///
/// The anti enumeration binding is here: `by_identifier` looks the account up, then the
/// found and unknown branches BOTH spend exactly one Argon2 op ([`verify_password`] on
/// found, [`verify_absent`] on unknown) and BOTH return the SAME
/// [`uniform_incorrect_nodes`] render on a failure, so no branch adds or removes a node or
/// message based on existence.
pub(super) async fn advance_login(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    submission: &Submission,
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
    // on whether the identifier exists), so it returns the required message on the offending
    // node before any lookup.
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

    // The account lookup and the CONVERGENT verify spend (the anti enumeration crux).
    match state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
    {
        Ok(Some(user)) => {
            // One Argon2 op on the found branch: the real verify when the account has a
            // usable native hash, or the dummy spend when it does not (a passkey only or
            // not yet migrated account), so the found branch costs the same as the unknown
            // branch below.
            let native_ok = if user.has_usable_password_hash() {
                state
                    .verify_password(&scope, password, &user.password_hash)
                    .await
                    .map_err(|_| FlowError::Store)?
            } else {
                state
                    .verify_absent(&scope, password)
                    .await
                    .map_err(|_| FlowError::Store)?;
                false
            };
            if native_ok {
                Ok(LoginStep::Complete {
                    subject: user.id.to_string(),
                    actor: interaction::user_actor(&user.id),
                    event: AuthenticationEvent::password(epoch_micros(state.now())),
                })
            } else {
                Ok(LoginStep::Render {
                    nodes: uniform_incorrect_nodes(transport, flow_id),
                })
            }
        }
        Ok(None) => {
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
        Err(_) => Err(FlowError::Store),
    }
}

/// The state tag a login render stays on (issue #84): the identifier plus password state.
#[must_use]
pub(super) fn render_state_tag() -> FlowStateTag {
    FlowStateTag::IdentifierPassword
}
