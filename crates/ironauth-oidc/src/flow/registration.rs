// SPDX-License-Identifier: MIT OR Apache-2.0

//! The registration journey (issue #84): the identifier plus password sign up as a flow
//! state machine. Like the login journey, every security decision is DELEGATED to the SAME
//! choke point the bootstrap `POST /register` (`register.rs`) uses, never re-derived here:
//!
//! - the credential abuse layer (issue #64) is the SAME register path regulation:
//!   [`OidcState::regulate_before`] on the [`AuthPath::Register`] counters BEFORE any
//!   account create or password hash, so registration spam climbs the per identifier and
//!   per IP throttle exactly as `register_post`;
//! - the #64 CLOSED mode anti enumeration recipe: an already registered and a brand new
//!   address BOTH run the SAME [`OidcState::dispatch_verification`] suppressed but timed
//!   send and render the SAME uniform acknowledgment ([`RegistrationStep::Ack`]), so a per
//!   node validation error NEVER discloses whether the identifier exists, on either
//!   transport. The open mode "already registered" disclosure is emitted ONLY when the
//!   tenant runs open registration (the engine reads [`OidcState::registration_closed`], it
//!   does not choose);
//! - the #80 abuse defenses (disposable/low reputation email, the proof of work gate, the
//!   waitlist) and the #82 risk to quarantine hook run through the SAME
//!   [`crate::disposable`], [`crate::pow_gate`], and store `register*` primitives, in the
//!   SAME order, so the flow registration is NO WEAKER than `/register`;
//! - the password policy, strength, and MANDATORY breach screen run through the SAME
//!   [`OidcState::password_policy`] / [`OidcState::screen_password`] before any hash;
//! - the session mint goes through [`crate::interaction::establish_session`] (the ONE
//!   session mint and lifecycle fence), called by the driver after the single use
//!   completion latch trips, so a registration is consumed ONLY on a genuine account create.

use ironauth_store::{
    ActorRef, AuthPath, CorrelationId, HumanId, RegisteredTraits, Scope, SignupQuarantineReason,
    SignupStep, UserState,
};

use super::message::{self, Message, MessageId};
use super::model::{
    Autocomplete, FlowStateTag, InputType, Node, NodeAttributes, NodeGroup, Transport,
};
use super::signup_fields::{self, FieldFailure, SignupValidation};
use super::{FlowError, Submission};
use crate::authn::AuthenticationEvent;
use crate::interaction;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// The signup field nodes for a freshly created registration flow (issue #87): the Signup-step
/// fields of the client's active form, appended to the initial details form so the very NEXT
/// flow created after a management write reflects the change (immediacy, no redeploy). Empty
/// when the flow collects no fields.
pub(super) async fn signup_start_nodes(
    state: &OidcState,
    scope: Scope,
    return_to: Option<&str>,
) -> Vec<Node> {
    match signup_fields::load_active_signup_form(state, scope, return_to).await {
        Some((config, schema, _)) => {
            signup_fields::signup_field_nodes(&config, &schema, SignupStep::Signup)
        }
        None => Vec::new(),
    }
}

/// The outcome of one registration transition (issue #84).
pub(super) enum RegistrationStep {
    /// Stay on the details state and re-render (a per node validation error, a throttle, or
    /// an abuse/policy failure). The nodes already carry any node level messages and the
    /// flow stays OPEN (never consumed), so this branch is never a completion oracle.
    Render {
        /// The nodes to render (already carrying their node level messages).
        nodes: Vec<Node>,
        /// The flow level messages (a throttle notice, for example).
        messages: Vec<Message>,
    },
    /// The uniform acknowledgment: the #64 closed mode ack (a suppressed but timed send ran,
    /// so an already registered and a new address are INDISTINGUISHABLE) or the waitlist
    /// pending notice. A terminal render on the [`RegistrationAck`](FlowStateTag::RegistrationAck)
    /// state; the flow stays OPEN (no session, no consume), so it is never a completion or
    /// enumeration oracle.
    Ack {
        /// The acknowledgment message id (the same for known and unknown in closed mode).
        message_id: MessageId,
    },
    /// A new account was GENUINELY created; the driver consumes the single use latch and
    /// mints the session through the ONE choke point. This is the ONLY branch that consumes
    /// the flow.
    Complete(Box<RegistrationSuccess>),
}

/// A genuinely completing registration (issue #84): everything the driver needs to mint the
/// first session for the freshly created account, exactly as `register_post` does on
/// success.
pub(super) struct RegistrationSuccess {
    /// The created subject (a `usr_` id string).
    pub subject: String,
    /// The audit actor for the session mint.
    pub actor: ActorRef,
    /// The recorded authentication event (a password login at the current instant, since
    /// registration authenticates the new user with the password they just set).
    pub event: AuthenticationEvent,
}

/// Build the registration details nodes in the deterministic contract order (issue #84):
/// the identifier field (Default group), the new password field (Password group), and the
/// submit control (Submit group, rank 90, so it renders after any collected profile fields).
/// On the browser transport a hidden `flow` node carries the flow id back on the form post.
/// `id_error` / `pw_error` attach a node level message to the offending node.
fn details_nodes(
    transport: Transport,
    flow_id: &str,
    identifier_prefill: &str,
    id_error: Option<MessageId>,
    pw_error: Option<MessageId>,
) -> Vec<Node> {
    let mut nodes = Vec::new();

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
            constraints: None,
        },
        Some(Message::of(message::REGISTER_IDENTIFIER_LABEL)),
    );
    if let Some(id) = id_error {
        identifier.messages.push(Message::of(id));
    }
    nodes.push(identifier);

    let mut password = Node::input(
        NodeGroup::Password,
        0,
        NodeAttributes::Input {
            name: "password".to_owned(),
            input_type: InputType::Password,
            value: None,
            required: true,
            autocomplete: Some(Autocomplete::NewPassword),
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::REGISTER_PASSWORD_LABEL)),
    );
    if let Some(id) = pw_error {
        password.messages.push(Message::of(id));
    }
    nodes.push(password);

    nodes.push(Node::input(
        NodeGroup::Submit,
        0,
        NodeAttributes::Input {
            name: "method".to_owned(),
            input_type: InputType::Submit,
            value: Some("register".to_owned()),
            required: false,
            autocomplete: None,
            disabled: false,
            constraints: None,
        },
        Some(Message::of(message::REGISTER_SUBMIT_LABEL)),
    ));

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

    nodes
}

/// The initial registration nodes for a freshly created flow (issue #84): the identifier
/// plus new password form with no errors and no prefill.
#[must_use]
pub(super) fn start_nodes(transport: Transport, flow_id: &str) -> Vec<Node> {
    details_nodes(transport, flow_id, "", None, None)
}

/// The uniform acknowledgment nodes (issue #84): an empty node set on the
/// [`RegistrationAck`](FlowStateTag::RegistrationAck) state. The acknowledgment copy is a
/// FLOW LEVEL message the driver attaches, IDENTICAL for a known and an unknown address, so
/// the rendered object never distinguishes existence.
#[must_use]
pub(super) fn ack_nodes() -> Vec<Node> {
    Vec::new()
}

/// The state tag a registration render stays on (issue #84): the details state.
#[must_use]
pub(super) fn render_state_tag() -> FlowStateTag {
    FlowStateTag::RegistrationDetails
}

/// Advance the registration journey one step (issue #84). Returns the transition outcome;
/// the driver handles persistence, the completion latch, and the session mint.
///
/// This reproduces the bootstrap `register_post` sequence in the SAME order so the flow
/// registration is NO WEAKER than `/register`:
///
/// 1. run [`OidcState::regulate_before`] on the register path counters (the throttle);
/// 2. CLOSED registration (the #64 anti enumeration crux): look the identifier up ONLY to
///    decide whether a verification send is permitted, run the SAME suppressed but timed
///    [`OidcState::dispatch_verification`], and render the SAME uniform acknowledgment either
///    way, so the surface is not an enumeration oracle;
/// 3. OPEN registration: the #80 disposable/PoW/waitlist defenses and the #82 quarantine
///    hook, the password policy/strength/breach screen, the admission controlled hash, and
///    the store create, exactly as `register_post`.
// The linear sequence (regulate, closed mode uniform path, open mode create) reads best as
// one function; splitting it would scatter the anti-enumeration and no-weaker-than-/register
// invariants across helpers, so the length lint is allowed here (mirroring `register_post`).
#[allow(clippy::too_many_lines)]
pub(super) async fn advance_registration(
    state: &OidcState,
    scope: Scope,
    record: &ironauth_store::FlowRecord,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
) -> Result<RegistrationStep, FlowError> {
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

    // The client's active signup form (issue #87), loaded ONCE at the live scope so a
    // management write reflects on the next transition (immediacy). Its Signup-step fields are
    // appended to every details render and validated on the create attempt below.
    let signup =
        signup_fields::load_active_signup_form(state, scope, record.return_to.as_deref()).await;
    // Build the details form PLUS the configured signup field nodes, with optional per field
    // validation messages attached. Ui ordering re-sorts by (group rank, sequence), so the
    // Profile group signup nodes always render after the identifier and password regardless of
    // append order.
    let details_with_signup =
        |id_err: Option<MessageId>, pw_err: Option<MessageId>, failures: &[FieldFailure]| {
            let mut nodes = details_nodes(transport, flow_id, identifier, id_err, pw_err);
            if let Some((config, schema, _)) = &signup {
                nodes.extend(signup_fields::signup_field_nodes_with_messages(
                    config,
                    schema,
                    SignupStep::Signup,
                    failures,
                ));
            }
            nodes
        };

    // Credential abuse regulation for the REGISTER path (issue #64), keyed on the canonical
    // identifier and the resolved peer IP, INDEPENDENTLY of the password path. Every
    // processed attempt is counted, so registration spam is throttled per identifier and per
    // IP. A throttle renders a flow level notice and stays OPEN (no create), existence
    // independent, so it is never an enumeration oracle.
    let ctx = crate::abuse::AttemptContext {
        path: AuthPath::Register,
        scope,
        ip: crate::abuse::resolved_client_ip(headers),
        identifier: Some(crate::abuse::canonical_login_identifier(identifier)),
        account_id: None,
        client_id: None,
    };
    if state.regulate_before(&ctx).await.is_throttled() {
        return Ok(RegistrationStep::Render {
            nodes: details_with_signup(None, None, &[]),
            messages: vec![Message::of(message::REGISTER_THROTTLED)],
        });
    }

    // CLOSED registration (issue #64): do NOT create an account inline and do NOT reveal
    // whether the identifier exists. The lookup runs for both present and absent
    // identifiers, the send is SUPPRESSED for an unknown recipient while spending the same
    // cost, and the SAME acknowledgment is returned either way.
    if state.registration_closed() {
        if identifier.is_empty() {
            return Ok(RegistrationStep::Render {
                nodes: details_with_signup(Some(message::REGISTER_IDENTIFIER_REQUIRED), None, &[]),
                messages: Vec::new(),
            });
        }
        let recipient_known = matches!(
            state
                .store()
                .scoped(scope)
                .users()
                .by_identifier(identifier)
                .await,
            Ok(Some(_))
        );
        state.dispatch_verification(
            scope,
            crate::verification::VerificationPurpose::Registration,
            identifier,
            recipient_known,
        );
        return Ok(RegistrationStep::Ack {
            message_id: message::REGISTER_ACK,
        });
    }

    // OPEN registration below. A per node validation error on an empty field is existence
    // INDEPENDENT (it does not depend on whether the identifier exists), so it is not an
    // enumeration oracle.
    let id_error = identifier
        .is_empty()
        .then_some(message::REGISTER_IDENTIFIER_REQUIRED);
    let pw_error = password
        .is_empty()
        .then_some(message::REGISTER_PASSWORD_REQUIRED);
    if id_error.is_some() || pw_error.is_some() {
        return Ok(RegistrationStep::Render {
            nodes: details_with_signup(id_error, pw_error, &[]),
            messages: Vec::new(),
        });
    }

    // Validate the configured signup fields SERVER AUTHORITATIVELY (issue #87, the critical
    // contract): each value is checked against the trait sub-schema AND the form's narrowing
    // rule (both must pass, so an empty or partial rule still enforces the full trait). A
    // failure re-renders the offending field nodes with the generic error id (the field
    // pointer in context), the SAME node and id on the browser and the API transport. On
    // success the assembled partial trait document is sealed atomically at the create below.
    // Existence independent (a field error never depends on whether the identifier exists), so
    // it is not an enumeration oracle.
    let collected_traits: Option<(String, i32)> = match &signup {
        Some((config, schema, version)) => {
            match signup_fields::validate_signup_submission(
                config,
                schema,
                SignupStep::Signup,
                &submission.node_values,
            ) {
                SignupValidation::Valid(document) => document
                    .as_object()
                    .filter(|map| !map.is_empty())
                    .and_then(|_| serde_json::to_string(&document).ok())
                    .map(|json| (json, *version)),
                SignupValidation::Invalid(failures) => {
                    return Ok(RegistrationStep::Render {
                        nodes: details_with_signup(None, None, &failures),
                        messages: Vec::new(),
                    });
                }
            }
        }
        None => None,
    };

    let render_details =
        |id_err: Option<MessageId>, pw_err: Option<MessageId>| RegistrationStep::Render {
            nodes: details_with_signup(id_err, pw_err, &[]),
            messages: Vec::new(),
        };

    // Disposable / low reputation email defense (issue #80). A BLOCK is an anti enumeration
    // UNIFORM failure: the same re-render an ordinary validation failure produces. A FLAG
    // admits but raises the PoW challenge level below. The #82 quarantine hook: a block is
    // instead QUARANTINED when the feature is armed (recoverable), else blocked as before.
    let disposable = crate::disposable::evaluate(
        &state.registration_abuse_config().disposable_email,
        &ironauth_screening::normalize_nfkc(identifier),
    );
    let mut quarantine_reason: Option<SignupQuarantineReason> = None;
    if disposable.is_block() {
        if state.signup_quarantine_enabled() {
            quarantine_reason = Some(SignupQuarantineReason::RiskOutput);
        } else {
            return Ok(render_details(
                None,
                Some(message::REGISTER_ADDRESS_UNUSABLE),
            ));
        }
    }

    // Proof of work gate (issue #80), CONDITIONED on the #79 risk level, BEFORE the hash so
    // an unsolved bot attempt spends no password work. The pow fields ride the submission
    // node values (the same way the bootstrap form carries them).
    let peer_ip = crate::abuse::resolved_client_ip(headers);
    if crate::pow_gate::challenge_required(state, peer_ip.as_deref(), disposable.is_flagged()) {
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
            crate::pow_gate::ENDPOINT_REGISTER,
            &solution,
        )
        .await
        {
            if state.signup_quarantine_enabled() {
                quarantine_reason = Some(SignupQuarantineReason::ChallengeFailure);
            } else {
                return Ok(render_details(
                    None,
                    Some(message::REGISTER_VERIFICATION_REQUIRED),
                ));
            }
        }
    }

    // NFKC normalize ONCE (issue #63): the length check, breach screen, and hash all operate
    // on the normalized form. The policy, strength, and MANDATORY breach screen run BEFORE
    // any hash; each failure re-renders the password node with a NON enumerating message.
    let normalized = ironauth_screening::normalize_nfkc(password);
    if state
        .password_policy()
        .evaluate(&normalized, ironauth_screening::FactorContext::SoleFactor)
        .is_err()
        || state
            .password_policy()
            .evaluate_strength(&normalized)
            .is_err()
    {
        return Ok(render_details(
            None,
            Some(message::REGISTER_PASSWORD_REJECTED),
        ));
    }
    match state.screen_password(&scope, &normalized).await {
        crate::state::ScreenDecision::Allowed => {}
        crate::state::ScreenDecision::Breached
        | crate::state::ScreenDecision::RefusedUnavailable => {
            return Ok(render_details(
                None,
                Some(message::REGISTER_PASSWORD_REJECTED),
            ));
        }
    }

    // Hash through the dedicated, admission controlled pool (issue #62). A saturated pool or
    // a pool fault is the neutral store error (never an oracle), exactly as `register_post`.
    let Ok(password_hash) = state.hash_password(&scope, password).await else {
        return Err(FlowError::Store);
    };

    // Waitlist gate (issue #80): a self service signup lands PENDING and cannot authenticate
    // until an admin approves it, so no session is established and the flow renders the
    // uniform pending acknowledgment.
    let waitlisted = state.registration_abuse_config().waitlist.enabled;

    // The validated signup traits (issue #87) seal atomically with the account insert, so a
    // committed account carries its collected traits or neither exists (mirroring `login.rs`
    // migration create). `None` when the flow collected no fields (an ordinary registration).
    let registered_traits = collected_traits
        .as_ref()
        .map(|(traits_json, schema_version)| RegisteredTraits {
            traits_json,
            schema_version: *schema_version,
        });

    let actor = ActorRef::human(HumanId::generate(state.env()));
    let scoped = state
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(state.env()));
    let result = if let Some(reason) = quarantine_reason {
        // The #82 fraud queue takes precedence over the waitlist: a risky signup is created
        // ACTIVE-but-quarantined (it authenticates with limited privileges) plus a pending
        // review row, rather than parked unauthenticatable in the waitlist.
        scoped
            .users()
            .register_quarantined_with_traits(
                state.env(),
                identifier,
                &password_hash,
                reason,
                registered_traits,
            )
            .await
    } else if waitlisted {
        scoped
            .users()
            .register_in_state_with_traits(
                state.env(),
                identifier,
                &password_hash,
                UserState::Waitlisted,
                registered_traits,
            )
            .await
    } else {
        scoped
            .users()
            .register_with_traits(state.env(), identifier, &password_hash, registered_traits)
            .await
    };

    match result {
        // A waitlisted (non quarantined) account cannot authenticate: the uniform pending
        // acknowledgment, no session. A quarantined signup is Active, so it falls through to
        // the completion path (limited privileges).
        Ok(_) if waitlisted && quarantine_reason.is_none() => Ok(RegistrationStep::Ack {
            message_id: message::REGISTER_PENDING,
        }),
        Ok(user_id) => {
            let subject = user_id.to_string();
            let session_actor = interaction::user_actor(&user_id);
            let event = AuthenticationEvent::password(epoch_micros(state.now()));
            Ok(RegistrationStep::Complete(Box::new(RegistrationSuccess {
                subject,
                actor: session_actor,
                event,
            })))
        }
        // The open mode duplicate disclosure: emitted ONLY here (the tenant runs open
        // registration, where duplicate disclosure is the accepted posture). The closed/
        // uniform path above never reaches this.
        Err(ironauth_store::StoreError::Conflict) => Ok(render_details(
            Some(message::REGISTER_ALREADY_REGISTERED),
            None,
        )),
        Err(_) => Err(FlowError::Store),
    }
}
