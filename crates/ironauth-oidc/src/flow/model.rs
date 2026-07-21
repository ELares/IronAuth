// SPDX-License-Identifier: MIT OR Apache-2.0

//! The flow object model (issue #84): the ONE typed object both transports render.
//!
//! Shape: Kratos style UI nodes (`ui.nodes[]`, each with a group, typed attributes, and
//! attached messages, plus flow level `ui.messages[]`), with our three hardenings baked in
//! as contract guarantees:
//!
//! 1. DETERMINISTIC node ordering: identical config yields identical node order, promised
//!    by [`Ui::sorted`], which orders nodes by a fixed `(group rank, sequence)` total
//!    order. No map iteration, no config hash dependence anywhere in node assembly.
//! 2. NUMERIC ONLY message ids: every human readable message keys on a stable numeric
//!    [`MessageId`](super::message::MessageId) plus a structured context (see
//!    [`super::message`]), never on a copy string.
//! 3. ONE object across BOTH transports: there is no browser/API bifurcation of the
//!    object; the transports differ only at the two IO edges (submission ingestion and
//!    continuation), never in the object they render.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

use super::message::Message;

/// The monotonic flow contract version (issue #84, FORK B). Bumped ONLY on a schema
/// breaking change; additive changes (a new node group, a new message id) do NOT bump it
/// and are covered by the golden snapshot gate. Mirrored on the wire as the
/// `X-IronAuth-Flow-Contract` response header.
///
/// Bumped to 2 for issue #87 (signup forms as data): the [`NodeAttributes::Input`] node
/// gains an optional `constraints` sub-object carrying the effective (trait narrowed by the
/// form) validation keywords a configured signup field renders under, so a client can offer
/// the SAME hints the server enforces from one source.
pub const CONTRACT_VERSION: u32 = 2;

/// The journey a flow drives (issue #84). One object renders every journey; there is no
/// journey specific client logic.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Journey {
    /// Sign in with an existing account.
    Login,
    /// Create a new account.
    Registration,
    /// A second factor challenge or enrollment.
    Mfa,
    /// Account recovery.
    Recovery,
    /// A federated (OIDC upstream) login launcher.
    Federation,
}

impl Journey {
    /// The stable wire string (the value stored in the `flows.journey` column).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Journey::Login => "login",
            Journey::Registration => "registration",
            Journey::Mfa => "mfa",
            Journey::Recovery => "recovery",
            Journey::Federation => "federation",
        }
    }

    /// Parse the wire string, or [`None`] for an unknown journey.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "login" => Some(Journey::Login),
            "registration" => Some(Journey::Registration),
            "mfa" => Some(Journey::Mfa),
            "recovery" => Some(Journey::Recovery),
            "federation" => Some(Journey::Federation),
            _ => None,
        }
    }

    /// The ordered flow PLAN for this journey (issue #91, the M9 flow inspector): the
    /// sequence of [`FlowStateTag`] positions the journey can occupy, from the start state
    /// to its terminal.
    ///
    /// This is the ONE transition source of truth the live engine and the read only flow
    /// inspector ([`crate::flow::inspect`]) share, MIRRORING how
    /// [`submit_action_for`](super::submit_action_for) is the one `ui.action` source both
    /// the engine and the golden corpus build from: the engine seeds its start state from
    /// `plan()[0]` (see `start_state` in [`super`]), and the inspector projects the plan
    /// from the SAME table, so the inspector's plan can never drift from the states the
    /// engine actually drives. The `plan_matches_engine` test pins that agreement (every
    /// golden corpus state is a member of its journey's plan, and each creatable journey's
    /// `start_state` step equals `plan()[0]`).
    ///
    /// The MFA states live in the LOGIN plan (they are reached FROM a login flow after the
    /// primary factor, never a creation entry), so the [`Journey::Mfa`] pseudo journey has
    /// an EMPTY plan and is not a creation entry. The federation launcher hands off to an
    /// EXTERNAL browser leg (a redirect, never a local completion), so its plan is the
    /// single launcher state with no `Completed` terminal.
    #[must_use]
    pub fn plan(self) -> &'static [FlowStateTag] {
        use FlowStateTag::{
            Completed, FederationStart, IdentifierPassword, MfaChallenge, MfaEnroll, RecoveryAck,
            RecoveryStart, RegistrationAck, RegistrationDetails,
        };
        match self {
            Journey::Login => &[IdentifierPassword, MfaChallenge, MfaEnroll, Completed],
            Journey::Registration => &[RegistrationDetails, RegistrationAck, Completed],
            Journey::Recovery => &[RecoveryStart, RecoveryAck, Completed],
            Journey::Federation => &[FederationStart],
            Journey::Mfa => &[],
        }
    }
}

/// The transport a flow was created on (issue #84). Set at creation and immutable, so a
/// flow created for a native JSON client is never continued as a browser flow.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// The browser transport: form posts, the same origin CSRF gate, and cookie plus 303
    /// redirect continuation.
    Browser,
    /// The API transport: `application/json` submission with a per flow submit token, and
    /// a 200 JSON envelope continuation.
    Api,
}

impl Transport {
    /// The stable wire string (the value stored in the `flows.transport` column).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Browser => "browser",
            Transport::Api => "api",
        }
    }
}

/// The current state machine position of a flow (issue #84). A single flat tag across all
/// journeys, so a client renders any state from the same field.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlowStateTag {
    /// The login identifier plus password first factor (also the login start state).
    IdentifierPassword,
    /// The registration details (identifier plus password) first factor, the registration
    /// start state.
    RegistrationDetails,
    /// The uniform registration acknowledgment (the #64 closed mode ack or the waitlist
    /// pending notice): a terminal render that discloses nothing, so the flow stays OPEN.
    RegistrationAck,
    /// A second factor challenge is required.
    MfaChallenge,
    /// A second factor enrollment is required.
    MfaEnroll,
    /// The recovery identifier entry (the recovery start state).
    RecoveryStart,
    /// The uniform recovery acknowledgment plus one-time-code entry: the #64 anti-enumeration
    /// render (identical for a known and an unknown identifier) that ALSO carries the code
    /// input, so an existing and an unknown identifier are indistinguishable while a genuine
    /// recovery can still complete. The flow stays OPEN until a correct code mints the session.
    RecoveryAck,
    /// The federated login launcher: the federation node group whose submission produces the
    /// redirect to the EXISTING outbound federation authorize leg.
    FederationStart,
    /// The flow completed and a session was minted.
    Completed,
}

/// A node group (issue #84). The group both categorizes a node for the client and fixes
/// its place in the DETERMINISTIC node order: nodes are emitted by ascending
/// `(group.rank(), sequence)`, so identical config yields identical order.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeGroup {
    /// Cross cutting nodes shared by every method (the identifier field, hidden fields).
    Default,
    /// The password method.
    Password,
    /// The passkey (WebAuthn) method.
    Passkey,
    /// The TOTP second factor method.
    Totp,
    /// The email one time code method.
    EmailOtp,
    /// The SMS one time code method.
    SmsOtp,
    /// The recovery code method.
    RecoveryCode,
    /// A federated (OIDC upstream) method.
    Oidc,
    /// Profile fields collected during registration.
    Profile,
}

impl NodeGroup {
    /// The fixed group rank that anchors the deterministic node order (issue #84). Lower
    /// ranks render first. The exact values are a CONTRACT GUARANTEE the golden snapshot
    /// locks.
    #[must_use]
    pub fn rank(self) -> u16 {
        match self {
            NodeGroup::Default => 0,
            NodeGroup::Password => 10,
            NodeGroup::Passkey => 20,
            NodeGroup::Totp => 30,
            NodeGroup::EmailOtp => 40,
            NodeGroup::SmsOtp => 50,
            NodeGroup::RecoveryCode => 60,
            NodeGroup::Oidc => 70,
            NodeGroup::Profile => 80,
        }
    }
}

/// A typed form input type (issue #84).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// A free text field.
    Text,
    /// A password field (never prefilled with a secret).
    Password,
    /// An email address field.
    Email,
    /// A telephone number field.
    Tel,
    /// A hidden field (a browser transport `return_to`, for example).
    Hidden,
    /// A checkbox (remember this device, for example).
    Checkbox,
    /// A submit control.
    Submit,
}

/// An `autocomplete` hint a browser uses to offer the right saved value (issue #84).
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Autocomplete {
    /// The account identifier.
    Username,
    /// The current password.
    CurrentPassword,
    /// A new password (registration, password change).
    NewPassword,
    /// A one time code (OTP, TOTP).
    OneTimeCode,
    /// A WebAuthn credential.
    Webauthn,
}

/// The effective validation constraints a configured signup field carries on the wire
/// (issue #87): the trait sub-schema's closed keyword vocabulary, TIGHTENED by the form's
/// narrowing rule (the trait always applies, the form only ever narrows). This is a CLIENT
/// HINT only: it is exactly what the server enforces authoritatively on submit, mirrored to
/// the wire so a hosted page or a reference SPA validates from ONE source. It carries no
/// secret and no value except the enumerated permitted values, which are the schema's own
/// configured members, never user data. Every keyword is skip-if-none, so a field with no
/// constraint of a given kind omits it.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldConstraints {
    /// The effective primitive type name (`string` / `number` / `integer` / `boolean`).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    /// The permitted values, when the field is enumerated (the schema's configured members).
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<Value>>,
    /// The minimum string length.
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,
    /// The maximum string length.
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    /// The minimum array length.
    #[serde(rename = "minItems", skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u64>,
    /// The maximum array length.
    #[serde(rename = "maxItems", skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
    /// The inclusive numeric lower bound.
    #[serde(rename = "minimum", skip_serializing_if = "Option::is_none")]
    pub minimum: Option<Number>,
    /// The inclusive numeric upper bound.
    #[serde(rename = "maximum", skip_serializing_if = "Option::is_none")]
    pub maximum: Option<Number>,
}

impl FieldConstraints {
    /// Whether every keyword is absent (an unconstrained field), so the builder can omit the
    /// sub-object entirely rather than emit an empty one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value_type.is_none()
            && self.allowed.is_none()
            && self.min_length.is_none()
            && self.max_length.is_none()
            && self.min_items.is_none()
            && self.max_items.is_none()
            && self.minimum.is_none()
            && self.maximum.is_none()
    }
}

/// The typed attributes of a node (issue #84): a tagged union over the renderable node
/// kinds. Tagged by `node_type` so a client dispatches on one field.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "node_type", rename_all = "snake_case")]
pub enum NodeAttributes {
    /// A form input the client renders and submits.
    Input {
        /// The form field name (for example `identifier`).
        name: String,
        /// The input type.
        input_type: InputType,
        /// A prefill value (never a secret), or [`None`].
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// Whether the field is required.
        required: bool,
        /// The `autocomplete` hint, or [`None`].
        #[serde(skip_serializing_if = "Option::is_none")]
        autocomplete: Option<Autocomplete>,
        /// Whether the control is disabled.
        disabled: bool,
        /// The effective validation constraints (issue #87), for a configured signup field
        /// only. [`None`] for every built in node (the identifier, the password, an OTP
        /// code), so those nodes serialize byte identically to before the field was added.
        #[serde(skip_serializing_if = "Option::is_none")]
        constraints: Option<FieldConstraints>,
    },
    /// A block of rendered copy (the copy IS a message, so it localizes).
    Text {
        /// The message this text renders.
        message: Message,
    },
}

/// One UI node (issue #84): a group, its typed attributes, an optional label, and any
/// messages (validation errors or hints) attached to THIS node. The `sequence` fixes the
/// node's place within its group in the deterministic order and is not serialized.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The node group.
    pub group: NodeGroup,
    /// The typed attributes.
    pub attributes: NodeAttributes,
    /// The node label (a message), or [`None`] for a label free node (hidden, text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<Message>,
    /// Errors and hints attached to THIS node (a per node validation error carries its
    /// message id here).
    pub messages: Vec<Message>,
    /// The intra group ordering key (issue #84). NOT serialized; it exists only to make the
    /// node order a total, config independent function.
    #[serde(skip)]
    pub sequence: u16,
}

impl Node {
    /// A form input node.
    #[must_use]
    pub fn input(
        group: NodeGroup,
        sequence: u16,
        attributes: NodeAttributes,
        label: Option<Message>,
    ) -> Self {
        Self {
            group,
            attributes,
            label,
            messages: Vec::new(),
            sequence,
        }
    }
}

/// The UI container (issue #84): the submission target, the method, the ordered nodes, and
/// the flow level messages.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
pub struct Ui {
    /// Where the client submits the flow.
    pub action: String,
    /// The submission method (informational for the API transport).
    pub method: String,
    /// The nodes, in the DETERMINISTIC contract order (see [`Ui::sorted`]).
    pub nodes: Vec<Node>,
    /// The flow level messages (errors and info not attached to a single node).
    pub messages: Vec<Message>,
}

impl Ui {
    /// Build a UI from an unordered node list, sorting it into the DETERMINISTIC contract
    /// order (issue #84 hardening 1): ascending `(group.rank(), node.sequence)`. The sort
    /// is stable and depends only on the group rank and the compile time sequence, never on
    /// insertion order or any config hash, so identical config yields identical order.
    #[must_use]
    pub fn new(
        action: String,
        method: String,
        mut nodes: Vec<Node>,
        messages: Vec<Message>,
    ) -> Self {
        nodes.sort_by_key(|node| (node.group.rank(), node.sequence));
        Self {
            action,
            method,
            nodes,
            messages,
        }
    }

    /// Re-sort the nodes into the deterministic order (used after attaching a node level
    /// error, so the order is order independent of when the error was pushed).
    pub fn sorted(&mut self) {
        self.nodes
            .sort_by_key(|node| (node.group.rank(), node.sequence));
    }
}

/// The whole flow object (issue #84): the ONE thing both transports render. The
/// `submit_token` is NOT here; it rides the API transport envelope only, so the object is
/// byte identical across transports.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    /// The flow contract version (FORK B). Also mirrored in the response header.
    pub contract_version: u32,
    /// The scope embedded `flw_` id.
    pub id: String,
    /// The journey this flow drives.
    pub journey: Journey,
    /// The current state machine position.
    pub state: FlowStateTag,
    /// The transport this flow was created on (immutable).
    pub transport: Transport,
    /// The flow expiry as a unix timestamp in seconds (from the app clock seam).
    pub expires_at: i64,
    /// The pending `/authorize` resume target, or [`None`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_url: Option<String>,
    /// The UI: ordered nodes plus flow level messages.
    pub ui: Ui,
}
