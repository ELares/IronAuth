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

use super::message::Message;

/// The monotonic flow contract version (issue #84, FORK B). Bumped ONLY on a schema
/// breaking change; additive changes (a new node group, a new message id) do NOT bump it
/// and are covered by the golden snapshot gate. Mirrored on the wire as the
/// `X-IronAuth-Flow-Contract` response header.
pub const CONTRACT_VERSION: u32 = 1;

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
            _ => None,
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
    /// A second factor challenge is required.
    MfaChallenge,
    /// A second factor enrollment is required.
    MfaEnroll,
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
