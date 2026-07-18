// SPDX-License-Identifier: MIT OR Apache-2.0

//! The numeric message id registry (issue #84).
//!
//! Every human readable message in the flow contract keys on a STABLE NUMERIC id plus a
//! structured [`MessageContext`], never on a copy string (one of the three hardenings over
//! the Kratos reference model). The `text` a message carries is only the default locale
//! (`en`) render, a convenience for a client that does not localize; i18n (issue #86) keys
//! on the id and the context, and swaps the text without touching either.
//!
//! The id assignments are a committed contract: `docs/flow-messages.json` snapshots them
//! and a CI diff gate (`scripts/flow-schema.sh`) fails a build that changes or removes an
//! id. New ids are additive. The numeric scheme groups by intent so the ranges stay
//! legible:
//!
//! - `10xxxxx` informational copy (labels, prompts, titles);
//! - `15xxxxx` success copy;
//! - `40xxxxx` flow level errors (expiry, completion, malformed input);
//! - `41xxxxx` login journey errors (the uniform identifier or password failure, the
//!   per node validation errors).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A stable numeric message id (issue #84). Serialized as a bare integer, so a client
/// keys its localized copy on the number, never on the default text.
#[derive(
    Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(transparent)]
pub struct MessageId(pub u32);

/// The kind of a message, so a client can style an error distinctly from an informational
/// hint or a success note without parsing the copy.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// An informational prompt, label, or title.
    Info,
    /// A success note (a step completed).
    Success,
    /// An error (a validation failure, an expiry, a uniform authentication failure).
    Error,
}

/// The structured parameters a localized render interpolates (issue #84): a stable, sorted
/// key/value map (`BTreeMap`, so an identical context serializes identically). The values
/// are NEVER interpolated into the numeric id; the id selects the template and the context
/// fills it. Empty for a message with no parameters.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, Default, PartialEq, Eq)]
#[serde(transparent)]
pub struct MessageContext(pub BTreeMap<String, String>);

impl MessageContext {
    /// An empty context (the common case: a message with no parameters).
    #[must_use]
    pub fn empty() -> Self {
        Self(BTreeMap::new())
    }

    /// A single `key = value` context.
    #[must_use]
    pub fn one(key: &str, value: &str) -> Self {
        let mut map = BTreeMap::new();
        map.insert(key.to_owned(), value.to_owned());
        Self(map)
    }
}

/// One human readable message: a stable numeric id, its kind, the default locale render,
/// and the structured context (issue #84). The id and the context are the localization
/// key; the text is a convenience.
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The stable numeric id (the localization key).
    pub id: MessageId,
    /// The message kind.
    pub kind: MessageKind,
    /// The default locale (`en`) render. A convenience only; i18n keys on `id`+`context`.
    pub text: String,
    /// The structured parameters. Empty for a parameterless message.
    pub context: MessageContext,
}

impl Message {
    /// Build the registered message for `id` with an empty context.
    ///
    /// # Panics
    ///
    /// Panics on an UNREGISTERED id, which is a programming error (a message used at
    /// runtime must be in [`REGISTRY`]); the message id snapshot test catches it.
    #[must_use]
    pub fn of(id: MessageId) -> Self {
        Self::with_context(id, MessageContext::empty())
    }

    /// Build the registered message for `id` with the given structured context.
    ///
    /// # Panics
    ///
    /// Panics on an UNREGISTERED id (see [`Message::of`]).
    #[must_use]
    pub fn with_context(id: MessageId, context: MessageContext) -> Self {
        let spec = spec_for(id).expect("every message id used at runtime is registered");
        Self {
            id,
            kind: spec.kind,
            text: spec.text.to_owned(),
            context,
        }
    }
}

/// A registry entry: the single source of truth for one message id (issue #84). The
/// `name` is a stable symbolic handle for humans and the snapshot; the wire only ever
/// carries the numeric id.
#[derive(Clone, Copy, Debug)]
pub struct MessageSpec {
    /// The stable numeric id.
    pub id: MessageId,
    /// A stable symbolic name (documentation and the snapshot; never on the wire).
    pub name: &'static str,
    /// The message kind.
    pub kind: MessageKind,
    /// The default locale (`en`) render.
    pub text: &'static str,
    /// The context keys a localized render of this message may reference (documentation
    /// and the snapshot), so a translator knows the parameters.
    pub context_keys: &'static [&'static str],
}

// The message id constants. Grouped by range (see the module docs). Every id used at
// runtime MUST appear in [`REGISTRY`] below, and the snapshot test locks the assignments.

/// The login page title.
pub const LOGIN_TITLE: MessageId = MessageId(1_010_001);
/// The identifier field label.
pub const LOGIN_IDENTIFIER_LABEL: MessageId = MessageId(1_010_002);
/// The password field label.
pub const LOGIN_PASSWORD_LABEL: MessageId = MessageId(1_010_003);
/// The sign in submit button label.
pub const LOGIN_SUBMIT_LABEL: MessageId = MessageId(1_010_004);

/// The login success note.
pub const LOGIN_SUCCESS: MessageId = MessageId(1_500_001);

/// The flow has expired.
pub const FLOW_EXPIRED: MessageId = MessageId(4_000_001);
/// The flow is already completed (the single use latch tripped).
pub const FLOW_ALREADY_COMPLETED: MessageId = MessageId(4_000_002);
/// The submission was not valid (a malformed node payload).
pub const FLOW_INVALID_SUBMISSION: MessageId = MessageId(4_000_003);
/// The transient payload was not valid JSON (or exceeded the size cap).
pub const FLOW_MALFORMED_TRANSIENT_PAYLOAD: MessageId = MessageId(4_000_004);
/// The flow could not be found (a uniform not found for an unknown or cross scope id).
pub const FLOW_NOT_FOUND: MessageId = MessageId(4_000_005);

/// The uniform login failure: the identifier or the password is incorrect. The SAME id
/// on the found and the unknown identifier branch (the anti enumeration crux).
pub const LOGIN_IDENTIFIER_OR_PASSWORD_INCORRECT: MessageId = MessageId(4_100_001);
/// The identifier field is required (a per node validation error).
pub const LOGIN_IDENTIFIER_REQUIRED: MessageId = MessageId(4_100_002);
/// The password field is required (a per node validation error).
pub const LOGIN_PASSWORD_REQUIRED: MessageId = MessageId(4_100_003);

/// The complete message registry (issue #84): the single source of truth the runtime and
/// the committed `docs/flow-messages.json` snapshot both read. Ordered by ascending id so
/// the snapshot is deterministic.
pub const REGISTRY: &[MessageSpec] = &[
    MessageSpec {
        id: LOGIN_TITLE,
        name: "login.title",
        kind: MessageKind::Info,
        text: "Sign in",
        context_keys: &[],
    },
    MessageSpec {
        id: LOGIN_IDENTIFIER_LABEL,
        name: "login.identifier.label",
        kind: MessageKind::Info,
        text: "Identifier",
        context_keys: &[],
    },
    MessageSpec {
        id: LOGIN_PASSWORD_LABEL,
        name: "login.password.label",
        kind: MessageKind::Info,
        text: "Password",
        context_keys: &[],
    },
    MessageSpec {
        id: LOGIN_SUBMIT_LABEL,
        name: "login.submit.label",
        kind: MessageKind::Info,
        text: "Sign in",
        context_keys: &[],
    },
    MessageSpec {
        id: LOGIN_SUCCESS,
        name: "login.success",
        kind: MessageKind::Success,
        text: "You are signed in.",
        context_keys: &[],
    },
    MessageSpec {
        id: FLOW_EXPIRED,
        name: "flow.expired",
        kind: MessageKind::Error,
        text: "This flow has expired. Start again.",
        context_keys: &[],
    },
    MessageSpec {
        id: FLOW_ALREADY_COMPLETED,
        name: "flow.already_completed",
        kind: MessageKind::Error,
        text: "This flow is already complete.",
        context_keys: &[],
    },
    MessageSpec {
        id: FLOW_INVALID_SUBMISSION,
        name: "flow.invalid_submission",
        kind: MessageKind::Error,
        text: "The submission was not valid.",
        context_keys: &[],
    },
    MessageSpec {
        id: FLOW_MALFORMED_TRANSIENT_PAYLOAD,
        name: "flow.malformed_transient_payload",
        kind: MessageKind::Error,
        text: "The transient payload was not valid JSON.",
        context_keys: &[],
    },
    MessageSpec {
        id: FLOW_NOT_FOUND,
        name: "flow.not_found",
        kind: MessageKind::Error,
        text: "No such flow.",
        context_keys: &[],
    },
    MessageSpec {
        id: LOGIN_IDENTIFIER_OR_PASSWORD_INCORRECT,
        name: "login.identifier_or_password_incorrect",
        kind: MessageKind::Error,
        text: "Incorrect identifier or password.",
        context_keys: &[],
    },
    MessageSpec {
        id: LOGIN_IDENTIFIER_REQUIRED,
        name: "login.identifier_required",
        kind: MessageKind::Error,
        text: "Enter your identifier.",
        context_keys: &[],
    },
    MessageSpec {
        id: LOGIN_PASSWORD_REQUIRED,
        name: "login.password_required",
        kind: MessageKind::Error,
        text: "Enter your password.",
        context_keys: &[],
    },
];

/// The registry entry for `id`, or [`None`] if the id is not registered.
#[must_use]
pub fn spec_for(id: MessageId) -> Option<&'static MessageSpec> {
    REGISTRY.iter().find(|spec| spec.id == id)
}

#[cfg(test)]
mod tests {
    use super::{MessageId, REGISTRY, spec_for};
    use std::collections::BTreeSet;

    #[test]
    fn every_registered_id_is_unique() {
        let mut seen = BTreeSet::new();
        for spec in REGISTRY {
            assert!(seen.insert(spec.id), "duplicate message id {:?}", spec.id);
        }
    }

    #[test]
    fn registry_is_sorted_by_ascending_id() {
        let mut prev = 0_u32;
        for spec in REGISTRY {
            assert!(
                spec.id.0 > prev,
                "the registry must be strictly ascending by id ({} follows {prev})",
                spec.id.0
            );
            prev = spec.id.0;
        }
    }

    #[test]
    fn spec_for_resolves_a_registered_id_and_rejects_an_unregistered_one() {
        assert!(spec_for(super::LOGIN_TITLE).is_some());
        assert!(spec_for(MessageId(9_999_999)).is_none());
    }
}
