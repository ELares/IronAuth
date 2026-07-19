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
//! - `10xxxxx` informational copy (labels, prompts, titles): `1010xxx` login, `1020xxx`
//!   registration, `1030xxx` MFA (challenge and enrollment);
//! - `15xxxxx` success copy;
//! - `4000xxx` flow level errors (expiry, completion, malformed input);
//! - `4100xxx` login journey errors (the uniform identifier or password failure, the
//!   per node validation errors);
//! - `4200xxx` registration journey errors (the per node validation errors, the uniform
//!   abuse and policy failures, the open mode duplicate disclosure);
//! - `4300xxx` MFA journey errors (the uniform second factor failure, the per node
//!   validation errors).

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

/// The registration page title.
pub const REGISTER_TITLE: MessageId = MessageId(1_020_001);
/// The registration identifier field label.
pub const REGISTER_IDENTIFIER_LABEL: MessageId = MessageId(1_020_002);
/// The registration password field label.
pub const REGISTER_PASSWORD_LABEL: MessageId = MessageId(1_020_003);
/// The registration submit button label.
pub const REGISTER_SUBMIT_LABEL: MessageId = MessageId(1_020_004);
/// The uniform closed registration acknowledgment (the #64 anti enumeration ack).
pub const REGISTER_ACK: MessageId = MessageId(1_020_005);
/// The waitlist pending acknowledgment.
pub const REGISTER_PENDING: MessageId = MessageId(1_020_006);

/// The MFA challenge page title.
pub const MFA_CHALLENGE_TITLE: MessageId = MessageId(1_030_001);
/// The MFA code field label (a TOTP or recovery code).
pub const MFA_CODE_LABEL: MessageId = MessageId(1_030_002);
/// The MFA submit button label.
pub const MFA_SUBMIT_LABEL: MessageId = MessageId(1_030_003);
/// The MFA enrollment page title.
pub const MFA_ENROLL_TITLE: MessageId = MessageId(1_030_004);
/// The MFA enrollment instructions (scan the code, then enter a code to confirm).
pub const MFA_ENROLL_INSTRUCTIONS: MessageId = MessageId(1_030_005);

/// The login success note.
pub const LOGIN_SUCCESS: MessageId = MessageId(1_500_001);
/// The registration success note (a new account was created and signed in).
pub const REGISTER_SUCCESS: MessageId = MessageId(1_520_001);
/// The MFA success note (a second factor was proven).
pub const MFA_SUCCESS: MessageId = MessageId(1_530_001);

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

/// The registration identifier field is required (a per node validation error). NOT an
/// enumeration oracle: an empty field does not depend on whether the identifier exists.
pub const REGISTER_IDENTIFIER_REQUIRED: MessageId = MessageId(4_200_001);
/// The registration password field is required (a per node validation error).
pub const REGISTER_PASSWORD_REQUIRED: MessageId = MessageId(4_200_002);
/// The chosen password was refused by policy, strength, or breach screening (a per node
/// validation error). Existence INDEPENDENT, so it is never an enumeration oracle.
pub const REGISTER_PASSWORD_REJECTED: MessageId = MessageId(4_200_003);
/// The address cannot be used to register (the #80 disposable/low reputation block), an
/// ORDINARY validation failure that leaks nothing about whether the identifier exists.
pub const REGISTER_ADDRESS_UNUSABLE: MessageId = MessageId(4_200_004);
/// Additional verification is required (the #80 proof of work gate was not satisfied).
pub const REGISTER_VERIFICATION_REQUIRED: MessageId = MessageId(4_200_005);
/// Too many registration attempts (the #64 register path throttle). Existence
/// independent, keyed only on the identifier and IP dimensions.
pub const REGISTER_THROTTLED: MessageId = MessageId(4_200_006);
/// That identifier is already registered. Emitted ONLY under OPEN registration, where
/// duplicate disclosure is the accepted posture; the closed/uniform path never emits it.
pub const REGISTER_ALREADY_REGISTERED: MessageId = MessageId(4_200_007);

/// The uniform MFA failure: the code was incorrect or expired. The SAME id whether the
/// code was a wrong TOTP, a replay, or a wrong recovery code (never an oracle).
pub const MFA_CODE_INCORRECT: MessageId = MessageId(4_300_001);
/// The MFA code field is required (a per node validation error).
pub const MFA_CODE_REQUIRED: MessageId = MessageId(4_300_002);
/// Too many second factor attempts (the #64/#72 second factor path throttle).
pub const MFA_THROTTLED: MessageId = MessageId(4_300_003);

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
        id: REGISTER_TITLE,
        name: "register.title",
        kind: MessageKind::Info,
        text: "Create account",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_IDENTIFIER_LABEL,
        name: "register.identifier.label",
        kind: MessageKind::Info,
        text: "Identifier",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_PASSWORD_LABEL,
        name: "register.password.label",
        kind: MessageKind::Info,
        text: "Password",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_SUBMIT_LABEL,
        name: "register.submit.label",
        kind: MessageKind::Info,
        text: "Create account",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_ACK,
        name: "register.ack",
        kind: MessageKind::Info,
        text: "If registration is available for that address, we have sent instructions to \
               complete it.",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_PENDING,
        name: "register.pending",
        kind: MessageKind::Info,
        text: "Your registration is pending approval. We will be in touch once your account \
               has been reviewed.",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_CHALLENGE_TITLE,
        name: "mfa.challenge.title",
        kind: MessageKind::Info,
        text: "Verify your identity",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_CODE_LABEL,
        name: "mfa.code.label",
        kind: MessageKind::Info,
        text: "Authentication code",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_SUBMIT_LABEL,
        name: "mfa.submit.label",
        kind: MessageKind::Info,
        text: "Verify",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_ENROLL_TITLE,
        name: "mfa.enroll.title",
        kind: MessageKind::Info,
        text: "Set up an authenticator",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_ENROLL_INSTRUCTIONS,
        name: "mfa.enroll.instructions",
        kind: MessageKind::Info,
        text: "Add this secret to your authenticator app, then enter a code to confirm.",
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
        id: REGISTER_SUCCESS,
        name: "register.success",
        kind: MessageKind::Success,
        text: "Your account has been created.",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_SUCCESS,
        name: "mfa.success",
        kind: MessageKind::Success,
        text: "Your identity has been verified.",
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
    MessageSpec {
        id: REGISTER_IDENTIFIER_REQUIRED,
        name: "register.identifier_required",
        kind: MessageKind::Error,
        text: "Enter an identifier.",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_PASSWORD_REQUIRED,
        name: "register.password_required",
        kind: MessageKind::Error,
        text: "Choose a password.",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_PASSWORD_REJECTED,
        name: "register.password_rejected",
        kind: MessageKind::Error,
        text: "That password cannot be used. Choose a different one.",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_ADDRESS_UNUSABLE,
        name: "register.address_unusable",
        kind: MessageKind::Error,
        text: "That address cannot be used to register. Use a different address.",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_VERIFICATION_REQUIRED,
        name: "register.verification_required",
        kind: MessageKind::Error,
        text: "Additional verification is required. Please try again.",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_THROTTLED,
        name: "register.throttled",
        kind: MessageKind::Error,
        text: "Too many attempts. Wait a moment and try again.",
        context_keys: &[],
    },
    MessageSpec {
        id: REGISTER_ALREADY_REGISTERED,
        name: "register.already_registered",
        kind: MessageKind::Error,
        text: "That identifier is already registered.",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_CODE_INCORRECT,
        name: "mfa.code_incorrect",
        kind: MessageKind::Error,
        text: "Incorrect or expired code.",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_CODE_REQUIRED,
        name: "mfa.code_required",
        kind: MessageKind::Error,
        text: "Enter a code to continue.",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_THROTTLED,
        name: "mfa.throttled",
        kind: MessageKind::Error,
        text: "Too many attempts. Wait a moment and try again.",
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
