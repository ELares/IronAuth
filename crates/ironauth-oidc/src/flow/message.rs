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
//!   registration, `1030xxx` MFA (challenge, enrollment, and the issue #311 show once
//!   recovery codes the enrollment mints), `1070xxx` the generic signup
//!   field label (issue #87, one id for every configured field, the field pointer riding
//!   the context so the registry stays finite), `1080xxx` consent (issue #88, the title,
//!   the client identity and verification badges, the well known scope descriptions plus a
//!   generic id carrying an unregistered scope token in the context, and the allow/deny
//!   labels);
//! - `15xxxxx` success copy;
//! - `4000xxx` flow level errors (expiry, completion, malformed input);
//! - `4100xxx` login journey errors (the uniform identifier or password failure, the
//!   per node validation errors);
//! - `4200xxx` registration journey errors (the per node validation errors, the uniform
//!   abuse and policy failures, the open mode duplicate disclosure); `4270xxx` the generic
//!   signup field validation errors (issue #87, one fixed id per failure KIND, the field
//!   pointer riding the context);
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
/// The show once recovery codes page title (issue #311).
pub const MFA_RECOVERY_CODES_TITLE: MessageId = MessageId(1_030_006);
/// The show once recovery codes instructions (issue #311): the codes are displayed exactly
/// once, here, at the moment the in flow enrollment minted them. The number of codes rides the
/// `count` structured context (the flow's answer to the direct account API's
/// `recovery_codes_remaining` field), never the copy string.
pub const MFA_RECOVERY_CODES_INSTRUCTIONS: MessageId = MessageId(1_030_007);
/// The label on each display only recovery code node (issue #311).
pub const MFA_RECOVERY_CODE_LABEL: MessageId = MessageId(1_030_008);
/// The recovery codes acknowledgment checkbox label (issue #311).
pub const MFA_RECOVERY_CODES_ACK_LABEL: MessageId = MessageId(1_030_009);
/// The recovery codes continue button label (issue #311).
pub const MFA_RECOVERY_CODES_CONTINUE_LABEL: MessageId = MessageId(1_030_010);
/// The notice a RE-RENDER of the show once recovery codes state carries (issue #311): the codes
/// were displayed once when they were minted and are NOT re-readable from the flow, so a back
/// navigation, a replay, or a resume points the user at the account surface instead. Informational
/// (nothing is lost; the codes are live and a fresh set can be minted there).
pub const MFA_RECOVERY_CODES_UNAVAILABLE: MessageId = MessageId(1_030_011);

/// The recovery page title.
pub const RECOVERY_TITLE: MessageId = MessageId(1_040_001);
/// The recovery identifier field label.
pub const RECOVERY_IDENTIFIER_LABEL: MessageId = MessageId(1_040_002);
/// The recovery request submit button label.
pub const RECOVERY_SUBMIT_LABEL: MessageId = MessageId(1_040_003);
/// The UNIFORM recovery acknowledgment (the #64 anti enumeration ack): the SAME copy for a
/// known and an unknown identifier, so it never discloses whether the account exists.
pub const RECOVERY_ACK: MessageId = MessageId(1_040_004);
/// The recovery one time code field label.
pub const RECOVERY_CODE_LABEL: MessageId = MessageId(1_040_005);
/// The recovery code submit button label.
pub const RECOVERY_VERIFY_LABEL: MessageId = MessageId(1_040_006);

/// The federated login launcher title.
pub const FEDERATION_TITLE: MessageId = MessageId(1_060_001);
/// The "continue with {provider}" affordance label. The provider slug rides the structured
/// context, never the copy string, so i18n keys on the id and the context.
pub const FEDERATION_CONTINUE_LABEL: MessageId = MessageId(1_060_002);

/// The GENERIC signup field label (issue #87): ONE id for every configured signup field, the
/// field's RFC 6901 trait pointer riding the `field` context so a locale bundle keys per
/// field copy on the pointer while the numeric id registry stays finite. The default text is
/// a neutral fallback for a client that does not localize.
pub const SIGNUP_FIELD_LABEL: MessageId = MessageId(1_070_001);
/// The progressive profiling submit button label (issue #87): the control that skips or submits
/// the held later-login profiling step. A skip (an empty submit) still mints the session.
pub const PROGRESSIVE_PROFILING_SUBMIT_LABEL: MessageId = MessageId(1_070_002);
/// The progressive profiling prompt (issue #87): the leading copy that explains the optional
/// later-login fields can be completed now or skipped. Informational only.
pub const PROGRESSIVE_PROFILING_PROMPT: MessageId = MessageId(1_070_003);

/// The consent page title (issue #88): the heading of the consent screen rendered as flow
/// nodes.
pub const CONSENT_TITLE: MessageId = MessageId(1_080_001);
/// The consent client identity copy (issue #88): the client asking for access. The client's
/// display name rides the `client_name` context and its optional logo the `logo_uri` context,
/// never the copy string, so a locale bundle keys on the id and the context while the numeric
/// id registry stays finite.
pub const CONSENT_CLIENT_NAME: MessageId = MessageId(1_080_002);
/// The consent verified badge (issue #88): the client has been verified by an administrator.
pub const CONSENT_CLIENT_VERIFIED: MessageId = MessageId(1_080_003);
/// The consent unverified badge (issue #88): the client has NOT been verified, shown so the
/// end user weighs the request accordingly.
pub const CONSENT_CLIENT_UNVERIFIED: MessageId = MessageId(1_080_004);
/// The consent scopes intro (issue #88): the leading copy before the per scope descriptions.
pub const CONSENT_SCOPES_INTRO: MessageId = MessageId(1_080_005);
/// The `openid` scope description (issue #88).
pub const CONSENT_SCOPE_OPENID: MessageId = MessageId(1_080_006);
/// The `profile` scope description (issue #88).
pub const CONSENT_SCOPE_PROFILE: MessageId = MessageId(1_080_007);
/// The `email` scope description (issue #88).
pub const CONSENT_SCOPE_EMAIL: MessageId = MessageId(1_080_008);
/// The `offline_access` scope description (issue #88).
pub const CONSENT_SCOPE_OFFLINE_ACCESS: MessageId = MessageId(1_080_009);
/// The `address` scope description (issue #88).
pub const CONSENT_SCOPE_ADDRESS: MessageId = MessageId(1_080_010);
/// The `phone` scope description (issue #88).
pub const CONSENT_SCOPE_PHONE: MessageId = MessageId(1_080_011);
/// The `admin` (sensitive) scope description (issue #88).
pub const CONSENT_SCOPE_ADMIN: MessageId = MessageId(1_080_012);
/// The `management` (sensitive) scope description (issue #88).
pub const CONSENT_SCOPE_MANAGEMENT: MessageId = MessageId(1_080_013);
/// The GENERIC scope description (issue #88): ONE id for every scope with no well known
/// description, the raw scope token riding the `scope` context (mirrors the issue #87 signup
/// field pattern) so the numeric id registry stays finite for arbitrary custom scopes.
pub const CONSENT_SCOPE_GENERIC: MessageId = MessageId(1_080_014);
/// The consent allow button label (issue #88): grant the client access.
pub const CONSENT_ALLOW_LABEL: MessageId = MessageId(1_080_015);
/// The consent deny button label (issue #88): refuse the client access.
pub const CONSENT_DENY_LABEL: MessageId = MessageId(1_080_016);

/// The organization picker prompt (issue #94, PR-B2): the leading copy that explains the subject
/// belongs to several organizations and must choose which one this login is for. Informational.
pub const ORG_PICKER_PROMPT: MessageId = MessageId(1_090_001);
/// The organization picker option label (issue #94, PR-B2): ONE id for every listed organization,
/// the organization's human-facing display name riding the `name` context (mirrors the issue #88
/// consent client-name pattern) so a locale bundle keys on the id while the numeric registry stays
/// finite for arbitrary organization names.
pub const ORG_PICKER_OPTION_LABEL: MessageId = MessageId(1_090_002);

/// The organization-creation name field label (issue #96, criterion 5). Rendered only when the
/// deployment installed the provisioning seam.
pub const ORG_PICKER_CREATE_NAME_LABEL: MessageId = MessageId(1_090_003);
/// The organization-creation submit label (issue #96, criterion 5).
pub const ORG_PICKER_CREATE_LABEL: MessageId = MessageId(1_090_004);

/// The login success note.
pub const LOGIN_SUCCESS: MessageId = MessageId(1_500_001);
/// The registration success note (a new account was created and signed in).
pub const REGISTER_SUCCESS: MessageId = MessageId(1_520_001);
/// The MFA success note (a second factor was proven).
pub const MFA_SUCCESS: MessageId = MessageId(1_530_001);
/// The recovery success note (access was recovered and the session established).
pub const RECOVERY_SUCCESS: MessageId = MessageId(1_540_001);

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

/// A required signup field (issue #87) was left empty. GENERIC across every configured
/// field, the field's RFC 6901 trait pointer riding the `field` context. Existence
/// independent, so it is never an enumeration oracle.
pub const SIGNUP_FIELD_REQUIRED: MessageId = MessageId(4_270_001);
/// A signup field value is below its effective lower bound (issue #87): shorter than the
/// minimum length, fewer than the minimum items, or less than the numeric minimum. The
/// field pointer rides the `field` context.
pub const SIGNUP_FIELD_TOO_SHORT: MessageId = MessageId(4_270_002);
/// A signup field value is above its effective upper bound (issue #87): longer than the
/// maximum length, more than the maximum items, or greater than the numeric maximum. The
/// field pointer rides the `field` context.
pub const SIGNUP_FIELD_TOO_LONG: MessageId = MessageId(4_270_003);
/// A signup field value is not one of the enumerated permitted values (issue #87). The
/// field pointer rides the `field` context.
pub const SIGNUP_FIELD_NOT_ALLOWED: MessageId = MessageId(4_270_004);
/// A signup field value is not the expected type or shape (issue #87): it does not match the
/// field's effective type. The field pointer rides the `field` context.
pub const SIGNUP_FIELD_INVALID_FORMAT: MessageId = MessageId(4_270_005);

/// A registered HTTP flow target rejected this field WITHOUT saying why (issue #112). The
/// field pointer rides the `field` context.
///
/// Separate from [`FLOW_TARGET_REJECTED_WITH_REASON`] because interpolation leaves an
/// unreferenced `{placeholder}` VERBATIM: a single id whose text were `{reason}` would render
/// the literal string `{reason}` to a person whenever the target sent no message. The id
/// selects the template, so there are two ids because there are genuinely two templates.
pub const FLOW_TARGET_REJECTED: MessageId = MessageId(4_280_001);
/// A registered HTTP flow target rejected this field AND explained why (issue #112). The
/// field pointer rides the `field` context and the target's own text, capped, rides `reason`.
///
/// The text is the target's, so it is a message PARAMETER and never a minted id: a third
/// party cannot add ids to the registry, and the render path escapes the value.
pub const FLOW_TARGET_REJECTED_WITH_REASON: MessageId = MessageId(4_280_002);
/// A sync HTTP flow target could not be consulted and its policy is fail closed (issue #112):
/// it timed out, failed at the transport, answered non 2xx, answered unverifiably, or answered
/// something this contract does not define. Deliberately uniform, and deliberately carries NO
/// field: there is nothing truthful to say about which field was wrong, and naming one would
/// invent a rejection the target never made.
pub const FLOW_TARGET_UNAVAILABLE: MessageId = MessageId(4_280_003);

/// The uniform MFA failure: the code was incorrect or expired. The SAME id whether the
/// code was a wrong TOTP, a replay, or a wrong recovery code (never an oracle).
pub const MFA_CODE_INCORRECT: MessageId = MessageId(4_300_001);
/// The MFA code field is required (a per node validation error).
pub const MFA_CODE_REQUIRED: MessageId = MessageId(4_300_002);
/// Too many second factor attempts (the #64/#72 second factor path throttle).
pub const MFA_THROTTLED: MessageId = MessageId(4_300_003);
/// The show once recovery codes acknowledgment is required (issue #311): a per node validation
/// error on the acknowledgment checkbox, so the login does not complete until the user confirms
/// they saved the codes. Carries no state and no user data, so it is never an oracle.
pub const MFA_RECOVERY_CODES_ACK_REQUIRED: MessageId = MessageId(4_300_004);

/// The recovery identifier field is required (a per node validation error). Existence
/// INDEPENDENT (an empty field does not depend on whether the identifier exists), so it is
/// never an enumeration oracle.
pub const RECOVERY_IDENTIFIER_REQUIRED: MessageId = MessageId(4_400_001);
/// The recovery code field is required (a per node validation error).
pub const RECOVERY_CODE_REQUIRED: MessageId = MessageId(4_400_002);
/// The UNIFORM recovery code failure: the code was incorrect or expired. The SAME id whether
/// the identifier was known with a wrong code, or unknown entirely (never an oracle).
pub const RECOVERY_CODE_INCORRECT: MessageId = MessageId(4_400_003);
/// Too many recovery attempts (the #64 recovery path throttle). Existence independent.
pub const RECOVERY_THROTTLED: MessageId = MessageId(4_400_004);

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
        id: MFA_RECOVERY_CODES_TITLE,
        name: "mfa.recovery_codes.title",
        kind: MessageKind::Info,
        text: "Save your recovery codes",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_RECOVERY_CODES_INSTRUCTIONS,
        name: "mfa.recovery_codes.instructions",
        kind: MessageKind::Info,
        text: "These one time recovery codes are shown once, now. Save them somewhere safe: \
               each one signs you in if you lose your authenticator.",
        context_keys: &["count"],
    },
    MessageSpec {
        id: MFA_RECOVERY_CODE_LABEL,
        name: "mfa.recovery_codes.code.label",
        kind: MessageKind::Info,
        text: "Recovery code",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_RECOVERY_CODES_ACK_LABEL,
        name: "mfa.recovery_codes.ack.label",
        kind: MessageKind::Info,
        text: "I have saved my recovery codes",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_RECOVERY_CODES_CONTINUE_LABEL,
        name: "mfa.recovery_codes.continue.label",
        kind: MessageKind::Info,
        text: "Continue",
        context_keys: &[],
    },
    MessageSpec {
        id: MFA_RECOVERY_CODES_UNAVAILABLE,
        name: "mfa.recovery_codes.unavailable",
        kind: MessageKind::Info,
        text: "Your recovery codes were shown once when they were created and cannot be shown \
               again here. Your authenticator is set up; generate a fresh set from your account \
               security settings whenever you need one.",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_TITLE,
        name: "recovery.title",
        kind: MessageKind::Info,
        text: "Recover your account",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_IDENTIFIER_LABEL,
        name: "recovery.identifier.label",
        kind: MessageKind::Info,
        text: "Identifier",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_SUBMIT_LABEL,
        name: "recovery.submit.label",
        kind: MessageKind::Info,
        text: "Send a recovery code",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_ACK,
        name: "recovery.ack",
        kind: MessageKind::Info,
        text: "If an account exists for that identifier, we have sent a recovery code. Enter \
               it below to continue.",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_CODE_LABEL,
        name: "recovery.code.label",
        kind: MessageKind::Info,
        text: "Recovery code",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_VERIFY_LABEL,
        name: "recovery.verify.label",
        kind: MessageKind::Info,
        text: "Verify and sign in",
        context_keys: &[],
    },
    MessageSpec {
        id: FEDERATION_TITLE,
        name: "federation.title",
        kind: MessageKind::Info,
        text: "Continue with a provider",
        context_keys: &[],
    },
    MessageSpec {
        id: FEDERATION_CONTINUE_LABEL,
        name: "federation.continue.label",
        kind: MessageKind::Info,
        text: "Continue with your identity provider",
        context_keys: &["provider"],
    },
    MessageSpec {
        id: SIGNUP_FIELD_LABEL,
        name: "signup.field.label",
        kind: MessageKind::Info,
        text: "Additional information",
        context_keys: &["field"],
    },
    MessageSpec {
        id: PROGRESSIVE_PROFILING_SUBMIT_LABEL,
        name: "progressive_profiling.submit.label",
        kind: MessageKind::Info,
        text: "Continue",
        context_keys: &[],
    },
    MessageSpec {
        id: PROGRESSIVE_PROFILING_PROMPT,
        name: "progressive_profiling.prompt",
        kind: MessageKind::Info,
        text: "Help us complete your profile. You can fill in these details now or skip for \
               now.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_TITLE,
        name: "consent.title",
        kind: MessageKind::Info,
        text: "Authorize access",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_CLIENT_NAME,
        name: "consent.client.name",
        kind: MessageKind::Info,
        text: "{client_name} is requesting access to your account.",
        context_keys: &["client_name", "logo_uri"],
    },
    MessageSpec {
        id: CONSENT_CLIENT_VERIFIED,
        name: "consent.client.verified",
        kind: MessageKind::Info,
        text: "This application has been verified.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_CLIENT_UNVERIFIED,
        name: "consent.client.unverified",
        kind: MessageKind::Info,
        text: "This application has not been verified.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPES_INTRO,
        name: "consent.scopes.intro",
        kind: MessageKind::Info,
        text: "It is requesting the following access:",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_OPENID,
        name: "consent.scope.openid.description",
        kind: MessageKind::Info,
        text: "Confirm your identity.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_PROFILE,
        name: "consent.scope.profile.description",
        kind: MessageKind::Info,
        text: "Access your basic profile information.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_EMAIL,
        name: "consent.scope.email.description",
        kind: MessageKind::Info,
        text: "Access your email address.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_OFFLINE_ACCESS,
        name: "consent.scope.offline_access.description",
        kind: MessageKind::Info,
        text: "Maintain access when you are not using the application.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_ADDRESS,
        name: "consent.scope.address.description",
        kind: MessageKind::Info,
        text: "Access your postal address.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_PHONE,
        name: "consent.scope.phone.description",
        kind: MessageKind::Info,
        text: "Access your phone number.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_ADMIN,
        name: "consent.scope.admin.description",
        kind: MessageKind::Info,
        text: "Perform administrative actions on your behalf.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_MANAGEMENT,
        name: "consent.scope.management.description",
        kind: MessageKind::Info,
        text: "Manage configuration on your behalf.",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_SCOPE_GENERIC,
        name: "consent.scope.generic.description",
        kind: MessageKind::Info,
        text: "Access an additional permission.",
        context_keys: &["scope"],
    },
    MessageSpec {
        id: CONSENT_ALLOW_LABEL,
        name: "consent.allow.label",
        kind: MessageKind::Info,
        text: "Allow",
        context_keys: &[],
    },
    MessageSpec {
        id: CONSENT_DENY_LABEL,
        name: "consent.deny.label",
        kind: MessageKind::Info,
        text: "Deny",
        context_keys: &[],
    },
    MessageSpec {
        id: ORG_PICKER_PROMPT,
        name: "org_picker.prompt",
        kind: MessageKind::Info,
        text: "Choose the organization to continue as.",
        context_keys: &[],
    },
    MessageSpec {
        id: ORG_PICKER_OPTION_LABEL,
        name: "org_picker.option.label",
        kind: MessageKind::Info,
        text: "Continue",
        context_keys: &["name"],
    },
    MessageSpec {
        id: ORG_PICKER_CREATE_NAME_LABEL,
        name: "org_picker.create.name.label",
        kind: MessageKind::Info,
        text: "New organization name",
        context_keys: &[],
    },
    MessageSpec {
        id: ORG_PICKER_CREATE_LABEL,
        name: "org_picker.create.label",
        kind: MessageKind::Info,
        text: "Create organization",
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
        id: RECOVERY_SUCCESS,
        name: "recovery.success",
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
        id: SIGNUP_FIELD_REQUIRED,
        name: "signup.field.required",
        kind: MessageKind::Error,
        text: "This field is required.",
        context_keys: &["field"],
    },
    MessageSpec {
        id: SIGNUP_FIELD_TOO_SHORT,
        name: "signup.field.too_short",
        kind: MessageKind::Error,
        text: "This value is too short.",
        context_keys: &["field"],
    },
    MessageSpec {
        id: SIGNUP_FIELD_TOO_LONG,
        name: "signup.field.too_long",
        kind: MessageKind::Error,
        text: "This value is too long.",
        context_keys: &["field"],
    },
    MessageSpec {
        id: SIGNUP_FIELD_NOT_ALLOWED,
        name: "signup.field.not_allowed",
        kind: MessageKind::Error,
        text: "This value is not one of the permitted values.",
        context_keys: &["field"],
    },
    MessageSpec {
        id: SIGNUP_FIELD_INVALID_FORMAT,
        name: "signup.field.invalid_format",
        kind: MessageKind::Error,
        text: "This value is not in the expected format.",
        context_keys: &["field"],
    },
    MessageSpec {
        id: FLOW_TARGET_REJECTED,
        name: "flow_target.rejected",
        kind: MessageKind::Error,
        text: "This value was rejected.",
        context_keys: &["field"],
    },
    MessageSpec {
        id: FLOW_TARGET_REJECTED_WITH_REASON,
        name: "flow_target.rejected_with_reason",
        kind: MessageKind::Error,
        text: "{reason}",
        context_keys: &["field", "reason"],
    },
    MessageSpec {
        id: FLOW_TARGET_UNAVAILABLE,
        name: "flow_target.unavailable",
        kind: MessageKind::Error,
        text: "We could not complete your request. Try again.",
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
    MessageSpec {
        id: MFA_RECOVERY_CODES_ACK_REQUIRED,
        name: "mfa.recovery_codes.ack_required",
        kind: MessageKind::Error,
        text: "Confirm you have saved your recovery codes to continue.",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_IDENTIFIER_REQUIRED,
        name: "recovery.identifier_required",
        kind: MessageKind::Error,
        text: "Enter your identifier.",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_CODE_REQUIRED,
        name: "recovery.code_required",
        kind: MessageKind::Error,
        text: "Enter the recovery code.",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_CODE_INCORRECT,
        name: "recovery.code_incorrect",
        kind: MessageKind::Error,
        text: "Incorrect or expired code.",
        context_keys: &[],
    },
    MessageSpec {
        id: RECOVERY_THROTTLED,
        name: "recovery.throttled",
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
