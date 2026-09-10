//! The CAEP vocabulary and the semantic mapping from an internal session end to it
//! (issue #144).
//!
//! # Why a mapping table and not a cast
//!
//! [`SessionEndCause`] is this deployment's OWN vocabulary: it records why a row in
//! `sessions` stopped being usable, in terms that only mean something here. CAEP is a
//! vocabulary a receiver written by someone else already understands. The two are not the
//! same shape, and pretending they are is the defect this module exists to prevent:
//!
//! - the cause set is OPEN to us and CLOSED to a receiver. Adding a seventh cause must not
//!   silently invent a seventh CAEP event type nobody can parse, so the mapping is
//!   exhaustive by `match` and a new variant fails to compile until someone decides what a
//!   receiver should be told.
//! - one CAEP type covers several causes. All six ends are a `session-revoked` to a
//!   receiver, because what a receiver DOES about them is identical: stop honouring
//!   anything minted under that session. The distinction between them survives in
//!   `initiating_entity` and `reason_admin`, which is where CAEP puts it.
//!
//! # What is NOT here
//!
//! [`CREDENTIAL_CHANGE`], [`TOKEN_CLAIMS_CHANGE`] and [`ASSURANCE_LEVEL_CHANGE`] are
//! defined because they are part of the vocabulary this build speaks about, but NOTHING
//! emits them yet and they are deliberately absent from
//! [`EVENTS_SUPPORTED`](crate::ssf_set::EVENTS_SUPPORTED). A password change is the sharp
//! case: it ends sessions, so it produces a `session-revoked` here, and it also changes a
//! credential, which is a `credential-change` -- but that second signal is about the
//! CREDENTIAL, not about any session, and it has to come from the credential layer with
//! the credential's own detail. Deriving it from a session end would report a changed
//! credential once per session the user happened to have open, and zero times for a user
//! with no session at all.

use ironauth_store::SessionEndCause;

use crate::ssf_set::SecurityEvent;

/// CAEP 1.0: a session belonging to the named subject was revoked.
///
/// THE SUBJECT IS THE USER, not the ended session. RFC 9493 gives this build three subject
/// formats and none of them names a session, so `sub_id` carries the user the session
/// belonged to. A receiver acts on that by ending what it holds for that user; it cannot
/// single out the one session, and this transmitter must not imply that it can.
pub const SESSION_REVOKED: &str =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

/// CAEP 1.0: a credential belonging to the subject was created, changed or removed.
///
/// DEFINED, NOT EMITTED. See the module header for why a session end cannot produce it.
pub const CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";

/// CAEP 1.0: a claim the transmitter asserts about the subject changed value.
///
/// DEFINED, NOT EMITTED.
pub const TOKEN_CLAIMS_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";

/// CAEP 1.0: the subject's authentication assurance level moved up or down.
///
/// DEFINED, NOT EMITTED.
pub const ASSURANCE_LEVEL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";

/// Who set a CAEP event in motion, as CAEP 1.0 spells it.
///
/// A CLOSED set of four strings in the specification. It is an enum here rather than a
/// `&str` per mapping row so that a row cannot spell one of them wrong: a receiver
/// matching on `initiating_entity` treats an unknown value as absent, so a typo degrades
/// silently into "we did not say who did this".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatingEntity {
    /// An operator acting through a management surface.
    Admin,
    /// The end user themselves.
    User,
    /// A policy evaluation, with no human in the loop at that moment.
    Policy,
    /// The transmitter itself, structurally.
    System,
}

impl InitiatingEntity {
    /// The CAEP wire string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
            Self::Policy => "policy",
            Self::System => "system",
        }
    }
}

/// One row of the documented semantic mapping (issue #144 criterion 2).
///
/// Every field is what a RECEIVER is told. `cause` is not carried into the SET: it is this
/// deployment's internal spelling, and a receiver that branched on it would be coupled to
/// a vocabulary we change freely.
///
/// THERE IS NO `initiating_entity` COLUMN HERE, and its absence is the finding that
/// reshaped this table. A cause does not determine who acted. `UserRevokedAll` is written
/// by the admin session surface, by SCIM deprovisioning, by the self-service account and
/// trusted-device surfaces, and by the risk engine: one cause spanning CAEP's `admin`,
/// `system`, `user` and `policy`. A table that answered `user` for it would have been
/// wrong three times out of four, and confidently. See [`initiating_entity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEndMapping {
    /// The CAEP event type URI the cause becomes.
    pub event_type: &'static str,
    /// The administrator-facing reason, in English.
    ///
    /// CAEP renders `reason_admin` as an object keyed by language tag; this is the value
    /// under `en`. It is prose for a human reading an audit trail, and MUST NOT be parsed:
    /// anything a receiver needs to branch on belongs in a typed member.
    ///
    /// It describes WHAT happened and never WHO did it, for the reason the struct doc
    /// gives: the cause does not know who did it.
    pub reason_admin_en: &'static str,
}

/// THE MAPPING TABLE (issue #144 criterion 2).
///
/// Exhaustive over [`SessionEndCause`] by `match`, so a new cause is a compile error here
/// before it is a silently unmapped signal in production.
///
/// All six rows carry the same `event_type` and that is the correct answer, not a
/// degenerate one: CAEP has exactly one event for "this session is over". What differs
/// between them is the human-readable reason, which is the only thing the cause alone
/// actually determines.
#[must_use]
pub fn map_session_end(cause: SessionEndCause) -> SessionEndMapping {
    let reason_admin_en = match cause {
        SessionEndCause::Revoked => "This session was revoked individually.",
        SessionEndCause::BulkRevoked => "This session was revoked as part of a set.",
        SessionEndCause::UserRevokedAll => "Every session belonging to this user was revoked.",
        SessionEndCause::LoggedOut => "The user logged out.",
        SessionEndCause::ReplacedByOtherSubject => {
            "A different user authenticated on the same browser session."
        }
        SessionEndCause::PasswordChanged => {
            "The user's password changed, which ends their other sessions."
        }
    };
    SessionEndMapping {
        event_type: SESSION_REVOKED,
        reason_admin_en,
    }
}

/// Who set this off, when this build can actually tell (CAEP 1.0 `initiating_entity`).
///
/// `None` MEANS NOT STATED, and that is a deliberate answer rather than a gap. CAEP makes
/// the member OPTIONAL, and a receiver reads an absent value as "the transmitter did not
/// say". Naming the wrong initiator is strictly worse than naming none: an audit trail
/// that records an operator revoking a session the user themselves ended is evidence of
/// something that did not happen.
///
/// # What is knowable here
///
/// The session-ended record carries an ACTOR KIND, which this deployment spells `human`,
/// `service`, or `agent`. That separates "a person did this" from "something automated
/// did this", and the automated half maps cleanly onto CAEP's `system`. It does NOT
/// separate an operator from the subject acting on their own account, which is exactly
/// CAEP's `admin` versus `user` distinction, so a human actor yields `None`.
///
/// Two causes are decided by the cause itself and override the actor:
///
/// - `LoggedOut` is written only by the RP logout path, which is the end user's own act
///   whatever principal carries it, so it is `user`.
/// - `ReplacedByOtherSubject` is structural. The outgoing user did not ask for it and
///   neither did an operator; a different subject authenticated and this session ended as
///   a consequence. Nobody INITIATED it against this user, which is `system`.
#[must_use]
pub fn initiating_entity(cause: SessionEndCause, actor_kind: &str) -> Option<InitiatingEntity> {
    match cause {
        SessionEndCause::LoggedOut => Some(InitiatingEntity::User),
        SessionEndCause::ReplacedByOtherSubject => Some(InitiatingEntity::System),
        _ => match actor_kind {
            "service" | "agent" => Some(InitiatingEntity::System),
            // A HUMAN, AND THAT IS ALL WE KNOW. `admin` and `user` are the same actor kind
            // here, so either answer would be a coin flip recorded as a fact.
            _ => None,
        },
    }
}

/// Build the CAEP event body for one session end.
///
/// `occurred_at_unix_micros` is the moment the session ENDED, carried on the session-ended
/// outbox message, not the moment this SET is built. A retry re-renders the same body, and
/// a receiver comparing `event_timestamp` against its own record of the session sees the
/// end, not the delivery.
///
/// `actor_kind` is the session-ended record's own actor spelling. It is passed through
/// rather than interpreted here beyond what [`initiating_entity`] can support, and when
/// that answers `None` the member is OMITTED rather than filled with a guess.
#[must_use]
pub fn session_end_event(
    cause: SessionEndCause,
    actor_kind: &str,
    occurred_at_unix_micros: i64,
) -> SecurityEvent {
    let mapping = map_session_end(cause);
    let mut payload = serde_json::Map::new();
    // CAEP renders `event_timestamp` in SECONDS. The internal stamp is microseconds, and
    // `div_euclid` rather than `/` so a pre-epoch stamp floors instead of truncating
    // toward zero, which would round it into the future.
    payload.insert(
        "event_timestamp".to_owned(),
        serde_json::Value::from(occurred_at_unix_micros.div_euclid(1_000_000)),
    );
    if let Some(entity) = initiating_entity(cause, actor_kind) {
        payload.insert(
            "initiating_entity".to_owned(),
            serde_json::Value::String(entity.as_str().to_owned()),
        );
    }
    payload.insert(
        "reason_admin".to_owned(),
        serde_json::json!({ "en": mapping.reason_admin_en }),
    );
    SecurityEvent {
        event_type: mapping.event_type.to_owned(),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every cause this build can record.
    ///
    /// The `match` below is the GUARD, and it is why this list cannot quietly fall behind
    /// the enum: adding a seventh variant makes this function fail to compile, so a new
    /// cause cannot be added without also being added here and therefore covered by every
    /// table-driven test in this module. An earlier version of this asserted a hard-coded
    /// length instead, which a new variant would have satisfied by simply not appearing.
    fn all_causes() -> Vec<SessionEndCause> {
        let exhaustive = |cause: SessionEndCause| match cause {
            SessionEndCause::Revoked
            | SessionEndCause::BulkRevoked
            | SessionEndCause::UserRevokedAll
            | SessionEndCause::LoggedOut
            | SessionEndCause::ReplacedByOtherSubject
            | SessionEndCause::PasswordChanged => (),
        };
        let causes = vec![
            SessionEndCause::Revoked,
            SessionEndCause::BulkRevoked,
            SessionEndCause::UserRevokedAll,
            SessionEndCause::LoggedOut,
            SessionEndCause::ReplacedByOtherSubject,
            SessionEndCause::PasswordChanged,
        ];
        for cause in &causes {
            exhaustive(*cause);
        }
        causes
    }

    #[test]
    fn the_cause_list_round_trips_through_the_stores_own_parser() {
        // The compile-time guard in `all_causes` catches an ADDED variant. This catches a
        // RENAMED wire string, which would compile fine and silently stop matching what
        // the store writes onto a session-ended message.
        for cause in all_causes() {
            assert_eq!(
                SessionEndCause::from_wire(cause.as_str()),
                Some(cause),
                "{} does not round-trip through the store's parser",
                cause.as_str()
            );
        }
    }

    #[test]
    fn each_session_end_cause_maps_to_its_own_documented_reason() {
        // Distinctness AND identity. Distinctness alone would pass with two causes' reasons
        // swapped, so every row is also pinned to its exact text.
        for (cause, expected) in [
            (
                SessionEndCause::Revoked,
                "This session was revoked individually.",
            ),
            (
                SessionEndCause::BulkRevoked,
                "This session was revoked as part of a set.",
            ),
            (
                SessionEndCause::UserRevokedAll,
                "Every session belonging to this user was revoked.",
            ),
            (SessionEndCause::LoggedOut, "The user logged out."),
            (
                SessionEndCause::ReplacedByOtherSubject,
                "A different user authenticated on the same browser session.",
            ),
            (
                SessionEndCause::PasswordChanged,
                "The user's password changed, which ends their other sessions.",
            ),
        ] {
            let row = map_session_end(cause);
            assert_eq!(row.event_type, SESSION_REVOKED, "{}", cause.as_str());
            assert_eq!(row.reason_admin_en, expected, "{}", cause.as_str());
        }

        let mut reasons = std::collections::BTreeSet::new();
        for cause in all_causes() {
            assert!(
                reasons.insert(map_session_end(cause).reason_admin_en),
                "{} reuses another cause's reason",
                cause.as_str()
            );
        }
    }

    #[test]
    fn a_reason_never_asserts_who_acted() {
        // The property that pairs with `initiating_entity` answering `None` for a human:
        // saying "an operator revoked this" in prose would smuggle back the claim the typed
        // member deliberately withholds, and an auditor reads the prose.
        for cause in all_causes() {
            let reason = map_session_end(cause).reason_admin_en.to_lowercase();
            for forbidden in ["operator", "administrator", "admin "] {
                assert!(
                    !reason.contains(forbidden),
                    "{} names an initiator in prose that the typed member will not state: {reason}",
                    cause.as_str()
                );
            }
        }
    }

    #[test]
    fn an_automated_actor_is_the_system_and_a_human_is_not_guessed_at() {
        // THE FINDING THIS ENCODES: one cause spans several initiators. `UserRevokedAll` is
        // written by the admin surface, by SCIM deprovisioning, by the self-service account
        // and trusted-device surfaces, and by the risk engine. Any fixed answer for it would
        // be wrong most of the time, so the actor decides, and where the actor cannot decide
        // nothing is said.
        for cause in [
            SessionEndCause::Revoked,
            SessionEndCause::BulkRevoked,
            SessionEndCause::UserRevokedAll,
            SessionEndCause::PasswordChanged,
        ] {
            assert_eq!(
                initiating_entity(cause, "service"),
                Some(InitiatingEntity::System),
                "{} by a service is not a human act",
                cause.as_str()
            );
            assert_eq!(
                initiating_entity(cause, "agent"),
                Some(InitiatingEntity::System),
                "{} by an agent is not a human act",
                cause.as_str()
            );
            assert_eq!(
                initiating_entity(cause, "human"),
                None,
                "{} by a human was reported as admin or user, which this build cannot tell apart",
                cause.as_str()
            );
        }
    }

    #[test]
    fn two_causes_are_decided_by_the_cause_whatever_the_actor() {
        // A logout is the end user's act whatever principal carries it, and a replacement
        // is nobody's act against the outgoing user. Both must hold for EVERY actor kind,
        // otherwise the override is not an override.
        for actor in ["human", "service", "agent", "unknown"] {
            assert_eq!(
                initiating_entity(SessionEndCause::LoggedOut, actor),
                Some(InitiatingEntity::User),
                "a logout under a {actor} actor"
            );
            assert_eq!(
                initiating_entity(SessionEndCause::ReplacedByOtherSubject, actor),
                Some(InitiatingEntity::System),
                "a replacement under a {actor} actor"
            );
        }
    }

    #[test]
    fn the_event_body_omits_the_initiator_it_cannot_support() {
        let human = session_end_event(SessionEndCause::Revoked, "human", 1_700_000_000_000_000);
        assert!(
            !human.payload.contains_key("initiating_entity"),
            "a guess was recorded as a fact: {:?}",
            human.payload
        );
        let service = session_end_event(SessionEndCause::Revoked, "service", 1_700_000_000_000_000);
        assert_eq!(
            service
                .payload
                .get("initiating_entity")
                .and_then(serde_json::Value::as_str),
            Some("system")
        );
    }

    #[test]
    fn the_event_body_carries_the_end_moment_in_seconds() {
        let event = session_end_event(SessionEndCause::LoggedOut, "human", 1_700_000_000_500_000);
        assert_eq!(event.event_type, SESSION_REVOKED);
        assert_eq!(
            event
                .payload
                .get("event_timestamp")
                .and_then(serde_json::Value::as_i64),
            Some(1_700_000_000),
            "CAEP renders the timestamp in seconds"
        );
        assert_eq!(
            event
                .payload
                .get("initiating_entity")
                .and_then(serde_json::Value::as_str),
            Some("user")
        );
        assert_eq!(
            event
                .payload
                .get("reason_admin")
                .and_then(|reason| reason.get("en"))
                .and_then(serde_json::Value::as_str),
            Some("The user logged out."),
            "reason_admin is keyed by language tag"
        );
    }

    #[test]
    fn a_pre_epoch_stamp_floors_instead_of_rounding_into_the_future() {
        // What `div_euclid` is FOR. Plain `/` truncates toward zero, so a stamp half a
        // second before the epoch would render as 0: the same second the epoch begins, and
        // therefore later than the moment it describes. Both other timestamp tests use
        // positive stamps, where the two operators agree, so without this the justification
        // written beside the call is unmeasured.
        let event = session_end_event(SessionEndCause::LoggedOut, "human", -500_000);
        assert_eq!(
            event
                .payload
                .get("event_timestamp")
                .and_then(serde_json::Value::as_i64),
            Some(-1),
            "a pre-epoch stamp rounded toward zero and landed in its own future"
        );
    }

    #[test]
    fn the_body_reports_the_end_moment_and_not_the_build_moment() {
        // The two arguments are independent, so a body that stamped `now` would still pass
        // every assertion above. Two ends an hour apart must render an hour apart.
        let early = session_end_event(SessionEndCause::Revoked, "human", 1_700_000_000_000_000);
        let late = session_end_event(SessionEndCause::Revoked, "human", 1_700_003_600_000_000);
        let stamp = |event: &SecurityEvent| {
            event
                .payload
                .get("event_timestamp")
                .and_then(serde_json::Value::as_i64)
                .expect("stamped")
        };
        assert_eq!(
            stamp(&late) - stamp(&early),
            3_600,
            "the stamp tracks the argument, not the clock"
        );
    }

    #[test]
    fn the_defined_but_unemitted_types_are_not_advertised() {
        // The honesty check that pairs with the module header: a receiver requesting one of
        // these would be told it will be delivered, and then never hear it.
        for unemitted in [
            CREDENTIAL_CHANGE,
            TOKEN_CLAIMS_CHANGE,
            ASSURANCE_LEVEL_CHANGE,
        ] {
            assert!(
                !crate::ssf_set::EVENTS_SUPPORTED.contains(&unemitted),
                "{unemitted} is advertised but nothing emits it"
            );
        }
        assert!(
            crate::ssf_set::EVENTS_SUPPORTED.contains(&SESSION_REVOKED),
            "the fan-out emits this one, so it must be advertised"
        );
    }
}
