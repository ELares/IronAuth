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

/// CAEP 1.0: every token and session minted under the named session is no longer to be
/// honoured.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEndMapping {
    /// The CAEP event type URI the cause becomes.
    pub event_type: &'static str,
    /// Who initiated it.
    pub initiating_entity: InitiatingEntity,
    /// The administrator-facing reason, in English.
    ///
    /// CAEP renders `reason_admin` as an object keyed by language tag; this is the value
    /// under `en`. It is prose for a human reading an audit trail, and MUST NOT be parsed:
    /// anything a receiver needs to branch on belongs in a typed member.
    pub reason_admin_en: &'static str,
}

/// THE MAPPING TABLE (issue #144 criterion 2).
///
/// Exhaustive over [`SessionEndCause`] by `match`, so a new cause is a compile error here
/// before it is a silently unmapped signal in production.
///
/// All six rows carry the same `event_type` and that is the correct answer, not a
/// degenerate one: CAEP has exactly one event for "this session is over", and the reason
/// it happened is carried in the members beside it. The rows differ in the two places CAEP
/// gives us to differ, which is what
/// `each_session_end_cause_maps_to_its_own_documented_row` pins.
#[must_use]
pub fn map_session_end(cause: SessionEndCause) -> SessionEndMapping {
    match cause {
        SessionEndCause::Revoked => SessionEndMapping {
            event_type: SESSION_REVOKED,
            initiating_entity: InitiatingEntity::Admin,
            reason_admin_en: "An operator revoked this session through the management API.",
        },
        SessionEndCause::BulkRevoked => SessionEndMapping {
            event_type: SESSION_REVOKED,
            initiating_entity: InitiatingEntity::Admin,
            reason_admin_en: "An operator revoked a set of sessions that included this one.",
        },
        SessionEndCause::UserRevokedAll => SessionEndMapping {
            event_type: SESSION_REVOKED,
            initiating_entity: InitiatingEntity::User,
            reason_admin_en: "The user signed out of every session.",
        },
        SessionEndCause::LoggedOut => SessionEndMapping {
            event_type: SESSION_REVOKED,
            initiating_entity: InitiatingEntity::User,
            reason_admin_en: "The user logged out.",
        },
        // SYSTEM, not user: the outgoing user did not ask for this. A different subject
        // authenticated on the same browser session, and their session ends as a
        // consequence of someone else's act.
        SessionEndCause::ReplacedByOtherSubject => SessionEndMapping {
            event_type: SESSION_REVOKED,
            initiating_entity: InitiatingEntity::System,
            reason_admin_en: "A different user authenticated on the same browser session.",
        },
        SessionEndCause::PasswordChanged => SessionEndMapping {
            event_type: SESSION_REVOKED,
            initiating_entity: InitiatingEntity::User,
            reason_admin_en: "The user changed their password, which ends their other sessions.",
        },
    }
}

/// Build the CAEP event body for one session end.
///
/// `occurred_at_unix_micros` is the moment the session ENDED, carried on the session-ended
/// outbox message, not the moment this SET is built. A retry re-renders the same body, and
/// a receiver comparing `event_timestamp` against its own record of the session sees the
/// end, not the delivery.
#[must_use]
pub fn session_end_event(cause: SessionEndCause, occurred_at_unix_micros: i64) -> SecurityEvent {
    let mapping = map_session_end(cause);
    let mut payload = serde_json::Map::new();
    // CAEP renders `event_timestamp` in SECONDS. The internal stamp is microseconds, and
    // `div_euclid` rather than `/` so a pre-epoch stamp floors instead of truncating
    // toward zero, which would round it into the future.
    payload.insert(
        "event_timestamp".to_owned(),
        serde_json::Value::from(occurred_at_unix_micros.div_euclid(1_000_000)),
    );
    payload.insert(
        "initiating_entity".to_owned(),
        serde_json::Value::String(mapping.initiating_entity.as_str().to_owned()),
    );
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

    /// Every cause this build can record, so the table-driven tests below cannot pass by
    /// covering a subset. A new variant makes `map_session_end` fail to compile; this list
    /// is what makes the new variant fail the TESTS too if someone adds a row without
    /// deciding whether it is distinguishable.
    const ALL_CAUSES: &[SessionEndCause] = &[
        SessionEndCause::Revoked,
        SessionEndCause::BulkRevoked,
        SessionEndCause::UserRevokedAll,
        SessionEndCause::LoggedOut,
        SessionEndCause::ReplacedByOtherSubject,
        SessionEndCause::PasswordChanged,
    ];

    #[test]
    fn the_cause_list_covers_every_variant_the_store_can_record() {
        // The guard on the guard: `ALL_CAUSES` is hand-written, so it can fall behind the
        // enum and quietly shrink every table-driven test below. `from_wire` is the
        // store's own parser, so round-tripping every wire string it accepts proves the
        // list is complete without this test knowing the variants a second time.
        for wire in [
            "revoked",
            "bulk_revoked",
            "user_revoked_all",
            "logged_out",
            "replaced_by_other_subject",
            "password_changed",
        ] {
            let cause = SessionEndCause::from_wire(wire).expect("store parses its own wire string");
            assert!(
                ALL_CAUSES.contains(&cause),
                "{wire} is a recordable cause the mapping tests never see"
            );
        }
        assert_eq!(
            ALL_CAUSES.len(),
            6,
            "a new cause needs a documented mapping"
        );
    }

    #[test]
    fn each_session_end_cause_maps_to_its_own_documented_row() {
        // NOT a distinctness assertion over the whole row: all six share an event type, so
        // requiring whole-row distinctness would be satisfied by the reason string alone
        // and would say nothing about `initiating_entity`. Each column is checked for what
        // it is actually supposed to carry.
        let mut reasons = std::collections::BTreeSet::new();
        for &cause in ALL_CAUSES {
            let row = map_session_end(cause);
            assert_eq!(
                row.event_type,
                SESSION_REVOKED,
                "{} is a session end and CAEP has one event for that",
                cause.as_str()
            );
            assert!(
                reasons.insert(row.reason_admin_en),
                "{} reuses another cause's reason, so an audit trail cannot tell them apart",
                cause.as_str()
            );
        }
        assert_eq!(reasons.len(), ALL_CAUSES.len());
    }

    #[test]
    fn the_initiator_is_the_one_the_cause_names() {
        // Pinned cause by cause rather than by counting distinct values: a table that maps
        // every cause to `System` has exactly as many distinct values as one that maps
        // nothing at all, and "at least two distinct initiators" would pass while the user
        // and the admin were swapped.
        for (cause, expected) in [
            (SessionEndCause::Revoked, InitiatingEntity::Admin),
            (SessionEndCause::BulkRevoked, InitiatingEntity::Admin),
            (SessionEndCause::UserRevokedAll, InitiatingEntity::User),
            (SessionEndCause::LoggedOut, InitiatingEntity::User),
            (
                SessionEndCause::ReplacedByOtherSubject,
                InitiatingEntity::System,
            ),
            (SessionEndCause::PasswordChanged, InitiatingEntity::User),
        ] {
            assert_eq!(
                map_session_end(cause).initiating_entity,
                expected,
                "{} names the wrong initiator",
                cause.as_str()
            );
        }
    }

    #[test]
    fn the_event_body_carries_the_end_moment_in_seconds() {
        let event = session_end_event(SessionEndCause::LoggedOut, 1_700_000_000_500_000);
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
    fn the_body_reports_the_end_moment_and_not_the_build_moment() {
        // The two arguments are independent, so a body that stamped `now` would still pass
        // every assertion above. Two ends an hour apart must render an hour apart.
        let early = session_end_event(SessionEndCause::Revoked, 1_700_000_000_000_000);
        let late = session_end_event(SessionEndCause::Revoked, 1_700_003_600_000_000);
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
