//! The RISC vocabulary and the mapping from this deployment's user lifecycle to it
//! (issue #144 criterion 3).
//!
//! RISC is the account-lifecycle half of Shared Signals, where CAEP is the session half.
//! A relying party subscribes to RISC to learn that an account it has a relationship with
//! was disabled, deleted, or had one of its identifiers changed, so that it can stop
//! honouring what it holds without waiting for the next sign-in that never comes.
//!
//! # The source is the domain event feed, not a second set of call sites
//!
//! This deployment already emits `user.deactivated`, `user.state_changed`, `user.deleted`,
//! `user.deprovisioned`, `user.identifier_added` and `user.identifier_removed` from every
//! surface that performs those actions: the admin API, SCIM, the self-service surfaces and
//! the offboarding worker. Mapping RISC off those events rather than off the surfaces means
//! a new surface that performs a lifecycle action is covered the moment it emits the event
//! the catalog already requires of it, instead of the day somebody remembers to add a
//! second emit beside it.
//!
//! Issue #144 criterion 3 asks for admin AND SCIM specifically. Both already emit these
//! events, and `crates/ironauth-admin/tests/scim_push_events.rs` pins the SCIM half
//! independently of anything here.
//!
//! # What is deliberately NOT carried
//!
//! `identifier-changed` is emitted WITHOUT RISC's optional `new-value` member. This build
//! knows an identifier changed and which identifier row it was; it does not put the
//! identifier itself into a SET. A SET is a signed token that sits in a poll queue and is
//! POSTed to an endpoint the receiver chose, and an email address or phone number inside
//! it is that address in one more place, readable by anyone who can read the queue. The
//! member is optional precisely so a transmitter can say "something changed, re-read it"
//! without republishing the value, and a receiver that needs the new identifier asks the
//! userinfo endpoint with the token it already holds.

use serde_json::Value;

use crate::ssf_set::SecurityEvent;

/// RISC 1.0: the account was disabled and its owner cannot currently use it.
pub const ACCOUNT_DISABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

/// RISC 1.0: an account that was disabled is usable again.
pub const ACCOUNT_ENABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled";

/// RISC 1.0: the account and its data are gone and will not come back.
pub const ACCOUNT_PURGED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-purged";

/// RISC 1.0: an identifier the subject is known by changed.
pub const IDENTIFIER_CHANGED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";

/// RISC 1.0: a credential belonging to the subject is believed to be in someone else's
/// hands.
///
/// DEFINED, NOT EMITTED. This is the type a Google Cross-Account Protection transmitter
/// SENDS US rather than one we produce, and receiving it is issue #144 criterion 4.
pub const CREDENTIAL_COMPROMISE: &str =
    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";

/// The domain event types this mapping reads.
///
/// RE-EXPORTED FROM THE STORE rather than written again here. The producer side is
/// `enqueue_domain_event`, which runs in the store and decides from this same list
/// whether to write a trigger at all. Two lists would drift, and drift in either
/// direction is silent: an extra entry writes triggers that map to nothing, a missing one
/// drops a lifecycle signal. `the_producer_set_is_exactly_what_the_mapping_handles`
/// drives every entry through [`map_domain_event`] and refuses a `None`.
pub use ironauth_store::SSF_LIFECYCLE_EVENT_TYPES as LIFECYCLE_EVENT_TYPES;

/// The event types this mapping can PRODUCE, for the advertised list.
///
/// A subset of the RISC vocabulary above: [`CREDENTIAL_COMPROMISE`] is inbound only, and
/// nothing here emits it.
pub const EMITTED_EVENT_TYPES: &[&str] = &[
    ACCOUNT_DISABLED,
    ACCOUNT_ENABLED,
    ACCOUNT_PURGED,
    IDENTIFIER_CHANGED,
];

/// The user this domain event is about, as the catalog requires every one of them to
/// carry.
///
/// `None` rather than a panic for a payload without it: the catalog validates the shape
/// before a delivery is ever created, so a missing `user_id` here means something wrote a
/// row that bypassed the catalog, and the caller turns that into a permanent failure
/// rather than a SET about nobody.
#[must_use]
pub fn subject_of(payload: &Value) -> Option<&str> {
    payload.get("user_id").and_then(Value::as_str)
}

/// THE MAPPING TABLE (issue #144 criterion 3).
///
/// `None` means this deployment's event does not correspond to a RISC signal, which is a
/// real answer and not a gap. `user.state_changed` is the case that shows why: it carries
/// every transition of [`UserState`](ironauth_store::UserState), and only some of those
/// are things RISC has a word for.
///
/// - `blocked` and `disabled` are the account being taken away from its owner, which is
///   `account-disabled`.
/// - `active` is it being given back, which is `account-enabled`.
/// - `scheduled_offboarding` is a PLAN to offboard later, and the offboarding itself emits
///   its own event when it runs. Reporting it as `account-disabled` would have the
///   receiver cut the user off at the moment the schedule was SET rather than the moment
///   it took effect. It is the only unmapped state a real transition can reach.
/// - `pending_verification` and `waitlisted` are refused too, though
///   [`UserState::can_transition_to`](ironauth_store::UserState::can_transition_to)
///   already forbids them as TARGETS, so a `user.state_changed` cannot carry either
///   today. They are matched rather than left to the catch-all because that guard and
///   this mapping are free to change apart, and the answer if one ever did arrive is
///   still "not a RISC transition": an account that has never been usable has not been
///   taken away from anyone.
///
/// `occurred_at_unix_ms` comes from the envelope, so a redelivery re-renders the same
/// body and a receiver sees when the change happened rather than when it was told.
#[must_use]
pub fn map_domain_event(
    event_type: &str,
    payload: &Value,
    occurred_at_unix_ms: i64,
) -> Option<SecurityEvent> {
    let risc_type = match event_type {
        "user.deactivated" => ACCOUNT_DISABLED,
        "user.deleted" | "user.deprovisioned" => ACCOUNT_PURGED,
        "user.identifier_added" | "user.identifier_removed" => IDENTIFIER_CHANGED,
        "user.state_changed" => match payload.get("state").and_then(Value::as_str)? {
            "blocked" | "disabled" => ACCOUNT_DISABLED,
            "active" => ACCOUNT_ENABLED,
            _ => return None,
        },
        _ => return None,
    };
    let mut body = serde_json::Map::new();
    // RISC renders `event_timestamp` in SECONDS, like CAEP. The envelope carries
    // MILLISECONDS, and `div_euclid` floors a pre-epoch stamp instead of truncating it
    // toward zero and into its own future.
    body.insert(
        "event_timestamp".to_owned(),
        Value::from(occurred_at_unix_ms.div_euclid(1_000)),
    );
    Some(SecurityEvent {
        event_type: risc_type.to_owned(),
        payload: body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(state: &str) -> Value {
        serde_json::json!({ "user_id": "usr_1", "state": state, "hard_kill": false })
    }

    fn type_of(event_type: &str, payload: &Value) -> Option<String> {
        map_domain_event(event_type, payload, 0).map(|event| event.event_type)
    }

    #[test]
    fn the_producer_set_is_exactly_what_the_mapping_handles() {
        // The two halves are written separately and must not drift: a type in the producer
        // set that maps to nothing writes a trigger no consumer can use, and a type the
        // mapping handles but the producer omits is a lifecycle signal that never leaves.
        //
        // `user.state_changed` is driven with a state that DOES map, because the entry
        // being justified here is the event type, not the state arm.
        for event_type in LIFECYCLE_EVENT_TYPES {
            let sample = payload("blocked");
            assert!(
                type_of(event_type, &sample).is_some(),
                "{event_type} is in the producer set and maps to nothing"
            );
        }
    }

    #[test]
    fn each_lifecycle_event_becomes_its_documented_risc_type() {
        let plain = serde_json::json!({ "user_id": "usr_1" });
        for (event_type, expected) in [
            ("user.deactivated", ACCOUNT_DISABLED),
            ("user.deleted", ACCOUNT_PURGED),
            ("user.deprovisioned", ACCOUNT_PURGED),
            ("user.identifier_added", IDENTIFIER_CHANGED),
            ("user.identifier_removed", IDENTIFIER_CHANGED),
        ] {
            assert_eq!(
                type_of(event_type, &plain).as_deref(),
                Some(expected),
                "{event_type} mapped to the wrong RISC type"
            );
        }
    }

    #[test]
    fn a_state_change_maps_only_the_transitions_risc_has_a_word_for() {
        // Both directions AND the refusals, in one test, because the refusals are what
        // stop a receiver being told an account was taken away when it never had it.
        assert_eq!(
            type_of("user.state_changed", &payload("blocked")).as_deref(),
            Some(ACCOUNT_DISABLED)
        );
        assert_eq!(
            type_of("user.state_changed", &payload("disabled")).as_deref(),
            Some(ACCOUNT_DISABLED)
        );
        assert_eq!(
            type_of("user.state_changed", &payload("active")).as_deref(),
            Some(ACCOUNT_ENABLED)
        );
        for unmapped in [
            "pending_verification",
            "waitlisted",
            "scheduled_offboarding",
        ] {
            assert_eq!(
                type_of("user.state_changed", &payload(unmapped)),
                None,
                "{unmapped} was reported as a RISC account transition"
            );
        }
    }

    #[test]
    fn every_user_state_the_store_can_record_is_decided_here() {
        // The guard against a SEVENTH state arriving and silently falling into the
        // catch-all. Every wire string the store can write is listed, and each is either
        // mapped or explicitly refused; a new state added to `UserState` without a
        // decision here fails this test rather than quietly emitting nothing.
        let decided = [
            "active",
            "blocked",
            "disabled",
            "pending_verification",
            "scheduled_offboarding",
            "waitlisted",
        ];
        for state in decided {
            let parsed = ironauth_store::UserState::from_wire(state);
            assert!(
                parsed.is_some(),
                "{state} is not a state the store can record, so this list is stale"
            );
        }
        assert_eq!(
            decided.len(),
            6,
            "a user state was added or removed without deciding what RISC says about it"
        );
    }

    #[test]
    fn an_unrelated_domain_event_produces_nothing() {
        // The set is a whitelist, not a prefix match: `user.signed_in` is a user event and
        // emphatically not an account lifecycle transition.
        for unrelated in [
            "user.signed_in",
            "user.created",
            "user.updated",
            "client.deleted",
        ] {
            assert_eq!(
                type_of(unrelated, &serde_json::json!({ "user_id": "usr_1" })),
                None,
                "{unrelated} produced a RISC event"
            );
        }
    }

    #[test]
    fn the_body_carries_the_moment_the_change_happened_in_seconds() {
        let event = map_domain_event(
            "user.deactivated",
            &serde_json::json!({ "user_id": "usr_1" }),
            1_700_000_000_500,
        )
        .expect("mapped");
        assert_eq!(
            event.payload.get("event_timestamp").and_then(Value::as_i64),
            Some(1_700_000_000),
            "RISC renders the timestamp in seconds and the envelope carries milliseconds"
        );
        // Independent of the argument, so a body stamping `now` would still pass the line
        // above on a frozen clock. Two changes an hour apart must render an hour apart.
        let later = map_domain_event(
            "user.deactivated",
            &serde_json::json!({ "user_id": "usr_1" }),
            1_700_003_600_500,
        )
        .expect("mapped");
        assert_eq!(
            later.payload["event_timestamp"].as_i64().expect("stamped")
                - event.payload["event_timestamp"].as_i64().expect("stamped"),
            3_600
        );
    }

    #[test]
    fn an_identifier_change_does_not_republish_the_identifier() {
        // RISC's `new-value` is optional and deliberately omitted: a SET sits in a poll
        // queue and is POSTed to an address the receiver chose, so an email or phone
        // number inside it is that value in one more readable place.
        let event = map_domain_event(
            "user.identifier_added",
            &serde_json::json!({
                "user_id": "usr_1",
                "identifier_id": "uid_1",
                "identifier_type": "email",
            }),
            0,
        )
        .expect("mapped");
        assert_eq!(event.event_type, IDENTIFIER_CHANGED);
        assert!(
            !event.payload.contains_key("new-value"),
            "the changed identifier was republished inside the SET: {:?}",
            event.payload
        );
        assert_eq!(
            event.payload.len(),
            1,
            "only the timestamp belongs in this body: {:?}",
            event.payload
        );
    }

    #[test]
    fn the_inbound_only_type_is_not_advertised_as_emitted() {
        assert!(
            !EMITTED_EVENT_TYPES.contains(&CREDENTIAL_COMPROMISE),
            "credential-compromise is received, not produced"
        );
        for emitted in EMITTED_EVENT_TYPES {
            assert!(emitted.contains("/risc/"), "{emitted} is not a RISC type");
        }
    }
}
