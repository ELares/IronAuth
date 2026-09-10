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
//! This deployment already emits `user.state_changed`, `user.deleted`,
//! `user.identifier_added` and `user.identifier_removed` from the writes that perform
//! those changes, whichever surface asked for them. Mapping RISC off those events rather
//! than off the surfaces means a new surface is covered the moment it emits the event the
//! catalog already requires of it, instead of the day somebody remembers to add a second
//! emit beside it.
//!
//! # ACCOUNT GRAIN, which is the rule that decides what is on the list
//!
//! This deployment announces membership changes and account changes separately, and
//! `reconcile_account_state` states the distinction: "a receiver that keeps its own copy
//! of the directory acts on the organization event; a receiver that gates on 'can this
//! person sign in at all' acts on this one, and the two are different questions whenever
//! a person belongs to more than one organization."
//!
//! RISC asks the second question, so only account-grain events are mapped.
//! `user.deactivated` and `user.deprovisioned` are the ORGANIZATION grain and are
//! deliberately absent: one organization deactivating a person another still holds active
//! leaves them signing in normally, and reporting `account-disabled` there would have
//! every receiver in the environment lock out a working account, with no later
//! `account-enabled` to undo it.
//!
//! Issue #144 criterion 3 asks for admin AND SCIM specifically, and both are covered
//! through this list rather than around it. A SCIM deactivation that IS the last one
//! moves the account, and `reconcile_account_state` emits `user.state_changed` when it
//! does; an admin block emits the same event.
//!
//! # Two account disables this does NOT reach, and why they are not fixed here
//!
//! Every mapped event is a domain event, so RISC is exactly as complete as the domain
//! event feed. Two paths disable an account by setting the state column directly in SQL
//! rather than going through `set_state_with_event`, and neither emits the account-grain
//! `user.state_changed`:
//!
//! - `execute_scheduled_offboardings`, when a scheduled offboarding comes due;
//! - the signup-quarantine rejection, which emits `signup_quarantine.resolved` instead.
//!
//! This is a PRE-EXISTING hole in the feed rather than one this vocabulary opened:
//! webhook receivers, which consume the same events, are blind to those two transitions
//! today. Papering over it here -- by mapping `signup_quarantine.resolved`, say -- would
//! put the account-grain claim on an event that does not carry it and would still leave
//! the offboarding executor silent. The fix belongs where the writes are, and it is
//! tracked in issue 1209.
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

/// The RISC event types this mapping can produce.
///
/// A subset of the vocabulary above: [`CREDENTIAL_COMPROMISE`] is inbound only, and
/// nothing here emits it.
///
/// [`EVENTS_SUPPORTED`](crate::ssf_set::EVENTS_SUPPORTED) does NOT read this list.
/// A `&[&str]` cannot be spliced into another `const` array, so that list spells its
/// entries out and `the_advertised_list_holds_exactly_these` binds the two instead. An
/// earlier version of this doc claimed the advertised list was built from here, which
/// was the "one artifact describes another" defect: the sentence was checkable and false.
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
/// - `scheduled_offboarding` is a PLAN to offboard later, not the offboarding. Reporting
///   it as `account-disabled` would have the receiver cut the user off at the moment the
///   schedule was SET rather than when it took effect. It is the only unmapped state a
///   real transition can reach.
///
///   AND THE EXECUTION IS NOT COVERED EITHER, which is a gap rather than a decision.
///   `execute_scheduled_offboardings` sets the state column directly and calls no event
///   emitter, so the moment the account actually IS disabled produces no domain event and
///   therefore no RISC signal. An earlier version of this
///   comment asserted the opposite -- "the offboarding itself emits its own event when it
///   runs" -- which was checkable and false.
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
        // ACCOUNT GRAIN ONLY. `user.deactivated` and `user.deprovisioned` are the
        // ORGANIZATION grain and are deliberately absent; see
        // `SSF_LIFECYCLE_EVENT_TYPES` for why mapping them would report an account as
        // disabled while its owner was still signing in.
        "user.deleted" => ACCOUNT_PURGED,
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
    use ironauth_store::UserState;

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
            ("user.deleted", ACCOUNT_PURGED),
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
        // A REAL GUARD, driven off `UserState::ALL` rather than a list written again here.
        //
        // The first version of this hard-coded six wire strings and asserted each parsed,
        // plus `len() == 6`. That cannot fail when a seventh state is added: the new state
        // simply never appears, every listed string still parses, and the count still
        // matches the list it was counting. A reviewer proved it by adding a seventh
        // variant to `UserState`; this test passed unchanged.
        //
        // What this DOES guarantee: every state in `UserState::ALL` is either mapped or
        // named in `refused_on_purpose`, and the two mutations that matter both fail it
        // (listing a mapped state as refused, and dropping an unmapped one).
        //
        // What keeps `ALL` itself complete is NOT this test, and saying otherwise would
        // be the overclaim the first version made. `ALL` is a hand-written array; a
        // seventh variant does not force it to grow. What does force the issue is that
        // `UserState::as_str` and `from_wire` are exhaustive matches, so a new variant
        // cannot be added without editing the impl block `ALL` sits in, and several
        // exhaustive matches elsewhere in the workspace stop compiling too.
        let refused_on_purpose = [
            // Reachable, and refused: a plan to offboard later. The offboarding itself
            // moves the account when it runs.
            UserState::ScheduledOffboarding,
            // Not reachable as transition targets at all (`can_transition_to` forbids
            // both), and refused anyway: an account that has never been usable has not
            // been taken away from anyone.
            UserState::PendingVerification,
            UserState::Waitlisted,
        ];
        for state in UserState::ALL {
            let mapped = type_of("user.state_changed", &payload(state.as_str()));
            if refused_on_purpose.contains(&state) {
                assert_eq!(
                    mapped,
                    None,
                    "{} is refused by name but produced a RISC event",
                    state.as_str()
                );
            } else {
                assert!(
                    mapped.is_some(),
                    "{} is a user state with no RISC decision: map it, or add it to \
                     refused_on_purpose with the reason",
                    state.as_str()
                );
            }
        }
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
            // THE ORGANIZATION GRAIN, which is the refusal that matters most here. Both
            // are real lifecycle notices and mapping them was the defect this suite now
            // guards: one organization deactivating a person another still holds active
            // leaves the account usable, so `account-disabled` would be a claim every
            // receiver acts on and nothing ever retracts.
            // `a_deactivate_by_one_organization_announces_no_account_change` in the SCIM
            // suite pins that the account state does not move.
            "user.deactivated",
            "user.deprovisioned",
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
            "user.deleted",
            &serde_json::json!({ "user_id": "usr_1", "hard_kill": false }),
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
            "user.deleted",
            &serde_json::json!({ "user_id": "usr_1", "hard_kill": false }),
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
    fn the_advertised_list_holds_exactly_these() {
        // The binding that makes `EMITTED_EVENT_TYPES` load-bearing rather than a second
        // list nobody reads. `EVENTS_SUPPORTED` cannot splice it in at compile time, so
        // the two are written separately and checked here in both directions: every type
        // this mapping produces is advertised, and the advertised RISC types are exactly
        // the ones it produces.
        for emitted in EMITTED_EVENT_TYPES {
            assert!(
                crate::ssf_set::EVENTS_SUPPORTED.contains(emitted),
                "{emitted} is produced by the mapping and not advertised, so a receiver \
                 cannot ask for it"
            );
        }
        let advertised_risc: Vec<&str> = crate::ssf_set::EVENTS_SUPPORTED
            .iter()
            .copied()
            .filter(|t| t.contains("/risc/"))
            .collect();
        assert_eq!(
            advertised_risc, EMITTED_EVENT_TYPES,
            "the advertised RISC types are not the set this mapping produces"
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
