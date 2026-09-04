// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every catalogued event has a decided meaning for outbound provisioning (issue #137).
//!
//! # Why the catalog is the denominator
//!
//! A translation tested by listing the events somebody thought of proves only that those events
//! work. The interesting failure is the event nobody thought of: it falls to a wildcard, produces
//! no SCIM request, and a departure never reaches the downstream. Nothing errors, nothing logs,
//! and the account stays live.
//!
//! So the test walks `ironauth_store::event_catalog::event_types()` and requires a DECISION for
//! every user and group event in it. Adding one to the catalog fails this suite until somebody
//! says what it means for outbound provisioning, which is exactly the decision that would
//! otherwise be skipped.

use ironauth_admin::scim_push_events::ScopeDecision;
use ironauth_admin::scim_push_events::{
    Collection, Ignored, PushIntent, intent_for, scope_decision,
};
use serde_json::json;

/// A payload carrying whichever subject id the event's schema requires.
fn payload_for(event_type: &str) -> serde_json::Value {
    if event_type.starts_with("org_group.") {
        json!({ "group_id": "grp_1" })
    } else {
        json!({ "user_id": "usr_1" })
    }
}

#[tokio::test]
async fn every_catalogued_subject_event_is_classified() {
    // THE DENOMINATOR. Not a list written here: the catalog's own registry, so this test cannot
    // drift behind the events that exist.
    let catalogued = ironauth_store::event_catalog::event_types();
    assert!(
        catalogued.len() > 50,
        "the catalog looks empty, so this test would pass vacuously: {}",
        catalogued.len()
    );

    let mut unclassified = Vec::new();
    let mut classified = 0_usize;
    for event_type in &catalogued {
        if !event_type.starts_with("user.") && !event_type.starts_with("org_group.") {
            // Not about a subject this connection pushes. Asserted below rather than assumed.
            assert_eq!(
                intent_for(event_type, &json!({})),
                PushIntent::Ignore(Ignored::NotASubject),
                "{event_type} is not a subject event but was not classified as one"
            );
            continue;
        }
        match intent_for(event_type, &payload_for(event_type)) {
            // A decision was made: push it, withdraw it, or deliberately do neither.
            PushIntent::Converge { .. }
            | PushIntent::Deprovision { .. }
            | PushIntent::Ignore(Ignored::NotAProvisioningSignal) => classified += 1,
            // The two that mean "nobody decided". `NotASubject` for something that IS a subject
            // event is the wildcard swallowing it, which is the defect this file exists to catch,
            // and `MalformedPayload` here means the payload this test built does not match the
            // schema the event registers, which is the same disagreement seen from the test side.
            PushIntent::Ignore(Ignored::NotASubject | Ignored::MalformedPayload) => {
                unclassified.push(event_type.clone());
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "these catalogued subject events have no decided meaning for outbound provisioning, so \
         each would silently produce no SCIM request: {unclassified:?}"
    );
    // AND THE COUNT IS NOT ZERO, because an empty loop satisfies the assertion above.
    assert!(
        classified >= 15,
        "only {classified} subject events were classified, which is fewer than the catalog holds"
    );
}

#[tokio::test]
async fn a_departure_is_a_deprovision_and_a_sign_in_is_not_a_write() {
    // The three departures. `user.deactivated` is the one most easily left out, and leaving it
    // out means a deactivated account stays live downstream, which is the failure #137 exists to
    // prevent.
    for event_type in ["user.deleted", "user.deprovisioned", "user.deactivated"] {
        assert_eq!(
            intent_for(event_type, &json!({ "user_id": "usr_1" })),
            PushIntent::Deprovision {
                collection: Collection::User,
                subject_id: "usr_1".to_owned(),
            },
            "{event_type} must deprovision"
        );
    }

    // AND THE CONTROL: a sign-in is catalogued, is about a user, and must NOT produce a write. A
    // translation that pushed on it would send a SCIM request per login, which is a load defect
    // and a rate-limit one.
    assert_eq!(
        intent_for("user.signed_in", &json!({ "user_id": "usr_1" })),
        PushIntent::Ignore(Ignored::NotAProvisioningSignal)
    );

    // A membership change converges the GROUP, not the member: RFC 7643 section 4.2 puts
    // `members` on the group, so the downstream write is a group update.
    assert_eq!(
        intent_for("org_group.member_added", &json!({ "group_id": "grp_1" })),
        PushIntent::Converge {
            collection: Collection::Group,
            subject_id: "grp_1".to_owned(),
        }
    );
}

#[tokio::test]
async fn a_payload_missing_its_subject_id_is_reported_rather_than_ignored() {
    // The catalog validates envelopes on the way in, so a registered event without its required
    // property means the schema and the producer disagree. Collapsing that into the same silence
    // as "not a provisioning signal" is how a producer bug becomes invisible.
    assert_eq!(
        intent_for("user.created", &json!({})),
        PushIntent::Ignore(Ignored::MalformedPayload)
    );
    assert_eq!(
        intent_for("org_group.deleted", &json!({ "user_id": "usr_1" })),
        PushIntent::Ignore(Ignored::MalformedPayload),
        "a group event carrying a user id is malformed, not a user deprovision"
    );
    // CONTROL: the same event with its own id is a real intent, so the refusals above are the
    // missing property and not the event type.
    assert_eq!(
        intent_for("org_group.deleted", &json!({ "group_id": "grp_1" })),
        PushIntent::Deprovision {
            collection: Collection::Group,
            subject_id: "grp_1".to_owned(),
        }
    );
}

#[tokio::test]
async fn leaving_scope_withdraws_only_what_was_provisioned() {
    // Criterion 4 reads as two rules, and implementing them separately lets them drift. Both come
    // from one input here: whether a LINK exists says whether this connection ever pushed the
    // subject.
    assert_eq!(scope_decision(true, false), ScopeDecision::Push);
    assert_eq!(scope_decision(true, true), ScopeDecision::Push);
    // Provisioned before, out of scope now: silence would leave them live downstream for ever.
    assert_eq!(scope_decision(false, true), ScopeDecision::Withdraw);
    // Never provisioned and out of scope: pushing a deprovision would ask the downstream to
    // remove somebody it has never heard of, which a strict server answers 404 and a worker would
    // then have to classify.
    assert_eq!(scope_decision(false, false), ScopeDecision::Skip);
}
