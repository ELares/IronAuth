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

/// A payload built from the event's OWN registered schema, not from a shape this test invented.
///
/// # Why this reads the catalog instead of hard-coding two keys
///
/// The first version returned `{"group_id": ...}` for every `org_group.*` event. The catalog
/// requires `org_group_id`, and the module under test read `group_id` too, so the test and the
/// code agreed with each other and both disagreed with the registry. Every group event was
/// silently classified as malformed and the suite was green: the denominator enumerated the
/// catalog's event NAMES and then measured them against a payload of its own invention.
///
/// An expected value that travels with the code it checks cannot detect a change to both. So the
/// required properties come from `payload_schema`, and a key renamed in the catalog now breaks
/// this test rather than being quietly mirrored by it.
fn expected_org(event_type: &str) -> Option<String> {
    // Derived from the schema, exactly as `payload_for` derives the payload. An earlier version
    // of this file wrote `Some("seed-organization_id")` onto every expected intent, which is
    // false for every event whose schema names no organization (`user.deleted` carries
    // `user_id` and `hard_kill`, and nothing else). Writing the expectation by hand is how the
    // group-key defect survived; deriving it is the correction applied consistently.
    let registered = ironauth_store::event_catalog::registered(event_type)?;
    let schema: serde_json::Value = serde_json::from_str(&registered.payload_schema).ok()?;
    let required = schema["required"].as_array()?;
    required
        .iter()
        .any(|n| n.as_str() == Some("organization_id"))
        .then(|| "seed-organization_id".to_owned())
}

fn payload_for(event_type: &str) -> serde_json::Value {
    // ONE BUILDER, shared with the worker suite, and THIS file is where the loop used to live.
    // The worker suite hand-wrote its envelopes instead, so pointing it at a derivation meant
    // giving it this one -- and the moment its output was validated, the loop's own defect
    // surfaced: it filled an array property with `[]` against a schema requiring an item. It had
    // sat here unnoticed because nothing in this file validates what it builds either; the
    // classification tests only ever read the properties they name.
    //
    // So the builder now honours `enum`, `minItems` and the item type rather than the top-level
    // `type` alone, and it lives in one place. What actually holds it to the registry is the
    // worker suite calling `validate_event` on the envelope it produces.
    ironauth_store::test_support::registry_payload(event_type, &json!({}))
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
        // The membership events are subject events despite their prefix: a person joining or
        // leaving the organization a connection pushes is precisely criterion 4.
        const MEMBERSHIP: &[&str] = &["organization.member_added", "organization.member_removed"];
        if !event_type.starts_with("user.")
            && !event_type.starts_with("org_group.")
            && !MEMBERSHIP.contains(&event_type.as_str())
        {
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
            intent_for(event_type, &payload_for(event_type)),
            PushIntent::Deprovision {
                collection: Collection::User,
                subject_id: "seed-user_id".to_owned(),
                organization_id: expected_org(event_type),
            },
            "{event_type} must deprovision"
        );
    }

    // AND THE CONTROL: a sign-in is catalogued, is about a user, and must NOT produce a write. A
    // translation that pushed on it would send a SCIM request per login, which is a load defect
    // and a rate-limit one.
    assert_eq!(
        intent_for("user.signed_in", &payload_for("user.signed_in")),
        PushIntent::Ignore(Ignored::NotAProvisioningSignal)
    );

    // A membership change converges the GROUP, not the member: RFC 7643 section 4.2 puts
    // `members` on the group, so the downstream write is a group update.
    assert_eq!(
        intent_for(
            "org_group.member_added",
            &payload_for("org_group.member_added")
        ),
        PushIntent::Converge {
            collection: Collection::Group,
            subject_id: "seed-org_group_id".to_owned(),
            organization_id: expected_org("org_group.member_added"),
        }
    );

    // JOINING AND LEAVING THE ORGANIZATION a connection pushes: criterion 4's most literal case.
    // Both are a CONVERGE, because `scope_decision` turns the "left" one into a withdrawal from
    // the link's presence. Classified as "not a subject" by the first version, so the one event
    // that says a person left produced no request and the downstream account stayed live.
    for event_type in ["organization.member_added", "organization.member_removed"] {
        assert_eq!(
            intent_for(event_type, &payload_for(event_type)),
            PushIntent::Converge {
                collection: Collection::User,
                subject_id: "seed-user_id".to_owned(),
                organization_id: expected_org(event_type),
            },
            "{event_type} must re-evaluate the subject"
        );
        // AND IT NAMES THE ORGANIZATION, which is what lets the worker drop an event belonging to
        // a different one. The feed is environment-wide; a connection is not.
        assert!(
            expected_org(event_type).is_some(),
            "{event_type} carries no organization, so the worker cannot confine it"
        );
    }
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
        intent_for("org_group.deleted", &payload_for("org_group.deleted")),
        PushIntent::Deprovision {
            collection: Collection::Group,
            subject_id: "seed-org_group_id".to_owned(),
            organization_id: expected_org("org_group.deleted"),
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
