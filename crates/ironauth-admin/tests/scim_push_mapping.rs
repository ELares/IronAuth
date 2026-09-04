// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an operator may and may not map onto an outbound SCIM resource (issue #137).
//!
//! # Why the refusals matter more than the mappings
//!
//! Applying a mapping correctly is the easy half and a single test covers it. The half that can
//! destroy a directory is what an operator is ALLOWED to map, because the connection's
//! `attribute_mapping` is a JSON object in a console field and every entry looks equally harmless
//! there.
//!
//! `externalId` is the one that matters. The merged client looks a subject up by it before every
//! write, and that lookup IS the idempotency: a mapping that pointed `externalId` at a trait would
//! change the value the moment somebody edited that trait, and the next convergence would miss and
//! create a second resource for the same person. Nothing would error. The duplicate would appear
//! days later in somebody else's directory.

use ironauth_admin::scim_push_mapping::{MappingError, RESERVED_ATTRIBUTES, resource_for};
use serde_json::json;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

fn source() -> serde_json::Value {
    json!({
        "identifier": "ada@example.com",
        "state": "active",
        "traits": {
            "given_name": "Ada",
            "family_name": "Lovelace",
            "department": "Engineering",
        },
    })
}

#[tokio::test]
async fn a_mapping_is_applied_and_the_protocol_attributes_are_not_the_operators_to_set() {
    let mapped = resource_for(
        USER_SCHEMA,
        "usr_1",
        true,
        &json!({
            "userName": "identifier",
            "name.givenName": "traits.given_name",
            "name.familyName": "traits.family_name",
        }),
        &source(),
    )
    .expect("the mapping applies");

    assert_eq!(mapped["userName"], json!("ada@example.com"));
    assert_eq!(mapped["name"]["givenName"], json!("Ada"));
    assert_eq!(mapped["name"]["familyName"], json!("Lovelace"));

    // SET BY THE MAPPER, not by the operator. `externalId` is the client's lookup key, `schemas`
    // describes the resource, and `active` carries the state the deletion policy acts on.
    assert_eq!(mapped["externalId"], json!("usr_1"));
    assert_eq!(mapped["schemas"], json!([USER_SCHEMA]));
    assert_eq!(mapped["active"], json!(true));

    // A SOURCE THE SUBJECT DOES NOT CARRY IS ABSENT, not null. Sending null would ask the
    // downstream to clear the attribute, and a PUT is a full replace (RFC 7644 section 3.5.1), so
    // a missing trait must simply not appear in the body.
    let sparse = resource_for(
        USER_SCHEMA,
        "usr_1",
        true,
        &json!({ "title": "traits.job_title" }),
        &source(),
    )
    .expect("a missing source is not an error");
    assert!(
        sparse.get("title").is_none(),
        "a missing trait was sent as a value: {sparse}"
    );
}

#[tokio::test]
async fn no_mapping_may_target_an_attribute_the_protocol_owns() {
    // THE DEFECT THIS EXCLUDES, and it is the worst one available to a console field.
    //
    // `externalId` mapped to a trait changes whenever somebody edits that trait. The next
    // convergence looks the subject up by the NEW value, finds nothing, and creates a second
    // resource. The first one stays behind, still active, still holding the old externalId, and
    // nothing in either directory says the two are the same person.
    // NAMED HERE, not read from RESERVED_ATTRIBUTES.
    //
    // The first draft of this test looped over the constant, so it asserted "whatever is reserved
    // is refused", which is true of an EMPTY list. Deleting `externalId` from the constant deleted
    // it from the expectation too, and the mutation survived: the single refusal this file's
    // header calls the one that matters was not pinned by anything.
    //
    // A test whose expected value travels with the code it checks cannot detect a change to both.
    const MUST_BE_RESERVED: &[&str] = &["id", "meta", "schemas", "externalId", "active"];
    assert_eq!(
        RESERVED_ATTRIBUTES, MUST_BE_RESERVED,
        "the reserved set changed; decide deliberately, because dropping externalId duplicates \
         every subject whose mapped source is later edited"
    );

    for attribute in MUST_BE_RESERVED {
        let outcome = resource_for(
            USER_SCHEMA,
            "usr_1",
            true,
            &json!({ *attribute: "identifier" }),
            &source(),
        );
        assert_eq!(
            outcome,
            Err(MappingError::Reserved {
                attribute: (*attribute).to_owned()
            }),
            "{attribute} was accepted as a mapping target"
        );
    }

    // AND THROUGH A SUB-PATH, which is how the check above would be walked around: `meta.created`
    // reaches `meta` just as surely as `meta` does, and a check that only compared whole strings
    // would let it.
    let outcome = resource_for(
        USER_SCHEMA,
        "usr_1",
        true,
        &json!({ "meta.created": "identifier" }),
        &source(),
    );
    assert_eq!(
        outcome,
        Err(MappingError::Reserved {
            attribute: "meta.created".to_owned()
        }),
        "a reserved attribute was reachable through a sub-path"
    );

    // AND externalId ON ITS OWN, spelled out, because it is the one whose loss is silent. The
    // other three are refused by conformant downstreams anyway; this one is accepted everywhere
    // and duplicates the directory the first time somebody edits the mapped trait.
    assert_eq!(
        resource_for(
            USER_SCHEMA,
            "usr_1",
            true,
            &json!({ "externalId": "traits.department" }),
            &source(),
        ),
        Err(MappingError::Reserved {
            attribute: "externalId".to_owned()
        }),
        "externalId was mappable onto a mutable trait"
    );

    // AND `active` ON ITS OWN, because it was the one missing from this list and its absence had a
    // consequence the others do not. A mapping pointing `active` at a trait makes that trait
    // decide departures: the worker builds a deactivation body, the mapping re-stamps `active`
    // from the trait on the way out, and the downstream is told the person is still enabled. The
    // deprovision reports success and the account stays live.
    assert_eq!(
        resource_for(
            USER_SCHEMA,
            "usr_1",
            false,
            &json!({ "active": "traits.department" }),
            &source(),
        ),
        Err(MappingError::Reserved {
            attribute: "active".to_owned()
        }),
        "a mapping could overwrite the deactivation flag"
    );

    // CONTROL: a NON-reserved attribute with the same shape maps fine, so the refusals above are
    // the attribute and not the dotted path.
    let mapped = resource_for(
        USER_SCHEMA,
        "usr_1",
        true,
        &json!({ "name.givenName": "traits.given_name" }),
        &source(),
    )
    .expect("a non-reserved sub-path maps");
    assert_eq!(mapped["name"]["givenName"], json!("Ada"));
}

#[tokio::test]
async fn a_malformed_mapping_is_refused_at_save_time_rather_than_at_write_time() {
    // Each of these varies ONE dimension from a mapping that would otherwise apply, so each
    // refusal is attributable to the guard it names.
    let cases: [(serde_json::Value, MappingError); 4] = [
        (json!(["userName", "identifier"]), MappingError::NotAnObject),
        (
            json!({ "userName": 42 }),
            MappingError::NotAPath {
                attribute: "userName".to_owned(),
            },
        ),
        (
            // Deeper than one level. Refused rather than flattened into a literal key containing
            // dots, which is what the reference downstream caught the first client doing.
            json!({ "name.given.first": "traits.given_name" }),
            MappingError::UnsupportedPath {
                path: "name.given.first".to_owned(),
            },
        ),
        (
            json!({ "": "identifier" }),
            MappingError::UnsupportedPath {
                path: String::new(),
            },
        ),
    ];
    for (mapping, expected) in cases {
        assert_eq!(
            resource_for(USER_SCHEMA, "usr_1", true, &mapping, &source()),
            Err(expected.clone()),
            "{mapping} was not refused as {expected:?}"
        );
    }

    // AN ABSENT MAPPING IS AN EMPTY ONE, not a refusal: a connection that sends only the protocol
    // attributes is a legitimate configuration. Explicit null is the house spelling for absent,
    // which 0189 records being caught asserting the opposite of.
    let bare = resource_for(USER_SCHEMA, "usr_1", true, &json!(null), &source())
        .expect("an absent mapping is empty, not invalid");
    assert_eq!(bare["externalId"], json!("usr_1"));
    assert!(bare.get("userName").is_none());
}

#[tokio::test]
async fn a_group_body_carries_no_active_attribute() {
    // RFC 7643 section 4.2 gives Group no `active`, and the first version stamped one on every
    // resource regardless.
    //
    // The consequence is not an ignored extra field. The merged client refuses a Group
    // deactivation by checking whether the stored representation carries `active`, so a Group
    // built by this mapper came back carrying one, that refusal was disarmed, and the deprovision
    // reported success while every member stayed in the group. The mapper and the guard were each
    // correct alone and wrong together.
    const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
    let group = resource_for(
        GROUP_SCHEMA,
        "grp_1",
        true,
        &json!({ "displayName": "traits.department" }),
        &source(),
    )
    .expect("a group maps");
    assert!(
        group.get("active").is_none(),
        "a Group body carries an attribute its schema does not define: {group}"
    );
    assert_eq!(group["externalId"], json!("grp_1"));
    assert_eq!(group["schemas"], json!([GROUP_SCHEMA]));
    assert_eq!(group["displayName"], json!("Engineering"));

    // CONTROL: a User body still carries it, so the omission above is about the schema and not
    // about the attribute having been dropped everywhere.
    let user = resource_for(USER_SCHEMA, "usr_1", true, &json!({}), &source()).expect("maps");
    assert_eq!(user["active"], json!(true));
}

#[tokio::test]
async fn a_deactivated_subject_maps_to_an_inactive_resource() {
    // `active` is what the Deactivate deletion policy acts on, so it has to come from the
    // subject's state rather than from the mapping. A connection whose operator mapped `active`
    // to a trait would decide departures by that trait, which is the reserved check above; this
    // is the other half, that the value actually tracks the argument.
    let inactive = resource_for(USER_SCHEMA, "usr_1", false, &json!({}), &source()).expect("maps");
    assert_eq!(inactive["active"], json!(false));
    let active = resource_for(USER_SCHEMA, "usr_1", true, &json!({}), &source()).expect("maps");
    assert_eq!(active["active"], json!(true));
}
