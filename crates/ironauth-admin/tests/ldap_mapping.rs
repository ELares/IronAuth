// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mapping a directory entry to an identity (issue #142).

use ironauth_admin::ldap_mapping::{
    DirectoryEntry, LdapMappingError, StableIdSource, principal_for,
};
use serde_json::json;

fn attrs(pairs: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
    pairs
        .iter()
        .map(|(name, values)| {
            (
                (*name).to_owned(),
                values.iter().map(|v| (*v).to_owned()).collect(),
            )
        })
        .collect()
}

/// THE PROPERTY THE WHOLE MODULE EXISTS FOR.
///
/// Ada moves from Engineering to Sales and marries, so her DN changes twice over. She is one
/// person throughout, and a sync that decided otherwise would deactivate her and create a
/// duplicate -- or, under `absence_policy = delete`, remove her.
///
/// The two entries below differ in EVERY mapped field except the GUID: different DN, different
/// cn, different mail. Only the GUID says they are the same person, so this fails the moment the
/// mapper prefers anything else.
#[test]
fn a_move_and_a_rename_do_not_change_who_the_person_is() {
    let mapping = json!({ "username": "uid", "email": "mail", "display_name": "cn" });

    let before = DirectoryEntry::new(
        "cn=Ada Byron,ou=Engineering,dc=example,dc=test",
        attrs(&[
            ("objectGUID", &["b3f1-ada"]),
            ("uid", &["ada"]),
            ("mail", &["ada.byron@example.test"]),
            ("cn", &["Ada Byron"]),
        ]),
    );
    let after = DirectoryEntry::new(
        "cn=Ada Lovelace,ou=Sales,dc=example,dc=test",
        attrs(&[
            ("objectGUID", &["b3f1-ada"]),
            ("uid", &["ada"]),
            ("mail", &["ada.lovelace@example.test"]),
            ("cn", &["Ada Lovelace"]),
        ]),
    );

    let before = principal_for(&before, &mapping).expect("maps");
    let after = principal_for(&after, &mapping).expect("maps");

    assert_eq!(
        before.stable_id, after.stable_id,
        "a move plus a rename produced a different identity"
    );
    assert_eq!(before.stable_id_source, StableIdSource::ObjectGuid);
    assert!(before.stable_id_source.survives_rename());

    // POSITIVE assertions on every other field, not just `assert_ne!` between the two results.
    // Comparing two outputs of the same function only proves the mapper is not returning a
    // constant: it moves with the input whatever the input is mapped to. Sourcing `display_name`
    // from `mail` -- the adjacent line, copy-pasted -- passed a `ne` check because the two mails
    // also differ, and so did emitting a mangled DN.
    assert_eq!(before.dn, "cn=Ada Byron,ou=Engineering,dc=example,dc=test");
    assert_eq!(after.dn, "cn=Ada Lovelace,ou=Sales,dc=example,dc=test");
    assert_eq!(before.email.as_deref(), Some("ada.byron@example.test"));
    assert_eq!(after.email.as_deref(), Some("ada.lovelace@example.test"));
    assert_eq!(before.display_name.as_deref(), Some("Ada Byron"));
    assert_eq!(after.display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(before.username, "ada");
}

/// A server with no `objectGUID` falls to RFC 4530's `entryUUID`, which is equally stable.
#[test]
fn openldap_is_identified_by_entry_uuid() {
    let entry = DirectoryEntry::new(
        "uid=grace,ou=People,dc=example,dc=test",
        attrs(&[("entryUUID", &["8f14-grace"]), ("uid", &["grace"])]),
    );
    let mapped = principal_for(&entry, &json!({})).expect("maps");
    assert_eq!(mapped.stable_id, "8f14-grace");
    assert_eq!(mapped.stable_id_source, StableIdSource::EntryUuid);
    assert!(mapped.stable_id_source.survives_rename());
}

/// `objectGUID` is preferred over `entryUUID` when a server publishes both, and the choice is
/// the mapper's rather than the order the attributes arrived in -- so this entry lists them in
/// the opposite order to the preference list.
#[test]
fn object_guid_wins_over_entry_uuid_regardless_of_attribute_order() {
    let entry = DirectoryEntry::new(
        "uid=both,dc=example,dc=test",
        attrs(&[
            ("entryUUID", &["uuid-value"]),
            ("objectGUID", &["guid-value"]),
            ("uid", &["both"]),
        ]),
    );
    let mapped = principal_for(&entry, &json!({})).expect("maps");
    assert_eq!(mapped.stable_id, "guid-value");
}

/// A directory publishing neither UUID still syncs, but it is a DEGRADED mode and the mapper says
/// so, because on that server a rename really is indistinguishable from a departure.
#[test]
fn a_server_with_no_uuid_falls_back_to_the_dn_and_admits_it() {
    let entry = DirectoryEntry::new(
        "uid=plain,dc=example,dc=test",
        attrs(&[("uid", &["plain"])]),
    );
    let mapped = principal_for(&entry, &json!({})).expect("maps");
    assert_eq!(mapped.stable_id, "uid=plain,dc=example,dc=test");
    assert_eq!(mapped.stable_id_source, StableIdSource::DistinguishedName);
    assert!(
        !mapped.stable_id_source.survives_rename(),
        "a DN-keyed identity must not claim to survive a rename"
    );
}

/// Two values for the identifier is refused, not resolved by taking the first.
///
/// A server that answers the two values in the other order on the next search would otherwise
/// give the same person a different identity between two syncs -- the exact duplication the
/// module is built to prevent, arriving by a different door.
#[test]
fn a_two_valued_identifier_is_refused_rather_than_picked_from() {
    let entry = DirectoryEntry::new(
        "uid=twins,dc=example,dc=test",
        attrs(&[
            ("objectGUID", &["first-value", "second-value"]),
            ("uid", &["twins"]),
        ]),
    );
    let err = principal_for(&entry, &json!({})).expect_err("must refuse");
    assert_eq!(
        err,
        LdapMappingError::AmbiguousStableId {
            attribute: "objectguid".to_owned(),
            count: 2,
        }
    );
}

/// A mapping naming a field this build does not sync is refused at save time.
///
/// Silently dropping it would leave the operator believing `manager` was being written.
#[test]
fn a_field_this_build_does_not_sync_is_refused_not_ignored() {
    let entry = DirectoryEntry::new("uid=x,dc=example,dc=test", attrs(&[("uid", &["x"])]));
    let err = principal_for(&entry, &json!({ "manager": "manager" })).expect_err("must refuse");
    assert_eq!(
        err,
        LdapMappingError::UnknownField {
            field: "manager".to_owned()
        }
    );
}

/// A principal with no login identifier is a row nobody can sign in as.
#[test]
fn an_entry_with_no_username_is_an_error() {
    let entry = DirectoryEntry::new(
        "cn=No Uid,dc=example,dc=test",
        attrs(&[("cn", &["No Uid"])]),
    );
    let err = principal_for(&entry, &json!({})).expect_err("must refuse");
    assert_eq!(
        err,
        LdapMappingError::Missing {
            field: "username".to_owned(),
            attribute: "uid".to_owned(),
        }
    );
}

/// Attribute names are case-insensitive per RFC 4512, and servers disagree about the case they
/// echo: Active Directory answers `sAMAccountName`, `OpenLDAP` echoes what was asked for.
///
/// TWO foldings have to happen and this fixture exercises both, because an earlier version wrote
/// the mapping in lowercase and so only ever tested the storing side -- removing the folding from
/// the LOOKUP left all ten tests green. Every case below is deliberately different: the entry
/// echoes one spelling, the operator wrote another, and neither is the lowercase form the map is
/// keyed by.
#[test]
fn attribute_lookup_folds_case_the_way_the_protocol_does() {
    let entry = DirectoryEntry::new(
        "cn=Case,dc=example,dc=test",
        attrs(&[
            ("SAMAccountName", &["case"]),
            ("MAIL", &["case@example.test"]),
        ]),
    );
    let mapped = principal_for(
        &entry,
        &json!({ "username": "sAMAccountName", "email": "Mail" }),
    )
    .expect("maps");
    assert_eq!(mapped.username, "case");
    assert_eq!(mapped.email.as_deref(), Some("case@example.test"));
}

/// The identifier attributes are matched case-insensitively too.
///
/// Active Directory answers `objectGUID` and the preference list is keyed in lowercase, so a
/// literal comparison would silently miss the GUID on every real AD entry and fall through to the
/// DN -- degrading identity to rename-fragile without any error to notice.
#[test]
fn the_identifier_is_found_in_the_case_the_server_echoes() {
    let entry = DirectoryEntry::new(
        "cn=AD,dc=example,dc=test",
        attrs(&[("objectGUID", &["ad-guid"]), ("uid", &["ad"])]),
    );
    let mapped = principal_for(&entry, &json!({})).expect("maps");
    assert_eq!(mapped.stable_id_source, StableIdSource::ObjectGuid);
    assert_eq!(mapped.stable_id, "ad-guid");
}

/// A mapping value that is not a string is a configuration error rather than a default.
#[test]
fn a_non_string_mapping_value_is_refused() {
    let entry = DirectoryEntry::new("uid=x,dc=example,dc=test", attrs(&[("uid", &["x"])]));
    let err = principal_for(&entry, &json!({ "email": ["mail"] })).expect_err("must refuse");
    assert_eq!(
        err,
        LdapMappingError::NotAnAttributeName {
            field: "email".to_owned()
        }
    );
}

/// An optional field the entry does not carry is absent, not an error: plenty of directory
/// accounts genuinely have no mail attribute.
#[test]
fn an_absent_optional_field_is_none_rather_than_a_refusal() {
    let entry = DirectoryEntry::new("uid=x,dc=example,dc=test", attrs(&[("uid", &["x"])]));
    let mapped = principal_for(&entry, &json!({ "email": "mail" })).expect("maps");
    assert_eq!(mapped.email, None);
}

/// ACTIVE DIRECTORY'S `objectGUID` IS NOT TEXT. It is a raw 16-byte value that arrives as an
/// octet string, so a mapper reading only text attributes finds no identifier on any AD entry
/// and silently falls through to the rename-fragile DN -- on the one directory this module's
/// whole thesis is aimed at.
///
/// The rendering is Active Directory's own display form, which is mixed-endian: the first three
/// groups are little-endian, the last two big-endian. An operator debugging a sync compares what
/// IronAuth stored against what `Get-ADUser` prints, and a straight hex dump of the same bytes
/// would look like a different person.
#[test]
fn an_active_directory_object_guid_arrives_as_octets_and_renders_the_way_ad_prints_it() {
    let raw: Vec<u8> = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let entry = DirectoryEntry::new(
        "cn=Ada,ou=People,dc=example,dc=test",
        attrs(&[("sAMAccountName", &["ada"])]),
    )
    .with_binary(vec![("objectGUID".to_owned(), vec![raw])]);

    let mapped = principal_for(&entry, &json!({ "username": "sAMAccountName" })).expect("maps");
    assert_eq!(mapped.stable_id_source, StableIdSource::ObjectGuid);
    assert_eq!(
        mapped.stable_id, "33221100-5544-7766-8899-aabbccddeeff",
        "the GUID must render the way Active Directory prints it, not in memory order"
    );
}

/// Two identifiers are ambiguous whichever form they arrived in, so the count spans both maps.
#[test]
fn a_text_and_an_octet_identifier_together_are_still_ambiguous() {
    let entry = DirectoryEntry::new("uid=x,dc=example,dc=test", attrs(&[("uid", &["x"])]))
        .with_binary(vec![("entryUUID".to_owned(), vec![b"from-bytes".to_vec()])]);
    let entry = DirectoryEntry::new(
        entry.dn.clone(),
        attrs(&[("uid", &["x"]), ("entryUUID", &["from-text"])]),
    )
    .with_binary(vec![("entryUUID".to_owned(), vec![b"from-bytes".to_vec()])]);

    let err = principal_for(&entry, &json!({})).expect_err("must refuse");
    assert_eq!(
        err,
        LdapMappingError::AmbiguousStableId {
            attribute: "entryuuid".to_owned(),
            count: 2,
        }
    );
}

/// A mapping that is not an object at all is refused rather than treated as an empty one.
///
/// Every fixture passed a JSON object, so the first refusal in `principal_for` had nothing behind
/// it: replacing it with `unwrap_or(&empty)` left the suite green. A corrupt `attribute_mapping`
/// column would then map every entry through the defaults and look like it worked.
#[test]
fn a_mapping_that_is_not_an_object_is_refused() {
    let entry = DirectoryEntry::new("uid=x,dc=example,dc=test", attrs(&[("uid", &["x"])]));
    for bad in [json!("uid"), json!([1, 2]), json!(null), json!(7)] {
        assert_eq!(
            principal_for(&entry, &bad).expect_err("must refuse"),
            LdapMappingError::NotAnObject,
            "accepted {bad} as a mapping"
        );
    }
}

/// Trying to map the stable identifier is refused with a message that says WHY.
///
/// Not the unknown-field error: the field is not unknown, it is not the operator's to choose, and
/// somebody told "no field named `stable_id` is synced" goes looking for a spelling mistake.
#[test]
fn mapping_the_stable_identifier_is_refused_as_reserved_not_as_a_typo() {
    let entry = DirectoryEntry::new("uid=x,dc=example,dc=test", attrs(&[("uid", &["x"])]));
    for field in ["stable_id", "dn"] {
        let err = principal_for(&entry, &json!({ field: "objectGUID" })).expect_err("must refuse");
        assert_eq!(
            err,
            LdapMappingError::StableIdNotMappable {
                field: field.to_owned()
            }
        );
        assert!(
            err.to_string().contains("rename"),
            "the message must explain the consequence: {err}"
        );
    }
}
