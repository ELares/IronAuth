// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic SCIM core-user importer (issue #57), one half of the escape hatch.
//!
//! Accepts SCIM 2.0 core user resources (RFC 7643) offline: a single resource, a
//! bare array, or a SCIM `ListResponse` envelope. This consumes SCIM-SHAPED data
//! from a file; it is NOT a SCIM protocol server (that is M14). SCIM exports do not
//! carry password hashes, so a SCIM user is imported credential-less by design (the
//! user sets a credential after import); a plaintext `password`, if present, is
//! reported as a gap rather than stored.
//!
//! # What maps
//!
//! | SCIM attribute            | IronAuth target                                  |
//! |---------------------------|--------------------------------------------------|
//! | `userName`                | `identifier` (required)                          |
//! | `externalId`              | `external_id`                                    |
//! | `emails` (primary/first)  | `claims.email`                                   |
//! | `name.*` / `displayName`  | `claims.given_name` / `family_name` / `name`     |
//! | `phoneNumbers`            | `claims.phone_number`                            |
//! | `active`                  | `state` (`false` -> `disabled`)                  |
//!
//! `groups`, `roles`, `entitlements`, the SP-assigned `id`, a plaintext `password`,
//! and any unconsumed attribute (including enterprise-extension URNs) are reported
//! per record.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::gap::{Gap, MappedUser, Mapping, Source};
use crate::parse::ParseError;

/// A SCIM core user resource. Named attributes are handled explicitly; anything
/// else lands in `extra` and is reported as a gap.
#[derive(Debug, Deserialize)]
struct ScimUser {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "externalId")]
    external_id: Option<String>,
    #[serde(default, rename = "userName")]
    user_name: Option<String>,
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    name: Option<ScimName>,
    #[serde(default)]
    emails: Vec<ScimValue>,
    #[serde(default, rename = "phoneNumbers")]
    phone_numbers: Vec<ScimValue>,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    groups: Vec<Value>,
    #[serde(default)]
    roles: Vec<Value>,
    #[serde(default)]
    entitlements: Vec<Value>,
    /// Every attribute the importer does not name (including `schemas` and any
    /// enterprise-extension URN): reported as a gap.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// A SCIM complex `name` attribute.
#[derive(Debug, Deserialize)]
struct ScimName {
    #[serde(default, rename = "givenName")]
    given_name: Option<String>,
    #[serde(default, rename = "familyName")]
    family_name: Option<String>,
    #[serde(default)]
    formatted: Option<String>,
    /// Every nested name sub-attribute the importer does not name (for example
    /// `middleName`, `honorificPrefix`, `honorificSuffix`): reported as a per-field
    /// gap so no nested name detail is silently dropped.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// A SCIM multi-valued attribute entry (`emails`, `phoneNumbers`).
#[derive(Debug, Deserialize)]
struct ScimValue {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    primary: Option<bool>,
    /// Every entry sub-attribute the importer does not name (for example `type`,
    /// `display`): reported as a per-field gap so no nested multi-valued detail is
    /// silently dropped.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Map SCIM core user resources into the #55 record format plus a per-record gap
/// report (issue #57).
///
/// Accepts a single resource object, a bare array of resources, or a SCIM
/// `ListResponse` envelope (`{ "Resources": [ .. ] }`).
///
/// # Errors
///
/// [`ParseError`] if the document is not well-formed JSON or not a recognized SCIM
/// shape. A per-user problem is a dropped record or a gap.
pub fn map_users(json: &str) -> Result<Mapping, ParseError> {
    let value: Value = serde_json::from_str(json).map_err(ParseError::from_serde)?;
    let resources = extract_resources(value)?;
    let users = resources
        .into_iter()
        .enumerate()
        .map(|(index, value)| map_value(index, value))
        .collect();
    Ok(Mapping {
        source: Source::Scim,
        users,
    })
}

/// Pull the raw resource values out of whichever SCIM shape was supplied. Each
/// resource is deserialized INDIVIDUALLY by [`map_value`], so one malformed
/// resource is reported and skipped rather than failing the whole import.
fn extract_resources(value: Value) -> Result<Vec<Value>, ParseError> {
    match value {
        Value::Array(items) => Ok(items),
        Value::Object(mut map) if map.contains_key("Resources") => match map.remove("Resources") {
            Some(Value::Array(items)) => Ok(items),
            _ => Err(ParseError::new(
                "SCIM ListResponse Resources is not an array",
            )),
        },
        Value::Object(_) => Ok(vec![value]),
        _ => Err(ParseError::new(
            "SCIM document is neither a resource, an array, nor a ListResponse",
        )),
    }
}

/// Deserialize one raw resource value into the typed shape and map it. A value that
/// cannot be parsed into a SCIM user becomes a dropped record with a field-level
/// reason and is skipped, so a single bad resource never fails the rest of the
/// import.
fn map_value(index: usize, value: Value) -> MappedUser {
    let source_key = crate::parse::source_key_from_value(
        &value,
        &["id", "externalId", "userName"],
        format!("scim-user-{index}"),
    );
    match serde_json::from_value::<ScimUser>(value) {
        Ok(user) => map_user(index, &user),
        Err(error) => {
            MappedUser::dropped(source_key, format!("malformed record: {error}"), Vec::new())
        }
    }
}

/// Map one SCIM user, accumulating gaps.
fn map_user(index: usize, user: &ScimUser) -> MappedUser {
    let source_key = user
        .id
        .clone()
        .or_else(|| user.external_id.clone())
        .or_else(|| user.user_name.clone())
        .unwrap_or_else(|| format!("scim-user-{index}"));
    let mut gaps = Vec::new();

    let Some(identifier) = user.user_name.clone() else {
        return MappedUser::dropped(
            source_key,
            "SCIM resource has no userName (the login handle is required)",
            gaps,
        );
    };

    let claims = build_claims(user);
    let state = match user.active {
        Some(false) => Some("disabled".to_owned()),
        _ => None,
    };
    record_gaps(user, &mut gaps);

    let record = ironauth_import::ImportRecord {
        identifier,
        id: None,
        external_id: user.external_id.clone(),
        state,
        claims,
        traits: None,
        traits_schema_version: None,
        // SCIM exports carry no password hash; the user is credential-less by design.
        password_hash: None,
        credentials: None,
        totp: None,
        recovery_codes: None,
    };
    MappedUser::mapped(source_key, record, gaps)
}

/// Build the OIDC standard-claim document from SCIM attributes.
fn build_claims(user: &ScimUser) -> Option<Value> {
    let mut claims = Map::new();
    if let Some(email) = primary_or_first(&user.emails) {
        claims.insert("email".to_owned(), Value::String(email));
    }
    if let Some(phone) = primary_or_first(&user.phone_numbers) {
        claims.insert("phone_number".to_owned(), Value::String(phone));
    }
    if let Some(name) = &user.name {
        if let Some(given) = &name.given_name {
            claims.insert("given_name".to_owned(), Value::String(given.clone()));
        }
        if let Some(family) = &name.family_name {
            claims.insert("family_name".to_owned(), Value::String(family.clone()));
        }
        let full = name
            .formatted
            .clone()
            .or_else(|| user.display_name.clone())
            .or_else(|| match (&name.given_name, &name.family_name) {
                (Some(g), Some(f)) => Some(format!("{g} {f}")),
                _ => None,
            });
        if let Some(full) = full {
            claims.insert("name".to_owned(), Value::String(full));
        }
    } else if let Some(display) = &user.display_name {
        claims.insert("name".to_owned(), Value::String(display.clone()));
    }
    if claims.is_empty() {
        None
    } else {
        Some(Value::Object(claims))
    }
}

/// The primary multi-valued entry's value, else the first entry's value.
fn primary_or_first(values: &[ScimValue]) -> Option<String> {
    values
        .iter()
        .find(|v| v.primary == Some(true))
        .or_else(|| values.first())
        .and_then(|v| v.value.clone())
}

/// Report every dropped secondary value and every unmodeled entry sub-attribute in
/// a SCIM multi-valued attribute (`emails`, `phoneNumbers`), so no nested value is
/// silently dropped. The one entry [`primary_or_first`] carries into claims is not
/// reported as a secondary drop; every other entry with a value is.
fn report_multivalue_gaps(field: &str, values: &[ScimValue], gaps: &mut Vec<Gap>) {
    // The index carried into claims: the first primary entry, else the first entry.
    let kept = values
        .iter()
        .position(|v| v.primary == Some(true))
        .or(if values.is_empty() { None } else { Some(0) });
    for (i, entry) in values.iter().enumerate() {
        if Some(i) != kept && entry.value.is_some() {
            gaps.push(Gap::new(
                format!("{field}[{i}]"),
                "secondary value",
                "only the primary (or first) value is carried into claims; secondary values are not imported",
            ));
        }
        for key in entry.extra.keys() {
            gaps.push(Gap::new(
                format!("{field}[{i}].{key}"),
                "unmodeled sub-attribute",
                "present on the multi-valued entry but not consumed by the SCIM importer",
            ));
        }
    }
}

/// Record a gap for every construct with no representable target and any unconsumed
/// attribute.
fn record_gaps(user: &ScimUser, gaps: &mut Vec<Gap>) {
    if !user.groups.is_empty() {
        gaps.push(Gap::new(
            "groups",
            format!("{} group membership(s)", user.groups.len()),
            "IronAuth has no representable group target",
        ));
    }
    if !user.roles.is_empty() {
        gaps.push(Gap::new(
            "roles",
            format!("{} role(s)", user.roles.len()),
            "IronAuth has no representable role target",
        ));
    }
    if !user.entitlements.is_empty() {
        gaps.push(Gap::new(
            "entitlements",
            format!("{} entitlement(s)", user.entitlements.len()),
            "IronAuth has no representable entitlement target",
        ));
    }
    if user.password.is_some() {
        gaps.push(Gap::new(
            "password",
            "plaintext password",
            "a plaintext password is never stored; the user sets a credential after import",
        ));
    }
    // Nested name sub-attributes with no modeled target (middleName, honorific*).
    if let Some(name) = &user.name {
        for key in name.extra.keys() {
            gaps.push(Gap::new(
                format!("name.{key}"),
                "unmodeled name sub-attribute",
                "present on the name attribute but not consumed by the SCIM importer",
            ));
        }
    }
    // Multi-valued attributes: only the primary (or first) value is carried into
    // claims, so every SECONDARY value is real user data that would otherwise be
    // dropped un-reported. Report each secondary value and each entry sub-attribute
    // (type, display, ...).
    report_multivalue_gaps("emails", &user.emails, gaps);
    report_multivalue_gaps("phoneNumbers", &user.phone_numbers, gaps);
    if user.id.is_some() {
        gaps.push(Gap::new(
            "id",
            "SCIM service-provider id",
            "the SP-assigned id is not preserved; externalId is used as the correlation key",
        ));
    }
    for key in user.extra.keys() {
        gaps.push(Gap::new(
            key.clone(),
            "unmodeled attribute",
            "present in the resource but not consumed by the SCIM importer",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gap::MapOutcome;

    #[test]
    fn a_list_response_envelope_maps_every_resource() {
        let json = r#"{
            "schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "Resources":[
                {"userName":"alice","externalId":"e1","emails":[{"value":"a@x.test","primary":true}],"active":true},
                {"userName":"bob","active":false}
            ]
        }"#;
        let mapping = map_users(json).expect("map");
        assert_eq!(mapping.users.len(), 2);
        let MapOutcome::Mapped(alice) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        assert_eq!(alice.identifier, "alice");
        assert_eq!(alice.external_id.as_deref(), Some("e1"));
        assert_eq!(alice.claims.as_ref().unwrap()["email"], "a@x.test");
        let MapOutcome::Mapped(bob) = &mapping.users[1].outcome else {
            panic!("mapped");
        };
        assert_eq!(bob.state.as_deref(), Some("disabled"));
    }

    #[test]
    fn groups_and_a_plaintext_password_are_gaps() {
        let json = r#"{"userName":"carol","groups":[{"value":"g1"}],"password":"secret"}"#;
        let mapping = map_users(json).expect("map");
        let fields: Vec<&str> = mapping.users[0]
            .gaps
            .iter()
            .map(|g| g.field.as_str())
            .collect();
        assert!(fields.contains(&"groups"));
        assert!(fields.contains(&"password"));
    }

    #[test]
    fn a_resource_without_username_is_dropped() {
        let mapping = map_users(r#"{"externalId":"e"}"#).expect("map");
        assert!(mapping.users[0].is_dropped());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(map_users("{not json").is_err());
    }

    #[test]
    fn one_malformed_resource_does_not_fail_the_import() {
        // MEDIUM 1: per-record isolation. The middle resource's `emails` is the
        // wrong shape, so it cannot deserialize; it is reported as a dropped record
        // and skipped while the good resources import.
        let json = r#"{"Resources":[
            {"userName":"alice"},
            {"userName":"bad","emails":"not-an-array"},
            {"userName":"carol"}
        ]}"#;
        let mapping = map_users(json).expect("the ListResponse still parses");
        assert_eq!(mapping.users.len(), 3);
        assert!(!mapping.users[0].is_dropped());
        assert!(!mapping.users[2].is_dropped());
        let bad = &mapping.users[1];
        assert!(bad.is_dropped());
        assert_eq!(bad.source_key, "bad");
        let MapOutcome::Dropped(reason) = &bad.outcome else {
            panic!("dropped");
        };
        assert!(reason.contains("malformed record"), "{reason}");
    }

    #[test]
    fn secondary_emails_phones_and_nested_name_fields_are_reported() {
        // MEDIUM 3: only the primary/first email and phone are carried into claims,
        // so every SECONDARY value is real user data that must be reported, along
        // with nested name and entry sub-attributes; nothing is silently dropped.
        let json = r#"{"userName":"nina",
            "name":{"givenName":"Nina","familyName":"Nolan","middleName":"Q","honorificPrefix":"Dr"},
            "emails":[
                {"value":"nina@work.test","primary":true,"type":"work"},
                {"value":"nina@home.test","type":"home"},
                {"value":"nina@alt.test"}
            ],
            "phoneNumbers":[
                {"value":"+15550001111","primary":true},
                {"value":"+15550002222"}
            ]}"#;
        let mapping = map_users(json).expect("map");
        let fields: Vec<&str> = mapping.users[0]
            .gaps
            .iter()
            .map(|g| g.field.as_str())
            .collect();
        // Nested name sub-attributes.
        assert!(fields.contains(&"name.middleName"), "{fields:?}");
        assert!(fields.contains(&"name.honorificPrefix"), "{fields:?}");
        // Secondary email and phone values (the primary is the one kept).
        assert!(fields.contains(&"emails[1]"), "{fields:?}");
        assert!(fields.contains(&"emails[2]"), "{fields:?}");
        assert!(fields.contains(&"phoneNumbers[1]"), "{fields:?}");
        // Entry sub-attributes (type/display).
        assert!(fields.contains(&"emails[0].type"), "{fields:?}");
        assert!(fields.contains(&"emails[1].type"), "{fields:?}");
    }
}
