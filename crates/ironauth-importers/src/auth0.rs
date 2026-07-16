// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Auth0 bulk-export importer (issue #57).
//!
//! Parses the Auth0 bulk user export (a JSON array or NDJSON) and, separately, the
//! password-hash export Auth0 gates behind a support ticket (NDJSON carrying
//! `passwordHash`). The two are joined by email: the profile export carries the
//! identity and metadata, the hash export carries the bcrypt verifier. An imported
//! user logs in with the original password (verified against the bcrypt hash) and
//! is rehashed to Argon2id on first login.
//!
//! # What maps
//!
//! | Auth0 field                       | IronAuth target                          |
//! |-----------------------------------|------------------------------------------|
//! | `email` (or `username`/`user_id`) | `identifier`                             |
//! | `user_id`                         | `external_id` (the idempotency key)      |
//! | `email_verified`, `name`, ...     | `claims`                                 |
//! | `phone_number` / `phone_verified` | `claims.phone_number` / `..._verified`   |
//! | `blocked`                         | `state` (`true` -> `blocked`)            |
//! | `app_metadata` / `user_metadata`  | `traits` (verbatim, unversioned)         |
//! | joined `passwordHash` (bcrypt)    | `password_hash`                          |
//!
//! # What is reported as a gap
//!
//! Secondary and social entries in the `identities` array (a linked-identity
//! concept IronAuth does not model), a user with no row in the hash export, a
//! `passwordHash` in an unrecognized scheme, enrolled MFA, and any field the
//! importer does not consume are all reported per record rather than dropped.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::gap::{Gap, MappedUser, Mapping, Source};
use crate::parse::ParseError;

/// One Auth0 profile-export user. Named fields are handled explicitly; anything
/// else lands in `extra` and is reported as a gap.
#[derive(Debug, Deserialize)]
struct Auth0User {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    nickname: Option<String>,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    phone_number: Option<String>,
    #[serde(default)]
    phone_verified: Option<bool>,
    #[serde(default)]
    blocked: Option<bool>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    last_login: Option<String>,
    #[serde(default)]
    logins_count: Option<i64>,
    #[serde(default)]
    identities: Vec<Value>,
    #[serde(default)]
    app_metadata: Option<Value>,
    #[serde(default)]
    user_metadata: Option<Value>,
    #[serde(default)]
    multifactor: Vec<String>,
    /// Every field the importer does not name: reported as a gap.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// One row of the Auth0 password-hash export.
#[derive(Debug, Deserialize)]
struct Auth0HashRow {
    #[serde(default)]
    email: Option<String>,
    #[serde(default, rename = "passwordHash")]
    password_hash: Option<String>,
}

/// Map an Auth0 bulk export, joining the optional password-hash export by email,
/// into the #55 record format plus a per-record gap report (issue #57).
///
/// `users_json` is the profile export (a JSON array or NDJSON of user objects).
/// `password_hashes_ndjson`, when present, is the separately obtained hash export
/// (NDJSON, one `{ "email": .., "passwordHash": .. }` per line).
///
/// # Errors
///
/// [`ParseError`] if the profile export is not a well-formed JSON array or NDJSON
/// of user objects. A malformed line in the hash export is skipped (it simply
/// contributes no join entry); a per-user problem is a dropped record or a gap,
/// never a whole-import failure.
pub fn map_export(
    users_json: &str,
    password_hashes_ndjson: Option<&str>,
) -> Result<Mapping, ParseError> {
    let hashes = match password_hashes_ndjson {
        Some(text) => parse_hash_export(text),
        None => HashMap::new(),
    };
    let mut mapped = Vec::new();
    let trimmed = users_json.trim_start();
    if trimmed.starts_with('[') {
        // A JSON array: parse the top-level container, then deserialize each user
        // object INDIVIDUALLY so one malformed user is reported and skipped rather
        // than failing the whole import.
        let values: Vec<Value> = serde_json::from_str(trimmed).map_err(ParseError::from_serde)?;
        for (index, value) in values.into_iter().enumerate() {
            mapped.push(map_value(index, value, &hashes));
        }
    } else {
        // NDJSON: a malformed line is skipped and reported (mirroring the
        // hash-export parser's tolerance), never failing the rest of the import.
        for (line_no, line) in users_json.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(line) {
                Ok(value) => mapped.push(map_value(line_no, value, &hashes)),
                Err(error) => mapped.push(MappedUser::dropped(
                    format!("auth0-line-{}", line_no + 1),
                    format!("malformed record: line {}: {error}", line_no + 1),
                    Vec::new(),
                )),
            }
        }
    }
    Ok(Mapping {
        source: Source::Auth0,
        users: mapped,
    })
}

/// Deserialize one raw user value into the typed shape, join its hash, and map it.
/// A value that cannot be parsed into an Auth0 user becomes a dropped record with a
/// field-level reason and is skipped, so a single bad user never fails the rest of
/// the import.
fn map_value(index: usize, value: Value, hashes: &HashMap<String, String>) -> MappedUser {
    let source_key = crate::parse::source_key_from_value(
        &value,
        &["user_id", "email"],
        format!("auth0-user-{index}"),
    );
    match serde_json::from_value::<Auth0User>(value) {
        Ok(user) => map_user(index, user, hashes),
        Err(error) => {
            MappedUser::dropped(source_key, format!("malformed record: {error}"), Vec::new())
        }
    }
}

/// Build the email -> bcrypt-hash join map from the hash export. A malformed line
/// is skipped rather than failing the whole import; a row without a usable email or
/// hash contributes nothing.
fn parse_hash_export(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let rows: Vec<Auth0HashRow> = if text.trim_start().starts_with('[') {
        serde_json::from_str(text).unwrap_or_default()
    } else {
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };
    for row in rows {
        if let (Some(email), Some(hash)) = (row.email, row.password_hash) {
            map.insert(email.to_ascii_lowercase(), hash);
        }
    }
    map
}

/// Map one Auth0 user, joining its password hash and accumulating gaps.
fn map_user(index: usize, user: Auth0User, hashes: &HashMap<String, String>) -> MappedUser {
    let source_key = user
        .user_id
        .clone()
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| format!("auth0-user-{index}"));
    let mut gaps = Vec::new();

    let identifier = user
        .email
        .clone()
        .or_else(|| user.username.clone())
        .or_else(|| user.user_id.clone());
    let Some(identifier) = identifier else {
        return MappedUser::dropped(
            source_key,
            "auth0 user has no email, username, or user_id to use as a login handle",
            gaps,
        );
    };

    let claims = build_claims(&user);
    let state = match user.blocked {
        Some(true) => Some("blocked".to_owned()),
        _ => None,
    };
    let password_hash = join_password(&user, hashes, &mut gaps);
    let traits = build_traits(&user);
    record_gaps(&user, &mut gaps);

    let record = ironauth_import::ImportRecord {
        identifier,
        id: None,
        // Move the id out (rather than clone) so this fn genuinely consumes `user`.
        external_id: user.user_id,
        state,
        claims,
        traits,
        traits_schema_version: None,
        password_hash,
        credentials: None,
    };
    MappedUser::mapped(source_key, record, gaps)
}

/// Build the OIDC standard-claim document from an Auth0 profile.
fn build_claims(user: &Auth0User) -> Option<Value> {
    let mut claims = Map::new();
    let mut put_str = |k: &str, v: &Option<String>| {
        if let Some(value) = v {
            claims.insert(k.to_owned(), Value::String(value.clone()));
        }
    };
    put_str("email", &user.email);
    put_str("name", &user.name);
    put_str("nickname", &user.nickname);
    put_str("given_name", &user.given_name);
    put_str("family_name", &user.family_name);
    put_str("picture", &user.picture);
    put_str("phone_number", &user.phone_number);
    if let Some(verified) = user.email_verified {
        claims.insert("email_verified".to_owned(), Value::Bool(verified));
    }
    if let Some(verified) = user.phone_verified {
        claims.insert("phone_number_verified".to_owned(), Value::Bool(verified));
    }
    if claims.is_empty() {
        None
    } else {
        Some(Value::Object(claims))
    }
}

/// Merge Auth0's two metadata objects into a single traits document. Absent when
/// the user carries neither.
fn build_traits(user: &Auth0User) -> Option<Value> {
    let mut traits = Map::new();
    if let Some(Value::Object(app)) = &user.app_metadata {
        if !app.is_empty() {
            traits.insert("app_metadata".to_owned(), Value::Object(app.clone()));
        }
    }
    if let Some(Value::Object(meta)) = &user.user_metadata {
        if !meta.is_empty() {
            traits.insert("user_metadata".to_owned(), Value::Object(meta.clone()));
        }
    }
    if traits.is_empty() {
        None
    } else {
        Some(Value::Object(traits))
    }
}

/// Join the user's bcrypt hash from the hash export, validating it is a recognized
/// scheme; record a gap when there is no hash or it is unrecognized.
fn join_password(
    user: &Auth0User,
    hashes: &HashMap<String, String>,
    gaps: &mut Vec<Gap>,
) -> Option<String> {
    let Some(email) = &user.email else {
        gaps.push(Gap::new(
            "passwordHash",
            "no email to join the hash export",
            "the password-hash export is keyed by email; this user cannot be joined and must reset their password",
        ));
        return None;
    };
    let Some(hash) = hashes.get(&email.to_ascii_lowercase()) else {
        gaps.push(Gap::new(
            "passwordHash",
            "no row in the password-hash export",
            "no hash was provided for this user (Auth0 gates the hash export); the user must reset their password",
        ));
        return None;
    };
    match ironauth_import::ForeignHash::parse(hash) {
        Ok(parsed) => Some(parsed.stored().to_owned()),
        Err(error) => {
            gaps.push(Gap::new(
                "passwordHash",
                "unrecognized password hash scheme",
                format!("the exported hash is not a recognized import scheme ({error}); the user must reset their password"),
            ));
            None
        }
    }
}

/// Record a gap for every construct with no representable target and any unconsumed
/// field.
fn record_gaps(user: &Auth0User, gaps: &mut Vec<Gap>) {
    // The identities array: the primary DB identity is represented by the credential
    // and the login handle; any additional (typically social) identity is a linked
    // account IronAuth does not model.
    if user.identities.len() > 1 {
        gaps.push(Gap::new(
            "identities",
            format!("{} linked identities", user.identities.len() - 1),
            "secondary/social linked identities are not represented; only the primary login is imported",
        ));
    } else if user.identities.len() == 1 && is_social(&user.identities[0]) {
        gaps.push(Gap::new(
            "identities[0]",
            "social identity",
            "a social-connection user has no importable password; the user signs in via the social provider or resets their password",
        ));
    }
    if !user.multifactor.is_empty() {
        gaps.push(Gap::new(
            "multifactor",
            user.multifactor.join(", "),
            "enrolled MFA secrets cannot ride a bulk export; the user re-enrolls them",
        ));
    }
    for (field, present) in [
        ("created_at", user.created_at.is_some()),
        ("updated_at", user.updated_at.is_some()),
        ("last_login", user.last_login.is_some()),
        ("logins_count", user.logins_count.is_some()),
    ] {
        if present {
            gaps.push(Gap::new(
                field,
                "source activity metadata",
                "not imported; IronAuth records its own lifecycle timestamps",
            ));
        }
    }
    for key in user.extra.keys() {
        gaps.push(Gap::new(
            key.clone(),
            "unmodeled field",
            "present in the export but not consumed by the Auth0 importer",
        ));
    }
}

/// Whether an `identities` entry is a social connection (heuristic: `isSocial` true
/// or a non-`auth0` provider).
fn is_social(identity: &Value) -> bool {
    if identity.get("isSocial").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    identity
        .get("provider")
        .and_then(Value::as_str)
        .is_some_and(|p| p != "auth0")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gap::MapOutcome;

    fn bcrypt_line(email: &str, hash: &str) -> String {
        format!(r#"{{"email":"{email}","passwordHash":"{hash}"}}"#)
    }

    #[test]
    fn a_user_joins_its_bcrypt_hash_by_email() {
        let hash = bcrypt::hash_with_result("pw", 4).expect("hash").to_string();
        let users = r#"[{"user_id":"auth0|1","email":"Alice@X.test","email_verified":true}]"#;
        let hashes = bcrypt_line("alice@x.test", &hash);
        let mapping = map_export(users, Some(&hashes)).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        assert_eq!(record.identifier, "Alice@X.test");
        assert_eq!(record.external_id.as_deref(), Some("auth0|1"));
        let stored = record.password_hash.as_deref().expect("hash joined");
        assert!(
            ironauth_import::ForeignHash::parse(stored)
                .expect("parse")
                .verify(b"pw")
        );
    }

    #[test]
    fn a_user_without_a_hash_row_is_credential_less_with_a_gap() {
        let users = r#"[{"user_id":"auth0|2","email":"bob@x.test"}]"#;
        let mapping = map_export(users, None).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        assert!(record.password_hash.is_none());
        assert!(
            mapping.users[0]
                .gaps
                .iter()
                .any(|g| g.field == "passwordHash")
        );
    }

    #[test]
    fn metadata_maps_to_traits() {
        let users = r#"[{"user_id":"auth0|3","email":"c@x.test","app_metadata":{"plan":"pro"},"user_metadata":{"theme":"dark"}}]"#;
        let mapping = map_export(users, None).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        let traits = record.traits.as_ref().expect("traits");
        assert_eq!(traits["app_metadata"]["plan"], "pro");
        assert_eq!(traits["user_metadata"]["theme"], "dark");
    }

    #[test]
    fn ndjson_profile_export_parses() {
        let users = "{\"user_id\":\"auth0|4\",\"email\":\"d@x.test\"}\n{\"user_id\":\"auth0|5\",\"email\":\"e@x.test\"}\n";
        let mapping = map_export(users, None).expect("map");
        assert_eq!(mapping.users.len(), 2);
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(map_export("[not json", None).is_err());
    }

    #[test]
    fn one_malformed_user_in_an_array_does_not_fail_the_import() {
        // MEDIUM 1: per-record isolation. The middle user's `identities` is the
        // wrong shape, so it cannot deserialize; it is reported as a dropped record
        // and skipped while the good users import.
        let users = r#"[
            {"user_id":"auth0|1","email":"a@x.test"},
            {"user_id":"auth0|2","email":"b@x.test","identities":"nope"},
            {"user_id":"auth0|3","email":"c@x.test"}
        ]"#;
        let mapping = map_export(users, None).expect("the top-level array still parses");
        assert_eq!(mapping.users.len(), 3);
        assert!(!mapping.users[0].is_dropped());
        assert!(!mapping.users[2].is_dropped());
        let bad = &mapping.users[1];
        assert!(bad.is_dropped());
        assert_eq!(bad.source_key, "auth0|2");
        let MapOutcome::Dropped(reason) = &bad.outcome else {
            panic!("dropped");
        };
        assert!(reason.contains("malformed record"), "{reason}");
    }

    #[test]
    fn a_malformed_ndjson_line_is_skipped_and_reported() {
        // MEDIUM 1: an NDJSON profile export mirrors the hash-export parser's
        // tolerance: a bad line is skipped and reported, never failing the import.
        let users = "{\"user_id\":\"auth0|1\",\"email\":\"a@x.test\"}\n{not json}\n{\"user_id\":\"auth0|2\",\"email\":\"b@x.test\"}\n";
        let mapping = map_export(users, None).expect("ndjson tolerates a bad line");
        assert_eq!(
            mapping.users.len(),
            3,
            "the bad line is reported, not dropped"
        );
        let dropped: Vec<&MappedUser> = mapping.users.iter().filter(|u| u.is_dropped()).collect();
        assert_eq!(dropped.len(), 1);
        let MapOutcome::Dropped(reason) = &dropped[0].outcome else {
            panic!("dropped");
        };
        assert!(reason.contains("malformed record"), "{reason}");
    }
}
