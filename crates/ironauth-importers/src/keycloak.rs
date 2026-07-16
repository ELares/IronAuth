// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Keycloak realm-export importer (issue #57).
//!
//! Parses a Keycloak realm export (`realm.json`) and maps its `users` array to the
//! #55 import record format. Each user's login handle, email and name claims,
//! lifecycle flag, custom attributes, and password credential are carried across;
//! Keycloak's PBKDF2 credential (the default hash provider) is re-encoded into the
//! canonical PHC string the scheme layer verifies, so an imported user logs in with
//! the original password and is rehashed to Argon2id on first login.
//!
//! # What maps
//!
//! | Keycloak field            | IronAuth target                                   |
//! |---------------------------|---------------------------------------------------|
//! | `username`                | `identifier` (required; a user without one drops) |
//! | `id`                      | `external_id` (the idempotency key)               |
//! | `email` / `emailVerified` | `claims.email` / `claims.email_verified`          |
//! | `firstName` / `lastName`  | `claims.given_name` / `claims.family_name` / `name` |
//! | `enabled`                 | `state` (`false` -> `disabled`, else `active`)    |
//! | `attributes`              | `traits` (verbatim, unversioned)                  |
//! | `credentials[password]`   | `password_hash` (PBKDF2-SHA256/512 -> PHC)        |
//!
//! # What is reported as a gap
//!
//! Keycloak's `realmRoles`, `clientRoles`, and `groups` have no representable
//! target in the current IronAuth identity model, so each membership is reported
//! per record rather than silently dropped. A legacy HMAC-SHA1 PBKDF2 credential
//! (algorithm `pbkdf2`), a bcrypt/argon2 hash provider, and non-password factors
//! (OTP, WebAuthn) whose secret material a bulk export cannot carry are all
//! reported as gaps, together with `requiredActions`, `federatedIdentities`, the
//! source creation timestamp, and any field the importer does not consume.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::gap::{Gap, MappedUser, Mapping, Source};
use crate::parse::ParseError;
use crate::phc::{self, Pbkdf2Prf};

/// A Keycloak realm export document. Only the `users` array is consumed; the
/// realm-level configuration (clients, role definitions, identity-provider config)
/// is not per-user record data and is not reported as a per-record gap.
///
/// The `users` are held as raw JSON values so each user object is deserialized
/// INDIVIDUALLY: one malformed user is reported as a dropped record and skipped,
/// never failing the whole import.
#[derive(Debug, Deserialize)]
struct Realm {
    #[serde(default)]
    users: Vec<Value>,
}

/// One Keycloak user. Named fields are handled explicitly; anything else lands in
/// `extra` and is reported as a gap, so no field is silently dropped.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KcUser {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    attributes: Option<Value>,
    #[serde(default)]
    credentials: Vec<KcCredential>,
    #[serde(default)]
    realm_roles: Vec<String>,
    #[serde(default)]
    client_roles: Option<Value>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    required_actions: Vec<String>,
    #[serde(default)]
    federated_identities: Vec<Value>,
    #[serde(default)]
    created_timestamp: Option<i64>,
    #[serde(default)]
    totp: Option<bool>,
    #[serde(default)]
    disableable_credential_types: Vec<String>,
    /// Every field the importer does not name: reported as a gap.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// One Keycloak credential entry (both the modern `secretData` / `credentialData`
/// form and the legacy top-level `hashedSaltedValue` form are supported).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KcCredential {
    #[serde(rename = "type", default)]
    credential_type: Option<String>,
    /// The modern form: a JSON STRING holding `{ "value": .., "salt": .. }`.
    #[serde(default)]
    secret_data: Option<String>,
    /// The modern form: a JSON STRING holding `{ "hashIterations": .., "algorithm": .. }`.
    #[serde(default)]
    credential_data: Option<String>,
    /// The legacy (pre-8.0) top-level derived key, base64.
    #[serde(default)]
    hashed_salted_value: Option<String>,
    /// The legacy top-level salt, base64.
    #[serde(default)]
    salt: Option<String>,
    /// The legacy top-level iteration count.
    #[serde(default)]
    hash_iterations: Option<u32>,
    /// The legacy top-level algorithm name.
    #[serde(default)]
    algorithm: Option<String>,
    /// Every credential sub-field the importer does not name (for example
    /// `priority`, `userLabel`, `createdDate`): reported as a per-field gap so no
    /// nested credential detail is silently dropped.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// The resolved operands of a Keycloak password credential.
struct KcPassword {
    algorithm: String,
    iterations: u32,
    salt_b64: String,
    value_b64: String,
}

/// Map a Keycloak realm export into the #55 record format plus a per-record gap
/// report (issue #57).
///
/// # Errors
///
/// [`ParseError`] if the top-level document is not a well-formed Keycloak realm
/// export (malformed JSON or a `users` field of the wrong shape). A per-USER
/// problem is never an error: it is reported as a dropped record or a gap in the
/// returned [`Mapping`], so a single bad user never fails the whole import.
pub fn map_realm(json: &str) -> Result<Mapping, ParseError> {
    let realm: Realm = serde_json::from_str(json).map_err(ParseError::from_serde)?;
    let users = realm
        .users
        .into_iter()
        .enumerate()
        .map(|(index, value)| map_value(index, value))
        .collect();
    Ok(Mapping {
        source: Source::Keycloak,
        users,
    })
}

/// Deserialize one raw user value into the typed shape and map it. A value that
/// cannot be parsed into a Keycloak user (a wrong-typed field) becomes a dropped
/// record with a field-level reason and is skipped, so a single bad user never
/// fails the rest of the import.
fn map_value(index: usize, value: Value) -> MappedUser {
    let source_key = crate::parse::source_key_from_value(
        &value,
        &["id", "username"],
        format!("keycloak-user-{index}"),
    );
    match serde_json::from_value::<KcUser>(value) {
        Ok(user) => map_user(index, &user),
        Err(error) => {
            MappedUser::dropped(source_key, format!("malformed record: {error}"), Vec::new())
        }
    }
}

/// Map one Keycloak user, accumulating gaps for every construct not carried
/// forward.
fn map_user(index: usize, user: &KcUser) -> MappedUser {
    let source_key = user
        .id
        .clone()
        .or_else(|| user.username.clone())
        .unwrap_or_else(|| format!("keycloak-user-{index}"));
    let mut gaps = Vec::new();

    let Some(identifier) = user.username.clone() else {
        return MappedUser::dropped(
            source_key,
            "keycloak user has no username (the login handle is required)",
            gaps,
        );
    };

    // Claims: email, verification flag, and name parts.
    let claims = build_claims(user);

    // State: an explicitly disabled account maps to the disabled lifecycle state.
    let state = match user.enabled {
        Some(false) => Some("disabled".to_owned()),
        _ => None,
    };

    // Password: the first password credential, re-encoded to a canonical hash.
    let password_hash = map_password(user, &mut gaps);

    // Traits: the custom attribute document, carried verbatim (unversioned).
    let traits = match &user.attributes {
        Some(Value::Object(map)) if !map.is_empty() => Some(Value::Object(map.clone())),
        _ => None,
    };

    record_membership_gaps(user, &mut gaps);

    let record = ironauth_import::ImportRecord {
        identifier,
        id: None,
        external_id: user.id.clone(),
        state,
        claims,
        traits,
        traits_schema_version: None,
        password_hash,
        credentials: None,
        totp: None,
        recovery_codes: None,
    };
    MappedUser::mapped(source_key, record, gaps)
}

/// Build the OIDC standard-claim document from a Keycloak user's profile fields.
fn build_claims(user: &KcUser) -> Option<Value> {
    let mut claims = Map::new();
    if let Some(username) = &user.username {
        claims.insert(
            "preferred_username".to_owned(),
            Value::String(username.clone()),
        );
    }
    if let Some(email) = &user.email {
        claims.insert("email".to_owned(), Value::String(email.clone()));
    }
    if let Some(verified) = user.email_verified {
        claims.insert("email_verified".to_owned(), Value::Bool(verified));
    }
    if let Some(given) = &user.first_name {
        claims.insert("given_name".to_owned(), Value::String(given.clone()));
    }
    if let Some(family) = &user.last_name {
        claims.insert("family_name".to_owned(), Value::String(family.clone()));
    }
    if let (Some(given), Some(family)) = (&user.first_name, &user.last_name) {
        claims.insert(
            "name".to_owned(),
            Value::String(format!("{given} {family}")),
        );
    }
    if claims.is_empty() {
        None
    } else {
        Some(Value::Object(claims))
    }
}

/// Resolve the user's password credential to a canonical hash string, or record a
/// gap explaining why it could not be carried. Non-password factors are always
/// reported as gaps (their secret material cannot ride a bulk export).
fn map_password(user: &KcUser, gaps: &mut Vec<Gap>) -> Option<String> {
    let mut mapped: Option<String> = None;
    for (i, cred) in user.credentials.iter().enumerate() {
        // No credential sub-field is silently dropped: report each unmodeled key
        // (for example `priority`) on this credential entry.
        for key in cred.extra.keys() {
            gaps.push(Gap::new(
                format!("credentials[{i}].{key}"),
                "unmodeled credential sub-field",
                "present on the credential entry but not consumed by the Keycloak importer",
            ));
        }
        let kind = cred.credential_type.as_deref().unwrap_or("");
        if kind != "password" {
            gaps.push(Gap::new(
                format!("credentials[{i}]"),
                format!("{} factor", if kind.is_empty() { "unknown" } else { kind }),
                "non-password factor secret material cannot be carried by a bulk export; the user re-enrolls it",
            ));
            continue;
        }
        if mapped.is_some() {
            gaps.push(Gap::new(
                format!("credentials[{i}]"),
                "additional password credential",
                "only the first password credential is imported",
            ));
            continue;
        }
        match resolve_password(cred) {
            Ok(password) => match encode_password(&password) {
                // Round-trip the emitted hash through the SAME `ForeignHash::parse`
                // the #55 engine runs at commit, so a credential the engine would
                // reject (for example `hashIterations` past the bound, or an
                // oversized operand) is reported here as a gap and the user is
                // imported CREDENTIAL-LESS, rather than emitting a hash that fails
                // the whole record at commit. The validation pass and the commit
                // pass cannot diverge.
                Ok(hash) => match ironauth_import::ForeignHash::parse(&hash) {
                    Ok(parsed) => mapped = Some(parsed.stored().to_owned()),
                    Err(error) => gaps.push(Gap::new(
                        format!("credentials[{i}]"),
                        format!("{} password hash", password.algorithm),
                        format!("the re-encoded hash was rejected by the scheme layer ({error}); the user must reset their password"),
                    )),
                },
                Err(reason) => gaps.push(Gap::new(
                    format!("credentials[{i}]"),
                    format!("{} password hash", password.algorithm),
                    reason,
                )),
            },
            Err(reason) => gaps.push(Gap::new(
                format!("credentials[{i}]"),
                "password credential",
                reason,
            )),
        }
    }
    mapped
}

/// Pull the algorithm, iterations, salt, and derived key out of a credential,
/// preferring the modern `secretData` / `credentialData` form and falling back to
/// the legacy top-level fields.
fn resolve_password(cred: &KcCredential) -> Result<KcPassword, String> {
    if let (Some(secret), Some(data)) = (&cred.secret_data, &cred.credential_data) {
        let secret: Value = serde_json::from_str(secret)
            .map_err(|_| "credential secretData is not valid JSON".to_owned())?;
        let data: Value = serde_json::from_str(data)
            .map_err(|_| "credential credentialData is not valid JSON".to_owned())?;
        let value_b64 = secret
            .get("value")
            .and_then(Value::as_str)
            .ok_or("credential secretData has no value")?
            .to_owned();
        let salt_b64 = secret
            .get("salt")
            .and_then(Value::as_str)
            .ok_or("credential secretData has no salt")?
            .to_owned();
        let iterations = data
            .get("hashIterations")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or("credential credentialData has no hashIterations")?;
        let algorithm = data
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or("pbkdf2-sha256")
            .to_owned();
        return Ok(KcPassword {
            algorithm,
            iterations,
            salt_b64,
            value_b64,
        });
    }
    if let (Some(value_b64), Some(salt_b64), Some(iterations)) = (
        cred.hashed_salted_value.clone(),
        cred.salt.clone(),
        cred.hash_iterations,
    ) {
        return Ok(KcPassword {
            algorithm: cred
                .algorithm
                .clone()
                .unwrap_or_else(|| "pbkdf2-sha256".to_owned()),
            iterations,
            salt_b64,
            value_b64,
        });
    }
    Err("password credential is missing its hash operands".to_owned())
}

/// Re-encode resolved operands into the canonical hash string the scheme layer
/// verifies, or return a reason the algorithm is not representable.
fn encode_password(password: &KcPassword) -> Result<String, String> {
    let prf = match password.algorithm.as_str() {
        "pbkdf2-sha256" => Pbkdf2Prf::Sha256,
        "pbkdf2-sha512" => Pbkdf2Prf::Sha512,
        "pbkdf2" => {
            return Err(
                "legacy HMAC-SHA1 PBKDF2 is not a recognized scheme; the user must reset their password"
                    .to_owned(),
            );
        }
        other => {
            return Err(format!(
                "keycloak hash provider '{other}' is not a recognized import scheme; the user must reset their password"
            ));
        }
    };
    let salt = phc::decode_std_b64(&password.salt_b64).ok_or("credential salt is not base64")?;
    let derived =
        phc::decode_std_b64(&password.value_b64).ok_or("credential value is not base64")?;
    Ok(phc::pbkdf2_phc(prf, password.iterations, &salt, &derived))
}

/// Record a gap for every membership or profile construct that has no representable
/// IronAuth target, plus any field the importer did not consume.
fn record_membership_gaps(user: &KcUser, gaps: &mut Vec<Gap>) {
    if !user.realm_roles.is_empty() {
        gaps.push(Gap::new(
            "realmRoles",
            format!("{} realm role(s)", user.realm_roles.len()),
            "IronAuth has no representable realm-role target",
        ));
    }
    if let Some(Value::Object(roles)) = &user.client_roles {
        if !roles.is_empty() {
            gaps.push(Gap::new(
                "clientRoles",
                format!("client roles for {} client(s)", roles.len()),
                "IronAuth has no representable client-role target",
            ));
        }
    }
    if !user.groups.is_empty() {
        gaps.push(Gap::new(
            "groups",
            format!("{} group membership(s)", user.groups.len()),
            "IronAuth has no representable group target",
        ));
    }
    if !user.required_actions.is_empty() {
        gaps.push(Gap::new(
            "requiredActions",
            user.required_actions.join(", "),
            "required actions are not represented; set them after import if needed",
        ));
    }
    if !user.federated_identities.is_empty() {
        gaps.push(Gap::new(
            "federatedIdentities",
            format!(
                "{} linked identity provider(s)",
                user.federated_identities.len()
            ),
            "linked social/identity-provider accounts are not represented",
        ));
    }
    if user.totp == Some(true) {
        gaps.push(Gap::new(
            "totp",
            "TOTP enrolled in source",
            "the TOTP secret cannot ride a bulk export; the user re-enrolls it",
        ));
    }
    if user.created_timestamp.is_some() {
        gaps.push(Gap::new(
            "createdTimestamp",
            "source creation timestamp",
            "not preserved; the imported user's created_at is the import time",
        ));
    }
    if !user.disableable_credential_types.is_empty() {
        gaps.push(Gap::new(
            "disableableCredentialTypes",
            user.disableable_credential_types.join(", "),
            "derived credential metadata is not imported",
        ));
    }
    for key in user.extra.keys() {
        gaps.push(Gap::new(
            key.clone(),
            "unmodeled field",
            "present in the export but not consumed by the Keycloak importer",
        ));
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;
    use crate::gap::MapOutcome;

    #[test]
    fn a_user_without_a_username_is_dropped_not_panicked() {
        let mapping = map_realm(r#"{"users":[{"id":"abc","email":"x@y.test"}]}"#).expect("parse");
        assert_eq!(mapping.users.len(), 1);
        assert!(mapping.users[0].is_dropped());
    }

    #[test]
    fn roles_and_groups_are_reported_as_gaps() {
        let json = r#"{"users":[{
            "id":"u1","username":"alice","enabled":true,
            "realmRoles":["offline_access"],
            "groups":["/eng"],
            "requiredActions":["UPDATE_PASSWORD"]
        }]}"#;
        let mapping = map_realm(json).expect("parse");
        let user = &mapping.users[0];
        assert!(!user.is_dropped());
        let fields: Vec<&str> = user.gaps.iter().map(|g| g.field.as_str()).collect();
        assert!(fields.contains(&"realmRoles"));
        assert!(fields.contains(&"groups"));
        assert!(fields.contains(&"requiredActions"));
    }

    #[test]
    fn a_pbkdf2_credential_is_encoded_to_a_recognized_scheme() {
        // secretData / credentialData with a 32-byte all-zero derived key: the exact
        // operand bytes do not matter for THIS test (it checks the scheme is
        // recognized and bounds-checked), only that the re-encoding parses.
        let value = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let salt = base64::engine::general_purpose::STANDARD.encode(b"sixteen-byte-slt");
        let json = format!(
            r#"{{"users":[{{"username":"bob","credentials":[{{
                "type":"password",
                "secretData":"{{\"value\":\"{value}\",\"salt\":\"{salt}\"}}",
                "credentialData":"{{\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\"}}"
            }}]}}]}}"#
        );
        let mapping = map_realm(&json).expect("parse");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("expected a mapped user");
        };
        let hash = record.password_hash.as_deref().expect("hash present");
        let parsed = ironauth_import::ForeignHash::parse(hash).expect("recognized scheme");
        assert_eq!(parsed.tag(), "pbkdf2");
    }

    #[test]
    fn a_legacy_sha1_pbkdf2_credential_is_a_gap_not_a_wrong_hash() {
        let value = base64::engine::general_purpose::STANDARD.encode([0_u8; 20]);
        let salt = base64::engine::general_purpose::STANDARD.encode(b"salt-bytes-here!");
        let json = format!(
            r#"{{"users":[{{"username":"carol","credentials":[{{
                "type":"password",
                "secretData":"{{\"value\":\"{value}\",\"salt\":\"{salt}\"}}",
                "credentialData":"{{\"hashIterations\":20000,\"algorithm\":\"pbkdf2\"}}"
            }}]}}]}}"#
        );
        let mapping = map_realm(&json).expect("parse");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("expected a mapped user");
        };
        assert!(record.password_hash.is_none(), "no hash was invented");
        assert!(
            mapping.users[0]
                .gaps
                .iter()
                .any(|g| g.reason.contains("HMAC-SHA1")),
            "the sha1 credential is reported"
        );
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        assert!(map_realm("{not json").is_err());
    }

    #[test]
    fn one_malformed_user_does_not_fail_the_whole_import() {
        // MEDIUM 1: per-record isolation at the document-parse layer. The middle
        // user's `credentials` is the wrong shape (a string, not an array), so it
        // cannot deserialize; it must be reported as a dropped record and skipped
        // while the good users import, never failing the rest.
        let json = r#"{"users":[
            {"id":"u1","username":"alice"},
            {"id":"u2","username":"bad","credentials":"not-an-array"},
            {"id":"u3","username":"carol"}
        ]}"#;
        let mapping = map_realm(json).expect("the top-level document still parses");
        assert_eq!(mapping.users.len(), 3);
        assert!(
            !mapping.users[0].is_dropped(),
            "the first good user imports"
        );
        assert!(!mapping.users[2].is_dropped(), "the last good user imports");
        let bad = &mapping.users[1];
        assert!(bad.is_dropped(), "the malformed user is dropped, not fatal");
        assert_eq!(bad.source_key, "u2", "the dropped record still has a key");
        let MapOutcome::Dropped(reason) = &bad.outcome else {
            panic!("dropped");
        };
        assert!(reason.contains("malformed record"), "{reason}");
    }

    #[test]
    fn out_of_bounds_iterations_import_credential_less_with_a_gap() {
        // MEDIUM 2: the emitted hash is round-tripped through the SAME
        // `ForeignHash::parse` the #55 engine runs at commit. `hashIterations`
        // beyond MAX_PBKDF2_ITERATIONS would be rejected there, so the importer must
        // report a gap and import the user CREDENTIAL-LESS rather than emitting a
        // hash that fails (loses) the whole record at commit.
        let value = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let salt = base64::engine::general_purpose::STANDARD.encode(b"sixteen-byte-slt");
        let json = format!(
            r#"{{"users":[{{"username":"dave","credentials":[{{
                "type":"password",
                "secretData":"{{\"value\":\"{value}\",\"salt\":\"{salt}\"}}",
                "credentialData":"{{\"hashIterations\":20000000,\"algorithm\":\"pbkdf2-sha256\"}}"
            }}]}}]}}"#
        );
        let mapping = map_realm(&json).expect("parse");
        let user = &mapping.users[0];
        let MapOutcome::Mapped(record) = &user.outcome else {
            panic!("the user is mapped, not lost");
        };
        assert!(
            record.password_hash.is_none(),
            "an out-of-bounds hash is never emitted"
        );
        assert!(
            user.gaps
                .iter()
                .any(|g| g.field == "credentials[0]" && g.reason.contains("rejected")),
            "the rejected credential is reported as a gap in the validation-only pass"
        );
    }

    #[test]
    fn credential_sub_fields_are_reported_not_silently_dropped() {
        // MEDIUM 3: nested per-credential sub-fields (for example `priority`) must
        // be reported, not silently dropped.
        let json = r#"{"users":[{"username":"peggy","credentials":[
            {"type":"password","priority":10,"userLabel":"my password"}
        ]}]}"#;
        let mapping = map_realm(json).expect("parse");
        let fields: Vec<&str> = mapping.users[0]
            .gaps
            .iter()
            .map(|g| g.field.as_str())
            .collect();
        assert!(fields.contains(&"credentials[0].priority"), "{fields:?}");
        assert!(fields.contains(&"credentials[0].userLabel"), "{fields:?}");
    }
}
