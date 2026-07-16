// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Firebase `auth:export` importer (issue #57).
//!
//! Parses `firebase auth:export` output and re-encodes each user's Firebase
//! modified-scrypt password hash into the canonical `$fbscrypt$` string the scheme
//! layer verifies. Firebase's modified scrypt derives a key with scrypt and then
//! AES-256-CTR encrypts the project's account SIGNER KEY under it, so verification
//! needs the PROJECT-LEVEL parameters (signer key, salt separator, rounds, memory
//! cost) that live OUTSIDE the per-user export: those are supplied through
//! [`FirebaseHashParams`]. An imported user logs in with the original password and
//! is rehashed to Argon2id on first login.
//!
//! # What maps
//!
//! | Firebase field                    | IronAuth target                          |
//! |-----------------------------------|------------------------------------------|
//! | `email` (or `phoneNumber`/`localId`) | `identifier`                          |
//! | `localId`                         | `external_id` (the idempotency key)      |
//! | `emailVerified`, `displayName`, ...| `claims`                                |
//! | `phoneNumber`                     | `claims.phone_number`                    |
//! | `disabled`                        | `state` (`true` -> `disabled`)           |
//! | `customAttributes` (a JSON string)| `traits` (verbatim, unversioned)         |
//! | `passwordHash` + `salt` + params  | `password_hash` (`$fbscrypt$`)           |
//!
//! # What is reported as a gap
//!
//! Social entries in `providerUserInfo` (a linked-identity concept IronAuth does
//! not model), a user with no password provider, a project hash algorithm other
//! than Firebase's SCRYPT, source activity timestamps, and any unconsumed field are
//! reported per record rather than dropped.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::gap::{Gap, MappedUser, Mapping, Source};
use crate::parse::ParseError;

/// The project-level parameters Firebase's modified scrypt needs to verify a hash
/// (issue #57). They live outside the per-user export (in the Firebase console's
/// password-hash parameters or the `hash_config` the Admin SDK / CLI reports), so
/// the operator supplies them once for the whole export.
#[derive(Debug, Clone)]
pub struct FirebaseHashParams {
    /// The project account signer key, base64 (`base64_signer_key`).
    signer_key_b64: String,
    /// The project salt separator, base64 (`base64_salt_separator`).
    salt_separator_b64: String,
    /// The scrypt rounds parameter (`rounds`).
    rounds: u32,
    /// The scrypt memory-cost parameter (`mem_cost`), a `log2(N)`.
    mem_cost: u32,
}

impl FirebaseHashParams {
    /// Build the project parameters directly.
    #[must_use]
    pub fn new(
        signer_key_b64: impl Into<String>,
        salt_separator_b64: impl Into<String>,
        rounds: u32,
        mem_cost: u32,
    ) -> Self {
        Self {
            signer_key_b64: signer_key_b64.into(),
            salt_separator_b64: salt_separator_b64.into(),
            rounds,
            mem_cost,
        }
    }

    /// Parse the project parameters from a Firebase `hash_config` JSON object, the
    /// shape the Admin SDK and CLI report:
    /// `{ "algorithm": "SCRYPT", "base64_signer_key": .., "base64_salt_separator": ..,
    /// "rounds": .., "mem_cost": .. }`.
    ///
    /// # Errors
    ///
    /// [`ParseError`] if the JSON is malformed, a required parameter is missing, or
    /// the `algorithm` is not Firebase's `SCRYPT` (a project that imported hashes
    /// under a different algorithm is not this modified-scrypt path).
    pub fn from_hash_config(json: &str) -> Result<Self, ParseError> {
        #[derive(Deserialize)]
        struct HashConfig {
            #[serde(default)]
            algorithm: Option<String>,
            #[serde(default)]
            base64_signer_key: Option<String>,
            #[serde(default)]
            base64_salt_separator: Option<String>,
            #[serde(default)]
            rounds: Option<u32>,
            #[serde(default)]
            mem_cost: Option<u32>,
        }
        let config: HashConfig = serde_json::from_str(json).map_err(ParseError::from_serde)?;
        if let Some(algorithm) = &config.algorithm {
            if !algorithm.eq_ignore_ascii_case("SCRYPT") {
                return Err(ParseError::new(format!(
                    "hash_config algorithm is '{algorithm}', not Firebase SCRYPT"
                )));
            }
        }
        let signer_key_b64 = config
            .base64_signer_key
            .ok_or_else(|| ParseError::new("hash_config is missing base64_signer_key"))?;
        let salt_separator_b64 = config
            .base64_salt_separator
            .ok_or_else(|| ParseError::new("hash_config is missing base64_salt_separator"))?;
        let rounds = config
            .rounds
            .ok_or_else(|| ParseError::new("hash_config is missing rounds"))?;
        let mem_cost = config
            .mem_cost
            .ok_or_else(|| ParseError::new("hash_config is missing mem_cost"))?;
        Ok(Self {
            signer_key_b64,
            salt_separator_b64,
            rounds,
            mem_cost,
        })
    }
}

/// A Firebase `auth:export` document.
#[derive(Debug, Deserialize)]
struct Export {
    #[serde(default)]
    users: Vec<FbUser>,
}

/// One Firebase user. Named fields are handled explicitly; anything else lands in
/// `extra` and is reported as a gap.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FbUser {
    #[serde(default)]
    local_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    photo_url: Option<String>,
    #[serde(default)]
    phone_number: Option<String>,
    #[serde(default)]
    password_hash: Option<String>,
    #[serde(default)]
    salt: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
    #[serde(default)]
    custom_attributes: Option<String>,
    #[serde(default)]
    provider_user_info: Vec<FbProvider>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    last_login_at: Option<String>,
    #[serde(default)]
    valid_since: Option<String>,
    /// Every field the importer does not name: reported as a gap.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// One `providerUserInfo` entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FbProvider {
    #[serde(default)]
    provider_id: Option<String>,
}

/// Map a Firebase `auth:export` document into the #55 record format plus a
/// per-record gap report (issue #57), verifying each password hash against the
/// supplied project parameters.
///
/// # Errors
///
/// [`ParseError`] if the top-level document is not a well-formed Firebase export. A
/// per-user problem is a dropped record or a gap, never a whole-import failure.
pub fn map_export(json: &str, params: &FirebaseHashParams) -> Result<Mapping, ParseError> {
    let export: Export = serde_json::from_str(json).map_err(ParseError::from_serde)?;
    let users = export
        .users
        .into_iter()
        .enumerate()
        .map(|(index, user)| map_user(index, user, params))
        .collect();
    Ok(Mapping {
        source: Source::Firebase,
        users,
    })
}

/// Map one Firebase user, re-encoding its modified-scrypt hash and accumulating
/// gaps.
fn map_user(index: usize, user: FbUser, params: &FirebaseHashParams) -> MappedUser {
    let source_key = user
        .local_id
        .clone()
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| format!("firebase-user-{index}"));
    let mut gaps = Vec::new();

    let identifier = user
        .email
        .clone()
        .or_else(|| user.phone_number.clone())
        .or_else(|| user.local_id.clone());
    let Some(identifier) = identifier else {
        return MappedUser::dropped(
            source_key,
            "firebase user has no email, phone number, or localId to use as a login handle",
            gaps,
        );
    };

    let claims = build_claims(&user);
    let state = match user.disabled {
        Some(true) => Some("disabled".to_owned()),
        _ => None,
    };
    let password_hash = map_password(&user, params, &mut gaps);
    let traits = build_traits(&user, &mut gaps);
    record_gaps(&user, &mut gaps);

    let record = ironauth_import::ImportRecord {
        identifier,
        id: None,
        // Move the id out (rather than clone) so this fn genuinely consumes `user`.
        external_id: user.local_id,
        state,
        claims,
        traits,
        traits_schema_version: None,
        password_hash,
        credentials: None,
    };
    MappedUser::mapped(source_key, record, gaps)
}

/// Build the OIDC standard-claim document from a Firebase profile.
fn build_claims(user: &FbUser) -> Option<Value> {
    let mut claims = Map::new();
    if let Some(email) = &user.email {
        claims.insert("email".to_owned(), Value::String(email.clone()));
    }
    if let Some(verified) = user.email_verified {
        claims.insert("email_verified".to_owned(), Value::Bool(verified));
    }
    if let Some(name) = &user.display_name {
        claims.insert("name".to_owned(), Value::String(name.clone()));
    }
    if let Some(photo) = &user.photo_url {
        claims.insert("picture".to_owned(), Value::String(photo.clone()));
    }
    if let Some(phone) = &user.phone_number {
        claims.insert("phone_number".to_owned(), Value::String(phone.clone()));
        // A Firebase phone identifier is a verified phone provider by construction.
        let phone_verified = user
            .provider_user_info
            .iter()
            .any(|p| p.provider_id.as_deref() == Some("phone"));
        if phone_verified {
            claims.insert("phone_number_verified".to_owned(), Value::Bool(true));
        }
    }
    if claims.is_empty() {
        None
    } else {
        Some(Value::Object(claims))
    }
}

/// Re-encode the user's Firebase modified-scrypt hash into the canonical
/// `$fbscrypt$` string, or record a gap when there is no password provider.
fn map_password(user: &FbUser, params: &FirebaseHashParams, gaps: &mut Vec<Gap>) -> Option<String> {
    let (Some(hash_b64), Some(salt_b64)) = (&user.password_hash, &user.salt) else {
        gaps.push(Gap::new(
            "passwordHash",
            "no password hash (social or phone-only user)",
            "the user has no password credential to import; they sign in via their provider or reset their password",
        ));
        return None;
    };
    let stored = ironauth_import::scheme::firebase_stored(
        params.mem_cost,
        params.rounds,
        &params.salt_separator_b64,
        &params.signer_key_b64,
        salt_b64,
        hash_b64,
    );
    match ironauth_import::ForeignHash::parse(&stored) {
        Ok(parsed) => Some(parsed.stored().to_owned()),
        Err(error) => {
            gaps.push(Gap::new(
                "passwordHash",
                "firebase modified-scrypt hash",
                format!("the hash or project parameters are out of bounds or malformed ({error}); the user must reset their password"),
            ));
            None
        }
    }
}

/// Parse the `customAttributes` JSON string into a traits document; a
/// non-object or malformed value is reported as a gap rather than dropped.
fn build_traits(user: &FbUser, gaps: &mut Vec<Gap>) -> Option<Value> {
    let raw = user.custom_attributes.as_deref()?;
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) if !map.is_empty() => Some(Value::Object(map)),
        Ok(_) => None,
        Err(_) => {
            gaps.push(Gap::new(
                "customAttributes",
                "custom attributes",
                "the customAttributes value is not a JSON object and was not imported as traits",
            ));
            None
        }
    }
}

/// Record a gap for every social provider and unconsumed field.
fn record_gaps(user: &FbUser, gaps: &mut Vec<Gap>) {
    let social: Vec<&str> = user
        .provider_user_info
        .iter()
        .filter_map(|p| p.provider_id.as_deref())
        .filter(|id| *id != "password" && *id != "phone")
        .collect();
    if !social.is_empty() {
        gaps.push(Gap::new(
            "providerUserInfo",
            format!("linked providers: {}", social.join(", ")),
            "social/federated linked identities are not represented; only the password login is imported",
        ));
    }
    for (field, present) in [
        ("createdAt", user.created_at.is_some()),
        ("lastLoginAt", user.last_login_at.is_some()),
        ("validSince", user.valid_since.is_some()),
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
            "present in the export but not consumed by the Firebase importer",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gap::MapOutcome;

    /// The published Firebase modified-scrypt vector's project parameters (password
    /// `user1password`). See `ironauth-import`'s scheme KAT.
    fn published_params() -> FirebaseHashParams {
        FirebaseHashParams::new(
            "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
            "Bw==",
            8,
            14,
        )
    }

    #[test]
    fn the_published_vector_verifies_through_the_importer() {
        let json = r#"{"users":[{
            "localId":"uid1","email":"user1@x.test","emailVerified":true,
            "passwordHash":"lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==",
            "salt":"42xEC+ixf3L2lw=="
        }]}"#;
        let mapping = map_export(json, &published_params()).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        let stored = record.password_hash.as_deref().expect("hash");
        let parsed = ironauth_import::ForeignHash::parse(stored).expect("parse");
        assert_eq!(parsed.tag(), "firebase-scrypt");
        assert!(
            parsed.verify(b"user1password"),
            "the original password verifies"
        );
        assert!(!parsed.verify(b"wrong"));
    }

    #[test]
    fn a_social_only_user_is_credential_less_with_gaps() {
        let json = r#"{"users":[{
            "localId":"uid2","email":"g@x.test",
            "providerUserInfo":[{"providerId":"google.com"}]
        }]}"#;
        let mapping = map_export(json, &published_params()).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        assert!(record.password_hash.is_none());
        let fields: Vec<&str> = mapping.users[0]
            .gaps
            .iter()
            .map(|g| g.field.as_str())
            .collect();
        assert!(fields.contains(&"passwordHash"));
        assert!(fields.contains(&"providerUserInfo"));
    }

    #[test]
    fn hash_config_rejects_a_non_scrypt_algorithm() {
        let config = r#"{"algorithm":"BCRYPT","base64_signer_key":"a","base64_salt_separator":"b","rounds":8,"mem_cost":14}"#;
        assert!(FirebaseHashParams::from_hash_config(config).is_err());
    }

    #[test]
    fn hash_config_parses_scrypt() {
        let config = r#"{"algorithm":"SCRYPT","base64_signer_key":"a","base64_salt_separator":"Bw==","rounds":8,"mem_cost":14}"#;
        assert!(FirebaseHashParams::from_hash_config(config).is_ok());
    }
}
