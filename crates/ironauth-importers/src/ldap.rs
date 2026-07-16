// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic LDAP importer (issue #57), the other half of the escape hatch.
//!
//! Accepts a JSON projection of an LDAP directory: an array of entry objects whose
//! keys are LDAP attribute names and whose values are a string or an array of
//! strings. (Parsing raw LDIF text is a documented later extension; a JSON
//! projection keeps this path on the same bounded, malformed-input-safe JSON parser
//! as the other importers.) The `userPassword` value carries an LDAP password
//! scheme, which is re-encoded into the canonical string the #55 scheme layer
//! verifies.
//!
//! # LDAP password schemes
//!
//! | Scheme                       | Handling                                        |
//! |------------------------------|-------------------------------------------------|
//! | `{PBKDF2-SHA256}` / `-SHA512`| re-encoded to a PBKDF2 PHC string (verifiable)  |
//! | `{CRYPT}` / `{ARGON2}`       | the wrapped modular-crypt hash is unwrapped     |
//! | a bare `$2.$` / `$argon2.$` /... | passed through to the scheme layer          |
//! | `{PBKDF2}` (HMAC-SHA1)        | reported as a gap (not a recognized scheme)     |
//! | `{SSHA}` / `{SHA}` / `{MD5}`  | reported as a gap (weak; forces a reset)        |
//!
//! A user whose scheme cannot be represented is imported credential-less with the
//! reason reported, never with a wrong or invented hash.

use serde_json::{Map, Value};

use crate::gap::{Gap, MappedUser, Mapping, Source};
use crate::parse::ParseError;
use crate::phc::{self, Pbkdf2Prf};

/// The LDAP attributes the importer consumes; every other attribute present on an
/// entry is reported as a gap.
const HANDLED: &[&str] = &[
    "dn",
    "uid",
    "cn",
    "sn",
    "givenname",
    "displayname",
    "mail",
    "telephonenumber",
    "userpassword",
];

/// Map an LDAP directory projection (a JSON array of entry objects) into the #55
/// record format plus a per-record gap report (issue #57).
///
/// # Errors
///
/// [`ParseError`] if the document is not a JSON array (or single object) of LDAP
/// entries. A per-entry problem is a dropped record or a gap.
pub fn map_entries(json: &str) -> Result<Mapping, ParseError> {
    let value: Value = serde_json::from_str(json).map_err(ParseError::from_serde)?;
    let entries = match value {
        Value::Array(entries) => entries,
        Value::Object(_) => vec![value],
        _ => {
            return Err(ParseError::new(
                "LDAP document is neither an entry object nor an array of entries",
            ));
        }
    };
    let users = entries.into_iter().enumerate().map(map_entry).collect();
    Ok(Mapping {
        source: Source::Ldap,
        users,
    })
}

/// Map one LDAP entry, accumulating gaps.
fn map_entry((index, entry): (usize, Value)) -> MappedUser {
    let Value::Object(attrs) = entry else {
        return MappedUser::dropped(
            format!("ldap-entry-{index}"),
            "LDAP entry is not a JSON object",
            Vec::new(),
        );
    };
    let dn = first_str(&attrs, "dn");
    let uid = first_str(&attrs, "uid");
    let source_key = dn
        .clone()
        .or_else(|| uid.clone())
        .unwrap_or_else(|| format!("ldap-entry-{index}"));
    let mut gaps = Vec::new();

    let identifier = uid
        .clone()
        .or_else(|| rdn_value(dn.as_deref()))
        .or_else(|| first_str(&attrs, "mail"));
    let Some(identifier) = identifier else {
        return MappedUser::dropped(
            source_key,
            "LDAP entry has no uid, resolvable dn, or mail to use as a login handle",
            gaps,
        );
    };

    let claims = build_claims(&attrs);
    let password_hash = match first_str(&attrs, "userPassword") {
        Some(raw) => map_password(&raw, &mut gaps),
        None => None,
    };
    record_gaps(&attrs, &mut gaps);

    let record = ironauth_import::ImportRecord {
        identifier,
        id: None,
        external_id: dn,
        state: None,
        claims,
        traits: None,
        traits_schema_version: None,
        password_hash,
        credentials: None,
    };
    MappedUser::mapped(source_key, record, gaps)
}

/// Build the OIDC standard-claim document from LDAP attributes.
fn build_claims(attrs: &Map<String, Value>) -> Option<Value> {
    let mut claims = Map::new();
    if let Some(mail) = first_str(attrs, "mail") {
        claims.insert("email".to_owned(), Value::String(mail));
    }
    if let Some(given) = first_str(attrs, "givenName") {
        claims.insert("given_name".to_owned(), Value::String(given));
    }
    if let Some(sn) = first_str(attrs, "sn") {
        claims.insert("family_name".to_owned(), Value::String(sn));
    }
    if let Some(name) = first_str(attrs, "cn").or_else(|| first_str(attrs, "displayName")) {
        claims.insert("name".to_owned(), Value::String(name));
    }
    if let Some(phone) = first_str(attrs, "telephoneNumber") {
        claims.insert("phone_number".to_owned(), Value::String(phone));
    }
    if claims.is_empty() {
        None
    } else {
        Some(Value::Object(claims))
    }
}

/// Re-encode an LDAP `userPassword` value into a canonical hash string, or record a
/// gap when its scheme is not representable.
fn map_password(raw: &str, gaps: &mut Vec<Gap>) -> Option<String> {
    match convert_ldap_scheme(raw) {
        Ok(stored) => match ironauth_import::ForeignHash::parse(&stored) {
            Ok(parsed) => Some(parsed.stored().to_owned()),
            Err(error) => {
                gaps.push(Gap::new(
                    "userPassword",
                    scheme_label(raw),
                    format!("re-encoded hash was rejected by the scheme layer ({error}); the user must reset their password"),
                ));
                None
            }
        },
        Err(reason) => {
            gaps.push(Gap::new("userPassword", scheme_label(raw), reason));
            None
        }
    }
}

/// The non-secret scheme label of an LDAP password value, for gap reporting (never
/// the hash bytes).
fn scheme_label(raw: &str) -> String {
    if let Some(end) = raw.find('}') {
        if raw.starts_with('{') {
            return format!("{} credential", &raw[..=end]);
        }
    }
    "modular-crypt credential".to_owned()
}

/// Convert an LDAP password value to a canonical hash string the scheme layer
/// verifies, or return the reason it cannot be represented.
fn convert_ldap_scheme(raw: &str) -> Result<String, String> {
    // A bare modular-crypt hash with no {SCHEME} prefix: hand straight to the layer.
    if !raw.starts_with('{') {
        return Ok(raw.to_owned());
    }
    let end = raw
        .find('}')
        .ok_or_else(|| "malformed LDAP scheme prefix".to_owned())?;
    let scheme = raw[1..end].to_ascii_uppercase();
    let body = &raw[end + 1..];
    match scheme.as_str() {
        "PBKDF2-SHA256" => convert_ldap_pbkdf2(Pbkdf2Prf::Sha256, body),
        "PBKDF2-SHA512" => convert_ldap_pbkdf2(Pbkdf2Prf::Sha512, body),
        // The wrapped value is itself a modular-crypt hash the scheme layer detects.
        "CRYPT" | "ARGON2" => Ok(body.to_owned()),
        "PBKDF2" => Err(
            "LDAP {PBKDF2} is HMAC-SHA1, not a recognized scheme; the user must reset their password"
                .to_owned(),
        ),
        "SSHA" | "SHA" | "SMD5" | "MD5" => Err(format!(
            "LDAP {{{scheme}}} is a weak SHA1/MD5 scheme that IronAuth declines to import; the user must reset their password"
        )),
        other => Err(format!(
            "LDAP scheme {{{other}}} is not a recognized import scheme; the user must reset their password"
        )),
    }
}

/// Convert a passlib `{PBKDF2-SHA256}<rounds>$<salt_ab64>$<checksum_ab64>` body into
/// a PBKDF2 PHC string.
fn convert_ldap_pbkdf2(prf: Pbkdf2Prf, body: &str) -> Result<String, String> {
    let parts: Vec<&str> = body.split('$').collect();
    if parts.len() != 3 {
        return Err("malformed {PBKDF2-*} value (expected rounds$salt$checksum)".to_owned());
    }
    let rounds: u32 = parts[0]
        .parse()
        .map_err(|_| "{PBKDF2-*} rounds is not a number".to_owned())?;
    let salt = phc::decode_ab64(parts[1]).ok_or("{PBKDF2-*} salt is not adapted base64")?;
    let checksum = phc::decode_ab64(parts[2]).ok_or("{PBKDF2-*} checksum is not adapted base64")?;
    Ok(phc::pbkdf2_phc(prf, rounds, &salt, &checksum))
}

/// The first string value of an attribute (case-insensitive key), whether the value
/// is a string or an array of strings.
fn first_str(attrs: &Map<String, Value>, key: &str) -> Option<String> {
    let value = attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v)?;
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => items.iter().find_map(|v| v.as_str().map(str::to_owned)),
        _ => None,
    }
}

/// The value of the first RDN of a distinguished name, for example
/// `uid=alice,ou=people` -> `alice`.
fn rdn_value(dn: Option<&str>) -> Option<String> {
    let dn = dn?;
    let first = dn.split(',').next()?;
    let (_, value) = first.split_once('=')?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

/// Record a gap for every attribute the importer did not consume.
fn record_gaps(attrs: &Map<String, Value>, gaps: &mut Vec<Gap>) {
    for key in attrs.keys() {
        if HANDLED.contains(&key.to_ascii_lowercase().as_str()) {
            continue;
        }
        gaps.push(Gap::new(
            key.clone(),
            "unmodeled attribute",
            "present in the entry but not consumed by the LDAP importer",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gap::MapOutcome;

    #[test]
    fn a_bare_bcrypt_userpassword_passes_through() {
        let hash = bcrypt::hash_with_result("pw", 4).expect("hash").to_string();
        let json =
            format!(r#"[{{"dn":"uid=al,ou=people,dc=x","uid":"al","userPassword":"{hash}"}}]"#);
        let mapping = map_entries(&json).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        assert_eq!(record.identifier, "al");
        assert_eq!(record.external_id.as_deref(), Some("uid=al,ou=people,dc=x"));
        let stored = record.password_hash.as_deref().expect("hash");
        assert!(
            ironauth_import::ForeignHash::parse(stored)
                .unwrap()
                .verify(b"pw")
        );
    }

    #[test]
    fn ssha_is_reported_as_a_gap_credential_less() {
        let json = r#"[{"uid":"weak","userPassword":"{SSHA}abcdefghdGVzdHNhbHQ="}]"#;
        let mapping = map_entries(json).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        assert!(record.password_hash.is_none());
        assert!(
            mapping.users[0]
                .gaps
                .iter()
                .any(|g| g.field == "userPassword" && g.reason.contains("weak"))
        );
    }

    #[test]
    fn rdn_is_used_when_uid_is_absent() {
        let json = r#"[{"dn":"cn=Bob Smith,ou=people,dc=x","mail":"bob@x.test"}]"#;
        let mapping = map_entries(json).expect("map");
        let MapOutcome::Mapped(record) = &mapping.users[0].outcome else {
            panic!("mapped");
        };
        assert_eq!(record.identifier, "Bob Smith");
    }

    #[test]
    fn unhandled_attributes_are_gaps() {
        let json = r#"[{"uid":"x","objectClass":["inetOrgPerson"],"employeeNumber":"42"}]"#;
        let mapping = map_entries(json).expect("map");
        let fields: Vec<&str> = mapping.users[0]
            .gaps
            .iter()
            .map(|g| g.field.as_str())
            .collect();
        assert!(fields.contains(&"objectClass"));
        assert!(fields.contains(&"employeeNumber"));
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(map_entries("[not json").is_err());
    }
}
