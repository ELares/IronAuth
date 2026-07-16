// SPDX-License-Identifier: MIT OR Apache-2.0

//! The line-delimited import record format (issue #55).
//!
//! Import input is a stream of newline-delimited JSON objects, one user per line.
//! The format is deliberately streaming-parseable: a 100k-user dataset is consumed
//! one line at a time, so the engine never holds more than a single record in
//! memory. [`parse_record_line`] parses one line; the [`crate::engine`] drives the
//! iteration.
//!
//! Each record carries the identity the admin create path (issue #52) needs: the
//! login handle, an optional caller-supplied id and external id (the idempotency
//! keys), an optional lifecycle state, an optional standard-claim document, and an
//! optional algorithm-tagged foreign password hash. A record with no hash creates a
//! credential-less account (it cannot log in until a credential is set); a record
//! WITH a hash imports it verbatim for the verify-then-rehash login path.

use core::fmt;

use serde::{Deserialize, Serialize};

/// One user to import (issue #55): the (de)serialized shape of a single JSON line.
///
/// The login handle is required; every other field is optional. The foreign
/// `password_hash`, when present, is a canonical algorithm-tagged string
/// ([`crate::scheme`]); a Firebase modified-scrypt hash is serialized with
/// [`crate::scheme::firebase_stored`] before it is placed here.
///
/// The SAME shape is what the full identity EXPORT (issue #58) SERIALIZES, so
/// export-to-import round-trips by construction: [`to_record_line`] writes exactly
/// what [`parse_record_line`] reads. Serialization SKIPS an absent optional field
/// (so a minimal record is one JSON key), and the shape stays
/// `deny_unknown_fields`, so a typo in a hand-written line is rejected rather than
/// silently dropping a credential.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRecord {
    /// The login handle (unique per scope). Required.
    pub identifier: String,
    /// A caller-supplied `usr_` id to create the user under, or [`None`] to mint a
    /// fresh one. The primary idempotency key: a re-import of the same id is a
    /// no-op, not a duplicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The external correlation id from the tenant's own systems, or [`None`]. A
    /// per-scope unique key, so it is the idempotency key when no id is supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The initial lifecycle state (`active`, `blocked`, `disabled`,
    /// `pending_verification`), or [`None`] for `active`. `scheduled_offboarding` is
    /// not a creatable state and is rejected per-record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The user's OIDC standard-claim document, or [`None`] for an empty object.
    /// Stored sealed at rest (issue #48) through the admin create path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
    /// The user's identity-traits document (issue #53), or [`None`] for a user with
    /// no traits. Sealed at rest through the admin create path, verbatim: an import
    /// restores the traits that already validated in the source instance as-is (issue
    /// #58), so a round-trip is lossless even into a fresh scope with no active
    /// schema. Must be a JSON object when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traits: Option<serde_json::Value>,
    /// The trait-schema version the `traits` document was last validated against in
    /// the source instance (issue #58), preserved verbatim, or [`None`] when there
    /// are no traits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traits_schema_version: Option<i32>,
    /// The password hash in a canonical algorithm-tagged string, or [`None`] for a
    /// credential-less account. Stored AS-IS and verified on the user's next login
    /// (verify-then-rehash). NEVER a plaintext password. A native Argon2id hash and a
    /// foreign hash are BOTH carried here (the login path verifies either), which is
    /// why a full export (issue #58) round-trips a native credential losslessly: the
    /// exported Argon2id string re-imports through the same foreign-verify-then-rehash
    /// path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// The user's enrolled MFA / login credentials (issue #58/#61): every passkey,
    /// TOTP, or recovery-code enrollment the account holds, restored so the exit
    /// export carries the credential REGISTRY, not merely the password. Absent (the
    /// common case) when the user has enrolled none. When the M7 factor issues add the
    /// concrete secret material (a TOTP seed, a passkey public key), it rides
    /// [`ImportCredential`] as additional fields, a purely additive change that the
    /// generalized field-coverage guard forces to be covered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<ImportCredential>>,
    /// The user's enrolled TOTP authenticators (issue #58/#69): each carries the RFC
    /// 6238 SEED the export opened (Base32), the parameters, the friendly name, the
    /// status, and the single-use step, so a re-imported factor verifies against the
    /// ORIGINAL authenticator (a TOTP seed is a portable shared secret, unlike a
    /// passkey). Absent when the user has enrolled no authenticator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<Vec<ImportTotp>>,
    /// The user's one-time recovery codes (issue #58/#69): each carries the one-way
    /// Argon2id HASH (verbatim, exactly like a password verifier, so the code stays
    /// redeemable) and its consumed state. Absent when the user has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<ImportRecoveryCode>>,
}

/// One enrolled TOTP authenticator to restore alongside a user (issue #58/#69): the
/// (de)serialized shape the full identity export writes for each `totp_credentials`
/// row. The SEED is the covenant secret (a long-lived shared secret, re-sealed under
/// the destination DEK at import); the internal `tot_` id, subject, scope, and key
/// version are re-minted / re-sealed against the destination.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportTotp {
    /// The RFC 6238 shared secret, Base32-encoded (the form the export emits and a
    /// fresh instance re-seals). SECRET material, never a plaintext-at-rest column.
    pub seed_base32: String,
    /// The RFC 6238 hash token (`SHA1`, `SHA256`, `SHA512`).
    pub algorithm: String,
    /// The number of decimal digits (6..=8).
    pub digits: i32,
    /// The time-step period in seconds (15..=60).
    pub period_secs: i32,
    /// The user-authored friendly name (1 to 200 characters), sealed at rest under
    /// the destination scope's DEK through the restore path.
    pub friendly_name: String,
    /// The enrollment status (`active` or `pending`), reproduced verbatim.
    pub status: String,
    /// The last time-step a verification consumed (the single-use spine), preserved
    /// so a re-imported factor keeps its anti-replay position, or [`None`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_consumed_step: Option<i64>,
}

impl fmt::Debug for ImportTotp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The seed and the friendly name are secret / PII; render only parameters.
        f.debug_struct("ImportTotp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period_secs", &self.period_secs)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// One one-time recovery code to restore alongside a user (issue #58/#69): the
/// (de)serialized shape the export writes for each `recovery_codes` row. The
/// `code_hash` is a one-way Argon2id verifier (never a plaintext code), carried
/// verbatim exactly like a password hash, so a still-unconsumed code stays redeemable
/// after import. The internal `rvc_` id, subject, and scope are re-minted.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRecoveryCode {
    /// The Argon2id PHC verifier of the code. One-way, never the plaintext code.
    pub code_hash: String,
    /// Whether the code was already redeemed in the source instance (single-use state).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub consumed: bool,
}

/// One enrolled credential to restore alongside a user (issue #58/#61): the
/// (de)serialized shape the full identity export writes for each row of the
/// `account_credentials` registry. The internal `crd_` id, the owning subject, the
/// scope, and the sealing key version are NOT carried (re-minted / re-sealed against
/// the destination), and `usable_for_login` is re-derived from `credential_type` at
/// enrollment, so a credential is a small, additive record: `credential_type`, the
/// friendly name, and an optional last-used instant.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportCredential {
    /// The factor kind (`passkey`, `totp`, `recovery_code`). A value outside the
    /// closed set fails the record, never silently drops the credential.
    pub credential_type: String,
    /// The user-authored friendly name (1 to 200 characters). Sealed at rest under
    /// the destination scope's DEK through the restore path.
    pub friendly_name: String,
    /// When the factor was last used to authenticate in the source instance, in
    /// microseconds since the Unix epoch, or [`None`] if it never was. Preserved
    /// verbatim so the credential registry round-trips losslessly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<i64>,
}

/// Serialize one [`ImportRecord`] into a single line of the import format (issue
/// #58): the exact bytes [`parse_record_line`] consumes, with no trailing newline
/// (the caller joins records with `\n`). This is the export side of the covenant;
/// pairing it with [`parse_record_line`] makes export-to-import lossless by
/// construction.
///
/// # Errors
///
/// [`serde_json::Error`] only if the record cannot be serialized, which for this
/// concrete shape (strings, optional strings, JSON objects, and integers) does not
/// occur in practice; it is surfaced rather than unwrapped so the export path
/// stays panic-free.
pub fn to_record_line(record: &ImportRecord) -> Result<String, serde_json::Error> {
    serde_json::to_string(record)
}

impl ImportRecord {
    /// The stable identity a per-record error is reported against and a duplicate is
    /// keyed on: the caller-supplied id if present, else the external id, else the
    /// login handle. Never a secret.
    #[must_use]
    pub fn record_key(&self) -> &str {
        self.id
            .as_deref()
            .or(self.external_id.as_deref())
            .unwrap_or(&self.identifier)
    }
}

/// Why a single import line could not be parsed (issue #55).
#[derive(Debug, Clone)]
pub struct RecordParseError {
    /// An operator-safe message. It carries the serde parse diagnostic (field name
    /// or JSON position), never a decoded secret value.
    message: String,
}

impl RecordParseError {
    /// The operator-safe parse diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for RecordParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RecordParseError {}

/// Parse a single line of the import format into an [`ImportRecord`].
///
/// A blank or whitespace-only line yields [`None`] (a benign separator, skipped by
/// the engine). A non-blank line that is not a valid record is an error the engine
/// reports and moves past, never a batch abort.
///
/// # Errors
///
/// [`RecordParseError`] if the line is non-blank but not a well-formed import
/// record (malformed JSON, a missing `identifier`, or an unknown field).
pub fn parse_record_line(line: &str) -> Result<Option<ImportRecord>, RecordParseError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    serde_json::from_str::<ImportRecord>(trimmed)
        .map(Some)
        .map_err(|error| RecordParseError {
            message: error.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_record() {
        let line = r#"{"identifier":"a@b.test","id":"usr_x","external_id":"crm-1","state":"active","claims":{"email":"a@b.test"},"password_hash":"$2b$10$abc"}"#;
        let record = parse_record_line(line).expect("parse").expect("some");
        assert_eq!(record.identifier, "a@b.test");
        assert_eq!(record.id.as_deref(), Some("usr_x"));
        assert_eq!(record.external_id.as_deref(), Some("crm-1"));
        assert_eq!(record.password_hash.as_deref(), Some("$2b$10$abc"));
        assert_eq!(record.record_key(), "usr_x");
    }

    #[test]
    fn record_key_falls_back_from_id_to_external_to_identifier() {
        let only_ext = parse_record_line(r#"{"identifier":"a","external_id":"e"}"#)
            .expect("parse")
            .expect("some");
        assert_eq!(only_ext.record_key(), "e");
        let only_id = parse_record_line(r#"{"identifier":"a"}"#)
            .expect("parse")
            .expect("some");
        assert_eq!(only_id.record_key(), "a");
    }

    #[test]
    fn blank_lines_are_skipped() {
        assert!(parse_record_line("").expect("parse").is_none());
        assert!(parse_record_line("   \t ").expect("parse").is_none());
    }

    #[test]
    fn credentials_round_trip_through_to_record_line_and_back() {
        // A record carrying an enrolled credential registry serializes and re-parses
        // symmetrically (issue #58): to_record_line writes exactly what
        // parse_record_line reads, so the exit export round-trips the registry.
        let record = ImportRecord {
            identifier: "gina@b.test".to_owned(),
            id: None,
            external_id: None,
            state: None,
            claims: None,
            traits: None,
            traits_schema_version: None,
            password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".to_owned()),
            credentials: Some(vec![
                ImportCredential {
                    credential_type: "passkey".to_owned(),
                    friendly_name: "my laptop".to_owned(),
                    last_used_at: None,
                },
                ImportCredential {
                    credential_type: "totp".to_owned(),
                    friendly_name: "authenticator".to_owned(),
                    last_used_at: Some(1_710_000_000_000_000),
                },
            ]),
            totp: None,
            recovery_codes: None,
        };
        let line = to_record_line(&record).expect("serialize");
        let parsed = parse_record_line(&line).expect("parse").expect("some");
        let credentials = parsed.credentials.expect("credentials preserved");
        assert_eq!(credentials.len(), 2);
        assert_eq!(credentials[0].credential_type, "passkey");
        assert_eq!(credentials[0].friendly_name, "my laptop");
        assert_eq!(credentials[1].credential_type, "totp");
        assert_eq!(credentials[1].last_used_at, Some(1_710_000_000_000_000));
    }

    #[test]
    fn totp_and_recovery_codes_round_trip_through_to_record_line_and_back() {
        // The SECOND FACTOR round-trips (issue #58/#69): the exported seed, parameters,
        // status, single-use step, and the recovery-code hashes serialize and re-parse
        // symmetrically, so the emitted bytes carry a factor that re-imports and
        // verifies, not a metadata echo. This is the byte-level guard the original
        // false-positive (asserting on an in-memory struct) lacked.
        let record = ImportRecord {
            identifier: "erin@b.test".to_owned(),
            id: None,
            external_id: None,
            state: None,
            claims: None,
            traits: None,
            traits_schema_version: None,
            password_hash: None,
            credentials: None,
            totp: Some(vec![ImportTotp {
                seed_base32: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned(),
                algorithm: "SHA1".to_owned(),
                digits: 6,
                period_secs: 30,
                friendly_name: "my phone".to_owned(),
                status: "active".to_owned(),
                last_consumed_step: Some(100),
            }]),
            recovery_codes: Some(vec![
                ImportRecoveryCode {
                    code_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g".to_owned(),
                    consumed: false,
                },
                ImportRecoveryCode {
                    code_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$b3RoZXJoYXNo".to_owned(),
                    consumed: true,
                },
            ]),
        };
        let line = to_record_line(&record).expect("serialize");
        // The EMITTED bytes carry the seed and the hashes (not merely the in-memory
        // struct): exactly what the export bug silently dropped.
        assert!(
            line.contains("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            "the emitted line carries the opened TOTP seed: {line}"
        );
        assert!(
            line.contains("aGFzaGhhc2g"),
            "the emitted line carries the recovery-code hash: {line}"
        );
        let parsed = parse_record_line(&line).expect("parse").expect("some");
        let totp = parsed.totp.expect("totp preserved");
        assert_eq!(totp.len(), 1);
        assert_eq!(totp[0].seed_base32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(totp[0].algorithm, "SHA1");
        assert_eq!(totp[0].digits, 6);
        assert_eq!(totp[0].period_secs, 30);
        assert_eq!(totp[0].status, "active");
        assert_eq!(totp[0].last_consumed_step, Some(100));
        let codes = parsed.recovery_codes.expect("recovery codes preserved");
        assert_eq!(codes.len(), 2);
        assert!(codes[0].code_hash.starts_with("$argon2"));
        assert!(!codes[0].consumed);
        assert!(codes[1].consumed);
    }

    #[test]
    fn an_unknown_credential_field_is_rejected() {
        // deny_unknown_fields on the nested credential shape: a typo cannot silently
        // drop a credential's data.
        assert!(
            parse_record_line(
                r#"{"identifier":"a","credentials":[{"credential_type":"totp","friendly_name":"x","lastused":1}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_and_missing_identifier_are_errors() {
        assert!(parse_record_line("{not json").is_err());
        assert!(parse_record_line(r#"{"id":"usr_x"}"#).is_err());
        // An unknown field is rejected so a typo (for example passwordhash) cannot
        // silently drop a credential.
        assert!(parse_record_line(r#"{"identifier":"a","passwrd":"x"}"#).is_err());
    }
}
