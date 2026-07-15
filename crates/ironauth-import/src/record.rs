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

use serde::Deserialize;

/// One user to import (issue #55): the deserialized shape of a single JSON line.
///
/// The login handle is required; every other field is optional. The foreign
/// `password_hash`, when present, is a canonical algorithm-tagged string
/// ([`crate::scheme`]); a Firebase modified-scrypt hash is serialized with
/// [`crate::scheme::firebase_stored`] before it is placed here.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRecord {
    /// The login handle (unique per scope). Required.
    pub identifier: String,
    /// A caller-supplied `usr_` id to create the user under, or [`None`] to mint a
    /// fresh one. The primary idempotency key: a re-import of the same id is a
    /// no-op, not a duplicate.
    #[serde(default)]
    pub id: Option<String>,
    /// The external correlation id from the tenant's own systems, or [`None`]. A
    /// per-scope unique key, so it is the idempotency key when no id is supplied.
    #[serde(default)]
    pub external_id: Option<String>,
    /// The initial lifecycle state (`active`, `blocked`, `disabled`,
    /// `pending_verification`), or [`None`] for `active`. `scheduled_offboarding` is
    /// not a creatable state and is rejected per-record.
    #[serde(default)]
    pub state: Option<String>,
    /// The user's OIDC standard-claim document, or [`None`] for an empty object.
    /// Stored sealed at rest (issue #48) through the admin create path.
    #[serde(default)]
    pub claims: Option<serde_json::Value>,
    /// The foreign password hash in a canonical algorithm-tagged string, or
    /// [`None`] for a credential-less account. Stored AS-IS and verified on the
    /// user's next login (verify-then-rehash). NEVER a plaintext password.
    #[serde(default)]
    pub password_hash: Option<String>,
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
    fn malformed_and_missing_identifier_are_errors() {
        assert!(parse_record_line("{not json").is_err());
        assert!(parse_record_line(r#"{"id":"usr_x"}"#).is_err());
        // An unknown field is rejected so a typo (for example passwordhash) cannot
        // silently drop a credential.
        assert!(parse_record_line(r#"{"identifier":"a","passwrd":"x"}"#).is_err());
    }
}
