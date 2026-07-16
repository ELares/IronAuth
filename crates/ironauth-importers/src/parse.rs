// SPDX-License-Identifier: MIT OR Apache-2.0

//! The top-level document parse error shared by every importer.
//!
//! A [`ParseError`] means the WHOLE vendor document could not be read (malformed
//! JSON, a top-level field of the wrong shape, or a missing hash-config parameter
//! Firebase's modified scrypt requires). A per-USER problem is never a parse error:
//! it is reported as a dropped record or a gap in the returned mapping, so a single
//! bad user never fails the import. The message is operator-safe: it carries the
//! serde diagnostic (a field name or JSON position), never a decoded secret.

/// Why a vendor export document could not be parsed at all (issue #57).
#[derive(Debug, Clone)]
pub struct ParseError {
    message: String,
}

impl ParseError {
    /// Build a parse error from an operator-safe message.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Wrap a serde diagnostic (a field name or JSON position, never a secret).
    // Takes the error by value because it is used directly as a `map_err` function
    // item at every call site; a by-reference signature would force a closure at
    // each one for no benefit.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn from_serde(error: serde_json::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }

    /// The operator-safe diagnostic.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

/// A best-effort, non-secret source key for a raw user record that FAILED to
/// deserialize into its typed shape.
///
/// Per-record resilience deserializes each user object individually, so a record
/// the importer cannot parse is reported as a dropped gap rather than failing the
/// whole import. Reporting needs a stable key even for that unparsed record: this
/// reads the first present, non-empty string among `fields` (the vendor id or login
/// handle) directly off the raw JSON value, falling back to the positional
/// `fallback` when none is usable. It never surfaces a secret (the caller passes
/// only identity fields, never a credential).
pub(crate) fn source_key_from_value(
    value: &serde_json::Value,
    fields: &[&str],
    fallback: String,
) -> String {
    for field in fields {
        if let Some(text) = value.get(field).and_then(serde_json::Value::as_str) {
            if !text.is_empty() {
                return text.to_owned();
            }
        }
    }
    fallback
}
