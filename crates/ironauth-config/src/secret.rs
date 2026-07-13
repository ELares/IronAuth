// SPDX-License-Identifier: MIT OR Apache-2.0

//! Secret indirection: config fields that hold sensitive values.
//!
//! A [`Secret`] names where a sensitive value lives; it is not the value.
//! Three forms deserialize from TOML: a literal string (discouraged outside
//! dev mode; `Config::load` collects a [`crate::Warning`] for it), a
//! `{ file = "/path" }` indirection, and an `{ env = "VAR" }` indirection.
//! Resolution happens explicitly via [`Secret::resolve`], which yields a
//! [`SecretString`].
//!
//! Redaction invariant: a secret VALUE never appears in `Debug`, `Display`,
//! serialization, or any error produced by this module. The file path or env
//! var NAME may appear (operators need it to fix a broken indirection); the
//! value may not, which is why `Debug` and `Serialize` are hand-written
//! instead of derived.

use std::fmt;
use std::path::PathBuf;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

/// The placeholder emitted wherever a secret value would otherwise print.
pub const REDACTED: &str = "[redacted]";

/// Where a secret value lives. See the module docs for the three forms.
#[derive(Clone, PartialEq, Eq)]
pub enum Secret {
    /// The value inline in the config file. Discouraged: config files get
    /// committed, copied, and pasted into tickets. `Config::load` flags this
    /// form unless `dev_mode` is set.
    Literal(SecretString),
    /// The value is the contents of this file, with one trailing newline
    /// trimmed (the shape `echo secret > file` produces).
    File(PathBuf),
    /// The value is in this environment variable.
    Env(String),
}

impl Secret {
    /// Whether this secret uses the discouraged literal form.
    #[must_use]
    pub fn is_literal(&self) -> bool {
        matches!(self, Secret::Literal(_))
    }

    /// Read the secret value from its source.
    ///
    /// The file form trims a single trailing newline (`\n` or `\r\n`); any
    /// other whitespace is preserved because it may be part of the value.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError`] naming the unreadable path or the missing env
    /// var. The error never carries any part of a secret value.
    pub fn resolve(&self) -> Result<SecretString, SecretError> {
        match self {
            Secret::Literal(value) => Ok(value.clone()),
            Secret::File(path) => match std::fs::read_to_string(path) {
                Ok(contents) => Ok(SecretString::new(trim_one_trailing_newline(&contents))),
                Err(source) => Err(SecretError::FileRead {
                    path: path.clone(),
                    source,
                }),
            },
            Secret::Env(var) => match std::env::var(var) {
                Ok(value) => Ok(SecretString::new(value)),
                // The NotUnicode payload would carry the (lossy) value; map
                // both failure modes to an error that names only the var.
                Err(std::env::VarError::NotPresent) => {
                    Err(SecretError::EnvMissing { var: var.clone() })
                }
                Err(std::env::VarError::NotUnicode(_)) => {
                    Err(SecretError::EnvNotUnicode { var: var.clone() })
                }
            },
        }
    }
}

/// Strip exactly one trailing `\n` or `\r\n`, if present.
fn trim_one_trailing_newline(s: &str) -> String {
    let s = s.strip_suffix('\n').unwrap_or(s);
    let s = s.strip_suffix('\r').unwrap_or(s);
    s.to_owned()
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The source form is diagnostic (which file, which var); the literal
        // value is not.
        match self {
            Secret::Literal(_) => write!(f, "Secret::Literal({REDACTED})"),
            Secret::File(path) => f.debug_tuple("Secret::File").field(path).finish(),
            Secret::Env(var) => f.debug_tuple("Secret::Env").field(var).finish(),
        }
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Config dumps stay useful: the indirection forms round-trip, the
        // literal form degrades to the placeholder.
        match self {
            Secret::Literal(_) => serializer.serialize_str(REDACTED),
            Secret::File(path) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("file", path)?;
                map.end()
            }
            Secret::Env(var) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("env", var)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(SecretVisitor)
    }
}

/// Hand-written visitor instead of an untagged enum so a malformed secret
/// fails with the accepted forms spelled out (untagged enums report only
/// "did not match any variant") and so the strictness rule (exactly one of
/// `file` or `env`) is explicit.
struct SecretVisitor;

const SECRET_FORMS: &str =
    "a literal string (discouraged), { file = \"/path\" }, or { env = \"VAR_NAME\" }";

impl<'de> Visitor<'de> for SecretVisitor {
    type Value = Secret;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a secret: {SECRET_FORMS}")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Secret, E> {
        Ok(Secret::Literal(SecretString::new(value)))
    }

    // Non-string scalars are rejected by TYPE only. serde's default fallbacks
    // would echo the value into the error (a bare numeric PIN or token would
    // then land in startup logs), so each scalar form is handled explicitly
    // and names the type without the value.
    fn visit_bool<E: de::Error>(self, _value: bool) -> Result<Secret, E> {
        Err(de::Error::custom(format!(
            "a boolean is not a secret; expected {SECRET_FORMS}"
        )))
    }

    fn visit_i64<E: de::Error>(self, _value: i64) -> Result<Secret, E> {
        Err(de::Error::custom(format!(
            "a number is not a secret; quote it to use a literal, or expected {SECRET_FORMS}"
        )))
    }

    fn visit_u64<E: de::Error>(self, _value: u64) -> Result<Secret, E> {
        Err(de::Error::custom(format!(
            "a number is not a secret; quote it to use a literal, or expected {SECRET_FORMS}"
        )))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Secret, E> {
        Err(de::Error::custom(format!(
            "a number is not a secret; quote it to use a literal, or expected {SECRET_FORMS}"
        )))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Secret, A::Error> {
        let Some(key) = map.next_key::<String>()? else {
            return Err(de::Error::custom(format!(
                "empty table is not a secret; expected {SECRET_FORMS}"
            )));
        };
        let secret = match key.as_str() {
            "file" => Secret::File(map.next_value::<PathBuf>()?),
            "env" => Secret::Env(map.next_value::<String>()?),
            other => {
                return Err(de::Error::unknown_field(other, &["file", "env"]));
            }
        };
        if let Some(extra) = map.next_key::<String>()? {
            return Err(de::Error::custom(format!(
                "secret takes exactly one of `file` or `env`, found extra key `{extra}`"
            )));
        }
        Ok(secret)
    }
}

impl JsonSchema for Secret {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Secret")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::Secret"))
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A secret value by indirection: the contents of a file ({ file = \"/path\" }), an environment variable ({ env = \"VAR_NAME\" }), or a literal string (discouraged; flagged outside dev mode).",
            "oneOf": [
                {
                    "type": "string",
                    "description": "Literal secret value. Discouraged outside dev mode."
                },
                {
                    "type": "object",
                    "properties": {
                        "file": {
                            "type": "string",
                            "description": "Path to a file whose contents are the secret; one trailing newline is trimmed."
                        }
                    },
                    "required": ["file"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "env": {
                            "type": "string",
                            "description": "Name of the environment variable holding the secret."
                        }
                    },
                    "required": ["env"],
                    "additionalProperties": false
                }
            ]
        })
    }
}

/// A resolved secret value.
///
/// Wraps the value so it cannot leak through `Debug`, `Display`, or
/// serialization; code that genuinely needs the value calls
/// [`SecretString::expose`] and owns the consequences at that call site.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a resolved value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The actual secret value. Every call site is a deliberate exposure
    /// point; never pass the result to logging or error formatting.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString({REDACTED})")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Failure to resolve a [`Secret`]. Never carries any part of a secret value.
#[derive(Debug)]
pub enum SecretError {
    /// The file form pointed at an unreadable path.
    FileRead {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The env form named a variable that is not set.
    EnvMissing {
        /// The variable that was not set.
        var: String,
    },
    /// The env form named a variable whose value is not valid UTF-8.
    EnvNotUnicode {
        /// The variable with the non-UTF-8 value.
        var: String,
    },
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::FileRead { path, source } => {
                write!(
                    f,
                    "cannot read secret from file '{}': {source}",
                    path.display()
                )
            }
            SecretError::EnvMissing { var } => {
                write!(
                    f,
                    "cannot read secret: environment variable '{var}' is not set"
                )
            }
            SecretError::EnvNotUnicode { var } => {
                write!(
                    f,
                    "cannot read secret: environment variable '{var}' is not valid UTF-8"
                )
            }
        }
    }
}

impl std::error::Error for SecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SecretError::FileRead { source, .. } => Some(source),
            SecretError::EnvMissing { .. } | SecretError::EnvNotUnicode { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_form_deserializes_and_is_flagged() {
        let secret: Secret = toml::from_str::<TestWrap>("s = \"hunter2\"")
            .expect("parses")
            .s;
        assert!(secret.is_literal());
        assert_eq!(secret.resolve().expect("resolves").expose(), "hunter2");
    }

    #[test]
    fn env_form_resolves_from_the_environment() {
        // PATH is guaranteed present in any test environment; asserting
        // equality with std::env avoids mutating the process environment
        // (std::env::set_var is unsafe under edition 2024).
        let secret: Secret = toml::from_str::<TestWrap>("s = { env = \"PATH\" }")
            .expect("parses")
            .s;
        assert!(!secret.is_literal());
        let resolved = secret.resolve().expect("PATH is set");
        assert_eq!(resolved.expose(), std::env::var("PATH").expect("PATH"));
    }

    #[test]
    fn env_form_missing_var_names_the_var_only() {
        let secret = Secret::Env("IRONAUTH_TEST_DEFINITELY_UNSET_VAR".to_owned());
        let err = secret.resolve().expect_err("var is unset");
        let msg = err.to_string();
        assert!(msg.contains("IRONAUTH_TEST_DEFINITELY_UNSET_VAR"), "{msg}");
    }

    #[test]
    fn malformed_secret_table_lists_the_accepted_forms() {
        let err = toml::from_str::<TestWrap>("s = { fille = \"/x\" }").expect_err("unknown key");
        let msg = err.to_string();
        assert!(msg.contains("fille"), "{msg}");
        assert!(msg.contains("file") && msg.contains("env"), "{msg}");

        let err =
            toml::from_str::<TestWrap>("s = { file = \"/x\", env = \"Y\" }").expect_err("both");
        assert!(err.to_string().contains("exactly one"), "{err}");
    }

    #[test]
    fn debug_display_serialize_redact_the_literal_value() {
        let secret = Secret::Literal(SecretString::new("hunter2"));
        for rendered in [
            format!("{secret:?}"),
            format!("{secret}"),
            toml::to_string(&TestWrap { s: secret.clone() }).expect("serializes"),
        ] {
            assert!(!rendered.contains("hunter2"), "leak: {rendered}");
            assert!(rendered.contains(REDACTED), "no placeholder: {rendered}");
        }

        let resolved = secret.resolve().expect("literal resolves");
        assert!(!format!("{resolved:?}").contains("hunter2"));
        assert!(!format!("{resolved}").contains("hunter2"));
    }

    #[test]
    fn non_string_secret_literal_is_rejected_by_type_without_echoing_value() {
        // An unquoted numeric PIN or a bool must fail by type only. The
        // surface that matters is `Error::message()`, which is exactly what
        // the loader retains (see Config::from_str); toml's full-line source
        // snippet is dropped there, and the visitor message must not add the
        // value back. Asserting on `.message()` mirrors the real log surface.
        for (toml_src, sentinel) in [
            ("s = 314159265358979", "314159265358979"),
            ("s = 3.14159265", "3.14159265"),
            ("s = true", "true"),
        ] {
            let err = toml::from_str::<TestWrap>(toml_src).expect_err(toml_src);
            let retained = err.message();
            assert!(!retained.contains(sentinel), "value echoed: {retained}");
            assert!(
                retained.contains("secret")
                    || retained.contains("number")
                    || retained.contains("boolean"),
                "unhelpful message: {retained}"
            );
        }
    }

    #[test]
    fn file_form_trims_exactly_one_trailing_newline() {
        assert_eq!(trim_one_trailing_newline("abc\n"), "abc");
        assert_eq!(trim_one_trailing_newline("abc\r\n"), "abc");
        assert_eq!(trim_one_trailing_newline("abc\n\n"), "abc\n");
        assert_eq!(trim_one_trailing_newline("abc"), "abc");
        assert_eq!(trim_one_trailing_newline(" abc "), " abc ");
    }

    /// Minimal container so tests parse a secret through real TOML.
    #[derive(Debug, serde::Deserialize, Serialize)]
    struct TestWrap {
        s: Secret,
    }
}
