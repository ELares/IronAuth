// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated connection strings.
//!
//! A [`Dsn`] is parsed and validated at config load, so a typo'd scheme or a
//! missing host fails at startup instead of at first query. The scheme
//! allowlist is a parameter: [`KNOWN_SCHEMES`] holds what IronAuth accepts
//! today (Postgres), and later backends (ironcache://, ironbus://) register by
//! extending that list; call sites with a narrower contract pass their own
//! list to [`Dsn::parse_with_schemes`].
//!
//! Redaction invariant: the password component never appears in `Debug`,
//! `Display`, serialization, or parse errors (parse errors never echo the
//! input at all). Code that needs the full string to connect calls
//! [`Dsn::expose`].

use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::secret::REDACTED;

/// Schemes IronAuth accepts in config today. ironcache:// and ironbus://
/// join this list when those optional backends land.
pub const KNOWN_SCHEMES: &[&str] = &["postgres", "postgresql"];

/// A validated connection string of the shape
/// `scheme://[user[:password]@]host[:port][/path][?params]`.
#[derive(Clone, PartialEq, Eq)]
pub struct Dsn {
    /// The full original string, password included. Exposed only via
    /// [`Dsn::expose`].
    raw: String,
    scheme: String,
    user: Option<String>,
    /// Whether the userinfo component carried a password. Drives userinfo
    /// rendering in [`Dsn::redacted`]. The password itself is only reachable
    /// through `raw`; it is never stored separately, so no code path can
    /// format it by accident.
    userinfo_password: bool,
    /// Whether the query string carried a credential parameter (`password` or
    /// `sslpassword`, both valid libpq URI keywords). Rendered redacted by
    /// [`Dsn::redacted`]; kept separate from `userinfo_password` so userinfo
    /// rendering is unaffected.
    query_password: bool,
    host: String,
    port: Option<u16>,
    /// Path plus query, including the leading separator; may be empty.
    tail: String,
}

/// Query-string keys whose values are credentials. Both are valid libpq
/// connection URI parameters, so a password can arrive in the query string
/// just as legitimately as in userinfo; both must redact.
const SECRET_QUERY_KEYS: &[&str] = &["password", "sslpassword"];

/// Redact credential-bearing query parameters in a `path[?query]` tail.
///
/// Returns the tail with any `password`/`sslpassword` value replaced by the
/// placeholder, and whether such a parameter carried a non-empty value.
fn redact_tail(tail: &str) -> (String, bool) {
    let Some((path, query)) = tail.split_once('?') else {
        return (tail.to_owned(), false);
    };
    let mut saw_secret = false;
    let mut out = String::with_capacity(tail.len());
    out.push_str(path);
    out.push('?');
    for (index, param) in query.split('&').enumerate() {
        if index > 0 {
            out.push('&');
        }
        match param.split_once('=') {
            Some((key, value))
                if SECRET_QUERY_KEYS
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(key)) =>
            {
                out.push_str(key);
                out.push('=');
                out.push_str(REDACTED);
                if !value.is_empty() {
                    saw_secret = true;
                }
            }
            _ => out.push_str(param),
        }
    }
    (out, saw_secret)
}

impl Dsn {
    /// Parse against [`KNOWN_SCHEMES`].
    ///
    /// # Errors
    ///
    /// Returns [`DsnError`] on an unknown scheme, missing host, or malformed
    /// port. Errors never echo the input (it may contain a password).
    pub fn parse(input: &str) -> Result<Self, DsnError> {
        Self::parse_with_schemes(input, KNOWN_SCHEMES)
    }

    /// Parse against a caller-supplied scheme allowlist (matched
    /// case-insensitively).
    ///
    /// # Errors
    ///
    /// Same contract as [`Dsn::parse`].
    pub fn parse_with_schemes(input: &str, allowed: &[&str]) -> Result<Self, DsnError> {
        let (scheme, rest) = input.split_once("://").ok_or(DsnError::MissingScheme)?;
        if !allowed.iter().any(|a| a.eq_ignore_ascii_case(scheme)) {
            return Err(DsnError::UnknownScheme {
                scheme: scheme.to_owned(),
                allowed: allowed.iter().map(|s| (*s).to_owned()).collect(),
            });
        }

        let (authority, tail) = match rest.find(['/', '?']) {
            Some(idx) => rest.split_at(idx),
            None => (rest, ""),
        };

        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((userinfo, hostport)) => (Some(userinfo), hostport),
            None => (None, authority),
        };
        let (user, userinfo_password) = match userinfo {
            Some(userinfo) => match userinfo.split_once(':') {
                Some((user, _password)) => (Some(user.to_owned()), true),
                None => (Some(userinfo.to_owned()), false),
            },
            None => (None, false),
        };

        let (host, port_str) = split_host_port(hostport)?;
        if host.is_empty() {
            return Err(DsnError::MissingHost);
        }
        let port = match port_str {
            Some(digits) => Some(digits.parse::<u16>().map_err(|_| DsnError::InvalidPort)?),
            None => None,
        };

        let (_, query_password) = redact_tail(tail);

        Ok(Self {
            raw: input.to_owned(),
            scheme: scheme.to_owned(),
            user,
            userinfo_password,
            query_password,
            host: host.to_owned(),
            port,
            tail: tail.to_owned(),
        })
    }

    /// The scheme, as written (schemes match case-insensitively).
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The user component, if present.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The host component (brackets retained for IPv6 literals).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, if one was written.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Whether the DSN embeds a password, in userinfo or the query string.
    #[must_use]
    pub fn has_password(&self) -> bool {
        self.userinfo_password || self.query_password
    }

    /// The full connection string, password included. Every call site is a
    /// deliberate exposure point (hand it to the database driver, never to
    /// logging or error formatting).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.raw
    }

    /// The redacted rendering used by `Debug`, `Display`, and `Serialize`.
    fn redacted(&self) -> String {
        let mut out = String::with_capacity(self.raw.len());
        out.push_str(&self.scheme);
        out.push_str("://");
        if self.user.is_some() || self.userinfo_password {
            if let Some(user) = &self.user {
                out.push_str(user);
            }
            if self.userinfo_password {
                out.push(':');
                out.push_str(REDACTED);
            }
            out.push('@');
        }
        out.push_str(&self.host);
        if let Some(port) = self.port {
            out.push(':');
            out.push_str(&port.to_string());
        }
        out.push_str(&redact_tail(&self.tail).0);
        out
    }
}

/// Split `hostport` into host and optional port digits, honoring IPv6
/// bracket literals.
fn split_host_port(hostport: &str) -> Result<(&str, Option<&str>), DsnError> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest.find(']').ok_or(DsnError::MissingHost)?;
        let host = &hostport[..end + 2];
        return match &rest[end + 1..] {
            "" => Ok((host, None)),
            after => match after.strip_prefix(':') {
                Some("") | None => Err(DsnError::InvalidPort),
                Some(port) => Ok((host, Some(port))),
            },
        };
    }
    match hostport.split_once(':') {
        Some((_, port)) if port.is_empty() || port.contains(':') => Err(DsnError::InvalidPort),
        Some((host, port)) => Ok((host, Some(port))),
        None => Ok((hostport, None)),
    }
}

impl fmt::Debug for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Dsn").field(&self.redacted()).finish()
    }
}

impl fmt::Display for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl Serialize for Dsn {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Config dumps carry the redacted form; a dump is not a credential
        // store. Reconnecting from a dump requires re-supplying the password.
        serializer.serialize_str(&self.redacted())
    }
}

impl<'de> Deserialize<'de> for Dsn {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Dsn::parse(&raw).map_err(de::Error::custom)
    }
}

impl JsonSchema for Dsn {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Dsn")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::Dsn"))
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "Connection string: scheme://[user[:password]@]host[:port][/path][?params]. Allowed schemes: postgres, postgresql. Embedding the password is discouraged; prefer a secret-typed companion field.",
            "pattern": "^[A-Za-z][A-Za-z0-9+.-]*://.+"
        })
    }
}

/// Why a connection string failed validation. Never echoes the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsnError {
    /// No `://` separator found.
    MissingScheme,
    /// The scheme is not on the allowlist.
    UnknownScheme {
        /// The scheme that was written.
        scheme: String,
        /// The schemes that would have been accepted.
        allowed: Vec<String>,
    },
    /// The authority has no host.
    MissingHost,
    /// The port is not a decimal number in range.
    InvalidPort,
}

impl fmt::Display for DsnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DsnError::MissingScheme => {
                write!(f, "invalid DSN: expected scheme://... (no '://' found)")
            }
            DsnError::UnknownScheme { scheme, allowed } => {
                write!(
                    f,
                    "invalid DSN: unknown scheme '{scheme}' (allowed: {})",
                    allowed.join(", ")
                )
            }
            DsnError::MissingHost => write!(f, "invalid DSN: missing host"),
            DsnError::InvalidPort => {
                write!(
                    f,
                    "invalid DSN: port must be a decimal number between 0 and 65535"
                )
            }
        }
    }
}

impl std::error::Error for DsnError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_full_postgres_dsn() {
        let dsn = Dsn::parse("postgres://app:s3cr3t@db.internal:5432/ironauth?sslmode=require")
            .expect("valid");
        assert_eq!(dsn.scheme(), "postgres");
        assert_eq!(dsn.user(), Some("app"));
        assert!(dsn.has_password());
        assert_eq!(dsn.host(), "db.internal");
        assert_eq!(dsn.port(), Some(5432));
        assert!(dsn.expose().contains("s3cr3t"));
    }

    #[test]
    fn accepts_minimal_and_ipv6_forms() {
        let dsn = Dsn::parse("postgresql://localhost").expect("valid");
        assert_eq!(dsn.host(), "localhost");
        assert_eq!(dsn.port(), None);
        assert_eq!(dsn.user(), None);

        let dsn = Dsn::parse("postgres://[::1]:5433/db").expect("valid");
        assert_eq!(dsn.host(), "[::1]");
        assert_eq!(dsn.port(), Some(5433));
    }

    #[test]
    fn rejects_bad_dsns_without_echoing_input() {
        let cases = [
            ("mysql://h/db", "unknown scheme 'mysql'"),
            ("postgres://", "missing host"),
            ("postgres://user:pw@/db", "missing host"),
            ("postgres://h:port/db", "port"),
            ("postgres://h:70000/db", "port"),
            ("postgres://h:/db", "port"),
            ("no-separator", "no '://'"),
        ];
        for (input, expected) in cases {
            let err = Dsn::parse(input).expect_err(input);
            let msg = err.to_string();
            assert!(msg.contains(expected), "{input}: {msg}");
            assert!(!msg.contains("pw"), "echoed input: {msg}");
        }
    }

    #[test]
    fn custom_scheme_allowlist_is_honored() {
        assert!(Dsn::parse("ironcache://c:6379").is_err());
        let dsn =
            Dsn::parse_with_schemes("ironcache://c:6379", &["ironcache"]).expect("allowed now");
        assert_eq!(dsn.scheme(), "ironcache");
        assert_eq!(dsn.port(), Some(6379));
    }

    #[test]
    fn debug_display_serialize_redact_the_password() {
        let dsn = Dsn::parse("postgres://app:s3cr3t@db:5432/ironauth").expect("valid");
        let json = serde_json::to_string(&dsn).expect("serializes");
        for rendered in [format!("{dsn:?}"), format!("{dsn}"), json] {
            assert!(!rendered.contains("s3cr3t"), "leak: {rendered}");
            assert!(rendered.contains(REDACTED), "no placeholder: {rendered}");
            assert!(rendered.contains("app"), "user should survive: {rendered}");
            assert!(
                rendered.contains("db:5432"),
                "host/port should survive: {rendered}"
            );
        }
    }

    #[test]
    fn password_free_dsn_renders_verbatim() {
        let raw = "postgres://app@db:5432/ironauth?sslmode=require";
        let dsn = Dsn::parse(raw).expect("valid");
        assert_eq!(dsn.to_string(), raw);
    }

    #[test]
    fn empty_user_with_password_still_redacts() {
        let dsn = Dsn::parse("postgres://:pw@db/x").expect("valid");
        let shown = dsn.to_string();
        assert!(!shown.contains("pw@"), "leak: {shown}");
        assert!(shown.contains(REDACTED), "{shown}");
    }

    #[test]
    fn query_string_password_is_redacted_everywhere() {
        // libpq accepts the password as a URI query parameter; it must redact
        // exactly like a userinfo password (regression for the query-form leak).
        let dsn =
            Dsn::parse("postgres://app@db:5432/ironauth?sslmode=require&password=ZQXSENTINEL")
                .expect("valid");
        assert!(dsn.has_password(), "query password must count");
        assert!(dsn.expose().contains("ZQXSENTINEL"), "expose keeps it");
        let json = serde_json::to_string(&dsn).expect("serializes");
        for rendered in [format!("{dsn:?}"), format!("{dsn}"), json] {
            assert!(!rendered.contains("ZQXSENTINEL"), "leak: {rendered}");
            assert!(rendered.contains(REDACTED), "no placeholder: {rendered}");
            assert!(
                rendered.contains("sslmode=require"),
                "non-secret param survives: {rendered}"
            );
        }
    }

    #[test]
    fn sslpassword_query_param_and_case_insensitivity_redact() {
        let dsn = Dsn::parse("postgres://db/x?SslPassword=ZQXSENTINEL").expect("valid");
        assert!(dsn.has_password());
        assert!(!dsn.to_string().contains("ZQXSENTINEL"), "leak: {dsn}");
    }

    #[test]
    fn empty_query_password_does_not_claim_a_password() {
        let dsn = Dsn::parse("postgres://db/x?password=").expect("valid");
        assert!(!dsn.has_password(), "empty value is not a password");
    }
}
