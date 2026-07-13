// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict configuration layer for IronAuth.
//!
//! Silent misconfiguration is a real identity-provider failure class, so this
//! crate is deliberately unforgiving: config is TOML, every table rejects
//! unknown keys, and any parse problem aborts startup naming the file, line,
//! column, and the accepted keys. There is no warn-and-continue path.
//!
//! The published contract is a JSON Schema derived from [`Config`]
//! ([`Config::json_schema`]); scripts/config-schema.sh regenerates the
//! `docs/config-schema.json` artifact (editors validate TOML against it via
//! taplo) and the generated `docs/CONFIG.md` reference, and CI fails on
//! drift.
//!
//! Secrets enter only through [`Secret`] indirection (file or env var;
//! literals are flagged outside dev mode) and can never leak through
//! `Debug`, `Display`, or serialization. Connection strings are validated
//! [`Dsn`] values with redacted passwords. Feature flags ride the maturity
//! ladder in [`features`]: experimental features boot only behind an
//! exact-version acknowledgment.

mod dsn;
mod features;
mod secret;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use dsn::{Dsn, DsnError, KNOWN_SCHEMES};
pub use features::{Feature, FeatureRegistry, FeatureValidationError, FeatureViolation, Maturity};
pub use secret::{REDACTED, Secret, SecretError, SecretString};

/// The root of the IronAuth process configuration.
///
/// Every section rejects unknown keys and every field has a serde default,
/// so an empty file is a valid (dev-oriented) configuration and a typo is a
/// startup failure, never a silently ignored setting.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Development mode. Relaxes operational nagging (currently: the
    /// literal-secret warning) but never relaxes parse strictness or the
    /// feature acknowledgment gate. Never set this in production.
    pub dev_mode: bool,

    /// HTTP server settings.
    pub server: ServerConfig,

    /// Trusted-proxy policy. Controls whether forwarding headers are honored;
    /// the safe default trusts nothing.
    pub proxy: ProxyConfig,

    /// Observability settings: log format and trace export.
    pub telemetry: TelemetryConfig,

    /// Primary database settings.
    pub database: DatabaseConfig,

    /// Management API settings (issue #11).
    pub admin: AdminConfig,

    /// OIDC provider settings (issue #12).
    pub oidc: OidcConfig,

    /// Feature toggles keyed by registered feature name. Enabling an
    /// experimental feature additionally requires `ack` equal to the
    /// feature's exact current version; see the feature reference in the
    /// generated docs/CONFIG.md.
    pub features: BTreeMap<String, FeatureToggle>,
}

/// HTTP server settings.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Socket address the public data plane listens on. This plane serves the
    /// protocol and hosted-page surfaces; health, readiness, and metrics are
    /// never exposed here.
    pub bind: String,

    /// Socket address the management plane listens on. Liveness, readiness,
    /// and the Prometheus metrics endpoint live here so the data plane is
    /// never probed publicly; bind it to a private interface.
    pub management_bind: String,

    /// Externally visible base URL (scheme and host) used to mint issuer and
    /// endpoint URLs. Unset means single-host development behind the bind
    /// address. The scheme, host, and issuer always derive from this value,
    /// never from request headers (see the `[proxy]` policy).
    pub public_url: Option<String>,

    /// Maximum seconds to drain in-flight requests after a shutdown signal
    /// before the process exits regardless. Zero exits without draining.
    pub shutdown_grace_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8443".to_owned(),
            management_bind: "127.0.0.1:9443".to_owned(),
            public_url: None,
            shutdown_grace_secs: 25,
        }
    }
}

/// Trusted-proxy policy.
///
/// Forwarding headers (RFC 7239 `Forwarded`, `X-Forwarded-For`,
/// `X-Forwarded-Proto`, `X-Forwarded-Host`) and the `Host` header are an
/// account-takeover class when trusted blindly. The default trusts NOTHING:
/// `trusted_hops = 0` and `trust_forwarded = false` mean the effective client
/// IP is the transport peer and the scheme, host, and issuer derive entirely
/// from `server.public_url`. Only when the server genuinely runs behind a
/// fixed number of trusted reverse proxies should these be raised, and even
/// then scheme and issuer stay config-derived.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ProxyConfig {
    /// Exact number of trusted reverse-proxy hops in front of the server.
    /// Zero (the default) means the server is exposed directly and no
    /// forwarding header is ever honored. Forwarding is honored only when the
    /// request presents exactly this many forwarding entries; any other count
    /// fails closed to the transport peer.
    pub trusted_hops: u32,

    /// Whether to honor forwarding headers at all. False (the default) ignores
    /// every forwarding header regardless of `trusted_hops`. Both this and a
    /// non-zero `trusted_hops` are required before any header is consulted.
    pub trust_forwarded: bool,
}

/// Observability settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    /// Structured-log output format for the process log stream.
    pub log_format: LogFormat,

    /// OpenTelemetry OTLP collector endpoint for trace export (for example
    /// `http://otel-collector:4317`). Trace export is compiled in only when
    /// the binary is built with the non-default `otlp` feature; setting this
    /// on a build without that feature logs a warning and is otherwise inert.
    pub otlp_endpoint: Option<String>,
}

/// Structured-log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// One JSON object per line with ECS-friendly field names. The production
    /// default: machine-parseable and safe to ship to a log pipeline.
    #[default]
    Json,
    /// Human-readable multi-line output for local development. Never emit this
    /// where logs are ingested by tooling.
    Pretty,
}

/// Primary database settings.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DatabaseConfig {
    /// Postgres connection string. Embedding the password here is
    /// discouraged; prefer the `password` secret, which is merged at
    /// connection time.
    pub url: Dsn,

    /// Database password supplied out of band, overriding any password
    /// embedded in `url`.
    pub password: Option<Secret>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: Dsn::parse("postgres://ironauth@localhost:5432/ironauth")
                .expect("default DSN is valid by construction (covered by test)"),
            password: None,
        }
    }
}

/// The ceiling any management list response is bounded by, no matter the
/// configured `admin.max_page_size` or a caller-supplied `limit`. It is the
/// last-resort bound so a single response can never trigger an unbounded scan.
/// The store applies the same value to every list query; keep this equal to
/// `ironauth_store`'s hard cap (a cross-crate test in `ironauth-admin` pins the
/// two together). Config load rejects an `admin.max_page_size` above it.
pub const MANAGEMENT_LIST_HARD_CAP: u32 = 1000;

/// Management API settings (issue #11).
///
/// The management API is the OpenAPI-first control plane on the management port.
/// It authorizes the operator plane (tenant CRUD) in M1 with a single config
/// bootstrap operator token; the full operator-plane credential class lands in
/// M5. Page-size limits are configurable (the tunability principle) with safe
/// defaults, never a baked-in one-way choice.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct AdminConfig {
    /// The bootstrap operator bearer token that authorizes the operator plane
    /// (tenant CRUD) in M1, presented as `Authorization: Bearer <token>`. Unset
    /// leaves the operator plane unauthorized (the management API still mounts,
    /// but every operator-plane request is rejected). Use the `file`/`env` secret
    /// indirection, never a literal, outside dev mode. The full operator-plane
    /// credential class lands in M5.
    pub bootstrap_operator_token: Option<Secret>,

    /// The database connection string the management (control) plane connects
    /// with. It MUST authenticate as the least-privilege `ironauth_control` role,
    /// a distinct credential class from the data-plane role, so the
    /// `management_credentials` FORCE row-level-security backstop applies beneath
    /// the repository layer. Use the `file`/`env` secret indirection, never a
    /// literal, outside dev mode. When unset and the management API is enabled:
    /// in production (`dev_mode = false`) the API refuses to mount (fail closed);
    /// in `dev_mode = true` it falls back to `database.url` with a warning that
    /// the role separation and the FORCE-RLS backstop are NOT enforced.
    pub control_database_url: Option<Secret>,

    /// The largest page a list endpoint will return, regardless of a larger
    /// caller-supplied `limit`. A ceiling that bounds any one response so a
    /// caller cannot request an unbounded scan. Config load rejects a value above
    /// the management list hard cap (1000).
    pub max_page_size: u32,

    /// The page size a list endpoint uses when the caller supplies no `limit`.
    /// Clamped to `max_page_size`.
    pub default_page_size: u32,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            bootstrap_operator_token: None,
            control_database_url: None,
            max_page_size: 200,
            default_page_size: 50,
        }
    }
}

/// The largest an authorization-code or access-token lifetime may be configured
/// to, in seconds. A code is a short-lived, single-use bearer credential and an
/// access token a bearer credential; a lifetime beyond one day is almost always
/// a misconfiguration, so config load rejects it (fail fast rather than mint a
/// long-lived code). The safe defaults are far below this ceiling.
pub const OIDC_MAX_LIFETIME_SECS: u64 = 86_400;

/// OIDC provider settings (issue #12).
///
/// The public authorization and token endpoints. Lifetimes are configurable (the
/// tunability principle) with safe defaults, never a baked-in one-way choice: the
/// authorization code is short-lived and single-use, the access token a little
/// longer. Mounting is opt-in so the default (and database-free) boot is
/// unchanged.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct OidcConfig {
    /// Whether to mount the public OIDC endpoints (`/authorize`, `/token`). Off
    /// by default so the default boot serves only the skeleton and needs no
    /// database. When on, the provider connects the data-plane store using
    /// `database.url`.
    pub enabled: bool,

    /// Authorization-code lifetime in seconds. A code is single-use and
    /// short-lived; the default (60) follows the OAuth 2.1 guidance that codes
    /// live about a minute. Must be at least 1 and at most
    /// `OIDC_MAX_LIFETIME_SECS`.
    pub authorization_code_ttl_secs: u64,

    /// Access-token lifetime in seconds. The default (300) is a conservative five
    /// minutes; refresh handling (rotation, families) lands in M3. Must be at
    /// least 1 and at most `OIDC_MAX_LIFETIME_SECS`.
    pub access_token_ttl_secs: u64,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 300,
        }
    }
}

/// One entry in the `[features]` table.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FeatureToggle {
    /// Whether the feature is enabled. When omitted, the feature's own default
    /// applies (on only for a Supported feature declared on by default), so
    /// naming a feature just to attach an `ack` does not silently turn a
    /// default-on feature off. Set `enabled = false` to force it off.
    pub enabled: Option<bool>,

    /// Exact-version acknowledgment, required to enable an experimental
    /// feature. Ignored for preview and supported features.
    pub ack: Option<String>,
}

/// A successfully parsed configuration plus the warnings the caller must
/// surface. Warnings never gate startup; everything gating startup is an
/// error.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed, validated configuration.
    pub config: Config,
    /// Warnings to surface to the operator. Empty when `dev_mode` is set.
    pub warnings: Vec<Warning>,
}

/// An operator-facing warning collected during load.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// A secret-typed field uses the literal form outside dev mode.
    LiteralSecret {
        /// Dotted key path of the offending field (for example
        /// `database.password`).
        key: String,
    },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Warning::LiteralSecret { key } => write!(
                f,
                "secret '{key}' is a literal value in the config file; \
                 use {{ file = \"/path\" }} or {{ env = \"VAR\" }} instead \
                 (or set dev_mode = true in development)"
            ),
        }
    }
}

impl Config {
    /// Load and strictly parse a TOML config file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Io`] if the file cannot be read; [`ConfigError::Parse`]
    /// (naming the file, line, column, and offending key with the accepted
    /// alternatives) on any syntax or schema violation. Unknown keys are
    /// errors; there is no warn-and-continue mode.
    pub fn load(path: impl AsRef<Path>) -> Result<Loaded, ConfigError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&contents, &path.display().to_string())
    }

    /// Strictly parse TOML config text. `source_name` names the origin in
    /// errors (a file path, or a marker like `"<inline>"` in tests).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] with the same contract as [`Config::load`].
    pub fn from_toml_str(input: &str, source_name: &str) -> Result<Loaded, ConfigError> {
        let config: Config = toml::from_str(input).map_err(|error| {
            let position = error.span().map(|span| line_and_column(input, span.start));
            ConfigError::Parse {
                source_name: source_name.to_owned(),
                position,
                message: error.message().to_owned(),
            }
        })?;
        config.validate()?;
        let warnings = config.collect_warnings();
        Ok(Loaded { config, warnings })
    }

    /// The JSON Schema (draft 2020-12) this crate's parser enforces, with
    /// field doc comments as descriptions. Published as a release artifact
    /// by scripts/config-schema.sh.
    #[must_use]
    pub fn json_schema() -> schemars::Schema {
        schemars::schema_for!(Config)
    }

    /// Post-parse lint pass. Warnings are suppressed wholesale in dev mode;
    /// parse strictness is not affected.
    fn collect_warnings(&self) -> Vec<Warning> {
        if self.dev_mode {
            return Vec::new();
        }
        let mut warnings = Vec::new();
        self.for_each_secret(|key, secret| {
            if secret.is_literal() {
                warnings.push(Warning::LiteralSecret {
                    key: key.to_owned(),
                });
            }
        });
        warnings
    }

    /// Visit every secret-typed field with its dotted key path. Sections
    /// added by later issues must register their secret fields here so the
    /// literal-form lint keeps covering the whole tree.
    fn for_each_secret(&self, mut visit: impl FnMut(&str, &Secret)) {
        if let Some(password) = &self.database.password {
            visit("database.password", password);
        }
        if let Some(token) = &self.admin.bootstrap_operator_token {
            visit("admin.bootstrap_operator_token", token);
        }
        if let Some(dsn) = &self.admin.control_database_url {
            visit("admin.control_database_url", dsn);
        }
    }

    /// Post-parse bound and cross-field checks the schema alone cannot express.
    /// Fatal (unlike a [`Warning`]): a violation aborts startup.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] if `admin.max_page_size` exceeds the management
    /// list hard cap (a larger cap would let the store's has-next sentinel be
    /// clamped away, hiding the last page).
    fn validate(&self) -> Result<(), ConfigError> {
        if self.admin.max_page_size > MANAGEMENT_LIST_HARD_CAP {
            return Err(ConfigError::Invalid {
                message: format!(
                    "admin.max_page_size ({}) must not exceed the management list hard cap ({MANAGEMENT_LIST_HARD_CAP})",
                    self.admin.max_page_size
                ),
            });
        }
        check_oidc_lifetime(
            "oidc.authorization_code_ttl_secs",
            self.oidc.authorization_code_ttl_secs,
        )?;
        check_oidc_lifetime(
            "oidc.access_token_ttl_secs",
            self.oidc.access_token_ttl_secs,
        )?;
        Ok(())
    }
}

/// Validate one OIDC lifetime: at least one second (a zero-second credential is
/// born expired) and no more than [`OIDC_MAX_LIFETIME_SECS`].
fn check_oidc_lifetime(key: &str, value: u64) -> Result<(), ConfigError> {
    if value < 1 {
        return Err(ConfigError::Invalid {
            message: format!("{key} must be at least 1 second"),
        });
    }
    if value > OIDC_MAX_LIFETIME_SECS {
        return Err(ConfigError::Invalid {
            message: format!("{key} ({value}) must not exceed {OIDC_MAX_LIFETIME_SECS} seconds"),
        });
    }
    Ok(())
}

/// Translate a byte offset into 1-based line and column (in characters).
fn line_and_column(input: &str, offset: usize) -> (usize, usize) {
    let prefix = &input[..offset.min(input.len())];
    let line = prefix.matches('\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, tail)| tail)
        .chars()
        .count()
        + 1;
    (line, column)
}

/// Why a configuration failed to load. Always fatal: the caller aborts
/// startup and shows the message.
#[derive(Debug)]
pub enum ConfigError {
    /// The config file could not be read.
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The config text violates the schema (syntax error, wrong type, or
    /// unknown key).
    Parse {
        /// The file path (or inline marker) the text came from.
        source_name: String,
        /// 1-based line and column of the offending item, when the parser
        /// attributed one.
        position: Option<(usize, usize)>,
        /// The parser's message; for unknown keys this names the offending
        /// key and lists the accepted fields.
        message: String,
    },
    /// A parsed value violates a bound or cross-field constraint the schema
    /// alone cannot express (for example `admin.max_page_size` above the
    /// management list hard cap).
    Invalid {
        /// The human-readable constraint violation. Never carries a secret.
        message: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io { path, source } => {
                write!(f, "cannot read config file '{}': {source}", path.display())
            }
            ConfigError::Parse {
                source_name,
                position,
                message,
            } => match position {
                Some((line, column)) => {
                    write!(f, "invalid config {source_name}:{line}:{column}: {message}")
                }
                None => write!(f, "invalid config {source_name}: {message}"),
            },
            ConfigError::Invalid { message } => write!(f, "invalid config: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::Parse { .. } | ConfigError::Invalid { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_the_documented_defaults() {
        let loaded = Config::from_toml_str("", "<inline>").expect("empty config is valid");
        assert!(loaded.warnings.is_empty());
        let config = loaded.config;
        assert!(!config.dev_mode);
        assert_eq!(config.server.bind, "127.0.0.1:8443");
        assert_eq!(config.server.management_bind, "127.0.0.1:9443");
        assert_eq!(config.server.public_url, None);
        assert_eq!(config.server.shutdown_grace_secs, 25);
        // Trusted-proxy policy defaults to trusting nothing.
        assert_eq!(config.proxy.trusted_hops, 0);
        assert!(!config.proxy.trust_forwarded);
        // Telemetry defaults to machine-parseable JSON with no exporter.
        assert_eq!(config.telemetry.log_format, LogFormat::Json);
        assert_eq!(config.telemetry.otlp_endpoint, None);
        assert_eq!(config.database.url.host(), "localhost");
        assert!(config.database.password.is_none());
        assert!(config.features.is_empty());
    }

    #[test]
    fn admin_section_defaults_parse_and_flag_a_literal_token() {
        // Defaults: operator plane unauthorized, control DSN unset, safe caps.
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert!(config.admin.bootstrap_operator_token.is_none());
        assert!(config.admin.control_database_url.is_none());
        assert_eq!(config.admin.max_page_size, 200);
        assert_eq!(config.admin.default_page_size, 50);

        // The bootstrap token is a secret: a literal value is flagged outside
        // dev mode and never echoed.
        let input = "[admin]\nbootstrap_operator_token = \"op-secret-123\"\nmax_page_size = 10\n";
        let loaded = Config::from_toml_str(input, "<inline>").expect("valid");
        assert_eq!(
            loaded.warnings,
            vec![Warning::LiteralSecret {
                key: "admin.bootstrap_operator_token".to_owned()
            }]
        );
        assert_eq!(loaded.config.admin.max_page_size, 10);
        assert!(!loaded.warnings[0].to_string().contains("op-secret-123"));

        // Unknown admin keys abort with the accepted fields.
        let err = Config::from_toml_str("[admin]\nmax_pages = 5\n", "ironauth.toml")
            .expect_err("unknown admin key");
        let msg = err.to_string();
        assert!(msg.contains("max_pages"), "{msg}");
        assert!(msg.contains("max_page_size"), "{msg}");
    }

    #[test]
    fn admin_control_database_url_parses_and_flags_a_literal() {
        // The indirection form resolves and never warns.
        let indirect = "[admin]\ncontrol_database_url = { env = \"IRONAUTH_CONTROL_DSN\" }\n";
        let loaded = Config::from_toml_str(indirect, "<inline>").expect("valid");
        assert!(loaded.config.admin.control_database_url.is_some());
        assert!(loaded.warnings.is_empty());

        // A literal control DSN is a secret: flagged outside dev mode, never echoed.
        let literal =
            "[admin]\ncontrol_database_url = \"postgres://ironauth_control:pw@db/ironauth\"\n";
        let loaded = Config::from_toml_str(literal, "<inline>").expect("valid");
        assert_eq!(
            loaded.warnings,
            vec![Warning::LiteralSecret {
                key: "admin.control_database_url".to_owned()
            }]
        );
        assert!(!loaded.warnings[0].to_string().contains("pw@db"), "leak");
    }

    #[test]
    fn max_page_size_above_the_hard_cap_is_rejected() {
        let ok = format!("[admin]\nmax_page_size = {MANAGEMENT_LIST_HARD_CAP}\n");
        assert_eq!(
            Config::from_toml_str(&ok, "<inline>")
                .expect("at the cap is valid")
                .config
                .admin
                .max_page_size,
            MANAGEMENT_LIST_HARD_CAP
        );

        let over = format!(
            "[admin]\nmax_page_size = {}\n",
            MANAGEMENT_LIST_HARD_CAP + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("over the cap");
        let msg = err.to_string();
        assert!(msg.contains("max_page_size"), "{msg}");
        assert!(msg.contains(&MANAGEMENT_LIST_HARD_CAP.to_string()), "{msg}");
    }

    #[test]
    fn oidc_section_defaults_and_rejects_bad_lifetimes_and_unknown_keys() {
        // Defaults: not mounted, 60s code, 300s access token.
        let config = Config::from_toml_str("", "<inline>").expect("valid").config;
        assert!(!config.oidc.enabled);
        assert_eq!(config.oidc.authorization_code_ttl_secs, 60);
        assert_eq!(config.oidc.access_token_ttl_secs, 300);

        // A configured, in-bounds override parses.
        let input = "[oidc]\nenabled = true\nauthorization_code_ttl_secs = 30\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert!(config.oidc.enabled);
        assert_eq!(config.oidc.authorization_code_ttl_secs, 30);

        // A zero lifetime (born expired) is rejected.
        let err =
            Config::from_toml_str("[oidc]\nauthorization_code_ttl_secs = 0\n", "ironauth.toml")
                .expect_err("zero ttl");
        assert!(
            err.to_string().contains("authorization_code_ttl_secs"),
            "{err}"
        );

        // A lifetime above the ceiling is rejected.
        let over = format!(
            "[oidc]\naccess_token_ttl_secs = {}\n",
            OIDC_MAX_LIFETIME_SECS + 1
        );
        let err = Config::from_toml_str(&over, "ironauth.toml").expect_err("over cap");
        assert!(err.to_string().contains("access_token_ttl_secs"), "{err}");

        // Unknown oidc keys abort with the accepted fields.
        let err = Config::from_toml_str("[oidc]\nttl = 5\n", "ironauth.toml")
            .expect_err("unknown oidc key");
        let msg = err.to_string();
        assert!(msg.contains("ttl"), "{msg}");
        assert!(msg.contains("authorization_code_ttl_secs"), "{msg}");
    }

    #[test]
    fn proxy_and_telemetry_sections_parse_and_reject_unknown_keys() {
        let input = "[proxy]\ntrusted_hops = 2\ntrust_forwarded = true\n\
                     [telemetry]\nlog_format = \"pretty\"\notlp_endpoint = \"http://c:4317\"\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        assert_eq!(config.proxy.trusted_hops, 2);
        assert!(config.proxy.trust_forwarded);
        assert_eq!(config.telemetry.log_format, LogFormat::Pretty);
        assert_eq!(
            config.telemetry.otlp_endpoint.as_deref(),
            Some("http://c:4317")
        );

        let err = Config::from_toml_str("[proxy]\nhops = 1\n", "ironauth.toml")
            .expect_err("unknown proxy key");
        let msg = err.to_string();
        assert!(msg.contains("hops"), "{msg}");
        assert!(msg.contains("trusted_hops"), "{msg}");

        let err = Config::from_toml_str("[telemetry]\nlog_format = \"yaml\"\n", "ironauth.toml")
            .expect_err("unknown log format");
        let msg = err.to_string();
        assert!(msg.contains("yaml"), "{msg}");
        assert!(msg.contains("json") && msg.contains("pretty"), "{msg}");
    }

    #[test]
    fn unknown_root_key_aborts_with_position_and_expected_fields() {
        let input = "dev_mode = true\nservre = { bind = \"0.0.0.0:1\" }\n";
        let err = Config::from_toml_str(input, "ironauth.toml").expect_err("unknown key");
        let msg = err.to_string();
        assert!(msg.contains("ironauth.toml:2:1"), "{msg}");
        assert!(msg.contains("servre"), "{msg}");
        // serde's expected-fields list is the did-you-mean.
        assert!(msg.contains("server"), "{msg}");
        assert!(msg.contains("database"), "{msg}");
    }

    #[test]
    fn unknown_nested_key_aborts_with_position() {
        let input = "[server]\nbindd = \"0.0.0.0:1\"\n";
        let err = Config::from_toml_str(input, "ironauth.toml").expect_err("unknown key");
        let msg = err.to_string();
        assert!(msg.contains("ironauth.toml:2:1"), "{msg}");
        assert!(msg.contains("bindd"), "{msg}");
        assert!(msg.contains("bind"), "{msg}");
    }

    #[test]
    fn literal_secret_warns_outside_dev_mode_only() {
        let input = "[database]\npassword = \"hunter2\"\n";
        let loaded = Config::from_toml_str(input, "<inline>").expect("valid");
        assert_eq!(
            loaded.warnings,
            vec![Warning::LiteralSecret {
                key: "database.password".to_owned()
            }]
        );
        let text = loaded.warnings[0].to_string();
        assert!(text.contains("database.password"), "{text}");
        assert!(!text.contains("hunter2"), "leak: {text}");

        let dev_input = format!("dev_mode = true\n{input}");
        let loaded = Config::from_toml_str(&dev_input, "<inline>").expect("valid");
        assert!(loaded.warnings.is_empty());

        let indirect = "[database]\npassword = { env = \"PGPASSWORD\" }\n";
        let loaded = Config::from_toml_str(indirect, "<inline>").expect("valid");
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn invalid_dsn_aborts_with_position_and_no_password_echo() {
        let input = "[database]\nurl = \"mysql://app:supersecret@db/x\"\n";
        let err = Config::from_toml_str(input, "ironauth.toml").expect_err("bad scheme");
        let msg = err.to_string();
        assert!(msg.contains("unknown scheme 'mysql'"), "{msg}");
        assert!(msg.contains("ironauth.toml:2"), "{msg}");
        assert!(!msg.contains("supersecret"), "leak: {msg}");
    }

    #[test]
    fn config_debug_and_dumps_redact_secrets() {
        let input = "[database]\nurl = \"postgres://app:dbpw@db:5432/x\"\npassword = \"hunter2\"\n";
        let config = Config::from_toml_str(input, "<inline>")
            .expect("valid")
            .config;
        let debug = format!("{config:?}");
        let dump = toml::to_string(&config).expect("dumps");
        for rendered in [debug, dump] {
            assert!(!rendered.contains("hunter2"), "leak: {rendered}");
            assert!(!rendered.contains("dbpw"), "leak: {rendered}");
            assert!(rendered.contains(REDACTED), "{rendered}");
        }
    }

    #[test]
    fn default_dsn_parses_by_construction() {
        // Guards the expect() in DatabaseConfig::default.
        let config = DatabaseConfig::default();
        assert_eq!(config.url.scheme(), "postgres");
    }

    #[test]
    fn line_and_column_are_one_based_and_char_counted() {
        assert_eq!(line_and_column("abc", 0), (1, 1));
        assert_eq!(line_and_column("abc\ndef", 4), (2, 1));
        assert_eq!(line_and_column("abc\ndef", 6), (2, 3));
    }

    #[test]
    fn json_schema_is_strict_and_described() {
        let schema = Config::json_schema();
        let value = serde_json::to_value(&schema).expect("schema serializes");
        // Strictness must reach the schema: unknown keys invalid at the root
        // and in every section definition.
        assert_eq!(value["additionalProperties"], serde_json::json!(false));
        for section in [
            "ServerConfig",
            "ProxyConfig",
            "TelemetryConfig",
            "DatabaseConfig",
            "AdminConfig",
            "OidcConfig",
            "FeatureToggle",
        ] {
            assert_eq!(
                value["$defs"][section]["additionalProperties"],
                serde_json::json!(false),
                "{section} must reject unknown keys"
            );
        }
        // Doc comments must flow into the schema as descriptions, and serde
        // defaults must surface as schema defaults.
        let bind = &value["$defs"]["ServerConfig"]["properties"]["bind"];
        assert!(
            bind["description"].as_str().is_some_and(|d| !d.is_empty()),
            "doc comments must flow into the schema: {bind}"
        );
        assert_eq!(bind["default"], serde_json::json!("127.0.0.1:8443"));
    }
}
