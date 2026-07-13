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

    /// Primary database settings.
    pub database: DatabaseConfig,

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
    /// Socket address the server listens on.
    pub bind: String,

    /// Externally visible base URL (scheme and host) used to mint issuer and
    /// endpoint URLs. Unset means single-host development behind the bind
    /// address.
    pub public_url: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8443".to_owned(),
            public_url: None,
        }
    }
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

/// One entry in the `[features]` table.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct FeatureToggle {
    /// Whether the feature is enabled.
    pub enabled: bool,

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
    }
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
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Io { source, .. } => Some(source),
            ConfigError::Parse { .. } => None,
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
        assert_eq!(config.server.public_url, None);
        assert_eq!(config.database.url.host(), "localhost");
        assert!(config.database.password.is_none());
        assert!(config.features.is_empty());
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
        for section in ["ServerConfig", "DatabaseConfig", "FeatureToggle"] {
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
