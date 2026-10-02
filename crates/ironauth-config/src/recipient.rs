// SPDX-License-Identifier: MIT OR Apache-2.0

//! Operator configuration for the subject-bound recipient ceremony (#1475).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ConfigError, Secret};

/// Subject-bound mailbox verification. Default off; separate from login OTP.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct RecipientVerificationConfig {
    /// Enable the authenticated hosted mailbox ceremony and current recipient proof.
    /// Requires OIDC, an HTTPS public URL and a configured TLS SMTP relay.
    /// Existing accounts still require controlled recipient-index backfill.
    pub enabled: bool,
    /// Deployment-owned SMTP settings. The browser cannot choose a relay or sender.
    pub smtp: Option<RecipientSmtpSettings>,
}

/// Mandatory certificate-verified encryption for the configured SMTP relay.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecipientSmtpSecurity {
    /// TLS from connection establishment, commonly port 465.
    Implicit,
    /// Mandatory STARTTLS, commonly port 587. No plaintext fallback.
    StartTls,
}

/// SMTP relay configuration. Required fields have no guessed operational defaults.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipientSmtpSettings {
    /// Relay DNS hostname or IPv4 address; no URL, path or embedded credentials.
    pub host: String,
    /// Explicit nonzero TCP port.
    pub port: u16,
    /// Required TLS policy; there is no plaintext mode.
    pub security: RecipientSmtpSecurity,
    /// Bare ASCII sender mailbox, without a display name or header syntax.
    pub sender: String,
    /// DNS domain used in the challenge-bound Message-ID.
    pub message_id_domain: String,
    /// Optional authentication username. Configure together with password.
    #[serde(default)]
    pub username: Option<Secret>,
    /// Optional authentication password, through the existing file/env secret seam.
    #[serde(default)]
    pub password: Option<Secret>,
    /// Maximum simultaneous delivery attempts, from 1 through 32; no waiting queue.
    #[serde(default = "default_in_flight")]
    pub max_in_flight: usize,
}

fn default_in_flight() -> usize {
    4
}

fn invalid(message: &str) -> ConfigError {
    ConfigError::Invalid {
        message: format!("oidc.recipient_verification: {message}"),
    }
}

fn dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl RecipientVerificationConfig {
    pub(crate) fn validate(
        &self,
        oidc_enabled: bool,
        public_url: Option<&str>,
    ) -> Result<(), ConfigError> {
        if self.enabled {
            let https = public_url.is_some_and(crate::is_well_formed_https_endpoint);
            if !oidc_enabled || !https || self.smtp.is_none() {
                return Err(invalid(
                    "enabling requires OIDC, an HTTPS public URL and SMTP settings",
                ));
            }
        }
        if let Some(smtp) = &self.smtp {
            if !dns_name(&smtp.host) || !dns_name(&smtp.message_id_domain) || smtp.port == 0 {
                return Err(invalid(
                    "relay host, Message-ID domain and port must be valid",
                ));
            }
            let parts: Vec<_> = smtp.sender.split('@').collect();
            if parts.len() != 2
                || parts[0].is_empty()
                || parts[0].len() > 64
                || smtp.sender.len() > 254
                || !dns_name(parts[1])
                || parts[0].starts_with('.')
                || parts[0].ends_with('.')
                || parts[0].contains("..")
                || !parts[0]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
            {
                return Err(invalid("sender must be a bare ASCII mailbox"));
            }
            if !(1..=32).contains(&smtp.max_in_flight) {
                return Err(invalid("max_in_flight must be between 1 and 32"));
            }
            if smtp.username.is_some() != smtp.password.is_some() {
                return Err(invalid(
                    "SMTP username and password must be configured together",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::Config;

    const CONFIG: &str = r#"
[server]
public_url = "https://auth.example.test"
[oidc]
enabled = true
[oidc.recipient_verification]
enabled = true
[oidc.recipient_verification.smtp]
host = "smtp.example.test"
port = 587
security = "start_tls"
sender = "verification@example.test"
message_id_domain = "auth.example.test"
username = { env = "RECIPIENT_SMTP_USER" }
password = { env = "RECIPIENT_SMTP_PASSWORD" }
"#;

    #[test]
    fn disabled_default_and_explicit_valid_relay() {
        assert!(!Config::default().oidc.recipient_verification.enabled);
        let loaded = Config::from_toml_str(CONFIG, "fixture").unwrap();
        assert!(loaded.config.oidc.recipient_verification.enabled);
        assert_eq!(
            loaded
                .config
                .oidc
                .recipient_verification
                .smtp
                .unwrap()
                .max_in_flight,
            4
        );
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn malformed_or_incomplete_relay_refuses_startup() {
        for (from, to) in [
            ("https://auth", "http://auth"),
            ("port = 587", "port = 0"),
            ("security = \"start_tls\"", "security = \"none\""),
            ("smtp.example.test", "smtp://user:secret@example.test"),
            ("verification@example.test", "Display <v@example.test>"),
            ("verification@example.test", "bad..local@example.test"),
            ("password = { env = \"RECIPIENT_SMTP_PASSWORD\" }", ""),
        ] {
            assert!(
                Config::from_toml_str(&CONFIG.replace(from, to), "fixture").is_err(),
                "{from}"
            );
        }
        assert!(
            Config::from_toml_str("[oidc.recipient_verification]\nenabled=true", "fixture")
                .is_err()
        );
        for extra in [
            "max_in_flight=0",
            "max_in_flight=33",
            "unknown_setting=true",
        ] {
            assert!(Config::from_toml_str(&format!("{CONFIG}\n{extra}"), "fixture").is_err());
        }
    }

    #[test]
    fn literal_credentials_are_redacted_and_both_are_linted() {
        let raw = CONFIG
            .replace("{ env = \"RECIPIENT_SMTP_USER\" }", "\"secret-user-1475\"")
            .replace(
                "{ env = \"RECIPIENT_SMTP_PASSWORD\" }",
                "\"secret-password-1475\"",
            );
        let loaded = Config::from_toml_str(&raw, "fixture").unwrap();
        assert_eq!(loaded.warnings.len(), 2);
        for output in [
            format!("{loaded:?}"),
            serde_json::to_string(&loaded.config).unwrap(),
        ] {
            assert!(!output.contains("secret-user-1475"));
            assert!(!output.contains("secret-password-1475"));
        }
    }
}
