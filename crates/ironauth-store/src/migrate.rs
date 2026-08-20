// SPDX-License-Identifier: MIT OR Apache-2.0

//! A runtime, expand-contract migration runner.
//!
//! Schema evolution for an identity provider is nearly irreversible and must be
//! zero-downtime N/N+1 safe, so every change moves through three phases:
//!
//! - **expand**: add the new shape additively (a nullable column, a new table),
//!   leaving the old shape in place so both binaries keep working;
//! - **migrate**: backfill the new shape from the old;
//! - **contract**: remove the old shape once no binary reads it.
//!
//! This runner tracks what it has applied in a `_schema_migrations` ledger,
//! applies each pending migration in order inside its own transaction (so a
//! failed migration leaves neither a partial schema change nor a ledger row),
//! and refuses two dangerous states outright: applying migrations out of order
//! (a lower version still pending while a higher one is already applied), and a
//! checksum drift on an already-applied migration (its text changed since it was
//! recorded, which means either tampering or an edit to shipped history). Both
//! surface as a typed [`MigrationError`].
//!
//! Concurrent runners (several replicas booting at once during a rolling
//! upgrade) are serialized by a session-level Postgres advisory lock, so the
//! losers wait and then find the chain already applied instead of racing to
//! create the same objects and failing with a raw error.
//!
//! Only the runtime sqlx query API is used (no `migrate!`/`query!` macros), so
//! the database-free build lanes stay database-free; the migration text is
//! embedded with `include_str!` and its checksum is computed at run time.
//!
//! ## Migration safety obligation
//!
//! A migration that introduces a new tenant-scoped table MUST, in the same
//! migration, ENABLE and FORCE row-level security, add the `(tenant, environment)`
//! isolation policy, and add the nonempty-scope CHECK constraint, exactly as the
//! isolation schema does. It must also be added to `scripts/query-audit.sh`'s
//! scoped-table list. The tenant-isolation discipline does not stop at the first
//! migration; it extends to every one.
//!
//! That last obligation used to be prose in two places and enforced in neither, so
//! a new forced-row-level-security table absent from the scoped-table list was
//! simply never grepped for and raw SQL against it passed silently.
//! `scripts/scoped-table-registration.sh` now derives the set from the migrations
//! and compares it against the list in both directions (issue #446).
//!
//! ## Registration obligation, and what enforces it
//!
//! [`registry`] is a hand-written list of `include_str!` entries, so a `.sql`
//! file dropped into `migrations/` without its entry is simply not in the chain.
//! That failure used to be silent in both of the controls that look like they
//! would catch it: the chain-count tripwire in `tests/migration.rs` asserts a
//! hardcoded number against the LIVE ledger, and an unregistered file never
//! reaches the ledger, so the ledger and the hardcoded number agreed with each
//! other while both were wrong about what is on disk (issue #446).
//!
//! The `registry_matches_the_migrations_directory` tests below close that by
//! reading the directory and comparing it against [`registry`] in BOTH
//! directions, by file name and by content. They are deliberately ADDITIONAL to
//! the chain-count tripwire rather than a replacement for it: the tripwire's
//! value is forcing a human to read every added migration (issue #390), which a
//! derived check cannot do, and the derived check catches a file nobody wired
//! in, which the tripwire cannot see.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

/// The phase a migration belongs to in the expand-contract lifecycle. Recorded
/// on the ledger row so an operator can see, per applied migration, whether it
/// added, backfilled, or removed schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Additive: a new column or table, safe for the old binary to ignore.
    Expand,
    /// Backfill: populate the new shape from the old.
    Migrate,
    /// Removal: drop the old shape once nothing reads it.
    Contract,
}

impl Phase {
    /// The stable wire string recorded in the ledger.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Expand => "expand",
            Phase::Migrate => "migrate",
            Phase::Contract => "contract",
        }
    }
}

/// One migration: an ordered version, a name, its phase, and its SQL text.
///
/// The SQL is a `'static` string (embedded with `include_str!` for the real
/// chain), so the checksum is over exactly the text that will run.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// The strictly ascending version. Versions must be unique and applied in
    /// ascending order with no gaps.
    pub version: i64,
    /// A short human-facing name (also stored in the ledger).
    pub name: &'static str,
    /// The expand-contract phase this migration belongs to.
    pub phase: Phase,
    /// The migration's SQL text, run verbatim (may contain many statements).
    pub sql: &'static str,
}

impl Migration {
    /// The hex SHA-256 checksum of this migration's SQL text. The ledger stores
    /// this at apply time; a later run recomputes it and refuses to proceed if
    /// it no longer matches (tamper and drift detection).
    #[must_use]
    pub fn checksum(&self) -> String {
        use std::fmt::Write as _;
        let digest = Sha256::digest(self.sql.as_bytes());
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// The outcome of a [`MigrationRunner::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// The versions applied by this run, in order. Empty when the schema was
    /// already current.
    newly_applied: Vec<i64>,
    /// How many migrations were already applied before this run.
    already_applied: usize,
}

impl MigrationReport {
    /// The versions applied by this run, in ascending order.
    #[must_use]
    pub fn newly_applied(&self) -> &[i64] {
        &self.newly_applied
    }

    /// How many migrations had already been applied before this run.
    #[must_use]
    pub fn already_applied(&self) -> usize {
        self.already_applied
    }
}

/// Why a migration run was refused or failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum MigrationError {
    /// A database or connection error.
    Database(sqlx::Error),
    /// The registry is not strictly ascending by version (a programming error
    /// in the migration set). Carries the offending version.
    NotSorted {
        /// The version that was not greater than its predecessor.
        version: i64,
    },
    /// A higher version is already applied while a lower version is still
    /// pending: applying now would run migrations out of order.
    OutOfOrder {
        /// The already-applied higher version.
        applied: i64,
        /// The still-pending lower version that should have come first.
        missing: i64,
    },
    /// An already-applied migration's SQL text no longer matches the checksum
    /// recorded when it was applied (tampering or an edit to shipped history).
    ChecksumMismatch {
        /// The version whose checksum drifted.
        version: i64,
    },
    /// The ledger records a version the current registry does not contain (the
    /// database was migrated by a newer or different build).
    UnknownApplied {
        /// The applied version missing from the registry.
        version: i64,
    },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::Database(_) => f.write_str("migration database error"),
            MigrationError::NotSorted { version } => {
                write!(
                    f,
                    "migration registry is not strictly ascending at version {version}"
                )
            }
            MigrationError::OutOfOrder { applied, missing } => write!(
                f,
                "out-of-order migrations: version {applied} is applied but lower version {missing} is still pending"
            ),
            MigrationError::ChecksumMismatch { version } => {
                write!(
                    f,
                    "checksum mismatch on already-applied migration version {version}"
                )
            }
            MigrationError::UnknownApplied { version } => write!(
                f,
                "applied migration version {version} is absent from this build's registry"
            ),
        }
    }
}

impl std::error::Error for MigrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MigrationError::Database(source) => Some(source),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for MigrationError {
    fn from(source: sqlx::Error) -> Self {
        MigrationError::Database(source)
    }
}

/// Bootstrap the ledger. Executed before the ledger is consulted; it is not
/// itself a tracked migration (it is the table the tracked migrations record
/// into). `IF NOT EXISTS` makes it a no-op on an already-initialized database.
const CREATE_LEDGER_SQL: &str = "\
CREATE TABLE IF NOT EXISTS _schema_migrations ( \
    version    bigint      PRIMARY KEY, \
    name       text        NOT NULL, \
    checksum   text        NOT NULL, \
    phase      text        NOT NULL, \
    applied_at timestamptz NOT NULL DEFAULT now() \
)";

/// The applied, ordered migration chain for IronAuth.
///
/// The `#6` isolation schema is version 1; the same-transaction audit log is
/// version 2; the management-API control plane (issue #11: the `ironauth_control`
/// role, soft-delete columns, and the `management_credentials` and
/// `idempotency_keys` tables) is version 3; the OIDC authorization-code grant
/// tables (issue #12: `grants`, `authorization_codes`, and `issued_tokens`) are
/// version 4; the per-environment `signing_keys` table (issue #19) is version 5;
/// the bootstrap login, consent, session, and secret-based client-authentication
/// tables (issue #20: `users`, `sessions`, `consents`, plus the additive `clients`
/// expand) are version 6; the recorded authentication context for honest ID token
/// claims (issue #14: the additive `sessions`, `authorization_codes`, and `clients`
/// column expands carrying the login method and `auth_time`) is version 7; the
/// registered redirect URIs for the exact-string redirect match (issue #13: the
/// additive `clients.redirect_uris` array column) are version 8; the `UserInfo`
/// standard-claim store (issue #15: the additive `users.claims` column backing the
/// scope-derived and claims-parameter-selected claim sets) is version 9; the
/// scope-aware-consent grant (issue #196: `GRANT UPDATE ON consents` so a
/// broadened consent is `UPSERTed` rather than dropped, a privilege grant with NO
/// schema change) is version 10; the `resource_servers` registry (issue #29: the
/// audience-to-token-format table the mint reads to select a registered resource
/// server's access-token format) is version 11; the `opaque_access_tokens` store
/// (issue #29: the digest-only reference-token table the internal resolve reads)
/// is version 12; the JWT-assertion client-authentication suite (issue #25: the
/// additive `clients` key/alg registration columns, the cross-node single-use
/// `client_assertion_jtis` replay cache, and the out-of-band
/// `client_auth_diagnostics` sink) is version 13; the Dynamic Client Registration
/// and configuration-management columns (issue #30: the additive `clients`
/// expand for the RFC 7592 registration access token hash, the registration
/// client URI, the negotiated `id_token_signed_response_alg`, the RFC 8252
/// `application_type`, and the `dcr_registered` origin flag) are version 14; the
/// pushed-authorization-request store (issue #27: the single-use
/// `pushed_authorization_requests` table RFC 9126 stores a validated request behind
/// a one-time `request_uri`, plus the additive per-client
/// `clients.require_pushed_authorization_requests` flag) is version 15; the
/// refresh-token rotation suite (issue #21: the `refresh_families` revocation spine
/// and the digest-only `refresh_tokens` generation store, plus the additive
/// `clients` consent-mode and rotation-override columns and the additive
/// `consents.expires_at` for remembered consent) is version 16; the
/// client-credentials service accounts (issue #23: the `service_accounts`
/// principal table and the additive `clients.custom_token_claims` column) are
/// version 17; the Dynamic
/// Client Registration abuse controls (issue #31: the `dcr_policies` reusable
/// named policy objects, the `dcr_initial_access_tokens` store, the
/// `dcr_rate_counters` endpoint-local counters, and the additive `clients`
/// quarantine and policy-chain columns) are version 18. That is
/// the whole production chain: it deliberately
/// carries no throwaway objects, so a real database never gains a demo table or
/// ledger rows beyond what the product needs. The worked expand-contract example
/// (add a nullable column, backfill, drop the old column) lives entirely in the
/// migration framework's own test (`tests/migration.rs`), driven through
/// [`MigrationRunner::from_migrations`]
/// against a throwaway test database, so all three phases are exercised in CI
/// without ever touching the real schema.
// A flat, linear list of the shipped migrations (one struct literal each); it grows
// by one entry per issue and is clearer as a single list than split across helpers.
#[allow(clippy::too_many_lines)]
fn registry() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            name: "tenant_isolation",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0001_tenant_isolation.sql"),
        },
        Migration {
            version: 2,
            name: "audit_log",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0002_audit_log.sql"),
        },
        Migration {
            version: 3,
            name: "management_api",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0003_management_api.sql"),
        },
        Migration {
            version: 4,
            name: "oidc_authorization",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0004_oidc_authorization.sql"),
        },
        Migration {
            version: 5,
            name: "signing_keys",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0005_signing_keys.sql"),
        },
        Migration {
            version: 6,
            name: "login_consent",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0006_login_consent.sql"),
        },
        Migration {
            version: 7,
            name: "authentication_context",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0007_authentication_context.sql"),
        },
        Migration {
            version: 8,
            name: "redirect_registration",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0008_redirect_registration.sql"),
        },
        Migration {
            version: 9,
            name: "userinfo_claims",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0009_userinfo_claims.sql"),
        },
        Migration {
            version: 10,
            name: "consent_scope_upsert",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0010_consent_scope_upsert.sql"),
        },
        Migration {
            version: 11,
            name: "resource_servers",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0011_resource_servers.sql"),
        },
        Migration {
            version: 12,
            name: "opaque_access_tokens",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0012_opaque_access_tokens.sql"),
        },
        Migration {
            version: 13,
            name: "client_auth_suite",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0013_client_auth_suite.sql"),
        },
        Migration {
            version: 14,
            name: "dynamic_client_registration",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0014_dynamic_client_registration.sql"),
        },
        Migration {
            version: 15,
            name: "pushed_authorization_requests",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0015_pushed_authorization_requests.sql"),
        },
        Migration {
            version: 16,
            name: "refresh_tokens",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0016_refresh_tokens.sql"),
        },
        Migration {
            version: 17,
            name: "client_credentials_service_accounts",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0017_client_credentials_service_accounts.sql"),
        },
        Migration {
            version: 18,
            name: "dcr_abuse_controls",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0018_dcr_abuse_controls.sql"),
        },
        Migration {
            version: 19,
            name: "resource_indicators",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0019_resource_indicators.sql"),
        },
        Migration {
            version: 20,
            name: "jwt_bearer_assertion",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0020_jwt_bearer_assertion.sql"),
        },
        Migration {
            version: 21,
            name: "device_authorization",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0021_device_authorization.sql"),
        },
        Migration {
            version: 22,
            name: "session_model",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0022_session_model.sql"),
        },
        Migration {
            version: 23,
            name: "rp_logout",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0023_rp_logout.sql"),
        },
        Migration {
            version: 24,
            name: "session_ended_events",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0024_session_ended_events.sql"),
        },
        Migration {
            version: 25,
            name: "backchannel_logout",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0025_backchannel_logout.sql"),
        },
        Migration {
            version: 26,
            name: "frontchannel_logout",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0026_frontchannel_logout.sql"),
        },
        Migration {
            version: 27,
            name: "resource_model_apis",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0027_resource_model_apis.sql"),
        },
        Migration {
            version: 28,
            name: "envelope_encryption",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0028_envelope_encryption.sql"),
        },
        Migration {
            version: 29,
            name: "environment_guardrails",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0029_environment_guardrails.sql"),
        },
        Migration {
            version: 30,
            name: "tenant_lifecycle",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0030_tenant_lifecycle.sql"),
        },
        Migration {
            version: 31,
            name: "byok_bindings",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0031_byok_bindings.sql"),
        },
        Migration {
            version: 32,
            name: "snapshot_export",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0032_snapshot_export.sql"),
        },
        Migration {
            version: 33,
            name: "custom_domains",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0033_custom_domains.sql"),
        },
        Migration {
            version: 34,
            name: "environment_secrets_variables",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0034_environment_secrets_variables.sql"),
        },
        Migration {
            version: 35,
            name: "config_promotion",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0035_config_promotion.sql"),
        },
        Migration {
            version: 36,
            name: "self_service_account",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0036_self_service_account.sql"),
        },
        Migration {
            version: 37,
            name: "admin_user_lifecycle",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0037_admin_user_lifecycle.sql"),
        },
        Migration {
            version: 38,
            name: "identity_traits",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0038_identity_traits.sql"),
        },
        Migration {
            version: 39,
            name: "foreign_password_import",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0039_foreign_password_import.sql"),
        },
        Migration {
            version: 40,
            name: "user_invitations",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0040_user_invitations.sql"),
        },
        Migration {
            version: 41,
            name: "flexible_identifiers",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0041_flexible_identifiers.sql"),
        },
        Migration {
            version: 42,
            name: "exit_export_credentials",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0042_exit_export_credentials.sql"),
        },
        Migration {
            version: 43,
            name: "migration_runs",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0043_migration_runs.sql"),
        },
        Migration {
            version: 44,
            name: "webauthn_credentials",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0044_webauthn_credentials.sql"),
        },
        Migration {
            version: 45,
            name: "totp_credentials",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0045_totp_credentials.sql"),
        },
        Migration {
            version: 46,
            name: "credential_abuse_defenses",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0046_credential_abuse_defenses.sql"),
        },
        Migration {
            version: 47,
            name: "step_up_policies",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0047_step_up_policies.sql"),
        },
        Migration {
            version: 48,
            name: "email_otp_magic_links",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0048_email_otp_magic_links.sql"),
        },
        Migration {
            version: 49,
            name: "credential_class_policies",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0049_credential_class_policies.sql"),
        },
        Migration {
            version: 50,
            name: "sms_otp",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0050_sms_otp.sql"),
        },
        Migration {
            version: 51,
            name: "passkey_attestation",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0051_passkey_attestation.sql"),
        },
        Migration {
            version: 52,
            name: "admin_sudo_elevations",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0052_admin_sudo_elevations.sql"),
        },
        Migration {
            version: 53,
            name: "trusted_devices",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0053_trusted_devices.sql"),
        },
        Migration {
            version: 54,
            name: "risk_engine",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0054_risk_engine.sql"),
        },
        Migration {
            version: 55,
            name: "account_recovery",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0055_account_recovery.sql"),
        },
        Migration {
            version: 56,
            name: "connectors",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0056_connectors.sql"),
        },
        Migration {
            version: 57,
            name: "registration_abuse_defenses",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0057_registration_abuse_defenses.sql"),
        },
        Migration {
            version: 58,
            name: "federation_login_state",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0058_federation_login_state.sql"),
        },
        Migration {
            version: 59,
            name: "enterprise_inbound_routing",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0059_enterprise_inbound_routing.sql"),
        },
        Migration {
            version: 60,
            name: "upstream_token_vault",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0060_upstream_token_vault.sql"),
        },
        Migration {
            version: 61,
            name: "account_links",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0061_account_links.sql"),
        },
        Migration {
            version: 62,
            name: "account_linking_wiring",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0062_account_linking_wiring.sql"),
        },
        Migration {
            version: 63,
            name: "fedcm_assertion_nonces",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0063_fedcm_assertion_nonces.sql"),
        },
        Migration {
            version: 64,
            name: "third_party_risk_signals",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0064_third_party_risk_signals.sql"),
        },
        Migration {
            version: 65,
            name: "signup_fraud_review",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0065_signup_fraud_review.sql"),
        },
        Migration {
            version: 66,
            name: "advanced_recovery_modes",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0066_advanced_recovery_modes.sql"),
        },
        Migration {
            version: 67,
            name: "headless_flows",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0067_headless_flows.sql"),
        },
        Migration {
            version: 68,
            name: "branding",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0068_branding.sql"),
        },
        Migration {
            version: 69,
            name: "locale_bundles",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0069_locale_bundles.sql"),
        },
        Migration {
            version: 70,
            name: "brand_assets",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0070_brand_assets.sql"),
        },
        Migration {
            version: 71,
            name: "diagnostic_reason_detail",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0071_diagnostic_reason_detail.sql"),
        },
        Migration {
            version: 72,
            name: "diagnostics_control_read",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0072_diagnostics_control_read.sql"),
        },
        Migration {
            version: 73,
            name: "policy_decision_traces",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0073_policy_decision_traces.sql"),
        },
        Migration {
            version: 74,
            name: "flows_control_read",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0074_flows_control_read.sql"),
        },
        Migration {
            version: 75,
            name: "signup_forms",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0075_signup_forms.sql"),
        },
        Migration {
            version: 76,
            name: "consent_lockdown",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0076_consent_lockdown.sql"),
        },
        Migration {
            version: 77,
            name: "client_admin_grants",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0077_client_admin_grants.sql"),
        },
        Migration {
            version: 78,
            name: "consent_control_grants",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0078_consent_control_grants.sql"),
        },
        Migration {
            version: 79,
            name: "flow_version_pin",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0079_flow_version_pin.sql"),
        },
        Migration {
            version: 80,
            name: "flow_versions",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0080_flow_versions.sql"),
        },
        Migration {
            version: 81,
            name: "first_party_challenge_codes",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0081_first_party_challenge_codes.sql"),
        },
        Migration {
            version: 82,
            name: "dpop_binding",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0082_dpop_binding.sql"),
        },
        Migration {
            version: 83,
            name: "dpop_proof_replay",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0083_dpop_proof_replay.sql"),
        },
        Migration {
            version: 84,
            name: "org_membership",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0084_org_membership.sql"),
        },
        Migration {
            version: 85,
            name: "org_token_context",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0085_org_token_context.sql"),
        },
        Migration {
            version: 86,
            name: "org_roles",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0086_org_roles.sql"),
        },
        Migration {
            version: 87,
            name: "org_groups",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0087_org_groups.sql"),
        },
        Migration {
            version: 88,
            name: "org_group_members",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0088_org_group_members.sql"),
        },
        Migration {
            version: 89,
            name: "org_role_assignments",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0089_org_role_assignments.sql"),
        },
        Migration {
            version: 90,
            name: "org_auth_policies",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0090_org_auth_policies.sql"),
        },
        Migration {
            version: 91,
            name: "permissions",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0091_permissions.sql"),
        },
        Migration {
            version: 92,
            name: "org_role_permissions",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0092_org_role_permissions.sql"),
        },
        Migration {
            version: 93,
            name: "org_default_role",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0093_org_default_role.sql"),
        },
        Migration {
            version: 94,
            name: "resource_server_permission_claims",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0094_resource_server_permission_claims.sql"),
        },
        Migration {
            version: 95,
            name: "token_size_event_budget_columns",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0095_token_size_event_budget_columns.sql"),
        },
        Migration {
            version: 96,
            name: "client_allowed_scopes",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0096_client_allowed_scopes.sql"),
        },
        Migration {
            version: 97,
            name: "email_factor_config",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0097_email_factor_config.sql"),
        },
        Migration {
            version: 98,
            name: "control_plane_dead_surface_grants",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0098_control_plane_dead_surface_grants.sql"),
        },
        Migration {
            version: 99,
            name: "outbox_messages",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0099_outbox_messages.sql"),
        },
        Migration {
            version: 100,
            name: "environment_secret_control_writes",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0100_environment_secret_control_writes.sql"),
        },
        Migration {
            version: 101,
            name: "migration_run_control_writes",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0101_migration_run_control_writes.sql"),
        },
        Migration {
            version: 102,
            name: "outbox_retention",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0102_outbox_retention.sql"),
        },
        Migration {
            version: 103,
            name: "broker_cutover_and_policy_bounds",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0103_broker_cutover_and_policy_bounds.sql"),
        },
        Migration {
            version: 104,
            name: "user_identifier_delete_grant",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0104_user_identifier_delete_grant.sql"),
        },
        Migration {
            version: 105,
            name: "sms_otp_control_grants",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0105_sms_otp_control_grants.sql"),
        },
        Migration {
            version: 106,
            name: "column_scope_consume_latches",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0106_column_scope_consume_latches.sql"),
        },
        Migration {
            version: 107,
            name: "column_scope_remaining_app_updates",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0107_column_scope_remaining_app_updates.sql"),
        },
        Migration {
            version: 108,
            name: "revoke_unused_app_insert_delete",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0108_revoke_unused_app_insert_delete.sql"),
        },
        Migration {
            version: 109,
            name: "idempotency_key_retention",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0109_idempotency_key_retention.sql"),
        },
        Migration {
            version: 110,
            name: "step_up_policy_control_grants",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0110_step_up_policy_control_grants.sql"),
        },
        Migration {
            version: 111,
            name: "webhook_endpoints",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0111_webhook_endpoints.sql"),
        },
        Migration {
            version: 112,
            name: "webhook_secret_rotation",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0112_webhook_secret_rotation.sql"),
        },
        Migration {
            version: 113,
            name: "webhook_delivery_attempts",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0113_webhook_delivery_attempts.sql"),
        },
        Migration {
            version: 114,
            name: "webhook_auto_disable",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0114_webhook_auto_disable.sql"),
        },
        Migration {
            version: 115,
            name: "client_par_requirement_control_grant",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0115_client_par_requirement_control_grant.sql"),
        },
        Migration {
            version: 116,
            name: "webhook_event_type_filter",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0116_webhook_event_type_filter.sql"),
        },
        Migration {
            version: 117,
            name: "domain_rule_verification",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0117_domain_rule_verification.sql"),
        },
        Migration {
            version: 118,
            name: "management_credential_grants",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0118_management_credential_grants.sql"),
        },
        Migration {
            version: 119,
            name: "management_credential_org_confinement",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0119_management_credential_org_confinement.sql"),
        },
        Migration {
            version: 120,
            name: "project_grants",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0120_project_grants.sql"),
        },
        Migration {
            version: 121,
            name: "org_scoped_clients",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0121_org_scoped_clients.sql"),
        },
        Migration {
            version: 122,
            name: "org_token_lifetime",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0122_org_token_lifetime.sql"),
        },
        Migration {
            version: 123,
            name: "api_keys",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0123_api_keys.sql"),
        },
        Migration {
            version: 124,
            name: "membership_principal_arc",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0124_membership_principal_arc.sql"),
        },
        Migration {
            version: 125,
            name: "control_reads_service_account_identity",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0125_control_reads_service_account_identity.sql"),
        },
        Migration {
            version: 126,
            name: "service_account_membership_uniqueness",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0126_service_account_membership_uniqueness.sql"),
        },
        Migration {
            version: 127,
            name: "control_reads_service_account_client",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0127_control_reads_service_account_client.sql"),
        },
        Migration {
            version: 128,
            name: "impersonation_sessions",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0128_impersonation_sessions.sql"),
        },
        Migration {
            version: 129,
            name: "impersonated_refresh_families",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0129_impersonated_refresh_families.sql"),
        },
        Migration {
            version: 130,
            name: "impersonation_authorizations",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0130_impersonation_authorizations.sql"),
        },
        Migration {
            version: 131,
            name: "user_trait_login_index",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0131_user_trait_login_index.sql"),
        },
        Migration {
            version: 132,
            name: "backfill_login_index_job_kind",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0132_backfill_login_index_job_kind.sql"),
        },
        Migration {
            version: 133,
            name: "audit_stream",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0133_audit_stream.sql"),
        },
        Migration {
            version: 134,
            name: "audit_stream_backfill",
            phase: Phase::Migrate,
            sql: include_str!("../migrations/0134_audit_stream_backfill.sql"),
        },
        Migration {
            version: 135,
            name: "audit_chain",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0135_audit_chain.sql"),
        },
        Migration {
            version: 136,
            name: "audit_retention_role",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0136_audit_retention_role.sql"),
        },
        Migration {
            version: 137,
            name: "log_streams",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0137_log_streams.sql"),
        },
        Migration {
            version: 138,
            name: "audit_organization",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0138_audit_organization.sql"),
        },
        Migration {
            version: 139,
            name: "log_stream_organization",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0139_log_stream_organization.sql"),
        },
        Migration {
            version: 140,
            name: "log_stream_dead_letters",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0140_log_stream_dead_letters.sql"),
        },
        Migration {
            version: 141,
            name: "authorization_code_dpop",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0141_authorization_code_dpop.sql"),
        },
        Migration {
            version: 142,
            name: "client_allow_bearer_tokens",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0142_client_allow_bearer_tokens.sql"),
        },
        Migration {
            version: 143,
            name: "client_token_exchange_policy",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0143_client_token_exchange_policy.sql"),
        },
        Migration {
            version: 144,
            name: "log_stream_signing_secret",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0144_log_stream_signing_secret.sql"),
        },
        Migration {
            version: 145,
            name: "message_templates",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0145_message_templates.sql"),
        },
        Migration {
            version: 146,
            name: "flow_targets",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0146_flow_targets.sql"),
        },
        Migration {
            version: 147,
            name: "backchannel_authentication",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0147_backchannel_authentication.sql"),
        },
        Migration {
            version: 148,
            name: "client_backchannel_delivery",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0148_client_backchannel_delivery.sql"),
        },
        Migration {
            version: 149,
            name: "external_issuer_audience_allow",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0149_external_issuer_audience_allow.sql"),
        },
        Migration {
            version: 150,
            name: "scope_fk_naming",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0150_scope_fk_naming.sql"),
        },
        Migration {
            version: 151,
            name: "backchannel_approved_requires_grant",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0151_backchannel_approved_requires_grant.sql"),
        },
        Migration {
            version: 152,
            name: "backchannel_approved_grant_validated",
            phase: Phase::Expand,
            sql: include_str!("../migrations/0152_backchannel_approved_grant_validated.sql"),
        },
    ]
}

/// The fixed key for the migration advisory lock. A session-level Postgres
/// advisory lock on this key serializes concurrent runners: during a rolling
/// upgrade several replicas may call the runner at once, and without this the
/// losers would race to create the same objects and fail their boot with a raw
/// "relation already exists" error. The value is the ASCII bytes of "IRONAUTH"
/// (fixed and process independent, so every runner contends on the same key).
const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x4952_4F4E_4155_5448;

/// Applies an ordered, checksummed migration chain against a Postgres pool.
///
/// Build it with [`MigrationRunner::new`] for the real IronAuth chain, or with
/// [`MigrationRunner::from_migrations`] to drive a custom chain (the migration
/// framework's own tests do this against a throwaway database). The pool must
/// authenticate as a role that owns the schema (never the low-privilege
/// application role): migrations run DDL and GRANTs.
pub struct MigrationRunner<'a> {
    pool: &'a PgPool,
    migrations: Vec<Migration>,
}

impl<'a> MigrationRunner<'a> {
    /// A runner for IronAuth's real migration chain.
    #[must_use]
    pub fn new(pool: &'a PgPool) -> Self {
        Self {
            pool,
            migrations: registry(),
        }
    }

    /// A runner for an explicit migration chain (test and tooling use).
    #[must_use]
    pub fn from_migrations(pool: &'a PgPool, migrations: Vec<Migration>) -> Self {
        Self { pool, migrations }
    }

    /// Apply every pending migration in order, recording each in the ledger.
    ///
    /// # Errors
    ///
    /// [`MigrationError::NotSorted`] if the registry is not strictly ascending;
    /// [`MigrationError::OutOfOrder`] if a higher version is already applied
    /// while a lower one is pending; [`MigrationError::ChecksumMismatch`] if an
    /// already-applied migration's text changed; [`MigrationError::UnknownApplied`]
    /// if the ledger names a version this build does not have;
    /// [`MigrationError::Database`] on any database failure. On refusal nothing
    /// is applied.
    pub async fn run(&self) -> Result<MigrationReport, MigrationError> {
        // 1. The registry must be strictly ascending by version. Checked in
        //    memory before any connection is touched.
        let mut prev: Option<i64> = None;
        for migration in &self.migrations {
            if prev.is_some_and(|p| migration.version <= p) {
                return Err(MigrationError::NotSorted {
                    version: migration.version,
                });
            }
            prev = Some(migration.version);
        }

        // Serialize concurrent runners (the rolling-upgrade boot race) with a
        // SESSION-level Postgres advisory lock on a dedicated connection. A
        // session advisory lock on a POOLED connection is NOT released when the
        // connection returns to the pool, so we MUST unlock explicitly on every
        // path: acquire, lock, run the ledger logic capturing its result, then
        // ALWAYS unlock before returning (no `?` between lock and unlock skips
        // it). While one runner holds the lock, others block at pg_advisory_lock
        // and, on acquiring it, find the chain already applied.
        let mut lock_conn = self.pool.acquire().await?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(MIGRATION_ADVISORY_LOCK_KEY)
            .execute(&mut *lock_conn)
            .await?;

        let result = self.run_locked().await;

        let unlock = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(MIGRATION_ADVISORY_LOCK_KEY)
            .execute(&mut *lock_conn)
            .await;

        match result {
            // The run succeeded: surface an unlock failure if one occurred, so a
            // stuck lock is never hidden behind a success.
            Ok(report) => {
                unlock?;
                Ok(report)
            }
            // The run failed: return its (more informative) error. The unlock was
            // still attempted above regardless.
            Err(error) => Err(error),
        }
    }

    /// The ledger logic (steps 2 to 6), run while holding the migration advisory
    /// lock. Kept exactly as the reviewed-correct ordering, checksum, and apply
    /// logic; only the surrounding serialization is new.
    async fn run_locked(&self) -> Result<MigrationReport, MigrationError> {
        // 2. Ensure the ledger exists before consulting it.
        sqlx::query(CREATE_LEDGER_SQL).execute(self.pool).await?;

        // 3. Load the applied set: version -> recorded checksum.
        let rows = sqlx::query("SELECT version, checksum FROM _schema_migrations ORDER BY version")
            .fetch_all(self.pool)
            .await?;
        let mut applied: BTreeMap<i64, String> = BTreeMap::new();
        for row in &rows {
            applied.insert(row.get("version"), row.get("checksum"));
        }

        // 4. Tamper and drift: every applied version must be known to this build
        //    and its recorded checksum must still match the migration text.
        for (&version, recorded) in &applied {
            let Some(migration) = self.migrations.iter().find(|m| m.version == version) else {
                return Err(MigrationError::UnknownApplied { version });
            };
            if &migration.checksum() != recorded {
                return Err(MigrationError::ChecksumMismatch { version });
            }
        }

        // 5. Ordering: walking ascending, once a version is pending, no later
        //    version may already be applied.
        let mut first_pending: Option<i64> = None;
        for migration in &self.migrations {
            let is_applied = applied.contains_key(&migration.version);
            match (first_pending, is_applied) {
                (None, false) => first_pending = Some(migration.version),
                (Some(missing), true) => {
                    return Err(MigrationError::OutOfOrder {
                        applied: migration.version,
                        missing,
                    });
                }
                _ => {}
            }
        }

        // 6. Apply each pending migration in order, atomically with its ledger
        //    row: a failure rolls back both, so a partial migration is never
        //    recorded as applied.
        let mut newly_applied = Vec::new();
        for migration in &self.migrations {
            if applied.contains_key(&migration.version) {
                continue;
            }
            let mut tx = self.pool.begin().await?;
            sqlx::raw_sql(migration.sql).execute(&mut *tx).await?;
            sqlx::query(
                "INSERT INTO _schema_migrations (version, name, checksum, phase) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(migration.version)
            .bind(migration.name)
            .bind(migration.checksum())
            .bind(migration.phase.as_str())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            newly_applied.push(migration.version);
        }

        Ok(MigrationReport {
            newly_applied,
            already_applied: applied.len(),
        })
    }
}

/// The registry against the directory it embeds from (issue #446).
///
/// [`registry`] is private, so these live inside the crate rather than in
/// `tests/`. They are pure file reads and need no database.
#[cfg(test)]
mod registry_matches_the_migrations_directory {
    use super::registry;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    /// The directory [`super::registry`] embeds from, resolved from the crate
    /// root rather than the process working directory, so the result does not
    /// depend on where the test runner was invoked from.
    fn migrations_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations")
    }

    /// Every file name in the migrations directory, whatever its extension.
    ///
    /// Deliberately unfiltered: filtering to `*.sql` here would hide exactly the
    /// mistakes `only_sql_files_live_in_the_migrations_directory` is there to
    /// catch, such as a `0099_thing.sql.bak` left behind by an editor.
    fn file_names_on_disk() -> BTreeSet<String> {
        let dir = migrations_dir();
        std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read the migrations directory {}: {e}", dir.display()))
            .map(|entry| {
                entry
                    .expect("read a migrations directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// The file name a registry entry claims, derived from the two fields the
    /// ledger records. This is the naming convention the whole chain follows:
    /// a zero-padded four-digit version, an underscore, the name, `.sql`.
    fn expected_file_name(version: i64, name: &str) -> String {
        format!("{version:04}_{name}.sql")
    }

    /// Whether a directory entry is a migration SQL file, by EXTENSION rather than
    /// by suffix, so `0099_thing.sql.bak` is a stray rather than a migration.
    fn is_sql(name: &str) -> bool {
        std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("sql"))
    }

    /// The registry's own file names.
    fn file_names_in_registry() -> BTreeSet<String> {
        registry()
            .iter()
            .map(|m| expected_file_name(m.version, m.name))
            .collect()
    }

    #[test]
    fn every_sql_file_on_disk_is_registered() {
        // The #446 direction: a `.sql` file added to the directory and never
        // wired into registry() is not in the chain, and neither the hardcoded
        // chain count nor the live ledger can see it, because it never reaches
        // the ledger at all.
        let registered = file_names_in_registry();
        let unregistered: Vec<String> = file_names_on_disk()
            .into_iter()
            .filter(|f| is_sql(f) && !registered.contains(f))
            .collect();
        assert!(
            unregistered.is_empty(),
            "these migration files exist on disk but are in no registry() entry, so they are \
             NOT in the shipped chain and would never run: {unregistered:?}. Add a Migration \
             entry for each in crates/ironauth-store/src/migrate.rs, or delete the file."
        );
    }

    #[test]
    fn every_registered_migration_has_its_file_on_disk() {
        // The other direction. A missing file is a compile error today (the
        // include_str! would not resolve), but a RENAME is not: renaming both
        // the file and the include_str! path while leaving `name` or `version`
        // stale still compiles, and this is what says so.
        let on_disk = file_names_on_disk();
        let missing: Vec<String> = file_names_in_registry()
            .into_iter()
            .filter(|f| !on_disk.contains(f))
            .collect();
        assert!(
            missing.is_empty(),
            "these registry() entries name a file that is not in \
             crates/ironauth-store/migrations: {missing:?}. A registry entry's version and name \
             must derive its file name exactly (NNNN_name.sql)."
        );
    }

    #[test]
    fn every_registered_migration_embeds_the_file_its_version_and_name_derive() {
        // Stronger than comparing the two SETS, and the reason the sets are
        // compared by DERIVED name rather than by the include_str! literal: an
        // entry whose path points at a DIFFERENT (also registered) file passes
        // both set comparisons, because both names are present on both sides.
        // Comparing embedded text against the derived path catches it.
        let dir = migrations_dir();
        for migration in registry() {
            let expected = expected_file_name(migration.version, migration.name);
            let path = dir.join(&expected);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            assert_eq!(
                migration.sql, on_disk,
                "version {} ({}) embeds text that is not the contents of {expected}; its \
                 include_str! path does not match its version and name",
                migration.version, migration.name
            );
        }
    }

    #[test]
    fn registry_versions_are_contiguous_from_one() {
        // run() already refuses a chain that is not strictly ascending, but it
        // cannot object to a GAP: skipping a number is silent there and is the
        // other easy mistake when adding a migration. A gap also breaks the
        // derived file name of everything a human counts by eye.
        let versions: Vec<i64> = registry().iter().map(|m| m.version).collect();
        let expected: Vec<i64> =
            (1..=i64::try_from(versions.len()).expect("chain length fits i64")).collect();
        assert_eq!(
            versions, expected,
            "migration versions must be 1..=N with no gaps, no duplicates, and in ascending order"
        );
    }

    #[test]
    fn only_sql_files_live_in_the_migrations_directory() {
        // Without this, `every_sql_file_on_disk_is_registered` is evadable by
        // accident: a stray `0099_thing.sql.bak` or `.sql.tmp` is not a `.sql`
        // file, so that test skips it, and a reader scanning the directory sees
        // a migration that is not in the chain.
        let strays: Vec<String> = file_names_on_disk()
            .into_iter()
            .filter(|f| !is_sql(f))
            .collect();
        assert!(
            strays.is_empty(),
            "crates/ironauth-store/migrations holds only migration SQL; these do not belong \
             and would be skipped by the registration check: {strays:?}"
        );
    }
}
