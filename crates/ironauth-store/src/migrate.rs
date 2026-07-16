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
