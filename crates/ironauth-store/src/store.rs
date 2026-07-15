// SPDX-License-Identifier: MIT OR Apache-2.0

//! The connection handle and the sole entry point to scoped repositories.
//!
//! [`Store`] owns the Postgres pool. The pool is a private field: no code
//! outside this crate can reach a raw connection to a tenant-scoped table, and
//! within the crate only [`crate::repository`] is allowed to (enforced by
//! `scripts/query-audit.sh`). The only way to touch a scoped table is
//! [`Store::scoped`], which demands a [`Scope`] and hands back repositories
//! that carry it.

use std::sync::Arc;

use ironauth_jose::MasterKey;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::error::StoreError;
use crate::migrate::MigrationRunner;
use crate::repository::{ManagementStore, ScopedStore};
use crate::scope::Scope;

/// The database handle. Cheap to clone (the pool is reference counted).
#[derive(Clone)]
pub struct Store {
    // Private on purpose. Reaching a scoped table requires `scoped(scope)`;
    // there is no accessor that hands out the raw pool to other crates.
    pool: PgPool,
    // The platform envelope master key (issue #48), when configured. It wraps
    // per-tenant KEKs and drives the blind-index derivation, so the store can seal
    // classified PII columns (users.identifier, users.claims) at rest and still look
    // a user up by identifier. It is `None` only where no encrypted-PII path runs
    // (a migration-owner or control-plane handle, or a store built before a key is
    // wired); the PII read/write paths then FAIL CLOSED rather than fall back to
    // plaintext. Never logged, displayed, or serialized (the key redacts itself).
    master: Option<Arc<MasterKey>>,
}

impl Store {
    /// Connect to Postgres at `url` with a bounded pool.
    ///
    /// In production `url` should authenticate as the low-privilege
    /// application role (never a superuser and never the table owner), so the
    /// forced row-level-security policies always apply beneath the repository
    /// layer.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] if the pool cannot be established.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(url)
            .await?;
        Ok(Self { pool, master: None })
    }

    /// Build a store from a pool the caller already configured (for example a
    /// pool shared with other subsystems, or the low-privilege pool the test
    /// harness injects). The pool stays private after construction; this does
    /// not widen access to scoped tables.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool, master: None }
    }

    /// Attach the platform envelope master key (issue #48), enabling the encrypted
    /// PII paths (sealing and blind-indexing users.identifier / users.claims). A
    /// handle without a key fails those paths closed, so wire this on every store
    /// that serves the login, registration, or `UserInfo` surface. Consumes and
    /// returns `self` so it composes with the constructors
    /// (`Store::connect(url).await?.with_master_key(key)`).
    #[must_use]
    pub fn with_master_key(mut self, master: Arc<MasterKey>) -> Self {
        self.master = Some(master);
        self
    }

    /// The pool, for the repository layer only. Crate-private so no other crate
    /// can issue an unscoped query against a scoped table.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The configured platform master key, for the repository layer only. `None`
    /// when no key is wired (the encrypted-PII paths then fail closed).
    pub(crate) fn master(&self) -> Option<&MasterKey> {
        self.master.as_deref()
    }

    /// Apply the full IronAuth migration chain to bring the schema current.
    ///
    /// Runs the runtime [`MigrationRunner`] over the two production migrations:
    /// the four-level isolation tables and policies (version 1) and the
    /// same-transaction audit log (version 2). The runner tracks applied
    /// migrations in a `_schema_migrations` ledger, applies each pending one in
    /// order inside its own transaction, serializes concurrent runners with a
    /// session advisory lock, and refuses out-of-order, checksum-drifted, or
    /// unknown-version application. It is idempotent: on an up-to-date database
    /// it applies nothing. Only the runtime sqlx API is used (no `migrate!`
    /// macro), so nothing here needs a database at build time.
    ///
    /// The pool must authenticate as a schema-owning role (never the
    /// low-privilege application role): migrations run DDL and GRANTs. The
    /// `ironauth_app` role must already exist so the grants resolve; it is
    /// provisioned out of band in production and by the test harness in tests.
    ///
    /// # Errors
    ///
    /// [`StoreError::Migration`] if the migration chain cannot be applied or is
    /// refused (out of order, checksum mismatch); [`StoreError::Database`] on a
    /// connection failure.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        MigrationRunner::new(&self.pool).run().await?;
        Ok(())
    }

    /// Enter a tenant-and-environment scope. This is the only door to the
    /// scoped repositories; every query they run is filtered by `scope`, which
    /// the caller can neither omit nor override per call.
    #[must_use]
    pub fn scoped(&self, scope: Scope) -> ScopedStore<'_> {
        ScopedStore::new(self, scope)
    }

    /// Enter the management (control) plane (issue #11). The door to the
    /// operator, tenant, environment, and management-credential repositories the
    /// data-plane [`Store::scoped`] cannot reach.
    ///
    /// In production the pool behind this store must authenticate as
    /// `ironauth_control`, NOT `ironauth_app`: control-plane credentials are a
    /// distinct class from data-plane keys, so construct a SEPARATE [`Store`]
    /// (from a separate pool) for each plane, and the `management_credentials`
    /// FORCE row-level-security backstop then applies to the control role too. The
    /// binary selects that DSN from `admin.control_database_url`; a `dev_mode`
    /// fallback to `database.url` is possible, in which case the role separation
    /// and that backstop are not enforced. Management mutations reuse the same
    /// audited-write primitive, so every one writes its audit row in the same
    /// transaction.
    #[must_use]
    pub fn management(&self) -> ManagementStore<'_> {
        ManagementStore::new(self)
    }
}
