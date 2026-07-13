// SPDX-License-Identifier: MIT OR Apache-2.0

//! The connection handle and the sole entry point to scoped repositories.
//!
//! [`Store`] owns the Postgres pool. The pool is a private field: no code
//! outside this crate can reach a raw connection to a tenant-scoped table, and
//! within the crate only [`crate::repository`] is allowed to (enforced by
//! `scripts/query-audit.sh`). The only way to touch a scoped table is
//! [`Store::scoped`], which demands a [`Scope`] and hands back repositories
//! that carry it.

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::error::StoreError;
use crate::repository::ScopedStore;
use crate::scope::Scope;

/// The minimal isolation schema, embedded at build time so no `migrations/`
/// directory has to travel with the binary and no database is touched to
/// compile. Applied by [`Store::migrate`].
const MIGRATION_SQL: &str = include_str!("../migrations/0001_tenant_isolation.sql");

/// The database handle. Cheap to clone (the pool is reference counted).
#[derive(Clone)]
pub struct Store {
    // Private on purpose. Reaching a scoped table requires `scoped(scope)`;
    // there is no accessor that hands out the raw pool to other crates.
    pool: PgPool,
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
        Ok(Self { pool })
    }

    /// Build a store from a pool the caller already configured (for example a
    /// pool shared with other subsystems, or the low-privilege pool the test
    /// harness injects). The pool stays private after construction; this does
    /// not widen access to scoped tables.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool, for the repository layer only. Crate-private so no other crate
    /// can issue an unscoped query against a scoped table.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply the minimal schema this issue needs: the four-level tables, the
    /// forced row-level-security policies, and the low-privilege application
    /// role and grants.
    ///
    /// This is intentionally minimal. The full expand-contract migration
    /// framework and the same-transaction audit log are owned by the relational
    /// primary store issue (#7); this ships only what tenant isolation (#6)
    /// requires. The schema is embedded with `include_str!` and applied via the
    /// runtime API (no `query!`/`migrate!` macros), so nothing here needs a
    /// database at build time. It is idempotent enough for a fresh database and
    /// a shared cluster's per-test databases (the role guard); the full
    /// re-runnable, versioned migration bookkeeping is #7's.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] if the schema fails to apply.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::raw_sql(MIGRATION_SQL).execute(&self.pool).await?;
        Ok(())
    }

    /// Enter a tenant-and-environment scope. This is the only door to the
    /// scoped repositories; every query they run is filtered by `scope`, which
    /// the caller can neither omit nor override per call.
    #[must_use]
    pub fn scoped(&self, scope: Scope) -> ScopedStore<'_> {
        ScopedStore::new(self, scope)
    }
}
