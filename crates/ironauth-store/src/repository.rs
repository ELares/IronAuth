// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scoped repositories: the only path to tenant-scoped tables.
//!
//! Everything in this module is constructed *from* a [`Scope`] and applies that
//! scope to every query itself. A caller can neither omit the scope nor pass a
//! different tenant per call, so a cross-tenant read is not expressible. This
//! is the compile-time half of the isolation model; every method also sets the
//! transaction-local row-level-security session variables, so the database
//! enforces the same boundary a third time beneath the application.
//!
//! This is the single module permitted to name a tenant-scoped table in SQL.
//! `scripts/query-audit.sh` fails the build if a scoped-table query appears in
//! any other source file, closing the raw-pool bypass that module visibility
//! already blocks across crates.
//!
//! Each operation runs inside a transaction that first binds
//! `ironauth.tenant_id` and `ironauth.environment_id` with `set_config(..,
//! true)` (transaction-local). The policies in the migration read those
//! variables, so an unset scope sees nothing (deny by default) and a set scope
//! sees only its own rows. The explicit `WHERE tenant_id = .. AND
//! environment_id = ..` clauses are the application-layer belt; row-level
//! security is the suspenders.

use ironauth_env::Env;
use sqlx::{Postgres, Row, Transaction};

use crate::error::StoreError;
use crate::id::ClientId;
use crate::scope::Scope;
use crate::store::Store;

/// A store bound to one `(tenant, environment)` scope. Hands out the per-kind
/// repositories, each already carrying the scope.
pub struct ScopedStore<'a> {
    store: &'a Store,
    scope: Scope,
}

impl<'a> ScopedStore<'a> {
    /// Bind a store to a scope. Crate-internal: callers reach this only through
    /// [`Store::scoped`], which is what makes the scope non-optional.
    pub(crate) fn new(store: &'a Store, scope: Scope) -> Self {
        Self { store, scope }
    }

    /// The OAuth client repository for this scope.
    #[must_use]
    pub fn clients(&self) -> ClientRepo<'a> {
        ClientRepo {
            store: self.store,
            scope: self.scope,
        }
    }
}

/// A record read back from the `clients` table, always within scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    /// The client identifier (embeds its tenant and environment).
    pub id: ClientId,
    /// The human-facing display name.
    pub display_name: String,
}

/// The repository for tenant-scoped OAuth clients.
///
/// There is no constructor that takes a tenant or environment argument, and no
/// query method accepts one: the scope is fixed at construction and applied to
/// every statement. That is the whole point, and the compile-fail tests prove
/// it cannot be circumvented.
pub struct ClientRepo<'a> {
    // Both fields private: no crate can retarget the scope or reach the pool.
    store: &'a Store,
    scope: Scope,
}

impl ClientRepo<'_> {
    /// Begin a transaction with the scope's row-level-security variables bound
    /// transaction-locally. Every operation flows through here, so no statement
    /// runs without the policy variables in place.
    async fn begin_scoped(&self) -> Result<Transaction<'_, Postgres>, StoreError> {
        let mut tx = self.store.pool().begin().await?;
        // set_config(name, value, is_local=true): parameterized and reset at
        // transaction end. SET LOCAL cannot take a bind parameter, so this is
        // the injection-safe form.
        sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
            .bind(self.scope.tenant().to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
            .bind(self.scope.environment().to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Parse an untrusted client identifier under this repository's scope.
    ///
    /// This is the oracle-free boundary for request handlers: a malformed
    /// identifier and one belonging to another tenant both return the uniform
    /// [`StoreError::NotFound`].
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<ClientId, StoreError> {
        Ok(ClientId::parse_in_scope(raw, &self.scope)?)
    }

    /// Create a client in this scope and return its fresh identifier.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create(&self, env: &Env, display_name: &str) -> Result<ClientId, StoreError> {
        let id = ClientId::generate(env, &self.scope);
        let mut tx = self.begin_scoped().await?;
        sqlx::query(
            "INSERT INTO clients (id, tenant_id, environment_id, display_name) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(display_name)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Fetch a client by identifier, within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope
    /// (absent, or belonging to another tenant or environment: the outcomes are
    /// indistinguishable).
    pub async fn get(&self, id: &ClientId) -> Result<ClientRecord, StoreError> {
        // Defense in depth: an identifier minted under another scope is a miss
        // here regardless of what the database would say.
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = self.begin_scoped().await?;
        let row = sqlx::query(
            "SELECT id, display_name FROM clients \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        self.row_to_record(&row)
    }

    /// List every client in this scope, oldest first.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(&self) -> Result<Vec<ClientRecord>, StoreError> {
        let mut tx = self.begin_scoped().await?;
        let rows = sqlx::query(
            "SELECT id, display_name FROM clients \
             WHERE tenant_id = $1 AND environment_id = $2 ORDER BY created_at, id",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter().map(|row| self.row_to_record(row)).collect()
    }

    /// Delete a client by identifier, within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope.
    pub async fn delete(&self, id: &ClientId) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = self.begin_scoped().await?;
        let result = sqlx::query(
            "DELETE FROM clients WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Turn a row into a [`ClientRecord`], reconstructing the typed identifier.
    fn row_to_record(&self, row: &sqlx::postgres::PgRow) -> Result<ClientRecord, StoreError> {
        let id_text: String = row.get("id");
        // The row came back through the scope filter and row-level security, so
        // it is in scope by construction; re-parse to the typed identifier.
        let id = ClientId::parse_in_scope(&id_text, &self.scope)?;
        Ok(ClientRecord {
            id,
            display_name: row.get("display_name"),
        })
    }
}
