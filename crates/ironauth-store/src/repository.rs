// SPDX-License-Identifier: MIT OR Apache-2.0

//! Scoped repositories: the only path to tenant-scoped tables, and the single
//! audited-write primitive every mutation must flow through.
//!
//! Everything in this module is constructed *from* a [`Scope`] and applies that
//! scope to every query itself. A caller can neither omit the scope nor pass a
//! different tenant per call, so a cross-tenant read is not expressible. This
//! is the compile-time half of the isolation model; every method also sets the
//! transaction-local row-level-security session variables, so the database
//! enforces the same boundary a third time beneath the application.
//!
//! This is the single module permitted to name a tenant-scoped table in SQL
//! (`clients`, `organizations`, `audit_log`). `scripts/query-audit.sh` fails the
//! build if a scoped-table query appears in any other source file, closing the
//! raw-pool bypass that module visibility already blocks across crates.
//!
//! # Reads versus writes
//!
//! Reads ([`ClientRepo`], [`AuditRepo`]) need no actor. Writes do: a mutation is
//! only reachable through [`ScopedStore::acting`], which demands an
//! [`ActorRef`] and a [`CorrelationId`]. So the acting context is required at the
//! type level for every write and for no read.
//!
//! # The audited-write primitive
//!
//! Every mutation routes through the single private [`write_audited`] function.
//! It opens one scoped transaction, runs the caller's data change, writes
//! exactly one [`audit_log`](crate::audit) row in that same transaction, and only
//! then commits. There is no other committing write path: the public mutators
//! ([`ActingClientRepo::create`], [`ActingClientRepo::delete`], and every future
//! one) are thin wrappers over it. A mutation therefore cannot commit without its
//! audit row, and a failed mutation commits neither. This is enforcement by
//! construction, not handler discipline: nothing a caller can write bypasses the
//! audited path, because the only place that commits a data change is the place
//! that also writes the audit row.

use std::time::SystemTime;

use ironauth_env::Env;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};

use crate::audit::{ActingContext, Action, ActorRef};
use crate::error::StoreError;
use crate::id::{AuditId, ClientId, CorrelationId, ScopedId, ScopedKind};
use crate::scope::Scope;
use crate::store::Store;

/// A store bound to one `(tenant, environment)` scope. Hands out the per-kind
/// read repositories, and the acting entry point for writes.
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

    /// The read-only OAuth client repository for this scope. Reads need no
    /// actor; to create or delete, go through [`ScopedStore::acting`].
    #[must_use]
    pub fn clients(&self) -> ClientRepo<'a> {
        ClientRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// The read-only audit-log repository for this scope. The log is append-only:
    /// rows are written only by the audited-write primitive, and this reads them
    /// back within scope.
    #[must_use]
    pub fn audit(&self) -> AuditRepo<'a> {
        AuditRepo {
            store: self.store,
            scope: self.scope,
        }
    }

    /// Enter an acting context (who is acting, and under which correlation id).
    /// The returned store hands out the *mutating* repositories, so every write
    /// carries an actor and a correlation id into its audit row.
    #[must_use]
    pub fn acting(&self, actor: ActorRef, correlation: CorrelationId) -> ActingStore<'a> {
        ActingStore {
            store: self.store,
            scope: self.scope,
            acting: ActingContext::new(actor, correlation),
        }
    }
}

/// A scope-and-actor bound store: the door to the mutating repositories.
pub struct ActingStore<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl<'a> ActingStore<'a> {
    /// The mutating OAuth client repository for this scope and actor.
    #[must_use]
    pub fn clients(&self) -> ActingClientRepo<'a> {
        ActingClientRepo {
            store: self.store,
            scope: self.scope,
            acting: self.acting,
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

/// The read-only repository for tenant-scoped OAuth clients.
///
/// The scope is fixed at construction and applied to every statement; there is
/// no constructor or method that takes a tenant or environment argument. Writes
/// live on [`ActingClientRepo`], reachable only with an acting context.
pub struct ClientRepo<'a> {
    // Both fields private: no crate can retarget the scope or reach the pool.
    store: &'a Store,
    scope: Scope,
}

impl ClientRepo<'_> {
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
        let mut tx = begin_scoped(self.store, self.scope).await?;
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
        let mut tx = begin_scoped(self.store, self.scope).await?;
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

    /// Turn a row into a [`ClientRecord`], reconstructing the typed identifier.
    fn row_to_record(&self, row: &PgRow) -> Result<ClientRecord, StoreError> {
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

/// The mutating repository for tenant-scoped OAuth clients.
///
/// Reachable only through [`ScopedStore::acting`], so every mutation carries an
/// actor and correlation id. Its mutators do not commit their own transactions;
/// they route through the module's single audited-write primitive, which is the
/// only committing write path and always writes the audit row in the same
/// transaction.
pub struct ActingClientRepo<'a> {
    store: &'a Store,
    scope: Scope,
    acting: ActingContext,
}

impl ActingClientRepo<'_> {
    /// Create a client in this scope and return its fresh identifier. Writes a
    /// `client.create` audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create(&self, env: &Env, display_name: &str) -> Result<ClientId, StoreError> {
        self.create_inner(env, display_name, false).await
    }

    /// Delete a client by identifier, within scope. Writes a `client.delete`
    /// audit row in the same transaction; a no-op delete (nothing in scope
    /// matched) writes no audit row and rolls back.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such client is visible in this scope.
    pub async fn delete(&self, env: &Env, id: &ClientId) -> Result<(), StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientDelete,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "DELETE FROM clients \
                     WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                // A delete that matched nothing is a uniform not-found. Erroring
                // here short-circuits the audited write before the audit insert,
                // so a no-op delete leaves no audit row (we audit real mutations).
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }

    /// Shared body of the client-create path. `poison_after_audit` is always
    /// `false` for the public mutator; the testing-only atomicity probe passes
    /// `true` to force a rollback after the data and audit inserts.
    async fn create_inner(
        &self,
        env: &Env,
        display_name: &str,
        poison_after_audit: bool,
    ) -> Result<ClientId, StoreError> {
        let id = ClientId::generate(env, &self.scope);
        let scope = self.scope;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::ClientCreate,
                target: &id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO clients (id, tenant_id, environment_id, display_name) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(display_name)
                .execute(&mut **tx)
                .await?;
                Ok(())
            },
            poison_after_audit,
        )
        .await?;
        Ok(id)
    }

    /// Testing-only atomicity probe: run a real `create` (the client insert and
    /// its audit insert), then force a guaranteed error inside the same
    /// transaction, so a test can assert that neither the client row nor the
    /// audit row survives. This exercises the exact production write path plus a
    /// trailing poison statement; the public [`create`](Self::create) never
    /// poisons. It always returns an error.
    ///
    /// # Errors
    ///
    /// Always errors (that is the point): the injected failure rolls the whole
    /// transaction back.
    #[cfg(feature = "testing")]
    pub async fn create_injecting_post_audit_failure(
        &self,
        env: &Env,
        display_name: &str,
    ) -> Result<ClientId, StoreError> {
        self.create_inner(env, display_name, true).await
    }
}

/// A record read back from the `audit_log` table, always within scope. The full
/// mutation envelope: who acted, what they did, on which resource, under which
/// request, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The audit event identifier (embeds its tenant and environment).
    pub id: AuditId,
    /// The action string, for example `client.create`.
    pub action: String,
    /// The acting principal.
    pub actor: ActorRef,
    /// The typed-prefix kind of the target resource, for example `cli`.
    pub target_kind: String,
    /// The target resource identifier in wire form.
    pub target_id: String,
    /// The correlation id of the request that caused the mutation.
    pub correlation_id: CorrelationId,
    /// The event time in microseconds since the Unix epoch, as recorded from the
    /// application clock seam at mutation time.
    pub occurred_at_unix_micros: i64,
}

/// The read-only repository for the append-only audit log.
pub struct AuditRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl AuditRepo<'_> {
    /// Every audit row in this scope, oldest first.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure, or if a stored row
    /// fails to decode into the typed envelope.
    pub async fn list(&self) -> Result<Vec<AuditRecord>, StoreError> {
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, action, actor_kind, actor_id, target_kind, target_id, \
             correlation_id, \
             (EXTRACT(EPOCH FROM occurred_at) * 1000000)::bigint AS occurred_us \
             FROM audit_log \
             WHERE tenant_id = $1 AND environment_id = $2 \
             ORDER BY occurred_at, recorded_at, id",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| self.row_to_audit_record(row))
            .collect()
    }

    /// Reconstruct a typed [`AuditRecord`] from a row read within scope.
    fn row_to_audit_record(&self, row: &PgRow) -> Result<AuditRecord, StoreError> {
        let id_text: String = row.get("id");
        let id = AuditId::parse_in_scope(&id_text, &self.scope)?;
        let actor_kind: String = row.get("actor_kind");
        let actor_id: String = row.get("actor_id");
        let actor = ActorRef::from_parts(&actor_kind, &actor_id)
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let correlation_text: String = row.get("correlation_id");
        let correlation_id = CorrelationId::parse(&correlation_text)
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        Ok(AuditRecord {
            id,
            action: row.get("action"),
            actor,
            target_kind: row.get("target_kind"),
            target_id: row.get("target_id"),
            correlation_id,
            occurred_at_unix_micros: row.get("occurred_us"),
        })
    }
}

/// Begin a transaction with the scope's row-level-security variables bound
/// transaction-locally. Every scoped operation flows through here, so no
/// statement runs without the policy variables in place.
async fn begin_scoped(
    store: &Store,
    scope: Scope,
) -> Result<Transaction<'_, Postgres>, StoreError> {
    let mut tx = store.pool().begin().await?;
    // set_config(name, value, is_local=true): parameterized and reset at
    // transaction end. SET LOCAL cannot take a bind parameter, so this is the
    // injection-safe form.
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

/// Everything the audited-write primitive needs besides the mutation itself:
/// the connection, the scope, the acting context, the clock/entropy seam, and
/// the envelope's action and typed target.
struct AuditedWrite<'a, K: ScopedKind> {
    store: &'a Store,
    scope: Scope,
    acting: &'a ActingContext,
    env: &'a Env,
    action: Action,
    target: &'a ScopedId<K>,
}

/// The single committing write path: perform a data mutation and its audit row
/// in one scoped transaction, then commit.
///
/// This is the whole enforcement mechanism. `mutate` runs the caller's data
/// change; [`insert_audit_row`] appends exactly one audit row in the same
/// transaction; only then does the transaction commit. If `mutate` fails, the
/// audit row is never written and nothing commits; if the audit insert fails,
/// the data change never commits. There is no code path that commits a data
/// change without also committing its audit row, so "a mutation without an audit
/// row" is unrepresentable rather than merely discouraged.
///
/// `poison_after_audit` is `false` on every production path; the testing
/// atomicity probe sets it to force a guaranteed in-transaction failure after
/// both inserts, to demonstrate they roll back together.
async fn write_audited<K, M>(
    spec: AuditedWrite<'_, K>,
    mutate: M,
    poison_after_audit: bool,
) -> Result<(), StoreError>
where
    K: ScopedKind,
    M: AsyncFnOnce(&mut Transaction<'_, Postgres>) -> Result<(), StoreError>,
{
    let mut tx = begin_scoped(spec.store, spec.scope).await?;
    // The data change and the audit row share this one transaction.
    mutate(&mut tx).await?;
    insert_audit_row(&mut tx, &spec).await?;
    if poison_after_audit {
        // Testing seam only (production callers pass false): force a guaranteed
        // error after both inserts are staged, so their joint rollback proves
        // the data change and the audit row are in the same transaction.
        sqlx::query("SELECT 1 / 0").execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Insert exactly one audit row into the current transaction. Called only by
/// [`write_audited`], after the data change and before the commit.
async fn insert_audit_row<K: ScopedKind>(
    tx: &mut Transaction<'_, Postgres>,
    spec: &AuditedWrite<'_, K>,
) -> Result<(), StoreError> {
    let audit_id = AuditId::generate(spec.env, &spec.scope);
    // Event time from the application clock seam, never the database clock, so
    // it is deterministic under a manual clock in tests. Bound as microseconds
    // since the epoch and reconstructed exactly as a timestamptz in SQL.
    let occurred_micros = epoch_micros(spec.env.clock().now_utc());
    let actor = spec.acting.actor();
    sqlx::query(
        "INSERT INTO audit_log \
         (id, tenant_id, environment_id, action, actor_kind, actor_id, \
          target_kind, target_id, correlation_id, occurred_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, \
                 TIMESTAMPTZ 'epoch' + ($10::text || ' microseconds')::interval)",
    )
    .bind(audit_id.to_string())
    .bind(spec.scope.tenant().to_string())
    .bind(spec.scope.environment().to_string())
    .bind(spec.action.as_str())
    .bind(actor.kind_str())
    .bind(actor.id_string())
    .bind(K::PREFIX)
    .bind(spec.target.to_string())
    .bind(spec.acting.correlation().to_string())
    .bind(occurred_micros)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Microseconds since the Unix epoch for a wall-clock instant. Negative for
/// pre-epoch times (never reached in practice; kept total for safety).
fn epoch_micros(at: SystemTime) -> i64 {
    match at.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_micros()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_micros()).map_or(i64::MIN, |micros| -micros)
        }
    }
}
