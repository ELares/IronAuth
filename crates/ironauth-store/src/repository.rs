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
//! then commits. Every public mutator ([`ActingClientRepo::create`],
//! [`ActingClientRepo::delete`], and every future one) is a thin wrapper over it,
//! so a mutation cannot commit without its audit row and a failed mutation
//! commits neither.
//!
//! This module is the enforcement boundary, and the enforcement is at the
//! crate/API level rather than a language-level impossibility. Outside this
//! module nothing can reach a scoped table at all: the pool is crate private,
//! module visibility blocks other crates, `scripts/query-audit.sh` fails the
//! build on scoped-table SQL anywhere else, and Postgres row-level security sits
//! beneath all of it. So no caller can commit a scoped write off the audited
//! path. Within this one module the discipline is a reviewed invariant: a future
//! in-module mutator must route through [`write_audited`] rather than commit its
//! own transaction. Keeping the committing write path a single private function
//! is what makes that invariant a one-line review rather than a per-handler
//! audit. This is enforcement by construction at the module boundary, not
//! handler discipline spread across the codebase.

use std::time::SystemTime;

use ironauth_env::Env;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};

use crate::audit::{ActingContext, Action, ActorRef};
use crate::error::StoreError;
use crate::id::{
    AuditId, AuditTarget, ClientId, CorrelationId, EnvironmentId, ManagementKeyId, OperatorId,
    TenantId,
};
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
        // Exact microsecond read-back requires PostgreSQL 14+, where
        // EXTRACT(EPOCH FROM timestamptz) returns numeric (exact). On older
        // versions it returns double precision and can round by +/- 1 us; the
        // stored value is exact regardless (it is written as an integer
        // microsecond interval), so this only affects the read-back precision.
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
/// the envelope's action and typed target. The target is any [`AuditTarget`], so
/// a management mutation on a level table (a tenant, an environment) audits
/// through the same primitive as a scoped-resource mutation.
struct AuditedWrite<'a, T: AuditTarget> {
    store: &'a Store,
    scope: Scope,
    acting: &'a ActingContext,
    env: &'a Env,
    action: Action,
    target: &'a T,
}

/// The single committing write path: perform a data mutation and its audit row
/// in one scoped transaction, then commit.
///
/// This is the whole enforcement mechanism. `mutate` runs the caller's data
/// change; [`insert_audit_row`] appends exactly one audit row in the same
/// transaction; only then does the transaction commit. If `mutate` fails, the
/// audit row is never written and nothing commits; if the audit insert fails,
/// the data change never commits. This is the single committing write path in
/// the module, so a mutation without its audit row cannot be committed off it
/// (the module boundary that protects that invariant is described on the module
/// documentation).
///
/// `poison_after_audit` is `false` on every production path; the testing
/// atomicity probe sets it to force a guaranteed in-transaction failure after
/// both inserts, to demonstrate they roll back together.
async fn write_audited<T, M>(
    spec: AuditedWrite<'_, T>,
    mutate: M,
    poison_after_audit: bool,
) -> Result<(), StoreError>
where
    T: AuditTarget,
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
async fn insert_audit_row<T: AuditTarget>(
    tx: &mut Transaction<'_, Postgres>,
    spec: &AuditedWrite<'_, T>,
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
    .bind(spec.target.audit_target_kind())
    .bind(spec.target.audit_target_id())
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

// ===========================================================================
// Management (control) plane (issue #11).
//
// The management API mutates the operator, tenant, and environment LEVEL tables
// the data-plane role cannot see, plus the environment-scoped
// `management_credentials` table. Everything below routes through the SAME
// `write_audited` primitive, so every management mutation writes its audit row
// in the same transaction as the data change; a management mutation without its
// audit row is as structurally impossible as a data-plane one.
//
// These repositories are reached only through [`Store::management`], whose pool
// must authenticate as `ironauth_control`. The data-plane [`Store::scoped`] and
// its pool stay entirely separate: control-plane credentials are a distinct
// class from data-plane keys, made real at the pool boundary.
// ===========================================================================

/// The maximum number of rows any management list query returns in one call.
/// The management API caps the caller-supplied page size below this; this is a
/// last-resort ceiling so an internal caller cannot ask for an unbounded scan.
const MANAGEMENT_LIST_HARD_CAP: i64 = 1000;

/// A cursor position for keyset pagination: the `(created_at, id)` of the last
/// row of the previous page. Ordering is by `created_at` then `id`, both stable
/// and total, so paging never loses or duplicates a row.
#[derive(Debug, Clone)]
pub struct CursorPosition {
    /// The `created_at` of the last row of the previous page, in microseconds
    /// since the Unix epoch.
    pub created_at_unix_micros: i64,
    /// The identifier of the last row of the previous page, in wire form.
    pub id: String,
}

/// The original response stored under an Idempotency-Key, replayed verbatim when
/// the same key is presented again so the mutation never runs twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdempotentResponse {
    /// Hash of the original request (method, path, body). A replay whose request
    /// fingerprint differs is a key reused for a different operation.
    pub request_fingerprint: String,
    /// The original HTTP status code.
    pub response_status: u16,
    /// The original response body, replayed byte for byte.
    pub response_body: String,
}

/// A pending Idempotency-Key record, written in the same transaction as the
/// mutation it guards so a stored response and its side effects commit together.
#[derive(Debug, Clone, Copy)]
pub struct IdempotencyWrite<'a> {
    /// The acting credential's audit-actor id (the isolation key here).
    pub credential_ref: &'a str,
    /// The client-supplied Idempotency-Key header value.
    pub key: &'a str,
    /// Hash of the request (method, path, body).
    pub request_fingerprint: &'a str,
    /// The status the caller is about to return.
    pub response_status: u16,
    /// The body the caller is about to return, stored for verbatim replay.
    pub response_body: &'a str,
}

/// A tenant row (management plane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRecord {
    /// The tenant identifier.
    pub id: TenantId,
    /// The operator that owns the tenant.
    pub operator_id: OperatorId,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// An environment row (management plane).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentRecord {
    /// The environment identifier.
    pub id: EnvironmentId,
    /// The tenant the environment belongs to.
    pub tenant_id: TenantId,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// A management API key row (metadata only; the secret is never stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementCredentialRecord {
    /// The key identifier (embeds its `(tenant, environment)` scope).
    pub id: ManagementKeyId,
    /// The human-facing display name.
    pub display_name: String,
    /// Creation time in microseconds since the Unix epoch (the pagination key).
    pub created_at_unix_micros: i64,
}

/// The control-plane entry point: reads and the acting door for writes.
///
/// Reached through [`Store::management`]. Its pool must authenticate as
/// `ironauth_control`.
pub struct ManagementStore<'a> {
    store: &'a Store,
}

impl<'a> ManagementStore<'a> {
    /// Bind the control plane to a store. Crate-internal: callers reach this
    /// only through [`Store::management`].
    pub(crate) fn new(store: &'a Store) -> Self {
        Self { store }
    }

    /// The read-only tenant repository under `operator`.
    #[must_use]
    pub fn tenants(&self, operator: OperatorId) -> TenantRepo<'a> {
        TenantRepo {
            store: self.store,
            operator,
        }
    }

    /// The read-only environment repository under `tenant`.
    #[must_use]
    pub fn environments(&self, tenant: TenantId) -> EnvironmentRepo<'a> {
        EnvironmentRepo {
            store: self.store,
            tenant,
        }
    }

    /// The read-only management-credential repository for `scope`.
    #[must_use]
    pub fn credentials(&self, scope: Scope) -> ManagementCredentialRepo<'a> {
        ManagementCredentialRepo {
            store: self.store,
            scope,
        }
    }

    /// The idempotency replay store (credential-scoped).
    #[must_use]
    pub fn idempotency(&self) -> IdempotencyRepo<'a> {
        IdempotencyRepo { store: self.store }
    }

    /// Enter an acting context for management writes. Every mutation reached
    /// through the returned store carries an actor and correlation id into its
    /// audit row.
    #[must_use]
    pub fn acting(&self, actor: ActorRef, correlation: CorrelationId) -> ActingManagementStore<'a> {
        ActingManagementStore {
            store: self.store,
            acting: ActingContext::new(actor, correlation),
        }
    }
}

/// The acting door to the mutating management repositories.
pub struct ActingManagementStore<'a> {
    store: &'a Store,
    acting: ActingContext,
}

impl<'a> ActingManagementStore<'a> {
    /// The mutating tenant repository under `operator`.
    #[must_use]
    pub fn tenants(&self, operator: OperatorId) -> ActingTenantRepo<'a> {
        ActingTenantRepo {
            store: self.store,
            acting: self.acting,
            operator,
        }
    }

    /// The mutating environment repository under `tenant`.
    #[must_use]
    pub fn environments(&self, tenant: TenantId) -> ActingEnvironmentRepo<'a> {
        ActingEnvironmentRepo {
            store: self.store,
            acting: self.acting,
            tenant,
        }
    }

    /// The mutating management-credential repository for `scope`.
    #[must_use]
    pub fn credentials(&self, scope: Scope) -> ActingManagementCredentialRepo<'a> {
        ActingManagementCredentialRepo {
            store: self.store,
            acting: self.acting,
            scope,
        }
    }
}

/// Read-only tenants under one operator.
pub struct TenantRepo<'a> {
    store: &'a Store,
    operator: OperatorId,
}

impl TenantRepo<'_> {
    /// Parse an untrusted tenant identifier. A malformed identifier is the
    /// uniform not-found, exactly like an absent one.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed.
    pub fn parse_id(&self, raw: &str) -> Result<TenantId, StoreError> {
        TenantId::parse(raw).map_err(|_| StoreError::NotFound)
    }

    /// Fetch a live tenant under this operator.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live tenant exists under this operator
    /// (absent, deactivated, or owned by another operator: indistinguishable).
    pub async fn get(&self, id: &TenantId) -> Result<TenantRecord, StoreError> {
        let row = sqlx::query(
            "SELECT id, operator_id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM tenants \
             WHERE id = $1 AND operator_id = $2 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.operator.to_string())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(StoreError::NotFound)?;
        tenant_from_row(&row)
    }

    /// One page of live tenants under this operator, ordered by `(created_at,
    /// id)`. Returns up to `limit` rows starting strictly after `after`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<TenantRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let rows = sqlx::query(
            "SELECT id, operator_id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM tenants \
             WHERE operator_id = $1 AND deleted_at IS NULL \
             AND ($2::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval, $3::text)) \
             ORDER BY created_at, id LIMIT $4",
        )
        .bind(self.operator.to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP))
        .fetch_all(self.store.pool())
        .await?;
        rows.iter().map(tenant_from_row).collect()
    }
}

/// Read-only environments under one tenant.
pub struct EnvironmentRepo<'a> {
    store: &'a Store,
    tenant: TenantId,
}

impl EnvironmentRepo<'_> {
    /// Parse an untrusted environment identifier. A malformed identifier is the
    /// uniform not-found, exactly like an absent or cross-tenant one.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the identifier is malformed.
    pub fn parse_id(&self, raw: &str) -> Result<EnvironmentId, StoreError> {
        EnvironmentId::parse(raw).map_err(|_| StoreError::NotFound)
    }

    /// Fetch a live environment under this tenant. An environment of ANOTHER
    /// tenant is the uniform not-found (the tenant filter is the anti-oracle).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live environment exists under this
    /// tenant.
    pub async fn get(&self, id: &EnvironmentId) -> Result<EnvironmentRecord, StoreError> {
        let row = sqlx::query(
            "SELECT id, tenant_id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM environments \
             WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.tenant.to_string())
        .fetch_optional(self.store.pool())
        .await?
        .ok_or(StoreError::NotFound)?;
        environment_from_row(&row)
    }

    /// One page of live environments under this tenant, ordered by `(created_at,
    /// id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<EnvironmentRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let rows = sqlx::query(
            "SELECT id, tenant_id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM environments \
             WHERE tenant_id = $1 AND deleted_at IS NULL \
             AND ($2::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($2::text || ' microseconds')::interval, $3::text)) \
             ORDER BY created_at, id LIMIT $4",
        )
        .bind(self.tenant.to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP))
        .fetch_all(self.store.pool())
        .await?;
        rows.iter().map(environment_from_row).collect()
    }
}

/// Read-only management credentials for one scope.
pub struct ManagementCredentialRepo<'a> {
    store: &'a Store,
    scope: Scope,
}

impl ManagementCredentialRepo<'_> {
    /// Parse an untrusted management-key identifier under this scope. A malformed
    /// identifier and one minted in another scope both return the uniform
    /// not-found.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if malformed or out of scope.
    pub fn parse_id(&self, raw: &str) -> Result<ManagementKeyId, StoreError> {
        Ok(ManagementKeyId::parse_in_scope(raw, &self.scope)?)
    }

    /// Fetch a live management key by id, within scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no such live key is visible in this scope.
    pub async fn get(
        &self,
        id: &ManagementKeyId,
    ) -> Result<ManagementCredentialRecord, StoreError> {
        if id.scope() != self.scope {
            return Err(StoreError::NotFound);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM management_credentials \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let row = row.ok_or(StoreError::NotFound)?;
        credential_from_row(&row, &self.scope)
    }

    /// One page of live management keys in this scope, ordered by `(created_at,
    /// id)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn list(
        &self,
        limit: i64,
        after: Option<&CursorPosition>,
    ) -> Result<Vec<ManagementCredentialRecord>, StoreError> {
        let (after_micros, after_id) = split_cursor(after);
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let rows = sqlx::query(
            "SELECT id, display_name, \
             (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_us \
             FROM management_credentials \
             WHERE tenant_id = $1 AND environment_id = $2 AND deleted_at IS NULL \
             AND ($3::bigint IS NULL OR (created_at, id) > \
                  (TIMESTAMPTZ 'epoch' + ($3::text || ' microseconds')::interval, $4::text)) \
             ORDER BY created_at, id LIMIT $5",
        )
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(after_micros)
        .bind(after_id)
        .bind(limit.clamp(0, MANAGEMENT_LIST_HARD_CAP))
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.iter()
            .map(|row| credential_from_row(row, &self.scope))
            .collect()
    }

    /// Whether a live key with `id` and this exact `key_hash` exists in scope.
    /// The authentication primitive: the caller has already recovered the scope
    /// from the presented token's id half, so this look-up runs within it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn authenticate(
        &self,
        id: &ManagementKeyId,
        key_hash: &str,
    ) -> Result<bool, StoreError> {
        if id.scope() != self.scope {
            return Ok(false);
        }
        let mut tx = begin_scoped(self.store, self.scope).await?;
        let row = sqlx::query(
            "SELECT 1 AS ok FROM management_credentials \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3 \
             AND key_hash = $4 AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .bind(self.scope.tenant().to_string())
        .bind(self.scope.environment().to_string())
        .bind(key_hash)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.is_some())
    }
}

/// The idempotency replay store (credential-scoped). See the migration for why
/// isolation here is by credential rather than tenant row-level security.
pub struct IdempotencyRepo<'a> {
    store: &'a Store,
}

impl IdempotencyRepo<'_> {
    /// Look up a stored response for `(credential_ref, key)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn lookup(
        &self,
        credential_ref: &str,
        key: &str,
    ) -> Result<Option<StoredIdempotentResponse>, StoreError> {
        let row = sqlx::query(
            "SELECT request_fingerprint, response_status, response_body \
             FROM idempotency_keys \
             WHERE credential_ref = $1 AND idempotency_key = $2",
        )
        .bind(credential_ref)
        .bind(key)
        .fetch_optional(self.store.pool())
        .await?;
        Ok(row.map(|row| {
            let status: i32 = row.get("response_status");
            StoredIdempotentResponse {
                request_fingerprint: row.get("request_fingerprint"),
                response_status: u16::try_from(status).unwrap_or(500),
                response_body: row.get("response_body"),
            }
        }))
    }
}

/// Mutating tenants under one operator.
pub struct ActingTenantRepo<'a> {
    store: &'a Store,
    acting: ActingContext,
    operator: OperatorId,
}

impl ActingTenantRepo<'_> {
    /// Create a tenant and its first environment in one transaction, and audit
    /// the creation scoped to `(new_tenant, new_first_environment)`.
    ///
    /// The operator-plane audit wrinkle: an operator-plane "create tenant" has no
    /// pre-existing `(tenant, environment)` scope to key the audit row on. It is
    /// resolved exactly as the design mandates: the tenant AND its first
    /// environment are created in the same transaction, then the audit row is
    /// written scoped to that fresh `(tenant, environment)` pair (both rows exist
    /// by the time the audit insert runs, so its foreign keys and the row-level
    /// security check are satisfied). The bootstrap operator row is ensured
    /// idempotently in the same transaction (platform self-bootstrap, not a
    /// caller mutation, so it is not itself audited).
    ///
    /// The identifiers are supplied by the caller (minted from the entropy seam)
    /// so the HTTP response can be built before the write and stored verbatim for
    /// idempotent replay.
    ///
    /// # Errors
    ///
    /// [`StoreError::IdempotencyConflict`] if a concurrent request already stored
    /// this Idempotency-Key; [`StoreError::Database`] on a persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        env: &Env,
        tenant_id: &TenantId,
        environment_id: &EnvironmentId,
        created_at_micros: i64,
        operator_display_name: &str,
        tenant_display_name: &str,
        environment_display_name: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let scope = Scope::new(*tenant_id, *environment_id);
        let operator = self.operator;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TenantCreate,
                target: tenant_id,
            },
            async move |tx| {
                // Ensure the (well-known) bootstrap operator exists so the tenant
                // foreign key resolves. Idempotent and not audited: this is the
                // platform bootstrapping itself, like a migration, not a
                // caller-visible mutation.
                sqlx::query(
                    "INSERT INTO operators (id, display_name) VALUES ($1, $2) \
                     ON CONFLICT (id) DO NOTHING",
                )
                .bind(operator.to_string())
                .bind(operator_display_name)
                .execute(&mut **tx)
                .await?;
                // created_at is bound from the application clock seam (not the
                // database clock), so the response body built before the write
                // matches the stored row exactly and paging stays deterministic
                // under a manual clock in tests.
                sqlx::query(
                    "INSERT INTO tenants (id, operator_id, display_name, created_at) \
                     VALUES ($1, $2, $3, \
                             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval)",
                )
                .bind(tenant_id.to_string())
                .bind(operator.to_string())
                .bind(tenant_display_name)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                sqlx::query(
                    "INSERT INTO environments (id, tenant_id, display_name, created_at) \
                     VALUES ($1, $2, $3, \
                             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval)",
                )
                .bind(environment_id.to_string())
                .bind(tenant_id.to_string())
                .bind(environment_display_name)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Deactivate a tenant (soft delete) and audit it scoped to the tenant and
    /// its oldest environment (which is retained, so the audit foreign key
    /// holds).
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live tenant matched under this operator.
    pub async fn delete(&self, env: &Env, id: &TenantId) -> Result<(), StoreError> {
        // The audit scope needs an environment of this tenant; pick the oldest
        // (it is retained through soft delete, so its row satisfies the audit
        // foreign key). A tenant always has its first environment.
        let scope_env = sqlx::query(
            "SELECT id FROM environments WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 1",
        )
        .bind(id.to_string())
        .fetch_optional(self.store.pool())
        .await?;
        let Some(scope_env) = scope_env else {
            return Err(StoreError::NotFound);
        };
        let environment = EnvironmentId::parse(&scope_env.get::<String, _>("id"))
            .map_err(|e| StoreError::Database(sqlx::Error::Decode(Box::new(e))))?;
        let scope = Scope::new(*id, environment);
        let operator = self.operator;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::TenantDelete,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE tenants SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND operator_id = $3 AND deleted_at IS NULL",
                )
                .bind(epoch_micros(env.clock().now_utc()))
                .bind(id.to_string())
                .bind(operator.to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }
}

/// Mutating environments under one tenant.
pub struct ActingEnvironmentRepo<'a> {
    store: &'a Store,
    acting: ActingContext,
    tenant: TenantId,
}

impl ActingEnvironmentRepo<'_> {
    /// Create an environment under this tenant, audited scoped to `(tenant,
    /// new_environment)`.
    ///
    /// # Errors
    ///
    /// [`StoreError::IdempotencyConflict`] on a concurrent Idempotency-Key race;
    /// [`StoreError::Database`] on a persistence failure (including a missing
    /// tenant, which surfaces as the tenant foreign-key violation).
    pub async fn create(
        &self,
        env: &Env,
        environment_id: &EnvironmentId,
        created_at_micros: i64,
        display_name: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
        let scope = Scope::new(self.tenant, *environment_id);
        let tenant = self.tenant;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentCreate,
                target: environment_id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO environments (id, tenant_id, display_name, created_at) \
                     VALUES ($1, $2, $3, \
                             TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval)",
                )
                .bind(environment_id.to_string())
                .bind(tenant.to_string())
                .bind(display_name)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Deactivate an environment (soft delete) under this tenant, audited scoped
    /// to `(tenant, environment)`. The row is retained, so the audit foreign key
    /// holds.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live environment matched under this tenant.
    pub async fn delete(&self, env: &Env, id: &EnvironmentId) -> Result<(), StoreError> {
        let scope = Scope::new(self.tenant, *id);
        let tenant = self.tenant;
        write_audited(
            AuditedWrite {
                store: self.store,
                scope,
                acting: &self.acting,
                env,
                action: Action::EnvironmentDelete,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE environments SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL",
                )
                .bind(epoch_micros(env.clock().now_utc()))
                .bind(id.to_string())
                .bind(tenant.to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }
}

/// Mutating management credentials for one scope.
pub struct ActingManagementCredentialRepo<'a> {
    store: &'a Store,
    acting: ActingContext,
    scope: Scope,
}

impl ActingManagementCredentialRepo<'_> {
    /// Mint a management key: store the key HASH (never the secret) and audit
    /// `management_key.create` in the same transaction, scoped to this scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::IdempotencyConflict`] on a concurrent Idempotency-Key race;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn create(
        &self,
        env: &Env,
        id: &ManagementKeyId,
        created_at_micros: i64,
        key_hash: &str,
        display_name: &str,
        idempotency: Option<IdempotencyWrite<'_>>,
    ) -> Result<(), StoreError> {
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
                action: Action::ManagementKeyCreate,
                target: id,
            },
            async move |tx| {
                sqlx::query(
                    "INSERT INTO management_credentials \
                     (id, tenant_id, environment_id, key_hash, display_name, created_at) \
                     VALUES ($1, $2, $3, $4, $5, \
                             TIMESTAMPTZ 'epoch' + ($6::text || ' microseconds')::interval)",
                )
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .bind(key_hash)
                .bind(display_name)
                .bind(created_at_micros)
                .execute(&mut **tx)
                .await?;
                insert_idempotency(tx, idempotency).await?;
                Ok(())
            },
            false,
        )
        .await
    }

    /// Revoke a management key (soft delete) and audit `management_key.delete`.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if no live key matched in this scope.
    pub async fn delete(&self, env: &Env, id: &ManagementKeyId) -> Result<(), StoreError> {
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
                action: Action::ManagementKeyDelete,
                target: id,
            },
            async move |tx| {
                let result = sqlx::query(
                    "UPDATE management_credentials SET deleted_at = \
                     TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval \
                     WHERE id = $2 AND tenant_id = $3 AND environment_id = $4 \
                     AND deleted_at IS NULL",
                )
                .bind(epoch_micros(env.clock().now_utc()))
                .bind(id.to_string())
                .bind(scope.tenant().to_string())
                .bind(scope.environment().to_string())
                .execute(&mut **tx)
                .await?;
                if result.rows_affected() == 0 {
                    return Err(StoreError::NotFound);
                }
                Ok(())
            },
            false,
        )
        .await
    }
}

/// Insert a pending idempotency row, if the caller supplied one. A primary-key
/// collision (a concurrent request already stored this key) surfaces as the
/// distinct [`StoreError::IdempotencyConflict`] so the caller can re-read and
/// replay rather than double-execute.
async fn insert_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    idempotency: Option<IdempotencyWrite<'_>>,
) -> Result<(), StoreError> {
    let Some(idem) = idempotency else {
        return Ok(());
    };
    let result = sqlx::query(
        "INSERT INTO idempotency_keys \
         (credential_ref, idempotency_key, request_fingerprint, response_status, response_body) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(idem.credential_ref)
    .bind(idem.key)
    .bind(idem.request_fingerprint)
    .bind(i32::from(idem.response_status))
    .bind(idem.response_body)
    .execute(&mut **tx)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if is_idempotency_conflict(&error) => Err(StoreError::IdempotencyConflict),
        Err(error) => Err(error.into()),
    }
}

/// Whether a database error is a primary-key collision on `idempotency_keys`.
fn is_idempotency_conflict(error: &sqlx::Error) -> bool {
    let Some(db) = error.as_database_error() else {
        return false;
    };
    db.code().as_deref() == Some("23505") && db.constraint() == Some("idempotency_keys_pkey")
}

/// Split an optional cursor into its bound parameters (both `None` when absent).
fn split_cursor(after: Option<&CursorPosition>) -> (Option<i64>, Option<String>) {
    match after {
        Some(cursor) => (Some(cursor.created_at_unix_micros), Some(cursor.id.clone())),
        None => (None, None),
    }
}

/// Reconstruct a [`TenantRecord`] from a row.
fn tenant_from_row(row: &PgRow) -> Result<TenantRecord, StoreError> {
    let decode =
        |e: crate::id::IdParseError| StoreError::Database(sqlx::Error::Decode(Box::new(e)));
    Ok(TenantRecord {
        id: TenantId::parse(&row.get::<String, _>("id")).map_err(decode)?,
        operator_id: OperatorId::parse(&row.get::<String, _>("operator_id")).map_err(decode)?,
        display_name: row.get("display_name"),
        created_at_unix_micros: row.get("created_us"),
    })
}

/// Reconstruct an [`EnvironmentRecord`] from a row.
fn environment_from_row(row: &PgRow) -> Result<EnvironmentRecord, StoreError> {
    let decode =
        |e: crate::id::IdParseError| StoreError::Database(sqlx::Error::Decode(Box::new(e)));
    Ok(EnvironmentRecord {
        id: EnvironmentId::parse(&row.get::<String, _>("id")).map_err(decode)?,
        tenant_id: TenantId::parse(&row.get::<String, _>("tenant_id")).map_err(decode)?,
        display_name: row.get("display_name"),
        created_at_unix_micros: row.get("created_us"),
    })
}

/// Reconstruct a [`ManagementCredentialRecord`] from a row read within scope.
fn credential_from_row(
    row: &PgRow,
    scope: &Scope,
) -> Result<ManagementCredentialRecord, StoreError> {
    let id_text: String = row.get("id");
    let id = ManagementKeyId::parse_in_scope(&id_text, scope)?;
    Ok(ManagementCredentialRecord {
        id,
        display_name: row.get("display_name"),
        created_at_unix_micros: row.get("created_us"),
    })
}
