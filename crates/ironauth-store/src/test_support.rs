// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real-database test harness (feature `testing`).
//!
//! Gives the RLS and IDOR integration tests a real Postgres to run against. It
//! is deliberately dependency-light: it drives a Postgres reached through
//! `DATABASE_URL` and adds no crate beyond sqlx, so the whole workspace stays
//! permissive-licensed, MSRV-1.85, and musl clean.
//!
//! `DATABASE_URL` must name a superuser or owner connection (the harness
//! creates a fresh per-run database and provisions the low-privilege role).
//! `scripts/with-test-db.sh` brings up a throwaway local Postgres and exports
//! `DATABASE_URL` for you; CI points it at a Postgres service. The tests fail
//! loudly if it is unset: an isolation test must never silently skip.
//!
//! Every run gets a fresh database, the minimal isolation schema applied, and
//! two handles:
//!
//! - [`TestDatabase::store`] / [`TestDatabase::app_pool`] authenticate as the
//!   low-privilege `ironauth_app` role (never a superuser, never the table
//!   owner), so forced row-level security genuinely applies. This is what the
//!   RLS test probes against.
//! - [`TestDatabase::owner_pool`] authenticates as the connection `DATABASE_URL`
//!   supplies and exists only to seed the operator, tenant, and environment
//!   level tables (which carry no per-tenant row-level security).
//!
//! This harness is the reusable substrate; future crates depend on
//! `ironauth-store` with `features = ["testing"]` and reuse it.

use std::sync::Arc;

use ironauth_env::{Env, FixedEntropy};
use ironauth_jose::MasterKey;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::audit::ActorRef;
use crate::id::{EnvironmentId, HumanId, OperatorId, TenantId};
use crate::scope::Scope;
use crate::store::Store;

/// The low-privilege data-plane role the migration grants to.
const APP_ROLE: &str = "ironauth_app";

/// The low-privilege control-plane role the management-API migration grants to
/// (issue #11). A peer of [`APP_ROLE`], never a superset: still never a
/// superuser and never a table owner, so forced row-level security applies.
const CONTROL_ROLE: &str = "ironauth_control";

/// A fresh, isolated database plus the handles the isolation tests need.
///
/// Cloning shares the same throwaway database and the same pools (every pool handle is
/// `Arc`-backed), which is what lets a test hold the database across a simulated
/// process restart. The database itself is torn down by the harness script, not by a
/// `Drop`, so a clone can never pull it out from under a live handle.
#[derive(Clone)]
pub struct TestDatabase {
    owner_pool: PgPool,
    app_pool: PgPool,
    control_pool: PgPool,
    store: Store,
    control_store: Store,
    /// The data-plane connection URL, kept so a test can open a BRAND-NEW pool against
    /// the SAME database and rebuild its process-level state from nothing: the
    /// rolling-restart simulation (issue #32 AC 1).
    app_url: String,
    /// The platform envelope master key (issue #48), shared across every data-plane
    /// handle this database hands out (including a simulated restart), so encrypted
    /// PII sealed by one handle reads back through another. Deterministic (a fixed
    /// entropy seed) so a run is reproducible; a fresh database per run means one
    /// shared key across databases is harmless.
    master: Arc<MasterKey>,
}

impl TestDatabase {
    /// Bring up a fresh database with the isolation schema applied.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if `DATABASE_URL` is unset or the
    /// database cannot be created or migrated. An isolation test that cannot
    /// reach a real database must fail loudly, never silently skip.
    pub async fn start() -> Self {
        let owner_base = std::env::var("DATABASE_URL").expect(
            "DATABASE_URL must point at a Postgres superuser/owner connection for the \
             isolation tests; scripts/with-test-db.sh starts a throwaway one and exports it",
        );
        let (host, port) = host_port_of(&owner_base);
        let db_name = format!("ironauth_test_{}", unique_suffix());

        // Fresh database per run: no cross-test state, no recycled rows.
        create_database(&owner_base, &db_name).await;

        let owner_url = swap_database(&owner_base, &db_name);
        let owner_pool = PgPool::connect(&owner_url)
            .await
            .expect("connect as owner to fresh database");

        // Provision the low-privilege roles BEFORE applying the schema: the
        // migrations GRANT to these roles but deliberately neither create them
        // nor ship a password (see the migration headers). This is test-only -- a
        // throwaway credential for a throwaway cluster -- and production
        // provisions the roles out of band instead. Both the data-plane
        // (`ironauth_app`) and the control-plane (`ironauth_control`, issue #11)
        // roles are provisioned the same race-safe way.
        provision_role(&owner_pool, APP_ROLE).await;
        provision_role(&owner_pool, CONTROL_ROLE).await;

        // Apply the schema (tables, forced RLS, policies, and the grants to the
        // roles provisioned above) as the owner.
        Store::from_pool(owner_pool.clone())
            .migrate()
            .await
            .expect("apply isolation migrations");

        // The data-plane handles authenticate as the low-privilege app role, so
        // they are subject to row-level security exactly as production is.
        let app_url = format!("postgres://{APP_ROLE}:{APP_ROLE}@{host}:{port}/{db_name}");
        // One platform master key for the whole database, so every data-plane
        // handle seals and opens PII under the same key (issue #48).
        let master = Arc::new(MasterKey::generate(
            "master-test",
            &FixedEntropy::new(0x4841_5348),
        ));

        let app_pool = PgPool::connect(&app_url)
            .await
            .expect("connect as low-privilege app role");
        let store = Store::from_pool(app_pool.clone()).with_master_key(master.clone());

        // The control-plane handle authenticates as the SEPARATE control role;
        // its pool is distinct from the data-plane pool, mirroring production
        // where the two credential classes never share a connection.
        let control_url =
            format!("postgres://{CONTROL_ROLE}:{CONTROL_ROLE}@{host}:{port}/{db_name}");
        let control_pool = PgPool::connect(&control_url)
            .await
            .expect("connect as low-privilege control role");
        let control_store = Store::from_pool(control_pool.clone());

        Self {
            owner_pool,
            app_pool,
            control_pool,
            store,
            control_store,
            app_url,
            master,
        }
    }

    /// The platform envelope master key wired into this database's data-plane
    /// handles (issue #48). A test that builds its OWN data-plane [`Store`] (a
    /// second simulated node) must attach THIS key with
    /// [`Store::with_master_key`] so it seals and opens PII compatibly.
    #[must_use]
    pub fn master_key(&self) -> Arc<MasterKey> {
        self.master.clone()
    }

    /// Open a BRAND-NEW data-plane pool against the SAME database and wrap it in a NEW
    /// [`Store`]: a node restart, simulated.
    ///
    /// Nothing in-process survives this (new pool, new connections, new `Store`), while
    /// Postgres keeps every row. It is what lets a test prove the milestone's first
    /// acceptance criterion: sessions are AUTHORITATIVE in Postgres, with no
    /// in-memory-only authoritative state, so a rolling restart loses no sessions.
    ///
    /// # Panics
    ///
    /// Panics if the new connection cannot be established.
    pub async fn restart_app_store(&self) -> Store {
        let pool = PgPool::connect(&self.app_url)
            .await
            .expect("reconnect as low-privilege app role after a simulated restart");
        Store::from_pool(pool).with_master_key(self.master.clone())
    }

    /// The store bound to the low-privilege application role. Repository
    /// operations run through here.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// A data-plane [`Store`] over a FRESH pool sized for a concurrency storm.
    ///
    /// The default per-run pool (10 connections) would serialize a many-way storm of
    /// concurrent writers and blunt the very race the concurrency tests exist to catch,
    /// so those tests build a WIDER pool (still well under the server's connection cap)
    /// and share it: the pool is `Arc`-backed, so cloning the returned [`Store`] into
    /// each spawned task hands out connections from the SAME bounded set rather than
    /// opening a new pool per task. Authenticates as the same low-privilege app role as
    /// [`TestDatabase::store`], so forced row-level security still applies.
    ///
    /// # Panics
    ///
    /// Panics if the wider pool cannot be established.
    pub async fn app_store_with_pool(&self, max_connections: u32) -> Store {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&self.app_url)
            .await
            .expect("build a wider data-plane pool for the concurrency storm");
        Store::from_pool(pool).with_master_key(self.master.clone())
    }

    /// The store bound to the low-privilege control-plane role (issue #11).
    /// Management-plane repository operations run through here; its pool is
    /// distinct from the data-plane [`TestDatabase::store`] pool.
    #[must_use]
    pub fn control_store(&self) -> &Store {
        &self.control_store
    }

    /// A raw pool as the low-privilege application role. The RLS test uses it to
    /// issue adversarial SQL directly, bypassing the repository's app-layer
    /// filter, and prove row-level security still holds.
    #[must_use]
    pub fn app_pool(&self) -> &PgPool {
        &self.app_pool
    }

    /// A raw pool as the low-privilege control-plane role. For adversarial SQL
    /// that proves row-level security holds on the management tables too.
    #[must_use]
    pub fn control_pool(&self) -> &PgPool {
        &self.control_pool
    }

    /// A raw pool as the connection `DATABASE_URL` supplies. For seeding the
    /// level tables only.
    #[must_use]
    pub fn owner_pool(&self) -> &PgPool {
        &self.owner_pool
    }

    /// A throwaway human actor for tests that need to perform a write. Writes
    /// require an acting context; tests that only need *an* actor (not a
    /// specific one) can use this rather than minting their own.
    #[must_use]
    pub fn test_actor(&self, env: &Env) -> ActorRef {
        ActorRef::human(HumanId::generate(env))
    }

    /// A fresh, empty database's owner pool with no schema applied.
    ///
    /// For migration-framework tests that drive a [`crate::MigrationRunner`] over
    /// a custom chain from a clean slate (an empty `_schema_migrations` ledger),
    /// separate from the full IronAuth chain [`TestDatabase::start`] applies.
    ///
    /// # Panics
    ///
    /// Panics if `DATABASE_URL` is unset or the database cannot be created, for
    /// the same fail-loud reason as [`TestDatabase::start`].
    pub async fn fresh_owner_pool() -> PgPool {
        let owner_base = std::env::var("DATABASE_URL").expect(
            "DATABASE_URL must point at a Postgres superuser/owner connection for the \
             migration tests; scripts/with-test-db.sh starts a throwaway one and exports it",
        );
        let db_name = format!("ironauth_test_{}", unique_suffix());
        create_database(&owner_base, &db_name).await;
        let owner_url = swap_database(&owner_base, &db_name);
        PgPool::connect(&owner_url)
            .await
            .expect("connect as owner to fresh database")
    }

    /// Seed a full operator -> tenant -> environment chain and return the
    /// resulting scope. Runs as the owner (the level tables carry no per-tenant
    /// row-level security; they are the management plane's, issue #11).
    ///
    /// # Panics
    ///
    /// Panics if the seed inserts fail.
    pub async fn seed_scope(&self, env: &Env) -> Scope {
        let operator = OperatorId::generate(env);
        sqlx::query("INSERT INTO operators (id, display_name) VALUES ($1, $2)")
            .bind(operator.to_string())
            .bind("test operator")
            .execute(&self.owner_pool)
            .await
            .expect("seed operator");

        let tenant = TenantId::generate(env);
        sqlx::query("INSERT INTO tenants (id, operator_id, display_name) VALUES ($1, $2, $3)")
            .bind(tenant.to_string())
            .bind(operator.to_string())
            .bind("test tenant")
            .execute(&self.owner_pool)
            .await
            .expect("seed tenant");

        let environment = self.seed_environment(env, tenant).await;
        Scope::new(tenant, environment)
    }

    /// Seed an additional environment for an existing tenant and return its id.
    ///
    /// # Panics
    ///
    /// Panics if the seed insert fails.
    pub async fn seed_environment(&self, env: &Env, tenant: TenantId) -> EnvironmentId {
        let environment = EnvironmentId::generate(env);
        sqlx::query("INSERT INTO environments (id, tenant_id, display_name) VALUES ($1, $2, $3)")
            .bind(environment.to_string())
            .bind(tenant.to_string())
            .bind("test environment")
            .execute(&self.owner_pool)
            .await
            .expect("seed environment");
        environment
    }
}

/// A process-unique suffix drawn from the entropy seam, so runs on a shared
/// cluster never collide on the database name.
fn unique_suffix() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0_u8; 8];
    Env::system().entropy().fill_bytes(&mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Create a low-privilege login role the schema grants to (`ironauth_app` or
/// `ironauth_control`).
///
/// The role is cluster-global, but the harness sets up many fresh per-run
/// databases concurrently, so a plain check-then-`CREATE ROLE` loses the race:
/// two setups both observe the role absent, and the second `CREATE ROLE` fails.
/// Catching both the higher-level `duplicate_object` and the underlying catalog
/// `unique_violation` (either can surface depending on timing) makes creation
/// idempotent and race-safe. The password is a throwaway for the test cluster
/// only; production provisions these roles out of band (see the migration
/// headers). `role` is a fixed identifier from this module, never user input.
async fn provision_role(owner_pool: &PgPool, role: &str) {
    sqlx::raw_sql(&format!(
        "DO $$ \
         BEGIN \
             CREATE ROLE {role} LOGIN PASSWORD '{role}'; \
         EXCEPTION WHEN duplicate_object OR unique_violation THEN \
             NULL; \
         END \
         $$;"
    ))
    .execute(owner_pool)
    .await
    .unwrap_or_else(|e| panic!("provision low-privilege role {role}: {e}"));
}

/// Create `db_name` via a transient connection to the maintenance database.
async fn create_database(owner_base: &str, db_name: &str) {
    let admin = PgPool::connect(owner_base)
        .await
        .expect("connect to maintenance database (check DATABASE_URL)");
    // Identifier is a fixed-format `ironauth_test_<hex>`, not user input.
    sqlx::query(&format!("CREATE DATABASE {db_name}"))
        .execute(&admin)
        .await
        .expect("create fresh test database");
    admin.close().await;
}

/// Replace the database path segment of a connection URL, preserving any query.
fn swap_database(url: &str, db_name: &str) -> String {
    let (base, query) = url
        .split_once('?')
        .map_or((url, None), |(b, q)| (b, Some(q)));
    let prefix = base.rsplit_once('/').map_or(base, |(prefix, _)| prefix);
    match query {
        Some(query) => format!("{prefix}/{db_name}?{query}"),
        None => format!("{prefix}/{db_name}"),
    }
}

/// Extract host and port from a connection URL, defaulting the port to 5432.
fn host_port_of(url: &str) -> (String, u16) {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme
        .rsplit_once('@')
        .map_or(after_scheme, |(_, rest)| rest);
    let host_port = authority.split(['/', '?']).next().unwrap_or(authority);
    match host_port.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(5432)),
        None => (host_port.to_string(), 5432),
    }
}
