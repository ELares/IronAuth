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

/// The SUFFIX the absent-scope conversion recognizes a scope foreign key by, re-exported
/// so the schema test that measures it against the live catalog reads THE SOURCE rather
/// than a hand-typed copy of it.
///
/// The copy is the version that was tried first and it does not work. A copy makes the
/// test insensitive to exactly the change most worth catching: widening the source
/// predicate leaves the copy narrow, the test keeps measuring the old rule, and it stays
/// green while every foreign-key violation in the schema starts answering not-found.
/// That was MEASURED (widening the source to `_fkey` left the whole file at 3 passed),
/// which is why this re-export exists.
///
/// Reading the source here does not make the test vacuous, because what it asserts is
/// not the suffix's spelling: it is a relation between the suffix and the live schema,
/// in both directions, and a widened suffix breaks that relation loudly.
pub const SCOPE_FK_SUFFIX: &str = crate::error::SCOPE_FK_SUFFIX;

/// The low-privilege data-plane role the migration grants to.
const APP_ROLE: &str = "ironauth_app";

/// The low-privilege control-plane role the management-API migration grants to
/// (issue #11). A peer of [`APP_ROLE`], never a superset: still never a
/// superuser and never a table owner, so forced row-level security applies.
const CONTROL_ROLE: &str = "ironauth_control";

/// The audit RETENTION role (issue #109). Holds SELECT and DELETE on `audit_log`
/// and `audit_chain` and nothing else anywhere, and deliberately holds no INSERT
/// on either: a role that could both write and remove an audit row could erase a
/// row and replace it, which is the tampering the log exists to make evident.
const AUDIT_RETENTION_ROLE: &str = "ironauth_audit_retention";

/// A fresh, isolated database plus the handles the isolation tests need.
///
/// Cloning shares the same throwaway database and the same pools (every pool handle is
/// `Arc`-backed), which is what lets a test hold the database across a simulated
/// process restart. The database itself is torn down by the harness script, not by a
/// `Drop`, so a clone can never pull it out from under a live handle.
#[derive(Clone)]
pub struct TestDatabase {
    /// The operator every seeded scope is owned by, when set.
    ///
    /// Each seed otherwise mints a FRESH operator, which since issue #185 makes the
    /// resulting tenant invisible to any surface acting as a different one. A harness
    /// driving the management API sets this to that API's own operator so the rows it
    /// seeds are rows the API can reach.
    seed_operator: Option<OperatorId>,
    owner_pool: PgPool,
    app_pool: PgPool,
    control_pool: PgPool,
    store: Store,
    control_store: Store,
    /// The audit RETENTION handle (issue #109), authenticating as the third
    /// credential class: it can remove an audit row and cannot write one.
    audit_retention_store: Store,
    /// The data-plane connection URL, kept so a test can open a BRAND-NEW pool against
    /// the SAME database and rebuild its process-level state from nothing: the
    /// rolling-restart simulation (issue #32 AC 1).
    app_url: String,
    /// The control-plane connection URL, kept for the same reason as `app_url`: a
    /// concurrency test needs a WIDER control-plane pool than the default one so its
    /// storm actually overlaps rather than queueing on connections.
    control_url: String,
    /// The audit retention connection URL, kept for the same reason as `app_url`.
    audit_retention_url: String,
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
        reclaim_leaked_databases(&owner_base).await;
        let db_name = fresh_database_name();

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
        provision_role(&owner_pool, AUDIT_RETENTION_ROLE).await;

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
        // The control plane manages users end to end (issue #52), which is a PII
        // surface, so it carries the platform master key exactly as the data plane
        // does: it seals, blind-indexes, and opens user PII through the envelope
        // substrate. Without the key those paths fail closed (never plaintext).
        let control_store = Store::from_pool(control_pool.clone()).with_master_key(master.clone());

        // The audit retention handle, a third credential class that can remove an
        // audit row and cannot write one.
        let audit_retention_url = format!(
            "postgres://{AUDIT_RETENTION_ROLE}:{AUDIT_RETENTION_ROLE}@{host}:{port}/{db_name}"
        );
        // LAZY, and capped at two connections. Every test database builds one of these,
        // but only the handful of retention tests ever uses one, and an eager pool per
        // database exhausted the server's connection limit: fourteen unrelated OIDC tests
        // failed with `PoolTimedOut` the first time this was wired eagerly.
        let audit_retention_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy(&audit_retention_url)
            .expect("build the lazy audit retention pool");
        // No master key: this role never touches a PII path, and handing it one
        // would widen a credential whose entire point is being narrow.
        let audit_retention_store = Store::from_pool(audit_retention_pool);

        Self {
            seed_operator: None,
            owner_pool,
            app_pool,
            control_pool,
            store,
            control_store,
            audit_retention_store,
            app_url,
            control_url,
            audit_retention_url,
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

    /// A CONTROL-plane store over a pool of `max_connections`, for a management-plane
    /// concurrency storm. The exact counterpart of
    /// [`TestDatabase::app_store_with_pool`], and needed for the same reason: a storm
    /// spawned across the default pool queues on connections instead of overlapping,
    /// so the interleaving it exists to exercise never happens.
    ///
    /// Authenticates as the same low-privilege control role as
    /// [`TestDatabase::control_store`], so forced row-level security and the
    /// column-scoped grants still apply.
    ///
    /// # Panics
    ///
    /// Panics if the wider pool cannot be established.
    pub async fn control_store_with_pool(&self, max_connections: u32) -> Store {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(&self.control_url)
            .await
            .expect("build a wider control-plane pool for the concurrency storm");
        Store::from_pool(pool).with_master_key(self.master.clone())
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

    /// Execute a raw statement as the OWNER role, for test setup and fault injection
    /// (issue #72): a test can `DROP` a table so a subsequent data-plane read FAULTS,
    /// proving a fail-closed path (for example that a step-up policy read fault at token
    /// issuance denies rather than silently issuing). Owner-only; never a data-plane
    /// surface.
    ///
    /// # Panics
    ///
    /// Panics if the statement cannot be executed.
    pub async fn execute_owner_sql(&self, sql: &str) {
        sqlx::query(sql)
            .execute(&self.owner_pool)
            .await
            .expect("execute owner SQL");
    }

    /// The low-privilege data-plane connection URL (`ironauth_app` role) for THIS
    /// throwaway database. A test that drives the `ironauth` binary as a subprocess (the
    /// CLI integration tests, issue #72) writes this into a config file so the CLI
    /// connects to the same database, as the same low-privilege role production uses, and
    /// its audited write is subject to forced row-level security exactly as it would be
    /// in production.
    #[must_use]
    pub fn app_url(&self) -> &str {
        &self.app_url
    }

    /// The low-privilege CONTROL-plane connection URL (`ironauth_control` role) for THIS
    /// throwaway database, the peer of [`TestDatabase::app_url`]. A test that drives the
    /// real boot path (the boot-wiring harness, issue #414) writes this into
    /// `admin.control_database_url` so the management plane connects as the SEPARATE
    /// credential class production uses, rather than borrowing the data-plane role and
    /// quietly testing a role separation that would not hold.
    #[must_use]
    pub fn control_url(&self) -> &str {
        &self.control_url
    }

    /// The audit RETENTION connection URL (`ironauth_audit_retention` role) for THIS
    /// throwaway database (issue #109).
    #[must_use]
    pub fn audit_retention_url(&self) -> &str {
        &self.audit_retention_url
    }

    /// A [`Store`] on the audit retention role. Use this for a retention sweep, so a
    /// test exercises the role separation production relies on rather than sweeping as
    /// the owner and proving nothing about the grants.
    #[must_use]
    pub fn audit_retention_store(&self) -> &Store {
        &self.audit_retention_store
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
        reclaim_leaked_databases(&owner_base).await;
        let db_name = fresh_database_name();
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
        self.seed_scope_with_kind(env, "dev", None).await
    }

    /// Like [`TestDatabase::seed_scope`] but with an explicit environment `kind`
    /// (`dev`, `staging`, or `prod`) and optional `custom_domain`, so a test can
    /// stand up a PROD environment and exercise the typed guardrails (issue #42).
    ///
    /// # Panics
    ///
    /// Panics if the seed inserts fail.
    pub async fn seed_scope_with_kind(
        &self,
        env: &Env,
        kind: &str,
        custom_domain: Option<&str>,
    ) -> Scope {
        let operator = self
            .seed_operator
            .unwrap_or_else(|| OperatorId::generate(env));
        // Idempotent: when `seed_operator` is set, every seeded scope shares ONE
        // operator, so the second seed would otherwise collide on the primary key.
        sqlx::query(
            "INSERT INTO operators (id, display_name) VALUES ($1, $2) \
             ON CONFLICT (id) DO NOTHING",
        )
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

        let environment = self
            .seed_environment_with_kind(env, tenant, kind, custom_domain)
            .await;
        Scope::new(tenant, environment)
    }

    /// The operator that owns `tenant`.
    ///
    /// Every seeded scope mints its OWN operator, so a test that needs to construct an
    /// environment repository has to ask rather than assume: since issue #185 that
    /// repository is fenced by the caller's operator, and guessing the wrong one turns
    /// every read into the uniform not-found.
    ///
    /// # Panics
    ///
    /// If no tenant row with that id exists.
    pub async fn owning_operator(&self, tenant: &TenantId) -> OperatorId {
        let owner: String = sqlx::query_scalar("SELECT operator_id FROM tenants WHERE id = $1")
            .bind(tenant.to_string())
            .fetch_one(&self.owner_pool)
            .await
            .expect("read the tenant's owning operator");
        OperatorId::parse(&owner).expect("a well-formed operator id")
    }

    /// Own every subsequently seeded scope with `operator` instead of a fresh one.
    ///
    /// See [`TestDatabase::seed_operator`]: since issue #185 a tenant owned by an
    /// operator the caller is not reads as the uniform not-found, so a harness driving a
    /// surface must seed rows under that surface's OWN operator.
    pub fn own_seeded_scopes_by(&mut self, operator: OperatorId) {
        self.seed_operator = Some(operator);
    }

    /// Set a scope's data-plane serving state directly, as the owner (issue #46):
    /// the precondition a control-plane suspend/resume cascade writes into
    /// `environment_states`. For tests (for example the OIDC data-plane fence) that
    /// need to drive the fence from a serving state without reaching for the full
    /// control-plane transition. `serving_status` is `active` or `suspended`.
    ///
    /// # Panics
    ///
    /// Panics if the upsert fails.
    pub async fn set_environment_serving_state(&self, scope: Scope, serving_status: &str) {
        // A test harness seeding a scoped table's serving-state precondition directly
        // as the owner (bypassing RLS), exactly as it seeds the operator/tenant/
        // environment level tables above. The inline SQL comment carries the
        // query-audit-allow marker Postgres ignores.
        sqlx::query(
            "INSERT INTO environment_states /* query-audit-allow: owner test seed */ \
             (tenant_id, environment_id, serving_status) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id, environment_id) \
             DO UPDATE SET serving_status = EXCLUDED.serving_status",
        )
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .bind(serving_status)
        .execute(&self.owner_pool)
        .await
        .expect("set environment serving state");
    }

    /// Seed an additional environment for an existing tenant and return its id.
    ///
    /// # Panics
    ///
    /// Panics if the seed insert fails.
    pub async fn seed_environment(&self, env: &Env, tenant: TenantId) -> EnvironmentId {
        self.seed_environment_with_kind(env, tenant, "dev", None)
            .await
    }

    /// Like [`TestDatabase::seed_environment`] but with an explicit `kind` and
    /// optional `custom_domain` (issue #42), so the guardrail projection resolves
    /// the intended typed guardrail set for the seeded environment.
    ///
    /// # Panics
    ///
    /// Panics if the seed insert fails.
    pub async fn seed_environment_with_kind(
        &self,
        env: &Env,
        tenant: TenantId,
        kind: &str,
        custom_domain: Option<&str>,
    ) -> EnvironmentId {
        let environment = EnvironmentId::generate(env);
        sqlx::query(
            "INSERT INTO environments (id, tenant_id, display_name, kind, custom_domain) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(environment.to_string())
        .bind(tenant.to_string())
        .bind("test environment")
        .bind(kind)
        .bind(custom_domain)
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

/// The prefix every per-test database carries, so a sweep can identify exactly what
/// it owns and never touch a database belonging to something else.
const TEST_DB_PREFIX: &str = "ironauth_test_";

/// How old a leftover per-test database must be before the sweep reclaims it, by
/// default.
///
/// This is the CONCURRENCY margin, not a tidiness preference. A run in progress owns
/// young databases, so the threshold has to exceed the longest run by enough that a
/// concurrent gate is never robbed of a database it is still using. The full local
/// gate takes well under an hour; six is a wide margin over that. The sweep ALSO
/// skips any database with a live connection, so this bound is the second of two
/// independent protections rather than the only one.
const RECLAIM_MIN_AGE_SECS: u64 = 6 * 60 * 60;

/// The lowest age the override below will accept, in seconds.
///
/// The live-connection guard does not cover the window between `CREATE DATABASE` and
/// the first connection to it. That window is milliseconds in principle and seconds
/// under load, so a floor of zero would let a sweep drop a database another test had
/// created and not yet opened. Five minutes is far above any plausible value of that
/// window and far below the length of a suite, which is what makes the override useful
/// at all.
///
/// COUPLED to a fixture, though not by direct causation and the difference matters.
/// `test_db_reclaim.rs` stages a sixty-second-old database and asserts a sweep spares it.
/// Lowering THIS constant alone does nothing, because the clamp only ever raises a
/// setting: CI passes 300 explicitly and would keep getting 300. The real invariant is
/// that the EFFECTIVE threshold must stay above the youngest fixture any test stages, and
/// this floor only bounds how low a SETTING is permitted to push it. Worth naming because
/// the two numbers are two directories apart and neither end says so.
const RECLAIM_MIN_AGE_FLOOR_SECS: u64 = 300;
// WHAT CATCHES A CHANGE TO IT, and an earlier version of this comment got the second half
// wrong. The integration fixture is staged at TEN MINUTES, so this floor could drift to 600
// with the whole suite green and only started failing at 900. That much was right. The claim
// that "a change inside it is caught by the unit tests alone" was NOT: five of the seven
// cases in `the_reclaim_threshold_override_is_clamped_at_its_floor` build their expectation
// FROM these constants, so moving one moves both sides of the assertion. Only the literal
// case had grip, and it does not bite until the floor exceeds 600, which is exactly why 900
// died and 600 did not.
//
// The literal assertions below close it: the constants are pinned to their values, so any
// drift costs a test edit and somebody noticing.

/// The environment variable that lowers [`RECLAIM_MIN_AGE_SECS`].
const RECLAIM_MIN_AGE_ENV: &str = "IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS";

/// The marker an operator sets to say "every database in this cluster is mine to reclaim".
///
/// Only consulted when the override LOWERS the threshold below the six-hour default, which
/// is the behaviour this crate added and the only part that is this crate's to guard. A
/// sweep at the default is the behaviour that predates it.
const DISPOSABLE_ENV: &str = "IRONAUTH_TEST_DB_DISPOSABLE";

/// How old a leftover per-test database must be before this process reclaims it.
///
/// # Why this is tunable at all
///
/// The six-hour default is correct for a developer machine, where the cluster outlives
/// many runs and a concurrent gate is a real possibility. It is exactly wrong for CI,
/// where the Postgres container is created fresh for every job: nothing in it is ever
/// six hours old, so the sweep reclaims NOTHING and every per-test database survives to
/// the end of the run in the container's DATA VOLUME. Not its writable layer, which an
/// earlier version of this sentence said: the official `postgres` image declares `PGDATA` a
/// volume, so the layer stays at 63 bytes after a run that created a database per test
/// while the volume holds gigabytes. It matters because it decides which command can see
/// the growth (`du -sh /var/lib/docker`, which counts volumes) and which cannot
/// (`docker ps --size`, which does not).
///
/// That is not a tidiness problem, it is the disk. MEASURED on the job this was written
/// for: 46 GB consumed, of which `target` was 24 GB. The rest is here, and it grows with
/// the number of tests, which is the quantity this project adds to every week.
///
/// The sweep runs once per PROCESS and `cargo test` runs test binaries one after
/// another, so a low threshold in CI reclaims the previous binaries' databases at the
/// start of each new one, bounding the total to roughly one binary's worth plus whatever
/// the floor keeps alive.
///
/// Clamped at [`RECLAIM_MIN_AGE_FLOOR_SECS`] rather than trusted: an operator who sets
/// zero would reintroduce the create-then-connect race the age check exists to close,
/// and a harness that lets its own safety bound be configured to nothing is not bounded.
/// An unparseable value falls back to the default rather than to the floor, because a
/// typo must not silently make the sweep more aggressive.
///
/// # Setting this against a SHARED cluster is not safe, and the default is why
///
/// The six-hour default exists because "a concurrent gate is a real possibility". Lowering
/// it lowers that protection for every database in the cluster `DATABASE_URL` names, not
/// only for this run's own. It is correct in CI because the Postgres container is created
/// fresh per job and nothing else is in it, and `cargo test` runs test binaries one after
/// another so at the moment binary N+1 sweeps, binaries 1..N have exited.
///
/// Neither of those holds on a developer machine pointed at a cluster somebody else is
/// also using, and neither holds under a process-per-test runner such as `cargo nextest`,
/// where a live process's database can be both past the threshold and connectionless
/// (sqlx closes idle connections after ten minutes with `min_connections` at zero). Set
/// this in CI, or in a throwaway cluster, and nowhere else.
fn reclaim_min_age_secs() -> u64 {
    let secs = reclaim_min_age_from(std::env::var(RECLAIM_MIN_AGE_ENV).ok().as_deref());
    // THE GUARD LIVES HERE, not in one test, and that placement is the whole of it.
    //
    // It began as an assertion on a single test in `test_db_reclaim.rs`, which is still there
    // as belt and braces because it fires earlier and with a more specific message. The other
    // three tests in that binary
    // drive the same cluster-wide sweep, and `TestDatabase::start` drives it once per
    // process from 103 test files, none of which consulted the marker. Review reproduced a
    // colleague's six-minute-old database being dropped by an UNGUARDED test while the
    // guarded one refused afterwards, which is the same shape as the round-5 finding one
    // level out.
    //
    // Gated on the override having LOWERED the threshold, because that is the part this
    // crate added. Sweeping at the six-hour default is behaviour that predates it and is
    // not this guard's to change; lowering it to five minutes across somebody else's
    // cluster is.
    if secs < RECLAIM_MIN_AGE_SECS {
        assert!(
            std::env::var(DISPOSABLE_ENV).is_ok_and(|value| value == "1"),
            "{RECLAIM_MIN_AGE_ENV} lowers the leftover sweep to {secs}s across EVERY \
             database in this cluster, so it runs only where that is known to be safe. Set \
             {DISPOSABLE_ENV}=1 if the cluster is disposable (a CI service container, or one \
             you created for this run); `scripts/with-test-db.sh` sets it for a cluster it \
             starts itself, but not when you pass your own DATABASE_URL"
        );
    }
    secs
}

/// The decision itself, over the raw setting rather than over the environment.
///
/// Split out so it is testable without mutating process-global state: `set_var` is
/// `unsafe` from the 2024 edition and the workspace sets `unsafe_code = "deny"`, and a
/// test that wrote the variable would race every other test in the binary regardless.
///
/// `deny` rather than `forbid`, which matters: an `#[allow(unsafe_code)]` would be
/// available, so the race is the reason this is split out and the lint is only the
/// reminder. The ENV READ itself is covered by a child-process test in
/// `test_db_reclaim.rs`, because this pure function cannot reach it and a mutant that
/// disconnected the read survived the whole crate until that test existed.
fn reclaim_min_age_from(raw: Option<&str>) -> u64 {
    raw.and_then(|raw| raw.trim().parse::<u64>().ok())
        .map_or(RECLAIM_MIN_AGE_SECS, |secs| {
            secs.max(RECLAIM_MIN_AGE_FLOOR_SECS)
        })
}

/// The count of leftovers at which the sweep says so loudly rather than quietly
/// tidying. A developer whose cluster is filling up should learn it at the START of a
/// run, not from a run that dies in the middle (issue #445).
const RECLAIM_NOISY_THRESHOLD: usize = 200;

/// A fresh per-test database name: the prefix, the creation instant, then entropy.
///
/// The instant is IN THE NAME because Postgres does not record when a database was
/// created, and the sweep needs an age it can trust. Reading it back out of the name
/// is what lets a reclaim distinguish a leftover from an in-flight run's database.
fn fresh_database_name() -> String {
    let secs = std::time::UNIX_EPOCH
        .elapsed()
        .map_or(0, |since| since.as_secs());
    format!("{TEST_DB_PREFIX}{secs}_{}", unique_suffix())
}

/// Parse the creation instant a [`fresh_database_name`] embedded, if this name is one
/// of ours in the current format.
fn created_at_secs(datname: &str) -> Option<u64> {
    datname
        .strip_prefix(TEST_DB_PREFIX)?
        .split_once('_')
        .and_then(|(secs, _)| secs.parse().ok())
}

/// Drop per-test databases left behind by runs that are over (issue #445).
///
/// `scripts/with-test-db.sh` removes the whole cluster it creates, so a throwaway run
/// cleans itself up. When `DATABASE_URL` points at an EXTERNAL cluster the script uses
/// it as-is and nothing ever removed these, so they accumulated across every run: 11,533
/// of them holding 163 GiB were measured on one machine, which exhausted the disk and
/// killed two gate runs mid-flight. The failure presents as a run that simply vanishes,
/// which is easy to misread as a harness fault rather than a full disk.
///
/// Self-healing rather than shutdown-dependent, which is the whole point: a run killed
/// by SIGKILL, by ENOSPC, or by a dead parent cannot clean up after itself, so the
/// reclaim happens on the NEXT run's way in and no abnormal exit can defeat it.
///
/// Two independent guards keep a concurrent run safe. A database is reclaimed only if
/// it is older than [`reclaim_min_age_secs`] AND has no live connection. Best effort
/// throughout: every failure here is ignored, because a harness that refuses to run
/// tests because it could not tidy up would be a worse defect than the one it fixes.
async fn reclaim_leaked_databases(owner_base: &str) {
    // Once per PROCESS, not once per database. A gate run builds hundreds of test
    // databases and sweeping before each would be hundreds of redundant catalog scans.
    static SWEPT: std::sync::Once = std::sync::Once::new();
    let mut should_run = false;
    SWEPT.call_once(|| should_run = true);
    if !should_run {
        return;
    }
    reclaim_leaked_databases_now(owner_base).await;
}

/// The reclaim itself, without the once-per-process latch, returning how many
/// databases it dropped.
///
/// Split out so the behaviour is DRIVABLE: through
/// [`reclaim_leaked_databases`] it can run at most once per process, so a test
/// could otherwise observe it at most once and never compare the cases it must
/// distinguish. The count is returned for the same reason, so a test asserts what
/// was reclaimed rather than that nothing panicked.
pub async fn reclaim_leaked_databases_now(owner_base: &str) -> usize {
    let Ok(admin) = PgPool::connect(owner_base).await else {
        return 0;
    };
    // Candidates: ours by prefix, and idle. `pg_stat_activity` is the live-use guard;
    // the age check below is the second one.
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT d.datname::text FROM pg_database d \
         WHERE d.datname LIKE $1 \
           AND NOT EXISTS ( \
               SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)",
    )
    .bind(format!("{TEST_DB_PREFIX}%"))
    .fetch_all(&admin)
    .await
    .unwrap_or_default();

    let now = std::time::UNIX_EPOCH
        .elapsed()
        .map_or(0, |since| since.as_secs());
    let min_age = reclaim_min_age_secs();
    let stale: Vec<String> = candidates
        .into_iter()
        .filter(|name| {
            // `>=` rather than `>`, and the boundary second is KNOWINGLY unmeasured. Both
            // operators are reachable, but the age here is derived from a wall-clock instant
            // encoded in the name and compared against a wall clock read later, so a fixture
            // staged to land exactly ON the threshold lands a few milliseconds past it by
            // the time this runs. A test aimed at the boundary would pass under either
            // operator most of the time and flake the rest, which is worse than an
            // unmeasured line. What IS measured is that the threshold is the configured
            // value and not the floor or the default, which is the property that matters:
            // an off-by-one second on a five-minute window is not a defect anyone can reach.
            created_at_secs(name).is_some_and(|created| now.saturating_sub(created) >= min_age)
        })
        .collect();

    if stale.len() >= RECLAIM_NOISY_THRESHOLD {
        eprintln!(
            "test-support: reclaiming {} leaked per-test databases (issue #445). If this \
             number keeps growing, the cluster in DATABASE_URL is being filled by runs \
             that end abnormally.",
            stale.len()
        );
    }
    let mut reclaimed = 0;
    for name in stale {
        // Not FORCE: the connection guard above already established this database is
        // idle, and FORCE would terminate a session that appeared in between, which is
        // exactly the concurrent run this sweep must never disturb.
        if sqlx::query(&format!("DROP DATABASE IF EXISTS {name}"))
            .execute(&admin)
            .await
            .is_ok()
        {
            reclaimed += 1;
        }
    }
    admin.close().await;
    reclaimed
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

#[cfg(test)]
mod reclaim_threshold_tests {
    use super::{RECLAIM_MIN_AGE_FLOOR_SECS, RECLAIM_MIN_AGE_SECS, reclaim_min_age_from};

    /// The override lowers the threshold, clamps at the floor, and ignores nonsense.
    ///
    /// The floor is the load-bearing case. `reclaim_leaked_databases_now` skips any
    /// database with a live connection, but that guard does not cover the window between
    /// `CREATE DATABASE` and the first connection to it, so a threshold of zero would let
    /// one test's sweep drop a database another test had just created. A harness that
    /// lets its own safety bound be configured to nothing is not bounded.
    ///
    /// The last case is the one that is easy to get backwards: a value that does not
    /// parse falls back to the DEFAULT, not to the floor. A typo must never silently make
    /// the sweep more aggressive than it was.
    #[test]
    fn the_reclaim_threshold_override_is_clamped_at_its_floor() {
        // THE CONSTANTS THEMSELVES, pinned to literals. Every case below builds its
        // expectation FROM these values, so without this a change to either moves both sides
        // of the assertion and passes: measured, the floor could drift 300 to 600 with the
        // whole suite green. Pinning them means a deliberate change costs a test edit.
        assert_eq!(
            RECLAIM_MIN_AGE_FLOOR_SECS, 300,
            "five minutes, and the comment at the constant reasons about that number"
        );
        assert_eq!(
            RECLAIM_MIN_AGE_SECS,
            6 * 60 * 60,
            "six hours, which is what makes the CI override a LOWERING and therefore guarded"
        );
        assert_eq!(
            reclaim_min_age_from(None),
            RECLAIM_MIN_AGE_SECS,
            "unset keeps the six-hour default a developer machine needs"
        );
        assert_eq!(
            reclaim_min_age_from(Some("600")),
            600,
            "a value above the floor is taken as given"
        );
        assert_eq!(
            reclaim_min_age_from(Some(" 600 ")),
            600,
            "surrounding whitespace is not a typo"
        );
        assert_eq!(
            reclaim_min_age_from(Some("0")),
            RECLAIM_MIN_AGE_FLOOR_SECS,
            "zero clamps to the floor rather than disabling the create-then-connect guard"
        );
        assert_eq!(
            reclaim_min_age_from(Some("1")),
            RECLAIM_MIN_AGE_FLOOR_SECS,
            "and so does anything else below it"
        );
        assert_eq!(
            reclaim_min_age_from(Some("not-a-number")),
            RECLAIM_MIN_AGE_SECS,
            "an unparseable value falls back to the DEFAULT, never to the floor"
        );
        assert_eq!(
            reclaim_min_age_from(Some("")),
            RECLAIM_MIN_AGE_SECS,
            "and so does an empty one"
        );
    }
}
