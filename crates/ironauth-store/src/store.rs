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
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::error::StoreError;
use crate::migrate::MigrationRunner;
use crate::outbox::{OutboxBackbone, WakeDispatcher};
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
    // The outbox wake-up dispatcher (issues #104, #944), on the PRODUCER side.
    //
    // The consumer half has always had a backbone: `OutboxWorkerPool` waits on one instead of
    // sleeping out the poll interval. Nothing ever signalled it. A deployment configuring
    // `ironbus_addr` paid for the broker connections and behaved exactly as `PollOnly`,
    // because every drain still waited its full interval, so the mode was a wake-up backbone
    // that was never woken.
    //
    // `None` means this handle signals nothing, and it is the state every deployment WITHOUT
    // a configured broker is in: the boot path installs a dispatcher only when a real backbone
    // was resolved, so Postgres-only mode costs nothing at all here rather than paying a
    // dedup and a channel send to reach a no-op notify.
    wakes: Option<Arc<WakeDispatcher>>,
}

impl Store {
    /// Run the pre-upgrade data preflight against this store's database (issue #148).
    ///
    /// Read-only: it probes live rows against the constraints every pending migration
    /// would impose and reports the ones that would be rejected. See
    /// [`crate::preflight`] for what it examines and what it says when it cannot.
    ///
    /// The pool stays private, as it does for every other operation on this type: the
    /// preflight is a method here rather than a free function taking a pool, so no
    /// caller gains a raw handle.
    ///
    /// # Errors
    ///
    /// [`crate::MigrationError::Database`] if the migration ledger cannot be read. An
    /// individual probe failing is reported in the returned value, not raised.
    pub async fn preflight(
        &self,
        chain: &[crate::Migration],
    ) -> Result<crate::preflight::Report, crate::MigrationError> {
        crate::preflight::run(&self.pool, chain).await
    }

    /// Whether the connected role can see every row, or is itself subject to row-level
    /// security (issue #148).
    ///
    /// This exists because of how the preflight fails when it is wrong. The scoped
    /// tables are FORCE ROW LEVEL SECURITY, and `ironauth_app` is deliberately neither
    /// superuser nor table owner, so a probe run on that connection with no scope bound
    /// returns zero rows FOR EVERY TABLE. Zero rows is exactly what a clean preflight
    /// looks like. Connecting as the server's own runtime role would therefore not make
    /// the doctor wrong occasionally; it would make it report a clean bill every time,
    /// most confidently on the databases with the most data in them.
    ///
    /// So the caller asks this first and refuses to report anything if the answer is no.
    ///
    /// `rolsuper OR rolbypassrls` and not "is the owner": FORCE ROW LEVEL SECURITY exists
    /// precisely to stop a table owner bypassing their own policies, so ownership is not
    /// sufficient here and the refusal message must not suggest it.
    ///
    /// # Errors
    ///
    /// [`crate::StoreError::Database`] if `pg_roles` cannot be read.
    pub async fn sees_through_row_level_security(&self) -> Result<bool, crate::StoreError> {
        let row = sqlx::query(
            "SELECT rolsuper OR rolbypassrls AS unrestricted \
             FROM pg_roles WHERE rolname = current_user",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<bool, _>("unrestricted"))
    }

    /// Rewrap every live tenant KEK from one platform master key to another (issue #153).
    ///
    /// The pool stays private, as everywhere else on this type. See [`crate::rekey`] for what
    /// the operation is, why it resumes without a cursor, and why it is offline.
    ///
    /// # Errors
    ///
    /// [`StoreError::Encryption`] if the connected role is subject to row-level security, if
    /// the two master keys share an id, or if a KEK does not open under `from`;
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn rekey_master(
        &self,
        from: &ironauth_jose::MasterKey,
        to: &ironauth_jose::MasterKey,
    ) -> Result<crate::rekey::RekeyReport, StoreError> {
        let env = ironauth_env::Env::system();
        crate::rekey::Rekey::new(&self.pool, from, to, env.entropy())
            .run()
            .await
    }

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
        Ok(Self {
            pool,
            master: None,
            wakes: None,
        })
    }

    /// A store whose pool CONNECTS TO NOTHING, for a test about wiring rather than data.
    ///
    /// `sqlx`'s lazy pool opens no connection until one is used, so this constructs a real
    /// `Store` with no database anywhere. It exists because the alternative was worse: the
    /// binary's sender-wiring test asks which sender a config installs, a `Store` is one of the
    /// constructor's arguments, and requiring a live database to answer a question about a
    /// branch on a config value turns a unit test into one a laptop without Postgres skips --
    /// which is how a wiring defect stays invisible.
    ///
    /// Any query through this store fails to connect. That is the point: a test that reached
    /// one would be measuring something this is not for.
    ///
    /// # Panics
    ///
    /// If the fixed URL above stops parsing, which would be an edit to this function.
    #[must_use]
    pub fn disconnected() -> Self {
        Self::from_pool(
            PgPoolOptions::new()
                .connect_lazy("postgres://ironauth:unused@127.0.0.1:1/unused")
                .expect("a lazy pool parses its url and connects to nothing"),
        )
    }

    /// Build a store from a pool the caller already configured (for example a
    /// pool shared with other subsystems, or the low-privilege pool the test
    /// harness injects). The pool stays private after construction; this does
    /// not widen access to scoped tables.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            master: None,
            wakes: None,
        }
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

    /// Attach the outbox wake-up backbone this handle SIGNALS on (issue #944).
    ///
    /// Wire this on every store that serves a surface which enqueues outbox work, which is
    /// every request-path store: the signal has to come from the producer, and the producer
    /// is whichever handler just committed a domain write. A store without one is
    /// Postgres-only and enqueues silently, which is the documented default rather than a
    /// degraded state.
    ///
    /// Wire this ONLY when a real broker is configured. Installing a `PollOnly` backbone here
    /// would be indistinguishable in behaviour and would still cost every enqueue-bearing
    /// commit a dedup and a channel send to reach a `notify` that does nothing, which is a
    /// price paid by deployments that opted into no broker at all.
    ///
    /// Starts one dispatcher thread per call, so pass one handle per process rather than
    /// building a store per request.
    #[must_use]
    pub fn with_outbox_backbone(mut self, backbone: Arc<dyn OutboxBackbone>) -> Self {
        self.wakes = Some(Arc::new(WakeDispatcher::spawn(backbone)));
        self
    }

    /// Share an ALREADY RUNNING dispatcher with another handle of the same process.
    ///
    /// `Store` is cloned freely, and every clone shares the dispatcher its parent carried.
    /// This exists for the boot path, which opens several stores against the same database
    /// and must not start a wake thread for each.
    #[must_use]
    pub fn with_wake_dispatcher(mut self, wakes: Arc<WakeDispatcher>) -> Self {
        self.wakes = Some(wakes);
        self
    }

    /// The wake dispatcher, for the repository layer's post-commit signal only.
    pub(crate) fn wakes(&self) -> Option<&Arc<WakeDispatcher>> {
        self.wakes.as_ref()
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

    /// The platform master key HANDLE, for the boot-wiring harness only (issue #414).
    ///
    /// The management plane and the OIDC data plane each open their own store, and the
    /// sealed PII one plane writes is only the sealed PII the other opens when both
    /// stores carry the SAME key. The key material itself is never exposed (a
    /// [`MasterKey`] redacts itself and offers no byte accessor), so a test proves that
    /// property by comparing the handles, which is why this returns the `Arc` rather
    /// than the key. Gated on `testing`, so the production build's surface is unchanged
    /// and the repository layer keeps reading the key through the crate-private
    /// [`Store::master`].
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn master_key(&self) -> Option<&Arc<MasterKey>> {
        self.master.as_ref()
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
        self.migrate_with_contract(crate::ContractPolicy::default())
            .await
            .map(|_| ())
    }

    /// Apply the chain under an explicit contract policy (issue #148), returning the report.
    ///
    /// [`Store::migrate`] keeps the default, which DEFERS contract migrations on an
    /// upgrade, and discards the report. Use this one wherever the deferral has to be
    /// visible: a caller that says "migrations applied" without reading
    /// [`MigrationReport::deferred_from`] is describing a database whose schema it has
    /// deliberately left short.
    ///
    /// # Errors
    ///
    /// [`StoreError::Migration`] if the chain cannot be applied or is refused;
    /// [`StoreError::Database`] on a connection failure.
    pub async fn migrate_with_contract(
        &self,
        contract: crate::ContractPolicy,
    ) -> Result<crate::MigrationReport, StoreError> {
        let report = MigrationRunner::new(&self.pool)
            .with_contract(contract)
            .run()
            .await?;
        Ok(report)
    }

    /// Record an idempotent response for a request whose WRITE happened on the OTHER plane.
    ///
    /// The management resend is the one operation whose decision is control-plane and whose
    /// write is data-plane, and `idempotency_keys` is a control-plane table the app role holds
    /// no grant on -- so the two genuinely cannot share a transaction. A resend that tried died
    /// on `permission denied for table idempotency_keys`, which is how this was found. query-audit-allow: prose quoting a Postgres error message, not a query
    ///
    /// SEPARATE, therefore, and the reason that is safe rather than a compromise: what stops a
    /// retried resend mailing twice is not this row, it is the compare-and-swap. A resend moves
    /// the message out of its terminal state, so a retry finds it `pending` and is refused as
    /// not-resendable, mailing nothing, whether or not this row committed. What the row buys is
    /// that a replay returns the ORIGINAL bytes rather than that refusal.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] on a persistence failure.
    pub async fn record_cross_plane_idempotency(
        &self,
        write: crate::repository::IdempotencyWrite<'_>,
    ) -> Result<(), crate::StoreError> {
        crate::repository::record_idempotency_alone(&self.pool, write).await
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
