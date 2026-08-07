// SPDX-License-Identifier: MIT OR Apache-2.0

//! The tenant lifecycle state machine, residency attributes, data-plane fence,
//! and the OFFBOARDING PIPELINE (issue #46), over a real database.
//!
//! Proves the acceptance criteria at the persistence layer:
//!
//! - the LIFECYCLE state machine: a created tenant is active; suspend -> suspended
//!   and resume -> active are the only valid toggles; every INVALID transition
//!   (resume-an-active, suspend-a-suspended, and any transition of a deleted
//!   tenant) is refused fail closed;
//! - RESIDENCY: a tenant's `home_region` and a per-environment `region` pin are
//!   recorded on create, read back, and immutable (the control role's grant
//!   excludes them, so a rewrite is refused);
//! - the data-plane FENCE: a suspended tenant's scope reads as fenced and a resumed
//!   one reads as served again, with no data loss, and a SECOND suspension fences it
//!   again (the cascade's upsert conflict arm, which one suspend and one resume
//!   cannot tell apart from a fixed value);
//! - the OFFBOARDING PIPELINE: a grace delete fences the tenant but keeps its keys
//!   INTACT (restorable, no data loss); the retention window gates restore and hard
//!   delete under a manual clock; only the terminal HARD DELETE crypto-shreds the
//!   envelope KEK, permanently, while a sibling tenant is unaffected;
//! - a RESTORE undoes the delete WITHOUT touching the tenant's lifecycle status
//!   (issue #432): a tenant that was suspended before the grace delete comes back
//!   still suspended AND still fenced, so a tenant READ and the data plane agree,
//!   while an active one serves again; and it REPORTS the status it committed
//!   rather than a predicted one (issue #438), which is what the endpoint's 200 body
//!   and every Idempotency-Key replay of it are rendered from;
//! - a RESTORE undoes THE DELETION IT IS UNDOING and no other (issue #439): an
//!   environment, or a management credential, that an operator deleted on its own
//!   beforehand stays deleted, stays fenced and stays unusable, while everything the
//!   tenant delete took down comes back; a tenant RESUME does not serve a deleted
//!   environment either, which is the same rule on the transition path; the deletions
//!   are told apart even when they read the SAME microsecond off a frozen clock,
//!   because the grace delete stamps strictly later than every tombstone it finds
//!   without dating itself back to one; an environment OUTSIDE the restored set is
//!   fenced rather than left on the serving absent-row default; a tenant whose
//!   environments were all decommissioned first comes back with none of them; and a
//!   restore whose deletion instant is re-stamped underneath it, by a real concurrent
//!   writer, is refused whole;
//! - cross-tenant isolation and audited transitions.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_env::{Env, ManualClock};
use ironauth_jose::MasterKey;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, EnvironmentId, EnvironmentServingState, EnvironmentType,
    ManagementKeyId, NewEnvironment, NewSigningKey, OperatorId, Scope, SigningKeyId,
    SigningKeyMaterialKind, StoreError, TenantId, TenantStatus,
};
use sqlx::Row;

/// A minted day-one key for a create transaction: its id and arbitrary seed bytes
/// (the store persists the seed verbatim, so these lifecycle tests need no real
/// cryptography). Mirrors the helper in the environment-guardrails suite.
struct DayOneKey {
    id: SigningKeyId,
    seed: [u8; 32],
}

impl DayOneKey {
    fn generate(env: &Env, scope: &Scope) -> Self {
        let id = SigningKeyId::generate(env, scope);
        let mut seed = [0_u8; 32];
        env.entropy().fill_bytes(&mut seed);
        Self { id, seed }
    }

    fn as_new(&self) -> NewSigningKey<'_> {
        NewSigningKey {
            id: &self.id,
            algorithm: "EdDSA",
            material_kind: SigningKeyMaterialKind::Ed25519Seed,
            material: &self.seed,
            publish_at_micros: 0,
            activate_at_micros: 0,
            retire_at_micros: None,
            expire_at_micros: None,
        }
    }
}

/// A test retention window: 30 days, so an in-window restore and a post-window hard
/// delete are cleanly separated by advancing the manual clock.
const RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A generated operator id shared by every tenant a test creates (so one operator
/// owns them all, mirroring the bootstrap operator plane).
struct Fixture {
    db: TestDatabase,
    env: Env,
    clock: Arc<ManualClock>,
    operator: OperatorId,
    actor: ActorRef,
    master: MasterKey,
}

impl Fixture {
    async fn start() -> Self {
        let db = TestDatabase::start().await;
        // A MANUAL clock frozen at the Unix epoch, so the offboarding retention
        // window is driven explicitly (these tests do not assert on absolute
        // timestamps, only on state and on the window boundary).
        let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0046);
        let operator = OperatorId::generate(&env);
        let actor = db.test_actor(&env);
        // A fresh master key for the envelope substrate. It is passed explicitly to
        // every provision/seal/open below, so the only requirement is internal
        // consistency (the generic secret path never reads the store's own key).
        let master = MasterKey::generate("lifecycle-test", env.entropy());
        Self {
            db,
            env,
            clock,
            operator,
            actor,
            master,
        }
    }

    /// Create a tenant (with its first environment) under the shared operator, with
    /// an optional recorded `home_region`. Returns the tenant scope.
    async fn create_tenant(&self, region: Option<&str>) -> Scope {
        let tenant = TenantId::generate(&self.env);
        let environment = EnvironmentId::generate(&self.env);
        let scope = Scope::new(tenant, environment);
        let key = DayOneKey::generate(&self.env, &scope);
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .create(
                &self.env,
                &tenant,
                &environment,
                1_000_000,
                "test operator",
                "test tenant",
                NewEnvironment {
                    display_name: "production",
                    kind: EnvironmentType::Dev,
                    custom_domain: None,
                    region: None,
                },
                region,
                &[key.as_new()],
                None,
            )
            .await
            .expect("create tenant");
        scope
    }

    async fn status(&self, tenant: &TenantId) -> Result<TenantStatus, StoreError> {
        self.db
            .control_store()
            .management()
            .tenants(self.operator)
            .get(tenant)
            .await
            .map(|record| record.status)
    }

    async fn suspend(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .suspend(&self.env, tenant, None)
            .await
    }

    async fn resume(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .resume(&self.env, tenant, None)
            .await
    }

    async fn delete(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .delete(&self.env, tenant)
            .await
    }

    /// Restore a grace-deleted tenant. Reports the lifecycle status the restore
    /// COMMITTED (issue #438), which is the status the tenant held before it was
    /// deleted, not a fixed `active`.
    async fn restore(&self, tenant: &TenantId) -> Result<TenantStatus, StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .restore(&self.env, tenant, RETENTION, None)
            .await
    }

    /// Attempt the grace delete as a DIFFERENT operator: the operator-plane isolation
    /// question for the offboarding path.
    async fn delete_as(&self, operator: OperatorId, tenant: &TenantId) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(operator)
            .delete(&self.env, tenant)
            .await
    }

    async fn hard_delete(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .hard_delete(&self.env, tenant, RETENTION, None)
            .await
    }

    /// Create a second environment (with an optional region pin) under an existing
    /// tenant, through the acting environment repository, and return its scope.
    async fn create_environment(&self, tenant: TenantId, region: Option<&str>) -> Scope {
        let (scope, result) = self.try_create_environment(tenant, region).await;
        result.expect("create environment");
        scope
    }

    /// Attempt to create a second environment under an existing tenant, returning the
    /// candidate scope alongside the raw store result so a test can assert on a
    /// refusal (for example a create under a non-active tenant).
    async fn try_create_environment(
        &self,
        tenant: TenantId,
        region: Option<&str>,
    ) -> (Scope, Result<(), StoreError>) {
        let environment = EnvironmentId::generate(&self.env);
        let scope = Scope::new(tenant, environment);
        let key = DayOneKey::generate(&self.env, &scope);
        let result = self
            .db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .environments(tenant)
            .create(
                &self.env,
                &environment,
                2_000_000,
                NewEnvironment {
                    display_name: "staging",
                    kind: EnvironmentType::Dev,
                    custom_domain: None,
                    region,
                },
                &[key.as_new()],
                None,
            )
            .await;
        (scope, result)
    }

    /// Delete ONE environment on its own, through the environment repository, the way
    /// an operator decommissions a single environment without touching the tenant.
    async fn delete_environment(&self, scope: Scope) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .environments(scope.tenant())
            .delete(&self.env, &scope.environment())
            .await
    }

    /// Whether a control-plane read still resolves this environment as LIVE (the read
    /// filters on `deleted_at IS NULL`, so this is the tombstone, observed the way the
    /// management API observes it).
    async fn environment_is_live(&self, scope: Scope) -> bool {
        self.db
            .control_store()
            .management()
            .environments(scope.tenant())
            .get(&scope.environment())
            .await
            .is_ok()
    }

    /// The raw `deleted_at` on an environment row, in epoch microseconds, or `None`
    /// when the row is live. Read straight out of the table because the #439
    /// discriminator is an ORDERING BETWEEN two tombstones and no repository read
    /// exposes either instant.
    async fn environment_deleted_at(&self, scope: Scope) -> Option<i64> {
        sqlx::query(
            "SELECT (EXTRACT(EPOCH FROM deleted_at) * 1000000)::bigint AS deleted_us \
             FROM environments WHERE id = $1",
        )
        .bind(scope.environment().to_string())
        .fetch_one(self.db.control_pool())
        .await
        .expect("read the environment tombstone")
        .get("deleted_us")
    }

    /// The raw `deleted_at` on a tenant row, in epoch microseconds, or `None` when the
    /// tenant is live. The other half of [`Fixture::environment_deleted_at`].
    async fn tenant_deleted_at(&self, tenant: &TenantId) -> Option<i64> {
        sqlx::query(
            "SELECT (EXTRACT(EPOCH FROM deleted_at) * 1000000)::bigint AS deleted_us \
             FROM tenants WHERE id = $1",
        )
        .bind(tenant.to_string())
        .fetch_one(self.db.control_pool())
        .await
        .expect("read the tenant tombstone")
        .get("deleted_us")
    }

    /// Insert an environments row DIRECTLY: live, with no serving-state row and no
    /// tombstone. That is the state a create leaves behind when it commits between a
    /// tenant delete's environment scan and that delete's commit, and no repository
    /// path produces it, because `ActingEnvironmentRepo::create` refuses a parent that
    /// is already tombstoned. The point here is the STATE, not the path to it.
    async fn insert_bare_environment(&self, tenant: TenantId) -> Scope {
        let environment = EnvironmentId::generate(&self.env);
        sqlx::query("INSERT INTO environments (id, tenant_id, display_name) VALUES ($1, $2, $3)")
            .bind(environment.to_string())
            .bind(tenant.to_string())
            .bind("arrived-mid-offboarding")
            .execute(self.db.control_pool())
            .await
            .expect("insert a bare environment row");
        Scope::new(tenant, environment)
    }

    /// Mint a management key in `scope` and return its id together with the hash it
    /// authenticates against, so a test can ask whether the credential still works.
    async fn mint_key(&self, scope: Scope, display_name: &str) -> (ManagementKeyId, String) {
        let id = ManagementKeyId::generate(&self.env, &scope);
        let key_hash = format!("hash-of-{display_name}");
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .credentials(scope)
            .create(&self.env, &id, 3_000_000, &key_hash, display_name, None)
            .await
            .expect("mint management key");
        (id, key_hash)
    }

    /// Revoke ONE management key on its own (the operator-driven revocation, distinct
    /// from the tenant delete's cascade).
    async fn revoke_key(&self, scope: Scope, id: &ManagementKeyId) {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .credentials(scope)
            .delete(&self.env, id)
            .await
            .expect("revoke management key");
    }

    /// Whether a management key still authenticates: the functional question a revoked
    /// credential must keep answering `false`.
    async fn key_authenticates(&self, scope: Scope, id: &ManagementKeyId, hash: &str) -> bool {
        self.db
            .control_store()
            .management()
            .credentials(scope)
            .authenticate(id, hash)
            .await
            .expect("authenticate management key")
    }

    /// Read an environment's recorded region pin through a control-plane read.
    async fn environment_region(&self, scope: Scope) -> Option<String> {
        self.db
            .control_store()
            .management()
            .environments(scope.tenant())
            .get(&scope.environment())
            .await
            .expect("get environment")
            .region
    }

    async fn serving_state(&self, scope: Scope) -> EnvironmentServingState {
        self.db
            .store()
            .scoped(scope)
            .environment_state()
            .await
            .expect("read serving state")
    }

    /// Provision a scope's KEK + DEK and seal one PII secret through the data plane.
    async fn seal_pii(&self, scope: Scope, purpose: &str, plaintext: &[u8]) {
        let acting = self
            .db
            .store()
            .scoped(scope)
            .acting(self.actor, CorrelationId::generate(&self.env));
        acting
            .envelope()
            .provision_kek(&self.env, &self.master)
            .await
            .expect("provision kek");
        acting
            .envelope()
            .provision_dek(&self.env, &self.master)
            .await
            .expect("provision dek");
        acting
            .envelope()
            .put_secret(&self.env, &self.master, purpose, plaintext)
            .await
            .expect("seal pii");
    }

    async fn open_pii(&self, scope: Scope, purpose: &str) -> Result<Vec<u8>, StoreError> {
        self.db
            .store()
            .scoped(scope)
            .envelope()
            .open_secret(&self.master, purpose)
            .await
    }

    /// Every audit action recorded against `tenant`, read as the owner.
    async fn audit_actions(&self, tenant: &TenantId) -> Vec<String> {
        sqlx::query(
            "SELECT action FROM audit_log WHERE tenant_id = $1 ORDER BY occurred_at, action",
        )
        .bind(tenant.to_string())
        .fetch_all(self.db.owner_pool())
        .await
        .expect("read audit log")
        .iter()
        .map(|row| row.get::<String, _>("action"))
        .collect()
    }
}

#[tokio::test]
async fn a_created_tenant_is_active_and_records_its_home_region() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(Some("eu-west")).await;

    let record = fx
        .db
        .control_store()
        .management()
        .tenants(fx.operator)
        .get(&scope.tenant())
        .await
        .expect("get tenant");
    assert_eq!(
        record.status,
        TenantStatus::Active,
        "created tenant is active"
    );
    assert_eq!(
        record.home_region.as_deref(),
        Some("eu-west"),
        "the recorded residency region round-trips through a read"
    );
    // A tenant created with no region records none.
    let bare = fx.create_tenant(None).await;
    let bare_record = fx
        .db
        .control_store()
        .management()
        .tenants(fx.operator)
        .get(&bare.tenant())
        .await
        .expect("get bare tenant");
    assert_eq!(
        bare_record.home_region, None,
        "no region recorded when omitted"
    );
}

#[tokio::test]
async fn suspend_and_resume_are_the_only_valid_toggles() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    // active --suspend--> suspended (valid).
    fx.suspend(&tenant).await.expect("suspend an active tenant");
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Suspended
    );

    // suspended --suspend--> INVALID (already suspended): refused fail closed.
    assert!(
        matches!(fx.suspend(&tenant).await, Err(StoreError::Conflict)),
        "suspending an already-suspended tenant is an invalid transition"
    );

    // suspended --resume--> active (valid).
    fx.resume(&tenant).await.expect("resume a suspended tenant");
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Active
    );

    // active --resume--> INVALID (already active): refused fail closed.
    assert!(
        matches!(fx.resume(&tenant).await, Err(StoreError::Conflict)),
        "resuming an already-active tenant is an invalid transition"
    );
}

#[tokio::test]
async fn a_deleted_tenant_refuses_every_further_transition() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    fx.delete(&tenant)
        .await
        .expect("delete (offboard) the tenant");

    // A deleted tenant is a tombstone: it is not visible to reads, and suspend,
    // resume, and a repeated delete are all the uniform NotFound (never a Conflict,
    // never a success).
    assert!(matches!(
        fx.status(&tenant).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fx.suspend(&tenant).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fx.resume(&tenant).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fx.delete(&tenant).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn a_suspended_tenant_is_fenced_off_the_data_plane_and_resumes_cleanly() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    // A fresh, active tenant is served (no fence).
    assert_eq!(
        fx.serving_state(scope).await,
        EnvironmentServingState::Active,
        "an active tenant serves its data plane"
    );

    // Suspend fences every one of the tenant's environments on the data plane.
    fx.suspend(&tenant).await.expect("suspend");
    assert_eq!(
        fx.serving_state(scope).await,
        EnvironmentServingState::Suspended,
        "a suspended tenant is fenced off the data plane"
    );
    assert!(fx.serving_state(scope).await.is_fenced());

    // Resume un-fences it with no data loss.
    fx.resume(&tenant).await.expect("resume");
    assert_eq!(
        fx.serving_state(scope).await,
        EnvironmentServingState::Active,
        "a resumed tenant serves again"
    );
}

#[tokio::test]
async fn the_fence_spans_every_environment_of_a_tenant() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();
    // A second environment under the same tenant.
    let env2 = fx.db.seed_environment(&fx.env, tenant).await;
    let scope2 = Scope::new(tenant, env2);

    fx.suspend(&tenant).await.expect("suspend");
    // BOTH environments are fenced (a tenant-level suspension cascades to all).
    assert!(fx.serving_state(scope).await.is_fenced());
    assert!(fx.serving_state(scope2).await.is_fenced());

    fx.resume(&tenant).await.expect("resume");
    assert!(!fx.serving_state(scope).await.is_fenced());
    assert!(!fx.serving_state(scope2).await.is_fenced());
}

#[tokio::test]
async fn a_resumed_tenant_is_fenced_again_when_suspended_a_second_time() {
    // Pins the UPSERT'S CONFLICT ARM in the lifecycle cascade, which nothing else
    // asserted on. A fresh tenant has no `environment_states` row, so its FIRST
    // transition takes the INSERT arm and every later one takes `ON CONFLICT ... DO
    // UPDATE`. The other fence tests stop after one resume, and the value a correct
    // resume writes ('active') is also the value a conflict arm frozen at a literal
    // 'active' would write, so they cannot tell the two apart: forcing that arm to
    // 'active' survives them. A SECOND suspension is the shape that separates them,
    // because there the two disagree. Across two environments, so the whole cascade
    // is covered and not just its first row.
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();
    let scope2 = fx.create_environment(tenant, None).await;

    // First suspension: the INSERT arm, already covered elsewhere.
    fx.suspend(&tenant).await.expect("first suspend");
    assert!(fx.serving_state(scope).await.is_fenced());
    assert!(fx.serving_state(scope2).await.is_fenced());

    // Resume: the CONFLICT arm, writing the state a resume implies.
    fx.resume(&tenant).await.expect("resume");
    assert!(!fx.serving_state(scope).await.is_fenced());
    assert!(!fx.serving_state(scope2).await.is_fenced());

    // Second suspension: the CONFLICT arm again, and this time the state it must
    // write is NOT the one the previous write left behind.
    fx.suspend(&tenant).await.expect("second suspend");
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Suspended
    );
    assert_eq!(
        fx.serving_state(scope).await,
        EnvironmentServingState::Suspended,
        "a re-suspended tenant is fenced again: the cascade's conflict arm writes the \
         state the transition implies, not a fixed value"
    );
    assert_eq!(
        fx.serving_state(scope2).await,
        EnvironmentServingState::Suspended,
        "and so is every other environment of it"
    );
}

#[tokio::test]
async fn a_grace_deleted_tenant_is_fenced_but_keeps_its_keys_and_is_restorable() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    // Seal a PII secret, readable before offboarding.
    fx.seal_pii(scope, "email", b"ada@lovelace.test").await;
    assert_eq!(
        fx.open_pii(scope, "email").await.expect("pii"),
        b"ada@lovelace.test"
    );

    // Offboard into the GRACE stage: the data plane is fenced, but the keys are LEFT
    // INTACT (no crypto-shred), so the sealed PII still opens. This is the property
    // the immediate-shred over-implementation broke: erasure must not happen here.
    fx.delete(&tenant).await.expect("grace delete");
    assert!(
        fx.serving_state(scope).await.is_fenced(),
        "a grace-deleted tenant is fenced off the data plane"
    );
    assert_eq!(
        fx.open_pii(scope, "email")
            .await
            .expect("pii intact in grace"),
        b"ada@lovelace.test",
        "the grace delete keeps the KEK intact, so the sealed PII still opens"
    );
    let kek_status: String = sqlx::query(
        "SELECT status FROM tenant_keks WHERE tenant_id = $1 AND environment_id = $2 \
         ORDER BY version DESC LIMIT 1",
    )
    .bind(tenant.to_string())
    .bind(scope.environment().to_string())
    .fetch_one(fx.db.owner_pool())
    .await
    .expect("kek row present")
    .get("status");
    assert_eq!(
        kek_status, "active",
        "the KEK is NOT destroyed by a grace delete"
    );

    // RESTORE inside the retention window: the tenant is live again, serving resumes,
    // and the PII opens (no data loss).
    fx.restore(&tenant).await.expect("restore in window");
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Active,
        "a restored tenant is active again"
    );
    assert!(
        !fx.serving_state(scope).await.is_fenced(),
        "a restored tenant serves its data plane again"
    );
    assert_eq!(
        fx.open_pii(scope, "email")
            .await
            .expect("pii after restore"),
        b"ada@lovelace.test",
        "a restored tenant loses no data"
    );
}

#[tokio::test]
async fn a_restore_returns_a_suspended_tenant_to_its_fence() {
    // A restore undoes the grace DELETE without touching the tenant's lifecycle status
    // (issue #432). It must not also lift an unrelated SUSPENSION:
    // `TenantStatus::Suspended` documents that a suspended tenant "is fenced (a
    // structured refusal) ... and a resume restores service", so a tenant whose
    // `status` still reads suspended must come back off the data plane. The defect
    // this pins wrote a literal `active` serving state for every environment, leaving
    // `tenants.status = suspended` (what a subsequent tenant READ reports) disagreeing
    // with an unfenced data plane, with no operator action ever having lifted the
    // suspension.
    let fx = Fixture::start().await;

    // The CONTROL, taken in the same test so the fence asserted below is attributable
    // to the suspension rather than to a restore that fences everything: an ACTIVE
    // tenant, deleted and restored, comes back SERVING. That DIRECTION is not new
    // here; `a_grace_deleted_tenant_is_fenced_but_keeps_its_keys_and_is_restorable`
    // already asserts a restored active tenant serves again on its single
    // environment. What this control adds is the SECOND environment, so the
    // derivation is controlled across the whole per-environment cascade rather than
    // on its first row only.
    let control = fx.create_tenant(None).await;
    let control_tenant = control.tenant();
    let control2 = fx.create_environment(control_tenant, None).await;

    // The subject: a suspended tenant, with a SECOND environment so the derivation is
    // proven across the whole per-environment cascade rather than on one row.
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();
    let scope2 = fx.create_environment(tenant, None).await;

    fx.suspend(&tenant).await.expect("suspend");
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Suspended
    );
    assert!(fx.serving_state(scope).await.is_fenced());
    assert!(fx.serving_state(scope2).await.is_fenced());

    // Grace-delete BOTH, then restore both inside the retention window.
    fx.delete(&control_tenant).await.expect("delete control");
    fx.delete(&tenant).await.expect("grace delete");
    fx.restore(&control_tenant).await.expect("restore control");
    fx.restore(&tenant).await.expect("restore in window");

    // The control serves again: the restore is not over-fencing.
    assert_eq!(
        fx.status(&control_tenant).await.expect("control status"),
        TenantStatus::Active,
        "a restored active tenant is active again"
    );
    assert!(
        !fx.serving_state(control).await.is_fenced(),
        "a restored ACTIVE tenant serves its data plane again"
    );
    assert!(
        !fx.serving_state(control2).await.is_fenced(),
        "and so does every one of its environments"
    );

    // The subject stays suspended in the control-plane READ (the one `GET
    // /v1/tenants/{id}` serves) AND stays fenced on the data plane: the two agree,
    // which is the property the defect broke. What the restore REPORTS is a third
    // surface, asserted in `a_restore_reports_the_status_it_committed`.
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Suspended,
        "a restore does not silently lift a suspension"
    );
    assert!(
        fx.serving_state(scope).await.is_fenced(),
        "a restored SUSPENDED tenant stays fenced off the data plane"
    );
    assert!(
        fx.serving_state(scope2).await.is_fenced(),
        "every environment of the restored suspended tenant stays fenced"
    );

    // The suspension is lifted only by the explicit RESUME, which still works on the
    // restored tenant and un-fences every one of its environments, so the fence a
    // restore preserves is not a permanent one. (Whether a restore loses DATA is a
    // different property, asserted over sealed PII in
    // `a_grace_deleted_tenant_is_fenced_but_keeps_its_keys_and_is_restorable`; this
    // test opens no PII and claims none.)
    fx.resume(&tenant).await.expect("resume after restore");
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Active
    );
    assert!(!fx.serving_state(scope).await.is_fenced());
    assert!(!fx.serving_state(scope2).await.is_fenced());
}

#[tokio::test]
async fn a_restore_leaves_an_individually_deleted_environment_deleted() {
    // A restore undoes THE DELETION IT IS UNDOING, not every deletion that ever
    // happened under the tenant (issue #439). The defect this pins cleared
    // `deleted_at` on EVERY environment of the tenant and wrote the tenant's serving
    // state over every one of them, so an environment an operator had decommissioned
    // on its own, before the tenant was ever offboarded, came back LIVE and SERVING as
    // a side effect of the tenant restore. Same one level down for management
    // credentials: a key revoked on its own came back able to authenticate.
    //
    // Every assertion below is made TWICE, once for the environment the tenant delete
    // took down (which must come back) and once for the one the operator took down
    // (which must not), so a fix that simply revived nothing would fail here just as
    // loudly as the defect.
    //
    // The clock is NEVER advanced, deliberately: this fixture's clock is manual and
    // frozen, so both deletions read the SAME microsecond off it. That is the case the
    // instant alone cannot separate, and it fails OPEN on all three dimensions below
    // (the decommissioned environment comes back live, unfenced, and the revoked key
    // authenticates again). The delete does not take the clock reading raw: it locks
    // the tenant's environment rows, reads the tombstones already under the tenant, and
    // stamps STRICTLY LATER than all of them. So this test runs the hardest ordering,
    // not the easiest.
    let fx = Fixture::start().await;
    let kept = fx.create_tenant(None).await;
    let tenant = kept.tenant();
    let decommissioned = fx.create_environment(tenant, None).await;

    // Two management keys in the environment that SURVIVES, so the credential half is
    // observed where `authenticate` can actually answer: it also joins the environment
    // and the tenant, so a key in the decommissioned environment would read as
    // unusable whatever its own tombstone said, and would prove nothing.
    let (revoked_key, revoked_hash) = fx.mint_key(kept, "revoked-before-offboarding").await;
    let (live_key, live_hash) = fx.mint_key(kept, "live-at-offboarding").await;
    assert!(
        fx.key_authenticates(kept, &revoked_key, &revoked_hash)
            .await,
        "both keys authenticate before anything is deleted"
    );

    // The operator decommissions one environment and revokes one key, deliberately and
    // independently of any tenant offboarding.
    fx.delete_environment(decommissioned)
        .await
        .expect("delete one environment on its own");
    fx.revoke_key(kept, &revoked_key).await;
    assert!(
        !fx.environment_is_live(decommissioned).await,
        "the decommissioned environment is deleted"
    );
    assert!(
        fx.serving_state(decommissioned).await.is_fenced(),
        "and its data plane is fenced"
    );
    assert!(
        !fx.key_authenticates(kept, &revoked_key, &revoked_hash)
            .await,
        "the revoked key no longer authenticates"
    );

    // No clock advance: the whole tenant is offboarded in the SAME microsecond the
    // operator's two deletions read, and then restored inside the window.
    fx.delete(&tenant).await.expect("grace delete");

    // The ordering the restore discriminates on, asserted DIRECTLY on the rows before
    // anything is undone: the two deletions read one microsecond off the frozen clock
    // and the offboarding's tombstone is still strictly later. Everything below is a
    // consequence of this one inequality.
    let decommissioned_at = fx
        .environment_deleted_at(decommissioned)
        .await
        .expect("the decommissioned environment is tombstoned");
    let offboarded_at = fx.tenant_deleted_at(&tenant).await.expect("in grace");
    assert!(
        offboarded_at > decommissioned_at,
        "the offboarding's instant ({offboarded_at}) must be STRICTLY later than the \
         tombstone that already existed ({decommissioned_at}), even when both deletions \
         read the same microsecond"
    );

    assert_eq!(
        fx.restore(&tenant).await.expect("restore in window"),
        TenantStatus::Active
    );

    // The environment the TENANT delete took down comes back, live and serving, with
    // the credential that was live when it went down.
    assert!(
        fx.environment_is_live(kept).await,
        "the environment the tenant delete tombstoned is live again"
    );
    assert!(
        !fx.serving_state(kept).await.is_fenced(),
        "and serves its data plane again"
    );
    assert!(
        fx.key_authenticates(kept, &live_key, &live_hash).await,
        "and the key that was live at offboarding authenticates again"
    );

    // The environment the OPERATOR took down stays down, on both dimensions: the
    // control-plane read still refuses it, and its data plane is still fenced. A
    // restore that only cleared the tombstone would pass the first and fail the
    // second, and one that only skipped the fence would fail the first.
    assert!(
        !fx.environment_is_live(decommissioned).await,
        "an environment deleted on its own stays deleted through a tenant restore"
    );
    assert!(
        fx.serving_state(decommissioned).await.is_fenced(),
        "and its data plane stays fenced"
    );
    assert!(
        !fx.key_authenticates(kept, &revoked_key, &revoked_hash)
            .await,
        "a management key revoked on its own stays revoked through a tenant restore"
    );
}

#[tokio::test]
async fn a_tenant_cannot_be_offboarded_by_another_operator() {
    // The operator predicate on the grace delete's guard is an isolation boundary, and
    // nothing in the tree asserted it: the predicate used to ride on the tombstone
    // UPDATE, where a mutation of it survived the whole suite because no test ever
    // constructed a second operator. It now rides on the row lock that opens the
    // transaction, which is a better place for it and no better measured, so this pins
    // it. The tenant must be INVISIBLE to an operator that does not own it, refused as
    // the uniform not-found rather than as a distinguishable permission error, and left
    // completely untouched.
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();
    let stranger = OperatorId::generate(&fx.env);

    assert!(
        matches!(
            fx.delete_as(stranger, &tenant).await,
            Err(StoreError::NotFound)
        ),
        "a tenant is not offboardable by an operator that does not own it"
    );
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Active,
        "and the refused offboarding left the tenant live"
    );
    assert!(
        fx.environment_is_live(scope).await && !fx.serving_state(scope).await.is_fenced(),
        "and its environment untouched and serving"
    );

    // The CONTROL: the OWNING operator's delete does go through, so the refusal above
    // is attributable to the operator rather than to a delete that refuses everything.
    fx.delete(&tenant)
        .await
        .expect("the owning operator offboards it");
    assert!(!fx.environment_is_live(scope).await);
}

#[tokio::test]
async fn a_restore_leaves_an_individually_revoked_management_key_revoked() {
    // The CREDENTIAL half of #439, isolated from the environment half, because the two
    // are separate dimensions and only one of them is covered by the other test.
    // Nothing is decommissioned here, so the only tombstone under the tenant when it is
    // offboarded is the REVOCATION's, read off the same frozen microsecond the
    // offboarding reads. A grace delete that consulted only its ENVIRONMENTS when
    // choosing its instant would find none, stamp the raw clock reading, tie with the
    // revocation, and hand a decommissioned management credential back its access as a
    // side effect of the tenant restore.
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();
    let (revoked, revoked_hash) = fx.mint_key(scope, "revoked-before-offboarding").await;
    let (live, live_hash) = fx.mint_key(scope, "live-at-offboarding").await;
    fx.revoke_key(scope, &revoked).await;
    assert!(
        !fx.key_authenticates(scope, &revoked, &revoked_hash).await,
        "the revoked key no longer authenticates"
    );

    fx.delete(&tenant).await.expect("grace delete");
    assert_eq!(
        fx.restore(&tenant).await.expect("restore in window"),
        TenantStatus::Active
    );

    // The CONTROL and the subject, in one test, so a restore that revived nothing fails
    // as loudly as one that revived everything.
    assert!(
        fx.key_authenticates(scope, &live, &live_hash).await,
        "the key that was live at offboarding authenticates again"
    );
    assert!(
        !fx.key_authenticates(scope, &revoked, &revoked_hash).await,
        "a management key revoked on its own stays revoked through a tenant restore"
    );
}

#[tokio::test]
async fn a_grace_delete_does_not_drag_its_instant_back_to_an_older_tombstone() {
    // The other half of the #439 stamping rule. The instant is the LATER of the clock
    // and one microsecond past the tombstones already under the tenant, and the `later
    // of` is load bearing: an instant pulled back to `oldest + 1` would satisfy every
    // equality predicate the restore uses and would look entirely correct, while
    // silently dating the offboarding to whenever the FIRST environment was
    // decommissioned. The retention window is measured from that instant, so the
    // tenant would age out of its own grace period early.
    const TWENTY_DAYS: Duration = Duration::from_secs(20 * 24 * 60 * 60);

    let fx = Fixture::start().await;
    let kept = fx.create_tenant(None).await;
    let tenant = kept.tenant();
    let decommissioned = fx.create_environment(tenant, None).await;
    fx.delete_environment(decommissioned)
        .await
        .expect("decommission one environment on its own");

    // Twenty days later the tenant is offboarded. Its tombstone is the CLOCK's, not
    // one microsecond past the decommissioning.
    fx.clock.advance(TWENTY_DAYS);
    fx.delete(&tenant).await.expect("grace delete");
    let offboarded_at = fx.tenant_deleted_at(&tenant).await.expect("in grace");
    assert_eq!(
        offboarded_at,
        i64::try_from(TWENTY_DAYS.as_micros()).expect("twenty days in microseconds"),
        "the grace delete stamps the clock's reading when it is already the later value"
    );

    // Twenty more days: forty since the environment went down, twenty since the tenant
    // did, against a thirty day retention window. A restore is still on offer, which it
    // would not be had the tenant's tombstone been dated to the decommissioning.
    fx.clock.advance(TWENTY_DAYS);
    assert_eq!(
        fx.restore(&tenant)
            .await
            .expect("restore inside the TENANT's own retention window"),
        TenantStatus::Active
    );
}

#[tokio::test]
async fn a_restore_of_a_tenant_whose_environments_were_all_decommissioned_brings_none_back() {
    // The NARROWING that #439's rule implies, pinned because it is not what an operator
    // would guess and because the behaviour before the fix was the exact opposite: a
    // tenant whose environments were ALL decommissioned individually before it was
    // offboarded comes back LIVE with ZERO live environments. Every one of those
    // tombstones belongs to its own decommissioning, so nothing in a tenant restore is
    // entitled to lift it. The last assertion records the narrowing as SURVIVABLE
    // rather than terminal: a fresh environment under the restored tenant serves.
    let fx = Fixture::start().await;
    let first = fx.create_tenant(None).await;
    let tenant = first.tenant();
    let second = fx.create_environment(tenant, None).await;
    fx.delete_environment(first)
        .await
        .expect("decommission the first environment");
    fx.delete_environment(second)
        .await
        .expect("decommission the second environment");

    fx.delete(&tenant).await.expect("grace delete");
    assert_eq!(
        fx.restore(&tenant).await.expect("restore in window"),
        TenantStatus::Active
    );

    // The TENANT is back and reads active.
    assert_eq!(
        fx.status(&tenant).await.expect("status"),
        TenantStatus::Active,
        "the tenant itself is restored"
    );
    // And it has nothing live under it, on both dimensions, for both environments.
    assert!(
        !fx.environment_is_live(first).await && !fx.environment_is_live(second).await,
        "no environment the operator decommissioned comes back"
    );
    assert!(
        fx.serving_state(first).await.is_fenced() && fx.serving_state(second).await.is_fenced(),
        "and neither data plane serves"
    );

    // Recoverable: a fresh environment under the restored tenant is live and serving.
    let fresh = fx.create_environment(tenant, None).await;
    assert!(
        fx.environment_is_live(fresh).await && !fx.serving_state(fresh).await.is_fenced(),
        "a fresh environment under the restored tenant serves, so the narrowing is \
         recoverable"
    );
}

#[tokio::test]
async fn a_restore_fences_an_environment_that_arrived_after_the_delete_scanned() {
    // `ActingEnvironmentRepo::create` checks the parent tenant's liveness with a
    // NON-LOCKING read, so under READ COMMITTED a create can commit after a tenant
    // delete listed the tenant's environments and before that delete committed. What
    // it leaves behind is an environment that is LIVE, carries no tombstone of this
    // delete's, and has no `environment_states` row at all. An absent row is the one
    // input `environment_state` reads as SERVING, so a restore that wrote only over its
    // matched set would leave that environment serving.
    //
    // The interleaving cannot be staged from a test, so the STATE it leaves is staged
    // directly: the row the racing create would have committed, and no serving state.
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();
    fx.delete(&tenant).await.expect("grace delete");
    let arrived = fx.insert_bare_environment(tenant).await;
    assert!(
        !fx.serving_state(arrived).await.is_fenced(),
        "with no serving-state row of its own it SERVES, which is the hazard"
    );

    assert_eq!(
        fx.restore(&tenant).await.expect("restore in window"),
        TenantStatus::Active
    );

    assert!(
        fx.serving_state(arrived).await.is_fenced(),
        "an environment outside the restored set is FENCED, not left on the absent-row \
         serving default"
    );
    // The CONTROL, and it discriminates precisely because the tenant is ACTIVE: the
    // environment this delete DID take down comes back SERVING in the same restore, so
    // the fence above is attributable to the environment being outside the matched set
    // rather than to a restore that fenced everything.
    assert!(
        !fx.serving_state(scope).await.is_fenced(),
        "the environment the tenant delete tombstoned serves again"
    );
}

#[tokio::test]
async fn a_restore_whose_deletion_instant_was_re_stamped_underneath_it_is_refused() {
    // The restore PRE-READS the deletion instant outside its transaction and every
    // cascade inside matches on that value, so the in-transaction tenant guard PINS it
    // (`deleted_at` equal to the pre-read, not merely `deleted_at IS NOT NULL`).
    // Without the pin, a restore-then-delete committing in that window would clear the
    // tenant tombstone while every cascade matched nothing, leaving a LIVE tenant whose
    // environments are all still tombstoned and fenced: the silent half-restored state.
    //
    // Staged with a real concurrent transaction rather than reasoned about. It
    // re-stamps the tombstones to a later instant and HOLDS the tenant row lock, so the
    // restore below pre-reads the OLD instant (an uncommitted write is invisible) and
    // then parks on that row until the re-stamp commits, which is exactly the
    // interleaving the pin exists for.
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();
    fx.delete(&tenant).await.expect("grace delete");

    let pool = fx.db.control_pool();
    let mut poisoner = pool.begin().await.expect("begin the racing writer");
    sqlx::query("UPDATE tenants SET deleted_at = deleted_at + INTERVAL '1 hour' WHERE id = $1")
        .bind(tenant.to_string())
        .execute(&mut *poisoner)
        .await
        .expect("re-stamp the tenant tombstone");
    sqlx::query(
        "UPDATE environments SET deleted_at = deleted_at + INTERVAL '1 hour' \
         WHERE tenant_id = $1 AND deleted_at IS NOT NULL",
    )
    .bind(tenant.to_string())
    .execute(&mut *poisoner)
    .await
    .expect("re-stamp the environment tombstones");

    let (result, ()) = tokio::join!(fx.restore(&tenant), async move {
        wait_until_a_backend_is_lock_blocked(pool).await;
        poisoner.commit().await.expect("commit the re-stamp");
    });

    assert!(
        matches!(result, Err(StoreError::NotFound)),
        "a restore whose pinned instant no longer matches is the uniform not found, \
         got {result:?}"
    );
    assert!(
        !fx.environment_is_live(scope).await,
        "and nothing is half applied: the environment stays tombstoned rather than \
         being stranded under a live tenant"
    );

    // The CONTROL: a FRESH restore, which pre-reads the NEW instant, succeeds and
    // brings everything back, so the refusal above is attributable to the pin rather
    // than to a restore that stopped working.
    assert_eq!(
        fx.restore(&tenant)
            .await
            .expect("a restore that pre-reads the re-stamped instant"),
        TenantStatus::Active
    );
    assert!(fx.environment_is_live(scope).await);
    assert!(!fx.serving_state(scope).await.is_fenced());
}

/// Block until some backend in THIS test's database is waiting on a lock.
///
/// The restore's first write is its guarded tenant UPDATE, so a lock wait here means
/// its pre-read has already run and it is parked on the racing writer's row lock: the
/// exact interleaving, reached without guessing a sleep. `pg_stat_activity` reports
/// wait state only for sessions the reader owns, and both the harness pool and the
/// store connect as the same low-privilege control role, so it is visible.
async fn wait_until_a_backend_is_lock_blocked(pool: &sqlx::PgPool) {
    for _ in 0..2_000 {
        let blocked: i64 = sqlx::query(
            "SELECT count(*) AS blocked FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .expect("read pg_stat_activity")
        .get("blocked");
        if blocked > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("no backend ever blocked on the racing writer's row lock");
}

#[tokio::test]
async fn a_tenant_resume_leaves_a_deleted_environment_fenced() {
    // The sibling of issue #439 on the SUSPEND/RESUME path, found by sweeping for the
    // same shape and measured before it was fixed: the transition cascade wrote the
    // tenant's derived serving state over EVERY environment, so a resume SERVED an
    // environment an operator had decommissioned. It matters because
    // `environment_state` reads that row and nothing else: a deleted environment's
    // whole data-plane fence is the row this cascade was overwriting. Without this the
    // restore fix is undone by the next suspend/resume pair.
    let fx = Fixture::start().await;
    let kept = fx.create_tenant(None).await;
    let tenant = kept.tenant();
    let decommissioned = fx.create_environment(tenant, None).await;

    fx.delete_environment(decommissioned)
        .await
        .expect("delete one environment on its own");
    assert!(
        fx.serving_state(decommissioned).await.is_fenced(),
        "its own deletion fences it"
    );

    fx.suspend(&tenant).await.expect("suspend");
    fx.resume(&tenant).await.expect("resume");

    assert!(
        fx.serving_state(decommissioned).await.is_fenced(),
        "a tenant resume does not serve an environment deleted on its own"
    );
    // The CONTROL: the live environment DOES come back, so the fence above is
    // attributable to the deletion rather than to a resume that stopped serving
    // anything.
    assert!(
        !fx.serving_state(kept).await.is_fenced(),
        "the tenant's live environment serves again after the resume"
    );
}

#[tokio::test]
async fn a_restore_reports_the_status_it_committed() {
    // The value the restore REPORTS is the one it wrote, for both statuses (issue
    // #438). This is the store half of the property; the endpoint half (that the 200
    // body and its Idempotency-Key replay carry it) is in the admin lifecycle suite.
    // Both directions are driven in one test so a report hardwired to either constant
    // fails: `active` fails the suspended row and `suspended` fails the active one.
    let fx = Fixture::start().await;

    let active = fx.create_tenant(None).await.tenant();
    fx.delete(&active).await.expect("delete active");
    assert_eq!(
        fx.restore(&active).await.expect("restore active"),
        TenantStatus::Active,
        "a restored active tenant reports active"
    );

    let suspended = fx.create_tenant(None).await.tenant();
    fx.suspend(&suspended).await.expect("suspend");
    fx.delete(&suspended).await.expect("delete suspended");
    assert_eq!(
        fx.restore(&suspended).await.expect("restore suspended"),
        TenantStatus::Suspended,
        "a restored SUSPENDED tenant reports suspended, not the restore's wished-for \
         post-condition"
    );

    // And the reported value is what a subsequent READ serves, which is the whole
    // point of reporting it from inside the write's transaction.
    assert_eq!(
        fx.status(&suspended).await.expect("status"),
        TenantStatus::Suspended
    );
    assert_eq!(
        fx.status(&active).await.expect("status"),
        TenantStatus::Active
    );
}

#[tokio::test]
async fn the_retention_window_gates_restore_and_hard_delete() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    fx.delete(&tenant).await.expect("grace delete");

    // Inside the window: hard delete is refused (the grace period must run first),
    // restore is allowed.
    assert!(
        matches!(fx.hard_delete(&tenant).await, Err(StoreError::Conflict)),
        "hard delete is refused inside the retention window"
    );

    // Advance the clock PAST the retention window.
    fx.clock.advance(RETENTION + Duration::from_secs(1));

    // Outside the window: restore is now refused (no longer offered), and hard delete
    // is due.
    assert!(
        matches!(fx.restore(&tenant).await, Err(StoreError::Conflict)),
        "restore is refused once the retention window has elapsed"
    );
    fx.hard_delete(&tenant)
        .await
        .expect("hard delete after window");

    // A purged tenant cannot be restored or purged again (a uniform NotFound).
    assert!(matches!(
        fx.restore(&tenant).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        fx.hard_delete(&tenant).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn hard_delete_crypto_shreds_its_pii_and_leaves_a_sibling_untouched() {
    let fx = Fixture::start().await;
    let victim = fx.create_tenant(None).await;
    let sibling = fx.create_tenant(None).await;

    // Both tenants seal a PII secret through the envelope substrate.
    fx.seal_pii(victim, "email", b"ada@lovelace.test").await;
    fx.seal_pii(sibling, "email", b"grace@hopper.test").await;
    assert_eq!(
        fx.open_pii(victim, "email").await.expect("victim pii"),
        b"ada@lovelace.test"
    );
    assert_eq!(
        fx.open_pii(sibling, "email").await.expect("sibling pii"),
        b"grace@hopper.test"
    );

    // Offboard the victim (grace), then advance past retention and HARD-DELETE: the
    // terminal stage crypto-shreds the victim's KEK. The ordinary delete never
    // shredded; only this terminal purge does.
    fx.delete(&victim.tenant()).await.expect("grace delete");
    fx.clock.advance(RETENTION + Duration::from_secs(1));
    fx.hard_delete(&victim.tenant()).await.expect("hard delete");

    // The victim's sealed PII is now PERMANENTLY undecryptable (the KEK is gone), a
    // distinct Encryption failure, never a plaintext and never a bare NotFound.
    assert!(
        matches!(
            fx.open_pii(victim, "email").await,
            Err(StoreError::Encryption)
        ),
        "a hard-deleted tenant's PII is undecryptable"
    );

    // The raw ciphertext is still on disk (nothing was deleted), the crypto-shred
    // property: the data remains but the key to it is destroyed.
    let ciphertext: Vec<u8> = sqlx::query(
        "SELECT ciphertext FROM encrypted_secrets WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(victim.tenant().to_string())
    .bind(victim.environment().to_string())
    .fetch_one(fx.db.owner_pool())
    .await
    .expect("ciphertext still present")
    .get("ciphertext");
    assert!(
        !ciphertext.is_empty(),
        "the sealed ciphertext is retained, only the key is shredded"
    );

    // The KEK row is retained as evidence but destroyed (empty wrapped bytes).
    let kek_status: String = sqlx::query(
        "SELECT status FROM tenant_keks WHERE tenant_id = $1 AND environment_id = $2 \
         ORDER BY version DESC LIMIT 1",
    )
    .bind(victim.tenant().to_string())
    .bind(victim.environment().to_string())
    .fetch_one(fx.db.owner_pool())
    .await
    .expect("kek row retained")
    .get("status");
    assert_eq!(kek_status, "destroyed", "the victim's KEK is destroyed");

    // The SIBLING tenant is entirely unaffected: its PII still opens, because every
    // scope has its own KEK and only the victim's was shredded.
    assert_eq!(
        fx.open_pii(sibling, "email")
            .await
            .expect("sibling pii survives"),
        b"grace@hopper.test",
        "a sibling tenant's PII is untouched by the victim's hard delete"
    );
}

#[tokio::test]
async fn an_environment_records_and_returns_its_region_pin() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(Some("eu-west")).await;

    // A second environment with its own region pin round-trips through a read.
    let pinned = fx.create_environment(scope.tenant(), Some("us-east")).await;
    assert_eq!(
        fx.environment_region(pinned).await.as_deref(),
        Some("us-east"),
        "the per-environment region pin round-trips through a read"
    );

    // An environment created without a pin records none.
    let bare = fx.create_environment(scope.tenant(), None).await;
    assert_eq!(
        fx.environment_region(bare).await,
        None,
        "no region recorded when omitted"
    );
}

#[tokio::test]
async fn a_new_environment_is_refused_under_a_non_active_tenant() {
    // The suspend/offboard fence covers only the environments that exist at suspend
    // time; a fresh environment seeds no serving-state row, so it would read Active.
    // A new environment must therefore not be born under a non-active parent tenant,
    // or it would gain an unfenced serving surface while the tenant is off the data
    // plane (issue #46). The create is refused fail closed for a suspended tenant AND
    // for a grace-deleted one, and works again after a resume.
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    // Under an ACTIVE tenant, a new environment is created and serves normally.
    let active_env = fx.create_environment(tenant, None).await;
    assert_eq!(
        fx.serving_state(active_env).await,
        EnvironmentServingState::Active,
        "an environment under an active tenant serves its data plane"
    );

    // Suspend the tenant, then attempt to add an environment: refused fail closed
    // with the lifecycle-precondition Conflict, and nothing is written.
    fx.suspend(&tenant).await.expect("suspend");
    let (would_be, refused) = fx.try_create_environment(tenant, None).await;
    assert!(
        matches!(refused, Err(StoreError::Conflict)),
        "creating an environment under a suspended tenant is refused; got {refused:?}"
    );
    // The refused environment does not exist: a control-plane read is the uniform
    // not-found (the create rolled back), so it never gained a serving surface.
    assert!(
        matches!(
            fx.db
                .control_store()
                .management()
                .environments(would_be.tenant())
                .get(&would_be.environment())
                .await,
            Err(StoreError::NotFound)
        ),
        "the refused environment was never persisted"
    );

    // Resume restores the ability to add environments.
    fx.resume(&tenant).await.expect("resume");
    let _resumed_env = fx.create_environment(tenant, None).await;

    // A grace-deleted (offboarding) tenant likewise cannot gain a new environment.
    fx.delete(&tenant).await.expect("grace delete");
    let (_deleted_scope, refused_deleted) = fx.try_create_environment(tenant, None).await;
    assert!(
        matches!(refused_deleted, Err(StoreError::Conflict)),
        "creating an environment under a grace-deleted tenant is refused; got {refused_deleted:?}"
    );
}

#[tokio::test]
async fn residency_pins_are_immutable_to_the_control_role() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(Some("eu-west")).await;
    let pinned = fx.create_environment(scope.tenant(), Some("us-east")).await;

    // The control role holds only a COLUMN-SCOPED UPDATE on tenants/environments that
    // EXCLUDES the residency columns (migration 0029), so Postgres refuses a rewrite
    // of home_region or region: immutability enforced by code, not merely by the
    // absence of an update path.
    let tenant_update = sqlx::query("UPDATE tenants SET home_region = $1 WHERE id = $2")
        .bind("us-east")
        .bind(scope.tenant().to_string())
        .execute(fx.db.control_pool())
        .await;
    assert!(
        tenant_update.is_err(),
        "the control role may not UPDATE tenants.home_region"
    );

    let env_update = sqlx::query("UPDATE environments SET region = $1 WHERE id = $2")
        .bind("eu-west")
        .bind(pinned.environment().to_string())
        .execute(fx.db.control_pool())
        .await;
    assert!(
        env_update.is_err(),
        "the control role may not UPDATE environments.region"
    );

    // The pins are unchanged (the refused writes were no-ops).
    assert_eq!(
        fx.environment_region(pinned).await.as_deref(),
        Some("us-east")
    );
}

#[tokio::test]
async fn lifecycle_transitions_are_audited() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    fx.suspend(&tenant).await.expect("suspend");
    fx.resume(&tenant).await.expect("resume");
    fx.delete(&tenant).await.expect("delete");

    let actions = fx.audit_actions(&tenant).await;
    for expected in [
        "tenant.create",
        "tenant.suspend",
        "tenant.resume",
        "tenant.delete",
    ] {
        assert!(
            actions.iter().any(|a| a == expected),
            "audit log records {expected}; got {actions:?}"
        );
    }
}

#[tokio::test]
async fn a_failed_transition_writes_no_audit_row() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;
    let tenant = scope.tenant();

    // An invalid transition (resume an active tenant) is refused and must leave no
    // audit trail: nothing happened.
    assert!(matches!(
        fx.resume(&tenant).await,
        Err(StoreError::Conflict)
    ));
    let actions = fx.audit_actions(&tenant).await;
    assert!(
        !actions.iter().any(|a| a == "tenant.resume"),
        "a refused transition writes no audit row; got {actions:?}"
    );
}

#[tokio::test]
async fn a_credential_grant_round_trips_through_authentication_and_absent_means_unrestricted() {
    // Issue #102. The grant is only worth anything if it survives the read that builds the
    // `Principal`: a column written and never read would leave every credential unrestricted
    // while the row claimed otherwise, which is the worst shape for an authorization control.
    //
    // The THREE states are asserted separately because they mean different things and two of
    // them look alike from a distance: no authentication at all, authenticated-unrestricted
    // (the pre-0118 world), and authenticated-restricted.
    let fx = Fixture::start().await;
    let scope = fx.create_tenant(None).await;

    // 1. UNRESTRICTED: no permissions column written, which is every credential minted before
    //    migration 0118. `Some(None)` and not `Some(Some(vec![]))`.
    let (open_id, open_hash) = fx.mint_key(scope, "unrestricted").await;
    assert_eq!(
        fx.db
            .control_store()
            .management()
            .credentials(scope)
            .authenticate_with_grants(&open_id, &open_hash)
            .await
            .expect("authenticate"),
        Some(None),
        "a credential with no permissions column must read as UNRESTRICTED, not as an empty \
         grant set: an empty set would revoke every key that predates the column"
    );

    // 2. RESTRICTED: the slugs come back exactly as stored, in order.
    let (scoped_id, scoped_hash) = fx.mint_key(scope, "restricted").await;
    sqlx::query(
        "UPDATE management_credentials SET permissions = $1 WHERE id = $2 \
         AND tenant_id = $3 AND environment_id = $4",
    )
    .bind(vec!["management.read".to_owned()])
    .bind(scoped_id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(fx.db.owner_pool())
    .await
    .expect("write the grant");

    assert_eq!(
        fx.db
            .control_store()
            .management()
            .credentials(scope)
            .authenticate_with_grants(&scoped_id, &scoped_hash)
            .await
            .expect("authenticate"),
        Some(Some(vec!["management.read".to_owned()])),
        "the stored grant did not survive the authentication read"
    );

    // 3. A WRONG key hash is no authentication at all, and must not be confused with an
    //    unrestricted one. `None` and `Some(None)` are one character apart in the type and
    //    opposite in meaning: the first denies everything, the second allows everything.
    assert_eq!(
        fx.db
            .control_store()
            .management()
            .credentials(scope)
            .authenticate_with_grants(&scoped_id, "hash-of-something-else")
            .await
            .expect("authenticate"),
        None,
        "a bad credential authenticated"
    );
}
