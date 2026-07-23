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
//!   one reads as served again, with no data loss;
//! - the OFFBOARDING PIPELINE: a grace delete fences the tenant but keeps its keys
//!   INTACT (restorable, no data loss); the retention window gates restore and hard
//!   delete under a manual clock; only the terminal HARD DELETE crypto-shreds the
//!   envelope KEK, permanently, while a sibling tenant is unaffected;
//! - cross-tenant isolation and audited transitions.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_env::{Env, ManualClock};
use ironauth_jose::MasterKey;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, EnvironmentId, EnvironmentServingState, EnvironmentType,
    NewEnvironment, NewSigningKey, OperatorId, Scope, SigningKeyId, SigningKeyMaterialKind,
    StoreError, TenantId, TenantStatus,
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

    async fn restore(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .restore(&self.env, tenant, RETENTION, None)
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
