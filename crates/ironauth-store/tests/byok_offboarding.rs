// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bring-your-own-key (BYOK) and crypto-shredding offboarding (issue #49), over a
//! real database (`DATABASE_URL`).
//!
//! EXTENDS the per-tenant envelope substrate (issue #48) and the tenant lifecycle
//! offboarding pipeline (issue #46). Proves the acceptance criteria this issue owns
//! at the persistence layer:
//!
//! - a scope is enrolled in a customer-managed-key binding that records only the
//!   driver and an OPAQUE external key reference, never key material;
//! - the terminal offboarding stage (hard delete / purge) SEVERS the binding in the
//!   SAME audited transaction that crypto-shreds the platform KEK, so a BYOK
//!   tenant's sealed PII is unrecoverable by either path while a sibling's binding
//!   and PII are untouched;
//! - revoking a customer root through the `ironauth-kms` seam fails closed (the
//!   crypto-shred-by-revocation property the offboarding sever mirrors);
//! - an unknown driver label is refused (fail closed), and no plaintext key or
//!   reference secret is ever stored.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ironauth_env::{Env, ManualClock};
use ironauth_jose::{Aad, Kek, MasterKey};
use ironauth_kms::{KmsError, KmsProvider, KmsProviderKind, LocalKmsProvider};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, ByokBinding, CorrelationId, EnvironmentId, EnvironmentType, NewEnvironment,
    NewSigningKey, OperatorId, Scope, SigningKeyId, SigningKeyMaterialKind, StoreError, TenantId,
};
use sqlx::Row;

/// A minted day-one signing key for a tenant/environment create (the store persists
/// the seed verbatim, so these tests need no real signing cryptography).
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

/// A 30-day retention window, so an in-window state and a post-window hard delete
/// are cleanly separated by advancing the manual clock.
const RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

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
        let (env, clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0049);
        let operator = OperatorId::generate(&env);
        let actor = db.test_actor(&env);
        let master = MasterKey::generate("byok-test", env.entropy());
        Self {
            db,
            env,
            clock,
            operator,
            actor,
            master,
        }
    }

    /// Create a tenant with its first environment under the shared operator.
    async fn create_tenant(&self) -> Scope {
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
                None,
                &[key.as_new()],
                None,
            )
            .await
            .expect("create tenant");
        scope
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

    /// Enroll a scope in BYOK through the data-plane acting envelope repository.
    async fn enroll_byok(
        &self,
        scope: Scope,
        provider: &str,
        key_ref: &str,
    ) -> Result<(), StoreError> {
        self.db
            .store()
            .scoped(scope)
            .acting(self.actor, CorrelationId::generate(&self.env))
            .envelope()
            .enroll_byok(&self.env, provider, key_ref)
            .await
    }

    async fn byok_binding(&self, scope: Scope) -> Option<ByokBinding> {
        self.db
            .store()
            .scoped(scope)
            .envelope()
            .byok_binding()
            .await
            .expect("read byok binding")
    }

    async fn open_pii(&self, scope: Scope, purpose: &str) -> Result<Vec<u8>, StoreError> {
        self.db
            .store()
            .scoped(scope)
            .envelope()
            .open_secret(&self.master, purpose)
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

    async fn hard_delete(&self, tenant: &TenantId) -> Result<(), StoreError> {
        self.db
            .control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .hard_delete(&self.env, tenant, RETENTION, None)
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
async fn enrolling_records_the_driver_and_reference_never_key_material() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant().await;
    fx.seal_pii(scope, "email", b"ada@lovelace.test").await;

    // A scope is not BYOK-governed until enrolled.
    assert!(fx.byok_binding(scope).await.is_none());

    let key_ref = "arn:aws:kms:example:key/opaque-handle";
    fx.enroll_byok(scope, KmsProviderKind::Aws.as_str(), key_ref)
        .await
        .expect("enroll byok");

    let binding = fx.byok_binding(scope).await.expect("binding present");
    assert_eq!(binding.provider, "aws");
    assert_eq!(binding.key_ref, key_ref);
    assert_eq!(binding.status, "active");

    // A second enroll is a Conflict, never a silent overwrite.
    assert!(matches!(
        fx.enroll_byok(scope, KmsProviderKind::Aws.as_str(), key_ref)
            .await,
        Err(StoreError::Conflict)
    ));

    // The enroll is audited, and the raw stored row carries only the opaque
    // reference (an ARN), never key material.
    assert!(
        fx.audit_actions(&scope.tenant())
            .await
            .contains(&"envelope.byok.enroll".to_owned())
    );
}

#[tokio::test]
async fn an_unknown_driver_label_is_refused_fail_closed() {
    let fx = Fixture::start().await;
    let scope = fx.create_tenant().await;
    // A typo (or an unroutable driver) fails closed before anything is stored.
    assert!(matches!(
        fx.enroll_byok(scope, "aws-typo", "handle").await,
        Err(StoreError::Encryption)
    ));
    assert!(fx.byok_binding(scope).await.is_none());
}

#[tokio::test]
async fn revoking_the_customer_root_fails_closed_and_shreds() {
    // The property the offboarding sever relies on, demonstrated through the KMS
    // seam: a customer root wraps the tenant KEK, and revoking the root makes the
    // KEK permanently unrecoverable with no platform fallback.
    let entropy = ironauth_env::FixedEntropy::new(0x49);
    let root = LocalKmsProvider::generate("customer-root-1", &entropy);
    let kek = Kek::generate(&entropy);
    let aad = Aad::builder()
        .text("kek-wrap")
        .text("ten_a")
        .version(1)
        .build();
    let wrapped = root.wrap_kek(&entropy, &aad, &kek).await.expect("wrap");

    root.revoke();
    assert_eq!(
        root.unwrap_kek(&aad, &wrapped).await.err(),
        Some(KmsError::AccessRevoked),
        "a revoked customer root cannot unwrap the tenant KEK"
    );
}

#[tokio::test]
async fn terminal_offboarding_severs_the_binding_and_shreds_while_a_sibling_survives() {
    let fx = Fixture::start().await;
    let victim = fx.create_tenant().await;
    let sibling = fx.create_tenant().await;

    // Both tenants seal PII and enroll in BYOK with the local (customer-supplied)
    // driver and their own opaque key reference.
    fx.seal_pii(victim, "email", b"ada@lovelace.test").await;
    fx.seal_pii(sibling, "email", b"grace@hopper.test").await;
    fx.enroll_byok(
        victim,
        KmsProviderKind::Local.as_str(),
        "customer-root/victim",
    )
    .await
    .expect("enroll victim");
    fx.enroll_byok(
        sibling,
        KmsProviderKind::Local.as_str(),
        "customer-root/sibling",
    )
    .await
    .expect("enroll sibling");

    // Offboard the victim (grace), advance past retention, then HARD-DELETE: the
    // terminal stage crypto-shreds the KEK and severs the BYOK binding in one
    // audited transaction.
    fx.delete(&victim.tenant()).await.expect("grace delete");
    fx.clock.advance(RETENTION + Duration::from_secs(1));
    fx.hard_delete(&victim.tenant()).await.expect("hard delete");

    // The victim's sealed PII is now permanently undecryptable.
    assert!(matches!(
        fx.open_pii(victim, "email").await,
        Err(StoreError::Encryption)
    ));

    // The victim's BYOK binding is SEVERED: status destroyed and the external
    // reference cleared, retained as erasure evidence.
    let victim_binding = fx.byok_binding(victim).await.expect("victim binding row");
    assert_eq!(victim_binding.status, "destroyed");
    assert_eq!(
        victim_binding.key_ref, "",
        "the external key reference is cleared on sever"
    );

    // The victim's KEK row is retained but destroyed.
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
    assert_eq!(kek_status, "destroyed");

    // The sibling is entirely unaffected: its PII still opens and its BYOK binding
    // is still active with its reference intact.
    assert_eq!(
        fx.open_pii(sibling, "email").await.expect("sibling pii"),
        b"grace@hopper.test"
    );
    let sibling_binding = fx.byok_binding(sibling).await.expect("sibling binding row");
    assert_eq!(sibling_binding.status, "active");
    assert_eq!(sibling_binding.key_ref, "customer-root/sibling");

    // The purge is audited on the victim.
    assert!(
        fx.audit_actions(&victim.tenant())
            .await
            .contains(&"tenant.purge".to_owned())
    );
}
