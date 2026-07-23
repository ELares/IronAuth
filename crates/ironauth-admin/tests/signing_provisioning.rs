// SPDX-License-Identifier: MIT OR Apache-2.0

//! Multi-algorithm day-one signing-key provisioning (issue #93).
//!
//! Every environment provisions all three JWKS signing algorithms (`EdDSA`,
//! `ES256`, `RS256`) at creation, so the compatibility wizard's per-algorithm
//! recommendations are actually SIGNABLE. These tests drive the real day-one
//! generation and the real store create path, then load the live issuer entry to
//! assert:
//!
//! 1. env-create provisions all three (three signing keys, distinct kids; the
//!    published JWKS ships all three; every algorithm is signable),
//! 2. `EdDSA` stays the deterministic default signer (the canonical-order fix),
//! 3. each algorithm's day-one key mints a token that verifies through the ONE
//!    hardened verify path,
//! 4. the operator backfill adds only the missing algorithms, idempotently,
//! 5. day-one generation is byte-for-byte reproducible under a fixed entropy source.

use std::time::{Duration, SystemTime};

use ironauth_admin::{DayOneSigningKeys, backfill_signing_algorithms};
use ironauth_env::{Env, ManualClock};
use ironauth_jose::{EmissionOptions, JwsAlgorithm, VerificationPolicy, sign_jws, verify};
use ironauth_oidc::{IssuerRegistry, JwksCacheWindow};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, EnvironmentId, EnvironmentType, NewEnvironment, NewSigningKey,
    OperatorId, Scope, SigningKeyId, SigningKeyMaterialKind, Store, TenantId,
};

/// The instant the day-one keys are provisioned live at (epoch microseconds).
const CREATED_AT_MICROS: i64 = 1_000_000;

/// The issuer base the registry publishes under.
const ISSUER_BASE: &str = "https://issuer.example.test";

/// A test rig: a real database, a deterministic environment, and a shared operator.
struct Rig {
    db: TestDatabase,
    env: Env,
    operator: OperatorId,
    actor: ActorRef,
}

impl Rig {
    async fn start(seed: u64) -> Self {
        let db = TestDatabase::start().await;
        let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, seed);
        let operator = OperatorId::generate(&env);
        let actor = db.test_actor(&env);
        Self {
            db,
            env,
            operator,
            actor,
        }
    }

    /// The data-plane store the issuer registry and the backfill provision through.
    fn data_store(&self) -> &Store {
        self.db.store()
    }

    /// The control-plane store that enumerates environment scopes.
    fn control_store(&self) -> &Store {
        self.db.control_store()
    }

    /// A fresh, unused `(tenant, environment)` scope.
    fn fresh_scope(&self) -> Scope {
        Scope::new(
            TenantId::generate(&self.env),
            EnvironmentId::generate(&self.env),
        )
    }

    /// Create a tenant and its first environment at `scope` under the shared
    /// operator, provisioning `signing_keys` (a slice) in the same transaction.
    async fn create_environment_in(&self, scope: Scope, signing_keys: &[NewSigningKey<'_>]) {
        let tenant = scope.tenant();
        let environment = scope.environment();
        self.control_store()
            .management()
            .acting(self.actor, CorrelationId::generate(&self.env))
            .tenants(self.operator)
            .create(
                &self.env,
                &tenant,
                &environment,
                CREATED_AT_MICROS,
                "test operator",
                "test tenant",
                NewEnvironment {
                    display_name: "production",
                    kind: EnvironmentType::Dev,
                    custom_domain: None,
                    region: None,
                },
                None,
                signing_keys,
                None,
            )
            .await
            .expect("create tenant and first environment");
    }

    /// A store-backed issuer registry over the data plane (the live load path).
    fn registry(&self) -> IssuerRegistry {
        IssuerRegistry::store_backed(
            ISSUER_BASE,
            JwksCacheWindow::clamped(300),
            self.data_store().clone(),
        )
    }
}

/// An instant safely after the day-one keys' activation, for signer/JWKS reads.
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(10)
}

/// The stored algorithm names in a scope, in load order.
async fn algorithms_in(store: &Store, scope: Scope) -> Vec<String> {
    store
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("list signing keys")
        .into_iter()
        .map(|record| record.algorithm)
        .collect()
}

// 1. Env-create provisions all three algorithms.
#[tokio::test]
async fn env_create_provisions_all_three_algorithms() {
    let rig = Rig::start(0x93_01).await;
    let scope = rig.fresh_scope();
    let day_one = DayOneSigningKeys::generate(&rig.env, &scope).expect("generate day-one keys");
    rig.create_environment_in(scope, &day_one.as_new(CREATED_AT_MICROS))
        .await;

    let records = rig
        .data_store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("list signing keys");
    assert_eq!(records.len(), 3, "three day-one signing keys");
    let algorithms: Vec<&str> = records.iter().map(|r| r.algorithm.as_str()).collect();
    assert!(algorithms.contains(&"EdDSA"));
    assert!(algorithms.contains(&"ES256"));
    assert!(algorithms.contains(&"RS256"));

    // Distinct kids.
    let mut kids: Vec<String> = records.iter().map(|r| r.id.to_string()).collect();
    kids.sort();
    kids.dedup();
    assert_eq!(kids.len(), 3, "three distinct kids");

    // The published JWKS ships all three JWKs.
    let registry = rig.registry();
    let jwks_json = registry
        .jwks_json(&scope, now())
        .await
        .expect("scope resolves")
        .expect("jwks builds");
    let jwks: serde_json::Value = serde_json::from_str(&jwks_json).expect("jwks json");
    assert_eq!(
        jwks["keys"].as_array().expect("keys array").len(),
        3,
        "the published JWKS carries all three keys"
    );

    // Every algorithm is signable (a key exists and the policy permits it).
    let entry = registry
        .entry_for(&scope, now())
        .await
        .expect("issuer entry");
    for alg in [
        JwsAlgorithm::EdDsa,
        JwsAlgorithm::Es256,
        JwsAlgorithm::Rs256,
    ] {
        assert!(entry.policy().permits(alg), "policy permits {alg:?}");
        assert!(
            entry.keyset().active_signer_for(now(), alg).is_some(),
            "a {alg:?} key is active",
        );
    }
}

// 2. EdDSA stays the deterministic default signer regardless of row order.
#[tokio::test]
async fn eddsa_stays_the_default_signer() {
    let rig = Rig::start(0x93_02).await;
    let scope = rig.fresh_scope();
    let day_one = DayOneSigningKeys::generate(&rig.env, &scope).expect("generate day-one keys");
    rig.create_environment_in(scope, &day_one.as_new(CREATED_AT_MICROS))
        .await;

    let registry = rig.registry();
    let entry = registry
        .entry_for(&scope, now())
        .await
        .expect("issuer entry");

    // All three keys share created_at (one transaction), so list order tie-breaks on
    // the random id. The canonical-order fix pins EdDSA as the default anyway.
    assert_eq!(
        entry.policy().preferred(),
        JwsAlgorithm::EdDsa,
        "EdDSA is the preferred (default) algorithm",
    );
    assert_eq!(
        entry.signer(now()).expect("a signer resolves").algorithm(),
        JwsAlgorithm::EdDsa,
        "the resolved default signer is EdDSA",
    );
    // The full policy order is canonical, proving the ordering logic ran (not luck).
    assert_eq!(
        entry.policy().allowed(),
        &[
            JwsAlgorithm::EdDsa,
            JwsAlgorithm::Es256,
            JwsAlgorithm::Rs256
        ],
        "the policy is in canonical preference order",
    );
}

// 3. Each algorithm's day-one key mints a token that verifies through the one path.
#[tokio::test]
async fn per_algorithm_round_trip_mint() {
    let rig = Rig::start(0x93_03).await;
    let scope = rig.fresh_scope();
    let day_one = DayOneSigningKeys::generate(&rig.env, &scope).expect("generate day-one keys");
    rig.create_environment_in(scope, &day_one.as_new(CREATED_AT_MICROS))
        .await;

    let registry = rig.registry();
    let entry = registry
        .entry_for(&scope, now())
        .await
        .expect("issuer entry");

    let issuer = ISSUER_BASE;
    let audience = "client-abc";
    let payload = format!(
        r#"{{"iss":"{issuer}","sub":"user-123","aud":"{audience}","exp":4102444800,"nbf":0,"iat":1}}"#
    )
    .into_bytes();

    for alg in [
        JwsAlgorithm::EdDsa,
        JwsAlgorithm::Es256,
        JwsAlgorithm::Rs256,
    ] {
        let key = entry
            .keyset()
            .active_signer_for(now(), alg)
            .unwrap_or_else(|| panic!("a {alg:?} signer is active"));
        let token = sign_jws(key, &payload, &EmissionOptions::new())
            .unwrap_or_else(|e| panic!("{alg:?} signs: {e}"));
        let trusted = key.verifying_key().expect("verifying key");
        let policy = VerificationPolicy::new(vec![alg], vec![trusted], issuer, audience)
            .expect("valid policy");
        let clock = ManualClock::new(now());
        let verified = verify(&token, &policy, &clock)
            .unwrap_or_else(|e| panic!("{alg:?} verifies: {:?}", e.reason()));
        assert_eq!(verified.algorithm(), alg, "{alg:?} round-trips");
        assert_eq!(verified.key_id(), key.kid());
    }
}

// 4. The backfill adds only the missing algorithms, idempotently.
#[tokio::test]
async fn backfill_adds_missing_algorithms_idempotently() {
    let rig = Rig::start(0x93_04).await;

    // Seed a LEGACY EdDSA-only environment (bypassing the all-three day-one path).
    let scope = rig.fresh_scope();
    let eddsa_id = SigningKeyId::generate(&rig.env, &scope);
    let mut eddsa_seed = [0_u8; 32];
    rig.env.entropy().fill_bytes(&mut eddsa_seed);
    let eddsa_key = NewSigningKey {
        id: &eddsa_id,
        algorithm: "EdDSA",
        material_kind: SigningKeyMaterialKind::Ed25519Seed,
        material: &eddsa_seed,
        publish_at_micros: CREATED_AT_MICROS,
        activate_at_micros: CREATED_AT_MICROS,
        retire_at_micros: None,
        expire_at_micros: None,
    };
    rig.create_environment_in(scope, &[eddsa_key]).await;

    assert_eq!(
        algorithms_in(rig.data_store(), scope).await,
        vec!["EdDSA".to_owned()],
        "legacy env starts EdDSA-only",
    );

    // First backfill run: adds ES256 and RS256, leaves EdDSA alone.
    let report = backfill_signing_algorithms(&rig.env, rig.control_store(), rig.data_store())
        .await
        .expect("backfill enumerates scopes");
    assert_eq!(report.scopes_scanned, 1);
    assert_eq!(report.keys_provisioned, 2, "ES256 + RS256 added");
    assert_eq!(report.scopes_failed, 0);

    let after = algorithms_in(rig.data_store(), scope).await;
    assert_eq!(after.len(), 3, "three algorithms after backfill");
    assert!(after.contains(&"EdDSA".to_owned()));
    assert!(after.contains(&"ES256".to_owned()));
    assert!(after.contains(&"RS256".to_owned()));

    // The original EdDSA key is untouched (same id, same material).
    let eddsa_row = rig
        .data_store()
        .scoped(scope)
        .signing_keys()
        .list()
        .await
        .expect("list")
        .into_iter()
        .find(|r| r.algorithm == "EdDSA")
        .expect("EdDSA key still present");
    assert_eq!(eddsa_row.id, eddsa_id, "the EdDSA kid is unchanged");
    assert_eq!(
        eddsa_row.material.expose(),
        &eddsa_seed,
        "the EdDSA material is untouched",
    );

    // Second run: fully idempotent, no duplicate rows.
    let rerun = backfill_signing_algorithms(&rig.env, rig.control_store(), rig.data_store())
        .await
        .expect("backfill reruns");
    assert_eq!(rerun.keys_provisioned, 0, "a rerun provisions nothing");
    assert_eq!(
        algorithms_in(rig.data_store(), scope).await.len(),
        3,
        "still exactly three keys after a rerun",
    );
}

// 5. Day-one generation is byte-for-byte reproducible under a fixed entropy source.
#[test]
fn day_one_generation_is_deterministic() {
    // Two fresh environments with the SAME seed reproduce the whole set (ids and
    // material), so the scope is derived from each env's own deterministic stream.
    let (env_a, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 0xABCD);
    let (env_b, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 0xABCD);
    let scope = Scope::new(TenantId::generate(&env_a), EnvironmentId::generate(&env_a));
    let scope_b = Scope::new(TenantId::generate(&env_b), EnvironmentId::generate(&env_b));
    assert_eq!(scope, scope_b, "scopes reproduce under the same seed");
    let a = DayOneSigningKeys::generate(&env_a, &scope).expect("set a");
    let b = DayOneSigningKeys::generate(&env_b, &scope).expect("set b");
    let rows_a = a.as_new(CREATED_AT_MICROS);
    let rows_b = b.as_new(CREATED_AT_MICROS);
    assert_eq!(rows_a.len(), 3);
    assert_eq!(rows_b.len(), 3);
    for (ka, kb) in rows_a.iter().zip(rows_b.iter()) {
        assert_eq!(ka.id.to_string(), kb.id.to_string(), "same kid");
        assert_eq!(ka.algorithm, kb.algorithm, "same algorithm");
        assert_eq!(ka.material, kb.material, "byte-identical key material");
    }
    // The three algorithms come out in the fixed EdDSA, ES256, RS256 order.
    assert_eq!(
        rows_a.iter().map(|k| k.algorithm).collect::<Vec<_>>(),
        vec!["EdDSA", "ES256", "RS256"],
    );
}
