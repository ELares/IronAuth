// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environments as first-class typed objects (issue #42), against a real
//! database, through the control-plane store.
//!
//! Covers: environment creation with a typed kind and custom domain; the day-one
//! signing key provisioned in the same transaction so a fresh environment is
//! immediately servable and its keys are its OWN identity; the scoped-key binding
//! (a sibling environment and a foreign tenant share no key); the DB CHECK that
//! pins the closed kind set; unbounded environment count with no per-environment
//! schema growth; and the environment-identity classification the snapshot and
//! promotion engines rely on.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, EnvironmentId, EnvironmentType, NewEnvironment, NewSigningKey,
    OperatorId, ResourceClassification, ResourceType, Scope, ServiceId, SigningKeyId,
    SigningKeyMaterialKind, StoreError, TenantId,
};
use sqlx::Row;

fn actor(env: &Env) -> ActorRef {
    ActorRef::service(ServiceId::generate(env))
}

/// A minted day-one key: its id and its (arbitrary, for a persistence test) seed
/// bytes. The store persists the seed verbatim, so these tests need no real
/// cryptography to exercise the scoped-key binding.
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

/// Create a tenant with a first environment of `kind` (and optional custom
/// domain) through the control plane, provisioning the first environment's day-one
/// key. Returns the operator, tenant, and first-environment ids.
async fn create_tenant_with_first_environment(
    db: &TestDatabase,
    env: &Env,
    kind: EnvironmentType,
    custom_domain: Option<&str>,
) -> (OperatorId, TenantId, EnvironmentId) {
    let operator = OperatorId::generate(env);
    let tenant_id = TenantId::generate(env);
    let environment_id = EnvironmentId::generate(env);
    let scope = Scope::new(tenant_id, environment_id);
    let key = DayOneKey::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .tenants(operator)
        .create(
            env,
            &tenant_id,
            &environment_id,
            1_000_000,
            "Operator",
            "Acme",
            NewEnvironment {
                display_name: "first",
                kind,
                custom_domain,
                region: None,
            },
            None,
            &[key.as_new()],
            None,
        )
        .await
        .expect("create tenant with first environment");
    (operator, tenant_id, environment_id)
}

/// Create an additional environment of `kind` under `tenant`, provisioning its
/// day-one key. Returns the new environment id.
async fn create_environment(
    db: &TestDatabase,
    env: &Env,
    tenant: TenantId,
    kind: EnvironmentType,
    custom_domain: Option<&str>,
    created_at_micros: i64,
) -> EnvironmentId {
    let environment_id = EnvironmentId::generate(env);
    let scope = Scope::new(tenant, environment_id);
    let key = DayOneKey::generate(env, &scope);
    db.control_store()
        .management()
        .acting(actor(env), CorrelationId::generate(env))
        .environments(tenant)
        .create(
            env,
            &environment_id,
            created_at_micros,
            NewEnvironment {
                display_name: "env",
                kind,
                custom_domain,
                region: None,
            },
            &[key.as_new()],
            None,
        )
        .await
        .expect("create environment");
    environment_id
}

/// How many base tables exist in the public schema (the "catalog"): the count
/// must not grow when environments are created, proving creation adds only
/// fixed-schema ROWS, never per-environment tables (issue #42, AC5).
async fn table_count(db: &TestDatabase) -> i64 {
    sqlx::query(
        "SELECT count(*) AS c FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
    )
    .fetch_one(db.owner_pool())
    .await
    .expect("count tables")
    .get("c")
}

#[tokio::test]
async fn environment_records_its_typed_kind_and_custom_domain() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    // A dev first environment: non-production, no custom domain.
    let (_op, tenant, first) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;
    let record = db
        .control_store()
        .management()
        .environments(tenant)
        .get(&first)
        .await
        .expect("get first environment");
    assert_eq!(record.kind, EnvironmentType::Dev);
    assert_eq!(record.custom_domain, None);
    assert_eq!(record.kind.guardrail_class().as_str(), "non-production");

    // A prod environment carrying its required custom domain round-trips.
    let prod = create_environment(
        &db,
        &env,
        tenant,
        EnvironmentType::Prod,
        Some("auth.acme.example"),
        2_000_000,
    )
    .await;
    let record = db
        .control_store()
        .management()
        .environments(tenant)
        .get(&prod)
        .await
        .expect("get prod environment");
    assert_eq!(record.kind, EnvironmentType::Prod);
    assert_eq!(record.custom_domain.as_deref(), Some("auth.acme.example"));
    assert!(record.kind.guardrails().require_https_redirect_uris);
    assert!(record.kind.guardrails().one_time_view_secrets);
}

#[tokio::test]
async fn each_environment_gets_its_own_disjoint_day_one_signing_key() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    let (_op, tenant, first) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;
    let second =
        create_environment(&db, &env, tenant, EnvironmentType::Staging, None, 2_000_000).await;

    // Each environment serves its OWN key set, provisioned at creation (so it
    // serves discovery immediately). The two key sets are non-empty and disjoint.
    let first_scope = Scope::new(tenant, first);
    let second_scope = Scope::new(tenant, second);
    let first_keys = db
        .store()
        .scoped(first_scope)
        .signing_keys()
        .list()
        .await
        .expect("first keys");
    let second_keys = db
        .store()
        .scoped(second_scope)
        .signing_keys()
        .list()
        .await
        .expect("second keys");
    assert_eq!(
        first_keys.len(),
        1,
        "the first environment has a day-one key"
    );
    assert_eq!(
        second_keys.len(),
        1,
        "the second environment has a day-one key"
    );
    assert_ne!(
        first_keys[0].id, second_keys[0].id,
        "sibling environments never share a signing key"
    );
    assert_eq!(first_keys[0].id.scope(), first_scope);
    assert_eq!(second_keys[0].id.scope(), second_scope);

    // The first environment's key is NOT visible under the sibling's scope: an
    // environment's keys are its own identity, never another environment's (the
    // scoped-key binding, the guarantee promotion relies on).
    assert!(matches!(
        db.store()
            .scoped(second_scope)
            .signing_keys()
            .get(&first_keys[0].id)
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn a_foreign_tenant_cannot_see_an_environments_key_or_kind() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    let (_op_a, tenant_a, env_a) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Prod, Some("a.example"))
            .await;
    let (_op_b, tenant_b, env_b) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;

    // Environment A read under tenant B is the uniform not-found (the tenant filter
    // is the anti-oracle: A's kind and domain are never disclosed cross-tenant).
    assert!(matches!(
        db.control_store()
            .management()
            .environments(tenant_b)
            .get(&env_a)
            .await,
        Err(StoreError::NotFound)
    ));

    // A's day-one key is not visible under B's first environment scope either.
    let scope_a = Scope::new(tenant_a, env_a);
    let key_a = db
        .store()
        .scoped(scope_a)
        .signing_keys()
        .list()
        .await
        .expect("A keys");
    let scope_b = Scope::new(tenant_b, env_b);
    assert!(matches!(
        db.store()
            .scoped(scope_b)
            .signing_keys()
            .get(&key_a[0].id)
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn the_kind_column_rejects_a_value_outside_the_closed_set() {
    // Defense in depth: even a caller that bypasses the application-layer parse
    // cannot store an environment with an unknown kind (the DB CHECK).
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (_op, tenant, _first) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;

    let bogus = EnvironmentId::generate(&env);
    let result = sqlx::query(
        "INSERT INTO environments (id, tenant_id, display_name, kind) VALUES ($1, $2, $3, $4)",
    )
    .bind(bogus.to_string())
    .bind(tenant.to_string())
    .bind("bad")
    .bind("production")
    .execute(db.owner_pool())
    .await;
    assert!(
        result.is_err(),
        "an unknown environment kind must violate the environments_kind_valid CHECK"
    );
}

#[tokio::test]
async fn fifty_plus_environments_create_with_no_count_gate_and_no_schema_growth() {
    let db = TestDatabase::start().await;
    let env = Env::system();

    let (_op, tenant, _first) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;

    // The catalog before creating the fleet.
    let tables_before = table_count(&db).await;

    // Create 54 more environments (55 total with the first): unlimited, no billing
    // or count gate. Each provisions its own day-one key.
    for i in 0..54_i64 {
        create_environment(&db, &env, tenant, EnvironmentType::Dev, None, 3_000_000 + i).await;
    }

    // The catalog is UNCHANGED: creation added only fixed-schema rows, never a
    // per-environment table, schema, or file (AC5).
    let tables_after = table_count(&db).await;
    assert_eq!(
        tables_before, tables_after,
        "creating environments must not add any table to the catalog"
    );

    // Every environment is live and listable (a large page proves none was gated).
    let listed = db
        .control_store()
        .management()
        .environments(tenant)
        .list(1000, None)
        .await
        .expect("list environments");
    assert_eq!(listed.len(), 55, "all 55 environments are live and listed");

    // Each environment has exactly its own day-one key (55 disjoint key sets).
    let mut key_ids = std::collections::BTreeSet::new();
    for record in &listed {
        let scope = Scope::new(tenant, record.id);
        let keys = db
            .store()
            .scoped(scope)
            .signing_keys()
            .list()
            .await
            .expect("keys");
        assert_eq!(keys.len(), 1, "every environment has one day-one key");
        assert!(
            key_ids.insert(keys[0].id.to_string()),
            "every environment's key id is unique"
        );
    }
}

#[tokio::test]
async fn the_data_plane_reads_the_typed_guardrail_from_the_scope_forced_projection() {
    // Issue #42: the data-plane role (which has NO grant on the environments level
    // table) reads the environment's typed guardrail through the scope-forced
    // projection view, and only ever for its OWN bound scope.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (_op, tenant, dev_env) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;
    let prod_env = create_environment(
        &db,
        &env,
        tenant,
        EnvironmentType::Prod,
        Some("auth.acme.example"),
        2_000_000,
    )
    .await;

    let dev = db
        .store()
        .scoped(Scope::new(tenant, dev_env))
        .environment_guardrails()
        .guardrails()
        .await
        .expect("dev guardrails");
    assert!(dev.allow_insecure_redirect_uris);
    assert!(!dev.require_https_redirect_uris);

    let prod = db
        .store()
        .scoped(Scope::new(tenant, prod_env))
        .environment_guardrails()
        .guardrails()
        .await
        .expect("prod guardrails");
    assert!(!prod.allow_insecure_redirect_uris);
    assert!(prod.require_https_redirect_uris);

    // A FOREIGN tenant naming the prod environment reads no guardrail row: the
    // projection is scope-forced, so it fails closed (NotFound), never disclosing
    // another tenant's environment kind.
    let (_op_b, tenant_b, _env_b) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;
    assert!(matches!(
        db.store()
            .scoped(Scope::new(tenant_b, prod_env))
            .environment_guardrails()
            .guardrails()
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn register_redirect_uris_enforces_the_prod_https_only_guardrail() {
    // Issue #42 acceptance 1 on the STATIC client-registration path: a prod
    // environment rejects an http loopback redirect with a guardrail violation,
    // while a dev environment registers the same loopback.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (_op, tenant, dev_env) =
        create_tenant_with_first_environment(&db, &env, EnvironmentType::Dev, None).await;
    let prod_env = create_environment(
        &db,
        &env,
        tenant,
        EnvironmentType::Prod,
        Some("auth.acme.example"),
        2_000_000,
    )
    .await;

    // Dev: the http loopback registers.
    let dev_scope = Scope::new(tenant, dev_env);
    let dev_client = db
        .store()
        .scoped(dev_scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "dev client")
        .await
        .expect("create dev client");
    db.store()
        .scoped(dev_scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .clients()
        .register_redirect_uris(&env, &dev_client, &["http://127.0.0.1:8080/cb"])
        .await
        .expect("a dev environment accepts an http loopback redirect");

    // Prod: the SAME http loopback is rejected with a guardrail violation naming the
    // https-only rule; an https redirect is accepted.
    let prod_scope = Scope::new(tenant, prod_env);
    let prod_client = db
        .store()
        .scoped(prod_scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .clients()
        .create(&env, "prod client")
        .await
        .expect("create prod client");
    let rejected = db
        .store()
        .scoped(prod_scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .clients()
        .register_redirect_uris(&env, &prod_client, &["http://127.0.0.1:8080/cb"])
        .await;
    match rejected {
        Err(StoreError::GuardrailViolation(violation)) => {
            assert_eq!(violation.code(), "https_only_redirect_uris");
        }
        other => panic!("a prod environment must reject an http loopback: {other:?}"),
    }
    db.store()
        .scoped(prod_scope)
        .acting(actor(&env), CorrelationId::generate(&env))
        .clients()
        .register_redirect_uris(&env, &prod_client, &["https://app.example/cb"])
        .await
        .expect("a prod environment accepts an https redirect");
}

#[test]
fn environment_signing_key_and_management_credential_are_environment_identity() {
    // The split #43 (snapshot) and #44 (promotion) rely on: the environment
    // itself, its signing keys, and its per-environment management credentials are
    // all ENVIRONMENT-IDENTITY, so a promotion never copies one environment's
    // identity onto another. Nothing #42 adds is promotable (kind, guardrails,
    // custom domain, and scoped keys all travel WITH the environment identity).
    for resource in [
        ResourceType::Environment,
        ResourceType::SigningKey,
        ResourceType::ManagementCredential,
    ] {
        assert_eq!(
            resource.classification(),
            ResourceClassification::EnvironmentIdentity,
            "{} must be environment-identity",
            resource.as_str()
        );
    }
}
