// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real database proof of policy revision guards and immutable identity bindings.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, ClientSubjectPolicy, CorrelationId, Scope, StoreError, UserId};

async fn fixture(db: &TestDatabase, env: &Env) -> (Scope, ClientId, UserId) {
    let scope = db.seed_scope(env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let client = acting
        .clients()
        .create(env, "identity fixture")
        .await
        .unwrap();
    let user = acting
        .users()
        .register(
            env,
            "identity@example.test",
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhhc2hoYXNo",
            None,
        )
        .await
        .unwrap();
    (scope, client, user)
}

fn pairwise() -> ClientSubjectPolicy {
    ClientSubjectPolicy::Pairwise {
        sector_identifier: "sector.example.test".to_owned(),
        sector_identifier_uri: Some("https://sector.example.test/redirects.json".to_owned()),
    }
}

async fn audits(db: &TestDatabase, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action=$1")
        .bind(action)
        .fetch_one(db.owner_pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn policy_and_redirects_persist_atomically_and_stale_aba_validation_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, _) = fixture(&db, &env).await;
    let read = db.store().scoped(scope).clients();
    let initial = read.subject_policy(&client).await.unwrap();
    assert_eq!(initial.policy, ClientSubjectPolicy::Public);
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    acting
        .clients()
        .register_redirect_uris(&env, &client, &["https://app.example.test/cb"])
        .await
        .unwrap();
    acting
        .clients()
        .register_redirect_uris(&env, &client, &[])
        .await
        .unwrap();
    let after_aba = read.subject_policy(&client).await.unwrap();
    assert_eq!(initial.redirect_uris, after_aba.redirect_uris);
    assert_eq!(after_aba.revision, initial.revision + 2);
    assert!(matches!(
        acting
            .clients()
            .set_subject_policy(&env, &initial, &pairwise(), &[])
            .await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(audits(&db, "client.subject_policy.update").await, 0);
    let redirects = vec!["https://app.example.test/cb".to_owned()];
    acting
        .clients()
        .set_subject_policy(&env, &after_aba, &pairwise(), &redirects)
        .await
        .unwrap();
    let restarted = db.restart_app_store().await;
    let current = restarted
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    assert_eq!(current.policy, pairwise());
    assert_eq!(current.redirect_uris, redirects);
    assert_eq!(current.revision, after_aba.revision + 1);
    // A legacy writer cannot replace validated redirects behind the policy's back.
    assert!(
        acting
            .clients()
            .register_redirect_uris(&env, &client, &["https://unvalidated.example.test/cb"])
            .await
            .is_err()
    );
    assert_eq!(read.subject_policy(&client).await.unwrap(), current);
    assert_eq!(audits(&db, "client.subject_policy.update").await, 1);
}

#[tokio::test]
async fn existing_public_binding_survives_switch_but_new_user_gets_pairwise_candidate() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let initial = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    assert_eq!(
        acting
            .clients()
            .bind_subject(&env, &initial, &user, &user.to_string())
            .await
            .unwrap(),
        user.to_string()
    );
    acting
        .clients()
        .set_subject_policy(&env, &initial, &pairwise(), &[])
        .await
        .unwrap();
    let current = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    let candidate = URL_SAFE_NO_PAD.encode([7; 32]);
    assert_eq!(
        acting
            .clients()
            .bind_subject(&env, &current, &user, &candidate)
            .await
            .unwrap(),
        user.to_string()
    );
    let second = acting
        .users()
        .register(&env, "second@example.test", "hash", None)
        .await
        .unwrap();
    assert_eq!(
        acting
            .clients()
            .bind_subject(&env, &current, &second, &candidate)
            .await
            .unwrap(),
        candidate
    );
    let restarted = db.restart_app_store().await;
    assert_eq!(
        restarted
            .scoped(scope)
            .clients()
            .subject_binding(&client, &user)
            .await
            .unwrap(),
        Some(user.to_string())
    );
    assert_eq!(
        restarted
            .scoped(scope)
            .clients()
            .subject_binding(&client, &second)
            .await
            .unwrap(),
        Some(candidate)
    );
    assert_eq!(audits(&db, "client.subject.bind").await, 2);
}

#[tokio::test]
async fn stale_first_derivation_cannot_bind_after_policy_changes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let initial = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    acting
        .clients()
        .set_subject_policy(&env, &initial, &pairwise(), &[])
        .await
        .unwrap();
    assert!(matches!(
        acting
            .clients()
            .bind_subject(&env, &initial, &user, &user.to_string())
            .await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .subject_binding(&client, &user)
            .await
            .unwrap(),
        None
    );
    assert_eq!(audits(&db, "client.subject.bind").await, 0);
}

#[tokio::test]
async fn concurrent_first_bindings_choose_one_value_and_one_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let initial = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .set_subject_policy(&env, &initial, &pairwise(), &[])
        .await
        .unwrap();
    let current = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for index in 0_u8..8 {
        let store = db.restart_app_store().await;
        let actor = db.test_actor(&env);
        let current = current.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let env = Env::system();
            barrier.wait().await;
            store
                .scoped(scope)
                .acting(actor, CorrelationId::generate(&env))
                .clients()
                .bind_subject(&env, &current, &user, &URL_SAFE_NO_PAD.encode([index; 32]))
                .await
                .unwrap()
        }));
    }
    let mut values = Vec::new();
    for task in tasks {
        values.push(task.await.unwrap());
    }
    assert!(values.iter().all(|value| value == &values[0]));
    assert_eq!(audits(&db, "client.subject.bind").await, 1);
}

#[tokio::test]
async fn scope_guards_and_database_grants_protect_bound_identity() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let (foreign_scope, foreign_client, foreign_user) = fixture(&db, &env).await;
    let reader = db.store().scoped(scope).clients();
    let initial = reader.subject_policy(&client).await.unwrap();
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert!(matches!(
        reader.subject_policy(&foreign_client).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        acting
            .clients()
            .bind_subject(&env, &initial, &foreign_user, &foreign_user.to_string())
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        db.store()
            .scoped(foreign_scope)
            .clients()
            .subject_binding(&client, &user)
            .await,
        Err(StoreError::NotFound)
    ));
    acting
        .clients()
        .bind_subject(&env, &initial, &user, &user.to_string())
        .await
        .unwrap();
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM client_subject_bindings")
        .fetch_one(db.app_pool())
        .await
        .unwrap();
    assert_eq!(visible, 0, "unscoped pooled read must not reveal mappings");
    for operation in ["UPDATE", "DELETE"] {
        let permitted: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user, 'client_subject_bindings', $1)",
        )
        .bind(operation)
        .fetch_one(db.app_pool())
        .await
        .unwrap();
        assert!(!permitted);
    }
    // Even owner SQL cannot create a cross-scope user relation.
    assert!(sqlx::query("INSERT INTO client_subject_bindings (tenant_id,environment_id,client_id,user_id,external_subject,policy_revision,created_at) VALUES ($1,$2,$3,$4,$5,0,now())")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string())
        .bind(client.to_string()).bind(foreign_user.to_string()).bind(foreign_user.to_string())
        .execute(db.owner_pool()).await.is_err());
}

#[tokio::test]
async fn failed_audits_roll_back_policy_revision_and_first_binding() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let initial = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    sqlx::raw_sql("CREATE FUNCTION reject_subject_audit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.action IN ('client.subject.bind','client.subject_policy.update') THEN RAISE EXCEPTION 'injected identity audit failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_subject_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_subject_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        acting
            .clients()
            .set_subject_policy(&env, &initial, &pairwise(), &[])
            .await
            .is_err()
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .subject_policy(&client)
            .await
            .unwrap(),
        initial
    );
    assert!(
        acting
            .clients()
            .bind_subject(&env, &initial, &user, &user.to_string())
            .await
            .is_err()
    );
    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .subject_binding(&client, &user)
            .await
            .unwrap(),
        None
    );
    assert_eq!(audits(&db, "client.subject.bind").await, 0);
    assert_eq!(audits(&db, "client.subject_policy.update").await, 0);
}

#[tokio::test]
async fn control_policy_writer_is_narrow_audited_and_revision_guarded() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, _) = fixture(&db, &env).await;
    let read = db
        .control_store()
        .management()
        .client_subject_policies(scope);
    let initial = read.get(&client).await.unwrap();
    let writer = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .client_subject_policies(scope);
    let committed = writer.set(&env, &initial, &pairwise()).await.unwrap();
    assert_eq!(read.get(&client).await.unwrap(), committed);
    assert_eq!(committed.redirect_uris, initial.redirect_uris);
    assert!(matches!(
        writer
            .set(&env, &initial, &ClientSubjectPolicy::Public)
            .await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(audits(&db, "client.subject_policy.update").await, 1);
    for column in ["redirect_uris", "secret_hash", "subject_policy_revision"] {
        let permitted: bool = sqlx::query_scalar(
            "SELECT has_column_privilege('ironauth_control','clients',$1,'UPDATE')",
        )
        .bind(column)
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
        assert!(!permitted, "control role cannot rewrite {column}");
    }
    for operation in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
        let permitted: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('ironauth_control','client_subject_bindings',$1)",
        )
        .bind(operation)
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
        assert!(!permitted);
    }
    let (foreign, foreign_client, _) = fixture(&db, &env).await;
    assert!(matches!(
        read.get(&foreign_client).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        db.control_store()
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .client_subject_policies(foreign)
            .set(&env, &committed, &ClientSubjectPolicy::Public)
            .await,
        Err(StoreError::NotFound)
    ));
    sqlx::raw_sql("CREATE FUNCTION reject_control_subject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='client.subject_policy.update' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_control_subject_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_control_subject_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        writer
            .set(&env, &committed, &ClientSubjectPolicy::Public)
            .await
            .is_err()
    );
    assert_eq!(read.get(&client).await.unwrap(), committed);
}

#[tokio::test]
async fn control_policy_writer_refuses_an_environment_deleted_after_validation() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, _) = fixture(&db, &env).await;
    let initial = db
        .control_store()
        .management()
        .client_subject_policies(scope)
        .get(&client)
        .await
        .unwrap();
    sqlx::query("UPDATE environments SET deleted_at=to_timestamp(1) WHERE id=$1 AND tenant_id=$2")
        .bind(scope.environment().to_string())
        .bind(scope.tenant().to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    assert!(matches!(
        db.control_store()
            .management()
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .client_subject_policies(scope)
            .set(&env, &initial, &pairwise())
            .await,
        Err(StoreError::NotFound)
    ));
    assert_eq!(audits(&db, "client.subject_policy.update").await, 0);
}
