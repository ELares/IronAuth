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

#[tokio::test]
async fn legacy_history_guard_blocks_policy_activation_without_blocking_public_issuance() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, modern, user) = fixture(&db, &env).await;
    let read = db.store().scoped(scope).clients();
    assert!(read.subject_policy(&modern).await.unwrap().history_ready);
    // The old INSERT shape omits the readiness column, even after schema expansion.
    let legacy = ClientId::generate(&env, &scope);
    sqlx::query(
        "INSERT INTO clients (id,tenant_id,environment_id,display_name) VALUES ($1,$2,$3,'legacy')",
    )
    .bind(legacy.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(db.owner_pool())
    .await
    .unwrap();
    let expected = read.subject_policy(&legacy).await.unwrap();
    assert!(!expected.history_ready);
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert_eq!(
        acting
            .clients()
            .bind_subject(&env, &expected, &user, &user.to_string())
            .await
            .unwrap(),
        user.to_string()
    );
    historical_grant(&db, &env, scope, legacy, &user.to_string(), None).await;
    let page = acting
        .clients()
        .backfill_public_subject_history(&env, &expected, None, 500)
        .await
        .unwrap();
    assert_eq!((page.scanned, page.inserted, page.next_user), (1, 0, None));
    assert!(
        !read.subject_policy(&legacy).await.unwrap().history_ready,
        "a final page cannot certify missing audit-only history"
    );
    assert!(matches!(
        acting
            .clients()
            .set_subject_policy(&env, &expected, &pairwise(), &[])
            .await,
        Err(StoreError::Conflict)
    ));
    let control = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert!(matches!(
        control
            .client_subject_policies(scope)
            .set(&env, &expected, &pairwise())
            .await,
        Err(StoreError::Conflict)
    ));
    control
        .client_subject_policies(scope)
        .set(&env, &expected, &ClientSubjectPolicy::Public)
        .await
        .unwrap();
    let error = sqlx::query("UPDATE clients SET subject_type='pairwise', pairwise_sector='sector.example.test', subject_policy_redirect_uris=redirect_uris WHERE id=$1")
        .bind(legacy.to_string()).execute(db.owner_pool()).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().constraint(),
        Some("client_subject_history_ready")
    );
    for role in ["ironauth_app", "ironauth_control"] {
        let permitted: bool = sqlx::query_scalar(
            "SELECT has_column_privilege($1,'clients','subject_history_ready','UPDATE')",
        )
        .bind(role)
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
        assert_eq!(
            permitted,
            role == "ironauth_control",
            "only reconciliation control role can update readiness"
        );
    }
    assert_eq!(read.subject_policy(&legacy).await.unwrap(), expected);
}

#[tokio::test]
async fn history_guard_expand_marks_existing_rows_pending_and_versions_readiness_changes() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, _) = fixture(&db, &env).await;
    // Reconstruct the pre-0253 column shape, retaining a real existing client.
    sqlx::query("ALTER TABLE clients DROP COLUMN subject_history_ready CASCADE")
        .execute(db.owner_pool())
        .await
        .unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/0253_client_subject_history_guard.sql"
    ))
    .execute(db.owner_pool())
    .await
    .unwrap();
    let read = db.store().scoped(scope).clients();
    let before = read.subject_policy(&client).await.unwrap();
    assert!(!before.history_ready);
    assert_eq!(before.policy, ClientSubjectPolicy::Public);
    // Owner-only fixture operation exercises the revision trigger. This is not
    // reconciliation implementation or a recommended manual workaround.
    sqlx::query("UPDATE clients SET subject_history_ready=true WHERE id=$1")
        .bind(client.to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    let after = read.subject_policy(&client).await.unwrap();
    assert!(after.history_ready);
    assert_eq!(after.revision, before.revision + 1);
    sqlx::query("UPDATE clients SET subject_history_ready=false WHERE id=$1")
        .bind(client.to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(
        read.subject_policy(&client).await.unwrap().revision,
        before.revision + 2
    );
}

#[tokio::test]
async fn all_new_client_creation_paths_allow_pairwise_without_legacy_reconciliation() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, public, _) = fixture(&db, &env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let confidential = acting
        .clients()
        .create_confidential(&env, "basic", "client_secret_basic", "hash")
        .await
        .unwrap();
    let auth_time = acting
        .clients()
        .create_requiring_auth_time(&env, "auth time")
        .await
        .unwrap();
    let jwt = acting
        .clients()
        .create_jwt_auth(
            &env,
            ironauth_store::NewJwtAuthClient {
                display_name: "jwt",
                auth_method: "private_key_jwt",
                jwks: None,
                jwks_uri: Some("https://client.example.test/jwks"),
                signing_alg: None,
                tls_client_auth_cert: None,
                tls_client_auth_subject_dn: None,
            },
        )
        .await
        .unwrap();
    for client in [public, confidential, auth_time, jwt] {
        let expected = db
            .store()
            .scoped(scope)
            .clients()
            .subject_policy(&client)
            .await
            .unwrap();
        assert!(expected.history_ready);
        acting
            .clients()
            .set_subject_policy(&env, &expected, &pairwise(), &[])
            .await
            .unwrap();
        assert_eq!(
            db.store()
                .scoped(scope)
                .clients()
                .subject_policy(&client)
                .await
                .unwrap()
                .policy,
            pairwise()
        );
    }
}

#[tokio::test]
async fn history_guard_expand_refuses_to_certify_an_unsupported_existing_pairwise_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, _) = fixture(&db, &env).await;
    let expected = db
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
        .set_subject_policy(&env, &expected, &pairwise(), &[])
        .await
        .unwrap();
    sqlx::query("ALTER TABLE clients DROP COLUMN subject_history_ready CASCADE")
        .execute(db.owner_pool())
        .await
        .unwrap();
    let mut tx = db.owner_pool().begin().await.unwrap();
    let error = sqlx::raw_sql(include_str!(
        "../migrations/0253_client_subject_history_guard.sql"
    ))
    .execute(&mut *tx)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().constraint(),
        Some("client_subject_history_ready")
    );
    tx.rollback().await.unwrap();
    let kind: String = sqlx::query_scalar("SELECT subject_type FROM clients WHERE id=$1")
        .bind(client.to_string())
        .fetch_one(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(
        kind, "pairwise",
        "failed upgrade must not rewrite existing identity policy"
    );
}

async fn audits(db: &TestDatabase, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action=$1")
        .bind(action)
        .fetch_one(db.owner_pool())
        .await
        .unwrap()
}

// Owner SQL models rows written before immutable bindings existed. These
// fixtures intentionally include expired/revoked records, not fresh issuance.
async fn historical_grant(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: ClientId,
    subject: &str,
    session: Option<ironauth_store::SessionId>,
) -> ironauth_store::GrantId {
    let id = ironauth_store::GrantId::generate(env, &scope);
    sqlx::query("INSERT INTO grants (id,tenant_id,environment_id,client_id,subject,session_ref,revoked_at) VALUES ($1,$2,$3,$4,$5,$6,'2020-01-01Z')")
        .bind(id.to_string()).bind(scope.tenant().to_string()).bind(scope.environment().to_string())
        .bind(client.to_string()).bind(subject).bind(session.map(|s| s.to_string()))
        .execute(db.owner_pool()).await.unwrap();
    id
}

async fn historical_session(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    subject: &str,
    actor: &str,
) -> ironauth_store::SessionId {
    let id = ironauth_store::SessionId::generate(env, &scope);
    sqlx::query("INSERT INTO sessions (id,tenant_id,environment_id,subject,auth_methods,auth_time,expires_at,revoked_at,impersonator,impersonation_reason_code,impersonation_reason_text,impersonation_started_at,impersonation_expires_at) VALUES ($1,$2,$3,$4,'pwd','2020-01-01Z','2020-01-01Z','2020-01-01Z',$5,'support_ticket','historical fixture','2020-01-01Z','2020-01-01 00:30Z')")
        .bind(id.to_string()).bind(scope.tenant().to_string()).bind(scope.environment().to_string())
        .bind(subject).bind(actor).execute(db.owner_pool()).await.unwrap();
    id
}

async fn historical_sources(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    client: ClientId,
    users: &[UserId],
) {
    let grant = historical_grant(db, env, scope, client, &users[0].to_string(), None).await;
    // A refresh-only subject and actor exercise their own branches.
    sqlx::query("INSERT INTO refresh_families (id,tenant_id,environment_id,grant_id,subject,client_id,created_at,absolute_expires_at,revoked_at,impersonator,impersonation_reason_code,impersonation_expires_at) VALUES ($1,$2,$3,$4,$5,$6,'2020-01-01Z','2020-01-01Z','2020-01-01Z',$7,'support_ticket','2020-01-01Z')")
        .bind(ironauth_store::RefreshFamilyId::generate(env, &scope).to_string())
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string()).bind(grant.to_string())
        .bind(users[1].to_string()).bind(client.to_string()).bind(users[2].to_string())
        .execute(db.owner_pool()).await.unwrap();
    let session =
        historical_session(db, env, scope, &users[3].to_string(), &users[4].to_string()).await;
    sqlx::query("INSERT INTO client_sessions (id,tenant_id,environment_id,session_id,client_id,sid,revoked_at) VALUES ($1,$2,$3,$4,$5,'historical-sid','2020-01-01Z')")
        .bind(ironauth_store::ClientSessionId::generate(env, &scope).to_string())
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string()).bind(session.to_string())
        .bind(client.to_string()).execute(db.owner_pool()).await.unwrap();
    let session =
        historical_session(db, env, scope, &users[0].to_string(), &users[5].to_string()).await;
    historical_grant(db, env, scope, client, &users[0].to_string(), Some(session)).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    // Other-client, no-history, and foreign-scope history must not enroll users.
    let other = acting.clients().create(env, "other history").await.unwrap();
    historical_grant(db, env, scope, other, &users[6].to_string(), None).await;
    let (foreign_scope, foreign_client, foreign_user) = fixture(db, env).await;
    historical_grant(
        db,
        env,
        foreign_scope,
        foreign_client,
        &users[8].to_string(),
        None,
    )
    .await;
    historical_grant(db, env, scope, client, &foreign_user.to_string(), None).await;
    historical_grant(db, env, scope, client, "service-principal", None).await;
    // A deleted account keeps identity history without gaining login eligibility.
    sqlx::query("UPDATE users SET deleted_at='2020-01-01Z' WHERE id=$1")
        .bind(users[5].to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn history_backfill_pages_retained_edges_without_enrolling_unrelated_users() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, first) = fixture(&db, &env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let read = db.store().scoped(scope).clients();
    let policy = read.subject_policy(&client).await.unwrap();
    let mut users = vec![first];
    for i in 1..9 {
        users.push(
            acting
                .users()
                .register(&env, &format!("history-{i}@example.test"), "hash", None)
                .await
                .unwrap(),
        );
    }
    historical_sources(&db, &env, scope, client, &users).await;
    let mut cursor = None;
    let mut scanned = 0;
    let mut inserted = 0;
    let mut pages = 0;
    loop {
        let page = acting
            .clients()
            .backfill_public_subject_history(&env, &policy, cursor.as_ref(), 2)
            .await
            .unwrap();
        assert_eq!(page.scanned, 2);
        let retry = acting
            .clients()
            .backfill_public_subject_history(&env, &policy, cursor.as_ref(), 2)
            .await
            .unwrap();
        assert_eq!(retry.scanned, page.scanned);
        assert_eq!(retry.next_user, page.next_user);
        assert_eq!(retry.inserted, 0);
        pages += 1;
        assert!(pages <= 3, "cursor must make progress");
        scanned += page.scanned;
        inserted += page.inserted;
        cursor = page.next_user;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!((scanned, inserted, pages), (6, 6, 3));
    for (i, user) in users.iter().enumerate() {
        assert_eq!(
            read.subject_binding(&client, user).await.unwrap(),
            (i < 6).then(|| user.to_string())
        );
    }
    assert_eq!(audits(&db, "client.subject_history.backfill").await, 6);
    acting
        .clients()
        .set_subject_policy(&env, &policy, &pairwise(), &[])
        .await
        .unwrap();
    let current = read.subject_policy(&client).await.unwrap();
    let candidate = URL_SAFE_NO_PAD.encode([9; 32]);
    assert_eq!(
        acting
            .clients()
            .bind_subject(&env, &current, &users[0], &candidate)
            .await
            .unwrap(),
        users[0].to_string()
    );
    assert_eq!(
        acting
            .clients()
            .bind_subject(&env, &current, &users[7], &candidate)
            .await
            .unwrap(),
        candidate
    );
    // Binding lookup preserves history; it is not an authorization decision.
    assert!(
        db.store()
            .scoped(scope)
            .users()
            .by_identifier("history-5@example.test")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn history_backfill_refuses_stale_nonpublic_and_foreign_inputs_and_rolls_back_failed_audit() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let read = db.store().scoped(scope).clients();
    let initial = read.subject_policy(&client).await.unwrap();
    historical_grant(&db, &env, scope, client, &user.to_string(), None).await;
    for limit in [0, 501] {
        assert!(matches!(
            acting
                .clients()
                .backfill_public_subject_history(&env, &initial, None, limit)
                .await,
            Err(StoreError::Invalid)
        ));
    }
    let (foreign_scope, foreign_client, foreign_user) = fixture(&db, &env).await;
    let foreign = db
        .store()
        .scoped(foreign_scope)
        .clients()
        .subject_policy(&foreign_client)
        .await
        .unwrap();
    assert!(matches!(
        acting
            .clients()
            .backfill_public_subject_history(&env, &foreign, None, 10)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        acting
            .clients()
            .backfill_public_subject_history(&env, &initial, Some(&foreign_user), 10)
            .await,
        Err(StoreError::NotFound)
    ));
    acting
        .clients()
        .set_subject_policy(&env, &initial, &pairwise(), &[])
        .await
        .unwrap();
    let current = read.subject_policy(&client).await.unwrap();
    for policy in [&initial, &current] {
        assert!(matches!(
            acting
                .clients()
                .backfill_public_subject_history(&env, policy, None, 10)
                .await,
            Err(StoreError::Conflict)
        ));
    }
    acting
        .clients()
        .set_subject_policy(&env, &current, &ClientSubjectPolicy::Public, &[])
        .await
        .unwrap();
    let current = read.subject_policy(&client).await.unwrap();
    assert!(matches!(
        acting
            .clients()
            .backfill_public_subject_history(&env, &initial, None, 10)
            .await,
        Err(StoreError::Conflict)
    ));
    sqlx::raw_sql("CREATE FUNCTION reject_history_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='client.subject_history.backfill' THEN RAISE EXCEPTION 'injected history audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_history_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_history_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        acting
            .clients()
            .backfill_public_subject_history(&env, &current, None, 10)
            .await
            .is_err()
    );
    assert_eq!(read.subject_binding(&client, &user).await.unwrap(), None);
    assert_eq!(audits(&db, "client.subject_history.backfill").await, 0);
    sqlx::query("DROP TRIGGER reject_history_audit ON audit_log")
        .execute(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(
        acting
            .clients()
            .backfill_public_subject_history(&env, &current, None, 10)
            .await
            .unwrap()
            .inserted,
        1
    );
}

#[tokio::test]
async fn history_backfill_concurrent_retries_preserve_an_existing_pairwise_binding() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let read = db.store().scoped(scope).clients();
    let initial = read.subject_policy(&client).await.unwrap();
    acting
        .clients()
        .set_subject_policy(&env, &initial, &pairwise(), &[])
        .await
        .unwrap();
    let current = read.subject_policy(&client).await.unwrap();
    let candidate = URL_SAFE_NO_PAD.encode([3; 32]);
    acting
        .clients()
        .bind_subject(&env, &current, &user, &candidate)
        .await
        .unwrap();
    acting
        .clients()
        .set_subject_policy(&env, &current, &ClientSubjectPolicy::Public, &[])
        .await
        .unwrap();
    let current = read.subject_policy(&client).await.unwrap();
    historical_grant(&db, &env, scope, client, &user.to_string(), None).await;
    let second = acting
        .users()
        .register(&env, "concurrent-history@example.test", "hash", None)
        .await
        .unwrap();
    historical_grant(&db, &env, scope, client, &second.to_string(), None).await;
    let clients = acting.clients();
    let (a, b) = tokio::join!(
        clients.backfill_public_subject_history(&env, &current, None, 500),
        clients.backfill_public_subject_history(&env, &current, None, 500)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!((a.scanned, b.scanned), (2, 2));
    assert_eq!(a.inserted + b.inserted, 1);
    assert_eq!(
        read.subject_binding(&client, &user).await.unwrap(),
        Some(candidate)
    );
    let restarted = db.restart_app_store().await;
    assert_eq!(
        restarted
            .scoped(scope)
            .clients()
            .subject_binding(&client, &second)
            .await
            .unwrap(),
        Some(second.to_string())
    );
    assert_eq!(audits(&db, "client.subject_history.backfill").await, 2);
    let empty = acting
        .clients()
        .backfill_public_subject_history(
            &env,
            &current,
            Some(
                &[user, second]
                    .into_iter()
                    .max_by_key(ToString::to_string)
                    .unwrap(),
            ),
            500,
        )
        .await
        .unwrap();
    assert_eq!(
        (empty.scanned, empty.inserted, empty.next_user),
        (0, 0, None)
    );
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
        assert_eq!(permitted, matches!(operation, "SELECT" | "INSERT"));
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

fn reconciliation_evidence() -> ironauth_store::ClientSubjectHistoryAttestation {
    ironauth_store::ClientSubjectHistoryAttestation {
        evidence_sha256: "a".repeat(64),
        legacy_issuers_stopped: true,
        external_history_reconciled: true,
        public_identifiers_retained: true,
    }
}

async fn legacy_policy(
    db: &TestDatabase,
    scope: Scope,
    client: ClientId,
) -> ironauth_store::ClientSubjectPolicySnapshot {
    sqlx::query("UPDATE clients SET subject_history_ready=false WHERE id=$1")
        .bind(client.to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    db.store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap()
}

// One linear transition from pending history through recovery, receipt and policy activation.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn reconciliation_covers_all_retained_history_and_explicit_roster_before_unlocking_policy() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let expected = legacy_policy(&db, scope, client).await;
    let actor = db.test_actor(&env);
    let data = db
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env));
    let external = data
        .users()
        .register(&env, "external-history@example.test", "hash", None)
        .await
        .unwrap();
    historical_grant(&db, &env, scope, client, &user.to_string(), None).await;
    let control = db
        .control_store()
        .management()
        .acting(actor, CorrelationId::generate(&env));
    let history = control.client_subject_history(scope);
    let read = db
        .control_store()
        .management()
        .client_subject_history(scope);
    assert_eq!(read.get(&client).await.unwrap().missing_bindings, 1);
    let evidence = reconciliation_evidence();
    assert!(matches!(
        history.reconcile(&env, &expected, &evidence).await,
        Err(StoreError::Conflict)
    ));
    // A skipped cursor can return a final empty page but cannot certify readiness.
    let skipped = history
        .backfill(&env, &expected, Some(&user), 1)
        .await
        .unwrap();
    assert_eq!(skipped.next_user, None);
    assert!(matches!(
        history.reconcile(&env, &expected, &evidence).await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        history
            .import_public(&env, &expected, &[external, external])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        history
            .import_public(&env, &expected, &[external])
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        history
            .backfill(&env, &expected, None, 1)
            .await
            .unwrap()
            .inserted,
        1
    );
    let complete = history.reconcile(&env, &expected, &evidence).await.unwrap();
    assert!(complete.ready);
    assert_eq!(
        (
            complete.retained_users,
            complete.missing_bindings,
            complete.conflicting_bindings
        ),
        (1, 0, 0)
    );
    assert_eq!(complete.revision, expected.revision + 1);
    assert_eq!(
        complete.evidence_sha256.as_deref(),
        Some(evidence.evidence_sha256.as_str())
    );
    assert!(complete.reconciled_at_unix_micros.is_some());
    assert_eq!(read.get(&client).await.unwrap(), complete);
    assert!(matches!(
        history.reconcile(&env, &expected, &evidence).await,
        Err(StoreError::Conflict)
    ));
    let current = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    control
        .client_subject_policies(scope)
        .set(&env, &current, &pairwise())
        .await
        .unwrap();
    for account in [user, external] {
        assert_eq!(
            db.store()
                .scoped(scope)
                .clients()
                .subject_binding(&client, &account)
                .await
                .unwrap(),
            Some(account.to_string())
        );
    }
    let restarted = db.restart_app_store().await;
    assert_eq!(
        restarted
            .management()
            .client_subject_history(scope)
            .get(&client)
            .await
            .unwrap()
            .evidence_sha256,
        complete.evidence_sha256
    );
    assert_eq!(audits(&db, "client.subject_history.reconcile").await, 1);
}

#[tokio::test]
async fn reconciliation_and_roster_import_rollback_on_audit_failure_and_reject_unattested_claims() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let expected = legacy_policy(&db, scope, client).await;
    let control = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let history = control.client_subject_history(scope);
    let valid = reconciliation_evidence();
    for evidence in [
        ironauth_store::ClientSubjectHistoryAttestation {
            legacy_issuers_stopped: false,
            ..valid.clone()
        },
        ironauth_store::ClientSubjectHistoryAttestation {
            external_history_reconciled: false,
            ..valid.clone()
        },
        ironauth_store::ClientSubjectHistoryAttestation {
            public_identifiers_retained: false,
            ..valid.clone()
        },
        ironauth_store::ClientSubjectHistoryAttestation {
            evidence_sha256: "A".repeat(64),
            ..valid.clone()
        },
    ] {
        assert!(matches!(
            history.reconcile(&env, &expected, &evidence).await,
            Err(StoreError::Invalid)
        ));
    }
    sqlx::raw_sql("CREATE FUNCTION reject_reconciliation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('client.subject_history.import','client.subject_history.reconcile') THEN RAISE EXCEPTION 'injected reconciliation audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_reconciliation_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_reconciliation_audit();")
        .execute(db.owner_pool()).await.unwrap();
    assert!(
        history
            .import_public(&env, &expected, &[user])
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
    assert!(history.reconcile(&env, &expected, &valid).await.is_err());
    assert_eq!(
        db.store()
            .scoped(scope)
            .clients()
            .subject_policy(&client)
            .await
            .unwrap(),
        expected
    );
    let report = db
        .control_store()
        .management()
        .client_subject_history(scope)
        .get(&client)
        .await
        .unwrap();
    assert_eq!(
        (
            report.ready,
            report.evidence_sha256,
            report.reconciled_at_unix_micros
        ),
        (false, None, None)
    );
    assert_eq!(audits(&db, "client.subject_history.import").await, 0);
    assert_eq!(audits(&db, "client.subject_history.reconcile").await, 0);
    sqlx::query("DROP TRIGGER reject_reconciliation_audit ON audit_log")
        .execute(db.owner_pool())
        .await
        .unwrap();
    assert_eq!(
        history
            .import_public(&env, &expected, &[user])
            .await
            .unwrap(),
        1
    );
    assert!(
        history
            .reconcile(&env, &expected, &valid)
            .await
            .unwrap()
            .ready
    );
}

// A shared corrupted-history fixture verifies refusal across every recovery operation.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn reconciliation_refuses_conflicting_unknown_foreign_and_deleted_scope_inputs() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, user) = fixture(&db, &env).await;
    let expected = legacy_policy(&db, scope, client).await;
    let (foreign_scope, foreign_client, foreign_user) = fixture(&db, &env).await;
    let foreign = db
        .store()
        .scoped(foreign_scope)
        .clients()
        .subject_policy(&foreign_client)
        .await
        .unwrap();
    let control = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let history = control.client_subject_history(scope);
    let evidence = reconciliation_evidence();
    assert!(matches!(
        history
            .import_public(&env, &expected, &[foreign_user])
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        history.reconcile(&env, &foreign, &evidence).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        db.control_store()
            .management()
            .client_subject_history(scope)
            .get(&foreign_client)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        history.import_public(&env, &expected, &[]).await,
        Err(StoreError::Invalid)
    ));
    assert!(matches!(
        history
            .import_public(&env, &expected, &vec![user; 501])
            .await,
        Err(StoreError::Invalid)
    ));
    let missing = UserId::generate(&env, &scope);
    assert!(matches!(
        history
            .import_public(&env, &expected, &[user, missing])
            .await,
        Err(StoreError::NotFound)
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
    historical_grant(&db, &env, scope, client, &user.to_string(), None).await;
    sqlx::query("INSERT INTO client_subject_bindings (tenant_id,environment_id,client_id,user_id,external_subject,policy_revision,created_at) VALUES ($1,$2,$3,$4,$5,0,'2020-01-01Z')")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string()).bind(client.to_string())
        .bind(user.to_string()).bind(URL_SAFE_NO_PAD.encode([8;32])).execute(db.owner_pool()).await.unwrap();
    assert!(matches!(
        history.import_public(&env, &expected, &[user]).await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        history
            .backfill(&env, &expected, None, 500)
            .await
            .unwrap()
            .inserted,
        0
    );
    assert_eq!(
        db.control_store()
            .management()
            .client_subject_history(scope)
            .get(&client)
            .await
            .unwrap()
            .conflicting_bindings,
        1
    );
    assert!(matches!(
        history.reconcile(&env, &expected, &evidence).await,
        Err(StoreError::Conflict)
    ));
    sqlx::query("UPDATE environments SET deleted_at='2020-01-01Z' WHERE id=$1")
        .bind(scope.environment().to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    assert!(matches!(
        history.import_public(&env, &expected, &[user]).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        history.backfill(&env, &expected, None, 500).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        history.reconcile(&env, &expected, &evidence).await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn concurrent_reconciliation_commits_one_receipt_and_does_not_rewrite_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, _) = fixture(&db, &env).await;
    let expected = legacy_policy(&db, scope, client).await;
    let control = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let repo = control.client_subject_history(scope);
    let a = reconciliation_evidence();
    let b = ironauth_store::ClientSubjectHistoryAttestation {
        evidence_sha256: "b".repeat(64),
        ..a.clone()
    };
    let (first, second) = tokio::join!(
        repo.reconcile(&env, &expected, &a),
        repo.reconcile(&env, &expected, &b)
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let (winner, loser) = if first.is_ok() {
        (first, second)
    } else {
        (second, first)
    };
    assert!(matches!(loser, Err(StoreError::Conflict)));
    let current = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    assert!(matches!(
        repo.reconcile(&env, &current, &a).await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        db.control_store()
            .management()
            .client_subject_history(scope)
            .get(&client)
            .await
            .unwrap(),
        winner.unwrap()
    );
    assert_eq!(audits(&db, "client.subject_history.reconcile").await, 1);
}

/// Opt-in, real-role scale qualification. Timings are observations, not flaky
/// wall-clock pass/fail thresholds. Run with --ignored --nocapture.
#[tokio::test]
#[ignore = "large retained-history dataset; run explicitly for release qualification"]
async fn grant_heavy_history_scale_qualification() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let (scope, client, _) = fixture(&db, &env).await;
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let other = acting
        .clients()
        .create(&env, "unrelated history load")
        .await
        .unwrap();
    let users = seed_scale_users(&db, &env, scope).await;
    sqlx::query("UPDATE clients SET subject_history_ready=false WHERE id=$1")
        .bind(client.to_string())
        .execute(db.owner_pool())
        .await
        .unwrap();
    let expected = db
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    // Repeated, revoked grant edges model retained history, not current sessions.
    seed_scale_grants(&db, scope, client, &users, 100_000).await;
    let control = db
        .control_store()
        .management()
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let history = control.client_subject_history(scope);
    for unrelated in [0, 100_000, 900_000] {
        if unrelated != 0 {
            seed_scale_grants(&db, scope, other, &users, unrelated).await;
        }
        db.execute_owner_sql("ANALYZE grants, users, client_subject_bindings")
            .await;
        let start = env.clock().monotonic();
        let report = db
            .control_store()
            .management()
            .client_subject_history(scope)
            .get(&client)
            .await
            .unwrap();
        let report_ms = env.clock().monotonic().duration_since(start).as_secs_f64() * 1000.0;
        assert_eq!(report.retained_users, 10_000);
        let start = env.clock().monotonic();
        let page = history.backfill(&env, &expected, None, 500).await.unwrap();
        assert_eq!(page.scanned, 500);
        eprintln!(
            "history-scale {}",
            serde_json::json!({"added_unrelated_grants": unrelated, "report_ms":report_ms, "first_page_ms":env.clock().monotonic().duration_since(start).as_secs_f64()*1000.0})
        );
    }
    let start = env.clock().monotonic();
    let mut cursor = None;
    let mut scanned = 0;
    let mut pages = 0;
    loop {
        let page = history
            .backfill(&env, &expected, cursor.as_ref(), 500)
            .await
            .unwrap();
        scanned += page.scanned;
        pages += 1;
        cursor = page.next_user;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!((scanned, pages), (10_000, 20));
    let all_pages_ms = env.clock().monotonic().duration_since(start).as_secs_f64() * 1000.0;
    let start = env.clock().monotonic();
    let report = history
        .reconcile(&env, &expected, &reconciliation_evidence())
        .await
        .unwrap();
    assert!(report.ready);
    assert_eq!(
        (
            report.retained_users,
            report.missing_bindings,
            report.conflicting_bindings
        ),
        (10_000, 0, 0)
    );
    eprintln!(
        "history-scale {}",
        serde_json::json!({"target_grants":100_000,"unrelated_grants":1_000_000,"users":10_000,"pages":pages,"all_pages_ms":all_pages_ms,"reconcile_ms":env.clock().monotonic().duration_since(start).as_secs_f64()*1000.0})
    );
    explain_scale_grants(&db, scope, client).await;
}

async fn seed_scale_grants(
    db: &TestDatabase,
    scope: Scope,
    client: ClientId,
    users: &[String],
    count: i32,
) {
    // Scope/client are bound parameters; IDs are test-only unique historical edges.
    sqlx::query("INSERT INTO grants (id,tenant_id,environment_id,client_id,subject,revoked_at) SELECT $3 || '-load-' || $5::text || '-' || n::text,$1,$2,$3,($4::text[])[1+((n-1)%array_length($4::text[],1))],'2020-01-01Z' FROM generate_series(1,$5::int) n")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string()).bind(client.to_string()).bind(users).bind(count)
        .execute(db.owner_pool()).await.unwrap();
}

async fn explain_scale_grants(db: &TestDatabase, scope: Scope, client: ClientId) {
    // Inspect the grant access path under the actual restricted control role/RLS.
    let mut tx = db.control_pool().begin().await.unwrap();
    sqlx::query("SELECT set_config('ironauth.tenant_id',$1,true),set_config('ironauth.environment_id',$2,true)")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string()).execute(&mut *tx).await.unwrap();
    let plan: serde_json::Value = sqlx::query_scalar("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) SELECT subject,session_ref FROM grants WHERE tenant_id=$1 AND environment_id=$2 AND client_id=$3")
        .bind(scope.tenant().to_string()).bind(scope.environment().to_string()).bind(client.to_string()).fetch_one(&mut *tx).await.unwrap();
    eprintln!("history-scale-grant-plan {plan}");
    tx.rollback().await.unwrap();
}

async fn seed_scale_users(db: &TestDatabase, env: &Env, scope: Scope) -> Vec<String> {
    let acting = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env));
    let mut users = Vec::new();
    for i in 0..10_000 {
        users.push(
            acting
                .users()
                .register(env, &format!("scale-{i}@example.test"), "hash", None)
                .await
                .unwrap()
                .to_string(),
        );
    }
    users
}
