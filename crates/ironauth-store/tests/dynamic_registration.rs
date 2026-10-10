// SPDX-License-Identifier: MIT OR Apache-2.0

//! The real app-role dynamic-registration insert preserves every metadata binding.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewDynamicClient};

#[tokio::test]
async fn dynamic_registration_preserves_metadata_and_policy_snapshot() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let redirects = ["https://client.example/callback".to_owned()];
    let input = registration_input(&redirects, &ironauth_store::ClientSubjectPolicy::Public);
    let registration = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients()
        .register_dynamic(&env, input, Some(10))
        .await
        .expect("app-role dynamic registration");
    let stored = db
        .store()
        .scoped(scope)
        .clients()
        .dynamic_registration(&registration.id)
        .await
        .expect("stored registration");
    assert_eq!(stored.display_name, input.display_name);
    assert_eq!(stored.redirect_uris, redirects);
    assert_eq!(
        stored.userinfo_signed_response_alg.as_deref(),
        input.userinfo_signed_response_alg
    );
    assert_eq!(
        stored.authorization_signed_response_alg.as_deref(),
        input.authorization_signed_response_alg
    );
    assert_eq!(
        stored.id_token_encrypted_response_alg.as_deref(),
        input.id_token_encrypted_response_alg
    );
    assert_eq!(
        stored.id_token_encrypted_response_enc.as_deref(),
        input.id_token_encrypted_response_enc
    );
    assert_eq!(
        stored.registration_access_token_hash.as_deref(),
        Some(input.registration_access_token_hash)
    );
    assert_eq!(
        stored.registration_client_uri.as_deref(),
        Some(registration.registration_client_uri.as_str())
    );
    assert_eq!(stored.dcr_policy_chain.as_deref(), input.dcr_policy_chain);
    assert!(stored.quarantined);
}

fn registration_input<'a>(
    redirects: &'a [String],
    policy: &'a ironauth_store::ClientSubjectPolicy,
) -> NewDynamicClient<'a> {
    NewDynamicClient {
        subject_policy: policy,
        display_name: "owned registration fixture",
        auth_method: "none",
        secret_hash: None,
        redirect_uris: redirects,
        application_type: "web",
        id_token_signed_response_alg: "EdDSA",
        userinfo_signed_response_alg: Some("EdDSA"),
        authorization_signed_response_alg: Some("ES256"),
        id_token_encrypted_response_alg: Some("ECDH-ES"),
        id_token_encrypted_response_enc: Some("A256GCM"),
        jwks: Some("{\"keys\":[]}"),
        jwks_uri: None,
        token_endpoint_auth_signing_alg: None,
        tls_client_auth_cert: None,
        tls_client_auth_subject_dn: None,
        use_mtls_endpoint_aliases: false,
        registration_access_token_hash: "owned-registration-token-digest",
        registration_uri_base: "https://issuer.example/connect/register",
        quarantined: true,
        dcr_policy_chain: Some("[]"),
    }
}

fn replacement<'a>(
    record: &'a ironauth_store::DynamicClientRecord,
    redirects: &'a [String],
    policy: &'a ironauth_store::ClientSubjectPolicy,
    new_hash: &'a str,
) -> ironauth_store::DynamicClientUpdate<'a> {
    ironauth_store::DynamicClientUpdate {
        subject_policy: policy,
        expected_subject_policy_revision: record.subject_policy_revision,
        expected_registration_access_token_hash: record.registration_access_token_hash.as_deref(),
        display_name: "replacement",
        auth_method: "none",
        redirect_uris: redirects,
        application_type: "web",
        id_token_signed_response_alg: "EdDSA",
        userinfo_signed_response_alg: None,
        jwks: record.jwks.as_deref(),
        jwks_uri: record.jwks_uri.as_deref(),
        token_endpoint_auth_signing_alg: None,
        registration_access_token_hash: new_hash,
    }
}

fn pairwise(host: &str) -> ironauth_store::ClientSubjectPolicy {
    ironauth_store::ClientSubjectPolicy::Pairwise {
        sector_identifier: host.to_owned(),
        sector_identifier_uri: None,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one concurrency scenario checks the winning identity, audit and token-only stale retry"
)]
#[tokio::test]
async fn concurrent_dynamic_updates_admit_only_the_authenticated_policy_revision() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store();
    let actor_a = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let actor_b = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let a = actor_a.clients();
    let b = actor_b.clients();
    let redirects = ["https://first.example/cb".to_owned()];
    let registration = a
        .register_dynamic(
            &env,
            registration_input(&redirects, &pairwise("first.example")),
            None,
        )
        .await
        .unwrap();
    let original = store
        .scoped(scope)
        .clients()
        .dynamic_registration(&registration.id)
        .await
        .unwrap();
    let first_redirects = ["https://winner-a.example/cb".to_owned()];
    let second_redirects = ["https://winner-b.example/cb".to_owned()];
    let first_policy = pairwise("winner-a.example");
    let second_policy = pairwise("winner-b.example");
    let (first, second) = tokio::join!(
        a.update_dynamic(
            &env,
            &registration.id,
            replacement(&original, &first_redirects, &first_policy, "new-a")
        ),
        b.update_dynamic(
            &env,
            &registration.id,
            replacement(&original, &second_redirects, &second_policy, "new-b")
        ),
    );
    assert_ne!(first.is_ok(), second.is_ok());
    assert!(matches!(
        if first.is_ok() { second } else { first },
        Err(ironauth_store::StoreError::NotFound)
    ));
    let stored = store
        .scoped(scope)
        .clients()
        .dynamic_registration(&registration.id)
        .await
        .unwrap();
    assert_eq!(
        stored.subject_policy_revision,
        original.subject_policy_revision + 1
    );
    if stored.registration_access_token_hash.as_deref() == Some("new-a") {
        assert_eq!(stored.subject_policy, first_policy);
        assert_eq!(stored.redirect_uris, first_redirects);
    } else {
        assert_eq!(
            stored.registration_access_token_hash.as_deref(),
            Some("new-b")
        );
        assert_eq!(stored.subject_policy, second_policy);
        assert_eq!(stored.redirect_uris, second_redirects);
    }
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action='client.updated'")
            .fetch_one(db.owner_pool())
            .await
            .unwrap();
    assert_eq!(audits, 1);
    // A metadata-only update still rotates the token; unchanged policy revision is
    // not enough to let the old registration token authorize a subsequent write.
    a.update_dynamic(
        &env,
        &registration.id,
        replacement(
            &stored,
            &stored.redirect_uris,
            &stored.subject_policy,
            "new-c",
        ),
    )
    .await
    .unwrap();
    assert!(matches!(
        a.update_dynamic(
            &env,
            &registration.id,
            replacement(
                &stored,
                &stored.redirect_uris,
                &stored.subject_policy,
                "stale-token"
            )
        )
        .await,
        Err(ironauth_store::StoreError::NotFound)
    ));
}

#[tokio::test]
async fn dynamic_policy_update_refuses_stale_validation_and_rolls_back_on_audit_failure() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let store = db.store();
    let acting = store
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    let repo = acting.clients();
    let reader = store.scoped(scope).clients();
    let redirects = ["https://original.example/cb".to_owned()];
    let registration = repo
        .register_dynamic(
            &env,
            registration_input(&redirects, &ironauth_store::ClientSubjectPolicy::Public),
            None,
        )
        .await
        .unwrap();
    let old = reader.dynamic_registration(&registration.id).await.unwrap();
    let old_policy = reader.subject_policy(&registration.id).await.unwrap();
    repo.set_subject_policy(&env, &old_policy, &pairwise("original.example"), &redirects)
        .await
        .unwrap();
    assert!(matches!(
        repo.update_dynamic(
            &env,
            &registration.id,
            replacement(
                &old,
                &redirects,
                &ironauth_store::ClientSubjectPolicy::Public,
                "stale-policy"
            )
        )
        .await,
        Err(ironauth_store::StoreError::NotFound)
    ));
    let current = reader.dynamic_registration(&registration.id).await.unwrap();
    assert_eq!(
        current.registration_access_token_hash,
        old.registration_access_token_hash
    );
    sqlx::raw_sql("CREATE FUNCTION reject_dynamic_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='client.updated' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_dynamic_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_dynamic_audit();")
        .execute(db.owner_pool()).await.unwrap();
    let new_redirects = ["https://replacement.example/cb".to_owned()];
    assert!(
        repo.update_dynamic(
            &env,
            &registration.id,
            replacement(
                &current,
                &new_redirects,
                &pairwise("replacement.example"),
                "uncommitted-token"
            )
        )
        .await
        .is_err()
    );
    assert_eq!(
        reader.dynamic_registration(&registration.id).await.unwrap(),
        current
    );
    let foreign = db.seed_scope(&env).await;
    assert!(matches!(
        store
            .scoped(foreign)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .clients()
            .update_dynamic(
                &env,
                &registration.id,
                replacement(
                    &current,
                    &redirects,
                    &current.subject_policy,
                    "foreign-token"
                )
            )
            .await,
        Err(ironauth_store::StoreError::NotFound)
    ));
}
