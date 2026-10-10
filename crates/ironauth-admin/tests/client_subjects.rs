// SPDX-License-Identifier: MIT OR Apache-2.0
//! Real control-role HTTP qualification for identity-policy configuration.
mod common;
use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{ClientId, CorrelationId, EnvironmentId, Scope, TenantId};
use serde_json::{Value, json};
use std::sync::Arc;

async fn fixture(h: &Harness, label: &str) -> (Scope, ClientId, String) {
    let (tenant, environment) = h.create_tenant(label, label).await;
    let scope = Scope::new(
        TenantId::parse(&tenant).unwrap(),
        EnvironmentId::parse(&environment).unwrap(),
    );
    let env = Env::system();
    let actor = ironauth_admin::bootstrap_operator_actor();
    let acting = h
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env));
    let client = acting.clients().create(&env, label).await.unwrap();
    acting
        .clients()
        .register_redirect_uris(&env, &client, &["https://app.example.test/cb"])
        .await
        .unwrap();
    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/clients/{client}/subject-policy");
    (scope, client, path)
}

async fn read(h: &Harness, path: &str) -> Value {
    let (status, _, body) = h.get(path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn legacy_client_cannot_enable_pairwise_or_claim_readiness_through_policy_api() {
    let h = Harness::start(20).await;
    let (_scope, client, path) = fixture(&h, "legacy history").await;
    assert_eq!(read(&h, &path).await["history_ready"], true);
    sqlx::query("UPDATE clients SET subject_history_ready=false WHERE id=$1")
        .bind(client.to_string())
        .execute(h.db().owner_pool())
        .await
        .unwrap();
    let initial = read(&h, &path).await;
    assert_eq!(initial["history_ready"], false);
    // Refuse before the absent fetcher could return 503 or contact this URL.
    let (status, _, body) = h
        .put(
            &path,
            &json!({
                "expected_revision":initial["revision"], "subject_type":"pairwise",
                "sector_identifier_uri":"https://sector.example.test/list"
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("reconcile legacy"));
    let (status, _, _) = h.put(&path, &json!({
        "expected_revision":initial["revision"], "subject_type":"public", "history_ready":true
    }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = h
        .put(
            &path,
            &json!({
                "expected_revision":initial["revision"], "subject_type":"public"
            })
            .to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read(&h, &path).await, initial);
}

#[tokio::test]
async fn management_policy_round_trip_preserves_bindings_and_rejects_stale_updates() {
    let h = Harness::start(20).await;
    let (scope, client, path) = fixture(&h, "policy roundtrip").await;
    let original = read(&h, &path).await;
    assert_eq!(original["subject_type"], "public");
    let env = Env::system();
    let acting = h.store().scoped(scope).acting(
        ironauth_admin::bootstrap_operator_actor(),
        CorrelationId::generate(&env),
    );
    let user = acting
        .users()
        .register(&env, "policy@example.test", "test-hash", None)
        .await
        .unwrap();
    let initial = h
        .store()
        .scoped(scope)
        .clients()
        .subject_policy(&client)
        .await
        .unwrap();
    acting
        .clients()
        .bind_subject(&env, &initial, &user, &user.to_string())
        .await
        .unwrap();
    let body =
        json!({"subject_type":"pairwise","expected_revision":original["revision"]}).to_string();
    let (status, headers, updated) = h.put(&path, &body).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    common::assert_rate_limit_headers(&headers);
    let updated: Value = serde_json::from_str(&updated).unwrap();
    assert_eq!(updated["sector_identifier"], "app.example.test");
    assert_eq!(updated["redirect_uris"], original["redirect_uris"]);
    assert_eq!(read(&h, &path).await, updated);
    assert_eq!(h.put(&path, &body).await.0, StatusCode::CONFLICT);
    assert_eq!(
        h.store()
            .scoped(scope)
            .clients()
            .subject_binding(&client, &user)
            .await
            .unwrap(),
        Some(user.to_string())
    );
    let audits = h
        .control_store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|a| a.action == "client.subject_policy.update")
            .count(),
        1
    );
}

#[tokio::test]
async fn management_policy_refuses_metadata_and_resolves_scope_before_parsing() {
    let h = Harness::start(20).await;
    let (scope, _, path) = fixture(&h, "policy validation").await;
    let (_, foreign, _) = fixture(&h, "foreign policy").await;
    let original = read(&h, &path).await;
    assert_eq!(
        h.put(&path, r#"{"subject_type":"public"}"#).await.0,
        StatusCode::BAD_REQUEST
    );
    for mut body in [
        json!({"subject_type":"wrong"}),
        json!({"subject_type":"public","sector_identifier_uri":"https://sector.example.test/list"}),
        json!({"subject_type":"pairwise","sector_identifier_uri":"http://sector.example.test/list"}),
        json!({"subject_type":"public","redirect_uris":[]}),
        json!({"subject_type":"pairwise","sector_identifier_uri":2}),
    ] {
        body["expected_revision"] = original["revision"].clone();
        assert_eq!(
            h.put(&path, &body.to_string()).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let absent = ClientId::generate(&Env::system(), &scope);
    let base = format!(
        "/v1/tenants/{}/environments/{}/clients",
        scope.tenant(),
        scope.environment()
    );
    let mut refusals = Vec::new();
    for id in [
        "invalid".to_owned(),
        absent.to_string(),
        foreign.to_string(),
    ] {
        let (status, _, body) = h
            .put(&format!("{base}/{id}/subject-policy"), "not-json")
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        refusals.push(body);
    }
    assert!(refusals.windows(2).all(|p| p[0] == p[1]));
    assert_eq!(
        h.put_as(&path, "bad-token", "not-json").await.0,
        StatusCode::UNAUTHORIZED
    );
    let unavailable = json!({"subject_type":"pairwise","expected_revision":original["revision"],"sector_identifier_uri":"https://sector.example.test/list"});
    assert_eq!(
        h.put(&path, &unavailable.to_string()).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(read(&h, &path).await, original);
}

#[tokio::test]
async fn management_policy_validates_sector_over_real_tls_and_blocks_private_targets() {
    use ironauth_fetch::{
        FetchLimits, Fetcher, RecordingDialer, StaticResolver, TestTlsIdentity, TestTlsTarget,
    };
    let identity = TestTlsIdentity::generate("sector.example.test");
    let document = TestTlsTarget::start(
        &identity,
        200,
        serde_json::to_vec(&vec!["https://app.example.test/cb"]).unwrap(),
    )
    .await;
    let fetcher = Fetcher::from_parts_trusting(
        FetchLimits::default(),
        Arc::new(StaticResolver::new(vec!["93.184.216.34".parse().unwrap()])),
        Arc::new(RecordingDialer::new(document.addr)),
        &identity.root_der,
    );
    let h = Harness::start_with_sector_fetcher(Arc::new(fetcher)).await;
    let (_, _, path) = fixture(&h, "TLS policy").await;
    let current = read(&h, &path).await;
    let body = json!({"subject_type":"pairwise","expected_revision":current["revision"],"sector_identifier_uri":"https://sector.example.test/list"});
    let (status, _, updated) = h.put(&path, &body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(
        read(&h, &path).await["sector_identifier"],
        "sector.example.test"
    );
    assert_eq!(document.received().len(), 1);
    for address in ["10.0.0.1", "169.254.169.254"] {
        let fetcher = Fetcher::from_parts_trusting(
            FetchLimits::default(),
            Arc::new(StaticResolver::new(vec![address.parse().unwrap()])),
            Arc::new(RecordingDialer::new(document.addr)),
            &identity.root_der,
        );
        let blocked = Harness::start_with_sector_fetcher(Arc::new(fetcher)).await;
        let (_, _, path) = fixture(&blocked, "blocked sector").await;
        let before = read(&blocked, &path).await;
        let body = json!({"subject_type":"pairwise","expected_revision":before["revision"],"sector_identifier_uri":"https://sector.example.test/list"});
        assert_eq!(
            blocked.put(&path, &body.to_string()).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(read(&blocked, &path).await, before);
    }
    assert_eq!(
        document.received().len(),
        1,
        "blocked requests never reach the socket"
    );
}

#[tokio::test]
async fn management_policy_requires_config_permission_and_correct_credential_scope() {
    let h = Harness::start(20).await;
    let (scope, _, path) = fixture(&h, "delegated policy").await;
    let (_, _, foreign_path) = fixture(&h, "foreign credentials").await;
    let token = h
        .create_key(
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
            "policy reader",
            "policy key",
        )
        .await;
    sqlx::query(
        "UPDATE management_credentials SET permissions=$1 WHERE tenant_id=$2 AND environment_id=$3",
    )
    .bind(vec!["management.read"])
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(h.db().owner_pool())
    .await
    .unwrap();
    assert_eq!(h.get_as(&path, &token).await.0, StatusCode::OK);
    assert_eq!(
        h.put_as(&path, &token, "not-json").await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.get_as(&foreign_path, &token).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.put_as(&foreign_path, &token, "not-json").await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn management_policy_requires_fresh_privilege_and_refuses_deleted_scope() {
    let (h, _) = Harness::start_with_sudo(600).await;
    let (scope, _, path) = fixture(&h, "sudo policy").await;
    let original = read(&h, &path).await;
    let request =
        json!({"subject_type":"pairwise","expected_revision":original["revision"]}).to_string();
    let (status, headers, body) = h.put(&path, &request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(headers.contains_key("www-authenticate"));
    assert_eq!(read(&h, &path).await, original);
    sqlx::query("UPDATE environments SET deleted_at=to_timestamp(1) WHERE id=$1 AND tenant_id=$2")
        .bind(scope.environment().to_string())
        .bind(scope.tenant().to_string())
        .execute(h.db().owner_pool())
        .await
        .unwrap();
    assert_eq!(h.get(&path).await.0, StatusCode::NOT_FOUND);
}
