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

async fn history_fixture(h: &Harness) -> (Scope, ClientId, String, Vec<ironauth_store::UserId>) {
    let (scope, client, policy_path) = fixture(h, "history workflow").await;
    sqlx::query("UPDATE clients SET subject_history_ready=false WHERE id=$1")
        .bind(client.to_string())
        .execute(h.db().owner_pool())
        .await
        .unwrap();
    let env = Env::system();
    let acting = h.store().scoped(scope).acting(
        ironauth_admin::bootstrap_operator_actor(),
        CorrelationId::generate(&env),
    );
    let mut users = Vec::new();
    for i in 0..3 {
        let user = acting
            .users()
            .register(&env, &format!("history-{i}@example.test"), "hash", None)
            .await
            .unwrap();
        if i < 2 {
            sqlx::query("INSERT INTO grants (id,tenant_id,environment_id,client_id,subject,revoked_at) VALUES ($1,$2,$3,$4,$5,'2020-01-01Z')")
                .bind(ironauth_store::GrantId::generate(&env,&scope).to_string()).bind(scope.tenant().to_string())
                .bind(scope.environment().to_string()).bind(client.to_string()).bind(user.to_string())
                .execute(h.db().owner_pool()).await.unwrap();
        }
        users.push(user);
    }
    (
        scope,
        client,
        policy_path.replace("/subject-policy", "/subject-history"),
        users,
    )
}

fn reconciliation_request(revision: &Value) -> Value {
    json!({"expected_revision":revision, "evidence_sha256":"a".repeat(64),
        "legacy_issuers_stopped":true,"external_history_reconciled":true,"public_identifiers_retained":true})
}

// One ordered operator journey: every request consumes the state from the previous step.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn history_api_recovers_pages_and_roster_then_unlocks_a_separate_policy_change() {
    let h = Harness::start(20).await;
    let (scope, client, path, users) = history_fixture(&h).await;
    let initial = read(&h, &path).await;
    assert_eq!(initial["missing_bindings"], 2);
    assert_eq!(initial["history_ready"], false);
    let revision = &initial["revision"];
    let complete = reconciliation_request(revision).to_string();
    assert_eq!(
        h.put(&format!("{path}/reconciliation"), &complete).await.0,
        StatusCode::CONFLICT
    );
    let request = json!({"expected_revision":revision,"limit":1}).to_string();
    let (status, headers, body) = h.put(&format!("{path}/backfill"), &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    common::assert_rate_limit_headers(&headers);
    let page: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(page["scanned"], 1);
    assert_eq!(page["inserted"], 1);
    let cursor = page["next_cursor"].as_str().unwrap();
    let retry: Value =
        serde_json::from_str(&h.put(&format!("{path}/backfill"), &request).await.2).unwrap();
    assert_eq!(retry["inserted"], 0);
    assert_eq!(retry["next_cursor"], cursor);
    assert_eq!(
        h.put(&format!("{path}/reconciliation"), &complete).await.0,
        StatusCode::CONFLICT
    );
    let (_, _, other) = fixture(&h, "cursor target").await;
    let other_revision = read(&h, &other).await["revision"].clone();
    assert_eq!(
        h.put(
            &other.replace("/subject-policy", "/subject-history/backfill"),
            &json!({"expected_revision":other_revision,"cursor":cursor}).to_string()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let request = json!({"expected_revision":revision,"limit":1,"cursor":cursor}).to_string();
    let (status, _, body) = h.put(&format!("{path}/backfill"), &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(serde_json::from_str::<Value>(&body).unwrap()["next_cursor"].is_null());
    let roster=json!({"expected_revision":revision,"user_ids":[users[2].to_string(),users[2].to_string()]}).to_string();
    for inserted in [1, 0] {
        let (status, _, body) = h.put(&format!("{path}/bindings"), &roster).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["inserted"],
            inserted
        );
    }
    let covered = read(&h, &path).await;
    assert_eq!(covered["missing_bindings"], 0);
    assert_eq!(
        covered["history_ready"], false,
        "coverage never replaces attestation"
    );
    let mut incomplete = reconciliation_request(revision);
    incomplete["external_history_reconciled"] = json!(false);
    assert_eq!(
        h.put(&format!("{path}/reconciliation"), &incomplete.to_string())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, _, body) = h.put(&format!("{path}/reconciliation"), &complete).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let receipt: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(receipt["history_ready"], true);
    assert_eq!(receipt["evidence_sha256"], "a".repeat(64));
    assert!(!receipt["reconciled_at_unix_micros"].is_null());
    assert_eq!(read(&h, &path).await, receipt);
    assert_eq!(
        h.put(&format!("{path}/reconciliation"), &complete).await.0,
        StatusCode::CONFLICT
    );
    let policy_path = path.replace("/subject-history", "/subject-policy");
    assert_eq!(read(&h, &policy_path).await["subject_type"], "public");
    assert_eq!(
        h.put(
            &policy_path,
            &json!({"expected_revision":receipt["revision"],"subject_type":"pairwise"}).to_string()
        )
        .await
        .0,
        StatusCode::OK
    );
    for user in users {
        assert_eq!(
            h.store()
                .scoped(scope)
                .clients()
                .subject_binding(&client, &user)
                .await
                .unwrap(),
            Some(user.to_string())
        );
    }
    assert_eq!(
        h.control_store()
            .scoped(scope)
            .audit()
            .list()
            .await
            .unwrap()
            .iter()
            .filter(|a| a.action == "client.subject_history.reconcile")
            .count(),
        1
    );
}

#[tokio::test]
async fn history_api_enforces_permissions_scope_and_sudo_before_reading_bodies() {
    let h = Harness::start(20).await;
    let (scope, _, path, _) = history_fixture(&h).await;
    let (_, _, foreign) = fixture(&h, "other history scope").await;
    let foreign = foreign.replace("/subject-policy", "/subject-history");
    let token = h
        .create_key(
            &scope.tenant().to_string(),
            &scope.environment().to_string(),
            "history reader",
            "history key",
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
    assert_eq!(h.get_as(&foreign, &token).await.0, StatusCode::FORBIDDEN);
    for suffix in ["backfill", "bindings", "reconciliation"] {
        assert_eq!(
            h.put_as(&format!("{path}/{suffix}"), &token, "not-json")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            h.put_as(&format!("{foreign}/{suffix}"), &token, "not-json")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            h.put_as(&format!("{path}/{suffix}"), "invalid", "not-json")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    sqlx::query("UPDATE environments SET deleted_at='2020-01-01Z' WHERE id=$1")
        .bind(scope.environment().to_string())
        .execute(h.db().owner_pool())
        .await
        .unwrap();
    for suffix in ["backfill", "bindings", "reconciliation"] {
        assert_eq!(
            h.put(&format!("{path}/{suffix}"), "not-json").await.0,
            StatusCode::NOT_FOUND
        );
    }
    let (sudo, _) = Harness::start_with_sudo(600).await;
    let (scope, _, path, _) = history_fixture(&sudo).await;
    for suffix in ["backfill", "bindings", "reconciliation"] {
        let (status, headers, _) = sudo.put(&format!("{path}/{suffix}"), "not-json").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.contains_key("www-authenticate"));
    }
    sqlx::query("UPDATE environments SET deleted_at='2020-01-01Z' WHERE id=$1")
        .bind(scope.environment().to_string())
        .execute(sudo.db().owner_pool())
        .await
        .unwrap();
    assert_eq!(sudo.get(&path).await.0, StatusCode::NOT_FOUND);
    for suffix in ["backfill", "bindings", "reconciliation"] {
        assert_eq!(
            sudo.put(&format!("{path}/{suffix}"), "not-json").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn history_api_refuses_invalid_batches_cursors_and_stale_revision_without_partial_import() {
    let h = Harness::start(20).await;
    let (scope, client, path, users) = history_fixture(&h).await;
    let revision = read(&h, &path).await["revision"].clone();
    for request in [
        json!({"expected_revision":revision,"limit":0}),
        json!({"expected_revision":revision,"cursor":"bad"}),
        json!({"expected_revision":-1}),
    ] {
        let status = h
            .put(&format!("{path}/backfill"), &request.to_string())
            .await
            .0;
        assert!(matches!(
            status,
            StatusCode::BAD_REQUEST | StatusCode::CONFLICT
        ));
    }
    for ids in [vec![], vec![users[0].to_string(); 501]] {
        assert_eq!(
            h.put(
                &format!("{path}/bindings"),
                &json!({"expected_revision":revision,"user_ids":ids}).to_string()
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let unknown = ironauth_store::UserId::generate(&Env::system(), &scope);
    assert_eq!(h.put(&format!("{path}/bindings"),&json!({"expected_revision":revision,"user_ids":[users[0].to_string(),unknown.to_string()]}).to_string()).await.0,StatusCode::NOT_FOUND);
    assert_eq!(
        h.store()
            .scoped(scope)
            .clients()
            .subject_binding(&client, &users[0])
            .await
            .unwrap(),
        None
    );
    let mut request = reconciliation_request(&revision);
    request["evidence_sha256"] = json!("not-a-digest");
    assert_eq!(
        h.put(&format!("{path}/reconciliation"), &request.to_string())
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}
