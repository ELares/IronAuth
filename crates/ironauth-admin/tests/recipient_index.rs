// SPDX-License-Identifier: MIT OR Apache-2.0

//! Actual management HTTP and Postgres qualification for legacy index preparation.
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, OPERATOR_TOKEN};
use serde_json::Value;

const APPLY: &str = r#"{"limit":1,"all_writers_upgraded":true}"#;

async fn fixture(h: &Harness) -> (String, String, String) {
    let (tenant, environment) = h.create_tenant("legacy-index", "tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    for n in 0..3 {
        let (status, _, _) = h
            .post(
                &format!("{base}/users"),
                &format!("user-{n}"),
                &serde_json::json!({"identifier":format!("person-{n}@example.test")}).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    sqlx::query("UPDATE users SET recipient_email_indexed = false, recipient_email_bidx = NULL WHERE tenant_id = $1 AND environment_id = $2")
        .bind(&tenant).bind(&environment).execute(h.db().owner_pool()).await.expect("legacy fixture");
    (
        tenant,
        environment,
        format!("{base}/recipient-verification/index"),
    )
}

async fn audits(h: &Harness) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'recipient_verification.index_backfill'",
    )
    .fetch_one(h.db().owner_pool())
    .await
    .expect("audit count")
}

async fn events(h: &Harness) -> Vec<Value> {
    sqlx::query_scalar(
        "SELECT payload FROM outbox_messages WHERE payload->>'type' = 'recipient_index.prepared'",
    )
    .fetch_all(h.db().owner_pool())
    .await
    .expect("committed recipient events")
}

#[tokio::test]
async fn preview_and_concurrent_replay_advance_once_and_deleted_environment_cannot_replay() {
    let h = Harness::start(50).await;
    let (tenant, environment, path) = fixture(&h).await;
    let (status, _, body) = h.get(&format!("{path}?limit=1")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let preview: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(preview["applied"], false);
    assert_eq!(preview["batch_users"], 1);
    assert_eq!(preview["unindexed_users"], 3);
    assert_eq!(audits(&h).await, 0);
    assert!(events(&h).await.is_empty());
    let (a, b) = tokio::join!(
        h.post(&path, "batch-1", APPLY),
        h.post(&path, "batch-1", APPLY)
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.2);
    assert_eq!(b.0, StatusCode::OK, "{}", b.2);
    assert_eq!(a.2, b.2);
    assert!(a.1.contains_key("ratelimit"));
    let applied: Value = serde_json::from_str(&a.2).unwrap();
    assert_eq!(applied["applied"], true);
    assert_eq!(applied["unindexed_users"], 2);
    assert_eq!(audits(&h).await, 1);
    let emitted = events(&h).await;
    assert_eq!(emitted.len(), 1, "concurrent replay emits exactly once");
    assert_eq!(emitted[0]["payload"], applied);
    assert_eq!(emitted[0]["tenant_id"], tenant);
    assert_eq!(emitted[0]["environment_id"], environment);
    ironauth_store::event_catalog::validate_event(&emitted[0]).expect("registered event contract");
    let (_, _, actual) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&actual).unwrap()["unindexed_users"],
        2
    );
    let (status, _, _) = h
        .post(
            &path,
            "batch-1",
            r#"{"limit":2,"all_writers_upgraded":true}"#,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _, body) = h
        .post_with_headers(
            "POST",
            &path,
            "batch-2",
            APPLY,
            &[("x-ironauth-entry-path", "mcp")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["unindexed_users"],
        1
    );
    assert_eq!(audits(&h).await, 2);
    assert_eq!(events(&h).await.len(), 2);
    let entries: Vec<Option<String>> = sqlx::query_scalar("SELECT entry_path FROM audit_log WHERE action = 'recipient_verification.index_backfill' ORDER BY occurred_at, id")
        .fetch_all(h.db().owner_pool()).await.expect("stored entry path");
    assert_eq!(entries, vec![None, Some("mcp".to_owned())]);
    let (status, _, body) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(
        h.post(&path, "batch-1", APPLY).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(h.get(&path).await.0, StatusCode::OK);
    assert_eq!(audits(&h).await, 2);
    assert_eq!(events(&h).await.len(), 2);
}

#[tokio::test]
async fn malformed_or_unacknowledged_batches_and_anonymous_requests_do_not_write() {
    let h = Harness::start(50).await;
    let (_, _, path) = fixture(&h).await;
    for body in [
        "{}",
        r#"{"all_writers_upgraded":false}"#,
        r#"{"all_writers_upgraded":true,"limit":0}"#,
        r#"{"all_writers_upgraded":true,"limit":101}"#,
        r#"{"all_writers_upgraded":true,"email":"other@example.test"}"#,
    ] {
        assert_eq!(
            h.post(&path, "invalid", body).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    for suffix in [
        "?limit=0",
        "?limit=101",
        "?limit=1&limit=2",
        "?unknown=true",
    ] {
        assert_eq!(
            h.get(&format!("{path}{suffix}")).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        h.post(&format!("{path}?limit=1"), "query", APPLY).await.0,
        StatusCode::BAD_REQUEST
    );
    let request = Request::builder()
        .method("POST")
        .uri(&path)
        .header("authorization", common::bearer(OPERATOR_TOKEN))
        .header("content-type", "application/json")
        .body(Body::from(APPLY))
        .unwrap();
    assert_eq!(h.send(request).await.0, StatusCode::BAD_REQUEST);
    for method in ["GET", "POST"] {
        let request = Request::builder()
            .method(method)
            .uri(&path)
            .header("idempotency-key", "anonymous")
            .header("content-type", "application/json")
            .body(Body::from(APPLY))
            .unwrap();
        assert_eq!(h.send(request).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(audits(&h).await, 0);
    assert!(events(&h).await.is_empty());
}

#[tokio::test]
async fn scoped_key_needs_current_permission_even_to_replay_and_cannot_cross_environments() {
    let h = Harness::start(50).await;
    let (tenant, environment, path) = fixture(&h).await;
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/keys"),
            "key",
            r#"{"display_name":"index operator"}"#,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "key creation");
    let key: Value = serde_json::from_str(&body).unwrap();
    let id = key["id"].as_str().unwrap();
    let token = key["secret"].as_str().unwrap();
    assert_eq!(
        h.post_as(&path, token, "first", APPLY).await.0,
        StatusCode::OK
    );
    sqlx::query("UPDATE management_credentials SET permissions = $1 WHERE id = $2")
        .bind(vec!["management.read"])
        .bind(id)
        .execute(h.db().owner_pool())
        .await
        .expect("restrict fixture");
    assert_eq!(h.get_as(&path, token).await.0, StatusCode::OK);
    let (status, _, denied) = h.post_as(&path, token, "first", APPLY).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(denied.contains("management.write_users"));
    assert_eq!(
        h.post_as(&path, token, "next", APPLY).await.0,
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE management_credentials SET permissions = $1 WHERE id = $2")
        .bind(vec!["management.write_users"])
        .bind(id)
        .execute(h.db().owner_pool())
        .await
        .expect("write only fixture");
    let (status, _, denied) = h.get_as(&path, token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(denied.contains("management.read"));
    assert_eq!(
        h.post_as(&path, token, "write-only", APPLY).await.0,
        StatusCode::OK
    );
    let (other_tenant, other_environment) = h.create_tenant("other", "other-tenant").await;
    let other = format!(
        "/v1/tenants/{other_tenant}/environments/{other_environment}/recipient-verification/index"
    );
    assert_eq!(
        h.post_as(&other, token, "foreign", APPLY).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/organizations"),
            "confined-org",
            r#"{"display_name":"Confined organization"}"#,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let org: Value = serde_json::from_str(&body).unwrap();
    sqlx::query(
        "UPDATE management_credentials SET organization_id = $1, permissions = $2 WHERE id = $3",
    )
    .bind(org["id"].as_str().unwrap())
    .bind(vec!["management.read", "management.write_users"])
    .bind(id)
    .execute(h.db().owner_pool())
    .await
    .expect("confined key fixture");
    assert_eq!(h.get_as(&path, token).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        h.post_as(&path, token, "first", APPLY).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.post_as(&path, token, "confined", APPLY).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(audits(&h).await, 2);
    assert_eq!(events(&h).await.len(), 2);
}

#[tokio::test]
async fn stale_privilege_cannot_replay_a_preparation_receipt() {
    let (h, clock) = Harness::start_with_sudo(60).await;
    let (tenant, environment) = h.create_tenant("sudo-index", "tenant").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let path = format!("{base}/recipient-verification/index");
    assert_eq!(
        h.post(&path, "batch", APPLY).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.post(&format!("{base}/admin/sudo/elevate"), "elevate", "{}")
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(h.post(&path, "batch", APPLY).await.0, StatusCode::OK);
    clock.advance(std::time::Duration::from_secs(61));
    let (status, _, body) = h.post(&path, "batch", APPLY).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("insufficient_user_authentication"));
    assert_eq!(audits(&h).await, 1);
}

#[tokio::test]
async fn audit_failure_rolls_back_indices_and_receipt_so_the_same_key_can_retry() {
    let h = Harness::start(50).await;
    let (_, _, path) = fixture(&h).await;
    sqlx::raw_sql(
        "CREATE FUNCTION reject_recipient_index_audit() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.action = 'recipient_verification.index_backfill' THEN \
         RAISE EXCEPTION 'synthetic audit persistence failure'; END IF; RETURN NEW; END $$; \
         CREATE TRIGGER reject_recipient_index_audit BEFORE INSERT ON audit_log \
         FOR EACH ROW EXECUTE FUNCTION reject_recipient_index_audit();",
    )
    .execute(h.db().owner_pool())
    .await
    .expect("audit failure fixture");
    let (status, _, _) = h.post(&path, "retry-after-failure", APPLY).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(audits(&h).await, 0);
    assert!(events(&h).await.is_empty());
    let (status, _, preview) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&preview).unwrap()["unindexed_users"],
        3
    );
    sqlx::raw_sql("DROP TRIGGER reject_recipient_index_audit ON audit_log; DROP FUNCTION reject_recipient_index_audit();")
        .execute(h.db().owner_pool()).await.expect("restore fixture persistence");
    let (status, _, body) = h.post(&path, "retry-after-failure", APPLY).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["unindexed_users"],
        2
    );
    assert_eq!(audits(&h).await, 1);
    assert_eq!(events(&h).await.len(), 1);
}

#[tokio::test]
async fn event_failure_rolls_back_indices_audit_and_receipt() {
    let h = Harness::start(50).await;
    let (_, _, path) = fixture(&h).await;
    sqlx::raw_sql(
        "CREATE FUNCTION reject_recipient_index_event() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.payload->>'type' = 'recipient_index.prepared' THEN \
         RAISE EXCEPTION 'synthetic event persistence failure'; END IF; RETURN NEW; END $$; \
         CREATE TRIGGER reject_recipient_index_event BEFORE INSERT ON outbox_messages \
         FOR EACH ROW EXECUTE FUNCTION reject_recipient_index_event();",
    )
    .execute(h.db().owner_pool())
    .await
    .expect("event failure fixture");
    assert_eq!(
        h.post(&path, "event-retry", APPLY).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(audits(&h).await, 0);
    assert!(events(&h).await.is_empty());
    let (_, _, preview) = h.get(&path).await;
    assert_eq!(
        serde_json::from_str::<Value>(&preview).unwrap()["unindexed_users"],
        3
    );
    sqlx::raw_sql("DROP TRIGGER reject_recipient_index_event ON outbox_messages; DROP FUNCTION reject_recipient_index_event();")
        .execute(h.db().owner_pool()).await.expect("restore event persistence");
    let (status, _, body) = h.post(&path, "event-retry", APPLY).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["unindexed_users"],
        2
    );
    assert_eq!(audits(&h).await, 1);
    assert_eq!(events(&h).await.len(), 1);
}
