// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real-store checks for subject-bound display names, never seeded profile writes
//! in place of the HTTP update being qualified.
mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::Harness;
use serde_json::{Value, json};

fn path(h: &Harness) -> String {
    format!(
        "/t/{}/e/{}/account/profile",
        h.scope().tenant(),
        h.scope().environment()
    )
}
async fn get(h: &Harness, cookie: Option<&str>) -> (StatusCode, Value) {
    let mut r = Request::builder().uri(path(h));
    if let Some(cookie) = cookie {
        r = r.header(header::COOKIE, cookie);
    }
    let (s, headers, b) = h.send(r.body(Body::empty()).unwrap()).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    (s, serde_json::from_str(&b).unwrap())
}
async fn post(h: &Harness, cookie: Option<&str>, origin: Option<&str>, body: Value) -> StatusCode {
    let mut r = Request::builder()
        .method("POST")
        .uri(path(h))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        r = r.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        r = r.header(header::ORIGIN, origin);
    }
    h.send(r.body(Body::from(body.to_string())).unwrap())
        .await
        .0
}

#[tokio::test]
async fn own_name_is_optional_persisted_and_conflict_aware_without_changing_other_claims() {
    let h = Harness::start().await;
    let subject=h.seed_user_with_claims("name-owner@example.test",common::SEED_PASSWORD,
        r#"{"email":"verified@example.test","email_verified":true,"given_name":"Original","custom":{"keep":1}}"#).await;
    let cookie = h.session_cookie(&subject).await;
    assert_eq!(
        get(&h, Some(&cookie)).await,
        (StatusCode::OK, json!({"name":""}))
    );
    let update = json!({"expected_name":"","name":"Alex Rivera"});
    assert_eq!(
        post(&h, Some(&cookie), Some(common::ISSUER_BASE), update.clone()).await,
        StatusCode::OK
    );
    assert_eq!(
        post(&h, Some(&cookie), Some(common::ISSUER_BASE), update).await,
        StatusCode::OK
    );
    let second_cookie = h.session_cookie(&subject).await;
    assert_eq!(
        get(&h, Some(&second_cookie)).await.1,
        json!({"name":"Alex Rivera"})
    );
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"Stale edit"})
        )
        .await,
        StatusCode::CONFLICT
    );
    let claims: Value = serde_json::from_str(
        &h.store()
            .scoped(h.scope())
            .users()
            .claims_for_subject(&subject)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        claims,
        json!({"name":"Alex Rivera","email":"verified@example.test","email_verified":true,"given_name":"Original","custom":{"keep":1}})
    );
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"Alex Rivera","name":""})
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(get(&h, Some(&cookie)).await.1, json!({"name":""}));
    let events: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM outbox_messages WHERE payload->>'type'='user.updated'",
    )
    .fetch_all(h.db().owner_pool())
    .await
    .unwrap();
    assert_eq!(
        events.len(),
        2,
        "one event for setting and one for clearing, none for replay or conflict"
    );
    for event in events {
        ironauth_store::event_catalog::validate_event(&event).unwrap();
        assert_eq!(
            event["payload"],
            json!({"user_id":subject,"fields":["claims"]})
        );
    }
    let rows = h.audit_rows_for_action("user.update").await;
    assert_eq!(
        rows.len(),
        3,
        "only three accepted HTTP writes have audit records"
    );
}

#[tokio::test]
async fn name_api_refuses_unauthenticated_cross_origin_forged_and_invalid_input() {
    let h = Harness::start().await;
    let subject = h
        .seed_user("name-only@example.test", common::SEED_PASSWORD)
        .await;
    let other = h
        .seed_user("other-name@example.test", common::SEED_PASSWORD)
        .await;
    let cookie = h.session_cookie(&subject).await;
    let update = json!({"expected_name":"","name":"Alex"});
    assert_eq!(get(&h, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        post(&h, None, Some(common::ISSUER_BASE), update.clone()).await,
        StatusCode::UNAUTHORIZED
    );
    for origin in [None, Some("https://untrusted.test"), Some("null")] {
        assert_eq!(
            post(&h, Some(&cookie), origin, update.clone()).await,
            StatusCode::FORBIDDEN
        );
    }
    for extra in ["subject", "email_verified", "role"] {
        let mut forged = update.clone();
        forged[extra] = json!(other);
        assert_eq!(
            post(&h, Some(&cookie), Some(common::ISSUER_BASE), forged).await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    for name in [" ".to_owned(), "a\nb".to_owned(), "x".repeat(81)] {
        assert_eq!(
            post(
                &h,
                Some(&cookie),
                Some(common::ISSUER_BASE),
                json!({"expected_name":"","name":name})
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(get(&h, Some(&cookie)).await.1, json!({"name":""}));
    assert_eq!(
        get(&h, Some(&h.session_cookie(&other).await)).await.1,
        json!({"name":""})
    );
    assert!(h.audit_rows_for_action("user.update").await.is_empty());
    let id = ironauth_store::UserId::parse_in_scope(&other, &h.scope()).unwrap();
    let caller = ironauth_store::UserId::parse_in_scope(&subject, &h.scope()).unwrap();
    let actor = ironauth_store::ActorRef::human(ironauth_store::HumanId::from_seed_bytes(
        caller.unique_bytes(),
    ));
    let denied = h
        .store()
        .scoped(h.scope())
        .acting(actor, ironauth_store::CorrelationId::generate(h.env()))
        .users()
        .set_own_display_name(h.env(), &id, "", "Forged")
        .await;
    assert!(matches!(denied, Err(ironauth_store::StoreError::NotFound)));
}

#[tokio::test]
async fn concurrent_different_names_cannot_silently_overwrite_each_other() {
    let h = Harness::start().await;
    let subject = h
        .seed_user("concurrent-name@example.test", common::SEED_PASSWORD)
        .await;
    let cookie = h.session_cookie(&subject).await;
    let (a, b) = tokio::join!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"First"})
        ),
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"Second"})
        )
    );
    assert!(
        (a == StatusCode::OK && b == StatusCode::CONFLICT)
            || (b == StatusCode::OK && a == StatusCode::CONFLICT)
    );
    assert_eq!(h.audit_rows_for_action("user.update").await.len(), 1);
    let expected = if a == StatusCode::OK {
        "First"
    } else {
        "Second"
    };
    assert_eq!(get(&h, Some(&cookie)).await.1, json!({"name":expected}));
}

#[tokio::test]
async fn hosted_settings_escape_names_and_refuse_foreign_return_targets() {
    let h = Harness::start().await;
    let subject = h
        .seed_user("hosted-name@example.test", common::SEED_PASSWORD)
        .await;
    let cookie = h.session_cookie(&subject).await;
    let name = "<script>alert(1)</script>";
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":name})
        )
        .await,
        StatusCode::OK
    );
    let page = format!(
        "/t/{}/e/{}/profile",
        h.scope().tenant(),
        h.scope().environment()
    );
    let (status, headers, body) = h
        .send(
            Request::builder()
                .uri(&page)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!body.contains(name));
    assert!(body.contains("Save name"));
    let bad = format!(
        "{page}?return_to={}",
        common::enc("https://untrusted.test/")
    );
    let (status, _, _) = h
        .send(
            Request::builder()
                .uri(bad)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = h
        .send(Request::builder().uri(page).body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn edited_label_reaches_userinfo_only_with_profile_access_and_preserves_subject() {
    use base64::Engine as _;
    let h = Harness::start().await;
    let subject = h
        .seed_user("userinfo-name@example.test", common::SEED_PASSWORD)
        .await;
    let cookie = h.session_cookie(&subject).await;
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"Alex Rivera"})
        )
        .await,
        StatusCode::OK
    );
    let client = h.client_id().to_string();
    h.grant_consent(&subject, &client).await;
    for scope in ["openid", "openid profile"] {
        let query = format!(
            "response_type=code&client_id={client}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256",
            common::enc(common::REDIRECT_URI),
            common::enc(scope),
            common::PKCE_CHALLENGE
        );
        let (status, headers, _) = h.authorize_with_cookie(&query, &cookie).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let code = common::location_param(&headers, "code").unwrap();
        let exchange = common::form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", common::REDIRECT_URI),
            ("client_id", &client),
            ("code_verifier", common::PKCE_VERIFIER),
        ]);
        let (status, _, wire) = h.token(&exchange).await;
        assert_eq!(status, StatusCode::OK);
        let tokens: Value = serde_json::from_str(&wire).unwrap();
        let encoded = tokens["id_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        let claims: Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap();
        let (status, _, body) = h
            .send(
                Request::builder()
                    .uri("/userinfo")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", tokens["access_token"].as_str().unwrap()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let info: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(info["sub"], claims["sub"]);
        assert_eq!(info["sub"], subject);
        if scope == "openid profile" {
            assert_eq!(info["name"], "Alex Rivera");
        } else {
            assert!(info.get("name").is_none());
        }
        assert!(info.get("email").is_none());
        assert!(info.get("email_verified").is_none());
    }
}

#[tokio::test]
async fn failed_event_commit_rolls_back_name_and_audit() {
    let h = Harness::start().await;
    let subject = h
        .seed_user("atomic-name@example.test", common::SEED_PASSWORD)
        .await;
    let cookie = h.session_cookie(&subject).await;
    sqlx::raw_sql("CREATE FUNCTION reject_profile_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.payload->>'type'='user.updated' THEN RAISE EXCEPTION 'fixture'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_profile_event BEFORE INSERT ON outbox_messages FOR EACH ROW EXECUTE FUNCTION reject_profile_event();")
        .execute(h.db().owner_pool()).await.unwrap();
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"Not committed"})
        )
        .await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(get(&h, Some(&cookie)).await.1, json!({"name":""}));
    assert!(h.audit_rows_for_action("user.update").await.is_empty());
    sqlx::raw_sql("DROP TRIGGER reject_profile_event ON outbox_messages; DROP FUNCTION reject_profile_event();").execute(h.db().owner_pool()).await.unwrap();
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"Not committed"})
        )
        .await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn removed_account_and_foreign_scope_cannot_read_or_change_the_label() {
    let h = Harness::start().await;
    let other = Harness::start().await;
    let subject = h
        .seed_user("disabled-name@example.test", common::SEED_PASSWORD)
        .await;
    let cookie = h.session_cookie(&subject).await;
    assert_eq!(get(&other, Some(&cookie)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        post(
            &other,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"No"})
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    h.set_user_state(&subject, ironauth_store::UserState::Disabled)
        .await;
    assert_eq!(get(&h, Some(&cookie)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"No"})
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert!(h.audit_rows_for_action("user.update").await.is_empty());
}

#[tokio::test]
async fn impersonation_cannot_read_or_write_the_name_or_open_the_editor() {
    let h = Harness::start().await;
    let subject = h
        .seed_user("profile-support@example.test", common::SEED_PASSWORD)
        .await;
    let (session, cookie) = h.session_with_id(&subject, "pwd", 0).await;
    assert_eq!(get(&h, Some(&cookie)).await.0, StatusCode::OK);
    let changed = sqlx::query(
        "UPDATE sessions SET impersonator='adm_support_engineer', \
         impersonation_reason_code='support_ticket', impersonation_reason_text='Profile test', \
         impersonation_started_at=now(), impersonation_expires_at=now()+INTERVAL '30 minutes' \
         WHERE id=$1",
    )
    .bind(session.to_string())
    .execute(h.db().owner_pool())
    .await
    .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    assert_eq!(get(&h, Some(&cookie)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        post(
            &h,
            Some(&cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":"","name":"Support edit"})
        )
        .await,
        StatusCode::FORBIDDEN
    );
    let (status, _, body) = h
        .send(
            Request::builder()
                .uri(format!(
                    "/t/{}/e/{}/profile",
                    h.scope().tenant(),
                    h.scope().environment()
                ))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!body.contains("id=\"profile-form\""));
    assert!(h.audit_rows_for_action("user.update").await.is_empty());
}

#[tokio::test]
async fn equal_names_keep_distinct_subjects_and_independent_profiles() {
    let h = Harness::start().await;
    let first = h
        .seed_user("first-label@example.test", common::SEED_PASSWORD)
        .await;
    let second = h
        .seed_user("second-label@example.test", common::SEED_PASSWORD)
        .await;
    assert_ne!(first, second);
    let first_cookie = h.session_cookie(&first).await;
    let second_cookie = h.session_cookie(&second).await;
    let label = "\u{1f338}".repeat(80);
    for cookie in [&first_cookie, &second_cookie] {
        assert_eq!(
            post(
                &h,
                Some(cookie),
                Some(common::ISSUER_BASE),
                json!({"expected_name":"","name":label})
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(get(&h, Some(cookie)).await.1, json!({"name":label}));
    }
    assert_eq!(
        post(
            &h,
            Some(&first_cookie),
            Some(common::ISSUER_BASE),
            json!({"expected_name":label,"name":""})
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(get(&h, Some(&first_cookie)).await.1, json!({"name":""}));
    assert_eq!(get(&h, Some(&second_cookie)).await.1, json!({"name":label}));
    let query = format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile&code_challenge={}&code_challenge_method=S256",
        h.client_id(),
        common::enc(common::REDIRECT_URI),
        common::PKCE_CHALLENGE
    );
    let consent = format!("/consent?return_to={}", common::enc(&query));
    let (status, _, body) = h.get_with_cookie(&consent, Some(&second_cookie)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Edit your display name"));
    assert!(body.contains(&format!(
        "/t/{}/e/{}/profile?return_to=",
        h.scope().tenant(),
        h.scope().environment()
    )));
}
