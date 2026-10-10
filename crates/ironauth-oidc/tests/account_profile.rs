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
