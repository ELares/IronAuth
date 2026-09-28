// SPDX-License-Identifier: MIT OR Apache-2.0

//! FAPI admission and request enforcement through the real router and database.
//! Hardened fixtures enter through normal control-plane admission with only a
//! conformant private-key client. Each refusal has a successful counterpart.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::fapi::Fixture;
use common::{REDIRECT_URI, json};

#[tokio::test]
async fn a_non_par_authorization_request_is_refused_only_under_hardened_mode() {
    for hardened in [false, true] {
        let fixture = Fixture::start(hardened).await;
        let headers = fixture.authorize(&fixture.query(true)).await;
        if hardened {
            assert_eq!(
                common::location_param(&headers, "error").as_deref(),
                Some("invalid_request_object")
            );
            let forged = format!("{}&par_resume=1", fixture.query(true));
            let headers = fixture.authorize(&forged).await;
            assert_eq!(
                common::location_param(&headers, "error").as_deref(),
                Some("invalid_request_object")
            );
            let query = fixture.pushed_query(true, "valid-par").await;
            let headers = fixture.authorize(&query).await;
            assert!(
                common::location_param(&headers, "code").is_some(),
                "{headers:?}"
            );
        } else {
            assert!(
                common::location_param(&headers, "code").is_some(),
                "{headers:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_pkce_less_request_is_refused_only_under_hardened_mode() {
    for hardened in [false, true] {
        let fixture = Fixture::start(hardened).await;
        let query = fixture.pushed_query(false, "without-pkce").await;
        let headers = fixture.authorize(&query).await;
        if hardened {
            assert_eq!(
                common::location_param(&headers, "error").as_deref(),
                Some("invalid_request")
            );
            let query = fixture.pushed_query(true, "with-pkce").await;
            let headers = fixture.authorize(&query).await;
            assert!(
                common::location_param(&headers, "code").is_some(),
                "{headers:?}"
            );
        } else {
            assert!(
                common::location_param(&headers, "code").is_some(),
                "{headers:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_bearer_code_exchange_is_refused_only_under_hardened_mode() {
    for hardened in [false, true] {
        let fixture = Fixture::start(hardened).await;
        let query = fixture.pushed_query(true, "exchange-par").await;
        let headers = fixture.authorize(&query).await;
        let code = common::location_param(&headers, "code").expect("authorization code");
        let (status, body) = fixture.exchange(&code, "bearer-exchange", false).await;
        if hardened {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(json(&body)["error"], "invalid_grant");
            // Rejection must not consume the code: a conformant retry succeeds.
            let (status, body) = fixture.exchange(&code, "bound-exchange", true).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(json(&body)["token_type"], "DPoP");
        } else {
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(json(&body)["token_type"], "Bearer");
        }
    }
}

#[tokio::test]
async fn public_client_registration_is_refused_only_under_hardened_mode() {
    for hardened in [false, true] {
        let fixture = Fixture::start(hardened).await;
        let request = Request::builder().method("POST")
            .uri(format!("/t/{}/e/{}/connect/register", fixture.harness.scope().tenant(), fixture.harness.scope().environment()))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"}).to_string()))
            .expect("registration request");
        let (status, _, body) = fixture.harness.send(request).await;
        if hardened {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(json(&body)["error"], "invalid_client_metadata");
            assert!(
                json(&body)["error_description"]
                    .as_str()
                    .expect("description")
                    .contains("none"),
                "{body}"
            );
        } else {
            assert_eq!(status, StatusCode::CREATED, "{body}");
            assert_eq!(json(&body)["token_endpoint_auth_method"], "none");
        }
    }
}
