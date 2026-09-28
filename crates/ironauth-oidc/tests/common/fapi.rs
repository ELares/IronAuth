// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformant FAPI client fixture shared by hardened-flow and introspection tests.

use super::{Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, form, json};
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ironauth_config::{OidcConfig, RegistrationMode};
use ironauth_jose::dpop_test_util::sign_proof;
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::{ClientAuthMethod, JWT_BEARER_ASSERTION_TYPE};

pub struct Fixture {
    pub harness: Harness,
    pub client: String,
    key: SigningKey,
    cookie: String,
}

impl Fixture {
    pub async fn start(hardened: bool) -> Self {
        let mut harness = Harness::start_with(OidcConfig {
            registration_enabled: true,
            registration_mode: RegistrationMode::Open,
            require_pkce_for_confidential_clients: false,
            ..OidcConfig::default()
        })
        .await;
        let key = SigningKey::ed25519_from_seed(Some("fapi-client".to_owned()), &[9; 32])
            .expect("client key");
        let jwks = JwkSet::from_signing_keys([&key])
            .expect("public keys")
            .to_json()
            .expect("public key JSON");
        let client = harness
            .create_jwt_auth_client(
                ClientAuthMethod::PrivateKeyJwt,
                Some(&jwks),
                None,
                Some("EdDSA"),
            )
            .await
            .to_string();
        // Admission must see only conformant clients, not a bypassed policy flag.
        let (actor, correlation) = harness.seeding_actor();
        harness
            .store()
            .scoped(harness.scope())
            .acting(actor, correlation)
            .clients()
            .delete(harness.env(), harness.client_id())
            .await
            .expect("retire the default public fixture client");
        if hardened {
            harness.harden_environment(None).await;
        }
        let subject = harness.seed_unique_user().await;
        harness.grant_consent(&subject, &client).await;
        let cookie = harness.session_cookie(&subject).await;
        Self {
            harness,
            client,
            key,
            cookie,
        }
    }

    pub fn assertion(&self, jti: &str) -> String {
        let claims = serde_json::json!({
            "iss": self.client, "sub": self.client, "aud": self.harness.issuer(),
            "exp": 3600, "iat": 0, "jti": jti,
        });
        sign_jws(
            &self.key,
            &serde_json::to_vec(&claims).expect("assertion claims"),
            &EmissionOptions::new(),
        )
        .expect("client assertion")
    }

    pub fn query(&self, pkce: bool) -> String {
        let mut query = form(&[
            ("response_type", "code"),
            ("client_id", &self.client),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid"),
            ("nonce", "n1"),
        ]);
        if pkce {
            query.push('&');
            query.push_str(&form(&[
                ("code_challenge", PKCE_CHALLENGE),
                ("code_challenge_method", "S256"),
            ]));
        }
        query
    }

    pub async fn pushed_query(&self, pkce: bool, jti: &str) -> String {
        let pushed = format!(
            "{}&{}",
            self.query(pkce),
            form(&[
                ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
                ("client_assertion", &self.assertion(jti)),
            ])
        );
        let (status, _, body) = self.harness.par(&pushed, None).await;
        assert_eq!(status, StatusCode::CREATED, "PAR: {body}");
        let value = json(&body);
        form(&[
            ("client_id", &self.client),
            (
                "request_uri",
                value["request_uri"].as_str().expect("PAR reference"),
            ),
        ])
    }

    pub async fn authorize(&self, query: &str) -> axum::http::HeaderMap {
        let (status, headers, body) = self
            .harness
            .authorize_with_cookie(query, &self.cookie)
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
        headers
    }

    pub async fn exchange(&self, code: &str, jti: &str, proof: bool) -> (StatusCode, String) {
        let exchange = form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", PKCE_VERIFIER),
            ("client_id", &self.client),
            ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
            ("client_assertion", &self.assertion(jti)),
        ]);
        let mut request = Request::builder()
            .method("POST")
            .uri("/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if proof {
            request = request.header(
                "DPoP",
                sign_proof(
                    &self.key,
                    "POST",
                    &format!("{}/token", super::ISSUER_BASE),
                    0,
                    jti,
                ),
            );
        }
        let (status, _, body) = self
            .harness
            .send(request.body(Body::from(exchange)).expect("token request"))
            .await;
        (status, body)
    }
}
