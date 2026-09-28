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
    let input = NewDynamicClient {
        display_name: "owned registration fixture",
        auth_method: "none",
        secret_hash: None,
        redirect_uris: &redirects,
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
    };
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
