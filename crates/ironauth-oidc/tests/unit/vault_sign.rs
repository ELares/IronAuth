// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Explicitly included by src/vault_sign.rs under cfg(test). The local mock
// Vault router is a test dependency, never a production OAuth endpoint.

use super::*;
use std::sync::Arc;

/// An owned local endpoint that reads the complete JSON request before signing.
/// The dialer redirects only this test's synthetic public URL to its socket.
async fn stub_transit() -> (
    std::net::SocketAddr,
    Arc<ironauth_jose::SigningKey>,
    tokio::task::JoinHandle<()>,
) {
    let key = ironauth_jose::SigningKey::ed25519_from_seed(None, &[9_u8; 32])
        .expect("the stub key loads");
    let signing_key = Arc::new(key);
    let router_key = Arc::clone(&signing_key);
    let router = axum::Router::new().route(
        "/v1/transit/sign/test-kid",
        axum::routing::post(move |axum::Json(value): axum::Json<serde_json::Value>| {
            let key = Arc::clone(&router_key);
            async move {
                let input = STANDARD
                    .decode(value["input"].as_str().expect("input string"))
                    .expect("base64 input");
                let signature = ironauth_jose::sign_detached(&key, &input).expect("stub signs");
                axum::Json(serde_json::json!({"data": {
                    "signature": format!("vault:v1:{}", STANDARD.encode(signature))
                }}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("owned stub serves");
    });
    (address, signing_key, server)
}

/// The shared battery: sign through the backend, verify through the public half.
#[tokio::test]
async fn vault_transit_signs_and_the_public_half_verifies() {
    let (addr, stub_key, server) = stub_transit().await;
    let token = Secret::Literal(ironauth_config::SecretString::new("test-token"));
    // The SSRF posture blocks loopback; the client_assertion pattern: a resolver
    // that returns a public sentinel + a dialer that forwards to the stub.
    let dialer = Arc::new(ironauth_fetch::RecordingDialer::new(addr));
    let resolver = Arc::new(ironauth_fetch::StaticResolver::new(vec![
        std::net::IpAddr::from([8, 8, 8, 8]),
    ]));
    let http = ironauth_fetch::Fetcher::from_parts(
        ironauth_fetch::FetchLimits::default(),
        resolver,
        dialer,
    );
    let signer = VaultTransitSigner::from_fetcher(
        "http://vault.test",
        "transit",
        token,
        Duration::from_secs(5),
        http,
    );
    let input = b"the full signing input, exactly as PureEdDSA demands";
    let trusted = stub_key.verifying_key().expect("the trusted key");
    // THE SHARED BATTERY (issue #161, the Dex pattern): the SAME battery the
    // local backend passes. The stub signed with the same key the public half
    // verifies against.
    let verify = |signature: &[u8]| {
        ironauth_jose::verify_detached(&trusted, JwsAlgorithm::EdDsa, input, signature).is_ok()
    };
    let outcome = ironauth_jose::external_signer::run_conformance_battery(
        &signer,
        "test-kid",
        JwsAlgorithm::EdDsa,
        input,
        verify,
    )
    .await;
    server.abort();
    assert!(outcome.is_ok(), "the vault backend passes: {outcome:?}");
}
