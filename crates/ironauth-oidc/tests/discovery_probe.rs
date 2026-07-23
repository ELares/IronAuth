// SPDX-License-Identifier: MIT OR Apache-2.0

//! The runtime half of the discovery diff harness (issue #18, acceptance
//! criterion 2): every advertised endpoint is OBSERVED as mounted, and every
//! served protocol endpoint is advertised, with the single documented carve-outs.
//!
//! This binary drives the LIVE wiring: the real `oidc_router` (over a Postgres
//! data plane, via the shared harness) merged with the `discovery_router`, exactly
//! as `crates/ironauth/src/main.rs` mounts them. It needs a database, so it is
//! gated behind `required-features = ["testing"]` and runs in CI, not on the
//! DB-free lanes.
//!
//! The DB-free half (advertised metadata equals the registries the subsystems
//! expose, plus the RS256-floor carve-out) lives in `tests/discovery.rs`.

mod common;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use ironauth_jose::{KeySet, SigningKey, SigningPolicy};
use ironauth_oidc::{
    ADVERTISED_ENDPOINTS, DiscoveryCapabilities, DiscoveryState, ID_TOKEN_CLAIMS_SUPPORTED,
    IssuerEntry, IssuerRegistry, JwksCacheWindow, PairwiseSalt, discovery_router,
};
use serde_json::Value;
use tower::ServiceExt;

use crate::common::{Harness, ISSUER_BASE, PKCE_VERIFIER, REDIRECT_URI, form, json};

/// The merged live router (protocol + discovery) and the appended-form discovery
/// URL for the harness scope.
///
/// Discovery now resolves the per-environment policy from a registry entry (issue
/// #194), so the harness scope is PROVISIONED in a pre-populated (database-free)
/// registry with an Ed25519 key; an unprovisioned scope would 404. This probe
/// exercises the config-driven advertised-vs-mounted diff, not the store path.
fn live_router(harness: &Harness) -> (Router, String) {
    let scope = harness.scope();
    let registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(600));
    let key =
        SigningKey::ed25519_from_seed(Some("probe-kid".to_owned()), &[0x11; 32]).expect("key");
    registry.insert(
        scope,
        IssuerEntry::new(
            KeySet::bootstrap(key, SystemTime::UNIX_EPOCH),
            SigningPolicy::eddsa_default(),
            PairwiseSalt::new(Vec::new()),
            ironauth_store::GuardrailSet::for_kind(ironauth_store::EnvironmentType::Dev),
        ),
    );
    let discovery = discovery_router(DiscoveryState::new(
        ISSUER_BASE,
        JwksCacheWindow::clamped(600),
        DiscoveryCapabilities::default(),
        Arc::new(registry),
        harness.env().clone(),
    ));
    let discovery_url = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    (harness.router().merge(discovery), discovery_url)
}

/// The status of a bare `GET` to `path` on the merged router.
async fn get_status(router: &Router, path: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router infallible")
        .status()
}

#[tokio::test]
async fn every_advertised_endpoint_is_observed_as_mounted() {
    // Acceptance criterion 2: probe the LIVE merged router at every endpoint the
    // discovery document advertises and confirm the route exists (a 404 would mean
    // discovery advertises an endpoint the server does not serve). A bare GET is
    // enough: an existing route answers with a 4xx other than 404 (a 405 for a
    // POST-only endpoint, or a validation error page), never a routing 404.
    let harness = Harness::start().await;
    let (router, discovery_url) = live_router(&harness);

    // Read the served discovery document and confirm its issuer matches the tokens.
    let body = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&discovery_url)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router infallible")
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let doc: Value = serde_json::from_slice(&body).expect("discovery json");
    assert_eq!(
        doc["issuer"].as_str(),
        Some(harness.issuer()),
        "the served issuer matches the one tokens carry"
    );

    // Every endpoint the document advertises is mounted (observed != 404), and its
    // URL is exactly the advertised one.
    for endpoint in ADVERTISED_ENDPOINTS {
        let advertised = doc[endpoint.metadata_key]
            .as_str()
            .unwrap_or_else(|| panic!("{} advertised", endpoint.metadata_key));
        assert_eq!(advertised, format!("{ISSUER_BASE}{}", endpoint.path));
        let status = get_status(&router, endpoint.path).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "advertised endpoint {} ({}) is not mounted",
            endpoint.metadata_key,
            endpoint.path,
        );
    }
}

#[tokio::test]
async fn served_protocol_endpoints_are_exactly_the_advertised_ones() {
    // The two protocol endpoints the provider serves (authorize, token) are both
    // advertised; the interaction pages (login, register, consent) are NOT
    // metadata endpoints and are deliberately absent from discovery.
    let harness = Harness::start().await;
    let (router, _) = live_router(&harness);

    for served in ["/authorize", "/token"] {
        assert_ne!(
            get_status(&router, served).await,
            StatusCode::NOT_FOUND,
            "{served} is served"
        );
        assert!(
            ADVERTISED_ENDPOINTS
                .iter()
                .any(|endpoint| endpoint.path == served),
            "{served} is advertised"
        );
    }
}

#[tokio::test]
async fn jwks_serving_is_the_remaining_issue_194_scope() {
    // Boundary marker for issue #194: discovery advertises jwks_uri (a required
    // OIDC field, pointing at the per-environment key set), but the JWKS route
    // needs the LOADED signing keys and is not mounted live yet. So a probe of the
    // advertised jwks_uri path 404s on today's merged router. When #194 loads keys
    // and mounts the JWKS surface, this endpoint starts answering; discovery does
    // not change (it already points at the right URL).
    //
    // This is the SECOND advertised-but-unobserved carve-out, alongside the
    // RS256-floor entry in id_token_signing_alg_values_supported (asserted in
    // tests/discovery.rs). Both are explicit and inert (no keys means no minted
    // tokens to validate); every other advertised endpoint is observed as mounted.
    let harness = Harness::start().await;
    let (router, discovery_url) = live_router(&harness);

    let body = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(&discovery_url)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router infallible")
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let doc: Value = serde_json::from_slice(&body).expect("discovery json");
    let jwks_uri = doc["jwks_uri"].as_str().expect("jwks_uri advertised");
    let jwks_path = jwks_uri
        .strip_prefix(ISSUER_BASE)
        .expect("jwks_uri under the base");
    assert_eq!(
        get_status(&router, jwks_path).await,
        StatusCode::NOT_FOUND,
        "JWKS serving is deferred to issue #194 (keys not loaded live)"
    );
}

#[tokio::test]
async fn advertised_claims_cover_every_claim_a_minted_id_token_carries() {
    // Acceptance criterion 2 (claims half): mint a REAL ID token through the live
    // flow and confirm every claim it carries is advertised in claims_supported.
    // `jti` (a token identifier, not a claim about the user) is the conventional
    // exception. When issue #14 expands the ID token claims, this fails until
    // ID_TOKEN_CLAIMS_SUPPORTED is updated, so advertised claims can never silently
    // drift from the claims the server actually mints.
    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // The harness client is public, so PKCE is mandatory (issue #13).
    let code = harness.issue_authenticated_code_pkce(&client_id).await;
    let exchange = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", PKCE_VERIFIER),
    ]);
    let (status, _, body) = harness.token(&exchange).await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    let id_token = json(&body)["id_token"]
        .as_str()
        .expect("id_token")
        .to_owned();

    // Decode the JWS payload segment and read the claim names the token carries.
    let payload = id_token.split('.').nth(1).expect("jws payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    let claims: serde_json::Map<String, Value> =
        serde_json::from_slice(&bytes).expect("claims json");

    let advertised: HashSet<&str> = ID_TOKEN_CLAIMS_SUPPORTED.iter().copied().collect();
    for name in claims.keys() {
        assert!(
            name == "jti" || advertised.contains(name.as_str()),
            "ID token claim {name:?} is minted but not advertised in claims_supported"
        );
    }
    // Guard against a vacuous pass: the token really did carry a subject.
    assert!(claims.contains_key("sub"), "minted ID token carries sub");
}
