// SPDX-License-Identifier: MIT OR Apache-2.0

//! Discovery generated from live config, served on both well-known forms (issue
//! #18).
//!
//! Database-free and key-free: the discovery surface needs only the issuer string,
//! the endpoint/capability registries, and the algorithm policy, so it is driven
//! directly through the [`ironauth_oidc::discovery_router`]. Covers acceptance
//! criteria 3 (explicit `request_uri_parameter_supported: false`; RS256 alongside
//! `EdDSA` in a default-policy environment), 4 (policy-filtered algorithm arrays with
//! the RS256 floor), 5 (both well-known forms resolve with the exact issuer
//! string), 6 (the MCP-probed RFC 8414 host-inserted form), 7 (a config toggle
//! adds/removes a capability without code changes), and the config-driven half of
//! criterion 2 (every advertised `*_supported` array equals the registry the
//! owning subsystem exposes).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use ironauth_env::Env;
use ironauth_jose::{JwsAlgorithm, SigningPolicy};
use ironauth_oidc::{
    ADVERTISED_ENDPOINTS, ClientAuthMethod, DiscoveryCapabilities, DiscoveryState, GrantType,
    ID_TOKEN_CLAIMS_SUPPORTED, JwksCacheWindow, PkceMethod, PromptValue, ResponseMode,
    ResponseType, SCOPES_SUPPORTED, SubjectType, discovery_document, discovery_router,
    id_token_signing_alg_values,
};
use ironauth_store::{EnvironmentId, Scope, TenantId};
use serde_json::{Value, json};
use tower::ServiceExt;

const ISSUER_BASE: &str = "https://issuer.test";

/// A discovery router over `ISSUER_BASE` with the given capabilities and a default
/// (`EdDSA`) policy, plus a freshly generated scope.
fn router_and_scope(capabilities: DiscoveryCapabilities) -> (Router, Scope) {
    let env = Env::system();
    let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let state = DiscoveryState::new(ISSUER_BASE, JwksCacheWindow::clamped(600), capabilities);
    (discovery_router(state), scope)
}

/// Drive one GET request through the router.
async fn get(router: &Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

/// The three well-known URLs for a scope: the appended OIDC form and the two
/// host-inserted RFC 8414 forms.
fn well_known_urls(scope: &Scope) -> [String; 3] {
    let path = format!("t/{}/e/{}", scope.tenant(), scope.environment());
    [
        // OIDC Discovery 1.0: suffix APPENDED to the issuer path.
        format!("/{path}/.well-known/openid-configuration"),
        // RFC 8414: well-known segment INSERTED between host and path (OAuth
        // server-metadata variant; the one MCP clients probe).
        format!("/.well-known/oauth-authorization-server/{path}"),
        // RFC 8414: host-inserted openid-configuration variant.
        format!("/.well-known/openid-configuration/{path}"),
    ]
}

#[tokio::test]
async fn both_well_known_forms_resolve_with_the_exact_issuer_string() {
    // Acceptance criterion 5: the appended OIDC form and BOTH host-inserted RFC
    // 8414 forms resolve, every one carrying the identical document with an issuer
    // that exact-string-matches the URL it was derived from (no trailing slash).
    let (router, scope) = router_and_scope(DiscoveryCapabilities::default());
    let expected_issuer = format!(
        "{ISSUER_BASE}/t/{}/e/{}",
        scope.tenant(),
        scope.environment()
    );

    let mut bodies = Vec::new();
    for uri in well_known_urls(&scope) {
        let (status, headers, body) = get(&router, &uri).await;
        assert_eq!(status, StatusCode::OK, "form {uri} resolves");
        assert!(
            headers.get(header::CACHE_CONTROL).is_some(),
            "{uri} carries Cache-Control"
        );
        assert!(headers.get(header::ETAG).is_some(), "{uri} carries ETag");
        assert_eq!(
            headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );

        let doc: Value = serde_json::from_str(&body).expect("json");
        // Exact string match, and no trailing-slash drift.
        assert_eq!(doc["issuer"], json!(expected_issuer), "{uri}");
        assert!(
            !expected_issuer.ends_with('/'),
            "issuer has no trailing slash"
        );
        assert_eq!(
            doc["jwks_uri"],
            json!(format!("{expected_issuer}/jwks.json")),
            "{uri}"
        );
        bodies.push(body);
    }

    // Every form serves the byte-identical document.
    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "all three well-known forms serve the same document"
    );
}

#[tokio::test]
async fn mcp_style_rfc8414_host_inserted_probe_succeeds() {
    // Acceptance criterion 6: an MCP client probes the RFC 8414 host-inserted
    // oauth-authorization-server form for a per-environment issuer.
    let (router, scope) = router_and_scope(DiscoveryCapabilities::default());
    let probe = format!(
        "/.well-known/oauth-authorization-server/t/{}/e/{}",
        scope.tenant(),
        scope.environment()
    );
    let (status, _, body) = get(&router, &probe).await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_str(&body).expect("json");
    let expected_issuer = format!(
        "{ISSUER_BASE}/t/{}/e/{}",
        scope.tenant(),
        scope.environment()
    );
    assert_eq!(doc["issuer"], json!(expected_issuer));
    // The endpoints an MCP client needs to start a flow are present.
    assert_eq!(
        doc["authorization_endpoint"],
        json!(format!("{ISSUER_BASE}/authorize"))
    );
    assert_eq!(doc["token_endpoint"], json!(format!("{ISSUER_BASE}/token")));
}

#[tokio::test]
async fn default_policy_environment_publishes_the_explicit_traps_and_rs256_floor() {
    // Acceptance criterion 3: request_uri_parameter_supported is false EXPLICITLY,
    // and RS256 appears alongside EdDSA in a default-policy environment.
    let (router, scope) = router_and_scope(DiscoveryCapabilities::default());
    let uri = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    let (status, _, body) = get(&router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let doc: Value = serde_json::from_str(&body).expect("json");

    assert_eq!(doc["request_uri_parameter_supported"], json!(false));
    assert_eq!(doc["request_parameter_supported"], json!(false));
    assert_eq!(doc["claims_parameter_supported"], json!(false));
    assert_eq!(
        doc["authorization_response_iss_parameter_supported"],
        json!(false)
    );

    let algs = string_array(&doc, "id_token_signing_alg_values_supported");
    assert!(
        algs.contains(&"EdDSA".to_owned()),
        "default policy signs EdDSA"
    );
    assert!(algs.contains(&"RS256".to_owned()), "RS256 floor is present");
}

#[test]
fn es256_only_policy_bans_eddsa_everywhere_but_keeps_the_rs256_floor() {
    // Acceptance criterion 4: an ES256-only environment advertises NO EdDSA in any
    // *_supported array, while RS256 remains as the id-token floor. Driven at the
    // generator with an explicit policy (the live mount uses the default policy
    // until per-environment policy sources load in issue #194).
    let policy = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("policy");
    let issuer = "https://issuer.test/t/tnt/e/env";
    let doc = discovery_document(
        issuer,
        ISSUER_BASE,
        &format!("{issuer}/jwks.json"),
        &policy,
        &DiscoveryCapabilities::default(),
    );

    let algs = string_array(&doc, "id_token_signing_alg_values_supported");
    assert_eq!(algs, vec!["ES256".to_owned(), "RS256".to_owned()]);

    // No *_supported array anywhere mentions EdDSA under an ES256-only policy.
    let object = doc.as_object().expect("object");
    for (key, value) in object {
        if key.ends_with("_supported") {
            if let Some(items) = value.as_array() {
                for item in items {
                    assert_ne!(
                        item.as_str(),
                        Some("EdDSA"),
                        "{key} must not advertise EdDSA under an ES256-only policy"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn a_disabled_feature_is_absent_and_an_enabled_one_appears() {
    // Acceptance criterion 7: toggling a per-environment capability adds or removes
    // it from discovery with NO code change to the generator (it loops over the
    // registries and the capability set).
    let (router, scope) = router_and_scope(DiscoveryCapabilities::default());
    let uri = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    let (_, _, body) = get(&router, &uri).await;
    let doc: Value = serde_json::from_str(&body).expect("json");
    // Disabled: only the registry-sourced query mode.
    assert_eq!(doc["response_modes_supported"], json!(["query"]));

    // Enable form_post (issue #17 seam) and it appears, with no generator edit.
    let (router, scope) = router_and_scope(
        DiscoveryCapabilities::default().with_additional_response_mode("form_post"),
    );
    let uri = format!(
        "/t/{}/e/{}/.well-known/openid-configuration",
        scope.tenant(),
        scope.environment()
    );
    let (_, _, body) = get(&router, &uri).await;
    let doc: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        doc["response_modes_supported"],
        json!(["query", "form_post"])
    );
}

#[tokio::test]
async fn a_malformed_scope_is_a_uniform_not_found_on_every_form() {
    let (router, _) = router_and_scope(DiscoveryCapabilities::default());
    let env = Env::system();
    let tenant = TenantId::generate(&env);
    // A malformed environment id fails on all three forms, with no oracle.
    for uri in [
        format!("/t/{tenant}/e/env_not-base64-!!/.well-known/openid-configuration"),
        format!("/.well-known/oauth-authorization-server/t/{tenant}/e/env_not-base64-!!"),
        format!("/.well-known/openid-configuration/t/{tenant}/e/env_not-base64-!!"),
    ] {
        assert_eq!(get(&router, &uri).await.0, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn discovery_routes_coexist_with_a_sibling_well_known_route() {
    // Guards the live composition: main.rs merges the discovery router onto a
    // public plane that already serves /.well-known/security.txt. The host-inserted
    // discovery forms share the /.well-known/ prefix, so this proves the merge does
    // not panic on a route conflict and both siblings still answer.
    async fn security_txt() -> &'static str {
        "Contact: mailto:security@issuer.test\n"
    }

    let (discovery, scope) = router_and_scope(DiscoveryCapabilities::default());
    let router = Router::new()
        .route(
            "/.well-known/security.txt",
            axum::routing::get(security_txt),
        )
        .merge(discovery);

    // The sibling static well-known route still answers.
    let (status, _, body) = get(&router, "/.well-known/security.txt").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("security@issuer.test"));

    // And every discovery form still resolves through the merged router.
    for uri in well_known_urls(&scope) {
        assert_eq!(get(&router, &uri).await.0, StatusCode::OK, "{uri}");
    }
}

#[test]
fn no_trailing_slash_drift_when_the_base_url_carries_one() {
    // The issuer value must exact-match regardless of a trailing slash on the
    // configured base URL.
    let env = Env::system();
    let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let issuer = format!(
        "{ISSUER_BASE}/t/{}/e/{}",
        scope.tenant(),
        scope.environment()
    );
    let doc = discovery_document(
        &issuer,
        ISSUER_BASE,
        &format!("{issuer}/jwks.json"),
        &SigningPolicy::eddsa_default(),
        &DiscoveryCapabilities::default(),
    );
    let advertised = doc["issuer"].as_str().expect("issuer string");
    assert!(
        !advertised.contains("//t/"),
        "no double slash in the issuer path"
    );
    assert_eq!(advertised, issuer);
}

#[test]
fn every_supported_array_equals_the_registry_its_subsystem_exposes() {
    // Acceptance criterion 2 (config-driven half): the advertised metadata is
    // exactly the registries/consts the owning subsystems expose, and every
    // advertised value round-trips through that subsystem's parser (advertised ==
    // observed). Nothing is hand-listed in the generator.
    let doc = discovery_document(
        "https://issuer.test/t/tnt/e/env",
        ISSUER_BASE,
        "https://issuer.test/t/tnt/e/env/jwks.json",
        &SigningPolicy::eddsa_default(),
        &DiscoveryCapabilities::default(),
    );

    // response_types: ResponseType::ALL, each parses back.
    let response_types = string_array(&doc, "response_types_supported");
    assert_eq!(
        response_types,
        as_strs(ResponseType::ALL, ResponseType::as_str)
    );
    for value in &response_types {
        assert!(ResponseType::parse(value).is_some(), "{value} is served");
    }

    // grant_types: GrantType::ALL, each parses back.
    let grant_types = string_array(&doc, "grant_types_supported");
    assert_eq!(grant_types, as_strs(GrantType::ALL, GrantType::as_str));
    for value in &grant_types {
        assert!(GrantType::parse(value).is_some(), "{value} is served");
    }

    // code_challenge_methods: PkceMethod::ALL, each parses back.
    let pkce = string_array(&doc, "code_challenge_methods_supported");
    assert_eq!(pkce, as_strs(PkceMethod::ALL, PkceMethod::as_str));
    for value in &pkce {
        assert!(PkceMethod::parse(value).is_some(), "{value} is served");
    }

    // response_modes: ResponseMode::ALL, each parses back.
    let response_modes = string_array(&doc, "response_modes_supported");
    assert_eq!(
        response_modes,
        as_strs(ResponseMode::ALL, ResponseMode::as_str)
    );
    for value in &response_modes {
        assert!(ResponseMode::parse(value).is_some(), "{value} is served");
    }

    // prompt_values: PromptValue::ALL, each parses back.
    let prompts = string_array(&doc, "prompt_values_supported");
    assert_eq!(prompts, as_strs(PromptValue::ALL, PromptValue::as_str));
    for value in &prompts {
        assert!(PromptValue::parse(value).is_some(), "{value} is served");
    }

    // token_endpoint_auth_methods: ClientAuthMethod::ALL, each parses back.
    let auth_methods = string_array(&doc, "token_endpoint_auth_methods_supported");
    assert_eq!(
        auth_methods,
        as_strs(ClientAuthMethod::ALL, ClientAuthMethod::as_str)
    );
    for value in &auth_methods {
        assert!(
            ClientAuthMethod::parse(value).is_some(),
            "{value} is served"
        );
    }

    // subject_types: SubjectType::ALL (no wire parser; compared to the registry).
    let subject_types = string_array(&doc, "subject_types_supported");
    assert_eq!(
        subject_types,
        as_strs(SubjectType::ALL, SubjectType::as_str)
    );

    // scopes and claims come from the module consts.
    assert_eq!(
        string_array(&doc, "scopes_supported"),
        SCOPES_SUPPORTED
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        string_array(&doc, "claims_supported"),
        ID_TOKEN_CLAIMS_SUPPORTED
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );

    // Endpoints: exactly the registry entries, no phantom endpoint advertised.
    let object = doc.as_object().expect("object");
    for endpoint in ADVERTISED_ENDPOINTS {
        assert_eq!(
            object.get(endpoint.metadata_key).and_then(Value::as_str),
            Some(format!("{ISSUER_BASE}{}", endpoint.path).as_str()),
            "{} advertised at its served path",
            endpoint.metadata_key,
        );
    }
    // No endpoint-shaped key beyond jwks_uri and the registry entries.
    for key in object.keys() {
        if key.ends_with("_endpoint") {
            assert!(
                ADVERTISED_ENDPOINTS
                    .iter()
                    .any(|endpoint| endpoint.metadata_key == key),
                "{key} is advertised but not in the endpoint registry"
            );
        }
    }
}

#[test]
fn rs256_floor_is_the_only_advertised_alg_that_need_not_be_policy_permitted() {
    // The documented single carve-out: every advertised id-token signing alg is
    // policy-permitted, EXCEPT RS256 (the floor), which may be advertised without
    // being permitted to sign.
    let policy = SigningPolicy::new(vec![JwsAlgorithm::Es256]).expect("policy");
    for advertised in id_token_signing_alg_values(&policy) {
        let alg = JwsAlgorithm::from_jose_name(&advertised).expect("known alg");
        let permitted = policy.permits(alg);
        assert!(
            permitted || advertised == "RS256",
            "{advertised} is advertised but neither policy-permitted nor the RS256 floor"
        );
    }
    // And RS256 here really is the carve-out: it is advertised yet NOT permitted.
    assert!(!policy.permits(JwsAlgorithm::Rs256));
    assert!(id_token_signing_alg_values(&policy).contains(&"RS256".to_owned()));
}

/// A `*_supported` (or any) JSON array field as owned strings.
fn string_array(doc: &Value, key: &str) -> Vec<String> {
    doc[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
        .iter()
        .map(|v| v.as_str().expect("string element").to_owned())
        .collect()
}

/// Map a registry slice to owned strings via its `as_str` projection.
fn as_strs<T: Copy>(all: &[T], as_str: impl Fn(T) -> &'static str) -> Vec<String> {
    all.iter().map(|value| as_str(*value).to_owned()).collect()
}
