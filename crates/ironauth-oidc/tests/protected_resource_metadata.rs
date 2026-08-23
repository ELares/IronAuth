// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9728 Protected Resource Metadata served for IronAuth-hosted resources (issue
//! #127). Over a real database (`DATABASE_URL`).
//!
//! # What this endpoint is for
//!
//! A client that receives a `401` from a protected resource follows the
//! `resource_metadata` pointer to a document naming which authorization servers that
//! resource trusts. That is the discovery chain MCP clients depend on. It only works
//! if the document is truthful, so the interesting cases here are the ones where a
//! document would LIE and must therefore not exist: an identifier nobody registered,
//! one registered in another tenant, and one whose shape this deployment does not host.
//!
//! # Why the route is deployment-root
//!
//! RFC 9728 section 3.1 composes the metadata URL from the RESOURCE identifier,
//! inserting the well-known segment between authority and path. A scope-routed URL is
//! not what that composition produces, so a spec-following client would never build
//! it. The scope is recovered from the path suffix instead, which is why an identifier
//! must be issuer-rooted with the scope in its path to be servable here.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{Harness, json, send_through};
use ironauth_jose::{KeySet, SigningKey, SigningPolicy};
use ironauth_oidc::{
    DiscoveryCapabilities, DiscoveryState, IssuerEntry, IssuerRegistry, JwksCacheWindow,
    PairwiseSalt, discovery_router,
};
use ironauth_store::{
    ActorRef, CorrelationId, NewResourceServer, ResourceServerId, ServiceId, TokenFormat,
};
use std::sync::Arc;
use std::time::SystemTime;

/// Register a resource server with `audience` in the harness scope.
async fn register_rs(harness: &Harness, audience: &str) {
    let env = harness.env();
    let id = ResourceServerId::generate(env, &harness.scope());
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: TokenFormat::AtJwt,
                access_token_ttl_secs: None,
            },
        )
        .await
        .expect("register resource server");
}

/// An IronAuth-hosted resource identifier in the harness scope: issuer-rooted, with the
/// scope in the path, which is the shape this endpoint serves.
fn hosted_resource(harness: &Harness, tail: &str) -> String {
    let scope = harness.scope();
    format!(
        "{}/t/{}/e/{}/{tail}",
        common::ISSUER_BASE,
        scope.tenant(),
        scope.environment()
    )
}

/// The well-known URL RFC 9728 section 3.1 composes for `resource`, as a request path.
fn well_known_path(harness: &Harness, tail: &str) -> String {
    let scope = harness.scope();
    format!(
        "/.well-known/oauth-protected-resource/t/{}/e/{}/{tail}",
        scope.tenant(),
        scope.environment()
    )
}

async fn get(harness: &Harness, path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    send_through(
        harness.router(),
        Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .expect("request builds"),
    )
    .await
}

/// A registered, IronAuth-hosted resource publishes a valid document at the path RFC
/// 9728 composes for it.
#[tokio::test]
async fn a_registered_hosted_resource_publishes_its_metadata() {
    let harness = Harness::start().await;
    let resource = hosted_resource(&harness, "mcp");
    register_rs(&harness, &resource).await;

    let (status, _, body) = get(&harness, &well_known_path(&harness, "mcp")).await;
    assert_eq!(status, StatusCode::OK, "served: {body}");
    let doc = json(&body);

    // The `resource` member MUST be the identifier itself, or the client cannot confirm
    // it fetched the document for the resource it was pointed at.
    assert_eq!(doc["resource"], resource);
    // `authorization_servers` MUST be the per-environment issuer, which is what the
    // client then runs AS discovery against.
    assert_eq!(
        doc["authorization_servers"],
        serde_json::json!([harness.issuer()])
    );
    assert!(
        doc["scopes_supported"]
            .as_array()
            .is_some_and(|s| !s.is_empty()),
        "scopes are advertised: {doc}"
    );
    // Stated, not inherited: RFC 9728 registers `body` and `query` too, and advertising
    // either would be a document that lies about what this server accepts.
    assert_eq!(
        doc["bearer_methods_supported"],
        serde_json::json!(["header"])
    );
}

/// The advertised `resource` equals the audience a token for it actually carries.
///
/// This is the property the whole document exists to make true, and the one
/// `prm::validate_configuration` refuses to publish without. If they diverged, a client
/// would follow discovery correctly and then be rejected by strict audience validation
/// with nothing on either side explaining why.
#[tokio::test]
async fn the_advertised_resource_is_the_audience_that_is_enforced() {
    let harness = Harness::start().await;
    let resource = hosted_resource(&harness, "api");
    register_rs(&harness, &resource).await;

    let (_, _, body) = get(&harness, &well_known_path(&harness, "api")).await;
    let advertised = json(&body)["resource"]
        .as_str()
        .expect("resource")
        .to_owned();

    // The registration is keyed by exactly this string, so a token minted for it carries
    // it as `aud` (RFC 8707). Same string, compared exactly.
    assert_eq!(advertised, resource);
}

/// An identifier nobody registered has NO document, even though its shape is one this
/// deployment could serve.
///
/// The registration is the authority. Publishing metadata for an unregistered resource
/// would advertise an authorization server for something IronAuth does not actually
/// protect.
#[tokio::test]
async fn an_unregistered_resource_has_no_document() {
    let harness = Harness::start().await;
    // Deliberately NOT registered.
    let (status, _, _) = get(&harness, &well_known_path(&harness, "never-registered")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// A resource registered in ANOTHER scope is not served under this one.
///
/// The lookup is scope-bound, and the scope comes from the path. Serving across scopes
/// would make this unauthenticated endpoint a probe for which resources exist anywhere
/// in the deployment.
#[tokio::test]
async fn a_resource_from_another_scope_is_not_served() {
    let harness = Harness::start().await;
    let foreign = harness.provision_foreign_scope().await;
    // An identifier rooted at the FOREIGN scope, registered in the HARNESS scope. The
    // path names the foreign scope, so the lookup runs there and must miss.
    let resource = format!(
        "{}/t/{}/e/{}/api",
        common::ISSUER_BASE,
        foreign.tenant(),
        foreign.environment()
    );
    register_rs(&harness, &resource).await;

    let path = format!(
        "/.well-known/oauth-protected-resource/t/{}/e/{}/api",
        foreign.tenant(),
        foreign.environment()
    );
    let (status, _, _) = get(&harness, &path).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a registration in one scope must not answer for another"
    );
}

/// A suffix that is not scope-rooted has no document, and reads identically to every
/// other miss.
///
/// A registered audience shaped this way keeps working as a resource server; its
/// metadata is its own origin's to publish. That is the non-breaking half of the
/// hosting rule.
#[tokio::test]
async fn a_non_hosted_identifier_shape_is_not_served() {
    let harness = Harness::start().await;
    register_rs(&harness, "https://api.example/a").await;

    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/a",
        "/.well-known/oauth-protected-resource/t/only-a-tenant",
        "/.well-known/oauth-protected-resource/x/tnt_1/e/env_1/api",
    ] {
        let (status, _, _) = get(&harness, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} must not be served");
    }
}

/// Every miss is the SAME response, so the endpoint is not an oracle for which tenants
/// or resources exist. It is necessarily unauthenticated, so this is the only thing
/// stopping it from enumerating the deployment.
#[tokio::test]
async fn every_miss_is_byte_identical() {
    let harness = Harness::start().await;
    let mut seen = std::collections::BTreeSet::new();
    for path in [
        // Unregistered, but a shape we host.
        well_known_path(&harness, "nope"),
        // A tenant that does not exist.
        "/.well-known/oauth-protected-resource/t/tnt_absent/e/env_absent/api".to_owned(),
        // A malformed scope.
        "/.well-known/oauth-protected-resource/t/!!!/e/!!!/api".to_owned(),
        // Not scope-rooted at all.
        "/.well-known/oauth-protected-resource/elsewhere".to_owned(),
    ] {
        let (status, _, body) = get(&harness, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        seen.insert(body);
    }
    assert_eq!(
        seen.len(),
        1,
        "every miss must be byte identical, got {seen:?}"
    );
}

/// The document carries the cache discipline the other well-known surfaces use, and a
/// conditional request is answered `304` (criterion 5).
#[tokio::test]
async fn the_document_is_cacheable_and_revalidates() {
    let harness = Harness::start().await;
    let resource = hosted_resource(&harness, "cached");
    register_rs(&harness, &resource).await;
    let path = well_known_path(&harness, "cached");

    let (status, headers, _) = get(&harness, &path).await;
    assert_eq!(status, StatusCode::OK);
    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .expect("Cache-Control");
    // The VALUE, not just the presence of the directive. `max-age=0` contains the
    // substring and is not a cache at all, so a presence check would pass for a
    // response that defeats the point of the header.
    let max_age: u64 = cache_control
        .split("max-age=")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|digits| digits.parse().ok())
        .unwrap_or_else(|| panic!("a numeric max-age: {cache_control}"));
    assert!(
        (300..=900).contains(&max_age),
        "max-age is in the band the other well-known surfaces use, got {max_age}"
    );
    let etag = headers
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("ETag")
        .to_owned();

    let conditional = send_through(
        harness.router(),
        Request::builder()
            .method("GET")
            .uri(&path)
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .expect("request builds"),
    )
    .await;
    assert_eq!(
        conditional.0,
        StatusCode::NOT_MODIFIED,
        "a matching ETag revalidates"
    );
}

/// The router with discovery merged in over a PROVISIONED registry.
///
/// The harness's own registry is store-backed and does not resolve its scope, so every
/// discovery form 404s on `harness.router()` alone. `discovery_probe.rs` documents exactly
/// this ("an unprovisioned scope would 404") and solves it the same way, so this follows the
/// established pattern rather than inventing one.
fn router_with_discovery(harness: &Harness) -> axum::Router {
    let scope = harness.scope();
    let registry = IssuerRegistry::new(common::ISSUER_BASE, JwksCacheWindow::clamped(600));
    let key =
        SigningKey::ed25519_from_seed(Some("prm-chain".to_owned()), &[0x22; 32]).expect("key");
    registry.insert(
        scope,
        IssuerEntry::new(
            KeySet::bootstrap(key, SystemTime::UNIX_EPOCH),
            SigningPolicy::eddsa_default(),
            PairwiseSalt::new(Vec::new()),
            ironauth_store::GuardrailSet::for_kind(ironauth_store::EnvironmentType::Dev),
        ),
    );
    harness.router().merge(discovery_router(DiscoveryState::new(
        common::ISSUER_BASE,
        JwksCacheWindow::clamped(600),
        DiscoveryCapabilities::default(),
        Arc::new(registry),
        harness.env().clone(),
    )))
}

/// A bare GET through a router, as a client would make it.
async fn fetch(router: &axum::Router, path: &str) -> (StatusCode, String) {
    let (status, _, body) = send_through(
        router.clone(),
        Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .expect("request builds"),
    )
    .await;
    (status, body)
}

/// The discovery chain completes: PRM document -> the authorization server it names -> that
/// server's metadata, with the issuer agreeing at every hop (issue #127 criterion 2).
///
/// This is the half of the chain that starts once a client HAS the document. The hop before it,
/// from a `401` and its `resource_metadata` pointer, is covered by
/// `the_chain_resolves_from_a_401_challenge_through_prm_to_the_authorization_server` below,
/// which drives `prm::challenge` and fetches what the pointer names.
///
/// An earlier revision of this comment said that builder "has no caller anywhere in the
/// workspace" and that the SDK middleware did not exist. The middleware half was true when
/// written and is not now (#939). The caller half was never true: `prm.rs`'s own
/// `#[cfg(test)]` module has called it since before that comment was written, and a
/// `tests/`-directory grep does not see an inline test module. What it MEANT still holds, and
/// this PR does not change it: `prm::challenge` has no PRODUCTION caller, because the `401`
/// criterion 2 describes is emitted by the customer's resource server through the TypeScript
/// middleware, which no Rust caller grep can ever show.
///
/// What this asserts is that once a client HAS the PRM document, every subsequent hop
/// resolves and agrees. The failure mode it exists for is a PRM naming an authorization
/// server whose metadata is served under a DIFFERENT issuer string: the client fetches keys
/// for one issuer and validates tokens minted by another, and both documents read correctly
/// on their own.
///
/// What it does NOT prove: the two issuer strings are each derived from the same
/// `ISSUER_BASE`, so their agreement is partly structural. The check that carries real weight
/// is the PATH COMPOSITION -- RFC 8414 inserts the well-known segment between host and path
/// rather than appending it, which is the hop a client gets wrong and which this walks for
/// real.
#[tokio::test]
async fn the_discovery_chain_resolves_from_the_prm_document_to_the_authorization_server() {
    let harness = Harness::start().await;
    let resource = hosted_resource(&harness, "mcp");
    register_rs(&harness, &resource).await;
    let router = router_with_discovery(&harness);

    // HOP 1: the PRM document for the resource.
    let (status, body) = fetch(&router, &well_known_path(&harness, "mcp")).await;
    assert_eq!(status, StatusCode::OK, "PRM: {body}");
    let prm = json(&body);
    assert_eq!(prm["resource"], resource);

    // HOP 2: the authorization server it names.
    let servers = prm["authorization_servers"]
        .as_array()
        .expect("authorization_servers is required by RFC 9728");
    assert_eq!(servers.len(), 1, "exactly one AS for a hosted resource");
    let issuer = servers[0].as_str().expect("issuer is a string").to_owned();

    // HOP 3: that server's metadata, at the path composed from the ISSUER the PRM gave us --
    // not from harness state, which would make the test agree with itself. RFC 8414 INSERTS
    // the well-known segment between host and path; appending it is the common mistake and
    // would 404 here.
    let as_path = issuer
        .strip_prefix(common::ISSUER_BASE)
        .map(|tail| format!("/.well-known/oauth-authorization-server{tail}"))
        .expect("the AS the PRM names must live under this deployment");
    let (status, body) = fetch(&router, &as_path).await;
    assert_eq!(status, StatusCode::OK, "AS metadata at {as_path}: {body}");
    let metadata = json(&body);

    // The hop that matters: the metadata's OWN issuer must be the string the PRM sent the
    // client to.
    assert_eq!(
        metadata["issuer"], issuer,
        "the AS metadata's issuer must be the identifier the PRM pointed at: {body}"
    );

    // The chain has to end somewhere usable.
    for required in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
        assert!(
            metadata[required].as_str().is_some_and(|v| !v.is_empty()),
            "a client that completed the chain must find {required}: {body}"
        );
    }

    // Every scope the PRM advertises must be one the AS actually supports, or a client
    // requests a scope that is refused at the authorization endpoint.
    let advertised: Vec<&str> = prm["scopes_supported"]
        .as_array()
        .expect("scopes_supported")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let supported: Vec<&str> = metadata["scopes_supported"]
        .as_array()
        .expect("AS scopes_supported")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        !advertised.is_empty(),
        "an empty advertised set would make the check below vacuous"
    );
    for scope in &advertised {
        assert!(
            supported.contains(scope),
            "the PRM advertises `{scope}`, which the authorization server does not support: \
             {supported:?}"
        );
    }
}

/// The document tracks the deployment's CONFIGURED issuer, and a resource registered under a
/// previous one stops being served rather than being served stale (issue #127 criterion 5).
///
/// `authorization_servers` is rendered per request from `state.issuer_for(&scope)`, so it is
/// never a stored value that could go stale. What IS stored is the registered audience, and
/// `resolve_hosted_resource` reconstructs the identifier it looks up from the CURRENT issuer
/// base. Those two facts together decide what a public-URL change does, and the answer is not
/// the obvious one:
///
///   registered under the CURRENT base -> served, naming the current issuer
///   registered under a PREVIOUS base  -> 404, not a document naming the new issuer
///
/// The second half is the one worth pinning, and it is the safe direction. The alternative
/// would be to match on the path suffix alone and serve a document whose `resource` field is
/// an identifier nobody registered, which is precisely the lie this endpoint exists not to
/// tell. But it is a SILENT break: after a public-URL change every previously published
/// discovery chain stops resolving, and the operator's signal is a 404 rather than an error,
/// so the remedy (re-register the resource servers under the new identifier) is worth knowing
/// before the change rather than after.
#[tokio::test]
async fn a_public_url_change_orphans_the_old_registration_and_serves_a_re_registered_one() {
    const MOVED_BASE: &str = "https://issuer-moved.test";

    let harness = Harness::start().await;
    let scope = harness.scope();
    let resource = hosted_resource(&harness, "moved");
    register_rs(&harness, &resource).await;
    let path = well_known_path(&harness, "moved");

    let (status, headers, body) = get(&harness, &path).await;
    assert_eq!(status, StatusCode::OK, "served before the move: {body}");
    let before: serde_json::Value = json(&body);
    let etag_before = headers
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("ETag")
        .to_owned();
    assert_eq!(
        before["authorization_servers"],
        serde_json::json!([format!(
            "{}/t/{}/e/{}",
            common::ISSUER_BASE,
            scope.tenant(),
            scope.environment()
        )]),
        "the document names the issuer this deployment is configured with: {before}"
    );

    // The SAME database, environment and rows, served by a deployment configured with a
    // different public URL. That is what a public-URL change is: the rows do not move, the
    // issuer the process derives from them does.
    let moved = harness.serving_router(&ironauth_config::OidcConfig::default(), MOVED_BASE);

    let (status, _, _) = send_through(
        moved.clone(),
        Request::builder()
            .method("GET")
            .uri(&path)
            .body(Body::empty())
            .expect("request builds"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the OLD registration is orphaned: its identifier is issuer-rooted at a base this \
         deployment no longer serves, so there is no truthful document to publish for it"
    );

    // A resource registered under the NEW base is served, and names the new issuer. This is
    // the half that proves the 404 above is about the stale REGISTRATION rather than the route
    // having broken: without it, a route that 404s unconditionally would pass just as well.
    let moved_resource = format!(
        "{}/t/{}/e/{}/moved",
        MOVED_BASE,
        scope.tenant(),
        scope.environment()
    );
    register_rs(&harness, &moved_resource).await;
    let (status, headers, body) = send_through(
        moved,
        Request::builder()
            .method("GET")
            .uri(&path)
            .body(Body::empty())
            .expect("request builds"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-registered and served: {body}");
    let after: serde_json::Value = json(&body);
    assert_eq!(
        after["resource"], moved_resource,
        "the document describes the identifier that is actually registered: {after}"
    );
    assert_eq!(
        after["authorization_servers"],
        serde_json::json!([format!(
            "{}/t/{}/e/{}",
            MOVED_BASE,
            scope.tenant(),
            scope.environment()
        )]),
        "and names the NEW issuer, rendered per request rather than stored: {after}"
    );

    let etag_after = headers
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("ETag")
        .to_owned();
    assert_ne!(
        etag_before, etag_after,
        "the ETag is content-derived, so it moves with the content: a stale one would let an \
         intermediary revalidate to 304 and keep serving the superseded issuer"
    );
}

/// The challenge corpus shared with the SDK, so "the SDK matches the crate" is falsifiable.
///
/// Both implementations build these challenges with their own builder and must produce the
/// same bytes. Before this file the crate's forms were pinned only by inline unit tests in
/// `prm.rs` and the SDK's by literals in its own suite, so the SDK's claim that "parameter
/// order matches the crate" was checked by nothing that read both.
fn challenge_corpus() -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/ironauth-sdk/vectors/prm-challenge-vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read the corpus at {}: {error}", path.display()));
    serde_json::from_str(&text).expect("the corpus is JSON")
}

/// Every challenge in the shared corpus is what this crate builds (issue #127 criterion 3).
#[test]
fn the_crate_builds_every_challenge_in_the_shared_corpus() {
    let corpus = challenge_corpus();
    let metadata_url = corpus["metadata_url"].as_str().expect("metadata_url");
    let cases = corpus["cases"].as_array().expect("cases");
    // The KINDS, not a count. A floor of three would be satisfied by three challenge cases,
    // and the file would then exercise one builder while claiming to pin both: losing the
    // insufficient-scope case is exactly the edit that drops all coverage of the other one.
    let kinds: std::collections::BTreeSet<&str> =
        cases.iter().filter_map(|c| c["kind"].as_str()).collect();
    assert!(
        kinds.contains("challenge") && kinds.contains("insufficient_scope"),
        "the corpus exercises BOTH challenge builders: {kinds:?}"
    );
    // Bound to the KIND. `c["error"].is_null()` alone is satisfied by the insufficient-scope
    // case, because serde_json indexes an ABSENT key to `Value::Null` and that case carries no
    // `error` member, so the predicate held whether or not the bare case existed. Measured:
    // with the bare case deleted, both suites stayed green.
    assert!(
        cases
            .iter()
            .any(|c| c["kind"] == "challenge" && c["error"].is_null()),
        "including the bare form, which is the answer to a request with no credential"
    );

    for case in cases {
        let name = case["name"].as_str().expect("name");
        let expected = case["expected"].as_str().expect("expected");
        let built = match case["kind"].as_str().expect("kind") {
            "challenge" => {
                let error = case["error"].as_str().map(|code| {
                    (
                        code,
                        case["error_description"]
                            .as_str()
                            .expect("a case with an error states its description"),
                    )
                });
                ironauth_oidc::prm::challenge(metadata_url, error)
            }
            "insufficient_scope" => ironauth_oidc::prm::insufficient_scope_challenge(
                metadata_url,
                case["scope"].as_str().expect("scope"),
            ),
            other => panic!("unknown case kind {other} in {name}"),
        };
        assert_eq!(built, expected, "case {name}");
    }
}

/// The discovery chain a client actually walks, starting where a client actually starts: at a
/// `401` (issue #127 criterion 2).
///
/// The sibling chain test starts AT the document, computing its path from the harness rather
/// than learning it from a refusal. That skips the hop discovery actually turns on: a client
/// has never heard of this deployment, and all it has is a `401` and the pointer inside it.
/// This test reads the metadata URL back OUT of a challenge string and fetches with that, so
/// the pointer has to name something this deployment serves.
#[tokio::test]
async fn the_chain_resolves_from_a_401_challenge_through_prm_to_the_authorization_server() {
    let harness = Harness::start().await;
    let resource = hosted_resource(&harness, "chain");
    register_rs(&harness, &resource).await;
    let router = router_with_discovery(&harness);

    // HOP 0: the refusal, built by the crate's own composer and its own challenge builder.
    //
    // `well_known_path_for` returns the ABSOLUTE URL, not a path to be joined to an origin. An
    // earlier revision prepended the origin again, and the doubled pointer still passed every
    // assertion here: `strip_prefix` below removes only the first copy, and axum routes on
    // `Uri::path()`, which discards whatever precedes it. The guard after the parse is what
    // makes that observable.
    let metadata_url = ironauth_oidc::prm::well_known_path_for(&resource)
        .expect("a hosted identifier composes a well-known URL");
    let www_authenticate = ironauth_oidc::prm::challenge(
        &metadata_url,
        Some((
            "invalid_token",
            "the access token is not valid for this resource",
        )),
    );

    // The client's parse: pull `resource_metadata` back out of the header value rather than
    // reusing the local. Reusing it would make the test agree with itself and would not notice
    // a builder that emitted a well-formed header naming the wrong URL.
    let pointer = www_authenticate
        .split("resource_metadata=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the challenge carries the pointer that makes discovery possible");
    let request_path = pointer
        .strip_prefix(common::ISSUER_BASE)
        .expect("the pointer must address this deployment");
    assert!(
        request_path.starts_with('/'),
        "the pointer must be exactly ONE absolute URL under this deployment. Without this the \
         fetch below succeeds on a malformed pointer anyway, because axum routes on the URI's \
         path and throws away anything before it: {pointer}"
    );

    // HOP 1: the document the pointer names.
    let (status, body) = fetch(&router, request_path).await;
    assert_eq!(status, StatusCode::OK, "PRM at {request_path}: {body}");
    let prm = json(&body);
    assert_eq!(
        prm["resource"], resource,
        "the document the CHALLENGE pointed at describes the resource that refused us: {prm}"
    );

    // HOP 2: the authorization server the document names, at the RFC 8414 composed path.
    let issuer = prm["authorization_servers"]
        .as_array()
        .and_then(|servers| servers.first())
        .and_then(serde_json::Value::as_str)
        .expect("authorization_servers is required by RFC 9728")
        .to_owned();
    let as_path = issuer
        .strip_prefix(common::ISSUER_BASE)
        .map(|tail| format!("/.well-known/oauth-authorization-server{tail}"))
        .expect("the AS the PRM names must live under this deployment");
    let (status, body) = fetch(&router, &as_path).await;
    assert_eq!(status, StatusCode::OK, "AS metadata at {as_path}: {body}");
    let metadata = json(&body);
    assert_eq!(
        metadata["issuer"], issuer,
        "the server's own issuer is the string the document sent us to, so the chain closes: \
         {metadata}"
    );
}
