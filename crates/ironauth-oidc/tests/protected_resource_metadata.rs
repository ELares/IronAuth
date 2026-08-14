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
use ironauth_store::{
    ActorRef, CorrelationId, NewResourceServer, ResourceServerId, ServiceId, TokenFormat,
};

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
