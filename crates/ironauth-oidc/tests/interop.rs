// SPDX-License-Identifier: MIT OR Apache-2.0

//! Interop: both client-secret authentication methods driven through the
//! mainstream `oauth2` Rust client crate (issue #20 acceptance).
//!
//! A real third-party OAuth 2.0 client library performs the `authorization_code`
//! token exchange against the in-process provider, once with
//! `AuthType::BasicAuth` (`client_secret_basic`) and once with
//! `AuthType::RequestBody` (`client_secret_post`). The oauth2 crate builds the
//! Authorization header and the request body exactly as a conforming client
//! would (including the RFC 6749 form-urlencoding of the credentials for Basic),
//! so a green exchange proves both methods interoperate with a mainstream
//! library, not merely with our own hand-built requests. The client's HTTP calls
//! are routed straight into the axum Router (no socket, no browser); the literal
//! headless-browser and JS/Python OIDC-conformance runs are deferred to the
//! M4/M9 certification wave. The sibling OIDC-specific client crate
//! (openidconnect) is intentionally excluded: it transitively pulls in the `rsa`
//! crate (RUSTSEC-2023-0071, no fixed version), which the supply-chain gate
//! rejects.

mod common;

use std::future::Future;
use std::pin::Pin;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response};
use http_body_util::BodyExt;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthType, AuthorizationCode, ClientId as OAuthClientId, ClientSecret, HttpRequest,
    HttpResponse, RedirectUrl, TokenResponse, TokenUrl,
};
use tower::ServiceExt;

use common::{Harness, REDIRECT_URI};
use ironauth_oidc::ClientAuthMethod;

/// The absolute token endpoint URL the oauth2 client is pointed at. Only the path
/// is used to route into the in-process Router; the host is a placeholder that
/// never leaves the process.
const TOKEN_URL: &str = "http://ironauth.test/token";

/// An HTTP-client error surfaced to the oauth2 crate. The in-process transport is
/// infallible in practice; this type only exists to satisfy the trait bound.
#[derive(Debug)]
struct TransportError(String);

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "in-process transport error: {}", self.0)
    }
}

impl std::error::Error for TransportError {}

/// Route one oauth2 `HttpRequest` (an `http::Request<Vec<u8>>`) into a clone of
/// the provider's Router. The absolute request URI is reduced to its path so the
/// in-process Router matches `/token`, and the response is collected back into an
/// `http::Response<Vec<u8>>` (the shape oauth2 parses).
async fn dispatch(router: Router, request: HttpRequest) -> HttpResponse {
    let (parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), |pq| pq.as_str().to_owned());
    let mut builder = Request::builder().method(parts.method).uri(path);
    for (name, value) in &parts.headers {
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Body::from(body))
        .expect("in-process request builds");

    let response = router.oneshot(request).await.expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();

    let mut out = Response::builder().status(status);
    for (name, value) in &headers {
        out = out.header(name, value);
    }
    out.body(bytes.to_vec())
        .expect("in-process response builds")
}

/// An async HTTP client (an `Fn(HttpRequest) -> Future`, which oauth2 accepts as
/// an `AsyncHttpClient`) that dispatches every request into the given Router.
fn router_client(
    router: Router,
) -> impl Fn(HttpRequest) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send>>
{
    move |request: HttpRequest| {
        let router = router.clone();
        Box::pin(async move { Ok(dispatch(router, request).await) })
    }
}

/// Register a confidential client for `method`, mint a code for a fresh
/// consenting subject, and redeem it through the `oauth2` crate configured with
/// `auth_type`. Asserts a real access token comes back.
async fn exchange_through_oauth2(harness: &Harness, method: ClientAuthMethod, auth_type: AuthType) {
    let (client, secret) = harness.create_confidential_client(method).await;
    let client_id = client.to_string();
    let code = harness.issue_authenticated_code(&client_id).await;

    let http_client = router_client(harness.router());
    let oauth = BasicClient::new(OAuthClientId::new(client_id))
        .set_client_secret(ClientSecret::new(secret))
        .set_token_uri(TokenUrl::new(TOKEN_URL.to_owned()).expect("token url parses"))
        .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_owned()).expect("redirect url parses"))
        .set_auth_type(auth_type);

    let token = oauth
        .exchange_code(AuthorizationCode::new(code))
        .request_async(&http_client)
        .await
        .expect("token exchange through the oauth2 client succeeds");

    assert!(
        !token.access_token().secret().is_empty(),
        "the oauth2 client receives a non-empty access token",
    );
}

#[tokio::test]
async fn oauth2_client_secret_basic_interops() {
    // AuthType::BasicAuth == client_secret_basic: credentials in the Authorization
    // header, form-urlencoded then base64. The generated secret is URL-safe, so
    // the encoded and raw forms coincide and the server authenticates it.
    let harness = Harness::start().await;
    exchange_through_oauth2(&harness, ClientAuthMethod::Basic, AuthType::BasicAuth).await;
}

#[tokio::test]
async fn oauth2_client_secret_post_interops() {
    // AuthType::RequestBody == client_secret_post: client_id and client_secret in
    // the form body.
    let harness = Harness::start().await;
    exchange_through_oauth2(&harness, ClientAuthMethod::Post, AuthType::RequestBody).await;
}
