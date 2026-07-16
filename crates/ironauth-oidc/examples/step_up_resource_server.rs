// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal sample resource server for RFC 9470 step-up authentication (issue #72).
//!
//! It protects `GET /payments`, which requires the multi-factor authentication
//! context (`urn:ironauth:acr:mfa`). It reads the presented bearer access token's
//! `acr` claim and, when it does not meet the floor, returns `401` with the exact
//! `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values=...`
//! challenge a client uses to step up (the contract documented in
//! `docs/design/step-up-authentication.md`). A token whose `acr` meets the floor is
//! accepted.
//!
//! It reuses the hyper/tokio stack (via axum). To keep the sample self-contained it
//! reads the `acr` claim from the token payload WITHOUT verifying the signature; a
//! real resource server MUST first verify the token (signature, `iss`, `aud`, `exp`)
//! against the authorization server's JWKS, exactly as the IronAuth JOSE core does.
//!
//! Run it with `cargo run -p ironauth-oidc --example step_up_resource_server`, then:
//!
//! ```text
//! # a password-only token is challenged
//! curl -i localhost:8080/payments -H 'authorization: Bearer <header>.<payload>.<sig>'
//! ```

use std::net::SocketAddr;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// The authentication-context floor a protected operation requires.
#[derive(Clone)]
struct Requirement {
    /// The `acr` the token must achieve (or rank at least as strong as).
    acr_floor: &'static str,
    /// The credential-ladder order (weakest first) used to rank acr values. In a
    /// real deployment this mirrors the tenant's `oidc.acr_order`.
    order: Vec<&'static str>,
}

#[tokio::main]
async fn main() {
    let requirement = Requirement {
        acr_floor: "urn:ironauth:acr:mfa",
        order: vec![
            "urn:ironauth:acr:pwd",
            "urn:ironauth:acr:mfa",
            "phr",
            "phrh",
        ],
    };
    let app = Router::new()
        .route("/payments", get(payments))
        .with_state(requirement);
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("sample step-up resource server listening on http://{addr}/payments");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind the listener");
    axum::serve(listener, app).await.expect("serve");
}

/// The protected `GET /payments` handler: accept a token whose `acr` meets the
/// floor, otherwise emit the RFC 9470 step-up challenge.
async fn payments(State(requirement): State<Requirement>, headers: HeaderMap) -> Response {
    let token = bearer_token(&headers);
    let acr = token.as_deref().and_then(access_token_acr);
    if acr
        .as_deref()
        .is_some_and(|acr| satisfies(acr, requirement.acr_floor, &requirement.order))
    {
        (StatusCode::OK, "payment authorized\n").into_response()
    } else {
        let challenge = format!(
            "Bearer error=\"insufficient_user_authentication\", \
             error_description=\"a higher authentication context is required\", \
             acr_values=\"{}\"",
            requirement.acr_floor
        );
        let mut response = (StatusCode::UNAUTHORIZED, "step-up required\n").into_response();
        if let Ok(value) = header::HeaderValue::from_str(&challenge) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

/// The bearer token from the `Authorization` header, if present.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_owned())
}

/// The `acr` claim of a JWT access token (its middle segment). A real RS verifies
/// the token first; this reads the claim for the sample only.
fn access_token_acr(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64_url_decode(payload)?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("acr")?.as_str().map(str::to_owned)
}

/// Whether `achieved` satisfies `required` under `order` (weakest first): the same
/// value, or a rank at least as strong.
fn satisfies(achieved: &str, required: &str, order: &[&str]) -> bool {
    if achieved == required {
        return true;
    }
    let rank = |acr: &str| order.iter().position(|candidate| *candidate == acr);
    match (rank(achieved), rank(required)) {
        (Some(a), Some(r)) => a >= r,
        _ => false,
    }
}

/// Decode a base64url (no padding) JWT segment.
fn base64_url_decode(segment: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .ok()
}
