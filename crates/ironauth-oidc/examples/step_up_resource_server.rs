// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal sample resource server for RFC 9470 step-up authentication (issue #72).
//!
//! It protects `GET /payments`, which requires the multi-factor authentication
//! context (`urn:ironauth:acr:mfa`) AND a recent authentication (a `max_age` of 300
//! seconds). It reads the presented bearer access token's `acr` and `auth_time` claims
//! and, when EITHER the `acr` does not meet the floor OR the authentication is older than
//! `max_age`, returns `401` with the exact
//! `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values=...,
//! max_age=...` challenge a client uses to step up (the contract documented in
//! `docs/design/step-up-authentication.md`). A token whose `acr` meets the floor AND
//! whose `auth_time` is within the window is accepted.
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
    /// The maximum authentication age in seconds: a token whose `auth_time` is older
    /// than this must re-authenticate even when its `acr` already meets the floor
    /// (OIDC Core `max_age`, RFC 9470). [`None`] means no age bound.
    max_age_secs: Option<u64>,
    /// The credential-ladder order (weakest first) used to rank acr values. In a
    /// real deployment this mirrors the tenant's deployment `oidc.acr_order`.
    order: Vec<&'static str>,
}

#[tokio::main]
async fn main() {
    let requirement = Requirement {
        acr_floor: "urn:ironauth:acr:mfa",
        max_age_secs: Some(300),
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

/// The protected `GET /payments` handler: accept a token whose `acr` meets the floor
/// AND whose `auth_time` is within `max_age`, otherwise emit the RFC 9470 step-up
/// challenge carrying both `acr_values` and `max_age`.
async fn payments(State(requirement): State<Requirement>, headers: HeaderMap) -> Response {
    let token = bearer_token(&headers);
    let acr = token.as_deref().and_then(access_token_acr);
    let auth_time = token.as_deref().and_then(access_token_auth_time);
    let acr_ok = acr
        .as_deref()
        .is_some_and(|acr| satisfies(acr, requirement.acr_floor, &requirement.order));
    // The age check mirrors the docs: a missing auth_time under a max_age bound fails
    // closed (the freshness cannot be proven), so it never silently passes.
    let age_ok = match requirement.max_age_secs {
        None => true,
        Some(max_age) => {
            auth_time.is_some_and(|auth_time| now_unix_secs().saturating_sub(auth_time) <= max_age)
        }
    };
    if acr_ok && age_ok {
        (StatusCode::OK, "payment authorized\n").into_response()
    } else {
        // RFC 9470 section 3: the challenge carries acr_values and, when an age bound
        // applies, max_age, so the client re-authorizes with BOTH.
        let mut challenge = format!(
            "Bearer error=\"insufficient_user_authentication\", \
             error_description=\"a higher authentication context is required\", \
             acr_values=\"{}\"",
            requirement.acr_floor
        );
        if let Some(max_age) = requirement.max_age_secs {
            use std::fmt::Write as _;
            let _ = write!(challenge, ", max_age={max_age}");
        }
        let mut response = (StatusCode::UNAUTHORIZED, "step-up required\n").into_response();
        if let Ok(value) = header::HeaderValue::from_str(&challenge) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

/// The current wall-clock time in whole seconds since the Unix epoch. This is a
/// STANDALONE sample resource server (a separate process from the IronAuth server), not
/// part of the AS, so it legitimately reads the host wall clock directly rather than the
/// server's determinism seam.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now() // invariant-allow: time-via-env -- standalone sample RS, outside the server clock seam
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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
    access_token_claims(token)?
        .get("acr")?
        .as_str()
        .map(str::to_owned)
}

/// The `auth_time` claim (seconds since the Unix epoch) of a JWT access token, used to
/// enforce `max_age`. A real RS verifies the token first; this reads the claim for the
/// sample only.
fn access_token_auth_time(token: &str) -> Option<u64> {
    access_token_claims(token)?.get("auth_time")?.as_u64()
}

/// The decoded claim object of a JWT access token (its middle segment).
fn access_token_claims(token: &str) -> Option<serde_json::Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64_url_decode(payload)?;
    serde_json::from_slice(&bytes).ok()
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
