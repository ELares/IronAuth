// SPDX-License-Identifier: MIT OR Apache-2.0

//! A fake upstream OIDC provider for the emulator (issue #121, criterion 4).
//!
//! It authenticates a fixed identity, always, immediately. That is the entire feature: a
//! federation login has an upstream in it, and testing one offline means having an upstream
//! that needs no network, no accounts, and no human.
//!
//! # Its own listener, like the capture sink and for the same reason
//!
//! This provider authenticates ANYONE who asks, with no credential of any kind. Mounting it
//! on the production router would make safety a matter of a conditional staying correct
//! forever; on its own loopback listener, started only by `ironauth dev`, the production
//! router has no such route to leak. The guarantee is structural.
//!
//! # It signs with the real JOSE path
//!
//! The `id_token` is signed through `ironauth_jose::sign_jws` and the JWKS is projected with
//! `JwkSet::from_signing_keys`, the same function the server's own JWKS endpoint uses. A
//! hand-rolled JWK would be a second encoder of the same bytes, which this workspace has
//! already been bitten by once (see `s256_challenge`'s documentation).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use ironauth_jose::{EmissionOptions, JwkSet, SigningKey};

/// The identity the fake provider always authenticates.
pub const FAKE_SUBJECT: &str = "upstream-user-1";
/// The email it always asserts.
pub const FAKE_EMAIL: &str = "upstream@example.test";
/// The `client_id` it accepts. It accepts any, but this is the one the emulator registers.
pub const FAKE_CLIENT_ID: &str = "ironauth-dev-upstream";
/// The authorization code it always returns.
pub const FAKE_CODE: &str = "upstream-code";

/// The provider's discovery document.
#[must_use]
pub fn discovery(issuer: &str) -> String {
    // Built with `serde_json`, never by hand. The first version assembled it as a raw string
    // with backslash line-continuations, which raw strings do NOT honour: the document went
    // out with literal backslashes and newlines inside it and parsed nowhere. A relying party
    // reads this with a real parser, so it is built with one.
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["openid", "email"],
    })
    .to_string()
}

/// The provider's JWKS, projected through the SAME function the server's own endpoint uses.
///
/// # Errors
///
/// A message when the key cannot be projected.
pub fn jwks(key: &SigningKey) -> Result<String, String> {
    let set = JwkSet::from_signing_keys([key]).map_err(|error| format!("{error:?}"))?;
    serde_json::to_string(&serde_json::json!({ "keys": set.keys() }))
        .map_err(|error| error.to_string())
}

/// The `id_token` this provider issues.
///
/// `nonce` is echoed when the request carried one, because a relying party that sent one will
/// reject a token without it, and an upstream that quietly dropped it would fail the
/// federation login for a reason that looks nothing like the omission.
///
/// # Errors
///
/// A message when signing fails.
pub fn id_token(
    key: &SigningKey,
    issuer: &str,
    audience: &str,
    now_secs: i64,
    nonce: Option<&str>,
) -> Result<String, String> {
    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": FAKE_SUBJECT,
        "aud": audience,
        "email": FAKE_EMAIL,
        "email_verified": true,
        "iat": now_secs,
        "exp": now_secs + 3600,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = serde_json::json!(nonce);
    }
    let payload = serde_json::to_vec(&claims).map_err(|error| error.to_string())?;
    ironauth_jose::sign_jws(key, &payload, &EmissionOptions::new())
        .map_err(|error| format!("signing the upstream id_token: {error:?}"))
}

/// One parsed query parameter lookup.
#[must_use]
pub fn query_param(target: &str, name: &str) -> Option<String> {
    let query = target.split_once('?').map(|(_, query)| query)?;
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return Some(crate::loopback_flow::percent_decode_public(value));
            }
        }
    }
    None
}

/// The redirect this provider answers an authorization request with.
///
/// Straight back to the relying party with a fixed code. There is no login page and no
/// consent: an upstream that required either could not be driven by a test, which is the
/// whole reason this exists.
#[must_use]
pub fn authorize_redirect(target: &str) -> String {
    let redirect_uri = query_param(target, "redirect_uri").unwrap_or_default();
    let state = query_param(target, "state").unwrap_or_default();
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}code={FAKE_CODE}&state={state}")
}

/// Serve the fake provider until the process exits.
pub fn serve(listener: TcpListener, key: SigningKey, issuer: String) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                continue;
            }
            let target = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
            let path = target.split('?').next().unwrap_or("/");

            let response = match path {
                "/.well-known/openid-configuration" => json_response(&discovery(&issuer)),
                "/jwks.json" => match jwks(&key) {
                    Ok(body) => json_response(&body),
                    Err(_) => {
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_owned()
                    }
                },
                "/authorize" => {
                    let location = authorize_redirect(&target);
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\n\
                         Content-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                }
                "/token" => {
                    // The `nonce` a real provider would have bound at /authorize is not
                    // replayed here: this provider keeps no state, which is a deliberate
                    // limitation and is why it is a TEST double rather than a provider.
                    match id_token(&key, &issuer, FAKE_CLIENT_ID, 0, None) {
                        Ok(token) => json_response(
                            &serde_json::json!({
                                "access_token": "upstream-access",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "id_token": token,
                            })
                            .to_string(),
                        ),
                        Err(_) => "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
                            .to_owned(),
                    }
                }
                _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
            };
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
}

/// A JSON response with `no-store`, because everything this serves is test material.
fn json_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_points_at_its_own_endpoints() {
        let doc = discovery("http://127.0.0.1:9999");
        // PARSED, not substring-matched: the first version satisfied a `contains` check
        // while being unparseable, which is how the defect shipped past its own test.
        let parsed: serde_json::Value =
            serde_json::from_str(&doc).expect("discovery must be valid JSON");
        assert_eq!(parsed["issuer"], "http://127.0.0.1:9999");
        assert_eq!(parsed["jwks_uri"], "http://127.0.0.1:9999/jwks.json");
        assert_eq!(parsed["id_token_signing_alg_values_supported"][0], "EdDSA");
    }

    #[test]
    fn the_authorize_redirect_carries_the_code_and_echoes_state() {
        let location = authorize_redirect(
            "/authorize?redirect_uri=http%3A%2F%2Fx%2Fcb&state=abc&scope=openid",
        );
        assert!(location.starts_with("http://x/cb?"), "{location}");
        assert!(
            location.contains(&format!("code={FAKE_CODE}")),
            "{location}"
        );
        // The state MUST come back: a relying party that sent one and got none refuses the
        // response, and the failure would look like a redirect problem rather than an echo.
        assert!(location.contains("state=abc"), "{location}");
    }

    /// A redirect that already carries a query gets `&`, not a second `?`, which would make
    /// the whole thing unparseable to the relying party.
    #[test]
    fn a_redirect_with_an_existing_query_is_appended_to() {
        let location =
            authorize_redirect("/authorize?redirect_uri=http%3A%2F%2Fx%2Fcb%3Fa%3D1&state=s");
        assert!(location.starts_with("http://x/cb?a=1&code="), "{location}");
    }
}
