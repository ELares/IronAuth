// SPDX-License-Identifier: MIT OR Apache-2.0

//! A fake upstream OIDC provider for the emulator (issue #121, criterion 4).
//!
//! It authenticates a fixed identity, always, immediately. That is the entire feature: a
//! federation login has an upstream in it, and testing one offline means having an upstream
//! that needs no network, no accounts, and no human.
//!
//! # Why it lives here and not in the CLI crate that boots it
//!
//! `ironauth dev` is the only thing that SERVES it, which is the argument for keeping it in
//! that crate. The argument against, and the reason it moved: criterion 4 asks that this
//! provider complete a federation login, and the federation suite lives here. Left in the
//! binary crate it could only have been tested by a SECOND hand-rolled upstream standing in
//! for it, which is a test of the stand-in. A double whose conformance is asserted against a
//! different double is not evidence about the one that ships.
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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use ironauth_env::Clock;
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
                return Some(crate::util::percent_decode(value));
            }
        }
    }
    None
}

/// The separator between the fixed code prefix and the encoded `nonce`. A `.` is not in the
/// base64url alphabet, so it cannot occur inside the encoded half and the split is unambiguous.
const CODE_NONCE_SEPARATOR: char = '.';

/// The authorization code this provider issues for an authorization request carrying `nonce`.
///
/// # The nonce rides IN the code, because this provider keeps no state
///
/// OIDC Core 3.1.2.1 binds the `nonce` at the authorization request and requires the ID token
/// to echo it; a relying party that sent one rejects a token without it. A stateful provider
/// remembers the pairing between the two legs. This one deliberately remembers nothing, so it
/// carries the nonce across the legs the only other way available: inside the value that
/// travels both directions. The relying party treats the code as opaque, which is exactly what
/// makes this safe to do.
///
/// This used to be a fixed string and the ID token carried no `nonce` at all, described in a
/// comment as a deliberate limitation of a test double. It was not a limitation of the double;
/// it made the double unusable for the one thing it exists to do, and no test said so.
#[must_use]
pub fn authorization_code(nonce: Option<&str>) -> String {
    match nonce {
        None => FAKE_CODE.to_owned(),
        Some(nonce) => format!(
            "{FAKE_CODE}{CODE_NONCE_SEPARATOR}{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, nonce)
        ),
    }
}

/// The `nonce` carried by `code`, if it carries one.
#[must_use]
pub fn nonce_from_code(code: &str) -> Option<String> {
    let (prefix, encoded) = code.split_once(CODE_NONCE_SEPARATOR)?;
    if prefix != FAKE_CODE {
        return None;
    }
    let bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded).ok()?;
    String::from_utf8(bytes).ok()
}

/// The redirect this provider answers an authorization request with.
///
/// Straight back to the relying party with a code. There is no login page and no consent: an
/// upstream that required either could not be driven by a test, which is the whole reason this
/// exists. The request's `nonce`, if any, rides inside the code (see [`authorization_code`]).
#[must_use]
pub fn authorize_redirect(target: &str) -> String {
    let redirect_uri = query_param(target, "redirect_uri").unwrap_or_default();
    let state = query_param(target, "state").unwrap_or_default();
    let code = authorization_code(query_param(target, "nonce").as_deref());
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    format!("{redirect_uri}{separator}code={code}&state={state}")
}

/// One parsed `application/x-www-form-urlencoded` field from a request body.
#[must_use]
pub fn form_field(body: &str, name: &str) -> Option<String> {
    for pair in body.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == name {
                return Some(crate::util::percent_decode(value));
            }
        }
    }
    None
}

/// The whole provider as a PURE function of one request: the raw request target, the request
/// body, and the wall clock to stamp tokens with.
///
/// `serve` is a socket loop around this and nothing else. The clock arrives as a parameter,
/// read off the [`Clock`] seam by the caller, because the integration suite runs on a fixed
/// test clock and a provider reading the host's would issue tokens that clock sees as
/// far-future. That the value USED to be hardcoded to `0` is why the parameter exists: every
/// token this provider issued expired in 1970, so no relying party checking `exp` could
/// ever have accepted one.
#[must_use]
pub fn respond(target: &str, body: &str, key: &SigningKey, issuer: &str, now_secs: i64) -> String {
    let path = target.split('?').next().unwrap_or("/");
    match path {
        "/.well-known/openid-configuration" => json_response(&discovery(issuer)),
        "/jwks.json" => match jwks(key) {
            Ok(body) => json_response(&body),
            Err(_) => "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_owned(),
        },
        "/authorize" => {
            let location = authorize_redirect(target);
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        }
        "/token" => {
            // The `nonce` the relying party bound at /authorize comes back inside the code it
            // is now redeeming, which is how a stateless provider echoes it.
            let nonce = form_field(body, "code").as_deref().and_then(nonce_from_code);
            match id_token(key, issuer, FAKE_CLIENT_ID, now_secs, nonce.as_deref()) {
                Ok(token) => json_response(
                    &serde_json::json!({
                        "access_token": "upstream-access",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "id_token": token,
                    })
                    .to_string(),
                ),
                Err(_) => {
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_owned()
                }
            }
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned(),
    }
}

/// The largest request body this provider will buffer. A form-encoded token request is a few
/// hundred bytes.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Serve the fake provider until the process exits, stamping tokens off `clock`.
pub fn serve(listener: TcpListener, key: SigningKey, issuer: String, clock: Arc<dyn Clock>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let target = line.split_whitespace().nth(1).unwrap_or("/").to_owned();

            // Headers, only to learn the body length. A token request that arrived without a
            // Content-Length carries no body, which `respond` reads as "no code" and answers
            // with a nonce-free token, so the relying party refuses it rather than this
            // blocking forever on a read that will never fill.
            let mut content_length = 0_usize;
            loop {
                let mut header = String::new();
                // A closed connection and a read error both end the header block: there is no
                // more request to parse either way.
                match reader.read_line(&mut header) {
                    Ok(1..) => {}
                    Ok(0) | Err(_) => break,
                }
                let trimmed = header.trim_end();
                if trimmed.is_empty() {
                    break;
                }
                if let Some((name, value)) = trimmed.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
            // Capped, because `content_length` is a number the CLIENT chose and the buffer is
            // allocated before a single body byte arrives: an unbounded read here lets one
            // request declaring a multi-gigabyte body take the process down without sending
            // it. A token request is a few hundred bytes; anything past the cap is not one.
            let content_length = content_length.min(MAX_BODY_BYTES);
            let mut body = vec![0_u8; content_length];
            if content_length > 0 && reader.read_exact(&mut body).is_err() {
                continue;
            }
            let body = String::from_utf8_lossy(&body).into_owned();

            let now_secs = clock
                .now_utc()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
                });
            let response = respond(&target, &body, &key, &issuer, now_secs);
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

    /// The whole point of the code format: what the relying party bound at /authorize is what
    /// comes back at /token, with no state kept in between.
    #[test]
    fn the_nonce_survives_the_round_trip_through_the_code() {
        let nonce = "Xy9_-abcDEF123";
        let code = authorization_code(Some(nonce));
        assert_ne!(code, FAKE_CODE, "a nonce-bearing code is not the bare code");
        assert_eq!(nonce_from_code(&code).as_deref(), Some(nonce));
    }

    /// A request that bound no nonce gets the bare code, and reading a nonce out of it yields
    /// nothing rather than an empty string, which would be echoed as `"nonce": ""` and match a
    /// relying party that bound nothing only by accident.
    #[test]
    fn a_code_for_a_request_without_a_nonce_carries_none() {
        let code = authorization_code(None);
        assert_eq!(code, FAKE_CODE);
        assert_eq!(nonce_from_code(&code), None);
    }

    /// The nonce reaches the ID token through the SAME path the relying party drives: an
    /// /authorize whose redirect it follows, then a /token carrying the code it was handed.
    /// Asserting on `authorization_code` alone would prove the encoding and not the wiring,
    /// which is the half that was missing.
    #[test]
    fn the_token_endpoint_echoes_the_nonce_bound_at_the_authorize_leg() {
        let key = SigningKey::ed25519_from_seed(Some("k".to_owned()), &[3_u8; 32]).expect("key");
        let bound = "nonce-from-the-relying-party";

        let redirect = authorize_redirect(&format!(
            "/authorize?redirect_uri=http%3A%2F%2Frp%2Fcb&state=s&nonce={bound}"
        ));
        let code = query_param(&redirect, "code").expect("the redirect carries a code");

        let response = respond(
            "/token",
            &format!("grant_type=authorization_code&code={code}"),
            &key,
            "http://up",
            1_700_000_000,
        );
        let body = response.split_once("\r\n\r\n").expect("body").1;
        let token = serde_json::from_str::<serde_json::Value>(body).expect("json")["id_token"]
            .as_str()
            .expect("id_token")
            .to_owned();
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                token.split('.').nth(1).expect("payload segment"),
            )
            .expect("base64"),
        )
        .expect("claims");

        assert_eq!(
            claims["nonce"].as_str(),
            Some(bound),
            "the ID token must echo the nonce the relying party bound, or it is refused"
        );
        // The clock reaches the token too. Hardcoded to zero, `exp` landed in 1970 and every
        // token this provider issued was already expired.
        assert_eq!(claims["iat"].as_i64(), Some(1_700_000_000));
        assert_eq!(claims["exp"].as_i64(), Some(1_700_003_600));
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
