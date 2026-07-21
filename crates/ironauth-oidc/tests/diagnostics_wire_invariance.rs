// SPDX-License-Identifier: MIT OR Apache-2.0

//! The HARD wire-vs-diagnostic invariant for the widened client-authentication
//! diagnostics (issue #91), over a real database through the actual token endpoint.
//!
//! The widening surfaces the SPECIFIC assertion reject reason (bad signature, expired,
//! clock skew, audience mismatch, unknown kid, disallowed algorithm) plus the coarse
//! reasons (unknown client, method mismatch, wrong secret) into the out-of-band
//! diagnostic RECORD only. This suite drives EACH reason and asserts the token
//! endpoint's wire response (status, body bytes, and the `WWW-Authenticate` header) is
//! BYTE-IDENTICAL across every one: the opaque `invalid_client` never becomes an oracle
//! for which check failed. The diagnostic record (the correct, specific reason) is the
//! ONLY thing that differs between runs.

mod common;

use axum::http::{StatusCode, header};
use common::{Harness, REDIRECT_URI, form, json};
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::{ClientAuthMethod, JWT_BEARER_ASSERTION_TYPE};

/// An EdDSA signing key from a fixed seed, tagged with `kid`.
fn ed25519_key(kid: &str, seed: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed; 32]).expect("ed25519")
}

/// The public JWK Set JSON for `key`, exactly what a client publishes.
fn jwks_json(key: &SigningKey) -> String {
    JwkSet::from_signing_keys([key])
        .expect("jwk set")
        .to_json()
        .expect("jwks json")
}

/// A signed client assertion with the given claims (`nbf` omitted when 0).
fn build_assertion(
    key: &SigningKey,
    iss: &str,
    sub: &str,
    aud: &str,
    exp: i64,
    jti: &str,
) -> String {
    let claims = serde_json::json!({
        "iss": iss, "sub": sub, "aud": aud, "exp": exp, "iat": 0, "jti": jti,
    });
    let payload = serde_json::to_vec(&claims).expect("serialize claims");
    sign_jws(key, &payload, &EmissionOptions::new()).expect("sign assertion")
}

/// A signed client assertion carrying a future `nbf` (for the not-yet-valid case).
fn build_assertion_with_nbf(
    key: &SigningKey,
    cid: &str,
    aud: &str,
    exp: i64,
    nbf: i64,
    jti: &str,
) -> String {
    let claims = serde_json::json!({
        "iss": cid, "sub": cid, "aud": aud, "exp": exp, "nbf": nbf, "iat": 0, "jti": jti,
    });
    let payload = serde_json::to_vec(&claims).expect("serialize claims");
    sign_jws(key, &payload, &EmissionOptions::new()).expect("sign assertion")
}

/// Flip one base64url character of the signature segment, keeping its length and
/// base64 validity so the assertion is rejected as a bad SIGNATURE (not a malformed
/// structure).
fn tamper_signature(assertion: &str) -> String {
    let mut parts: Vec<&str> = assertion.split('.').collect();
    let sig = parts[2].to_owned();
    let first = sig.chars().next().unwrap_or('A');
    let replacement = if first == 'A' { 'B' } else { 'A' };
    let tampered = format!("{replacement}{}", &sig[1..]);
    parts[2] = &tampered;
    parts.join(".")
}

/// The exchange body for presenting a `private_key_jwt` assertion at the token endpoint.
fn assertion_body(code: &str, assertion: &str) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT_URI),
        ("client_assertion", assertion),
        ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
    ])
}

/// The `WWW-Authenticate` header value of a response's headers, if present.
fn www_authenticate(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[tokio::test]
async fn every_widened_assertion_reason_is_a_byte_identical_invalid_client() {
    let h = Harness::start().await;
    // A private_key_jwt client whose registered JWKS holds exactly the "ck" key.
    let key = ed25519_key("ck", 7);
    // A DIFFERENT key whose kid is NOT registered, for the unknown-kid case.
    let stray = ed25519_key("zzz", 9);
    let jwks = jwks_json(&key);
    let client = h
        .create_jwt_auth_client(ClientAuthMethod::PrivateKeyJwt, Some(&jwks), None, None)
        .await;
    let cid = client.to_string();

    // One failing assertion per widened reason. All are correctly formed enough to
    // reach the specific check that rejects them.
    let cases: Vec<(&str, String)> = vec![
        (
            "assertion_bad_signature",
            tamper_signature(&build_assertion(
                &key,
                &cid,
                &cid,
                h.issuer(),
                3600,
                "jti-badsig",
            )),
        ),
        (
            "assertion_expired",
            build_assertion(&key, &cid, &cid, h.issuer(), -1000, "jti-expired"),
        ),
        (
            "assertion_clock_skew",
            build_assertion_with_nbf(&key, &cid, h.issuer(), 2_000_000, 1_000_000, "jti-nbf"),
        ),
        (
            "assertion_audience_mismatch",
            build_assertion(&key, &cid, &cid, "https://evil.test", 3600, "jti-aud"),
        ),
        (
            // Signed by the stray key, whose kid names no registered verification key.
            "assertion_kid_unknown",
            build_assertion(&stray, &cid, &cid, h.issuer(), 3600, "jti-kid"),
        ),
    ];

    // The ES512 disallowed-algorithm case is hand-crafted (this core excludes ES512),
    // so a garbage signature suffices: it is rejected at the alg stage.
    let alg_case = {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES512","kid":"ck"}"#);
        let claims = serde_json::json!({
            "iss": cid, "sub": cid, "aud": h.issuer(), "exp": 3600, "iat": 0, "jti": "jti-alg",
        });
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims"));
        format!("{head}.{payload}.c2lnbmF0dXJl")
    };
    let mut cases = cases;
    cases.push(("assertion_algorithm_disallowed", alg_case));

    // Drive each case through the REAL token endpoint and collect the wire tuple.
    let mut wires: Vec<(&str, StatusCode, Option<String>, String)> = Vec::new();
    for (name, assertion) in &cases {
        // A fresh valid code per attempt (client auth is checked and fails before the
        // code is redeemed, but a fresh code keeps every request shape identical).
        let code = h.issue_authenticated_code(&cid).await;
        let (status, headers, body) = h.token(&assertion_body(&code, assertion)).await;
        wires.push((name, status, www_authenticate(&headers), body));
    }

    // Every widened reason produced a BYTE-IDENTICAL wire response: same status, same
    // (absent) WWW-Authenticate, and the same opaque body. The reason NEVER leaks.
    let (base_name, base_status, base_www, base_body) = &wires[0];
    for (name, status, www, body) in &wires {
        assert_eq!(
            status, base_status,
            "{name} status differs from {base_name}"
        );
        assert_eq!(
            www, base_www,
            "{name} WWW-Authenticate differs from {base_name}"
        );
        assert_eq!(
            body, base_body,
            "{name} body differs from {base_name}: the wire leaked the reason"
        );
    }
    assert_eq!(
        *base_status,
        StatusCode::UNAUTHORIZED,
        "invalid_client is 401"
    );
    assert_eq!(json(base_body)["error"], "invalid_client");
    assert_eq!(
        json(base_body)["error_description"],
        "client authentication failed",
        "the description is a fixed generic string, never an oracle"
    );
    assert!(
        base_www.is_none(),
        "an assertion (non-Basic) attempt never carries WWW-Authenticate"
    );

    // The RECORD is the only thing that differs: each specific widened reason is present
    // out of band for this client.
    let diags = h.client_auth_diagnostics(&cid).await;
    for (reason, _) in &cases {
        assert!(
            diags.iter().any(|d| &d.failure_reason == reason),
            "the {reason} failure is diagnosed out of band: {diags:?}"
        );
    }
}

#[tokio::test]
async fn secret_path_reasons_share_the_same_invalid_client_wire_response() {
    // The coarse (non-assertion) reasons carry the SAME opaque wire response as the
    // assertion reasons: an unknown client, a method mismatch, and a wrong secret are
    // all a byte-identical invalid_client, and only the diagnostic reason differs.
    let h = Harness::start().await;
    let (post_client, _secret) = h.create_confidential_client(ClientAuthMethod::Post).await;
    let post_id = post_client.to_string();

    // unknown_client: a well-formed but unregistered client id (via the form, so no
    // Basic header and thus no WWW-Authenticate).
    let unknown_id = ironauth_store::ClientId::generate(h.env(), &h.scope()).to_string();
    let unknown_code = h.issue_authenticated_code(&post_id).await;
    let unknown_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &unknown_code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &unknown_id),
        ("client_secret", "irrelevant"),
    ]);
    let (u_status, u_headers, u_body) = h.token(&unknown_body).await;

    // bad_secret: the registered Post client with the wrong secret.
    let bad_code = h.issue_authenticated_code(&post_id).await;
    let bad_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &bad_code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &post_id),
        ("client_secret", "the-wrong-secret"),
    ]);
    let (b_status, b_headers, b_body) = h.token(&bad_body).await;

    // method_mismatch: the Post client presenting as a public client (no secret).
    let mm_code = h.issue_authenticated_code(&post_id).await;
    let mm_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &mm_code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &post_id),
    ]);
    let (m_status, m_headers, m_body) = h.token(&mm_body).await;

    // All three are the byte-identical invalid_client (401, same body, no WWW-Authenticate).
    for (name, status, headers, body) in [
        ("unknown_client", u_status, &u_headers, &u_body),
        ("bad_secret", b_status, &b_headers, &b_body),
        ("method_mismatch", m_status, &m_headers, &m_body),
    ] {
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name} status");
        assert_eq!(json(body)["error"], "invalid_client", "{name} error");
        assert!(
            www_authenticate(headers).is_none(),
            "{name} carries no WWW-Authenticate (a form, not Basic, attempt)"
        );
    }
    assert_eq!(
        u_body, b_body,
        "unknown_client and bad_secret are byte-identical"
    );
    assert_eq!(
        b_body, m_body,
        "bad_secret and method_mismatch are byte-identical"
    );

    // The wrong secret over BASIC is the SAME body and status; the ONLY difference is the
    // added WWW-Authenticate challenge (a transport property, never the reason).
    use base64::Engine;
    let (basic_client, _s) = h.create_confidential_client(ClientAuthMethod::Basic).await;
    let basic_id = basic_client.to_string();
    let basic_code = h.issue_authenticated_code(&basic_id).await;
    let basic_header = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{basic_id}:the-wrong-secret"))
    );
    let basic_form = form(&[
        ("grant_type", "authorization_code"),
        ("code", &basic_code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    let (basic_status, basic_headers, basic_body) =
        h.token_with_auth(&basic_form, Some(&basic_header)).await;
    assert_eq!(
        basic_status,
        StatusCode::UNAUTHORIZED,
        "basic wrong secret status"
    );
    assert_eq!(
        basic_body, b_body,
        "the Basic wrong-secret body is byte-identical to the form paths"
    );
    assert!(
        www_authenticate(&basic_headers).is_some(),
        "the ONLY wire difference for a Basic attempt is the WWW-Authenticate header"
    );

    // The records carry the specific coarse reasons (the wire above never did).
    let post_diags = h.client_auth_diagnostics(&post_id).await;
    assert!(post_diags.iter().any(|d| d.failure_reason == "bad_secret"));
    assert!(
        post_diags
            .iter()
            .any(|d| d.failure_reason == "method_mismatch")
    );
    assert!(
        h.client_auth_diagnostics(&unknown_id)
            .await
            .iter()
            .any(|d| d.failure_reason == "unknown_client"),
        "the unknown client is diagnosed out of band"
    );
}
