// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generic OIDC UPSTREAM: discovery, code exchange, and the security-critical
//! validation of an upstream ID token (issue #75, PR B).
//!
//! A declarative connector (issue #75, PR A) describes an OIDC-shaped upstream as
//! pure DATA. This module turns that data into a federated login WITHOUT a line of
//! per-provider code: it resolves the connector's endpoints (from an explicit set or
//! a fetched discovery document), exchanges the authorization code, and VALIDATES the
//! returned upstream ID token. Adding a provider is a stored definition, never a
//! release.
//!
//! # The two hardened seams
//!
//! Every outbound call (discovery, JWKS, token exchange, `UserInfo`) rides the one
//! SSRF-hardened [`ironauth_fetch::Fetcher`], so a connector URL that resolves to a
//! loopback or internal address is [`ironauth_fetch::FetchError::Blocked`] on the wire
//! (mapped here to [`ConnectorError::UpstreamUnavailable`]); this module writes no ad
//! hoc HTTP.
//!
//! The upstream ID token is validated through the ONE JOSE entry point
//! ([`ironauth_jose::verify`]): this module builds a [`VerificationPolicy`] pinning the
//! algorithm allowlist (the upstream-advertised or connector-allowed algorithms
//! INTERSECTED with the JOSE core's allowlist), the trusted keys (the cached upstream
//! JWKS, never a token-embedded key), the expected issuer (the configured connector
//! issuer), and the expected audience (the connector's client id), then verifies the
//! bound `nonce`. It writes NO crypto: `alg: none`, algorithm confusion, an unknown
//! `kid`, a forged issuer, a wrong audience, and an expired token ALL die inside
//! [`ironauth_jose::verify`], and every rejection maps to
//! [`ConnectorError::UpstreamProtocol`] so no identity is ever provisioned from an
//! unverified token.

use ironauth_connector::{ConnectorError, ResolvedEndpoints, discovery_url, parse_discovery};
use ironauth_env::Clock;
use ironauth_fetch::{FetchError, FetchPurpose, FetchRequest, Fetcher};
use ironauth_jose::{JwsAlgorithm, TrustedKey, VerificationPolicy, verify};

use crate::util::percent_encode_query;

/// The verified, honest identity recovered from a validated upstream ID token (issue
/// #75). Every field derives from claims that passed [`ironauth_jose::verify`]; nothing
/// here is trusted from an unverified token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpstreamIdentity {
    /// The upstream stable subject (`sub`): the federated user's key at the provider.
    pub subject: String,
    /// The upstream email, if the token carried one. Its trustworthiness is governed
    /// by the connector's `email_verified_trust` capability; PR B provisions a minimal
    /// identity and PR C generalizes claim mapping.
    pub email: Option<String>,
    /// The upstream's OWN asserted `amr` tokens, carried through verbatim for an honest
    /// federated `amr` passthrough (never re-asserted as a LOCAL factor). Empty when the
    /// upstream asserted none.
    pub upstream_amr: Vec<String>,
    /// The upstream's OWN `acr`, retained for the honest federated context. [`None`]
    /// when the upstream asserted none.
    pub upstream_acr: Option<String>,
    /// The upstream `auth_time` in epoch SECONDS, if the token asserted one. When
    /// absent the callback instant (from the clock seam) is the honest `auth_time`.
    pub auth_time_secs: Option<i64>,
}

/// The JOSE core's full signature-algorithm allowlist. HMAC and `none` are absent by
/// construction (see [`ironauth_jose`]), so intersecting any upstream-advertised list
/// with this set can never admit a symmetric or unsecured algorithm.
fn jose_supported_algs() -> Vec<JwsAlgorithm> {
    vec![
        JwsAlgorithm::EdDsa,
        JwsAlgorithm::Es256,
        JwsAlgorithm::Es384,
        JwsAlgorithm::Rs256,
        JwsAlgorithm::Rs384,
        JwsAlgorithm::Rs512,
        JwsAlgorithm::Ps256,
        JwsAlgorithm::Ps384,
        JwsAlgorithm::Ps512,
    ]
}

/// Resolve the algorithm allowlist for verifying an upstream ID token: the
/// upstream-advertised `id_token_signing_alg_values_supported` (or the connector's
/// configured algorithms) INTERSECTED with the JOSE core's allowlist.
///
/// When `advertised` is [`None`] (an explicit-endpoint connector advertises nothing),
/// the full JOSE allowlist governs, so any core-supported algorithm the upstream
/// actually signs with is accepted (and `none`/HMAC remain impossible). When
/// `advertised` is present, an unrecognized or non-core name is dropped, so the result
/// is exactly the algorithms BOTH sides can do.
#[must_use]
pub fn resolve_alg_allowlist(advertised: Option<&[String]>) -> Vec<JwsAlgorithm> {
    let Some(names) = advertised else {
        return jose_supported_algs();
    };
    let mut algs: Vec<JwsAlgorithm> = Vec::new();
    for name in names {
        if let Some(alg) = JwsAlgorithm::from_jose_name(name) {
            if !algs.contains(&alg) {
                algs.push(alg);
            }
        }
    }
    algs
}

/// Map an [`ironauth_fetch::FetchError`] to the transient [`ConnectorError::UpstreamUnavailable`].
/// A blocked SSRF target, a timeout, a redirect, an oversized body, or a transport
/// failure all mean the exchange could not COMPLETE, so issue #76 may retry or trip a
/// breaker. The message is non-sensitive (it never names a resolved address).
fn unavailable(err: &FetchError) -> ConnectorError {
    ConnectorError::UpstreamUnavailable(err.to_string())
}

/// Resolve a connector's endpoints, fetching and parsing the upstream discovery
/// document for an issuer-form connector (validating the mix-up defence) or resolving
/// an explicit-endpoint connector directly.
///
/// The `issuer` argument, when [`Some`], is the configured connector issuer whose
/// `.well-known/openid-configuration` is fetched (through [`FetchPurpose::FederationDiscovery`])
/// and whose in-document issuer must match. When [`None`], `explicit` is resolved.
///
/// # Errors
///
/// [`ConnectorError::UpstreamUnavailable`] if the discovery fetch is blocked, times
/// out, or returns a non-2xx; [`ConnectorError::UpstreamProtocol`] if the document is
/// malformed or its issuer does not match (the mix-up defence); or
/// [`ConnectorError::Config`] if neither an issuer nor an explicit set was supplied.
pub async fn fetch_discovery(
    fetcher: &Fetcher,
    issuer: &str,
    allow_http: bool,
) -> Result<ResolvedEndpoints, ConnectorError> {
    let url = discovery_url(issuer);
    let mut request = FetchRequest::get(FetchPurpose::FederationDiscovery, url);
    if allow_http {
        request = request.allow_plaintext_http();
    }
    let response = fetcher
        .fetch(request)
        .await
        .map_err(|err| unavailable(&err))?;
    if !response.status().is_success() {
        return Err(ConnectorError::UpstreamUnavailable(format!(
            "the discovery endpoint returned HTTP {}",
            response.status().as_u16()
        )));
    }
    parse_discovery(response.body(), issuer)
}

/// Exchange an authorization `code` at the upstream token endpoint, returning the raw
/// upstream ID token string (still to be VALIDATED by [`validate_upstream_id_token`]).
///
/// The connector's client secret authenticates the request (form-encoded client
/// credentials) alongside the PKCE `code_verifier` when one was used. The request rides
/// the hardened fetcher through [`FetchPurpose::FederationToken`].
///
/// # Errors
///
/// [`ConnectorError::UpstreamUnavailable`] if the exchange is blocked, times out, or
/// returns a non-2xx; [`ConnectorError::UpstreamProtocol`] if the response is not JSON
/// or carries no `id_token`.
pub async fn exchange_code(
    fetcher: &Fetcher,
    request: TokenExchange<'_>,
    allow_http: bool,
) -> Result<String, ConnectorError> {
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
        percent_encode_query(request.code),
        percent_encode_query(request.redirect_uri),
        percent_encode_query(request.client_id),
        percent_encode_query(request.client_secret),
    );
    if let Some(verifier) = request.code_verifier {
        form.push_str("&code_verifier=");
        form.push_str(&percent_encode_query(verifier));
    }
    let mut http = FetchRequest::new(
        FetchPurpose::FederationToken,
        axum::http::Method::POST,
        request.token_url.to_owned(),
    )
    .header(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/x-www-form-urlencoded"),
    )
    .body(form.into_bytes());
    if allow_http {
        http = http.allow_plaintext_http();
    }
    let response = fetcher.fetch(http).await.map_err(|err| unavailable(&err))?;
    if !response.status().is_success() {
        return Err(ConnectorError::UpstreamUnavailable(format!(
            "the token endpoint returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let body: serde_json::Value = serde_json::from_slice(response.body()).map_err(|_| {
        ConnectorError::UpstreamProtocol("the token response is not JSON".to_owned())
    })?;
    body.get("id_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            ConnectorError::UpstreamProtocol("the token response carried no id_token".to_owned())
        })
}

/// The inputs for a token exchange, bundled to keep the argument count readable.
#[derive(Debug, Clone, Copy)]
pub struct TokenExchange<'a> {
    /// The upstream token endpoint URL.
    pub token_url: &'a str,
    /// The authorization code returned to the callback.
    pub code: &'a str,
    /// The callback redirect URI, echoed exactly.
    pub redirect_uri: &'a str,
    /// The connector's registered client id.
    pub client_id: &'a str,
    /// The connector's unsealed client secret.
    pub client_secret: &'a str,
    /// The PKCE `code_verifier` when the authorize leg sent an `S256` challenge.
    pub code_verifier: Option<&'a str>,
}

/// The inputs for validating an upstream ID token, bundled to keep the argument count
/// readable and the call site self-documenting.
#[derive(Debug, Clone, Copy)]
pub struct UpstreamTokenPolicy<'a> {
    /// The configured connector issuer, matched EXACTLY against the token's `iss`.
    pub expected_issuer: &'a str,
    /// The connector's client id, matched EXACTLY against the token's `aud`.
    pub expected_audience: &'a str,
    /// The single-use `nonce` bound at the authorize leg, matched EXACTLY against the
    /// token's `nonce` claim (replay defence).
    pub expected_nonce: &'a str,
    /// The resolved algorithm allowlist (see [`resolve_alg_allowlist`]).
    pub allowed_algs: &'a [JwsAlgorithm],
}

/// Validate an upstream ID token through the JOSE core and recover the honest
/// federated identity (issue #75, the security crux).
///
/// `keys` are the cached UPSTREAM trusted keys (from the per-connector JWKS cache); an
/// EMPTY set fails closed as [`ConnectorError::UpstreamUnavailable`] (the JWKS could not
/// be resolved, for example because a private-range `jwks_uri` was blocked). The policy
/// pins the algorithm allowlist, the trusted keys, the expected issuer and audience;
/// [`ironauth_jose::verify`] performs the ONE signature check and enforces
/// `iss`/`aud`/`exp`/`nbf`. The bound `nonce` is checked here against the verified
/// claims. Every verification failure is [`ConnectorError::UpstreamProtocol`], so no
/// identity is produced from an unverified token.
///
/// # Errors
///
/// [`ConnectorError::UpstreamUnavailable`] for an empty key set;
/// [`ConnectorError::Config`] for an unbuildable policy (an empty issuer or audience, a
/// connector misconfiguration); [`ConnectorError::UpstreamProtocol`] for any token
/// rejection (`alg: none`, algorithm confusion, an unknown `kid`, a forged issuer, a
/// wrong audience, an expired token, a `nonce` mismatch, or a missing `sub`).
pub fn validate_upstream_id_token(
    token: &str,
    keys: Vec<TrustedKey>,
    policy: UpstreamTokenPolicy<'_>,
    clock: &dyn Clock,
) -> Result<VerifiedUpstreamIdentity, ConnectorError> {
    if keys.is_empty() {
        return Err(ConnectorError::UpstreamUnavailable(
            "the upstream published no usable signing key (empty JWKS)".to_owned(),
        ));
    }
    if policy.allowed_algs.is_empty() {
        return Err(ConnectorError::UpstreamProtocol(
            "the upstream advertised no signing algorithm the core can verify".to_owned(),
        ));
    }
    let verification = VerificationPolicy::new(
        policy.allowed_algs.to_vec(),
        keys,
        policy.expected_issuer,
        policy.expected_audience,
    )
    .map_err(|err| ConnectorError::Config(err.to_string()))?;

    let verified = verify(token, &verification, clock)
        .map_err(|err| ConnectorError::UpstreamProtocol(err.to_string()))?;
    let claims = verified.claims();

    // The bound nonce (RFC OIDC Core 3.1.2.1): the token's nonce must EXACTLY equal the
    // single-use value bound at the authorize leg. A missing or mismatched nonce is a
    // replay or a forged callback, so it is rejected as a protocol fault.
    let nonce_ok = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .is_some_and(|nonce| nonce == policy.expected_nonce);
    if !nonce_ok {
        return Err(ConnectorError::UpstreamProtocol(
            "the upstream ID token nonce did not match the bound value".to_owned(),
        ));
    }

    let subject = claims
        .subject()
        .ok_or_else(|| {
            ConnectorError::UpstreamProtocol("the upstream ID token carried no sub".to_owned())
        })?
        .to_owned();

    Ok(VerifiedUpstreamIdentity {
        subject,
        email: claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        upstream_amr: amr_from_claims(claims.get("amr")),
        upstream_acr: claims
            .get("acr")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        auth_time_secs: claims.get("auth_time").and_then(serde_json::Value::as_i64),
    })
}

/// Extract the upstream `amr` as a list of strings, accepting either a JSON array of
/// strings (the OIDC form) or a single bare string, and dropping any non-string member.
fn amr_from_claims(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        Some(serde_json::Value::String(single)) => vec![single.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ironauth_env::Env;
    use ironauth_jose::{EmissionOptions, SigningKey, TrustedKey, sign_jws};

    use super::*;

    // The loopback-server / injected-dialer harness tests exercise the outbound fetch
    // path and so need the `testing` feature (for the plaintext-http resolver constructor)
    // and the ironauth-fetch `test-harness` seams. The pure ID-token-validation crux tests
    // above need neither, so they always compile.
    #[cfg(feature = "testing")]
    use ironauth_fetch::{FetchLimits, Fetcher, RecordingDialer, StaticResolver};
    #[cfg(feature = "testing")]
    use ironauth_jose::JwkSet;
    #[cfg(feature = "testing")]
    use std::net::{IpAddr, SocketAddr};
    #[cfg(feature = "testing")]
    use std::sync::Arc;
    #[cfg(feature = "testing")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(feature = "testing")]
    use tokio::net::TcpListener;

    #[cfg(feature = "testing")]
    use crate::federation_jwks::FederationKeyResolver;

    const ISSUER: &str = "https://upstream.example";
    const CLIENT_ID: &str = "ironauth-at-upstream";
    const NONCE: &str = "n-0S6_WzA2Mj";

    fn upstream_key() -> SigningKey {
        SigningKey::ed25519_from_seed(Some("up".to_owned()), &[9_u8; 32]).expect("upstream key")
    }

    fn trusted(key: &SigningKey) -> Vec<TrustedKey> {
        vec![key.verifying_key().expect("verifying key")]
    }

    fn sign(key: &SigningKey, claims: &serde_json::Value) -> String {
        let payload = serde_json::to_vec(claims).expect("serialize");
        sign_jws(key, &payload, &EmissionOptions::new().with_typ("JWT")).expect("sign")
    }

    fn id_token(key: &SigningKey, extra: serde_json::Value) -> String {
        let mut claims = serde_json::json!({
            "iss": ISSUER,
            "sub": "upstream-subject-123",
            "aud": CLIENT_ID,
            "exp": 4_102_444_800_i64, // year 2100
            "iat": 0,
            "nonce": NONCE,
        });
        if let (serde_json::Value::Object(base), serde_json::Value::Object(more)) =
            (&mut claims, extra)
        {
            for (k, v) in more {
                base.insert(k, v);
            }
        }
        sign(key, &claims)
    }

    fn policy(algs: &[JwsAlgorithm]) -> UpstreamTokenPolicy<'_> {
        UpstreamTokenPolicy {
            expected_issuer: ISSUER,
            expected_audience: CLIENT_ID,
            expected_nonce: NONCE,
            allowed_algs: algs,
        }
    }

    fn manual_clock() -> (Env, std::sync::Arc<ironauth_env::ManualClock>) {
        Env::deterministic(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            1,
        )
    }

    // ---- The security crux: upstream ID-token validation ----

    #[test]
    fn a_valid_upstream_id_token_yields_the_honest_identity() {
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let algs = jose_supported_algs();
        let token = id_token(
            &key,
            serde_json::json!({ "email": "user@upstream.example", "amr": ["pwd", "otp"], "acr": "aal2", "auth_time": 1_699_999_000 }),
        );
        let identity =
            validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
                .expect("valid token accepted");
        assert_eq!(identity.subject, "upstream-subject-123");
        assert_eq!(identity.email.as_deref(), Some("user@upstream.example"));
        assert_eq!(
            identity.upstream_amr,
            vec!["pwd".to_owned(), "otp".to_owned()]
        );
        assert_eq!(identity.upstream_acr.as_deref(), Some("aal2"));
        assert_eq!(identity.auth_time_secs, Some(1_699_999_000));
    }

    #[test]
    fn alg_none_is_rejected_by_the_jose_core() {
        // A hand-crafted unsecured token (alg:none, empty signature) dies in verify.
        let (env, _clock) = manual_clock();
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let body = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": ISSUER, "sub": "x", "aud": CLIENT_ID, "exp": 4_102_444_800_i64, "nonce": NONCE
            }))
            .unwrap(),
        );
        let token = format!("{head}.{body}.");
        let key = upstream_key();
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("alg=none rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn algorithm_confusion_is_rejected() {
        // The token claims RS256 but the trusted key is Ed25519: the key-family mismatch
        // dies in verify (the classic RS/EC/Ed confusion is inexpressible against a
        // family-typed key).
        let (env, _clock) = manual_clock();
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"up"}"#);
        let body = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": ISSUER, "sub": "x", "aud": CLIENT_ID, "exp": 4_102_444_800_i64, "nonce": NONCE
            }))
            .unwrap(),
        );
        let token = format!("{head}.{body}.c2ln");
        let key = upstream_key();
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("alg confusion rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn an_unknown_kid_is_rejected() {
        // A token naming a kid no trusted key answers to is rejected (never a key source).
        let (env, _clock) = manual_clock();
        let signer = SigningKey::ed25519_from_seed(Some("other".to_owned()), &[1_u8; 32]).unwrap();
        let token = id_token(&signer, serde_json::json!({}));
        let key = upstream_key(); // trusted set only has kid "up"
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("unknown kid rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_forged_issuer_is_rejected() {
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({ "iss": "https://evil.example" }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("forged iss rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_wrong_audience_is_rejected() {
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({ "aud": "some-other-client" }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("wrong aud rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let key = upstream_key();
        let (env, _clock) = manual_clock(); // now = 1_700_000_000
        let token = id_token(&key, serde_json::json!({ "exp": 1_600_000_000_i64 }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("expired rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        // Signed with a DIFFERENT key that reuses the trusted kid: the kid matches but the
        // signature does not verify against the trusted key.
        let (env, _clock) = manual_clock();
        let forger = SigningKey::ed25519_from_seed(Some("up".to_owned()), &[42_u8; 32]).unwrap();
        let token = id_token(&forger, serde_json::json!({}));
        let key = upstream_key();
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("forged signature rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_nonce_mismatch_is_rejected_even_when_the_signature_is_valid() {
        // A validly-signed token whose nonce does not match the bound value is a replay
        // or forged callback: rejected as a protocol fault, no identity produced.
        let key = upstream_key();
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({ "nonce": "attacker-chosen" }));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("nonce mismatch rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    #[test]
    fn an_empty_key_set_fails_closed_as_unavailable() {
        let (env, _clock) = manual_clock();
        let key = upstream_key();
        let token = id_token(&key, serde_json::json!({}));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, Vec::new(), policy(&algs), env.clock())
            .expect_err("empty keys fail closed");
        assert!(
            matches!(err, ConnectorError::UpstreamUnavailable(_)),
            "{err:?}"
        );
    }

    #[test]
    fn the_alg_allowlist_is_the_intersection_with_the_core() {
        // An upstream advertising a mix of core and non-core algs yields only the core ones.
        let advertised = vec![
            "EdDSA".to_owned(),
            "ES256".to_owned(),
            "HS256".to_owned(), // never in the core
            "none".to_owned(),  // never in the core
            "ES512".to_owned(), // not a core alg
        ];
        let algs = resolve_alg_allowlist(Some(&advertised));
        assert_eq!(algs, vec![JwsAlgorithm::EdDsa, JwsAlgorithm::Es256]);
        // No advertised list -> the full core allowlist.
        assert_eq!(resolve_alg_allowlist(None).len(), 9);
    }

    #[test]
    fn a_token_signed_with_a_non_allowlisted_alg_is_rejected() {
        // The upstream advertised only ES256, but the token is EdDSA: not on the allowlist.
        let key = upstream_key(); // EdDSA
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({}));
        let algs = resolve_alg_allowlist(Some(&["ES256".to_owned()]));
        let err = validate_upstream_id_token(&token, trusted(&key), policy(&algs), env.clock())
            .expect_err("non-allowlisted alg rejected");
        assert!(
            matches!(err, ConnectorError::UpstreamProtocol(_)),
            "{err:?}"
        );
    }

    // ---- SSRF through the fetcher: private-range jwks_uri is Blocked ----

    /// Start an in-process loopback HTTP server that serves `body` as JSON to every
    /// request, returning its address (mirrors the #25 client-assertion test server).
    #[cfg(feature = "testing")]
    async fn start_server(body: String) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        addr
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn a_public_jwks_uri_resolves_through_the_hardened_fetcher_and_caches() {
        let key = upstream_key();
        let jwks = JwkSet::from_signing_keys([&key])
            .expect("jwk set")
            .to_json()
            .expect("json");
        let server = start_server(jwks).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
        let fetcher =
            Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
        let resolver =
            FederationKeyResolver::new_allow_http(Arc::new(fetcher), Duration::from_secs(300));

        let now = SystemTime::UNIX_EPOCH;
        let keys = resolver
            .resolve(now, "cnr_a", "http://upstream.example/jwks")
            .await;
        assert_eq!(
            keys.len(),
            1,
            "the upstream key resolved through the fetcher"
        );
        // A second resolve hits the cache: the fetcher is not dialed again.
        let again = resolver
            .resolve(now, "cnr_a", "http://upstream.example/jwks")
            .await;
        assert_eq!(again.len(), 1);
        assert_eq!(dialer.requested().len(), 1, "the second resolve was cached");
        // The dial went to the PUBLIC pinned address, never the loopback (resolve-once).
        assert_eq!(dialer.requested()[0].ip(), IpAddr::from([93, 184, 216, 34]));
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn a_private_range_jwks_uri_is_blocked_and_fails_closed() {
        // A connector URL whose public-looking host RESOLVES to a private address is
        // Blocked by the fetcher, so the resolver yields no keys and validation fails
        // closed as UpstreamUnavailable. This is the SSRF acceptance criterion.
        let key = upstream_key();
        let jwks = JwkSet::from_signing_keys([&key])
            .unwrap()
            .to_json()
            .unwrap();
        let server = start_server(jwks).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        // The resolver maps the host to a link-local metadata address (169.254.169.254).
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([
            169, 254, 169, 254,
        ])]));
        let fetcher =
            Fetcher::from_parts(FetchLimits::default(), resolver_seam, Arc::clone(&dialer));
        let resolver =
            FederationKeyResolver::new_allow_http(Arc::new(fetcher), Duration::from_secs(300));

        let keys = resolver
            .resolve(
                SystemTime::UNIX_EPOCH,
                "cnr_b",
                "http://upstream.example/jwks",
            )
            .await;
        assert!(
            keys.is_empty(),
            "a private-range jwks_uri resolves to no keys"
        );
        assert!(
            dialer.requested().is_empty(),
            "the blocked address is never dialed (resolve-once, no rebind)"
        );
        // Validation then fails closed as unavailable.
        let (env, _clock) = manual_clock();
        let token = id_token(&key, serde_json::json!({}));
        let algs = jose_supported_algs();
        let err = validate_upstream_id_token(&token, keys, policy(&algs), env.clock())
            .expect_err("blocked jwks fails closed");
        assert!(
            matches!(err, ConnectorError::UpstreamUnavailable(_)),
            "{err:?}"
        );
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn discovery_is_fetched_through_the_hardened_fetcher_and_validates_the_issuer() {
        // A plaintext-http issuer so the in-process loopback server (no TLS) can serve the
        // document through the injected dialer; a production issuer is https, fetched over
        // TLS, but the mix-up and parse logic under test is scheme-independent.
        let http_issuer = "http://upstream.example";
        let doc = format!(
            r#"{{"issuer":"{http_issuer}","authorization_endpoint":"https://upstream.example/authorize","token_endpoint":"https://upstream.example/token","jwks_uri":"https://upstream.example/jwks","id_token_signing_alg_values_supported":["EdDSA"],"code_challenge_methods_supported":["S256"]}}"#
        );
        let server = start_server(doc).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([93, 184, 216, 34])]));
        let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, dialer);
        let resolved = fetch_discovery(&fetcher, http_issuer, true)
            .await
            .expect("discovery resolves");
        assert_eq!(resolved.jwks_uri, "https://upstream.example/jwks");
        assert!(resolved.advertises_s256());
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn a_private_range_discovery_issuer_is_blocked() {
        let server = start_server("{}".to_owned()).await;
        let dialer = Arc::new(RecordingDialer::new(server));
        let resolver_seam = Arc::new(StaticResolver::new(vec![IpAddr::from([10, 0, 0, 5])]));
        let fetcher = Fetcher::from_parts(FetchLimits::default(), resolver_seam, dialer);
        let err = fetch_discovery(&fetcher, ISSUER, true)
            .await
            .expect_err("blocked discovery");
        assert!(
            matches!(err, ConnectorError::UpstreamUnavailable(_)),
            "{err:?}"
        );
    }
}
