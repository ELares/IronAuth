// SPDX-License-Identifier: MIT OR Apache-2.0

//! `DPoP` (RFC 9449) proof validation and the RFC 7638 JWK thumbprint.
//!
//! A `DPoP` proof is a compact JWS the client SELF-SIGNS with an ephemeral key,
//! carrying that key's PUBLIC half in the `jwk` protected-header member. Unlike
//! [`crate::verify`], which only ever trusts a key supplied out of band through a
//! policy, this path deliberately verifies a proof against the key EMBEDDED in
//! its own header: the proof asserts possession of a private key, and the server
//! binds the issued token to that key's thumbprint (`cnf.jkt`, RFC 7800). Trust
//! is still never blind: the embedded key is checked against the classic `DPoP`
//! pitfalls before it verifies anything.
//!
//! The module is PURE and sans-IO. Every time-dependent decision is taken against
//! the `now` argument the caller threads in; this core never reads the wall clock
//! itself, so the freshness window is testable with fixed instants. The stateful pieces
//! of `DPoP` (the `jti` replay cache, server-issued nonce) are the caller's, above
//! this layer.
//!
//! # What is checked, and why
//!
//! - The embedded `jwk` MUST be a PUBLIC key: any private member (`d`, `p`, `q`,
//!   `dp`, `dq`, `qi`) makes the proof malformed and is rejected.
//! - `alg` MUST be one of `EdDSA`, `ES256`, or `RS256`: asymmetric only, never
//!   `none`, never an HMAC algorithm (so the public-key-as-HMAC-secret confusion
//!   is inexpressible, exactly as in the main verifier).
//! - `alg` MUST AGREE with the key type (`ES256` with an `EC`/`P-256` key,
//!   `EdDSA` with an `OKP`/`Ed25519` key, `RS256` with an `RSA` key), so a
//!   signature can never be verified under a mismatched algorithm.
//! - `typ` MUST be `dpop+jwt`, and the `htm`/`htu`/`iat`/`jti` claims (plus the
//!   optional `ath` and `nonce`) MUST match the caller's expectations.
//!
//! Every rejection is a distinct [`DpopError`] for server-side diagnostics, but
//! the messages are value-free: no attacker-supplied bytes are ever echoed. The
//! token endpoint (Phase B) maps every variant to one uniform response, so the
//! granular reason never becomes a client-visible oracle.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use crate::crypto;
use crate::json::parse_unique_object;
use crate::jwks::{Jwk, trusted_key_from_jwk};
use crate::policy::{JwsAlgorithm, VerificationCaps};
use crate::verify::{max_b64_len, split_segments};

/// The required `typ` of a `DPoP` proof JWT (RFC 9449 section 4.2).
const DPOP_TYP: &str = "dpop+jwt";

/// The private JWK members a PUBLIC proof key must never carry (RFC 7518): the EC/OKP
/// private key `d`, the RSA private primes and CRT values, and the multi-prime `oth`
/// array. Their presence is treated as malformed (or an attempt to smuggle a private
/// key), never ignored.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth"];

/// An upper bound on the accepted `jti` length, so an unbounded identifier cannot
/// bloat the caller's replay cache. Generous for any realistic unique id.
const MAX_JTI_LEN: usize = 256;

/// A failure to validate a `DPoP` proof or compute a thumbprint.
///
/// Each variant names one precise cause for server-side logs and metrics. The
/// [`std::fmt::Display`] rendering is deliberately VALUE-FREE: it never includes
/// the offending `htm`, `htu`, `jti`, or any other attacker-controlled bytes, so
/// a log line cannot leak proof contents. The token endpoint collapses every
/// variant into one uniform client response, so the distinction is never an
/// oracle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum DpopError {
    /// The proof exceeded a pre-processing size cap, rejected before any decode.
    TooLarge,
    /// The proof was structurally malformed: not three `.`-separated segments,
    /// a segment that was not valid unpadded base64url, or a header or payload
    /// that was not a JSON object with unique keys.
    Malformed,
    /// The embedded `jwk` was absent, was not an object, was missing a required
    /// member, or named a key type or curve this core cannot represent.
    MalformedKey,
    /// The embedded `jwk` carried a PRIVATE member (`d`, `p`, `q`, `dp`, `dq`, or
    /// `qi`). A `DPoP` proof key is public by definition.
    PrivateKeyInProof,
    /// The `alg` header was absent or was not one of the asymmetric proof
    /// algorithms `EdDSA`, `ES256`, `RS256` (so `none` and every HMAC name are
    /// rejected here).
    UnsupportedAlgorithm,
    /// The `alg` header did not agree with the embedded key type (for example
    /// `ES256` over an `RSA` key), which would be an algorithm-confusion attack.
    AlgKeyMismatch,
    /// The signature did not verify against the embedded public key.
    BadSignature,
    /// The `typ` header was not `dpop+jwt`.
    WrongType,
    /// The `htm` claim did not equal the expected HTTP method.
    HtmMismatch,
    /// The `htu` claim did not equal the expected (normalized) request URI.
    HtuMismatch,
    /// The `iat` claim was absent or not an integer number of seconds.
    MissingIat,
    /// The `iat` claim was further in the past than the freshness window allows.
    Expired,
    /// The `iat` claim was further in the future than the skew allowance permits.
    NotYetValid,
    /// The `jti` claim was absent, empty, or longer than the accepted bound.
    MissingJti,
    /// An `ath` binding was expected but the proof's `ath` was absent or did not
    /// match.
    AthMismatch,
    /// A `nonce` was expected but the proof's `nonce` was absent or did not match.
    NonceMismatch,
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DpopError::TooLarge => "dpop proof exceeds the size cap",
            DpopError::Malformed => "dpop proof is structurally malformed",
            DpopError::MalformedKey => "dpop proof embedded key is malformed or unsupported",
            DpopError::PrivateKeyInProof => "dpop proof embedded key carries private material",
            DpopError::UnsupportedAlgorithm => {
                "dpop proof algorithm is not an accepted asymmetric algorithm"
            }
            DpopError::AlgKeyMismatch => {
                "dpop proof algorithm does not agree with the embedded key type"
            }
            DpopError::BadSignature => "dpop proof signature did not verify",
            DpopError::WrongType => "dpop proof type header is not dpop+jwt",
            DpopError::HtmMismatch => "dpop proof http method claim did not match",
            DpopError::HtuMismatch => "dpop proof http uri claim did not match",
            DpopError::MissingIat => "dpop proof issued-at claim is absent or malformed",
            DpopError::Expired => "dpop proof issued-at is outside the freshness window",
            DpopError::NotYetValid => "dpop proof issued-at is in the future beyond the skew",
            DpopError::MissingJti => "dpop proof identifier claim is absent, empty, or too long",
            DpopError::AthMismatch => "dpop proof access-token hash did not match",
            DpopError::NonceMismatch => "dpop proof nonce did not match",
        })
    }
}

impl std::error::Error for DpopError {}

/// The RFC 7638 JWK thumbprint (`jkt`) of `jwk`, base64url-encoded.
///
/// Builds the CANONICAL JWK: only the RFC 7638 required members, in strict
/// lexicographic order, with no whitespace, then hashes the UTF-8 bytes with
/// SHA-256 and base64url-encodes (no padding). The required members per key type
/// are `crv`, `kty`, `x`, `y` for `EC`; `crv`, `kty`, `x` for `OKP`; and `e`,
/// `kty`, `n` for `RSA`. The ordering is guaranteed by building a [`BTreeMap`]
/// keyed on the member names, so it never depends on the input member order.
///
/// # Errors
///
/// [`DpopError::MalformedKey`] if `jwk` has no `kty`, has an unsupported `kty`,
/// or is missing a required member for its type.
pub fn jwk_thumbprint(jwk: &Jwk) -> Result<String, DpopError> {
    let kty = jwk.kty().ok_or(DpopError::MalformedKey)?;
    // A BTreeMap keyed on the member names serializes in lexicographic key order
    // with no whitespace, which is exactly the RFC 7638 canonical form, and does
    // not depend on how the members were ordered in the input.
    let canonical: BTreeMap<&str, &str> = match kty {
        "EC" => BTreeMap::from([
            ("crv", required_str(jwk, "crv")?),
            ("kty", "EC"),
            ("x", required_str(jwk, "x")?),
            ("y", required_str(jwk, "y")?),
        ]),
        "OKP" => BTreeMap::from([
            ("crv", required_str(jwk, "crv")?),
            ("kty", "OKP"),
            ("x", required_str(jwk, "x")?),
        ]),
        "RSA" => BTreeMap::from([
            ("e", required_str(jwk, "e")?),
            ("kty", "RSA"),
            ("n", required_str(jwk, "n")?),
        ]),
        _ => return Err(DpopError::MalformedKey),
    };
    let json = serde_json::to_string(&canonical).map_err(|_| DpopError::MalformedKey)?;
    Ok(URL_SAFE_NO_PAD.encode(crypto::sha256(json.as_bytes())))
}

/// Read a required string JWK member, or [`DpopError::MalformedKey`] if it is
/// absent or not a string.
fn required_str<'a>(jwk: &'a Jwk, member: &str) -> Result<&'a str, DpopError> {
    jwk.get(member)
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedKey)
}

/// What a valid `DPoP` proof is checked against (RFC 9449 section 4.3).
///
/// The lifetime ties the borrowed method, URI, and optional bindings to the
/// caller's request context, so nothing is copied to validate one proof.
pub struct DpopExpectations<'a> {
    /// The HTTP method of the request the proof covers, compared case-sensitively
    /// (RFC 9449 uses the uppercase method token, for example `POST`).
    pub htm: &'a str,
    /// The request URI the proof covers, ALREADY normalized by the caller to the
    /// scheme, authority, and path only. RFC 9449 section 4.3 excludes the query
    /// and fragment from `htu`, so the caller strips them from BOTH the actual
    /// request URI and (implicitly) the value it expects here before comparison.
    pub htu: &'a str,
    /// How far in the PAST the `iat` may be and still be fresh.
    pub iat_leeway: Duration,
    /// How far in the FUTURE the `iat` may be, tolerating small clock skew.
    pub iat_skew: Duration,
    /// The expected access-token hash (`ath`), when the proof is presented at a
    /// resource server or bound to a specific access token. [`None`] skips the
    /// check.
    pub ath: Option<&'a str>,
    /// The expected server-issued `DPoP` nonce, when one was challenged. [`None`]
    /// skips the check.
    pub nonce: Option<&'a str>,
}

/// The trusted outcome of a valid `DPoP` proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpopProof {
    /// The RFC 7638 thumbprint of the proof key: the value to bind as `cnf.jkt`
    /// on the issued token.
    pub jkt: String,
    /// The proof's unique identifier, for the caller's replay cache (Phase B).
    pub jti: String,
    /// The proof's issued-at time.
    pub iat: SystemTime,
}

/// Validate a compact `DPoP` proof JWS against `expected`, evaluated at `now`.
///
/// On success the proof's signature verified against its own embedded public key,
/// the key passed every anti-confusion guard, and every claim matched. The
/// returned [`DpopProof`] carries the key thumbprint to bind and the `jti` for
/// the caller's replay defense. This function is PURE: `now` is the only clock,
/// and there is no I/O or hidden state.
///
/// The caller MUST normalize `expected.htu` (and the request URI it derived it
/// from) to scheme, authority, and path with no query or fragment, per RFC 9449
/// section 4.3, before calling.
///
/// # Errors
///
/// [`DpopError`] for every rejection: an oversized or malformed proof, an
/// embedded key that is private, unsupported, or mismatched with `alg`, a bad
/// signature, a wrong `typ`, or any claim (`htm`, `htu`, `iat`, `jti`, `ath`,
/// `nonce`) that does not match `expected`.
pub fn validate_dpop_proof(
    proof_jws: &str,
    expected: &DpopExpectations,
    now: SystemTime,
) -> Result<DpopProof, DpopError> {
    let verified = verify_embedded(proof_jws)?;

    // typ is read only now, from the header that the signature just covered.
    let typ = verified
        .header
        .get("typ")
        .and_then(Value::as_str)
        .ok_or(DpopError::WrongType)?;
    if typ != DPOP_TYP {
        return Err(DpopError::WrongType);
    }

    let jkt = jwk_thumbprint(&verified.jwk)?;

    let claims = parse_unique_object(&verified.payload).map_err(|()| DpopError::Malformed)?;

    if claims.get("htm").and_then(Value::as_str) != Some(expected.htm) {
        return Err(DpopError::HtmMismatch);
    }
    if claims.get("htu").and_then(Value::as_str) != Some(expected.htu) {
        return Err(DpopError::HtuMismatch);
    }

    let iat_secs = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(DpopError::MissingIat)?;
    check_iat_window(iat_secs, now, expected.iat_leeway, expected.iat_skew)?;

    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or(DpopError::MissingJti)?;
    if jti.is_empty() || jti.len() > MAX_JTI_LEN {
        return Err(DpopError::MissingJti);
    }

    if let Some(expected_ath) = expected.ath {
        if claims.get("ath").and_then(Value::as_str) != Some(expected_ath) {
            return Err(DpopError::AthMismatch);
        }
    }
    if let Some(expected_nonce) = expected.nonce {
        if claims.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
            return Err(DpopError::NonceMismatch);
        }
    }

    Ok(DpopProof {
        jkt,
        jti: jti.to_owned(),
        iat: UNIX_EPOCH + Duration::from_secs(iat_secs),
    })
}

/// The pieces recovered from a proof whose signature verified against its own
/// embedded key: the embedded key, its (verified) protected header, and the
/// decoded payload bytes.
struct VerifiedEmbedded {
    jwk: Jwk,
    header: Map<String, Value>,
    payload: Vec<u8>,
}

/// Verify a compact JWS against the PUBLIC key embedded in its own `jwk` header,
/// after enforcing the `DPoP` key guards. On success the signature is valid and the
/// embedded key is a public, allowlisted, algorithm-agreeing key.
fn verify_embedded(proof: &str) -> Result<VerifiedEmbedded, DpopError> {
    let caps = VerificationCaps::DEFAULT;

    // Size cap first, before any base64 or JSON work.
    if proof.len() > caps.max_token_bytes {
        return Err(DpopError::TooLarge);
    }

    let (header_b64, payload_b64, signature_b64) =
        split_segments(proof).ok_or(DpopError::Malformed)?;
    if header_b64.len() > max_b64_len(caps.max_header_bytes) {
        return Err(DpopError::TooLarge);
    }
    if payload_b64.len() > max_b64_len(caps.max_payload_bytes) {
        return Err(DpopError::TooLarge);
    }

    let header_bytes = decode_segment(header_b64)?;
    let header = parse_unique_object(&header_bytes).map_err(|()| DpopError::Malformed)?;

    // The embedded key. Wrapped into a Jwk so it shares the ONE JWK to key mapping
    // (trusted_key_from_jwk) and the ONE thumbprint routine with the JWKS path.
    let jwk_object = header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or(DpopError::MalformedKey)?;
    let jwk = Jwk::from_object(jwk_object.clone());

    // A proof key is public by definition; a private member is malformed.
    for member in PRIVATE_JWK_MEMBERS {
        if jwk.get(member).is_some() {
            return Err(DpopError::PrivateKeyInProof);
        }
    }

    // Asymmetric proof algorithms only; never none, never HMAC.
    let alg = proof_algorithm(header.get("alg"))?;

    // The algorithm must agree with the key type, or a mismatched-alg confusion
    // would be possible.
    if !alg_agrees_with_key(alg, &jwk) {
        return Err(DpopError::AlgKeyMismatch);
    }

    let key = trusted_key_from_jwk(&jwk).ok_or(DpopError::MalformedKey)?;

    let signature = decode_segment(signature_b64)?;
    let payload = decode_segment(payload_b64)?;

    // The one signature check, over the exact signed input `header.payload`.
    let signing_input = signing_input_bytes(header_b64, payload_b64);
    crypto::verify_signature(alg, &key.material, &signing_input, &signature)
        .map_err(|()| DpopError::BadSignature)?;

    Ok(VerifiedEmbedded {
        jwk,
        header,
        payload,
    })
}

/// Map a proof `alg` header to the accepted asymmetric algorithm, or reject it.
///
/// Only `EdDSA`, `ES256`, and `RS256` are accepted for a `DPoP` proof; every other
/// name (including `none`, the HMAC family, and the wider signing matrix such as
/// `ES384`) is [`DpopError::UnsupportedAlgorithm`].
fn proof_algorithm(alg: Option<&Value>) -> Result<JwsAlgorithm, DpopError> {
    match alg.and_then(Value::as_str) {
        Some("EdDSA") => Ok(JwsAlgorithm::EdDsa),
        Some("ES256") => Ok(JwsAlgorithm::Es256),
        Some("RS256") => Ok(JwsAlgorithm::Rs256),
        _ => Err(DpopError::UnsupportedAlgorithm),
    }
}

/// Whether `alg` agrees with the embedded key's `kty` and `crv`.
fn alg_agrees_with_key(alg: JwsAlgorithm, jwk: &Jwk) -> bool {
    let kty = jwk.kty();
    let crv = jwk.get("crv").and_then(Value::as_str);
    match alg {
        JwsAlgorithm::EdDsa => kty == Some("OKP") && crv == Some("Ed25519"),
        JwsAlgorithm::Es256 => kty == Some("EC") && crv == Some("P-256"),
        JwsAlgorithm::Rs256 => kty == Some("RSA"),
        // No other algorithm is ever produced by proof_algorithm.
        _ => false,
    }
}

/// Decode one unpadded base64url segment, or [`DpopError::Malformed`].
fn decode_segment(segment: &str) -> Result<Vec<u8>, DpopError> {
    URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|_| DpopError::Malformed)
}

/// The JWS signing input `base64url(header) || '.' || base64url(payload)`.
fn signing_input_bytes(header_b64: &str, payload_b64: &str) -> Vec<u8> {
    let mut input = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
    input.extend_from_slice(header_b64.as_bytes());
    input.push(b'.');
    input.extend_from_slice(payload_b64.as_bytes());
    input
}

/// Enforce that `iat_secs` is within `[now - leeway, now + skew]`, in whole
/// seconds since the Unix epoch.
fn check_iat_window(
    iat_secs: u64,
    now: SystemTime,
    leeway: Duration,
    skew: Duration,
) -> Result<(), DpopError> {
    let now_secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    // Too old: iat + leeway < now.
    if iat_secs.saturating_add(leeway.as_secs()) < now_secs {
        return Err(DpopError::Expired);
    }
    // Too far in the future: iat > now + skew.
    if iat_secs > now_secs.saturating_add(skew.as_secs()) {
        return Err(DpopError::NotYetValid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_key::{PublicComponents, SigningKey};
    use ironauth_env::FixedEntropy;
    use serde_json::json;

    // ---- Fixtures --------------------------------------------------------

    /// A fixed instant well after the epoch, so freshness-window arithmetic
    /// never underflows.
    fn fixed_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn ed25519_key() -> SigningKey {
        SigningKey::ed25519_from_seed(Some("proof-ed".to_owned()), &[7_u8; 32]).expect("ed25519")
    }

    fn es256_key() -> SigningKey {
        let der = crate::signing_key::generate_ecdsa_p256_pkcs8_der(&FixedEntropy::new(11))
            .expect("es256 der");
        SigningKey::ecdsa_p256_from_pkcs8(Some("proof-ec".to_owned()), &der).expect("es256")
    }

    /// The PUBLIC jwk JSON object for a signing key, as it appears in a proof
    /// header.
    fn public_jwk(key: &SigningKey) -> Value {
        match key.public_components().expect("components") {
            PublicComponents::Okp { x } => json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(x),
            }),
            PublicComponents::Ec { crv, x, y } => json!({
                "kty": "EC",
                "crv": crv,
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
            }),
            PublicComponents::Rsa { n, e } => json!({
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(n),
                "e": URL_SAFE_NO_PAD.encode(e),
            }),
        }
    }

    fn b64(value: &Value) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("json"))
    }

    /// Assemble a compact JWS from a header and payload, signed by `key`.
    fn sign_proof(key: &SigningKey, header: &Value, payload: &Value) -> String {
        let header_b64 = b64(header);
        let payload_b64 = b64(payload);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = crate::sign::sign_asymmetric(key, signing_input.as_bytes()).expect("sign");
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    /// A well-formed proof over the default happy-path claims.
    fn happy_proof(key: &SigningKey, alg: &str) -> String {
        let header = json!({ "typ": DPOP_TYP, "alg": alg, "jwk": public_jwk(key) });
        let payload = json!({
            "htm": "POST",
            "htu": "https://issuer.example.test/token",
            "iat": 1_700_000_000_u64,
            "jti": "id-0001",
        });
        sign_proof(key, &header, &payload)
    }

    fn default_expectations<'a>() -> DpopExpectations<'a> {
        DpopExpectations {
            htm: "POST",
            htu: "https://issuer.example.test/token",
            iat_leeway: Duration::from_secs(300),
            iat_skew: Duration::from_secs(30),
            ath: None,
            nonce: None,
        }
    }

    // ---- RFC 7638 thumbprint known answers -------------------------------

    /// The RFC 7638 section 3.1 example RSA key thumbprint.
    #[test]
    fn rfc7638_rsa_known_answer() {
        let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhD\
                 R1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C\
                 f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1\
                 n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1\
                 jF44-csFCur-kEgU8awapJzKnqDKgw";
        let jwk = Jwk::from_object(
            json!({ "kty": "RSA", "n": n, "e": "AQAB" })
                .as_object()
                .expect("object")
                .clone(),
        );
        assert_eq!(
            jwk_thumbprint(&jwk).expect("thumbprint"),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// An OKP (Ed25519) known answer, computed from the RFC 8037 public key.
    #[test]
    fn okp_known_answer() {
        let jwk = Jwk::from_object(
            json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            })
            .as_object()
            .expect("object")
            .clone(),
        );
        assert_eq!(
            jwk_thumbprint(&jwk).expect("thumbprint"),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    /// An EC (P-256) known answer, computed from a fixed public point.
    #[test]
    fn ec_known_answer() {
        let jwk = Jwk::from_object(
            json!({
                "kty": "EC",
                "crv": "P-256",
                "x": "hdEyrWjHW37UXH7vRl6YozC2cUua-ynJvd-qKub432M",
                "y": "xJdJS3bMBb7cX7m45xychk5H3m_0CPI0Ep2wApTgx00",
            })
            .as_object()
            .expect("object")
            .clone(),
        );
        assert_eq!(
            jwk_thumbprint(&jwk).expect("thumbprint"),
            "_TmrTfiaQvxU7MPwdXYstGjT9nWDrtl4eHYKMDkyM-I"
        );
    }

    /// The thumbprint does not depend on the input member order.
    #[test]
    fn thumbprint_is_member_order_independent() {
        let ordered = Jwk::from_object(
            json!({
                "crv": "P-256",
                "kty": "EC",
                "x": "hdEyrWjHW37UXH7vRl6YozC2cUua-ynJvd-qKub432M",
                "y": "xJdJS3bMBb7cX7m45xychk5H3m_0CPI0Ep2wApTgx00",
            })
            .as_object()
            .expect("object")
            .clone(),
        );
        let shuffled = Jwk::from_object(
            json!({
                "y": "xJdJS3bMBb7cX7m45xychk5H3m_0CPI0Ep2wApTgx00",
                "kty": "EC",
                "x": "hdEyrWjHW37UXH7vRl6YozC2cUua-ynJvd-qKub432M",
                "crv": "P-256",
                "use": "sig",
                "kid": "ignored",
            })
            .as_object()
            .expect("object")
            .clone(),
        );
        assert_eq!(
            jwk_thumbprint(&ordered).expect("a"),
            jwk_thumbprint(&shuffled).expect("b"),
        );
    }

    #[test]
    fn thumbprint_rejects_missing_member() {
        let jwk = Jwk::from_object(
            json!({ "kty": "EC", "crv": "P-256", "x": "AA" })
                .as_object()
                .expect("object")
                .clone(),
        );
        assert_eq!(jwk_thumbprint(&jwk), Err(DpopError::MalformedKey));
    }

    // ---- verify_embedded -------------------------------------------------

    #[test]
    fn valid_es256_proof_verifies() {
        let key = es256_key();
        let proof = happy_proof(&key, "ES256");
        let out = validate_dpop_proof(&proof, &default_expectations(), fixed_now()).expect("valid");
        assert_eq!(out.jti, "id-0001");
    }

    #[test]
    fn valid_eddsa_proof_verifies() {
        let key = ed25519_key();
        let proof = happy_proof(&key, "EdDSA");
        let out = validate_dpop_proof(&proof, &default_expectations(), fixed_now()).expect("valid");
        assert_eq!(out.jti, "id-0001");
        // The bound thumbprint is the RFC 7638 thumbprint of the embedded key.
        assert_eq!(out.jkt, jwk_thumbprint(&key_jwk(&key)).expect("jkt"));
    }

    fn key_jwk(key: &SigningKey) -> Jwk {
        Jwk::from_object(public_jwk(key).as_object().expect("object").clone())
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let key = ed25519_key();
        let proof = happy_proof(&key, "EdDSA");
        // Flip the last byte of the signature segment.
        let mut chars: Vec<char> = proof.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(
            validate_dpop_proof(&tampered, &default_expectations(), fixed_now()),
            Err(DpopError::BadSignature)
        );
    }

    #[test]
    fn embedded_private_key_is_rejected() {
        // Every private member, including the multi-prime `oth` array, is refused; the
        // proof is otherwise valid (signed by the real key), so only the private-member
        // guard can reject it.
        for member in ["d", "p", "q", "dp", "dq", "qi", "oth"] {
            let key = ed25519_key();
            let mut jwk = public_jwk(&key);
            jwk.as_object_mut()
                .expect("object")
                .insert(member.to_owned(), json!("c2VjcmV0"));
            let header = json!({ "typ": DPOP_TYP, "alg": "EdDSA", "jwk": jwk });
            let payload = json!({ "htm": "POST", "htu": "https://issuer.example.test/token", "iat": 1_700_000_000_u64, "jti": "id" });
            let proof = sign_proof(&key, &header, &payload);
            assert_eq!(
                validate_dpop_proof(&proof, &default_expectations(), fixed_now()),
                Err(DpopError::PrivateKeyInProof),
                "member {member} must be rejected as private material"
            );
        }
    }

    #[test]
    fn alg_none_and_hmac_are_rejected() {
        let key = ed25519_key();
        for alg in ["none", "HS256"] {
            let header = json!({ "typ": DPOP_TYP, "alg": alg, "jwk": public_jwk(&key) });
            let payload = json!({ "htm": "POST", "htu": "https://issuer.example.test/token", "iat": 1_700_000_000_u64, "jti": "id" });
            let proof = sign_proof(&key, &header, &payload);
            assert_eq!(
                validate_dpop_proof(&proof, &default_expectations(), fixed_now()),
                Err(DpopError::UnsupportedAlgorithm),
                "{alg}"
            );
        }
    }

    #[test]
    fn es256_alg_over_rsa_key_is_a_mismatch() {
        let key = ed25519_key();
        // An RSA jwk (RFC 7638 example key) presented under an ES256 alg.
        let rsa_jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78",
            "e": "AQAB",
        });
        let header = json!({ "typ": DPOP_TYP, "alg": "ES256", "jwk": rsa_jwk });
        let payload = json!({ "htm": "POST", "htu": "https://issuer.example.test/token", "iat": 1_700_000_000_u64, "jti": "id" });
        // Signed by an unrelated key; the mismatch is caught before any signature check.
        let proof = sign_proof(&key, &header, &payload);
        assert_eq!(
            validate_dpop_proof(&proof, &default_expectations(), fixed_now()),
            Err(DpopError::AlgKeyMismatch)
        );
    }

    // ---- validator claim checks ------------------------------------------

    #[test]
    fn wrong_typ_is_rejected() {
        let key = ed25519_key();
        let header = json!({ "typ": "jwt", "alg": "EdDSA", "jwk": public_jwk(&key) });
        let payload = json!({ "htm": "POST", "htu": "https://issuer.example.test/token", "iat": 1_700_000_000_u64, "jti": "id" });
        let proof = sign_proof(&key, &header, &payload);
        assert_eq!(
            validate_dpop_proof(&proof, &default_expectations(), fixed_now()),
            Err(DpopError::WrongType)
        );
    }

    #[test]
    fn wrong_htm_and_htu_are_rejected() {
        let key = ed25519_key();
        let proof = happy_proof(&key, "EdDSA");

        let mut wrong_method = default_expectations();
        wrong_method.htm = "GET";
        assert_eq!(
            validate_dpop_proof(&proof, &wrong_method, fixed_now()),
            Err(DpopError::HtmMismatch)
        );

        let mut wrong_uri = default_expectations();
        wrong_uri.htu = "https://issuer.example.test/other";
        assert_eq!(
            validate_dpop_proof(&proof, &wrong_uri, fixed_now()),
            Err(DpopError::HtuMismatch)
        );
    }

    #[test]
    fn stale_and_future_iat_are_rejected() {
        let key = ed25519_key();
        let proof = happy_proof(&key, "EdDSA");
        let expected = default_expectations();

        // now far ahead of iat + leeway -> stale.
        let late = UNIX_EPOCH + Duration::from_secs(1_700_000_000 + 10_000);
        assert_eq!(
            validate_dpop_proof(&proof, &expected, late),
            Err(DpopError::Expired)
        );

        // now far before iat - skew -> future.
        let early = UNIX_EPOCH + Duration::from_secs(1_700_000_000 - 10_000);
        assert_eq!(
            validate_dpop_proof(&proof, &expected, early),
            Err(DpopError::NotYetValid)
        );
    }

    #[test]
    fn missing_iat_and_jti_are_rejected() {
        let key = ed25519_key();

        let header = json!({ "typ": DPOP_TYP, "alg": "EdDSA", "jwk": public_jwk(&key) });
        let no_iat =
            json!({ "htm": "POST", "htu": "https://issuer.example.test/token", "jti": "id" });
        let proof = sign_proof(&key, &header, &no_iat);
        assert_eq!(
            validate_dpop_proof(&proof, &default_expectations(), fixed_now()),
            Err(DpopError::MissingIat)
        );

        let no_jti = json!({ "htm": "POST", "htu": "https://issuer.example.test/token", "iat": 1_700_000_000_u64 });
        let proof = sign_proof(&key, &header, &no_jti);
        assert_eq!(
            validate_dpop_proof(&proof, &default_expectations(), fixed_now()),
            Err(DpopError::MissingJti)
        );

        let empty_jti = json!({ "htm": "POST", "htu": "https://issuer.example.test/token", "iat": 1_700_000_000_u64, "jti": "" });
        let proof = sign_proof(&key, &header, &empty_jti);
        assert_eq!(
            validate_dpop_proof(&proof, &default_expectations(), fixed_now()),
            Err(DpopError::MissingJti)
        );
    }

    #[test]
    fn ath_and_nonce_are_checked_only_when_expected() {
        let key = ed25519_key();
        let header = json!({ "typ": DPOP_TYP, "alg": "EdDSA", "jwk": public_jwk(&key) });
        let payload = json!({
            "htm": "POST",
            "htu": "https://issuer.example.test/token",
            "iat": 1_700_000_000_u64,
            "jti": "id",
            "ath": "correct-ath",
            "nonce": "correct-nonce",
        });
        let proof = sign_proof(&key, &header, &payload);

        // Matching expectations pass.
        let mut ok = default_expectations();
        ok.ath = Some("correct-ath");
        ok.nonce = Some("correct-nonce");
        assert!(validate_dpop_proof(&proof, &ok, fixed_now()).is_ok());

        // Wrong ath.
        let mut bad_ath = default_expectations();
        bad_ath.ath = Some("other");
        assert_eq!(
            validate_dpop_proof(&proof, &bad_ath, fixed_now()),
            Err(DpopError::AthMismatch)
        );

        // Wrong nonce.
        let mut bad_nonce = default_expectations();
        bad_nonce.nonce = Some("other");
        assert_eq!(
            validate_dpop_proof(&proof, &bad_nonce, fixed_now()),
            Err(DpopError::NonceMismatch)
        );
    }

    #[test]
    fn oversized_proof_is_rejected_before_decode() {
        let big = "a".repeat(VerificationCaps::DEFAULT.max_token_bytes + 1);
        assert_eq!(
            validate_dpop_proof(&big, &default_expectations(), fixed_now()),
            Err(DpopError::TooLarge)
        );
    }

    #[test]
    fn structurally_broken_proof_is_malformed() {
        assert_eq!(
            validate_dpop_proof("not-a-proof", &default_expectations(), fixed_now()),
            Err(DpopError::Malformed)
        );
    }
}
