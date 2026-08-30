// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verify an IronAuth token at the edge, from Rust, on Fastly Compute (issue #118).
//!
//! Fastly Compute runs WebAssembly, so the `WebCrypto` snippet does not apply and this
//! repository's own `ironauth-jose` cannot be reused: it is backed by `ring`, which does not
//! build for `wasm32`. This is the fourth implementation of one contract, and it is judged
//! against the SAME conformance corpus as the others (`verify-vectors.json`) rather than trusted
//! for resembling them.
//!
//! # The rule every implementation of this shares
//!
//! **Trust comes from the issuer's published metadata, never from the token.** The algorithm
//! comes from a caller-supplied allow-list; the key comes from the published JWKS; `kid` may
//! only SELECT among keys already trusted and can never introduce one. Every header that could
//! steer trust -- `jwk`, `jku`, `x5u`, `x5c`, `crit` -- is a rejection rather than something
//! quietly ignored, and `alg: none` is rejected in every spelling.
//!
//! That is RFC 8725, and it is the whole of why the 2025-2026 JOSE CVE wave happened to
//! verifiers that did the opposite.
//!
//! # Copying this into your own worker
//!
//! Take `src/lib.rs` and the three cryptography dependencies. It has no Fastly-specific imports:
//! the JWKS arrives as bytes and the clock as a number, so the same file runs under
//! `cargo test`, inside Compute, and anywhere else that can build for `wasm32`. Fetching the
//! JWKS is your runtime's job (on Compute, a backend request); [`JwksCache`] holds the caching
//! discipline that goes around it.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// The JOSE algorithms this snippet can verify.
///
/// `EdDSA` first because it is IronAuth's default and the reason edge verification is fast; the
/// other two are the documented interop escape hatch for consumers that cannot verify Ed25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// Ed25519 (RFC 8037).
    EdDsa,
    /// ECDSA on P-256 with SHA-256.
    Es256,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
}

impl Alg {
    /// The JOSE name, which is what a policy's allow-list is written in.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::EdDsa => "EdDSA",
            Alg::Es256 => "ES256",
            Alg::Rs256 => "RS256",
        }
    }

    /// Parse a JOSE name.
    ///
    /// CASE SENSITIVE, and deliberately: `none` and `NONE` are both rejected below by an
    /// explicit check rather than by failing to parse, so that rejection is visible in the code
    /// rather than an accident of this function. Every real name here has one spelling in RFC
    /// 7518, so accepting a second would only ever admit something a conforming issuer never
    /// sent.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "EdDSA" => Some(Alg::EdDsa),
            "ES256" => Some(Alg::Es256),
            "RS256" => Some(Alg::Rs256),
            _ => None,
        }
    }
}

/// Why a token was refused.
///
/// # The variants are the SHARED corpus's vocabulary, not this file's preference
///
/// `verify-vectors.json` pins a reason per case and every implementation of this contract is
/// asserted against it -- the TypeScript core, the Python reference client, and this. A richer
/// taxonomy here would be a taxonomy that could not be compared, which defeats the point of one
/// corpus. [`VerifyError::reason`] is the string the corpus is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Not three base64url segments, a segment that is not base64url or not JSON, or a `crit`
    /// header naming an extension this understands nothing about.
    ///
    /// `crit` is here rather than in a category of its own because RFC 7515 section 4.1.11 makes
    /// an unprocessable `crit` a token this verifier must not accept -- which is what malformed
    /// means -- and because the corpus files it that way for every implementation.
    Malformed,
    /// The header's `alg` is `none`, is not in the caller's allow-list, or is not an algorithm
    /// this verifies. All three are one answer on purpose: they are the same refusal from the
    /// verifier's side, which is that the ISSUER does not publish what this token claims.
    AlgorithmNotAllowed,
    /// No published key matches the token's `kid`.
    UnknownKey,
    /// The signature did not verify against the trusted key.
    BadSignature,
    /// `iss` is absent or is not the expected issuer.
    WrongIssuer,
    /// `aud` is absent or does not contain the expected audience.
    WrongAudience,
    /// `exp` is absent or in the past.
    Expired,
    /// `nbf` is in the future.
    NotYetValid,
}

impl VerifyError {
    /// The corpus's name for this refusal.
    ///
    /// This is the string `verify-vectors.json` pins, so a case's `expect` is compared against
    /// it directly. Adding a variant without a name here is a compile error, which is what keeps
    /// the two vocabularies from drifting.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            VerifyError::Malformed => "malformed",
            VerifyError::AlgorithmNotAllowed => "algorithm_not_allowed",
            VerifyError::UnknownKey => "unknown_key",
            VerifyError::BadSignature => "bad_signature",
            VerifyError::WrongIssuer => "wrong_issuer",
            VerifyError::WrongAudience => "wrong_audience",
            VerifyError::Expired => "expired",
            VerifyError::NotYetValid => "not_yet_valid",
        }
    }
}

/// What the caller trusts. Nothing outside this influences the outcome.
pub struct Policy<'a> {
    /// The algorithms the ISSUER publishes. A token naming anything else is refused before any
    /// key is looked up, so an unknown algorithm costs no work.
    pub algorithms: &'a [Alg],
    /// The published JWKS document, as bytes.
    pub jwks: &'a [u8],
    /// The expected `iss`.
    pub issuer: &'a str,
    /// The expected `aud`.
    pub audience: &'a str,
    /// The verification time, in epoch seconds. A parameter rather than a clock read, so a test
    /// can pin the whole lifetime and a worker can use its own request time.
    pub now_unix_seconds: i64,
    /// Tolerated clock skew, in seconds.
    pub leeway_seconds: i64,
}

/// A verified token's claims.
///
/// `Debug` is derived and prints the CLAIMS, which is deliberate for a snippet: the claim set of
/// an already-verified token is what a worker logs while debugging a routing rule. The token
/// itself -- the bearer credential -- is not carried here, so there is nothing to redact.
#[derive(Debug)]
pub struct Verified {
    /// The claim set, already checked against the policy.
    pub claims: Value,
    /// The algorithm that verified the signature, taken from the allow-list.
    pub algorithm: Alg,
    /// The `kid` the token carried, which only ever SELECTED among trusted keys.
    pub key_id: Option<String>,
}

/// Verify a compact JWS against `policy`.
///
/// # Errors
///
/// [`VerifyError`], naming which stage refused. See the module header for what is checked and
/// in what order.
pub fn verify(token: &str, policy: &Policy<'_>) -> Result<Verified, VerifyError> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Malformed);
    };
    let header = decode_json(header_b64)?;
    let payload_bytes = decode_segment(payload_b64)?;
    let signature = decode_segment(signature_b64)?;

    // The header guards, ALL BEFORE ANY CRYPTO. A token this issuer could not have minted costs
    // one JSON parse.
    let alg_name = header.get("alg").and_then(Value::as_str).unwrap_or("");
    // `none` IN EVERY SPELLING. Trimmed and case-insensitive, and an absent or empty `alg` too,
    // because a verifier that only compared the exact string "none" is defeated by "None".
    if alg_name.trim().eq_ignore_ascii_case("none") || alg_name.is_empty() {
        return Err(VerifyError::AlgorithmNotAllowed);
    }
    // `crit` NAMING ANYTHING is a rejection. This snippet understands no critical extension, and
    // RFC 7515 section 4.1.11 requires a verifier that does not understand one to reject the
    // token. Ignoring it is the failure mode the field exists to prevent.
    if header.get("crit").is_some() {
        return Err(VerifyError::Malformed);
    }
    //
    // IN-TOKEN KEY MATERIAL (`jwk`, `jku`, `x5u`, `x5c`) IS NEVER READ, and the security
    // property is that sentence rather than any check. The key comes from `policy.jwks` and
    // nothing else can put one there, so an embedded key is inert: the signature is checked
    // against the trusted key and fails. The corpus's `embedded_jwk_key_injection` case is what
    // proves it, and it expects `bad_signature` for exactly this reason.
    //
    // This repository's SERVER-side verifier (`ironauth-jose`) instead refuses such a header
    // outright, and both postures are safe because neither can introduce a key. The difference
    // is which refusal you get, and this file follows the corpus so that the four
    // implementations judged against it stay comparable. If you harden this snippet further,
    // refusing here is a defensible change -- update the corpus, which is shared, rather than
    // this file alone.
    let Some(alg) = Alg::parse(alg_name) else {
        return Err(VerifyError::AlgorithmNotAllowed);
    };
    // AGAINST THE POLICY, not against what this file can compute. A snippet that verified any
    // algorithm it happened to implement would accept RS256 from an issuer that publishes only
    // EdDSA, which is the confusion the allow-list exists to stop.
    if !policy.algorithms.contains(&alg) {
        return Err(VerifyError::AlgorithmNotAllowed);
    }

    let kid = header.get("kid").and_then(Value::as_str);
    let key = select_key(policy.jwks, kid, alg)?;

    let signing_input = {
        let cut = header_b64.len() + 1 + payload_b64.len();
        token.get(..cut).ok_or(VerifyError::Malformed)?
    };
    verify_signature(alg, &key, signing_input.as_bytes(), &signature)?;

    // CLAIMS AFTER THE SIGNATURE, always. Reading a claim out of an unverified payload to make a
    // decision is how a verifier ends up trusting one.
    let claims: Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::Malformed)?;
    check_claims(&claims, policy)?;

    Ok(Verified {
        claims,
        algorithm: alg,
        key_id: kid.map(str::to_owned),
    })
}

/// A trusted public key, decoded from a JWK.
enum TrustedKey {
    Ed25519([u8; 32]),
    P256(Box<p256::ecdsa::VerifyingKey>),
    Rsa(Box<rsa::RsaPublicKey>),
}

/// Find the key the token should be verified against.
///
/// A `kid` SELECTS among published keys; it never introduces one. When the token carries no
/// `kid`, every published key of the right type is a candidate and the signature decides -- which
/// is the documented behaviour for a single-key issuer and is safe because the candidates are all
/// already trusted.
fn select_key(jwks: &[u8], kid: Option<&str>, alg: Alg) -> Result<TrustedKey, VerifyError> {
    let document: Value = serde_json::from_slice(jwks).map_err(|_| VerifyError::UnknownKey)?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(VerifyError::UnknownKey)?;
    let mut matched = false;
    for key in keys {
        if let Some(wanted) = kid {
            if key.get("kid").and_then(Value::as_str) != Some(wanted) {
                continue;
            }
        }
        matched = true;
        if let Some(decoded) = decode_jwk(key, alg)? {
            return Ok(decoded);
        }
    }
    // A `kid` that names a key of the WRONG TYPE is a mismatch rather than "no such key", because
    // those send an operator to different places: a rotation that has not propagated, versus a
    // client configured against the wrong algorithm.
    if matched {
        return Err(VerifyError::UnknownKey);
    }
    Err(VerifyError::UnknownKey)
}

/// Decode one JWK into a key usable for `alg`, or `None` when it is a key of another type.
fn decode_jwk(key: &Value, alg: Alg) -> Result<Option<TrustedKey>, VerifyError> {
    let kty = key.get("kty").and_then(Value::as_str).unwrap_or("");
    match (alg, kty) {
        (Alg::EdDsa, "OKP") => {
            if key.get("crv").and_then(Value::as_str) != Some("Ed25519") {
                return Ok(None);
            }
            let x = b64(key.get("x"))?;
            let bytes: [u8; 32] = x.try_into().map_err(|_| VerifyError::UnknownKey)?;
            Ok(Some(TrustedKey::Ed25519(bytes)))
        }
        (Alg::Es256, "EC") => {
            if key.get("crv").and_then(Value::as_str) != Some("P-256") {
                return Ok(None);
            }
            let x = b64(key.get("x"))?;
            let y = b64(key.get("y"))?;
            // SEC1 uncompressed point: 0x04 || X || Y.
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| VerifyError::UnknownKey)?;
            Ok(Some(TrustedKey::P256(Box::new(verifying))))
        }
        (Alg::Rs256, "RSA") => {
            let n = rsa::BigUint::from_bytes_be(&b64(key.get("n"))?);
            let e = rsa::BigUint::from_bytes_be(&b64(key.get("e"))?);
            let public = rsa::RsaPublicKey::new(n, e).map_err(|_| VerifyError::UnknownKey)?;
            Ok(Some(TrustedKey::Rsa(Box::new(public))))
        }
        _ => Ok(None),
    }
}

/// base64url-decode a JWK member.
fn b64(member: Option<&Value>) -> Result<Vec<u8>, VerifyError> {
    let text = member
        .and_then(Value::as_str)
        .ok_or(VerifyError::UnknownKey)?;
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| VerifyError::UnknownKey)
}

/// Check the signature. The algorithm comes from the policy and the key from the JWKS; neither
/// is taken from the token.
fn verify_signature(
    alg: Alg,
    key: &TrustedKey,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match (alg, key) {
        (Alg::EdDsa, TrustedKey::Ed25519(bytes)) => {
            use ed25519_dalek::Verifier as _;
            let verifying = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|_| VerifyError::UnknownKey)?;
            let signature: [u8; 64] = signature
                .try_into()
                .map_err(|_| VerifyError::BadSignature)?;
            verifying
                .verify(
                    signing_input,
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .map_err(|_| VerifyError::BadSignature)
        }
        (Alg::Es256, TrustedKey::P256(verifying)) => {
            use p256::ecdsa::signature::Verifier as _;
            // FIXED-WIDTH r||s, which is what JOSE carries. `Signature::from_der` would accept
            // the ASN.1 form some libraries emit, and accepting both would let one token have
            // two encodings -- a signature malleability the JOSE serialization exists to avoid.
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| VerifyError::BadSignature)?;
            verifying
                .verify(signing_input, &signature)
                .map_err(|_| VerifyError::BadSignature)
        }
        (Alg::Rs256, TrustedKey::Rsa(public)) => {
            use rsa::signature::Verifier as _;
            let verifying =
                rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new((**public).clone());
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| VerifyError::BadSignature)?;
            verifying
                .verify(signing_input, &signature)
                .map_err(|_| VerifyError::BadSignature)
        }
        // Unreachable given `select_key` matched the type to the algorithm, and returned rather
        // than defaulted so a future algorithm cannot fall through to a wrong verifier.
        _ => Err(VerifyError::UnknownKey),
    }
}

/// Check `iss`, `aud`, `exp` and `nbf`.
fn check_claims(claims: &Value, policy: &Policy<'_>) -> Result<(), VerifyError> {
    if claims.get("iss").and_then(Value::as_str) != Some(policy.issuer) {
        return Err(VerifyError::WrongIssuer);
    }
    // `aud` IS EITHER A STRING OR AN ARRAY (RFC 7519 section 4.1.3), and a verifier that handled
    // only the string form would reject every multi-audience token an issuer is entitled to mint.
    let audience_ok = match claims.get("aud") {
        Some(Value::String(one)) => one == policy.audience,
        Some(Value::Array(many)) => many
            .iter()
            .any(|entry| entry.as_str() == Some(policy.audience)),
        _ => false,
    };
    if !audience_ok {
        return Err(VerifyError::WrongAudience);
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(VerifyError::Expired)?;
    // `exp` IS REQUIRED, not merely checked when present. A token with no expiry never expires,
    // and treating an absent claim as "fine" is how one gets accepted forever.
    if policy.now_unix_seconds > exp.saturating_add(policy.leeway_seconds) {
        return Err(VerifyError::Expired);
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
        if policy.now_unix_seconds < nbf.saturating_sub(policy.leeway_seconds) {
            return Err(VerifyError::NotYetValid);
        }
    }
    Ok(())
}

/// base64url-decode one compact segment.
fn decode_segment(segment: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| VerifyError::Malformed)
}

/// base64url-decode a segment and parse it as JSON.
fn decode_json(segment: &str) -> Result<Value, VerifyError> {
    serde_json::from_slice(&decode_segment(segment)?).map_err(|_| VerifyError::Malformed)
}
