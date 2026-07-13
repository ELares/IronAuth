// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected-header parsing and the header trust guards.
//!
//! This module reads the token's protected header ONLY to reject it or to
//! extract two non-trust values: the claimed `alg` (checked against the policy
//! allowlist and the key family, never used to reach outside the policy) and an
//! optional `kid` (a selector among already-trusted keys, never a key source).
//! Every header member that could steer trust from the token, introduce key
//! material, or expand input is a hard reject here, before any signature check.

use serde_json::Value;

use crate::error::RejectReason;
use crate::json::parse_unique_object;
use crate::policy::{JwsAlgorithm, VerificationCaps};

/// The two non-trust values extracted from a validated protected header.
pub(crate) struct ProtectedHeader {
    /// The claimed algorithm, already confirmed supported (not `none`, not
    /// HMAC). Still to be checked against the policy allowlist and key family.
    pub(crate) alg: JwsAlgorithm,
    /// The optional key id, used only to select among trusted keys.
    pub(crate) kid: Option<String>,
}

/// Registered JOSE header parameters. A `crit` member naming any of these is
/// malformed (RFC 7515 section 4.1.11 forbids listing registered names).
const REGISTERED_HEADER_PARAMS: &[&str] = &[
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "enc",
    "zip", "epk", "apu", "apv", "iv", "tag", "aad", "p2s", "p2c",
];

/// Parse and validate the decoded protected-header bytes.
///
/// Returns the extracted [`ProtectedHeader`] on success, or the precise
/// [`RejectReason`] for the first guard that fires.
pub(crate) fn parse(
    bytes: &[u8],
    caps: &VerificationCaps,
) -> Result<ProtectedHeader, RejectReason> {
    let object = parse_unique_object(bytes).map_err(|()| RejectReason::HeaderMalformed)?;

    // JWE and compression: reject structurally, before any field that could
    // expand input is honored.
    if object.contains_key("enc") || object.contains_key("epk") || object.contains_key("tag") {
        return Err(RejectReason::EncryptionPresent);
    }
    if object.contains_key("zip") {
        return Err(RejectReason::CompressionPresent);
    }

    // RFC 7797: `b64` steers whether the payload is base64url-encoded and MUST
    // appear in `crit` if used. A `b64` inside `crit` is already rejected (any
    // crit is); a BARE `b64` member is a trust-steering parameter we do not
    // honor, so reject it rather than silently ignore it.
    if object.contains_key("b64") {
        return Err(RejectReason::UnsupportedHeaderParam);
    }

    // PBES2: reject the key-derivation parameters outright, and reject a
    // bomb-shaped iteration count cheaply.
    if object.contains_key("p2s") {
        return Err(RejectReason::Pbes2Present);
    }
    if let Some(p2c) = object.get("p2c") {
        // Any p2c means PBES2. If it is a number above the cap, that is the
        // cheap oversized-iteration rejection; either way PBES2 is excluded.
        if let Some(count) = p2c.as_u64() {
            if count > u64::from(caps.max_pbes2_count) {
                return Err(RejectReason::Pbes2Present);
            }
        }
        return Err(RejectReason::Pbes2Present);
    }

    // In-token key material: never trusted, never fetched, always rejected.
    if object.contains_key("jwk")
        || object.contains_key("jku")
        || object.contains_key("x5u")
        || object.contains_key("x5c")
    {
        return Err(RejectReason::EmbeddedKeyInjection);
    }

    // crit: the core understands no extensions in M1, so any crit is a reject.
    if let Some(crit) = object.get("crit") {
        return Err(classify_crit(crit));
    }

    // alg: the only trust-relevant field we read, and only to match the policy.
    let alg = classify_alg(object.get("alg"))?;

    // kid: an optional selector among trusted keys. Must be a string if present.
    let kid = match object.get("kid") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(RejectReason::HeaderMalformed),
    };

    Ok(ProtectedHeader { alg, kid })
}

/// Classify the `alg` header value into a supported algorithm or a reject.
fn classify_alg(alg: Option<&Value>) -> Result<JwsAlgorithm, RejectReason> {
    let name = match alg {
        // Absent or null alg is an unsecured JWS: treat as the `none` reject.
        None | Some(Value::Null) => return Err(RejectReason::AlgNone),
        Some(Value::String(s)) => s,
        // A non-string alg is structurally malformed.
        Some(_) => return Err(RejectReason::HeaderMalformed),
    };

    // Reject `none` in every case and whitespace variant, and the empty string.
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Err(RejectReason::AlgNone);
    }

    // Exact, case-sensitive match against the supported set. HMAC and every
    // other unsupported name (including a padded near-miss like " RS256 ") lands
    // here as UnsupportedAlg.
    JwsAlgorithm::from_jose_name(name).ok_or(RejectReason::UnsupportedAlg)
}

/// Classify a `crit` header value. Any outcome is a reject; the distinction is
/// only for diagnostics.
fn classify_crit(crit: &Value) -> RejectReason {
    let Value::Array(members) = crit else {
        return RejectReason::MalformedCrit;
    };
    if members.is_empty() {
        // RFC 7515: crit MUST NOT be empty.
        return RejectReason::MalformedCrit;
    }
    let mut seen: Vec<&str> = Vec::with_capacity(members.len());
    for member in members {
        let Value::String(name) = member else {
            return RejectReason::MalformedCrit;
        };
        if seen.contains(&name.as_str()) {
            return RejectReason::MalformedCrit;
        }
        if REGISTERED_HEADER_PARAMS.contains(&name.as_str()) {
            // crit MUST NOT list registered parameters.
            return RejectReason::MalformedCrit;
        }
        seen.push(name);
    }
    // Well-formed, but naming extensions we do not understand.
    RejectReason::UnknownCrit
}
