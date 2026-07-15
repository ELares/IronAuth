// SPDX-License-Identifier: MIT OR Apache-2.0

//! Claim parsing and the central, non-optional claim enforcement.
//!
//! Enforcement runs only AFTER the signature has verified, so no unverified
//! payload is ever trusted. The rules follow OIDC Core 3.1.3.7: `iss` and `aud`
//! are matched EXACTLY (no substring, prefix, or normalization), `aud` may be a
//! JSON array in which the expected audience must appear as an exact member, and
//! `exp`/`nbf`/`iat` are checked against the env clock within a bounded,
//! configurable skew. There is no flag to skip any of this: the policy cannot be
//! built without an expected issuer and audience, and `exp` is required by
//! default.

use serde_json::{Map, Value};

use crate::error::RejectReason;
use crate::json::parse_unique_object;
use crate::policy::VerificationPolicy;

/// The verified claims of a token, exposed after all checks pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedClaims {
    issuer: String,
    subject: Option<String>,
    audiences: Vec<String>,
    expiration: Option<i64>,
    not_before: Option<i64>,
    issued_at: Option<i64>,
    raw: Map<String, Value>,
}

impl VerifiedClaims {
    /// The `iss` claim, matched exactly against the expected issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The `sub` claim, if present.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The `aud` claim as a normalized list. The expected audience is guaranteed
    /// to be an exact member.
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// The `exp` claim as seconds since the Unix epoch, if present.
    #[must_use]
    pub fn expiration(&self) -> Option<i64> {
        self.expiration
    }

    /// The `nbf` claim as seconds since the Unix epoch, if present.
    #[must_use]
    pub fn not_before(&self) -> Option<i64> {
        self.not_before
    }

    /// The `iat` claim as seconds since the Unix epoch, if present.
    #[must_use]
    pub fn issued_at(&self) -> Option<i64> {
        self.issued_at
    }

    /// The full set of claims, for reading application-specific members.
    #[must_use]
    pub fn raw(&self) -> &Map<String, Value> {
        &self.raw
    }

    /// A single claim by name, for reading application-specific members.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.raw.get(name)
    }
}

/// Parse the claims and enforce the central rules against `now_secs` (seconds
/// since the Unix epoch, from the env clock).
pub(crate) fn parse_and_enforce(
    bytes: &[u8],
    policy: &VerificationPolicy,
    now_secs: i64,
) -> Result<VerifiedClaims, RejectReason> {
    let raw = parse_unique_object(bytes).map_err(|()| RejectReason::ClaimsMalformed)?;

    let issuer = enforce_issuer(&raw, &policy.expected_iss)?;
    let audiences = enforce_audience(&raw, &policy.expected_aud)?;

    let skew = i64::try_from(policy.max_skew.as_secs()).unwrap_or(i64::MAX);

    let expiration = enforce_exp(&raw, now_secs, skew, policy.allow_expired)?;
    let not_before = enforce_nbf(&raw, now_secs, skew)?;
    let issued_at = enforce_iat(&raw, now_secs, skew, policy.require_iat)?;

    let subject = match raw.get("sub") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(RejectReason::ClaimsMalformed),
    };

    Ok(VerifiedClaims {
        issuer,
        subject,
        audiences,
        expiration,
        not_before,
        issued_at,
        raw,
    })
}

fn enforce_issuer(raw: &Map<String, Value>, expected: &str) -> Result<String, RejectReason> {
    match raw.get("iss") {
        None | Some(Value::Null) => Err(RejectReason::ClaimMissing),
        Some(Value::String(iss)) => {
            // Exact, byte-for-byte match. No substring, prefix, or case folding.
            if iss == expected {
                Ok(iss.clone())
            } else {
                Err(RejectReason::IssuerMismatch)
            }
        }
        Some(_) => Err(RejectReason::ClaimsMalformed),
    }
}

fn enforce_audience(raw: &Map<String, Value>, expected: &str) -> Result<Vec<String>, RejectReason> {
    match raw.get("aud") {
        None | Some(Value::Null) => Err(RejectReason::ClaimMissing),
        Some(Value::String(aud)) => {
            if aud == expected {
                Ok(vec![aud.clone()])
            } else {
                Err(RejectReason::AudienceMismatch)
            }
        }
        Some(Value::Array(items)) => {
            let mut auds = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(s) => auds.push(s.clone()),
                    // A non-string member makes the whole aud claim malformed.
                    _ => return Err(RejectReason::ClaimsMalformed),
                }
            }
            // Exact membership: the expected audience must appear verbatim.
            if auds.iter().any(|a| a == expected) {
                Ok(auds)
            } else {
                Err(RejectReason::AudienceMismatch)
            }
        }
        Some(_) => Err(RejectReason::ClaimsMalformed),
    }
}

/// The largest integer an `f64` represents exactly (2^53).
const MAX_EXACT_F64_INT: f64 = 9_007_199_254_740_992.0;

/// The largest absolute `NumericDate` (in seconds) accepted. Anything at or
/// beyond 2^53 seconds is a date near year 285-million: no legitimate token
/// carries one, and 2^53 is also the largest integer an `f64` represents
/// exactly, so this is the clean fail-closed boundary for both branches below.
const MAX_ABS_NUMERIC_DATE: i64 = 9_007_199_254_740_992; // 2^53

/// Read a `NumericDate` claim as integer seconds. A non-number, a non-finite
/// float, or an absurd magnitude (|seconds| >= 2^53) is malformed.
///
/// Rejecting the absurd magnitude uniformly is what keeps `exp` fail-closed like
/// `nbf`/`iat`: without it a huge `exp` would silently make a token
/// non-expiring, while a huge `nbf`/`iat` already fails closed.
fn numeric_date(value: &Value) -> Result<i64, RejectReason> {
    let secs = if let Some(n) = value.as_i64() {
        n
    } else if let Some(f) = value.as_f64() {
        if !f.is_finite() {
            // NaN or infinity is not a valid NumericDate.
            return Err(RejectReason::ClaimsMalformed);
        }
        // NumericDate may be fractional; floor to whole seconds. The magnitude
        // guard below rejects anything outside the exact-integer f64 range, so
        // this cast never truncates or wraps for a value it lets through; a
        // value at or beyond the range is rejected rather than clamped.
        let floored = f.floor();
        if floored >= MAX_EXACT_F64_INT || floored <= -MAX_EXACT_F64_INT {
            return Err(RejectReason::ClaimsMalformed);
        }
        #[allow(
            clippy::cast_possible_truncation,
            reason = "value is bounded to the exact-integer f64 range, so this neither truncates nor wraps"
        )]
        let v = floored as i64;
        v
    } else {
        return Err(RejectReason::ClaimsMalformed);
    };

    // Uniform fail-closed guard for both branches: an absurd magnitude (a date
    // near year 285-million) is malformed, so a huge exp cannot make a token
    // non-expiring. Compared by bounds rather than abs() so i64::MIN cannot
    // overflow.
    if secs >= MAX_ABS_NUMERIC_DATE || secs <= -MAX_ABS_NUMERIC_DATE {
        return Err(RejectReason::ClaimsMalformed);
    }
    Ok(secs)
}

fn enforce_exp(
    raw: &Map<String, Value>,
    now_secs: i64,
    skew: i64,
    allow_expired: bool,
) -> Result<Option<i64>, RejectReason> {
    match raw.get("exp") {
        // exp is required regardless: a token without an expiry is refused even when
        // allow_expired is set, so the relaxation admits only a well-formed PAST exp,
        // never a token that simply omits one.
        None | Some(Value::Null) => Err(RejectReason::ClaimMissing),
        Some(value) => {
            let exp = numeric_date(value)?;
            // Rejected once now has passed exp plus the tolerated skew, UNLESS the
            // caller opted into accepting a past expiry (RP-Initiated Logout's
            // id_token_hint, VerificationPolicy::allow_expired). The claim is still
            // parsed and returned; only the "now > exp" rejection is waived.
            if !allow_expired && now_secs > exp.saturating_add(skew) {
                Err(RejectReason::Expired)
            } else {
                Ok(Some(exp))
            }
        }
    }
}

fn enforce_nbf(
    raw: &Map<String, Value>,
    now_secs: i64,
    skew: i64,
) -> Result<Option<i64>, RejectReason> {
    match raw.get("nbf") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let nbf = numeric_date(value)?;
            // Rejected while now plus tolerance is still before nbf.
            if now_secs.saturating_add(skew) < nbf {
                Err(RejectReason::NotYetValid)
            } else {
                Ok(Some(nbf))
            }
        }
    }
}

fn enforce_iat(
    raw: &Map<String, Value>,
    now_secs: i64,
    skew: i64,
    require: bool,
) -> Result<Option<i64>, RejectReason> {
    match raw.get("iat") {
        None | Some(Value::Null) => {
            if require {
                Err(RejectReason::ClaimMissing)
            } else {
                Ok(None)
            }
        }
        Some(value) => {
            let iat = numeric_date(value)?;
            // An issue time in the future beyond tolerance is refused.
            if iat > now_secs.saturating_add(skew) {
                Err(RejectReason::IssuedInFuture)
            } else {
                Ok(Some(iat))
            }
        }
    }
}
