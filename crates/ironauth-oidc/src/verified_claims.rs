// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `verified_claims` envelope (issue #164, IDA schema readiness).
//!
//! This module is the schema-readiness seam: the claims pipeline carries
//! per-claim verification metadata (trust framework, evidence, assurance) so
//! the full IDA `verified_claims` surface is an additive feature later instead
//! of a core rework. TODAY it ships the subset semantics:
//!
//! - The STORED side: the user's claim document (migration 0009, stored
//!   verbatim) may carry a `verified_claims` member:
//!
//!   ```json
//!   {
//!     "verification": {
//!       "trust_framework": "de_aml",
//!       "assurance": "high",
//!       "evidence": [{"type": "document", "method": "pipp"}]
//!     },
//!     "claims": {"email": "a@b.test"}
//!   }
//!   ```
//!
//! - The REQUESTED side: the `claims` parameter names `verified_claims`, and
//!   the request may pin the verification subset (the trust frameworks and
//!   assurance levels it will accept), exactly the subset semantics IDA
//!   needs. An envelope that does not satisfy the pinned subset is OMITTED,
//!   the same omission rule the per-claim path applies.
//! - The EMITTED side: [`release_subset`] produces the filtered envelope; the
//!   one shared assembler (`scope_claims::assemble_claims`) releases it.
//!
//! The model is deliberately a carrier, not a verifier: this module does not
//! inspect or assert anything about the metadata's truth, it moves it. Whether
//! a trust framework label is believable is the identity-proofing question the
//! framework itself answers.

use serde_json::Value;

use crate::claims_request::ClaimSpec;

/// The claim name of the `verified_claims` envelope (the OIDC/IDA standard name).
pub const VERIFIED_CLAIMS_CLAIM: &str = "verified_claims";

/// Release the envelope the request's spec allows, or `None` when the envelope
/// does not satisfy the request's pinned subset.
///
/// - A request with NO pin releases the envelope verbatim (voluntary claim:
///   present in the bag, released).
/// - A request pinning `verification.trust_framework` (one or more values)
///   releases the envelope ONLY when its framework is among them.
/// - A request pinning `verification.assurance` releases the envelope ONLY
///   when the assurance is among the pinned values.
/// - An essential request whose pins fail yields `None` (the caller omits the
///   claim; the essential/voluntary distinction is the CALLER's concern, the
///   subset rule is this module's).
///
/// The envelope is never partially released: verification metadata and claims
/// ride together, because releasing the claims half without the assurance
/// context would present unverifiable identity data as verified.
pub fn release_subset(envelope: &Value, spec: &ClaimSpec) -> Option<Value> {
    let object = envelope.as_object()?;
    let verification = object.get("verification")?.as_object()?;
    let framework = verification
        .get("trust_framework")
        .and_then(Value::as_str)?;

    // The request's pins live under `verification` inside the request's own
    // envelope-shaped spec: `{"verified_claims": {"verification": {...}}}`.
    let requested_value = spec.pinned_value()?;
    let requested_verification = requested_value.get("verification")?.as_object()?;

    // Trust framework: pinned only when the request names values.
    if let Some(pinned) = requested_verification.get("trust_framework") {
        let accepted = pinned
            .as_array()
            .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
            .or_else(|| pinned.as_str().map(|s| vec![s]))?;
        // Unknown framework names obey the same exact comparison as known ones.
        let matches = accepted.contains(&framework);
        if !matches {
            return None;
        }
    }

    // Assurance: pinned the same way.
    if let Some(pinned) = requested_verification.get("assurance") {
        let accepted = pinned
            .as_array()
            .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
            .or_else(|| pinned.as_str().map(|s| vec![s]))?;
        let assurance = verification.get("assurance").and_then(Value::as_str)?;
        if !accepted.contains(&assurance) {
            return None;
        }
    }

    Some(envelope.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn envelope(framework: &str, assurance: &str) -> Value {
        json!({
            "verification": {
                "trust_framework": framework,
                "assurance": assurance,
                "evidence": [{"type": "document"}]
            },
            "claims": {"email": "a@b.test"}
        })
    }

    fn spec(value: Value) -> ClaimSpec {
        ClaimSpec::with_value(value)
    }

    #[test]
    fn an_unpinned_request_releases_the_envelope_verbatim() {
        let released = release_subset(
            &envelope("de_aml", "high"),
            &spec(json!({"verification": {}})),
        )
        .expect("released");
        assert_eq!(released, envelope("de_aml", "high"));
    }

    #[test]
    fn a_matching_framework_pin_releases() {
        let request = spec(json!({"verification": {"trust_framework": ["de_aml"]}}));
        assert!(release_subset(&envelope("de_aml", "high"), &request).is_some());
    }

    #[test]
    fn a_mismatched_framework_pin_omits() {
        let request = spec(json!({"verification": {"trust_framework": ["eidas"]}}));
        assert_eq!(
            release_subset(&envelope("de_aml", "high"), &request),
            None,
            "an envelope outside the pinned framework is omitted, never partially released"
        );
    }

    #[test]
    fn an_assurance_pin_is_enforced() {
        let request = spec(json!({"verification": {"assurance": ["low"]}}));
        assert_eq!(release_subset(&envelope("de_aml", "high"), &request), None);
        let request = spec(json!({"verification": {"assurance": ["high"]}}));
        assert!(release_subset(&envelope("de_aml", "high"), &request).is_some());
    }

    #[test]
    fn an_envelope_without_verification_is_never_released() {
        assert_eq!(
            release_subset(
                &json!({"claims": {"email": "a@b.test"}}),
                &spec(json!({"verification": {}}))
            ),
            None,
            "claims without the verification context must not present as verified"
        );
    }
}
