// SPDX-License-Identifier: MIT OR Apache-2.0

//! clientDataJSON parsing and validation (WebAuthn Level 3 section 5.8.1).
//!
//! The clientDataJSON is the browser's attestation of what it believes it did:
//! the ceremony type, the challenge it was given, and the origin it was invoked
//! from. It is parsed as JSON (never CBOR) and its three security-relevant
//! fields are checked against server expectations: the type must match the
//! ceremony, the challenge must equal the single-use challenge the server
//! issued, and the origin must be one the environment allows.

use serde::Deserialize;

use crate::encoding::{b64_decode, constant_time_eq};
use crate::error::CeremonyError;

/// The clientDataJSON `type` for a registration (create) ceremony.
pub const TYPE_CREATE: &str = "webauthn.create";
/// The clientDataJSON `type` for an authentication (get) ceremony.
pub const TYPE_GET: &str = "webauthn.get";

#[derive(Debug, Deserialize)]
struct RawClientData {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

/// The validated clientDataJSON fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientData {
    /// The ceremony type string (`webauthn.create` or `webauthn.get`).
    pub ceremony_type: String,
    /// The origin the ceremony was invoked from.
    pub origin: String,
}

/// Parse and validate clientDataJSON against the expected ceremony type,
/// single-use challenge, and allowed origins.
///
/// The `raw_json` must be the exact bytes the authenticator signed over (for an
/// assertion the SHA-256 of these bytes is part of the signed message), so the
/// caller passes the decoded clientDataJSON bytes verbatim.
///
/// # Errors
///
/// - [`CeremonyError::MalformedClientData`] if the JSON does not parse or the
///   challenge is not valid base64url.
/// - [`CeremonyError::WrongCeremonyType`] if the type is not `expected_type`.
/// - [`CeremonyError::ChallengeMismatch`] if the challenge does not equal
///   `expected_challenge`.
/// - [`CeremonyError::OriginMismatch`] if the origin is not in `allowed_origins`.
pub fn validate_client_data(
    raw_json: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
    allowed_origins: &[String],
) -> Result<ClientData, CeremonyError> {
    let raw: RawClientData =
        serde_json::from_slice(raw_json).map_err(|_| CeremonyError::MalformedClientData)?;

    if raw.ceremony_type != expected_type {
        return Err(CeremonyError::WrongCeremonyType);
    }

    let challenge_bytes = b64_decode(&raw.challenge).ok_or(CeremonyError::MalformedClientData)?;
    if !constant_time_eq(&challenge_bytes, expected_challenge) {
        return Err(CeremonyError::ChallengeMismatch);
    }

    // A cross-origin ceremony is refused: an IdP login must be top-level.
    if raw.cross_origin == Some(true) {
        return Err(CeremonyError::OriginMismatch);
    }

    if !allowed_origins.iter().any(|o| o == &raw.origin) {
        return Err(CeremonyError::OriginMismatch);
    }

    Ok(ClientData {
        ceremony_type: raw.ceremony_type,
        origin: raw.origin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::b64_encode;

    fn client_json(ceremony_type: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{ceremony_type}","challenge":"{}","origin":"{origin}"}}"#,
            b64_encode(challenge)
        )
        .into_bytes()
    }

    #[test]
    fn accepts_a_matching_ceremony() {
        let origins = vec!["https://auth.example.test".to_string()];
        let json = client_json(TYPE_GET, b"the-challenge", "https://auth.example.test");
        let data = validate_client_data(&json, TYPE_GET, b"the-challenge", &origins).unwrap();
        assert_eq!(data.ceremony_type, TYPE_GET);
        assert_eq!(data.origin, "https://auth.example.test");
    }

    #[test]
    fn rejects_wrong_type() {
        let origins = vec!["https://auth.example.test".to_string()];
        let json = client_json(TYPE_CREATE, b"c", "https://auth.example.test");
        assert_eq!(
            validate_client_data(&json, TYPE_GET, b"c", &origins),
            Err(CeremonyError::WrongCeremonyType)
        );
    }

    #[test]
    fn rejects_challenge_mismatch() {
        let origins = vec!["https://auth.example.test".to_string()];
        let json = client_json(TYPE_GET, b"other", "https://auth.example.test");
        assert_eq!(
            validate_client_data(&json, TYPE_GET, b"expected", &origins),
            Err(CeremonyError::ChallengeMismatch)
        );
    }

    #[test]
    fn accepts_a_listed_related_origin_and_rejects_an_unlisted_one() {
        // WebAuthn Related Origin Requests (issue #67): with the serving origin AND a
        // related origin in the allowed set, a ceremony from EITHER verifies, while an
        // origin outside the set still fails with OriginMismatch. This is the whole of
        // the origin-set widening at the core; the RP-ID-hash and signature live in
        // verify.rs and are unchanged.
        let origins = vec![
            "https://auth.example.test".to_string(),
            "https://example.de".to_string(),
        ];
        let related = client_json(TYPE_GET, b"c", "https://example.de");
        assert_eq!(
            validate_client_data(&related, TYPE_GET, b"c", &origins)
                .unwrap()
                .origin,
            "https://example.de"
        );
        let serving = client_json(TYPE_GET, b"c", "https://auth.example.test");
        assert!(validate_client_data(&serving, TYPE_GET, b"c", &origins).is_ok());
        let unlisted = client_json(TYPE_GET, b"c", "https://brand2.com");
        assert_eq!(
            validate_client_data(&unlisted, TYPE_GET, b"c", &origins),
            Err(CeremonyError::OriginMismatch)
        );
    }

    #[test]
    fn rejects_foreign_origin() {
        let origins = vec!["https://auth.example.test".to_string()];
        let json = client_json(TYPE_GET, b"c", "https://evil.example.test");
        assert_eq!(
            validate_client_data(&json, TYPE_GET, b"c", &origins),
            Err(CeremonyError::OriginMismatch)
        );
    }

    #[test]
    fn rejects_cross_origin() {
        let origins = vec!["https://auth.example.test".to_string()];
        let json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://auth.example.test","crossOrigin":true}}"#,
            b64_encode(b"c")
        );
        assert_eq!(
            validate_client_data(json.as_bytes(), TYPE_GET, b"c", &origins),
            Err(CeremonyError::OriginMismatch)
        );
    }

    #[test]
    fn rejects_malformed_json() {
        let origins = vec!["https://auth.example.test".to_string()];
        assert_eq!(
            validate_client_data(b"not json", TYPE_GET, b"c", &origins),
            Err(CeremonyError::MalformedClientData)
        );
    }
}
