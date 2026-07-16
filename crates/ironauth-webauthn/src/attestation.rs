// SPDX-License-Identifier: MIT OR Apache-2.0

//! attestationObject decoding (WebAuthn Level 3 section 6.5).
//!
//! The attestationObject is a CBOR map `{ fmt, attStmt, authData }`. This issue
//! deliberately does NOT validate the attestation statement (`fmt`/`attStmt`):
//! attestation-statement trust, MDS3, and AAGUID allowlists are out of scope
//! (issue #66), and the ceremony requests `attestation: "none"`. So this module
//! extracts only the `authData` byte string; the security of registration comes
//! from the challenge, origin, RP ID hash, and flag checks on that authData, not
//! from the attestation statement.

use ciborium::value::Value;

use crate::error::CeremonyError;

/// Extract the raw `authData` byte string from an attestationObject.
///
/// # Errors
///
/// Returns [`CeremonyError::MalformedAttestationObject`] if the bytes are not a
/// CBOR map or the map has no `authData` byte string.
pub fn extract_auth_data(attestation_object: &[u8]) -> Result<Vec<u8>, CeremonyError> {
    let value: Value = ciborium::from_reader(attestation_object)
        .map_err(|_| CeremonyError::MalformedAttestationObject)?;
    let map = value
        .as_map()
        .ok_or(CeremonyError::MalformedAttestationObject)?;
    for (key, entry) in map {
        if key.as_text() == Some("authData") {
            return entry
                .as_bytes()
                .cloned()
                .ok_or(CeremonyError::MalformedAttestationObject);
        }
    }
    Err(CeremonyError::MalformedAttestationObject)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation_object(auth_data: Vec<u8>) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    #[test]
    fn extracts_auth_data() {
        let obj = attestation_object(vec![1, 2, 3, 4]);
        assert_eq!(extract_auth_data(&obj).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_non_cbor() {
        assert_eq!(
            extract_auth_data(&[0xff, 0xff]),
            Err(CeremonyError::MalformedAttestationObject)
        );
    }

    #[test]
    fn rejects_map_without_auth_data() {
        let value = Value::Map(vec![(
            Value::Text("fmt".into()),
            Value::Text("none".into()),
        )]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        assert_eq!(
            extract_auth_data(&out),
            Err(CeremonyError::MalformedAttestationObject)
        );
    }
}
