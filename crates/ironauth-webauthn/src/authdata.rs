// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticator data parsing (WebAuthn Level 3 section 6.1).
//!
//! Authenticator data is the fixed 37-byte header (`rpIdHash` + flags +
//! signCount) optionally followed by attested credential data (on registration)
//! and a CBOR extensions map. Parsing is total and bounds-checked: any
//! truncation or malformed CBOR returns an error rather than panicking, which
//! the fuzz target exercises.

use std::io::Cursor;

use ciborium::value::Value;

use crate::error::CeremonyError;
use crate::flags::AuthenticatorFlags;

/// The fixed header length: 32-byte rpIdHash + 1 flags byte + 4 signCount bytes.
const HEADER_LEN: usize = 37;
/// The AAGUID length in the attested credential data.
const AAGUID_LEN: usize = 16;

/// Parsed authenticator data.
#[derive(Clone, Debug)]
pub struct AuthenticatorData {
    /// SHA-256 of the RP ID the authenticator scoped this operation to.
    pub rp_id_hash: [u8; 32],
    /// The parsed flags byte (UP/UV/BE/BS/AT/ED).
    pub flags: AuthenticatorFlags,
    /// The signature counter (0 if the authenticator does not implement one).
    pub sign_count: u32,
    /// The attested credential data, present only on registration (AT flag set).
    pub attested_credential: Option<AttestedCredential>,
}

/// The attested credential data carried in a registration's authenticator data.
#[derive(Clone, Debug)]
pub struct AttestedCredential {
    /// The authenticator model identifier (all zero for privacy-preserving
    /// authenticators).
    pub aaguid: [u8; AAGUID_LEN],
    /// The credential id the authenticator minted.
    pub credential_id: Vec<u8>,
    /// The raw `COSE_Key` bytes of the credential public key, stored verbatim so
    /// the exact bytes round-trip through persistence for later verification.
    pub cose_public_key: Vec<u8>,
}

/// Parse authenticator data.
///
/// # Errors
///
/// Returns [`CeremonyError::MalformedAuthenticatorData`] if the buffer is
/// shorter than the header, the attested credential data is truncated, or the
/// embedded COSE public key is not valid CBOR.
pub fn parse_authenticator_data(bytes: &[u8]) -> Result<AuthenticatorData, CeremonyError> {
    if bytes.len() < HEADER_LEN {
        return Err(CeremonyError::MalformedAuthenticatorData);
    }
    let rp_id_hash: [u8; 32] = <[u8; 32]>::try_from(&bytes[0..32])
        .map_err(|_| CeremonyError::MalformedAuthenticatorData)?;
    let flags = AuthenticatorFlags::from_byte(bytes[32]);
    let sign_count = u32::from_be_bytes(
        <[u8; 4]>::try_from(&bytes[33..37])
            .map_err(|_| CeremonyError::MalformedAuthenticatorData)?,
    );

    let attested_credential = if flags.attested_credential_data {
        Some(parse_attested_credential(&bytes[HEADER_LEN..])?)
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential,
    })
}

fn parse_attested_credential(bytes: &[u8]) -> Result<AttestedCredential, CeremonyError> {
    // aaguid (16) + credIdLen (2) minimum.
    if bytes.len() < AAGUID_LEN + 2 {
        return Err(CeremonyError::MalformedAuthenticatorData);
    }
    let aaguid: [u8; AAGUID_LEN] = <[u8; AAGUID_LEN]>::try_from(&bytes[0..AAGUID_LEN])
        .map_err(|_| CeremonyError::MalformedAuthenticatorData)?;
    let cred_id_len = usize::from(u16::from_be_bytes(
        <[u8; 2]>::try_from(&bytes[AAGUID_LEN..AAGUID_LEN + 2])
            .map_err(|_| CeremonyError::MalformedAuthenticatorData)?,
    ));
    let cred_id_start = AAGUID_LEN + 2;
    let cred_id_end = cred_id_start
        .checked_add(cred_id_len)
        .ok_or(CeremonyError::MalformedAuthenticatorData)?;
    if bytes.len() < cred_id_end {
        return Err(CeremonyError::MalformedAuthenticatorData);
    }
    let credential_id = bytes[cred_id_start..cred_id_end].to_vec();

    // The COSE public key is a single CBOR item of unknown length; read exactly
    // one item and measure how many bytes it consumed so the raw COSE bytes can
    // be sliced out and stored verbatim.
    let cose_slice = &bytes[cred_id_end..];
    let mut cursor = Cursor::new(cose_slice);
    let _key: Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| CeremonyError::MalformedAuthenticatorData)?;
    let consumed = usize::try_from(cursor.position())
        .map_err(|_| CeremonyError::MalformedAuthenticatorData)?;
    let cose_public_key = cose_slice[..consumed].to_vec();

    Ok(AttestedCredential {
        aaguid,
        credential_id,
        cose_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Integer;

    fn sample_cose_key() -> Vec<u8> {
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-7)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(1)),
            ),
            (
                Value::Integer(Integer::from(-2)),
                Value::Bytes(vec![1_u8; 32]),
            ),
            (
                Value::Integer(Integer::from(-3)),
                Value::Bytes(vec![2_u8; 32]),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    fn registration_authdata(cred_id: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xaa; 32]); // rpIdHash
        data.push(0b0100_0101); // UP + UV + AT
        data.extend_from_slice(&[0, 0, 0, 5]); // signCount 5
        data.extend_from_slice(&[0xbb; 16]); // aaguid
        data.extend_from_slice(&u16::try_from(cred_id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(cred_id);
        data.extend_from_slice(&sample_cose_key());
        data.extend_from_slice(trailing);
        data
    }

    #[test]
    fn parses_the_assertion_header() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xaa; 32]);
        data.push(0b0000_0101); // UP + UV, no AT
        data.extend_from_slice(&[0, 0, 0, 42]);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert_eq!(parsed.rp_id_hash, [0xaa; 32]);
        assert!(parsed.flags.user_present);
        assert!(parsed.flags.user_verified);
        assert_eq!(parsed.sign_count, 42);
        assert!(parsed.attested_credential.is_none());
    }

    #[test]
    fn parses_attested_credential_and_slices_the_exact_cose_bytes() {
        let cred_id = vec![9_u8; 20];
        let data = registration_authdata(&cred_id, &[]);
        let parsed = parse_authenticator_data(&data).unwrap();
        let attested = parsed.attested_credential.unwrap();
        assert_eq!(attested.aaguid, [0xbb; 16]);
        assert_eq!(attested.credential_id, cred_id);
        assert_eq!(attested.cose_public_key, sample_cose_key());
    }

    #[test]
    fn ignores_trailing_extension_bytes_after_the_cose_key() {
        // A registration with AT set: the COSE key must be sliced to its exact
        // length even when extension bytes follow.
        let cred_id = vec![3_u8; 16];
        let data = registration_authdata(&cred_id, &[0xde, 0xad, 0xbe, 0xef]);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert_eq!(
            parsed.attested_credential.unwrap().cose_public_key,
            sample_cose_key()
        );
    }

    #[test]
    fn rejects_a_truncated_header() {
        assert!(parse_authenticator_data(&[0_u8; 10]).is_err());
    }

    #[test]
    fn rejects_a_credential_id_length_past_the_end() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xaa; 32]);
        data.push(0b0100_0001); // UP + AT
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&[0xbb; 16]);
        data.extend_from_slice(&u16::MAX.to_be_bytes()); // claims 65535 bytes
        data.extend_from_slice(&[0_u8; 4]); // but only 4 present
        assert!(parse_authenticator_data(&data).is_err());
    }
}
