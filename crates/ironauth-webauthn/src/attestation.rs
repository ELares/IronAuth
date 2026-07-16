// SPDX-License-Identifier: MIT OR Apache-2.0

//! attestationObject decoding and attestation-statement verification (WebAuthn
//! Level 3 section 6.5, section 8.2), for the FIDO MDS3 attestation policy (issue
//! #66 PR B).
//!
//! The attestationObject is a CBOR map `{ fmt, attStmt, authData }`. PR A extracted
//! only `authData` (attestation was `none` and trust came from the challenge,
//! origin, RP ID, and flag checks). PR B ADDS the statement path: under a tenant's
//! `direct` attestation mode, [`verify_attestation`] parses `fmt` and `attStmt` and
//! verifies a `packed` statement per WebAuthn L3 section 8.2. Two formats are
//! supported in v1, `none` and `packed`; any other format (`tpm`, `android-key`,
//! `android-safetynet`, `apple`, `fido-u2f`) is DEFERRED and, under `direct`, is a
//! clean fail-closed reject, never a silent downgrade to unattested.
//!
//! The verifier is PURE: the caller supplies the client-data hash, the credential
//! public key, the authenticator AAGUID, the trusted MDS3 attestation roots for
//! that AAGUID, and the clock instant. It performs no store read and no clock read;
//! the OIDC registration handler does those and passes the results in.

use ciborium::value::Value;
use ironauth_jose::WebauthnKey;

use crate::error::CeremonyError;
use crate::x509::{self, Certificate};

/// A decoded attestationObject: its format, its statement (raw CBOR entries), and
/// the authenticator data byte string.
#[derive(Debug, Clone)]
pub struct AttestationObject {
    /// The attestation statement format identifier (`none`, `packed`, ...).
    pub fmt: String,
    /// The attestation statement map entries, verbatim CBOR.
    pub att_stmt: Vec<(Value, Value)>,
    /// The raw authenticator data byte string.
    pub auth_data: Vec<u8>,
}

/// The attestation TYPE established (WebAuthn L3 section 6.5.3), mapped to the
/// `webauthn_credentials.attestation_type` persistence token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationType {
    /// No attestation statement (or `fmt: "none"`): the authenticator model is not
    /// proven. Persists as `none`.
    None,
    /// Self attestation: the statement is signed by the credential key itself, so
    /// it proves possession but NOT the authenticator model. Persists as `self`.
    SelfAttestation,
    /// Basic (full) attestation: a manufacturer attestation certificate chain that
    /// terminates at a trusted MDS3 root, proving the authenticator model. Persists
    /// as `basic`.
    Basic,
}

impl AttestationType {
    /// The persistence token for the `attestation_type` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AttestationType::None => "none",
            AttestationType::SelfAttestation => "self",
            AttestationType::Basic => "basic",
        }
    }
}

/// The outcome of attestation verification: the established type, the format
/// token, and whether the authenticator MODEL was cryptographically proven against
/// a trusted MDS3 root.
///
/// `model_verified` is the STORED `attestation_verified` fact: it is `true` ONLY
/// for basic attestation whose chain terminated at a trusted root AND whose
/// certificate AAGUID matched the authenticator data. It is `false` for `none` and
/// for self attestation (possession without a model proof), so the strongest
/// credential-class rung is never claimed on an unproven model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationOutcome {
    /// The established attestation type.
    pub attestation_type: AttestationType,
    /// The attestation format token (`none` or `packed`).
    pub fmt: &'static str,
    /// Whether the authenticator model was proven against a trusted MDS3 root.
    pub model_verified: bool,
}

// COSE algorithm identifiers used in a packed `alg`.
const ALG_ES256: i128 = -7;
const ALG_EDDSA: i128 = -8;
const ALG_RS256: i128 = -257;

/// Extract the raw `authData` byte string from an attestationObject.
///
/// Retained for the registration ceremony verifier, which needs only `authData`;
/// the statement path uses [`parse_attestation_object`].
///
/// # Errors
///
/// Returns [`CeremonyError::MalformedAttestationObject`] if the bytes are not a
/// CBOR map or the map has no `authData` byte string.
pub fn extract_auth_data(attestation_object: &[u8]) -> Result<Vec<u8>, CeremonyError> {
    Ok(parse_attestation_object(attestation_object)?.auth_data)
}

/// Parse an attestationObject into its `fmt`, `attStmt`, and `authData`.
///
/// # Errors
///
/// [`CeremonyError::MalformedAttestationObject`] if the bytes are not a CBOR map
/// or lack a valid `fmt`/`authData`.
pub fn parse_attestation_object(
    attestation_object: &[u8],
) -> Result<AttestationObject, CeremonyError> {
    let value: Value = ciborium::from_reader(attestation_object)
        .map_err(|_| CeremonyError::MalformedAttestationObject)?;
    let map = value
        .as_map()
        .ok_or(CeremonyError::MalformedAttestationObject)?;

    let mut fmt = None;
    let mut att_stmt = None;
    let mut auth_data = None;
    for (key, entry) in map {
        match key.as_text() {
            Some("fmt") => fmt = entry.as_text().map(str::to_owned),
            Some("attStmt") => att_stmt = entry.as_map().cloned(),
            Some("authData") => auth_data = entry.as_bytes().cloned(),
            _ => {}
        }
    }

    Ok(AttestationObject {
        fmt: fmt.ok_or(CeremonyError::MalformedAttestationObject)?,
        att_stmt: att_stmt.unwrap_or_default(),
        auth_data: auth_data.ok_or(CeremonyError::MalformedAttestationObject)?,
    })
}

/// Verify an attestation statement under tenant `direct` mode (WebAuthn L3 section
/// 8.2), given the client-data hash, the just-registered credential public key,
/// the authenticator AAGUID, the trusted MDS3 attestation roots (raw DER) for that
/// AAGUID, and the clock instant.
///
/// Returns the [`AttestationOutcome`]: `model_verified` is `true` only for basic
/// attestation that verified AND chained to a trusted root AND whose certificate
/// AAGUID matched. `none` and self attestation yield `model_verified: false`. An
/// unsupported format is [`CeremonyError::UnsupportedAttestationFormat`] (fail
/// closed under `direct`).
///
/// # Errors
///
/// A [`CeremonyError`] for an unsupported format, a bad signature, a broken chain,
/// or an AAGUID spoof.
pub fn verify_attestation(
    attestation: &AttestationObject,
    client_data_hash: &[u8],
    credential_key: &WebauthnKey,
    aaguid: &[u8; 16],
    trust_anchors_der: &[Vec<u8>],
    now_unix: i64,
) -> Result<AttestationOutcome, CeremonyError> {
    match attestation.fmt.as_str() {
        "none" => Ok(AttestationOutcome {
            attestation_type: AttestationType::None,
            fmt: "none",
            model_verified: false,
        }),
        "packed" => verify_packed(
            attestation,
            client_data_hash,
            credential_key,
            aaguid,
            trust_anchors_der,
            now_unix,
        ),
        _ => Err(CeremonyError::UnsupportedAttestationFormat),
    }
}

/// Verify a `packed` attestation statement (WebAuthn L3 section 8.2.1).
fn verify_packed(
    attestation: &AttestationObject,
    client_data_hash: &[u8],
    credential_key: &WebauthnKey,
    aaguid: &[u8; 16],
    trust_anchors_der: &[Vec<u8>],
    now_unix: i64,
) -> Result<AttestationOutcome, CeremonyError> {
    let alg =
        stmt_int(&attestation.att_stmt, "alg").ok_or(CeremonyError::MalformedAttestationObject)?;
    let sig = stmt_bytes(&attestation.att_stmt, "sig")
        .ok_or(CeremonyError::MalformedAttestationObject)?;
    let x5c = stmt_x5c(&attestation.att_stmt);

    // The signed message is authData || clientDataHash.
    let mut signed = Vec::with_capacity(attestation.auth_data.len() + client_data_hash.len());
    signed.extend_from_slice(&attestation.auth_data);
    signed.extend_from_slice(client_data_hash);

    if let Some(chain_ders) = x5c {
        // Full (basic) attestation: verify the leaf certificate signs the statement,
        // its AAGUID extension matches, and the chain terminates at a trusted root.
        if chain_ders.is_empty() {
            return Err(CeremonyError::MalformedAttestationObject);
        }
        let chain: Vec<Certificate<'_>> = chain_ders
            .iter()
            .map(|der| x509::parse_certificate(der))
            .collect::<Result<_, _>>()
            .map_err(|_| CeremonyError::AttestationChainInvalid)?;
        let leaf = &chain[0];

        // The leaf key signs authData || clientDataHash. A packed ECDSA signature is
        // ASN.1 DER (like a ceremony signature), so the DER-form primitive is correct.
        ironauth_jose::verify_webauthn_signature(&leaf.public_key, &signed, &sig)
            .map_err(|_| CeremonyError::AttestationSignatureInvalid)?;

        // If the certificate carries the FIDO AAGUID extension it MUST match the
        // authenticator data AAGUID: this is the AAGUID-spoof defence.
        if let Some(cert_aaguid) = leaf.aaguid {
            if &cert_aaguid != aaguid {
                return Err(CeremonyError::AttestationAaguidMismatch);
            }
        }

        // Chain the leaf to a trusted MDS3 attestation root for this AAGUID.
        let anchors: Vec<Certificate<'_>> = trust_anchors_der
            .iter()
            .map(|der| x509::parse_certificate(der))
            .collect::<Result<_, _>>()
            .map_err(|_| CeremonyError::AttestationChainInvalid)?;
        x509::verify_chain(&chain, &anchors, now_unix)
            .map_err(|_| CeremonyError::AttestationChainInvalid)?;

        // The alg must be consistent with the leaf key family (an ECDSA leaf cannot
        // claim an RSA alg): reject an inconsistent statement rather than trust it.
        if !alg_matches_key(alg, &leaf.public_key) {
            return Err(CeremonyError::AttestationSignatureInvalid);
        }

        Ok(AttestationOutcome {
            attestation_type: AttestationType::Basic,
            fmt: "packed",
            model_verified: true,
        })
    } else {
        // Self attestation: the statement is signed by the CREDENTIAL key. This proves
        // possession but NOT the authenticator model, so model_verified stays false.
        if !alg_matches_key(alg, credential_key) {
            return Err(CeremonyError::AttestationSignatureInvalid);
        }
        ironauth_jose::verify_webauthn_signature(credential_key, &signed, &sig)
            .map_err(|_| CeremonyError::AttestationSignatureInvalid)?;
        Ok(AttestationOutcome {
            attestation_type: AttestationType::SelfAttestation,
            fmt: "packed",
            model_verified: false,
        })
    }
}

/// Whether a COSE `alg` is consistent with a public key's family.
fn alg_matches_key(alg: i128, key: &WebauthnKey) -> bool {
    matches!(
        (alg, key),
        (ALG_ES256, WebauthnKey::Es256 { .. })
            | (ALG_EDDSA, WebauthnKey::Ed25519 { .. })
            | (ALG_RS256, WebauthnKey::Rs256 { .. })
    )
}

/// Read an integer-valued attestation-statement entry by text key.
fn stmt_int(att_stmt: &[(Value, Value)], key: &str) -> Option<i128> {
    find(att_stmt, key)?.as_integer().map(i128::from)
}

/// Read a byte-string attestation-statement entry by text key.
fn stmt_bytes(att_stmt: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    find(att_stmt, key)?.as_bytes().cloned()
}

/// Read the `x5c` certificate array (each a DER byte string) if present.
fn stmt_x5c(att_stmt: &[(Value, Value)]) -> Option<Vec<Vec<u8>>> {
    let array = find(att_stmt, "x5c")?.as_array()?;
    Some(array.iter().filter_map(|v| v.as_bytes().cloned()).collect())
}

/// Find a text-keyed attestation-statement entry.
fn find<'a>(att_stmt: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    att_stmt
        .iter()
        .find_map(|(k, v)| (k.as_text() == Some(key)).then_some(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation_object(fmt: &str, auth_data: Vec<u8>) -> Vec<u8> {
        let value = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text(fmt.into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    #[test]
    fn extracts_auth_data() {
        let obj = attestation_object("none", vec![1, 2, 3, 4]);
        assert_eq!(extract_auth_data(&obj).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn parses_fmt_and_stmt() {
        let obj = attestation_object("none", vec![9, 9]);
        let parsed = parse_attestation_object(&obj).unwrap();
        assert_eq!(parsed.fmt, "none");
        assert!(parsed.att_stmt.is_empty());
        assert_eq!(parsed.auth_data, vec![9, 9]);
    }

    #[test]
    fn rejects_non_cbor() {
        assert!(matches!(
            parse_attestation_object(&[0xff, 0xff]),
            Err(CeremonyError::MalformedAttestationObject)
        ));
    }

    #[test]
    fn rejects_map_without_auth_data() {
        let value = Value::Map(vec![(
            Value::Text("fmt".into()),
            Value::Text("none".into()),
        )]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        assert!(matches!(
            parse_attestation_object(&out),
            Err(CeremonyError::MalformedAttestationObject)
        ));
    }

    #[test]
    fn none_format_is_unverified() {
        let obj = parse_attestation_object(&attestation_object("none", vec![0; 37])).unwrap();
        let key = WebauthnKey::Ed25519 {
            public_key: vec![0; 32],
        };
        let outcome = verify_attestation(&obj, &[0; 32], &key, &[0; 16], &[], 0).unwrap();
        assert_eq!(outcome.attestation_type, AttestationType::None);
        assert!(!outcome.model_verified);
    }

    #[test]
    fn an_unsupported_format_fails_closed_under_direct() {
        let obj = parse_attestation_object(&attestation_object("tpm", vec![0; 37])).unwrap();
        let key = WebauthnKey::Ed25519 {
            public_key: vec![0; 32],
        };
        assert_eq!(
            verify_attestation(&obj, &[0; 32], &key, &[0; 16], &[], 0),
            Err(CeremonyError::UnsupportedAttestationFormat)
        );
    }

    // ---- Packed attestation (issue #66 PR B) ----

    use crate::testpki::{CertSpec, build_cert};
    use ironauth_jose::webauthn::test_util;

    const MODEL_ROOT_SEED: [u8; 32] = [4; 32];
    const LEAF_SEED: [u8; 32] = [5; 32];
    const CRED_SEED: [u8; 32] = [6; 32];
    const NOW: i64 = 1_700_000_000;
    const FAR: i64 = 4_102_444_800;
    const AAGUID: [u8; 16] = [0x11; 16];
    const AUTH_DATA: &[u8] = &[0xAB; 40];
    const CDH: &[u8] = &[0x22; 32];

    fn model_root() -> Vec<u8> {
        build_cert(&CertSpec {
            subject_cn: "Model Root",
            issuer_cn: "Model Root",
            subject_seed: MODEL_ROOT_SEED,
            issuer_seed: MODEL_ROOT_SEED,
            not_before: 0,
            not_after: FAR,
            aaguid: None,
            is_ca: true,
            path_len: None,
            key_usage: None,
        })
    }

    fn leaf(cert_aaguid: Option<[u8; 16]>) -> Vec<u8> {
        build_cert(&CertSpec {
            subject_cn: "Model Signer",
            issuer_cn: "Model Root",
            subject_seed: LEAF_SEED,
            issuer_seed: MODEL_ROOT_SEED,
            not_before: 0,
            not_after: FAR,
            aaguid: cert_aaguid,
            is_ca: false,
            path_len: None,
            key_usage: None,
        })
    }

    fn packed_object(x5c: Option<Vec<Vec<u8>>>, sig: Vec<u8>) -> AttestationObject {
        let mut stmt = vec![
            (
                Value::Text("alg".into()),
                Value::Integer((-8_i128).try_into().unwrap()),
            ),
            (Value::Text("sig".into()), Value::Bytes(sig)),
        ];
        if let Some(chain) = x5c {
            stmt.push((
                Value::Text("x5c".into()),
                Value::Array(chain.into_iter().map(Value::Bytes).collect()),
            ));
        }
        AttestationObject {
            fmt: "packed".into(),
            att_stmt: stmt,
            auth_data: AUTH_DATA.to_vec(),
        }
    }

    fn signed_message() -> Vec<u8> {
        let mut m = AUTH_DATA.to_vec();
        m.extend_from_slice(CDH);
        m
    }

    #[test]
    fn packed_basic_attestation_with_a_valid_chain_is_model_verified() {
        let sig = test_util::ed25519_sign(&LEAF_SEED, &signed_message());
        let obj = packed_object(Some(vec![leaf(Some(AAGUID))]), sig);
        let cred_key = WebauthnKey::Ed25519 {
            public_key: test_util::ed25519_public_key_from_seed(&CRED_SEED),
        };
        let outcome =
            verify_attestation(&obj, CDH, &cred_key, &AAGUID, &[model_root()], NOW).unwrap();
        assert_eq!(outcome.attestation_type, AttestationType::Basic);
        assert_eq!(outcome.fmt, "packed");
        assert!(outcome.model_verified);
    }

    #[test]
    fn packed_with_a_mismatched_cert_aaguid_is_a_spoof_reject() {
        // The leaf carries a DIFFERENT AAGUID than the authenticator data: reject.
        let sig = test_util::ed25519_sign(&LEAF_SEED, &signed_message());
        let obj = packed_object(Some(vec![leaf(Some([0xAA; 16]))]), sig);
        let cred_key = WebauthnKey::Ed25519 {
            public_key: test_util::ed25519_public_key_from_seed(&CRED_SEED),
        };
        assert_eq!(
            verify_attestation(&obj, CDH, &cred_key, &AAGUID, &[model_root()], NOW),
            Err(CeremonyError::AttestationAaguidMismatch)
        );
    }

    #[test]
    fn packed_basic_with_a_chain_to_a_wrong_root_is_rejected() {
        let sig = test_util::ed25519_sign(&LEAF_SEED, &signed_message());
        let obj = packed_object(Some(vec![leaf(Some(AAGUID))]), sig);
        let cred_key = WebauthnKey::Ed25519 {
            public_key: test_util::ed25519_public_key_from_seed(&CRED_SEED),
        };
        let wrong_root = build_cert(&CertSpec {
            subject_cn: "Wrong Root",
            issuer_cn: "Wrong Root",
            subject_seed: [9; 32],
            issuer_seed: [9; 32],
            not_before: 0,
            not_after: FAR,
            aaguid: None,
            is_ca: true,
            path_len: None,
            key_usage: None,
        });
        assert_eq!(
            verify_attestation(&obj, CDH, &cred_key, &AAGUID, &[wrong_root], NOW),
            Err(CeremonyError::AttestationChainInvalid)
        );
    }

    #[test]
    fn packed_self_attestation_is_not_model_verified() {
        // No x5c: signed by the credential key. Proves possession, not the model.
        let cred_key = WebauthnKey::Ed25519 {
            public_key: test_util::ed25519_public_key_from_seed(&CRED_SEED),
        };
        let sig = test_util::ed25519_sign(&CRED_SEED, &signed_message());
        let obj = packed_object(None, sig);
        let outcome = verify_attestation(&obj, CDH, &cred_key, &AAGUID, &[], NOW).unwrap();
        assert_eq!(outcome.attestation_type, AttestationType::SelfAttestation);
        assert!(!outcome.model_verified);
    }

    #[test]
    fn packed_with_a_bad_signature_is_rejected() {
        let mut sig = test_util::ed25519_sign(&CRED_SEED, &signed_message());
        sig[0] ^= 0x01;
        let cred_key = WebauthnKey::Ed25519 {
            public_key: test_util::ed25519_public_key_from_seed(&CRED_SEED),
        };
        let obj = packed_object(None, sig);
        assert_eq!(
            verify_attestation(&obj, CDH, &cred_key, &AAGUID, &[], NOW),
            Err(CeremonyError::AttestationSignatureInvalid)
        );
    }
}
