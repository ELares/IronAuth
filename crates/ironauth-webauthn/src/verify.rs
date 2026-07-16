// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two ceremony verification entry points: registration and authentication.
//!
//! Both are total, side-effect free, and carry no wire oracle. They enforce the
//! security-critical checks the acceptance criteria call out: the single-use
//! challenge echo (compared against the challenge the caller retrieved from the
//! single-use store), origin, RP ID hash, and the authenticator flags. The
//! authentication path additionally verifies the assertion signature against the
//! stored credential public key (delegated to the ring-backed JOSE core) and
//! computes the sign-count clone-detection verdict.
//!
//! Neither function mutates anything: no partial credential is created here. The
//! store layer only persists AFTER a verification returns `Ok`, so a timed-out,
//! cancelled, or rejected ceremony leaves no rows.

use crate::attestation::extract_auth_data;
use crate::authdata::parse_authenticator_data;
use crate::client_data::{TYPE_CREATE, TYPE_GET, validate_client_data};
use crate::cose::parse_cose_key;
use crate::digest::sha256;
use crate::encoding::b64_decode;
use crate::error::CeremonyError;
use crate::options::{AuthenticationResponse, RegistrationResponse};
use crate::types::{AssertionOutcome, RegisteredCredential, sign_count_verdict};

/// The expected values a ceremony response is verified against.
///
/// `expected_challenge` is the raw challenge bytes the caller retrieved from the
/// single-use challenge store and marked consumed; a replayed or expired
/// challenge never reaches here because the store returns nothing to compare.
#[derive(Clone, Copy)]
pub struct VerificationParams<'a> {
    /// The per-environment RP ID (its SHA-256 must match the authenticator data).
    pub rp_id: &'a str,
    /// The origins allowed for this environment (the clientData origin must be
    /// one of them).
    pub allowed_origins: &'a [String],
    /// The single-use challenge the server issued for this ceremony.
    pub expected_challenge: &'a [u8],
    /// Whether user verification is required (UV must be asserted).
    pub require_user_verification: bool,
}

/// The stored credential an authentication assertion is verified against.
#[derive(Clone, Copy)]
pub struct StoredCredential<'a> {
    /// The raw `COSE_Key` bytes persisted at registration.
    pub cose_public_key: &'a [u8],
    /// The signature counter currently stored for this credential.
    pub sign_count: u32,
}

/// Verify a registration ceremony response and return the credential to persist.
///
/// Registration requests `attestation: "none"`, so there is no attestation
/// statement to trust (that is issue #66). Security comes from the checks here:
/// the single-use challenge, the origin, the RP ID hash, user presence, and
/// (when required) user verification. The credential public key is extracted
/// from the attested credential data and parsed to confirm it is one of the
/// supported algorithms.
///
/// # Errors
///
/// Returns a [`CeremonyError`] for any malformed field or failed check; the
/// caller maps every variant to one non-enumerating response.
pub fn verify_registration(
    response: &RegistrationResponse,
    params: &VerificationParams<'_>,
) -> Result<RegisteredCredential, CeremonyError> {
    let client_data_bytes =
        b64_decode(&response.response.client_data_json).ok_or(CeremonyError::MalformedResponse)?;
    validate_client_data(
        &client_data_bytes,
        TYPE_CREATE,
        params.expected_challenge,
        params.allowed_origins,
    )?;

    let attestation_bytes = b64_decode(&response.response.attestation_object)
        .ok_or(CeremonyError::MalformedResponse)?;
    let auth_data_bytes = extract_auth_data(&attestation_bytes)?;
    let auth_data = parse_authenticator_data(&auth_data_bytes)?;

    if auth_data.rp_id_hash != sha256(params.rp_id.as_bytes()) {
        return Err(CeremonyError::RpIdMismatch);
    }
    if !auth_data.flags.user_present {
        return Err(CeremonyError::UserPresenceMissing);
    }
    if params.require_user_verification && !auth_data.flags.user_verified {
        return Err(CeremonyError::UserVerificationMissing);
    }

    let attested = auth_data
        .attested_credential
        .ok_or(CeremonyError::AttestedCredentialDataMissing)?;
    // Confirm the COSE key parses into a supported algorithm now, so a bad key
    // is rejected at registration rather than at first authentication.
    parse_cose_key(&attested.cose_public_key)?;

    let discoverable = response
        .client_extension_results
        .cred_props
        .as_ref()
        .and_then(|c| c.rk);

    Ok(RegisteredCredential {
        credential_id: attested.credential_id,
        cose_public_key: attested.cose_public_key,
        aaguid: attested.aaguid,
        transports: response.response.transports.clone(),
        sign_count: auth_data.sign_count,
        backup_eligible: auth_data.flags.backup_eligible,
        backup_state: auth_data.flags.backup_state,
        user_verified: auth_data.flags.user_verified,
        discoverable,
    })
}

/// Verify an authentication assertion against a stored credential.
///
/// Verifies the single-use challenge, origin, RP ID hash, and flags, then the
/// assertion signature over `authenticatorData || SHA-256(clientDataJSON)` using
/// the stored public key (via the ring-backed JOSE core). The returned
/// [`AssertionOutcome`] carries the sign-count clone-detection verdict and the
/// current BE/BS flags for the store layer to persist.
///
/// # Errors
///
/// Returns a [`CeremonyError`] for any malformed field or failed check.
/// [`CeremonyError::BadSignature`] must be indistinguishable on the wire from a
/// missing credential, so the caller maps both to the same response.
pub fn verify_authentication(
    response: &AuthenticationResponse,
    stored: &StoredCredential<'_>,
    params: &VerificationParams<'_>,
) -> Result<AssertionOutcome, CeremonyError> {
    let client_data_bytes =
        b64_decode(&response.response.client_data_json).ok_or(CeremonyError::MalformedResponse)?;
    validate_client_data(
        &client_data_bytes,
        TYPE_GET,
        params.expected_challenge,
        params.allowed_origins,
    )?;

    let auth_data_bytes = b64_decode(&response.response.authenticator_data)
        .ok_or(CeremonyError::MalformedResponse)?;
    let auth_data = parse_authenticator_data(&auth_data_bytes)?;

    if auth_data.rp_id_hash != sha256(params.rp_id.as_bytes()) {
        return Err(CeremonyError::RpIdMismatch);
    }
    if !auth_data.flags.user_present {
        return Err(CeremonyError::UserPresenceMissing);
    }
    if params.require_user_verification && !auth_data.flags.user_verified {
        return Err(CeremonyError::UserVerificationMissing);
    }

    // The WebAuthn signed message is authenticatorData || SHA-256(clientDataJSON).
    let client_data_hash = sha256(&client_data_bytes);
    let mut signed_message = Vec::with_capacity(auth_data_bytes.len() + client_data_hash.len());
    signed_message.extend_from_slice(&auth_data_bytes);
    signed_message.extend_from_slice(&client_data_hash);

    let signature =
        b64_decode(&response.response.signature).ok_or(CeremonyError::MalformedResponse)?;
    let key = parse_cose_key(stored.cose_public_key)?;
    ironauth_jose::verify_webauthn_signature(&key, &signed_message, &signature)
        .map_err(|_| CeremonyError::BadSignature)?;

    Ok(AssertionOutcome {
        sign_count: auth_data.sign_count,
        sign_count_verdict: sign_count_verdict(stored.sign_count, auth_data.sign_count),
        backup_eligible: auth_data.flags.backup_eligible,
        backup_state: auth_data.flags.backup_state,
        user_verified: auth_data.flags.user_verified,
    })
}
