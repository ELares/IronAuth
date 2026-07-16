// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ceremony error surface.
//!
//! Like the JOSE core, verification carries no wire oracle: the caller maps
//! every [`CeremonyError`] to one non-enumerating, user-actionable message (see
//! the module docs on the crate root). The variants exist for server-side
//! diagnostics and metrics, never to be echoed verbatim to the client.

use std::fmt;

/// Why a WebAuthn ceremony response was rejected.
///
/// Bounded cardinality, for logs and metrics. The HTTP layer collapses all of
/// these to a single generic ceremony-failed response so an attacker cannot use
/// the error as an oracle (in particular, [`CeremonyError::CredentialNotFound`]
/// and a signature failure must be indistinguishable on the wire).
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CeremonyError {
    /// The response envelope or one of its base64url fields was malformed.
    MalformedResponse,
    /// The attestationObject CBOR could not be parsed or lacked authData.
    MalformedAttestationObject,
    /// The authenticator data was too short or structurally invalid.
    MalformedAuthenticatorData,
    /// The COSE credential public key could not be parsed or used an
    /// unsupported algorithm.
    UnsupportedOrMalformedKey,
    /// The clientDataJSON could not be parsed.
    MalformedClientData,
    /// The clientDataJSON `type` was not the expected ceremony type.
    WrongCeremonyType,
    /// The clientDataJSON challenge did not match the expected single-use
    /// challenge (a replayed, expired, or foreign challenge).
    ChallengeMismatch,
    /// The clientDataJSON origin was not an allowed origin for this environment.
    OriginMismatch,
    /// The RP ID hash in the authenticator data did not match the expected
    /// per-environment RP ID.
    RpIdMismatch,
    /// User presence (UP) was not asserted.
    UserPresenceMissing,
    /// User verification (UV) was required but not asserted.
    UserVerificationMissing,
    /// Registration authenticator data carried no attested credential data.
    AttestedCredentialDataMissing,
    /// The stored credential referenced by the assertion was not found.
    CredentialNotFound,
    /// The assertion signature did not verify against the stored public key.
    BadSignature,
}

impl CeremonyError {
    /// A stable, low-cardinality metric label for this reason.
    ///
    /// For server-side metrics only; never return it to a client.
    #[must_use]
    pub fn as_metric_label(self) -> &'static str {
        match self {
            CeremonyError::MalformedResponse => "malformed_response",
            CeremonyError::MalformedAttestationObject => "malformed_attestation_object",
            CeremonyError::MalformedAuthenticatorData => "malformed_authenticator_data",
            CeremonyError::UnsupportedOrMalformedKey => "unsupported_or_malformed_key",
            CeremonyError::MalformedClientData => "malformed_client_data",
            CeremonyError::WrongCeremonyType => "wrong_ceremony_type",
            CeremonyError::ChallengeMismatch => "challenge_mismatch",
            CeremonyError::OriginMismatch => "origin_mismatch",
            CeremonyError::RpIdMismatch => "rp_id_mismatch",
            CeremonyError::UserPresenceMissing => "user_presence_missing",
            CeremonyError::UserVerificationMissing => "user_verification_missing",
            CeremonyError::AttestedCredentialDataMissing => "attested_credential_data_missing",
            CeremonyError::CredentialNotFound => "credential_not_found",
            CeremonyError::BadSignature => "bad_signature",
        }
    }
}

impl fmt::Debug for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CeremonyError")
            .field(&self.as_metric_label())
            .finish()
    }
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // One fixed, non-enumerating string. The specific reason is available
        // through `as_metric_label` for diagnostics, never on the wire.
        f.write_str("the passkey ceremony could not be completed")
    }
}

impl std::error::Error for CeremonyError {}
