// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared ceremony value types: the relying party, user-verification policy,
//! credential descriptors, the ceremony outputs, and the sign-count clone
//! detection verdict.

/// The relying party for a ceremony: its per-environment RP ID and a display
/// name.
///
/// The RP ID is the registrable-domain identifier the authenticator scopes the
/// credential to; it is per-environment configuration validated against the
/// serving origin at startup. The authenticator hashes it into the
/// authenticator data, which the verifier checks.
#[derive(Clone, Debug)]
pub struct RelyingParty {
    /// The RP ID (e.g. `auth.example.com`).
    pub id: String,
    /// A human-readable relying-party name shown by some authenticators.
    pub name: String,
}

/// The user a registration ceremony enrolls a credential for.
#[derive(Clone, Debug)]
pub struct CeremonyUser {
    /// The opaque user handle (never a plain email or a monotonic id): the
    /// bytes the authenticator returns as `userHandle` on a discoverable-credential
    /// assertion. Kept stable per (tenant, environment, subject).
    pub id: Vec<u8>,
    /// The user name (e.g. the login identifier) shown in the authenticator UI.
    pub name: String,
    /// The user display name shown in the authenticator UI.
    pub display_name: String,
}

/// A credential descriptor for `excludeCredentials` (dedupe on registration) or
/// `allowCredentials` (a non-discoverable authentication).
#[derive(Clone, Debug)]
pub struct CredentialDescriptor {
    /// The raw credential id bytes.
    pub id: Vec<u8>,
    /// The authenticator transports last observed for this credential.
    pub transports: Vec<String>,
}

/// The user-verification requirement a ceremony asks the authenticator to meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerification {
    /// User verification is required; the ceremony must produce a UV assertion.
    Required,
    /// User verification is preferred but not required.
    Preferred,
    /// User verification is discouraged.
    Discouraged,
}

impl UserVerification {
    /// The WebAuthn wire token for this requirement.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            UserVerification::Required => "required",
            UserVerification::Preferred => "preferred",
            UserVerification::Discouraged => "discouraged",
        }
    }

    /// Whether a UV assertion is mandatory under this requirement.
    #[must_use]
    pub fn requires_uv(self) -> bool {
        matches!(self, UserVerification::Required)
    }
}

/// The credential a registration ceremony verified and the metadata to persist.
#[derive(Clone, Debug)]
pub struct RegisteredCredential {
    /// The credential id the authenticator minted.
    pub credential_id: Vec<u8>,
    /// The raw `COSE_Key` bytes of the credential public key, stored verbatim.
    pub cose_public_key: Vec<u8>,
    /// The authenticator model identifier.
    pub aaguid: [u8; 16],
    /// The transports the client reported for this credential.
    pub transports: Vec<String>,
    /// The initial signature counter.
    pub sign_count: u32,
    /// Backup-eligible flag (BE) at registration: fixed for the credential life.
    pub backup_eligible: bool,
    /// Backup-state flag (BS) at registration.
    pub backup_state: bool,
    /// Whether user verification was performed at registration.
    pub user_verified: bool,
    /// The `credProps.rk` client-extension result: whether the created
    /// credential is discoverable (resident). `None` if the client did not
    /// report it.
    pub discoverable: Option<bool>,
}

/// The outcome of a verified authentication assertion and the metadata to update
/// on the stored credential.
#[derive(Clone, Debug)]
pub struct AssertionOutcome {
    /// The signature counter presented in this assertion.
    pub sign_count: u32,
    /// The clone-detection verdict comparing the presented counter to the stored
    /// one.
    pub sign_count_verdict: SignCountVerdict,
    /// The backup-eligible flag observed on this assertion.
    pub backup_eligible: bool,
    /// The backup-state flag observed on this assertion (may have changed since
    /// registration; persist it).
    pub backup_state: bool,
    /// Whether user verification was performed on this assertion.
    pub user_verified: bool,
}

/// The sign-count clone-detection verdict (WebAuthn Level 3 section 6.1.1).
///
/// The verifier computes this; the per-tenant policy layer decides whether a
/// [`SignCountVerdict::Regressed`] warns or blocks. A zero-counter authenticator
/// (common for synced passkeys, which do not implement a counter) is
/// [`SignCountVerdict::NotSupported`] and never a false positive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignCountVerdict {
    /// The presented counter is greater than the stored counter: a normal
    /// increment. Persist the new value.
    Ok,
    /// Both the presented and stored counters are zero: the authenticator does
    /// not implement a counter. No signal, nothing to persist.
    NotSupported,
    /// The presented counter did not advance past the stored counter: a possible
    /// cloned authenticator.
    Regressed {
        /// The counter value currently stored for the credential.
        stored: u32,
        /// The counter value presented in this assertion.
        presented: u32,
    },
}

/// Compute the sign-count verdict from the stored and presented counters.
///
/// A zero/zero pair means the authenticator does not implement a counter and is
/// never flagged (the synced-passkey case). Otherwise a strictly increasing
/// counter is normal; anything else is a regression signal.
#[must_use]
pub fn sign_count_verdict(stored: u32, presented: u32) -> SignCountVerdict {
    if stored == 0 && presented == 0 {
        SignCountVerdict::NotSupported
    } else if presented > stored {
        SignCountVerdict::Ok
    } else {
        SignCountVerdict::Regressed { stored, presented }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_counters_are_not_supported_not_a_clone() {
        assert_eq!(sign_count_verdict(0, 0), SignCountVerdict::NotSupported);
    }

    #[test]
    fn an_advancing_counter_is_ok() {
        assert_eq!(sign_count_verdict(5, 6), SignCountVerdict::Ok);
        assert_eq!(sign_count_verdict(0, 1), SignCountVerdict::Ok);
    }

    #[test]
    fn a_stalled_or_regressing_counter_is_flagged() {
        assert_eq!(
            sign_count_verdict(6, 6),
            SignCountVerdict::Regressed {
                stored: 6,
                presented: 6
            }
        );
        assert_eq!(
            sign_count_verdict(10, 3),
            SignCountVerdict::Regressed {
                stored: 10,
                presented: 3
            }
        );
        // A counter that was nonzero then reports zero is a regression, not
        // "not supported".
        assert_eq!(
            sign_count_verdict(4, 0),
            SignCountVerdict::Regressed {
                stored: 4,
                presented: 0
            }
        );
    }
}
