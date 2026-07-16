// SPDX-License-Identifier: MIT OR Apache-2.0

//! The authenticator-data flags byte (WebAuthn Level 3 section 6.1).
//!
//! The single flags byte encodes user presence, user verification, the two
//! backup flags that distinguish a device-bound authenticator from a synced
//! one, and whether attested credential data or extensions follow. Parsing it
//! is the one place the backup-eligible and backup-state signals enter the
//! system; they are impossible to reconstruct after the ceremony, so they are
//! read here and persisted per credential.

/// The parsed authenticator-data flags byte.
// This is a bit-flags struct that mirrors the six WebAuthn authenticator-data
// flag bits one-to-one; individual named bools are clearer at the call sites
// (which check `flags.user_verified` etc.) than a packed bitfield would be.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatorFlags {
    /// User Present (UP, bit 0): the user interacted with the authenticator.
    pub user_present: bool,
    /// User Verified (UV, bit 2): the user was verified (PIN, biometric).
    pub user_verified: bool,
    /// Backup Eligible (BE, bit 3): the credential is eligible to be backed up
    /// or synced. A device-bound key clears this; a passkey that can sync sets
    /// it. Fixed for the lifetime of the credential.
    pub backup_eligible: bool,
    /// Backup State (BS, bit 4): the credential is currently backed up or
    /// synced. Can change over the credential's life (a key that later syncs).
    pub backup_state: bool,
    /// Attested Credential Data present (AT, bit 6): the authenticator data is
    /// followed by attested credential data (set on registration).
    pub attested_credential_data: bool,
    /// Extension data present (ED, bit 7): the authenticator data is followed by
    /// a CBOR extensions map.
    pub extension_data: bool,
}

impl AuthenticatorFlags {
    /// Parse the flags byte into its individual bits.
    #[must_use]
    pub fn from_byte(byte: u8) -> Self {
        Self {
            user_present: byte & 0b0000_0001 != 0,
            user_verified: byte & 0b0000_0100 != 0,
            backup_eligible: byte & 0b0000_1000 != 0,
            backup_state: byte & 0b0001_0000 != 0,
            attested_credential_data: byte & 0b0100_0000 != 0,
            extension_data: byte & 0b1000_0000 != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_bit_independently() {
        assert!(AuthenticatorFlags::from_byte(0b0000_0001).user_present);
        assert!(AuthenticatorFlags::from_byte(0b0000_0100).user_verified);
        assert!(AuthenticatorFlags::from_byte(0b0000_1000).backup_eligible);
        assert!(AuthenticatorFlags::from_byte(0b0001_0000).backup_state);
        assert!(AuthenticatorFlags::from_byte(0b0100_0000).attested_credential_data);
        assert!(AuthenticatorFlags::from_byte(0b1000_0000).extension_data);
    }

    #[test]
    fn a_typical_synced_passkey_registration_byte() {
        // UP + UV + BE + BS + AT: a synced passkey enrolling with verification.
        let flags = AuthenticatorFlags::from_byte(0b0101_1101);
        assert!(flags.user_present);
        assert!(flags.user_verified);
        assert!(flags.backup_eligible);
        assert!(flags.backup_state);
        assert!(flags.attested_credential_data);
        assert!(!flags.extension_data);
    }

    #[test]
    fn a_device_bound_key_clears_the_backup_flags() {
        // UP + UV + AT, no BE/BS: a hardware-bound authenticator.
        let flags = AuthenticatorFlags::from_byte(0b0100_0101);
        assert!(flags.user_present);
        assert!(flags.user_verified);
        assert!(!flags.backup_eligible);
        assert!(!flags.backup_state);
        assert!(flags.attested_credential_data);
    }

    #[test]
    fn an_empty_byte_asserts_nothing() {
        let flags = AuthenticatorFlags::from_byte(0);
        assert!(!flags.user_present);
        assert!(!flags.user_verified);
        assert!(!flags.backup_eligible);
        assert!(!flags.backup_state);
        assert!(!flags.attested_credential_data);
        assert!(!flags.extension_data);
    }
}
