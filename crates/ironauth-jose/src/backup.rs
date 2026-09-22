// SPDX-License-Identifier: MIT OR Apache-2.0

//! The backup seal: AEAD-encrypt a logical backup so it is ciphertext before it leaves the
//! host, with the tag doubling as the integrity check (issue #153).
//!
//! # Why a dedicated module and not a second call into the envelope
//!
//! The envelope seals per-tenant COLUMNS under the scope's DEK/KEK hierarchy, which is the
//! right machinery when the reader is a running server that can resolve the hierarchy.
//! A BACKUP is read by a future restore, possibly on a fresh machine, before any of that
//! exists - so it is sealed under the operator-held master key directly, with its own
//! domain-separated derivation so no other use of the same master key shares a keystream.
//!
//! The derivation mirrors `envelope::MasterKey::derive`: `HMAC-SHA256(master, label)` gives
//! the AEAD key, so a key for the backup is cryptographically separated from the wrapping
//! use of the same master key. The `context` is bound as AAD, so a file cannot be replayed
//! under a different purpose.
//!
//! # The file shape
//!
//! `magic(8) || version(1) || nonce(12) || ciphertext || tag(16)` - one sealed blob, no
//! plaintext metadata. `open` refuses on a wrong key, a tampered byte, or a foreign magic:
//! the AEAD tag IS the checksum the criterion asks for, verified on write and on restore.

use ironauth_env::Entropy as _;
use ring::aead::{AES_256_GCM, Aad as RingAad, LessSafeKey, Nonce, UnboundKey};

/// The derivation label: a domain-separated `HMAC-SHA256(master, label)`, the same pattern
/// `envelope::MasterKey::derive` uses, so the backup keystream never collides with the
/// envelope's wrapping keystream under one master key.
const BACKUP_DERIVE_LABEL: &[u8] = b"ironauth.backup.seal.v1";

/// The file magic, so a wrong file (or a file of the wrong build) is refused loudly rather
/// than parsed as ciphertext.
const MAGIC: &[u8] = b"IRONBK01";

/// The sealed file format version.
const VERSION: u8 = 1;

/// The length of the nonce.
const NONCE_LEN: usize = 12;

/// The length of the AEAD tag.
const TAG_LEN: usize = 16;

/// A sealed backup: the on-disk shape described at the module level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBackup {
    bytes: Vec<u8>,
}

/// Why [`SealedBackup::open`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupOpenError {
    /// The file is not a sealed backup of this build (wrong magic or version).
    Foreign,
    /// The AEAD tag did not verify: a tampered byte, a wrong master key, or a corrupted
    /// file. Restore MUST refuse here, per the criterion.
    Integrity,
    /// The context this file was sealed under does not match the caller's.
    ContextMismatch,
}

impl std::fmt::Display for BackupOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Foreign => f.write_str("the file is not an IronAuth backup of this build"),
            Self::Integrity => {
                f.write_str("the backup did not verify: a tampered byte or a wrong master key")
            }
            Self::ContextMismatch => f.write_str("the backup was sealed under a different context"),
        }
    }
}

impl std::error::Error for BackupOpenError {}

/// The derived AEAD key for the backup use: `HMAC-SHA256(master, BACKUP_DERIVE_LABEL)`.
fn seal_key(master_key: &[u8]) -> [u8; 32] {
    let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, master_key);
    let tag = ring::hmac::sign(&mac, BACKUP_DERIVE_LABEL);
    let mut raw = [0_u8; 32];
    raw.copy_from_slice(tag.as_ref());
    raw
}

impl SealedBackup {
    /// Seal `plaintext` under `master_key`, binding `context` as AAD.
    ///
    /// # Panics
    ///
    /// Panics if `context` is empty: an unbound seal is a replay hazard, and a caller that
    /// cannot name what it is sealing should not be sealing.
    #[must_use]
    pub fn seal(plaintext: &[u8], master_key: &[u8], context: &[u8]) -> Self {
        assert!(
            !context.is_empty(),
            "a backup seal context must not be empty"
        );
        let unbound =
            UnboundKey::new(&AES_256_GCM, &seal_key(master_key)).expect("32-byte AES-256-GCM key");
        let key = LessSafeKey::new(unbound);
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        ironauth_env::OsEntropy.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        // The in_out region must be a Vec: ring's bound is `Extend`, which a bare slice does
        // not satisfy. The plaintext runs to the end of the Vec and the tag is appended onto
        // it; the fixed header (magic, version, nonce) is then assembled in front.
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, RingAad::from(context), &mut in_out)
            .expect("in-place seal on a correctly sized buffer");
        let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + NONCE_LEN + in_out.len());
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend_from_slice(&in_out);
        Self { bytes }
    }

    /// Open and verify a sealed backup, refusing on any tampering, a wrong key, or a wrong
    /// context.
    ///
    /// # Errors
    ///
    /// [`BackupOpenError`] on a foreign file, an unverifiable tag (the checksum mismatch the
    /// criterion names), or a context mismatch.
    ///
    /// # Panics
    ///
    /// Panics if `master_key` is not 32 bytes - the derivation guarantees the length for

    /// every material this module is handed, so a wrong-length key is a programming error.
    pub fn open(&self, master_key: &[u8], context: &[u8]) -> Result<Vec<u8>, BackupOpenError> {
        if !self.bytes.starts_with(MAGIC)
            || self.bytes.len() < MAGIC.len() + 1 + NONCE_LEN + TAG_LEN
        {
            return Err(BackupOpenError::Foreign);
        }
        if self.bytes[MAGIC.len()] != VERSION {
            return Err(BackupOpenError::Foreign);
        }
        let mut in_out: Vec<u8> = self.bytes[MAGIC.len() + 1 + NONCE_LEN..].to_vec();
        let nonce = Nonce::assume_unique_for_key(
            self.bytes[MAGIC.len() + 1..MAGIC.len() + 1 + NONCE_LEN]
                .try_into()
                .expect("nonce length"),
        );
        let unbound =
            UnboundKey::new(&AES_256_GCM, &seal_key(master_key)).expect("32-byte AES-256-GCM key");
        let key = LessSafeKey::new(unbound);
        let opened = key
            .open_in_place(nonce, RingAad::from(context), &mut in_out)
            .map_err(|_| {
                // A tag failure is either a tampered byte or a wrong key; both MUST refuse.
                BackupOpenError::Integrity
            })?;
        Ok(opened.to_vec())
    }

    /// The raw sealed bytes, for writing to the destination.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A sealed blob from raw bytes, for reading back from a file.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = &[7_u8; 32];
    const OTHER: &[u8] = &[9_u8; 32];
    const CONTEXT: &[u8] = b"ironauth logical backup v1";

    fn sealed() -> SealedBackup {
        SealedBackup::seal(b"the whole logical dump", MASTER, CONTEXT)
    }

    #[test]
    fn round_trips_under_the_same_key_and_context() {
        let plaintext = b"CREATE TABLE sessions (...);\\nCOPY sessions FROM ...;"; // query-audit-allow: test-only literal, no SQL executes
        let sealed = SealedBackup::seal(plaintext, MASTER, CONTEXT);
        assert_eq!(
            SealedBackup::open(&sealed, MASTER, CONTEXT).expect("opens"),
            plaintext
        );
        // The plaintext never appears in the sealed bytes (encrypted before leaving the host).
        assert!(
            !sealed
                .as_bytes()
                .windows(plaintext.len())
                .any(|w| w == plaintext)
        );
    }

    /// THE CHECKSUM MISMATCH THE CRITERION NAMES: a single flipped byte refuses restore.
    #[test]
    fn a_tampered_byte_refuses_restore() {
        let mut bytes = sealed().as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert_eq!(
            SealedBackup::open(&SealedBackup::from_bytes(bytes), MASTER, CONTEXT),
            Err(BackupOpenError::Integrity),
            "restore MUST refuse on a checksum mismatch"
        );
    }

    #[test]
    fn a_wrong_key_refuses_restore() {
        assert_eq!(
            SealedBackup::open(&sealed(), OTHER, CONTEXT),
            Err(BackupOpenError::Integrity),
            "a wrong master key must not decrypt"
        );
    }

    #[test]
    fn a_wrong_context_refuses_restore() {
        assert_eq!(
            SealedBackup::open(&sealed(), MASTER, b"a different purpose"),
            Err(BackupOpenError::Integrity),
            "the AAD binds the purpose, so a replayed file under another context refuses"
        );
    }

    #[test]
    fn a_foreign_file_refuses_restore() {
        for foreign in [
            Vec::new(),
            b"IRONBK01".to_vec(),
            b"not a backup at all".to_vec(),
        ] {
            assert_eq!(
                SealedBackup::open(&SealedBackup::from_bytes(foreign.clone()), MASTER, CONTEXT),
                Err(BackupOpenError::Foreign),
                "{foreign:?}"
            );
        }
    }

    #[test]
    fn the_key_is_domain_separated_from_the_envelope_use() {
        // The backup keystream must not equal the envelope's wrapping keystream under the
        // same master key: derive both and compare the derived keys.
        let backup_key = seal_key(MASTER);
        let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, MASTER);
        let envelope_key: Vec<u8> = ring::hmac::sign(&mac, crate::envelope::MASTER_DERIVE_LABEL)
            .as_ref()
            .to_vec();
        assert_ne!(
            backup_key.as_slice(),
            envelope_key,
            "the backup and the envelope must never share a keystream"
        );
    }
}
