// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-tenant envelope encryption for PII and secrets at rest (issue #48).
//!
//! This module is the crypto primitive half of IronAuth's data-at-rest
//! protection. It lives in `ironauth-jose` for one structural reason: the
//! workspace lets exactly ONE crate name `ring` directly (enforced by
//! `scripts/jose-audit.sh`), and the envelope scheme is built on a standard
//! `ring` AEAD (`ring::aead`, AES-256-GCM per NIST SP 800-38D). No novel cipher
//! and no novel mode is invented here; the whole scheme is key management around
//! a single, well-reviewed AEAD.
//!
//! # The DEK / KEK envelope
//!
//! Three key tiers, each a 256-bit AEAD key:
//!
//! - a **master key** (a [`MasterKey`]) held by the platform, supplied from the
//!   configuration or environment seam. It never encrypts record payloads; it
//!   only wraps per-tenant KEKs.
//! - a per-tenant **key-encryption key** (a [`Kek`]). Stored only in wrapped
//!   form (sealed under the master key). It never encrypts record payloads; it
//!   only wraps that tenant's DEKs. Destroying every wrapped copy of a tenant's
//!   KEK renders all of that tenant's data permanently unreadable: the
//!   crypto-shredding property (issue #48 acceptance, productized as offboarding
//!   in #49).
//! - a per-tenant **data-encryption key** (a [`Dek`], versioned). Stored only in
//!   wrapped form (sealed under the KEK). It seals and opens the actual PII and
//!   secret payloads.
//!
//! Wrapping is itself an AEAD seal: a KEK's plaintext is the DEK's 32 raw bytes;
//! the wrapped DEK is those bytes sealed under the KEK. So there is one AEAD in
//! play at every tier, never a bespoke key-wrap construction.
//!
//! # Context binding (associated data)
//!
//! Every seal and every wrap binds an **associated-data context**: the caller
//! passes the tenant id, environment id, purpose/column, and key version as AAD.
//! AES-GCM authenticates that AAD without encrypting it, so a ciphertext lifted
//! out of one row (or one tenant, or one column) fails authentication when
//! presented against a different context. A stored ciphertext therefore cannot
//! be replayed into another row, tenant, environment, or field. Build the AAD
//! with [`Aad::builder`] so the field framing is canonical and unambiguous.
//!
//! # Nonces and key material come from the entropy seam
//!
//! Every key and every AEAD nonce is drawn from [`ironauth_env::Entropy`]
//! (invariant 3), never an OS RNG directly, so the whole scheme is deterministic
//! under a test entropy source. A fresh random 96-bit nonce is drawn per seal
//! and per wrap and is never reused under one key (NIST SP 800-38D permits random
//! 96-bit nonces; the birthday bound is far beyond any per-key message count
//! IronAuth reaches before a DEK rotation). The nonce is stored alongside the
//! ciphertext it belongs to, in the [`Sealed`] blob.
//!
//! # Key material never leaks
//!
//! [`MasterKey`], [`Kek`], and [`Dek`] never implement `Display`, render their
//! bytes in `Debug`, or serialize; their `Debug` is `<redacted>`, and their
//! backing bytes are best-effort zeroed on drop. Raw key bytes leave the process
//! only as ciphertext (a wrapped key or a sealed payload).

use ironauth_env::Entropy;
use ring::aead::{AES_256_GCM, Aad as RingAad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hmac;

/// The AEAD key length in bytes (AES-256-GCM: a 256-bit key).
pub const KEY_LEN: usize = 32;

/// The AEAD nonce length in bytes (AES-256-GCM: a 96-bit nonce).
pub const NONCE_BYTES: usize = NONCE_LEN;

/// The domain-separation label mixed in when deriving a master key from
/// externally supplied key material (a configured secret), so the derivation is
/// bound to this purpose and cannot collide with any other keyed use.
const MASTER_DERIVE_LABEL: &[u8] = b"ironauth.envelope.master-key.derive.v1";

/// The domain-separation label mixed in when deriving the blind-index subkey from
/// the master key, so the HMAC key used for searchable indexes is cryptographically
/// separated from the AEAD wrapping use of the same master key (key separation).
const BLIND_INDEX_SUBKEY_LABEL: &[u8] = b"ironauth.envelope.blind-index.subkey.v1";

/// Best-effort wipe of a heap buffer that transiently held key material or a
/// decrypted plaintext, so it does not linger in freed heap. Mirrors the
/// `AeadKey` drop wipe: a byte fill the optimizer is discouraged from eliding by
/// a `black_box` read. No `unsafe`, no extra crate.
fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    std::hint::black_box(&*buf);
}

/// A failure in an envelope operation.
///
/// The variants carry NO plaintext, key material, tenant data, or ciphertext:
/// an envelope error must be safe to log. A decryption failure
/// ([`EnvelopeError::Decrypt`]) is deliberately its own variant, distinct from a
/// missing record, so a caller can tell "this ciphertext did not authenticate"
/// (a wrong key, a tampered blob, or a replayed context) apart from "there is no
/// such row" (issue #48: decryption failures are structured errors
/// distinguishable from missing data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// A sealed blob was malformed (too short to carry a nonce and a tag, or an
    /// unknown format version). Fail closed rather than guess a layout.
    Format,
    /// Authenticated decryption failed: a wrong key, a tampered ciphertext or
    /// tag, or a context (AAD) that does not match the one the blob was sealed
    /// under. Never distinguishes which, so it is not an oracle.
    Decrypt,
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EnvelopeError::Format => f.write_str("malformed sealed blob"),
            EnvelopeError::Decrypt => f.write_str("authenticated decryption failed"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// A canonical associated-data context bound to a ciphertext.
///
/// AES-GCM authenticates this data without encrypting it. Two contexts are equal
/// only if every field was appended in the same order with the same bytes, so a
/// ciphertext sealed under one context fails to open under any other. Build it
/// with [`Aad::builder`]; each field is length-prefixed, so `("ab", "c")` and
/// `("a", "bc")` never collide.
#[derive(Clone, PartialEq, Eq)]
pub struct Aad {
    bytes: Vec<u8>,
}

impl Aad {
    /// Start building a context. Append the binding fields in a fixed order, then
    /// call [`AadBuilder::build`].
    #[must_use]
    pub fn builder() -> AadBuilder {
        AadBuilder { bytes: Vec::new() }
    }

    /// The raw context bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for Aad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The context is not secret (it is tenant/env/column identity), but keep
        // Debug terse and byte-free.
        f.debug_struct("Aad").finish_non_exhaustive()
    }
}

/// A builder for an [`Aad`] context that length-prefixes every field so the
/// concatenation is unambiguous.
#[derive(Debug)]
pub struct AadBuilder {
    bytes: Vec<u8>,
}

impl AadBuilder {
    /// Append one binding field. The field's length is encoded before its bytes,
    /// so no two distinct field sequences can produce the same context.
    #[must_use]
    pub fn field(mut self, value: &[u8]) -> Self {
        // A 64-bit big-endian length prefix frames each field unambiguously.
        let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(value);
        self
    }

    /// Append one binding field given as text (a tenant id, a column purpose).
    #[must_use]
    pub fn text(self, value: &str) -> Self {
        self.field(value.as_bytes())
    }

    /// Append one binding field given as a key version.
    #[must_use]
    pub fn version(self, value: i64) -> Self {
        self.field(&value.to_be_bytes())
    }

    /// Finish the context.
    #[must_use]
    pub fn build(self) -> Aad {
        Aad { bytes: self.bytes }
    }
}

/// A sealed blob: a fresh nonce followed by the AEAD ciphertext-with-tag.
///
/// This is exactly what is persisted (a `bytea`). It carries no plaintext and,
/// on its own, nothing about which key or context opens it; that binding is the
/// caller's stored key version plus the AAD it reconstructs at open time.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    bytes: Vec<u8>,
}

impl Sealed {
    /// The wire bytes to persist.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Take ownership of the wire bytes to persist.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Reconstruct a sealed blob read back from storage.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Format`] if the blob is too short to hold a nonce and an
    /// authentication tag.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, EnvelopeError> {
        if bytes.len() < NONCE_BYTES + AES_256_GCM.tag_len() {
            return Err(EnvelopeError::Format);
        }
        Ok(Self { bytes })
    }
}

impl core::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sealed")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A 256-bit AEAD key. The one place raw key bytes live in memory.
///
/// Never printed, displayed, or serialized; `Debug` is `<redacted>` and the
/// bytes are best-effort zeroed on drop.
struct AeadKey {
    bytes: [u8; KEY_LEN],
}

impl AeadKey {
    /// A fresh random key drawn from the entropy seam.
    fn generate(entropy: &dyn Entropy) -> Self {
        let mut bytes = [0_u8; KEY_LEN];
        entropy.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Reconstruct a key from raw bytes (unwrapping a wrapped key, or loading the
    /// master key from configuration).
    fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Seal `plaintext` under this key with `aad` bound, drawing a fresh nonce
    /// from the entropy seam. The result is `nonce || ciphertext || tag`.
    fn seal(&self, entropy: &dyn Entropy, aad: &Aad, plaintext: &[u8]) -> Sealed {
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        entropy.fill_bytes(&mut nonce_bytes);

        // A fresh LessSafeKey per call: the "less safe" name is the nonce-reuse
        // caveat, which we discharge by drawing a fresh random nonce every time
        // (see the module docs). The key material never escapes this scope.
        let unbound =
            UnboundKey::new(&AES_256_GCM, &self.bytes).expect("AES-256-GCM accepts a 32-byte key");
        let key = LessSafeKey::new(unbound);

        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            RingAad::from(aad.as_bytes()),
            &mut in_out,
        )
        .expect("AES-256-GCM sealing does not fail for in-memory input");

        let mut bytes = Vec::with_capacity(NONCE_BYTES + in_out.len());
        bytes.extend_from_slice(&nonce_bytes);
        bytes.append(&mut in_out);
        Sealed { bytes }
    }

    /// Open a sealed blob under this key with `aad` bound.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Format`] if the blob is malformed; [`EnvelopeError::Decrypt`]
    /// if authentication fails (wrong key, tampered blob, or mismatched context).
    fn open(&self, aad: &Aad, sealed: &Sealed) -> Result<Vec<u8>, EnvelopeError> {
        let bytes = &sealed.bytes;
        if bytes.len() < NONCE_BYTES + AES_256_GCM.tag_len() {
            return Err(EnvelopeError::Format);
        }
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        nonce_bytes.copy_from_slice(&bytes[..NONCE_BYTES]);
        let mut in_out = bytes[NONCE_BYTES..].to_vec();

        let unbound =
            UnboundKey::new(&AES_256_GCM, &self.bytes).expect("AES-256-GCM accepts a 32-byte key");
        let key = LessSafeKey::new(unbound);

        let result = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                RingAad::from(aad.as_bytes()),
                &mut in_out,
            )
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| EnvelopeError::Decrypt);
        // `in_out` still holds the recovered plaintext (open_in_place decrypts in
        // place, then we copied it out). Wipe the working buffer so the plaintext
        // (a wrapped key's raw bytes, or a decrypted PII payload) does not linger.
        wipe(&mut in_out);
        result
    }

    /// The raw bytes, for wrapping this key's material under a parent key. Kept
    /// private to the module so no consumer can extract a key in the clear.
    fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        // Best-effort zeroization without the `zeroize` crate and without
        // `unsafe`. `fill(0)` plus a `black_box` read discourages the optimizer
        // from eliding the wipe as a dead store.
        self.bytes.fill(0);
        std::hint::black_box(&self.bytes);
    }
}

impl core::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadKey(<redacted>)")
    }
}

/// The platform-held root key. Wraps per-tenant KEKs; never seals a payload.
///
/// Supplied from configuration or the environment seam (fail closed when
/// absent). It is the single secret whose loss or destruction affects every
/// tenant, so it is held only in memory, never persisted by this layer. It
/// carries a stable identifier (a key id / generation label, for example
/// `master-1`) that is bound into every wrapped KEK's associated data and stored
/// alongside it, so a KEK wrapped under one master-key generation cannot be
/// unwrapped under another.
#[derive(Debug)]
pub struct MasterKey {
    id: String,
    key: AeadKey,
}

impl MasterKey {
    /// Load the master key from its stable id and 32 raw bytes (from
    /// configuration).
    #[must_use]
    pub fn from_bytes(id: impl Into<String>, bytes: [u8; KEY_LEN]) -> Self {
        Self {
            id: id.into(),
            key: AeadKey::from_bytes(bytes),
        }
    }

    /// A fresh random master key from the entropy seam (test and bootstrap use).
    #[must_use]
    pub fn generate(id: impl Into<String>, entropy: &dyn Entropy) -> Self {
        Self {
            id: id.into(),
            key: AeadKey::generate(entropy),
        }
    }

    /// The master key's stable identifier (bound into every wrapped KEK's AAD).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Wrap `kek` under this master key, binding `aad`. The result is stored as
    /// the tenant's wrapped KEK.
    #[must_use]
    pub fn wrap_kek(&self, entropy: &dyn Entropy, aad: &Aad, kek: &Kek) -> Sealed {
        self.key.seal(entropy, aad, kek.key.expose())
    }

    /// Unwrap a tenant KEK under this master key, binding `aad`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Format`] if the wrapped blob is malformed;
    /// [`EnvelopeError::Decrypt`] if it does not authenticate (a wrong master
    /// key, a tampered blob, or a mismatched context, for example a KEK
    /// crypto-shredded to an empty blob).
    pub fn unwrap_kek(&self, aad: &Aad, wrapped: &Sealed) -> Result<Kek, EnvelopeError> {
        let mut bytes = self.key.open(aad, wrapped)?;
        let raw = to_key_bytes(&bytes);
        // Wipe the transient unwrapped key bytes now that they are copied into the
        // fixed array (or rejected): the raw KEK material must not linger in freed
        // heap. `raw`, on the success path, is owned by an `AeadKey` that wipes on
        // drop.
        wipe(&mut bytes);
        Ok(Kek {
            key: AeadKey::from_bytes(raw?),
        })
    }

    /// Derive a master key deterministically from externally supplied key material
    /// (a configured platform secret of any length) and a stable id. The 32-byte
    /// AEAD key is `HMAC-SHA256(ikm, label)`, domain-separated by a fixed label, so
    /// the same secret always yields the same master key (stable across restarts,
    /// which every wrapped KEK depends on) without requiring the operator to supply
    /// exactly 32 raw bytes. Supply a high-entropy secret.
    #[must_use]
    pub fn derive(id: impl Into<String>, ikm: &[u8]) -> Self {
        let mac_key = hmac::Key::new(hmac::HMAC_SHA256, ikm);
        let tag = hmac::sign(&mac_key, MASTER_DERIVE_LABEL);
        let mut raw = [0_u8; KEY_LEN];
        raw.copy_from_slice(tag.as_ref());
        Self {
            id: id.into(),
            key: AeadKey::from_bytes(raw),
        }
    }

    /// Compute the deterministic blind index of `context` under this master key: a
    /// keyed HMAC-SHA256 whose key is a subkey derived from the master key (a
    /// domain-separated `HMAC-SHA256(master, label)`), so the searchable index key
    /// is cryptographically separated from the AEAD wrapping use of the same master
    /// key.
    ///
    /// A blind index makes an encrypted PII column equality-searchable WITHOUT a
    /// plaintext lookup column: the same `context` (which the caller builds to bind
    /// the tenant, environment, column label, and the normalized value) always maps
    /// to the same tag, while a fresh-nonce AEAD ciphertext never does. Because the
    /// caller binds the tenant and environment into `context`, the same value in two
    /// tenants yields two different tags, so an index collision cannot leak across
    /// tenants and the tag is never a bare unsalted hash of the value.
    #[must_use]
    pub fn blind_index(&self, context: &Aad) -> BlindIndex {
        let subkey_mac = hmac::Key::new(hmac::HMAC_SHA256, self.key.expose());
        let subkey = hmac::sign(&subkey_mac, BLIND_INDEX_SUBKEY_LABEL);
        let index_mac = hmac::Key::new(hmac::HMAC_SHA256, subkey.as_ref());
        let tag = hmac::sign(&index_mac, context.as_bytes());
        BlindIndex {
            bytes: tag.as_ref().to_vec(),
        }
    }
}

/// A deterministic blind index: the keyed HMAC tag persisted as the searchable
/// column standing in for an encrypted (non-searchable) PII value. It carries no
/// recoverable plaintext (HMAC is one-way) and is safe to store and to query by
/// equality; it is NOT a secret key, so it renders its bytes for binding to a
/// query, but its `Debug` stays terse.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindIndex {
    bytes: Vec<u8>,
}

impl BlindIndex {
    /// The tag bytes to persist or to bind into an equality query.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Take ownership of the tag bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl core::fmt::Debug for BlindIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlindIndex")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A per-tenant key-encryption key. Wraps that tenant's DEKs; never seals a
/// payload. Stored only wrapped under the master key.
#[derive(Debug)]
pub struct Kek {
    key: AeadKey,
}

impl Kek {
    /// A fresh random KEK from the entropy seam.
    #[must_use]
    pub fn generate(entropy: &dyn Entropy) -> Self {
        Self {
            key: AeadKey::generate(entropy),
        }
    }

    /// Wrap `dek` under this KEK, binding `aad`. The result is stored as a
    /// wrapped DEK.
    #[must_use]
    pub fn wrap_dek(&self, entropy: &dyn Entropy, aad: &Aad, dek: &Dek) -> Sealed {
        self.key.seal(entropy, aad, dek.key.expose())
    }

    /// Unwrap a DEK under this KEK, binding `aad`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Format`] if malformed; [`EnvelopeError::Decrypt`] if it
    /// does not authenticate.
    pub fn unwrap_dek(&self, aad: &Aad, wrapped: &Sealed) -> Result<Dek, EnvelopeError> {
        let mut bytes = self.key.open(aad, wrapped)?;
        let raw = to_key_bytes(&bytes);
        // Wipe the transient unwrapped DEK bytes now that they are copied into the
        // fixed array (or rejected).
        wipe(&mut bytes);
        Ok(Dek {
            key: AeadKey::from_bytes(raw?),
        })
    }
}

/// A per-tenant data-encryption key. Seals and opens the actual PII and secret
/// payloads. Stored only wrapped under the tenant KEK.
#[derive(Debug)]
pub struct Dek {
    key: AeadKey,
}

impl Dek {
    /// A fresh random DEK from the entropy seam.
    #[must_use]
    pub fn generate(entropy: &dyn Entropy) -> Self {
        Self {
            key: AeadKey::generate(entropy),
        }
    }

    /// Seal a record `plaintext` under this DEK, binding `aad` (the record's
    /// tenant, environment, column, and DEK version), drawing a fresh nonce.
    #[must_use]
    pub fn seal(&self, entropy: &dyn Entropy, aad: &Aad, plaintext: &[u8]) -> Sealed {
        self.key.seal(entropy, aad, plaintext)
    }

    /// Open a record ciphertext under this DEK, binding `aad`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Format`] if malformed; [`EnvelopeError::Decrypt`] if it
    /// does not authenticate (a wrong tenant/DEK, a tampered blob, or a
    /// ciphertext replayed from another row/column/tenant).
    pub fn open(&self, aad: &Aad, sealed: &Sealed) -> Result<Vec<u8>, EnvelopeError> {
        self.key.open(aad, sealed)
    }
}

/// Coerce an unwrapped key payload to a fixed 32-byte key, failing closed if the
/// length is wrong (a corrupt or foreign wrapped blob).
fn to_key_bytes(bytes: &[u8]) -> Result<[u8; KEY_LEN], EnvelopeError> {
    let raw: [u8; KEY_LEN] = bytes.try_into().map_err(|_| EnvelopeError::Format)?;
    Ok(raw)
}

#[cfg(test)]
// The KEK/DEK vocabulary is deliberately close (kek_ctx/dek_ctx, wrapped_kek/
// wrapped_dek): the three-bytes-different names mirror the envelope tiers and are
// clearer paired than artificially spread apart.
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use ironauth_env::FixedEntropy;

    fn aad(tenant: &str, env: &str, purpose: &str, version: i64) -> Aad {
        Aad::builder()
            .text(tenant)
            .text(env)
            .text(purpose)
            .version(version)
            .build()
    }

    #[test]
    fn seal_open_round_trip() {
        let entropy = FixedEntropy::new(1);
        let dek = Dek::generate(&entropy);
        let context = aad("ten_a", "env_a", "email", 1);
        let sealed = dek.seal(&entropy, &context, b"ada@example.test");
        let opened = dek.open(&context, &sealed).expect("round trips");
        assert_eq!(opened, b"ada@example.test");
    }

    #[test]
    fn ciphertext_carries_no_plaintext() {
        let entropy = FixedEntropy::new(2);
        let dek = Dek::generate(&entropy);
        let context = aad("ten_a", "env_a", "email", 1);
        let secret = b"super-secret-value";
        let sealed = dek.seal(&entropy, &context, secret);
        assert!(
            !sealed.as_bytes().windows(secret.len()).any(|w| w == secret),
            "the sealed blob must not contain the plaintext"
        );
    }

    #[test]
    fn wrong_context_fails_to_open() {
        let entropy = FixedEntropy::new(3);
        let dek = Dek::generate(&entropy);
        let sealed = dek.seal(&entropy, &aad("ten_a", "env_a", "email", 1), b"pii");
        // A different column, tenant, environment, or version each fail.
        assert_eq!(
            dek.open(&aad("ten_a", "env_a", "phone", 1), &sealed),
            Err(EnvelopeError::Decrypt)
        );
        assert_eq!(
            dek.open(&aad("ten_b", "env_a", "email", 1), &sealed),
            Err(EnvelopeError::Decrypt)
        );
        assert_eq!(
            dek.open(&aad("ten_a", "env_b", "email", 1), &sealed),
            Err(EnvelopeError::Decrypt)
        );
        assert_eq!(
            dek.open(&aad("ten_a", "env_a", "email", 2), &sealed),
            Err(EnvelopeError::Decrypt)
        );
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let entropy = FixedEntropy::new(4);
        let dek_a = Dek::generate(&entropy);
        let dek_b = Dek::generate(&entropy);
        let context = aad("ten_a", "env_a", "email", 1);
        let sealed = dek_a.seal(&entropy, &context, b"pii");
        assert_eq!(dek_b.open(&context, &sealed), Err(EnvelopeError::Decrypt));
    }

    #[test]
    fn nonce_is_fresh_per_seal() {
        let entropy = FixedEntropy::new(5);
        let dek = Dek::generate(&entropy);
        let context = aad("ten_a", "env_a", "email", 1);
        let first = dek.seal(&entropy, &context, b"same");
        let second = dek.seal(&entropy, &context, b"same");
        assert_ne!(
            &first.as_bytes()[..NONCE_BYTES],
            &second.as_bytes()[..NONCE_BYTES],
            "each seal draws a fresh nonce"
        );
        assert_ne!(
            first.as_bytes(),
            second.as_bytes(),
            "identical plaintext seals to distinct ciphertext"
        );
    }

    #[test]
    fn kek_wrap_dek_round_trip() {
        let entropy = FixedEntropy::new(6);
        let kek = Kek::generate(&entropy);
        let dek = Dek::generate(&entropy);
        let wrap_ctx = aad("ten_a", "env_a", "dek-wrap", 1);
        let wrapped = kek.wrap_dek(&entropy, &wrap_ctx, &dek);
        let unwrapped = kek.unwrap_dek(&wrap_ctx, &wrapped).expect("unwrap");

        // The unwrapped DEK opens what the original DEK sealed.
        let payload_ctx = aad("ten_a", "env_a", "email", 1);
        let sealed = dek.seal(&entropy, &payload_ctx, b"pii");
        assert_eq!(unwrapped.open(&payload_ctx, &sealed).expect("open"), b"pii");
    }

    #[test]
    fn master_wrap_kek_round_trip_and_shred() {
        let entropy = FixedEntropy::new(7);
        let master = MasterKey::generate("master-1", &entropy);
        let kek = Kek::generate(&entropy);
        let dek = Dek::generate(&entropy);
        let kek_ctx = aad("ten_a", "env_a", "kek-wrap", 1);
        let dek_ctx = aad("ten_a", "env_a", "dek-wrap", 1);
        let payload_ctx = aad("ten_a", "env_a", "email", 1);

        let wrapped_kek = master.wrap_kek(&entropy, &kek_ctx, &kek);
        let wrapped_dek = kek.wrap_dek(&entropy, &dek_ctx, &dek);
        let sealed = dek.seal(&entropy, &payload_ctx, b"pii");

        // Legitimate read: master -> kek -> dek -> plaintext.
        let recovered_kek = master
            .unwrap_kek(&kek_ctx, &wrapped_kek)
            .expect("unwrap kek");
        let recovered_dek = recovered_kek
            .unwrap_dek(&dek_ctx, &wrapped_dek)
            .expect("unwrap dek");
        assert_eq!(
            recovered_dek.open(&payload_ctx, &sealed).expect("open"),
            b"pii"
        );

        // Crypto-shred: destroy the wrapped KEK (overwrite with an empty blob).
        // With no recoverable KEK, the DEK cannot be unwrapped, so the ciphertext
        // is permanently unreadable even though it is still on disk.
        let shredded = Sealed::from_bytes(vec![0_u8; NONCE_BYTES + AES_256_GCM.tag_len()])
            .expect("min-length blob");
        assert!(master.unwrap_kek(&kek_ctx, &shredded).is_err());
    }

    #[test]
    fn blind_index_is_deterministic_and_context_separated() {
        let entropy = FixedEntropy::new(20);
        let master = MasterKey::generate("master-1", &entropy);
        let ctx_a = aad("ten_a", "env_a", "user.identifier", 0);
        let ctx_b = aad("ten_b", "env_a", "user.identifier", 0);

        // Deterministic: the same context always maps to the same tag (so an
        // equality lookup works), and the tag is a full 32-byte HMAC output.
        let one = master.blind_index(&ctx_a);
        let two = master.blind_index(&ctx_a);
        assert_eq!(one.as_bytes(), two.as_bytes());
        assert_eq!(one.as_bytes().len(), 32);

        // Per-tenant: the SAME value under two tenants yields different tags, so an
        // index collision cannot leak across tenants.
        assert_ne!(master.blind_index(&ctx_b).as_bytes(), one.as_bytes());
    }

    #[test]
    fn blind_index_differs_across_master_keys() {
        // Two independent master keys produce different blind indexes for the same
        // context: the index is keyed, never a bare unsalted hash of the value.
        let a = MasterKey::generate("m", &FixedEntropy::new(21));
        let b = MasterKey::generate("m", &FixedEntropy::new(22));
        let ctx = aad("ten_a", "env_a", "user.identifier", 0);
        assert_ne!(
            a.blind_index(&ctx).as_bytes(),
            b.blind_index(&ctx).as_bytes()
        );
    }

    #[test]
    fn derive_is_stable_and_ikm_sensitive() {
        // The same secret always yields the same master key (stable across
        // restarts, which every wrapped KEK depends on); a different secret yields
        // a master key that cannot open the first's ciphertext.
        let entropy = FixedEntropy::new(23);
        let m1 = MasterKey::derive("master-1", b"a-high-entropy-platform-secret");
        let m2 = MasterKey::derive("master-1", b"a-high-entropy-platform-secret");
        let m3 = MasterKey::derive("master-1", b"a-different-platform-secret");
        let kek = Kek::generate(&entropy);
        let ctx = aad("ten_a", "env_a", "kek-wrap", 1);
        let wrapped = m1.wrap_kek(&entropy, &ctx, &kek);
        assert!(m2.unwrap_kek(&ctx, &wrapped).is_ok(), "same secret unwraps");
        assert!(m3.unwrap_kek(&ctx, &wrapped).is_err(), "other secret fails");
        // The derived blind index also matches only for the identical secret.
        assert_eq!(
            m1.blind_index(&ctx).as_bytes(),
            m2.blind_index(&ctx).as_bytes()
        );
        assert_ne!(
            m1.blind_index(&ctx).as_bytes(),
            m3.blind_index(&ctx).as_bytes()
        );
    }

    #[test]
    fn blind_index_debug_is_byte_free() {
        let master = MasterKey::generate("m", &FixedEntropy::new(24));
        let rendered = format!("{:?}", master.blind_index(&aad("t", "e", "p", 0)));
        assert!(rendered.contains("BlindIndex"));
        assert!(!rendered.contains('['), "no raw bytes in Debug: {rendered}");
    }

    #[test]
    fn debug_never_reveals_key_material() {
        let entropy = FixedEntropy::new(8);
        let master = MasterKey::generate("master-1", &entropy);
        let kek = Kek::generate(&entropy);
        let dek = Dek::generate(&entropy);
        for rendered in [
            format!("{master:?}"),
            format!("{kek:?}"),
            format!("{dek:?}"),
        ] {
            assert!(rendered.contains("redacted"), "got: {rendered}");
        }
    }

    #[test]
    fn short_blob_is_a_format_error() {
        assert_eq!(
            Sealed::from_bytes(vec![0_u8; 3]),
            Err(EnvelopeError::Format)
        );
    }

    #[test]
    fn fixed_entropy_is_the_only_randomness_source() {
        // A sanity check that the primitive works with the deterministic seam:
        // two independent engines seeded identically produce identical output.
        let a = FixedEntropy::new(9);
        let b = FixedEntropy::new(9);
        let dek_a = Dek::generate(&a);
        let dek_b = Dek::generate(&b);
        let ctx = aad("ten_a", "env_a", "email", 1);
        assert_eq!(
            dek_a.seal(&a, &ctx, b"pii").as_bytes(),
            dek_b.seal(&b, &ctx, b"pii").as_bytes()
        );
    }
}
