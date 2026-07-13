// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared helpers for the ironauth-jose test suites.
//!
//! The Ed25519 signer is deterministic: it is built from a fixed 32-byte seed
//! with `Ed25519KeyPair::from_seed_unchecked`, and Ed25519 signing needs no
//! randomness, so every token this helper produces is reproducible with no OS
//! entropy and no clock reads (times come from a `ManualClock`). That keeps the
//! adversarial and claim-edge vectors buildable at test time without tripping
//! the workspace invariant lints. The ECDSA and RSA positive vectors, which
//! would need a randomized signer, are instead committed constants in
//! [`vectors`], generated once offline.

#![allow(dead_code)]

pub mod signing_keys;
pub mod vectors;

use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ironauth_env::ManualClock;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// The expected issuer used by every vector.
pub const ISS: &str = "https://issuer.example.test";
/// The expected audience used by every vector.
pub const AUD: &str = "client-abc";
/// The fixed "current time" (seconds since the Unix epoch) the tests evaluate
/// at: 2023-11-14T22:13:20Z.
pub const NOW: u64 = 1_700_000_000;
/// The fixed `kid` of the deterministic Ed25519 signer.
pub const ED25519_KID: &str = "ed25519-1";

/// A fixed, non-secret Ed25519 seed. Deterministic test key only.
const ED25519_SEED: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

/// base64url-encode without padding, as JWS requires.
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// A `ManualClock` frozen at `secs` seconds since the Unix epoch.
#[must_use]
pub fn clock_at(secs: u64) -> ManualClock {
    ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

/// A `ManualClock` frozen at [`NOW`].
#[must_use]
pub fn now_clock() -> ManualClock {
    clock_at(NOW)
}

/// A deterministic Ed25519 signer for building test tokens.
pub struct Ed25519Signer {
    key: Ed25519KeyPair,
    public: Vec<u8>,
}

impl Ed25519Signer {
    /// Build the signer from the fixed seed.
    #[must_use]
    pub fn new() -> Self {
        let key = Ed25519KeyPair::from_seed_unchecked(&ED25519_SEED).expect("valid Ed25519 seed");
        let public = key.public_key().as_ref().to_vec();
        Self { key, public }
    }

    /// The raw 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Sign `msg`, returning the 64-byte signature.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg).as_ref().to_vec()
    }
}

impl Default for Ed25519Signer {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a compact JWS from a header and payload JSON string, signed with the
/// deterministic Ed25519 signer.
#[must_use]
pub fn signed_ed25519(signer: &Ed25519Signer, header_json: &str, payload_json: &str) -> String {
    let signing_input = format!(
        "{}.{}",
        b64(header_json.as_bytes()),
        b64(payload_json.as_bytes())
    );
    let signature = signer.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64(&signature))
}

/// Assemble a compact JWS from a header, payload, and an explicit (possibly
/// invalid) signature. For vectors rejected before the signature check, the
/// signature bytes are irrelevant.
#[must_use]
pub fn assemble(header_json: &str, payload_json: &str, signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64(header_json.as_bytes()),
        b64(payload_json.as_bytes()),
        b64(signature)
    )
}

/// The standard, valid-at-[`NOW`] claim set (nbf < now < exp).
#[must_use]
pub fn standard_claims() -> String {
    format!(
        r#"{{"iss":"{ISS}","sub":"user-123","aud":"{AUD}","exp":{},"nbf":{},"iat":{}}}"#,
        NOW + 3600,
        NOW - 60,
        NOW - 60
    )
}

/// A claim set with overridable `iss`, `aud` (raw JSON), `exp`, `nbf`, `iat`.
/// Pass the `aud` as a JSON fragment (a quoted string or an array).
#[must_use]
pub fn claims_with(iss: &str, aud_json: &str, exp: i64, nbf: i64, iat: i64) -> String {
    format!(
        r#"{{"iss":"{iss}","sub":"user-123","aud":{aud_json},"exp":{exp},"nbf":{nbf},"iat":{iat}}}"#
    )
}

/// HMAC-SHA256 over `msg` with `key`, for the RS/HS confusion vector (the
/// attacker signs with the victim's RSA public key bytes as the HMAC secret).
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&hmac_key, msg).as_ref().to_vec()
}
