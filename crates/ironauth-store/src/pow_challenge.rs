// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof-of-work challenge store value types (issue #80).
//!
//! The hashcash logic (the challenge issuance, the leading-zero-bit verification, and
//! the `ChallengeProvider` trait) lives in the `ironauth-oidc` crate; this module carries
//! only the persistence-layer inputs and views the [`crate::repository`] `PowChallengeRepo`
//! reads and writes. A challenge is NOT a secret (it is handed to the client to solve), so
//! the challenge bytes are stored in the clear; the single-use latch and the context
//! binding are the security-bearing state.

/// A proof-of-work challenge to mint (issue #80): the random challenge bytes, the
/// difficulty (leading zero bits a solving nonce must produce), the SHA-256 of the
/// endpoint plus request context the challenge is BOUND to, and the expiry. The
/// challenge is minted by the server via `env.entropy()`; the expiry is derived from
/// `env.clock()`.
#[derive(Debug, Clone, Copy)]
pub struct NewPowChallenge<'a> {
    /// The random challenge bytes the server issued. Not a secret.
    pub challenge: &'a [u8],
    /// The number of leading zero bits `hash(challenge || nonce)` must have.
    pub difficulty_bits: i32,
    /// The SHA-256 of the endpoint plus the request context the challenge is bound to,
    /// so a solved challenge cannot be replayed to a different endpoint/context.
    pub context_hash: &'a [u8],
    /// The challenge expiry in microseconds since the epoch (via `env.clock()`).
    pub expires_at_micros: i64,
}

/// A resolved, live proof-of-work challenge (issue #80), returned by a lookup before it
/// is consumed. Carries exactly what the verifier needs to check a presented nonce: the
/// challenge bytes and the required difficulty. The context binding is checked by the
/// consume query (an exact match on `context_hash`), not returned here.
#[derive(Debug, Clone)]
pub struct PowChallengeView {
    /// The random challenge bytes the client must find a qualifying nonce for.
    pub challenge: Vec<u8>,
    /// The number of leading zero bits the solving nonce must produce.
    pub difficulty_bits: i32,
}
