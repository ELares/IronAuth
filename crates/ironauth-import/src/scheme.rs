// SPDX-License-Identifier: MIT OR Apache-2.0

//! The algorithm-tagged foreign password-hash scheme layer (issue #55).
//!
//! This is the passwap-style reusable core: a stored foreign hash is PARSED into a
//! recognized [`Scheme`], VERIFIED against a candidate password by dispatching on
//! that scheme, and (at import) BOUNDS-CHECKED so an attacker-supplied cost
//! parameter cannot turn a later login verification into a denial-of-service vector
//! (the Kratos lesson: out-of-bounds imported costs are rejected at import, never
//! silently accepted). The module has NO database or store dependency, so it is
//! self-contained and the login path ([`ironauth_oidc`]) can consume it directly.
//!
//! # Storage contract
//!
//! A foreign hash is stored AS-IS: the canonical, self-describing string is the
//! verifier and the [`Scheme::tag`] is the non-secret algorithm label. There is no
//! function here that recovers a plaintext password; every scheme is a one-way
//! verifier.
//!
//! # Recognized schemes and their string forms
//!
//! | Scheme                     | Detected prefix                          |
//! |----------------------------|------------------------------------------|
//! | [`Scheme::Bcrypt`]         | `$2a$` / `$2b$` / `$2x$` / `$2y$`        |
//! | [`Scheme::Scrypt`]         | `$scrypt$` (PHC)                          |
//! | [`Scheme::Pbkdf2`]         | `$pbkdf2-sha256$` / `$pbkdf2-sha512$`     |
//! | [`Scheme::Argon2`]         | `$argon2i$` / `$argon2d$` / `$argon2id$` |
//! | [`Scheme::FirebaseScrypt`] | `$fbscrypt$` (canonical, see below)      |
//!
//! Firebase's modified scrypt is not self-describing in the wild (its
//! account-wide signer key, salt separator, and cost live outside the per-user
//! hash), so this crate defines a canonical, self-contained serialization that
//! round-trips through [`firebase_stored`]:
//!
//! ```text
//! $fbscrypt$n=<mem_cost>,r=<rounds>,p=1$<salt_sep_b64>$<signer_key_b64>$<salt_b64>$<hash_b64>
//! ```

use aes::Aes256;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ctr::Ctr128BE;
use password_hash::{PasswordHash, PasswordVerifier};
use subtle::ConstantTimeEq;

/// AES-256 in big-endian 128-bit-counter CTR mode: the cipher Firebase's modified
/// scrypt runs over the account signer key after scrypt key derivation.
type Aes256Ctr = Ctr128BE<Aes256>;

/// The documented maximum bcrypt cost accepted at import (a work factor of
/// `2^cost`). Above this a single verification is a denial-of-service vector, so
/// the record is rejected at import (the Kratos lesson).
pub const MAX_BCRYPT_COST: u32 = 15;
/// The minimum bcrypt cost bcrypt itself permits; below it the hash is malformed.
pub const MIN_BCRYPT_COST: u32 = 4;
/// The documented maximum scrypt `log2(N)` accepted at import (CPU/memory cost).
pub const MAX_SCRYPT_LOG_N: u32 = 20;
/// The documented maximum scrypt block-size parameter `r` accepted at import.
pub const MAX_SCRYPT_R: u32 = 32;
/// The documented maximum scrypt parallelism `p` accepted at import.
pub const MAX_SCRYPT_P: u32 = 16;
/// The documented maximum PBKDF2 iteration count accepted at import.
pub const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
/// The documented maximum Argon2 memory cost, in KiB, accepted at import.
pub const MAX_ARGON2_MEMORY_KIB: u32 = 4_194_304;
/// The documented maximum Argon2 pass count accepted at import.
pub const MAX_ARGON2_PASSES: u32 = 16;
/// The documented maximum Argon2 parallelism accepted at import.
pub const MAX_ARGON2_PARALLELISM: u32 = 16;
/// The documented maximum Firebase modified-scrypt memory cost (`log2(N)`)
/// accepted at import.
pub const MAX_FIREBASE_MEM_COST: u32 = 20;
/// The documented maximum Firebase modified-scrypt rounds (`r`) accepted at import.
pub const MAX_FIREBASE_ROUNDS: u32 = 16;

/// The scrypt-derived-key length Firebase's modified scrypt uses; the first 32
/// bytes key the AES-256-CTR pass.
const FIREBASE_DERIVED_KEY_LEN: usize = 64;
/// The all-zero 128-bit IV Firebase's modified scrypt runs AES-256-CTR under.
const FIREBASE_IV: [u8; 16] = [0_u8; 16];

/// A recognized foreign password-hash scheme (issue #55). The variant is the
/// algorithm tag stored alongside the hash; verification dispatches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// bcrypt (Blowfish-based), any of the `$2a$` / `$2b$` / `$2x$` / `$2y$`
    /// variants (they share one verify path).
    Bcrypt,
    /// scrypt (RFC 7914) in the PHC string form `$scrypt$ln=..,r=..,p=..$salt$hash`.
    Scrypt,
    /// PBKDF2 (RFC 8018 / PKCS#5 v2.1) over HMAC-SHA256 or HMAC-SHA512 in the PHC
    /// string form `$pbkdf2-sha256$i=..$salt$hash`.
    Pbkdf2,
    /// The Argon2 family (Argon2i, Argon2d, Argon2id) in the RFC 9106 PHC form.
    Argon2,
    /// Firebase's modified scrypt (scrypt key derivation followed by AES-256-CTR
    /// over the account signer key), in this crate's canonical `$fbscrypt$` form.
    FirebaseScrypt,
}

impl Scheme {
    /// The stable, non-secret algorithm tag stored alongside the hash and used for
    /// dispatch and metrics.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Scheme::Bcrypt => "bcrypt",
            Scheme::Scrypt => "scrypt",
            Scheme::Pbkdf2 => "pbkdf2",
            Scheme::Argon2 => "argon2",
            Scheme::FirebaseScrypt => "firebase-scrypt",
        }
    }

    /// Reconstruct a scheme from its [`Scheme::tag`], or [`None`] for an unknown
    /// tag.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "bcrypt" => Some(Scheme::Bcrypt),
            "scrypt" => Some(Scheme::Scrypt),
            "pbkdf2" => Some(Scheme::Pbkdf2),
            "argon2" => Some(Scheme::Argon2),
            "firebase-scrypt" => Some(Scheme::FirebaseScrypt),
            _ => None,
        }
    }
}

/// Why a foreign hash string could not be accepted at import (issue #55).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    /// The string matches no recognized scheme prefix.
    Unrecognized,
    /// The string matches a scheme prefix but is not a well-formed hash of that
    /// scheme (a parse failure), so it could never verify.
    Malformed,
    /// A cost parameter exceeds this crate's documented denial-of-service bound (or
    /// falls below the scheme minimum). The message names the offending parameter;
    /// it is operator-safe and never echoes attacker-controlled bytes.
    OutOfBounds(&'static str),
}

impl core::fmt::Display for HashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HashError::Unrecognized => f.write_str("unrecognized foreign hash scheme"),
            HashError::Malformed => f.write_str("malformed foreign hash for its scheme"),
            HashError::OutOfBounds(param) => {
                write!(f, "foreign hash cost parameter out of bounds: {param}")
            }
        }
    }
}

impl std::error::Error for HashError {}

/// A parsed, bounds-checked foreign password hash (issue #55): the recognized
/// [`Scheme`] and the canonical stored verifier string. Constructing one proves
/// the string is a well-formed hash of a recognized scheme whose cost parameters
/// are within the documented bounds, so a later [`ForeignHash::verify`] can never
/// be a denial-of-service vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignHash {
    scheme: Scheme,
    stored: String,
}

impl ForeignHash {
    /// Parse and bounds-check a stored foreign hash string.
    ///
    /// The scheme is detected from the leading marker, the string is validated as a
    /// well-formed hash of that scheme, and its cost parameters are checked against
    /// the documented maxima. The plaintext password is never involved.
    ///
    /// # Errors
    ///
    /// [`HashError::Unrecognized`] if no scheme prefix matches;
    /// [`HashError::Malformed`] if the string is not a valid hash of its scheme;
    /// [`HashError::OutOfBounds`] if a cost parameter is outside the documented
    /// bounds.
    pub fn parse(stored: &str) -> Result<Self, HashError> {
        let scheme = detect(stored).ok_or(HashError::Unrecognized)?;
        match scheme {
            Scheme::Bcrypt => bounds_bcrypt(stored)?,
            Scheme::Scrypt => bounds_scrypt(stored)?,
            Scheme::Pbkdf2 => bounds_pbkdf2(stored)?,
            Scheme::Argon2 => bounds_argon2(stored)?,
            Scheme::FirebaseScrypt => {
                parse_firebase(stored)?;
            }
        }
        Ok(Self {
            scheme,
            stored: stored.to_owned(),
        })
    }

    /// The recognized scheme.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The non-secret algorithm tag ([`Scheme::tag`]) for storage and metrics.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        self.scheme.tag()
    }

    /// The canonical stored verifier string, to persist AS-IS.
    #[must_use]
    pub fn stored(&self) -> &str {
        &self.stored
    }

    /// Verify `password` against this foreign hash, dispatching on its scheme.
    /// Returns `false` for a wrong password AND for any internal decode failure
    /// (fail closed); a corrupt stored value can never authenticate. This never
    /// panics.
    #[must_use]
    pub fn verify(&self, password: &[u8]) -> bool {
        match self.scheme {
            Scheme::Bcrypt => bcrypt::verify(password, &self.stored).unwrap_or(false),
            Scheme::Scrypt => phc_verify(&scrypt::Scrypt, password, &self.stored),
            Scheme::Pbkdf2 => phc_verify(&pbkdf2::Pbkdf2, password, &self.stored),
            Scheme::Argon2 => phc_verify(&argon2::Argon2::default(), password, &self.stored),
            Scheme::FirebaseScrypt => match parse_firebase(&self.stored) {
                Ok(fb) => fb.verify(password),
                Err(_) => false,
            },
        }
    }
}

/// Verify a PHC-string hash with `verifier`, returning `false` on a wrong password
/// or an unparsable string (fail closed).
fn phc_verify(verifier: &dyn PasswordVerifier, password: &[u8], stored: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(parsed) => verifier.verify_password(password, &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Detect the scheme from the leading marker of a stored hash string.
fn detect(stored: &str) -> Option<Scheme> {
    if stored.starts_with("$2a$")
        || stored.starts_with("$2b$")
        || stored.starts_with("$2x$")
        || stored.starts_with("$2y$")
    {
        Some(Scheme::Bcrypt)
    } else if stored.starts_with("$scrypt$") {
        Some(Scheme::Scrypt)
    } else if stored.starts_with("$pbkdf2-") {
        Some(Scheme::Pbkdf2)
    } else if stored.starts_with("$argon2") {
        Some(Scheme::Argon2)
    } else if stored.starts_with("$fbscrypt$") {
        Some(Scheme::FirebaseScrypt)
    } else {
        None
    }
}

/// Read a decimal PHC parameter (for example `m`, `t`, `ln`, `i`) from a parsed
/// hash, or [`None`] when it is absent or not a decimal.
fn phc_param(parsed: &PasswordHash, name: &str) -> Option<u32> {
    parsed
        .params
        .iter()
        .find(|(ident, _)| ident.as_str() == name)
        .and_then(|(_, value)| value.decimal().ok())
}

/// Bounds-check a bcrypt hash: the cost embedded at bytes 4..6 (`$2b$NN$...`) must
/// be within `[MIN_BCRYPT_COST, MAX_BCRYPT_COST]`.
fn bounds_bcrypt(stored: &str) -> Result<(), HashError> {
    let cost_str = stored.get(4..6).ok_or(HashError::Malformed)?;
    let cost: u32 = cost_str.parse().map_err(|_| HashError::Malformed)?;
    if cost < MIN_BCRYPT_COST {
        return Err(HashError::OutOfBounds("bcrypt cost below minimum"));
    }
    if cost > MAX_BCRYPT_COST {
        return Err(HashError::OutOfBounds("bcrypt cost"));
    }
    Ok(())
}

/// Bounds-check a scrypt PHC hash: `ln`, `r`, and `p` within the documented maxima.
fn bounds_scrypt(stored: &str) -> Result<(), HashError> {
    let parsed = PasswordHash::new(stored).map_err(|_| HashError::Malformed)?;
    let log_n = phc_param(&parsed, "ln").ok_or(HashError::Malformed)?;
    let r = phc_param(&parsed, "r").ok_or(HashError::Malformed)?;
    let p = phc_param(&parsed, "p").ok_or(HashError::Malformed)?;
    if log_n > MAX_SCRYPT_LOG_N {
        return Err(HashError::OutOfBounds("scrypt log2(N)"));
    }
    if r > MAX_SCRYPT_R {
        return Err(HashError::OutOfBounds("scrypt r"));
    }
    if p > MAX_SCRYPT_P {
        return Err(HashError::OutOfBounds("scrypt p"));
    }
    Ok(())
}

/// Bounds-check a PBKDF2 PHC hash: the iteration count `i` within the documented
/// maximum.
fn bounds_pbkdf2(stored: &str) -> Result<(), HashError> {
    let parsed = PasswordHash::new(stored).map_err(|_| HashError::Malformed)?;
    let iterations = phc_param(&parsed, "i").ok_or(HashError::Malformed)?;
    if iterations > MAX_PBKDF2_ITERATIONS {
        return Err(HashError::OutOfBounds("pbkdf2 iterations"));
    }
    Ok(())
}

/// Bounds-check an Argon2 PHC hash: memory `m`, passes `t`, and parallelism `p`
/// within the documented maxima.
fn bounds_argon2(stored: &str) -> Result<(), HashError> {
    let parsed = PasswordHash::new(stored).map_err(|_| HashError::Malformed)?;
    let m = phc_param(&parsed, "m").ok_or(HashError::Malformed)?;
    let t = phc_param(&parsed, "t").ok_or(HashError::Malformed)?;
    let p = phc_param(&parsed, "p").ok_or(HashError::Malformed)?;
    if m > MAX_ARGON2_MEMORY_KIB {
        return Err(HashError::OutOfBounds("argon2 memory"));
    }
    if t > MAX_ARGON2_PASSES {
        return Err(HashError::OutOfBounds("argon2 passes"));
    }
    if p > MAX_ARGON2_PARALLELISM {
        return Err(HashError::OutOfBounds("argon2 parallelism"));
    }
    Ok(())
}

/// The decoded operands of a canonical Firebase modified-scrypt hash.
struct Firebase {
    mem_cost: u8,
    rounds: u32,
    salt_separator: Vec<u8>,
    signer_key: Vec<u8>,
    salt: Vec<u8>,
    expected: Vec<u8>,
}

impl Firebase {
    /// Verify `password` against this Firebase hash: scrypt-derive a 64-byte key,
    /// AES-256-CTR the signer key under its first 32 bytes, and constant-time
    /// compare against the expected hash. Fail closed on any internal error.
    fn verify(&self, password: &[u8]) -> bool {
        let mut salt_input = self.salt.clone();
        salt_input.extend_from_slice(&self.salt_separator);
        let Ok(params) =
            scrypt::Params::new(self.mem_cost, self.rounds, 1, FIREBASE_DERIVED_KEY_LEN)
        else {
            return false;
        };
        let mut derived = [0_u8; FIREBASE_DERIVED_KEY_LEN];
        if scrypt::scrypt(password, &salt_input, &params, &mut derived).is_err() {
            return false;
        }
        let Ok(mut cipher) = Aes256Ctr::new_from_slices(&derived[..32], &FIREBASE_IV) else {
            return false;
        };
        let mut block = self.signer_key.clone();
        cipher.apply_keystream(&mut block);
        block.ct_eq(&self.expected).into()
    }
}

/// Serialize Firebase modified-scrypt operands into this crate's canonical
/// `$fbscrypt$` storage string. The four byte operands are supplied already
/// standard-base64-encoded exactly as a Firebase account export carries them.
#[must_use]
pub fn firebase_stored(
    mem_cost: u32,
    rounds: u32,
    salt_separator_b64: &str,
    signer_key_b64: &str,
    salt_b64: &str,
    hash_b64: &str,
) -> String {
    format!(
        "$fbscrypt$n={mem_cost},r={rounds},p=1${salt_separator_b64}${signer_key_b64}${salt_b64}${hash_b64}"
    )
}

/// Parse and bounds-check a canonical `$fbscrypt$` string.
fn parse_firebase(stored: &str) -> Result<Firebase, HashError> {
    // $fbscrypt$n=<mem>,r=<rounds>,p=1$<saltSep>$<signerKey>$<salt>$<hash>
    let body = stored
        .strip_prefix("$fbscrypt$")
        .ok_or(HashError::Malformed)?;
    let parts: Vec<&str> = body.split('$').collect();
    if parts.len() != 5 {
        return Err(HashError::Malformed);
    }
    let (mem_cost, rounds) = parse_firebase_params(parts[0])?;
    if mem_cost > MAX_FIREBASE_MEM_COST {
        return Err(HashError::OutOfBounds("firebase mem_cost"));
    }
    if rounds > MAX_FIREBASE_ROUNDS {
        return Err(HashError::OutOfBounds("firebase rounds"));
    }
    let salt_separator = B64.decode(parts[1]).map_err(|_| HashError::Malformed)?;
    let signer_key = B64.decode(parts[2]).map_err(|_| HashError::Malformed)?;
    let salt = B64.decode(parts[3]).map_err(|_| HashError::Malformed)?;
    let expected = B64.decode(parts[4]).map_err(|_| HashError::Malformed)?;
    let mem_cost = u8::try_from(mem_cost).map_err(|_| HashError::Malformed)?;
    Ok(Firebase {
        mem_cost,
        rounds,
        salt_separator,
        signer_key,
        salt,
        expected,
    })
}

/// Parse the `n=<mem>,r=<rounds>,p=1` parameter segment of a `$fbscrypt$` string.
fn parse_firebase_params(segment: &str) -> Result<(u32, u32), HashError> {
    let mut mem_cost = None;
    let mut rounds = None;
    for field in segment.split(',') {
        let (key, value) = field.split_once('=').ok_or(HashError::Malformed)?;
        match key {
            "n" => mem_cost = Some(value.parse().map_err(|_| HashError::Malformed)?),
            "r" => rounds = Some(value.parse().map_err(|_| HashError::Malformed)?),
            // p is pinned to 1 by the algorithm; accept and ignore its presence.
            "p" => {}
            _ => return Err(HashError::Malformed),
        }
    }
    Ok((
        mem_cost.ok_or(HashError::Malformed)?,
        rounds.ok_or(HashError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHasher, SaltString};

    /// A known-answer vector for a scheme: a password and a hash produced by an
    /// external implementation of that scheme.
    fn assert_kat(stored: &str, password: &str, scheme: Scheme) {
        let parsed = ForeignHash::parse(stored).expect("KAT parses");
        assert_eq!(parsed.scheme(), scheme, "scheme detected");
        assert!(
            parsed.verify(password.as_bytes()),
            "correct password verifies"
        );
        assert!(
            !parsed.verify(b"definitely-the-wrong-password"),
            "wrong password rejected"
        );
    }

    #[test]
    fn bcrypt_all_four_variants_verify() {
        // One bcrypt hash produced by the library at cost 6, replayed under each of
        // the four version prefixes (they share one verify path), proving the
        // parser and verifier accept $2a$/$2b$/$2x$/$2y$.
        let base = bcrypt::hash_with_result("hunter2", 6).expect("bcrypt hash");
        let body = &base.to_string()[4..]; // strip the "$2b$" the crate emits
        for prefix in ["$2a$", "$2b$", "$2x$", "$2y$"] {
            let stored = format!("{prefix}{body}");
            let parsed = ForeignHash::parse(&stored).unwrap_or_else(|e| panic!("{prefix}: {e}"));
            assert_eq!(parsed.scheme(), Scheme::Bcrypt);
            assert_eq!(parsed.tag(), "bcrypt");
            assert!(parsed.verify(b"hunter2"), "{prefix} verifies");
            assert!(!parsed.verify(b"wrong"), "{prefix} rejects wrong");
        }
    }

    #[test]
    fn scrypt_round_trip_kat() {
        use scrypt::password_hash::PasswordHasher;
        let salt = SaltString::encode_b64(b"scryptsalt00").expect("salt");
        let hash = scrypt::Scrypt
            .hash_password(b"correct horse", &salt)
            .expect("scrypt hash")
            .to_string();
        assert_kat(&hash, "correct horse", Scheme::Scrypt);
    }

    #[test]
    fn pbkdf2_round_trip_kat() {
        use pbkdf2::password_hash::PasswordHasher;
        let salt = SaltString::encode_b64(b"pbkdf2salt00").expect("salt");
        let hash = pbkdf2::Pbkdf2
            .hash_password(b"s3cret", &salt)
            .expect("pbkdf2 hash")
            .to_string();
        assert!(hash.starts_with("$pbkdf2-"), "{hash}");
        assert_kat(&hash, "s3cret", Scheme::Pbkdf2);
    }

    #[test]
    fn argon2_round_trip_kat() {
        let salt = SaltString::encode_b64(b"argon2salt000").expect("salt");
        let hash = argon2::Argon2::default()
            .hash_password(b"passw0rd", &salt)
            .expect("argon2 hash")
            .to_string();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert_kat(&hash, "passw0rd", Scheme::Argon2);
    }

    #[test]
    fn firebase_published_known_answer_vector() {
        // The canonical Firebase modified-scrypt test vector published by Firebase
        // (github.com/firebase/scrypt): a real cross-implementation KAT.
        let stored = firebase_stored(
            14,
            8,
            "Bw==",
            "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
            "42xEC+ixf3L2lw==",
            "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==",
        );
        let parsed = ForeignHash::parse(&stored).expect("firebase parses");
        assert_eq!(parsed.scheme(), Scheme::FirebaseScrypt);
        assert_eq!(parsed.tag(), "firebase-scrypt");
        assert!(
            parsed.verify(b"user1password"),
            "the published Firebase vector verifies"
        );
        assert!(!parsed.verify(b"user1passwordX"), "wrong password rejected");
    }

    #[test]
    fn unrecognized_and_malformed_are_rejected() {
        assert_eq!(
            ForeignHash::parse("not-a-hash").unwrap_err(),
            HashError::Unrecognized
        );
        assert_eq!(
            ForeignHash::parse("$scrypt$broken").unwrap_err(),
            HashError::Malformed
        );
        assert_eq!(ForeignHash::parse("").unwrap_err(), HashError::Unrecognized);
    }

    #[test]
    fn bcrypt_cost_out_of_bounds_is_rejected() {
        // A cost of 31 (the bcrypt maximum) is far above the documented DoS bound,
        // so it is rejected at parse with a per-parameter OutOfBounds error.
        let stored = format!("$2b$31${}", "a".repeat(53));
        assert_eq!(
            ForeignHash::parse(&stored).unwrap_err(),
            HashError::OutOfBounds("bcrypt cost")
        );
    }

    #[test]
    fn pbkdf2_iterations_out_of_bounds_is_rejected() {
        use pbkdf2::password_hash::PasswordHasher;
        // Hash at a cheap iteration count, then rewrite only the `i=` parameter to
        // one above the documented bound: the bounds check parses the parameter and
        // rejects it WITHOUT running the (expensive) KDF, so the test stays fast.
        let salt = SaltString::encode_b64(b"pbkdf2salt00").expect("salt");
        let params = pbkdf2::Params {
            rounds: 1000,
            output_length: 32,
        };
        let hash = pbkdf2::Pbkdf2
            .hash_password_customized(
                b"pw",
                Some(pbkdf2::Algorithm::Pbkdf2Sha256.ident()),
                None,
                params,
                &salt,
            )
            .expect("pbkdf2 hash")
            .to_string();
        let over = hash.replace("i=1000,", &format!("i={},", MAX_PBKDF2_ITERATIONS + 1));
        assert_ne!(over, hash, "the iteration parameter was rewritten");
        assert_eq!(
            ForeignHash::parse(&over).unwrap_err(),
            HashError::OutOfBounds("pbkdf2 iterations")
        );
    }

    #[test]
    fn firebase_mem_cost_out_of_bounds_is_rejected() {
        let stored = firebase_stored(MAX_FIREBASE_MEM_COST + 1, 8, "Bw==", "AAAA", "AAAA", "AAAA");
        assert_eq!(
            ForeignHash::parse(&stored).unwrap_err(),
            HashError::OutOfBounds("firebase mem_cost")
        );
    }

    #[test]
    fn scheme_tag_round_trips() {
        for scheme in [
            Scheme::Bcrypt,
            Scheme::Scrypt,
            Scheme::Pbkdf2,
            Scheme::Argon2,
            Scheme::FirebaseScrypt,
        ] {
            assert_eq!(Scheme::from_tag(scheme.tag()), Some(scheme));
        }
        assert_eq!(Scheme::from_tag("md5"), None);
    }
}
