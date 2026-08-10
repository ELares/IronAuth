// SPDX-License-Identifier: MIT OR Apache-2.0

// The README is included as crate documentation so its Rust examples are COMPILED and RUN
// by `cargo test`. The first draft of that README invented an API (a `Verdict` enum and a
// `verify` returning `Result`) that this crate has never had. A README example nobody
// compiles is the unmeasured-sentence defect in its most public form: it is the first thing
// a crates.io reader tries.
#![doc = include_str!("../README.md")]

//! The algorithm-tagged foreign password-hash scheme layer (issue #55).
//!
//! This is the passwap-style reusable core: a stored foreign hash is PARSED into a
//! recognized [`Scheme`], VERIFIED against a candidate password by dispatching on
//! that scheme, and (at import) BOUNDS-CHECKED so an attacker-supplied cost
//! parameter cannot turn a later login verification into a denial-of-service vector
//! (the Kratos lesson: out-of-bounds imported costs are rejected at import, never
//! silently accepted). The module has NO database or store dependency, so it is
//! self-contained and the login path (`ironauth-oidc`) can consume it directly.
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
//! | [`Scheme::ShaCrypt`]       | `$5$` (SHA-256) / `$6$` (SHA-512)        |
//! | [`Scheme::Ldap`]           | `{SHA}` / `{SSHA}` / `{SHA256}` / ...     |
//!
//! # Two schemes with no cost to bound, and why that is the dangerous case
//!
//! Every bound in this crate exists because an attacker-supplied cost turns a later
//! login into a denial-of-service vector. The LDAP schemes invert that: `{SHA}` and
//! its relatives are a SINGLE unsalted or lightly salted digest pass, so they verify
//! in microseconds and there is no cost parameter to reject. The hazard is not that
//! verification is slow, it is that the stored hash is nearly free to attack offline.
//! So this crate recognizes them (a user who cannot be verified cannot be migrated at
//! all) and [`Scheme::rehash_is_urgent`] reports which schemes must not survive a
//! first successful login. `{MD5}` and `{SMD5}` are deliberately NOT recognized: MD5
//! is not in the issue's list and accepting it would be adding a scheme nothing asked
//! for on the strength of it being easy.
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
/// The documented maximum SHA-crypt `rounds=` accepted at import. glibc permits up to
/// 999999999, which is minutes of CPU for ONE verification and therefore exactly the
/// vector the bounds exist for. A million rounds is already far beyond any deployment
/// that expects to serve logins.
pub const MAX_SHA_CRYPT_ROUNDS: u32 = 1_000_000;
/// The minimum SHA-crypt `rounds=` glibc itself accepts; below it the string is
/// malformed rather than merely cheap.
pub const MIN_SHA_CRYPT_ROUNDS: u32 = 1_000;

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
    /// SHA-crypt, the glibc modular-crypt scheme: `$5$` (SHA-256) and `$6$`
    /// (SHA-512), with the optional `rounds=` parameter. One variant rather than two
    /// because the two share a format, a bound and a verify path; the digest width is
    /// carried in the string, which is where dispatch already reads it from.
    ShaCrypt,
    /// The LDAP/RFC 2307 digest schemes: `{SHA}`, `{SSHA}`, `{SHA256}`, `{SSHA256}`,
    /// `{SHA512}`, `{SSHA512}`. Salted (`{S...}`) forms append the salt to the digest
    /// inside the base64 payload. They carry NO cost parameter; see the module note.
    Ldap,
}

impl Scheme {
    /// Every variant, in declaration order.
    ///
    /// A slice rather than something each test writes out for itself. Two tests in
    /// this file sweep every scheme, and a hand-written list beside an enum is the
    /// shape where a variant added later is simply absent from the sweep and nothing
    /// says so. Adding a variant without extending this array is a compile error,
    /// because the length is declared.
    pub const ALL: [Scheme; 7] = [
        Scheme::Bcrypt,
        Scheme::Scrypt,
        Scheme::Pbkdf2,
        Scheme::Argon2,
        Scheme::FirebaseScrypt,
        Scheme::ShaCrypt,
        Scheme::Ldap,
    ];

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
            Scheme::ShaCrypt => "sha-crypt",
            Scheme::Ldap => "ldap-digest",
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
            "sha-crypt" => Some(Scheme::ShaCrypt),
            "ldap-digest" => Some(Scheme::Ldap),
            _ => None,
        }
    }

    /// Whether a first successful login against this scheme must REPLACE the stored
    /// hash rather than merely be allowed to succeed.
    ///
    /// Every scheme here is a foreign hash and every one of them is meant to be
    /// rehashed to Argon2id eventually. This names the ones where leaving the old
    /// hash in place is a standing exposure rather than a deferred cleanup: the LDAP
    /// digests are one unsalted or lightly salted pass, so a stolen row is attacked
    /// at the speed of a raw digest and no import bound can change that. A caller
    /// that rehashes everything is correct and can ignore this; one that rehashes
    /// lazily must not ignore it for these.
    #[must_use]
    pub fn rehash_is_urgent(self) -> bool {
        matches!(self, Scheme::Ldap)
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
            Scheme::ShaCrypt => bounds_sha_crypt(stored)?,
            // No cost parameter to bound; what CAN fail is the payload, so the parse
            // runs here and a malformed one is refused at import rather than at login.
            Scheme::Ldap => {
                parse_ldap(stored)?;
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
            Scheme::ShaCrypt => sha_crypt_verify(password, &self.stored),
            Scheme::Ldap => match parse_ldap(&self.stored) {
                Ok(ldap) => ldap.verify(password),
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
    } else if stored.starts_with("$5$") || stored.starts_with("$6$") {
        Some(Scheme::ShaCrypt)
    } else if ldap_variant(stored).is_some() {
        Some(Scheme::Ldap)
    } else {
        None
    }
}

/// Bounds-check a SHA-crypt string: the optional `rounds=` field must sit inside the
/// documented window.
///
/// The parameter is OPTIONAL in the format (`$6$salt$hash` means the glibc default of
/// 5000), so its ABSENCE is accepted rather than treated as a malformed string. Only a
/// present-and-unparseable field is malformed; an omitted one is the common case and
/// rejecting it would refuse most real `/etc/shadow` rows.
fn bounds_sha_crypt(stored: &str) -> Result<(), HashError> {
    // `$6$rounds=5000$salt$hash`: field 2 carries the parameter when present.
    let Some(field) = stored.split('$').nth(2) else {
        return Err(HashError::Malformed);
    };
    let Some(rounds) = field.strip_prefix("rounds=") else {
        // No `rounds=`, so the scheme default applies and there is nothing to bound.
        // The payload itself is validated by the verify path, which fails closed.
        return Ok(());
    };
    let rounds: u32 = rounds.parse().map_err(|_| HashError::Malformed)?;
    if rounds > MAX_SHA_CRYPT_ROUNDS {
        return Err(HashError::OutOfBounds("sha-crypt rounds"));
    }
    if rounds < MIN_SHA_CRYPT_ROUNDS {
        return Err(HashError::OutOfBounds("sha-crypt rounds"));
    }
    Ok(())
}

/// Verify a SHA-crypt string, failing closed on any decode failure.
///
/// SHA-crypt is Modular Crypt Format and not PHC, so this cannot go through the
/// `phc_verify` helper the other schemes share: `sha-crypt` brings its own, newer
/// `password_hash`, and its `PasswordVerifier` is implemented over MCF rather than
/// over the PHC `PasswordHash` this file's other verifiers take. The `str` impl is
/// used deliberately; it parses the MCF string with the same code the typed impls
/// delegate to, and taking it avoids a second `password-hash` in the manifest whose
/// only purpose would be to turn on a feature.
///
/// `ShaCrypt::default()` is not a choice of digest. The algorithm is read from the
/// string's own `$5$`/`$6$` id inside `verify_password`, so a `$5$` hash is verified
/// as SHA-256 whatever this receiver was built with.
fn sha_crypt_verify(password: &[u8], stored: &str) -> bool {
    use sha_crypt::password_hash::PasswordVerifier as _;

    sha_crypt::ShaCrypt::default()
        .verify_password(password, stored)
        .is_ok()
}

/// One parsed LDAP/RFC 2307 digest: the digest bytes and, for a salted variant, the
/// salt that was appended to the password before hashing.
struct LdapHash {
    variant: LdapVariant,
    digest: Vec<u8>,
    salt: Vec<u8>,
}

/// Which LDAP digest a string declares, and whether it is salted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LdapVariant {
    Sha1 { salted: bool },
    Sha256 { salted: bool },
    Sha512 { salted: bool },
}

impl LdapVariant {
    /// The digest width in bytes, which is also where the salt begins in a salted
    /// payload. Read from the VARIANT and never from the payload length: taking it
    /// from the payload would let a truncated blob redefine where the salt starts and
    /// verify against a shorter digest than the scheme specifies.
    fn digest_len(self) -> usize {
        match self {
            LdapVariant::Sha1 { .. } => 20,
            LdapVariant::Sha256 { .. } => 32,
            LdapVariant::Sha512 { .. } => 64,
        }
    }

    fn salted(self) -> bool {
        match self {
            LdapVariant::Sha1 { salted }
            | LdapVariant::Sha256 { salted }
            | LdapVariant::Sha512 { salted } => salted,
        }
    }
}

/// The declared variant and the base64 payload, or [`None`] when the string carries no
/// recognized LDAP prefix.
///
/// The order of this table is NOT load-bearing, and saying so is the point: the tags
/// look like they overlap (`{SSHA}` and `{SSHA256}` share four characters) but the
/// CLOSING BRACE terminates every one of them, so `{SSHA}` does not prefix
/// `{SSHA256}...` and no ordering can confuse the two. A comment claiming the order
/// protects against that would describe a hazard this format does not have, and the
/// next author would preserve an ordering for a reason that was never true.
fn ldap_variant(stored: &str) -> Option<(LdapVariant, &str)> {
    const PREFIXES: &[(&str, LdapVariant)] = &[
        ("{SSHA256}", LdapVariant::Sha256 { salted: true }),
        ("{SSHA512}", LdapVariant::Sha512 { salted: true }),
        ("{SHA256}", LdapVariant::Sha256 { salted: false }),
        ("{SHA512}", LdapVariant::Sha512 { salted: false }),
        ("{SSHA}", LdapVariant::Sha1 { salted: true }),
        ("{SHA}", LdapVariant::Sha1 { salted: false }),
    ];
    PREFIXES
        .iter()
        .find_map(|(prefix, variant)| stored.strip_prefix(prefix).map(|rest| (*variant, rest)))
}

/// Parse an LDAP digest string into its digest and salt.
fn parse_ldap(stored: &str) -> Result<LdapHash, HashError> {
    let (variant, payload) = ldap_variant(stored).ok_or(HashError::Unrecognized)?;
    let raw = B64.decode(payload).map_err(|_| HashError::Malformed)?;
    let width = variant.digest_len();
    if variant.salted() {
        // A salted payload is digest || salt, so anything at or below the digest width
        // carries no salt and is not the scheme it claims to be. Refused at import: a
        // login-time failure would look like a wrong password.
        if raw.len() <= width {
            return Err(HashError::Malformed);
        }
        let (digest, salt) = raw.split_at(width);
        Ok(LdapHash {
            variant,
            digest: digest.to_vec(),
            salt: salt.to_vec(),
        })
    } else {
        if raw.len() != width {
            return Err(HashError::Malformed);
        }
        Ok(LdapHash {
            variant,
            digest: raw,
            salt: Vec::new(),
        })
    }
}

impl LdapHash {
    /// Recompute the digest over `password || salt` and compare in constant time.
    fn verify(&self, password: &[u8]) -> bool {
        use sha1::Digest as _;

        let computed: Vec<u8> = match self.variant {
            LdapVariant::Sha1 { .. } => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(password);
                hasher.update(&self.salt);
                hasher.finalize().to_vec()
            }
            LdapVariant::Sha256 { .. } => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(password);
                hasher.update(&self.salt);
                hasher.finalize().to_vec()
            }
            LdapVariant::Sha512 { .. } => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(password);
                hasher.update(&self.salt);
                hasher.finalize().to_vec()
            }
        };
        computed.ct_eq(&self.digest).into()
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

    /// The published SHA-crypt specification vectors (Drepper), asserted as CONSTANTS
    /// rather than round-tripped through this crate's own hasher.
    ///
    /// A round-trip would prove only that the implementation agrees with itself. These
    /// strings come from the specification that defines the algorithm, so a passing
    /// assertion is two independent sources agreeing about the same bytes.
    #[test]
    fn sha_crypt_published_known_answer_vectors() {
        for (stored, password) in [
            (
                "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
                "Hello world!",
            ),
            (
                "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJue\
                 sI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
                "Hello world!",
            ),
            (
                "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.op\
                 qey6IcA",
                "Hello world!",
            ),
        ] {
            let stored: String = stored.split_whitespace().collect();
            assert_kat(&stored, password, Scheme::ShaCrypt);
        }
    }

    /// The `rounds=` bound, at both ends and in its absence.
    ///
    /// Absence is the case worth stating: `$6$salt$hash` is the common `/etc/shadow`
    /// shape and means the scheme default, so treating a missing parameter as
    /// malformed would refuse most real rows.
    #[test]
    fn sha_crypt_rounds_out_of_bounds_is_rejected_and_absence_is_not() {
        let over = format!(
            "$6$rounds={}$saltstring$x",
            u64::from(MAX_SHA_CRYPT_ROUNDS) + 1
        );
        assert_eq!(
            ForeignHash::parse(&over),
            Err(HashError::OutOfBounds("sha-crypt rounds")),
            "a rounds count above the documented bound is minutes of CPU per login"
        );
        let under = format!("$6$rounds={}$saltstring$x", MIN_SHA_CRYPT_ROUNDS - 1);
        assert_eq!(
            ForeignHash::parse(&under),
            Err(HashError::OutOfBounds("sha-crypt rounds")),
            "below the scheme minimum the string is not a SHA-crypt hash"
        );
        let at = format!("$6$rounds={MAX_SHA_CRYPT_ROUNDS}$saltstring$x");
        assert!(
            ForeignHash::parse(&at).is_ok(),
            "the bound is inclusive, or an operator's documented maximum is off by one"
        );
        assert!(
            ForeignHash::parse("$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl").is_ok(),
            "an omitted rounds= means the scheme default and must not be malformed"
        );
    }

    /// Every LDAP variant, salted and unsalted, against vectors computed OUTSIDE this
    /// crate (Python `hashlib` and `base64`) so the assertion is not the implementation
    /// checked against itself.
    ///
    /// Each salted variant uses a salt of a DIFFERENT length (2, 10 and 19 bytes), and
    /// none of them is 8. That is not decoration. The first version of these fixtures
    /// used one 8-byte salt everywhere, and 8 happens to equal `payload_len` minus the
    /// SHA-1 digest width, so an implementation taking the width from the PAYLOAD
    /// rather than from the variant passed every case. A mutation sweep found it. With
    /// three different lengths no single arithmetic mistake is right for all of them.
    #[test]
    fn ldap_digest_known_answer_vectors() {
        const PASSWORD: &str = "correct horse battery staple";
        for stored in [
            "{SHA}q/eq1kOINtvlJqojGr3i0O73TUI=",
            "{SSHA}fg1cZ6fA9NAz+kgbHLCBGNDXIa5zMw==",
            "{SHA256}xLvLH77JnWW/WdhcjLYu4tuWPw/hBvSD2a+nO9Tjmoo=",
            "{SSHA256}rbpZpvJNNYAP5+B0oYnh/gRwFDNi7tgUQ5ydDWrE1vdzYWx0LTEzY2hy",
            "{SHA512}vl73Z52Iq5qQRfYmflX15XhLS4zXZLXNhVpSRPkcYmlTzUbEPXZohz/W7707IhJJ\
             MVWAAxljRyoHh4H+BG5irg==",
            "{SSHA512}JodACNxpTAd0DIaHvcP5uCTsFi8Ofk8+LKZP7HPwd1qWYfjZOyY7mLbLRdPMXheo\
             d9+qpNFl7/Jgi5pTlPu+dWEtbmluZXRlZW4tYnl0ZS1zbHQ=",
        ] {
            let stored: String = stored.split_whitespace().collect();
            assert_kat(&stored, PASSWORD, Scheme::Ldap);
        }
    }

    /// Each variant is read as ITSELF, and the digest boundary comes from the variant.
    ///
    /// The tags look like they overlap, and they do not: the closing brace terminates
    /// each one, so `{SSHA}` cannot prefix `{SSHA256}`. What this pins is the property
    /// that genuinely can break, which is where the SALT begins. The widths asserted
    /// here are the scheme's digest widths and the three payloads exceed them by three
    /// different amounts, so a boundary computed from the payload length is wrong for
    /// at least two of the three.
    #[test]
    fn each_ldap_variant_is_read_as_itself_with_the_scheme_digest_width() {
        for (stored, digest, salt) in [
            ("{SSHA}fg1cZ6fA9NAz+kgbHLCBGNDXIa5zMw==", 20, 2),
            (
                "{SSHA256}rbpZpvJNNYAP5+B0oYnh/gRwFDNi7tgUQ5ydDWrE1vdzYWx0LTEzY2hy",
                32,
                10,
            ),
            (
                "{SSHA512}JodACNxpTAd0DIaHvcP5uCTsFi8Ofk8+LKZP7HPwd1qWYfjZOyY7mLbLRdPM\
                 Xheod9+qpNFl7/Jgi5pTlPu+dWEtbmluZXRlZW4tYnl0ZS1zbHQ=",
                64,
                19,
            ),
        ] {
            let stored: String = stored.split_whitespace().collect();
            let parsed = parse_ldap(&stored).expect("the fixture parses");
            assert_eq!(
                (parsed.digest.len(), parsed.salt.len()),
                (digest, salt),
                "{stored} split at the wrong boundary"
            );
        }
    }

    /// A salted payload no longer than its digest carries no salt, and is refused at
    /// IMPORT rather than failing at login where it would look like a wrong password.
    #[test]
    fn a_truncated_salted_ldap_payload_is_malformed_not_a_wrong_password() {
        // A bare 20-byte SHA-1 digest labelled as SALTED SHA-1.
        let bare = "{SSHA}q/eq1kOINtvlJqojGr3i0O73TUI=";
        assert_eq!(ForeignHash::parse(bare), Err(HashError::Malformed));
        // An unsalted variant whose payload is the wrong WIDTH is malformed too.
        let wrong_width = "{SHA}q/eq1kOINtvlJqojGr3i0O73TUIAAA==";
        assert_eq!(ForeignHash::parse(wrong_width), Err(HashError::Malformed));
    }

    /// The MD5 LDAP schemes are deliberately unrecognized, and this is the assertion
    /// that says so rather than a comment claiming it.
    #[test]
    fn the_md5_ldap_schemes_are_not_recognized() {
        for stored in [
            "{MD5}X03MO1qnZdYdgyfeuILPmQ==",
            "{SMD5}X03MO1qnZdYdgyfeuILPmXNhbHQ=",
        ] {
            assert_eq!(
                ForeignHash::parse(stored),
                Err(HashError::Unrecognized),
                "{stored} is not in the issue's scheme list and is not accepted on the \
                 strength of being easy to add"
            );
        }
    }

    /// The LDAP digests, and only they, are reported as urgent to rehash.
    ///
    /// Asserted over EVERY variant rather than the two that make the point, so a
    /// scheme added later cannot inherit `false` by never being listed here.
    #[test]
    fn only_the_unsalted_digest_schemes_are_urgent_to_rehash() {
        let urgent: Vec<&str> = Scheme::ALL
            .iter()
            .filter(|scheme| scheme.rehash_is_urgent())
            .map(|scheme| scheme.tag())
            .collect();
        assert_eq!(
            urgent,
            vec!["ldap-digest"],
            "the urgent set is stated over EVERY scheme, so a variant added later \
             cannot inherit `false` by never being listed"
        );
    }

    #[test]
    fn scheme_tag_round_trips() {
        for scheme in Scheme::ALL {
            assert_eq!(
                Scheme::from_tag(scheme.tag()),
                Some(scheme),
                "{} does not round-trip through its tag, so a stored row of that \
                 scheme cannot be dispatched after a restart",
                scheme.tag()
            );
        }
        assert_eq!(Scheme::from_tag("md5"), None);
        // Every tag distinct: two schemes sharing one would round-trip individually
        // and still dispatch the second as the first.
        let mut tags: Vec<&str> = Scheme::ALL.iter().map(|s| s.tag()).collect();
        tags.sort_unstable();
        let count = tags.len();
        tags.dedup();
        assert_eq!(tags.len(), count, "two schemes share an algorithm tag");
    }
}

#[cfg(test)]
mod independence {
    /// This crate's own manifest, read at COMPILE time so the assertion below cannot be
    /// fooled by a working tree that differs from what was built.
    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// This crate depends on NO ironauth crate, which is the property that lets it publish
    /// (issue #55).
    ///
    /// It is pinned rather than trusted because the failure is silent and one line long. A
    /// single `ironauth-store.workspace = true` added here for convenience compiles, tests,
    /// and passes every other gate, and the only symptom is that `cargo package` starts
    /// failing with `no matching package named ironauth-store found` at the moment somebody
    /// tries to release it, which is the worst time to discover it. That is exactly the
    /// failure `ironauth-import` has today and the reason this crate was split out of it.
    ///
    /// The scan is a TEXT scan and its ceiling is worth stating: it reads the `[dependencies]`
    /// section of this manifest only, so an ironauth crate reached through a renamed
    /// dependency (`foo = { package = "ironauth-store" }`) would slip past the prefix check.
    /// It catches the ordinary way this breaks, which is somebody adding the obvious line.
    #[test]
    fn this_crate_depends_on_no_ironauth_crate() {
        // Scoped to the dependency tables, which is what the doc above claims and what the
        // first version of this test did NOT do: it scanned the whole file and matched this
        // crate's own `name = "ironauth-hash-scheme"`, so it failed on a manifest that was
        // correct. A guard that cannot pass on a correct input teaches people to delete it.
        let offenders: Vec<&str> = MANIFEST
            .lines()
            .map(str::trim)
            .scan(false, |in_deps, line| {
                if line.starts_with('[') {
                    *in_deps = line.contains("dependencies");
                    return Some(("", false));
                }
                Some((line, *in_deps))
            })
            .filter(|(line, in_deps)| {
                *in_deps && !line.starts_with('#') && line.starts_with("ironauth-")
            })
            .map(|(line, _)| line)
            .collect();
        assert!(
            offenders.is_empty(),
            "this crate gained an ironauth dependency, which makes it unpublishable on its \
             own and undoes the split issue #55 asked for: {offenders:?}"
        );
    }
}

#[cfg(test)]
mod publishability {
    /// This crate's own manifest, read at compile time.
    const MANIFEST: &str = include_str!("../Cargo.toml");

    /// The crate depends on NO `ironauth-*` crate.
    ///
    /// The manifest carries a comment saying this absence is load-bearing and that adding
    /// such a dependency "would silently revoke" the crate's ability to be published on its
    /// own. Nothing enforced it, so the comment was a promise rather than a property: a
    /// single `ironauth-store = { path = ... }` would have made every future
    /// `cargo publish` fail, and the first person to find out would have been whoever ran
    /// the release.
    ///
    /// Scanned over the DEPENDENCY sections only, because the comment itself names
    /// `ironauth-*` and a scan of the whole file would match its own warning and pass for
    /// the wrong reason.
    #[test]
    fn the_crate_depends_on_no_ironauth_crate() {
        let mut in_dependencies = false;
        let mut offenders: Vec<&str> = Vec::new();
        for line in MANIFEST.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_dependencies = trimmed.contains("dependencies");
                continue;
            }
            if !in_dependencies || trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("ironauth-") || trimmed.starts_with("ironauth_") {
                offenders.push(trimmed);
            }
        }
        assert!(
            offenders.is_empty(),
            "this crate gained an ironauth-* dependency, which is what makes it publishable \
             on its own. Publishing would now require publishing that crate too, and every \
             one below it. Offending entries: {offenders:?}"
        );
    }

    /// The metadata crates.io requires of a published crate is present.
    ///
    /// Criterion 6 of issue #55 asks the crate to publish "with its own documentation". A
    /// missing `readme` is not a build failure and not a publish failure; it is a crate page
    /// with no body, discovered after the version is permanent and unyankable into
    /// correctness.
    #[test]
    fn the_publish_metadata_is_present() {
        for key in [
            "description",
            "readme",
            "documentation",
            "license",
            "repository",
        ] {
            assert!(
                MANIFEST
                    .lines()
                    .any(|line| line.trim_start().starts_with(key)),
                "the manifest is missing `{key}`, which a published crate needs"
            );
        }
    }

    /// The description does not promise a capability the crate does not contain.
    ///
    /// It said "and rehash decisions". There is no rehash logic here and never was: the
    /// crate answers whether a password matches, and the policy that decides whether to
    /// replace a stored hash lives with the password policy, which this crate cannot see.
    /// That string is the single most-read sentence the crate ships, since it is what
    /// crates.io lists, and it was wrong.
    #[test]
    fn the_description_does_not_claim_rehash() {
        let description = MANIFEST
            .lines()
            .find(|line| line.trim_start().starts_with("description"))
            .expect("a description");
        assert!(
            !description.to_ascii_lowercase().contains("rehash"),
            "the published description claims rehash decisions this crate does not make: \
             {description}"
        );
    }
}
