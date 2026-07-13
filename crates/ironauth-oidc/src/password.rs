// SPDX-License-Identifier: MIT OR Apache-2.0

//! The bootstrap password hasher (issue #20).
//!
//! This is a MINIMAL slice of the M7 password system: it ships only the raw
//! Argon2id hash and verify at the OWASP default parameters, in the standard PHC
//! string format. It deliberately does NOT ship the M7 apparatus (a
//! parameter-tuning helper, an admission-controlled hashing pool, breach
//! screening, or lockout); when M7 lands it reuses this same hash FORMAT, so
//! stored hashes carry forward unchanged.
//!
//! # Parameters
//!
//! Argon2id at the OWASP defaults: memory `m = 19456` KiB, iterations `t = 2`,
//! parallelism `p = 1`. The parameters are embedded in the emitted PHC string, so
//! [`verify_password`] reconstructs them from the stored hash and a later
//! parameter bump does not invalidate an existing hash.
//!
//! # Determinism seam
//!
//! The per-hash salt is drawn from the [`ironauth_env`] entropy seam, never a
//! direct OS or crate RNG, so hashing is reproducible under a fixed test entropy
//! source and the invariant lints stay satisfied.
//!
//! # One-way only
//!
//! There is no function here that recovers a plaintext password, and nothing
//! stores one: [`hash_password`] returns the one-way PHC verifier, and the store
//! persists only that string.

use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use ironauth_env::Env;

/// OWASP Argon2id memory cost, in KiB.
const OWASP_M_COST_KIB: u32 = 19_456;
/// OWASP Argon2id iteration (time) cost.
const OWASP_T_COST: u32 = 2;
/// OWASP Argon2id parallelism (lanes).
const OWASP_P_COST: u32 = 1;
/// Salt length in bytes (128 bits).
const SALT_BYTES: usize = 16;

/// Why a password hash could not be produced. Verification never errors (it
/// returns a bool), so this is only the hashing side; it is unreachable in
/// practice because the parameters are fixed and valid by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    /// The Argon2id context or hashing step failed. Only reachable if the fixed
    /// OWASP parameters became invalid, which cannot happen for the constants
    /// above.
    Hash,
}

/// The Argon2id context at the OWASP default parameters.
fn argon2() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(OWASP_M_COST_KIB, OWASP_T_COST, OWASP_P_COST, None)
        .map_err(|_| PasswordError::Hash)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash `password` with Argon2id at the OWASP defaults, drawing the salt from the
/// environment entropy seam, and return the PHC string to store.
///
/// # Errors
///
/// [`PasswordError::Hash`] if the salt cannot be encoded or the hashing step
/// fails (unreachable for the fixed valid parameters; surfaced rather than
/// panicked so a caller fails closed).
pub fn hash_password(env: &Env, password: &str) -> Result<String, PasswordError> {
    let mut salt_bytes = [0_u8; SALT_BYTES];
    env.entropy().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| PasswordError::Hash)?;
    let hash = argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| PasswordError::Hash)?;
    Ok(hash.to_string())
}

/// Verify `password` against a stored PHC `hash`. Returns `false` for a wrong
/// password AND for a malformed stored hash (fail closed), so a corrupt row can
/// never authenticate. The Argon2id parameters come from the stored hash, so a
/// hash written at older parameters still verifies.
#[must_use]
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Run a full Argon2id verification against a fixed dummy hash and always return
/// `false`. The login surface calls this when no account matches the presented
/// identifier, so a present and an absent account take comparable time and the
/// endpoint is not a user-enumeration oracle.
///
/// The dummy hash is computed once (process wide) from a fixed throwaway password
/// and a fixed salt at the same OWASP parameters, so it costs the same as a real
/// verification. It protects no real secret, so a fixed salt is fine here and no
/// entropy seam is involved.
#[must_use]
pub fn verify_absent(password: &str) -> bool {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY.get_or_init(|| {
        // A fixed salt: this hash only exists to spend Argon2id time, so it needs
        // no randomness. encode_b64 of a fixed byte pattern is valid by
        // construction; fall back to an empty string only if that ever fails, in
        // which case verify_password below returns false anyway.
        let salt = SaltString::encode_b64(&[0x24_u8; SALT_BYTES]).ok();
        salt.and_then(|salt| {
            argon2()
                .ok()?
                .hash_password(b"ironauth-absent-user-placeholder", &salt)
                .ok()
                .map(|hash| hash.to_string())
        })
        .unwrap_or_default()
    });
    // Run the verification for its timing (Argon2id work), then discard the
    // result and always return false. black_box keeps the compiler from eliding
    // the unused verification.
    std::hint::black_box(verify_password(password, dummy));
    false
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn hash_round_trips_and_rejects_wrong_password() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 7);
        let hash = hash_password(&env, "correct horse battery staple").expect("hash");
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong password", &hash));
    }

    #[test]
    fn emitted_hash_is_argon2id_at_owasp_parameters() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 11);
        let hash = hash_password(&env, "pw").expect("hash");
        // PHC prefix identifies the algorithm; the parameters are embedded.
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert!(hash.contains("m=19456"), "OWASP memory cost: {hash}");
        assert!(hash.contains("t=2"), "OWASP time cost: {hash}");
        assert!(hash.contains("p=1"), "OWASP parallelism: {hash}");
        // No plaintext is present in the stored form.
        assert!(!hash.contains("pw$") && !hash.ends_with("pw"), "{hash}");
    }

    #[test]
    fn different_salts_make_two_hashes_of_the_same_password_differ() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 3);
        let a = hash_password(&env, "same").expect("hash a");
        let b = hash_password(&env, "same").expect("hash b");
        assert_ne!(a, b, "the salt seam must vary the hash");
        assert!(verify_password("same", &a) && verify_password("same", &b));
    }

    #[test]
    fn verify_rejects_a_malformed_stored_hash() {
        assert!(!verify_password("anything", "not-a-phc-string"));
        assert!(!verify_password("anything", ""));
    }

    #[test]
    fn verify_absent_is_always_false() {
        assert!(!verify_absent("anything"));
        assert!(!verify_absent(""));
    }
}
