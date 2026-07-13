// SPDX-License-Identifier: MIT OR Apache-2.0

//! The caller-supplied verification policy: the ONLY source of trust.
//!
//! Everything the verifier trusts to make a decision lives here and is supplied
//! by the caller out of band (resolved from configuration or a JWKS, never from
//! the token): the algorithm allowlist, the trusted key(s), the expected issuer
//! and audience, the clock skew, and the pre-processing caps. The token can
//! present an `alg` and a `kid`, but they are treated as untrusted claims that
//! must MATCH the policy; they can never reach outside it to name an algorithm
//! or introduce a key.

use std::time::Duration;

/// A JWS signature algorithm this core can verify.
///
/// The set is closed and every member is backed by a `ring` primitive. HMAC
/// (`HS*`) is deliberately absent: with no symmetric verification path, the
/// classic "verify an `RS256` token as `HS256` using the RSA public key as the
/// HMAC secret" confusion is not merely blocked but inexpressible. The excluded
/// algorithms and the reasons are in `docs/WILL-NOT-IMPLEMENT.md`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[non_exhaustive]
pub enum JwsAlgorithm {
    /// `EdDSA` over Curve25519 (Ed25519). The IronAuth default.
    EdDsa,
    /// ECDSA using P-256 and SHA-256.
    Es256,
    /// ECDSA using P-384 and SHA-384.
    Es384,
    /// RSASSA-PKCS1-v1_5 using SHA-256.
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384.
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512.
    Rs512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    Ps256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384.
    Ps384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512.
    Ps512,
}

impl JwsAlgorithm {
    /// The JOSE `alg` name (RFC 7518) for this algorithm.
    #[must_use]
    pub fn as_jose_name(self) -> &'static str {
        match self {
            JwsAlgorithm::EdDsa => "EdDSA",
            JwsAlgorithm::Es256 => "ES256",
            JwsAlgorithm::Es384 => "ES384",
            JwsAlgorithm::Rs256 => "RS256",
            JwsAlgorithm::Rs384 => "RS384",
            JwsAlgorithm::Rs512 => "RS512",
            JwsAlgorithm::Ps256 => "PS256",
            JwsAlgorithm::Ps384 => "PS384",
            JwsAlgorithm::Ps512 => "PS512",
        }
    }

    /// Parse a supported JOSE `alg` name, exactly and case-sensitively.
    ///
    /// Returns `None` for every unsupported or malformed name, including
    /// `none`, the HMAC names, and any casing or whitespace variant, so the
    /// caller cannot be tricked by a near-miss spelling.
    #[must_use]
    pub fn from_jose_name(name: &str) -> Option<Self> {
        Some(match name {
            "EdDSA" => JwsAlgorithm::EdDsa,
            "ES256" => JwsAlgorithm::Es256,
            "ES384" => JwsAlgorithm::Es384,
            "RS256" => JwsAlgorithm::Rs256,
            "RS384" => JwsAlgorithm::Rs384,
            "RS512" => JwsAlgorithm::Rs512,
            "PS256" => JwsAlgorithm::Ps256,
            "PS384" => JwsAlgorithm::Ps384,
            "PS512" => JwsAlgorithm::Ps512,
            _ => return None,
        })
    }

    /// The key family this algorithm must be verified with.
    #[must_use]
    pub fn key_family(self) -> KeyFamily {
        match self {
            JwsAlgorithm::EdDsa => KeyFamily::Ed25519,
            JwsAlgorithm::Es256 => KeyFamily::EcP256,
            JwsAlgorithm::Es384 => KeyFamily::EcP384,
            JwsAlgorithm::Rs256
            | JwsAlgorithm::Rs384
            | JwsAlgorithm::Rs512
            | JwsAlgorithm::Ps256
            | JwsAlgorithm::Ps384
            | JwsAlgorithm::Ps512 => KeyFamily::Rsa,
        }
    }
}

/// The type of a public key, used to reject algorithm/key confusion.
///
/// A trusted key has exactly one family; a token's claimed algorithm must map
/// to the same family or the token is rejected before any signature check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyFamily {
    /// An Ed25519 public key (32-byte compressed point).
    Ed25519,
    /// An ECDSA P-256 public key.
    EcP256,
    /// An ECDSA P-384 public key.
    EcP384,
    /// An RSA public key (usable for both RSASSA-PKCS1-v1_5 and RSASSA-PSS).
    Rsa,
}

/// The normalized public-key material for one trusted key. Crate-private: the
/// raw bytes are only ever handed to the private crypto module.
#[derive(Clone, Debug)]
pub(crate) enum KeyMaterial {
    /// Raw 32-byte Ed25519 public key.
    Ed25519(Vec<u8>),
    /// SEC1 uncompressed point `0x04 || x || y`, 65 bytes for P-256.
    EcP256(Vec<u8>),
    /// SEC1 uncompressed point `0x04 || x || y`, 97 bytes for P-384.
    EcP384(Vec<u8>),
    /// RSA modulus and exponent, big-endian.
    Rsa {
        /// Modulus `n`.
        n: Vec<u8>,
        /// Public exponent `e`.
        e: Vec<u8>,
    },
}

impl KeyMaterial {
    pub(crate) fn family(&self) -> KeyFamily {
        match self {
            KeyMaterial::Ed25519(_) => KeyFamily::Ed25519,
            KeyMaterial::EcP256(_) => KeyFamily::EcP256,
            KeyMaterial::EcP384(_) => KeyFamily::EcP384,
            KeyMaterial::Rsa { .. } => KeyFamily::Rsa,
        }
    }
}

/// A public key the caller has decided to trust, out of band.
///
/// Keys enter verification ONLY through the policy; the token can never
/// introduce one. An optional `kid` lets a token select among already-trusted
/// keys, and nothing more.
#[derive(Clone, Debug)]
pub struct TrustedKey {
    pub(crate) kid: Option<String>,
    pub(crate) material: KeyMaterial,
}

impl TrustedKey {
    /// An Ed25519 trusted key from its raw 32-byte public key.
    ///
    /// # Errors
    ///
    /// [`KeyError::BadLength`] if `public_key` is not exactly 32 bytes.
    pub fn ed25519(kid: Option<String>, public_key: &[u8]) -> Result<Self, KeyError> {
        if public_key.len() != 32 {
            return Err(KeyError::BadLength {
                expected: 32,
                actual: public_key.len(),
            });
        }
        Ok(Self {
            kid,
            material: KeyMaterial::Ed25519(public_key.to_vec()),
        })
    }

    /// An ECDSA P-256 trusted key from its affine coordinates (32 bytes each).
    ///
    /// # Errors
    ///
    /// [`KeyError::BadLength`] if either coordinate is not exactly 32 bytes.
    pub fn ecdsa_p256(kid: Option<String>, x: &[u8], y: &[u8]) -> Result<Self, KeyError> {
        let point = sec1_point(x, y, 32)?;
        Ok(Self {
            kid,
            material: KeyMaterial::EcP256(point),
        })
    }

    /// An ECDSA P-384 trusted key from its affine coordinates (48 bytes each).
    ///
    /// # Errors
    ///
    /// [`KeyError::BadLength`] if either coordinate is not exactly 48 bytes.
    pub fn ecdsa_p384(kid: Option<String>, x: &[u8], y: &[u8]) -> Result<Self, KeyError> {
        let point = sec1_point(x, y, 48)?;
        Ok(Self {
            kid,
            material: KeyMaterial::EcP384(point),
        })
    }

    /// An ECDSA P-256 trusted key from a SEC1 uncompressed point
    /// (`0x04 || x || y`, 65 bytes).
    ///
    /// # Errors
    ///
    /// [`KeyError::BadLength`] if `point` is not 65 bytes, or
    /// [`KeyError::BadEncoding`] if it is not an uncompressed point.
    pub fn ecdsa_p256_point(kid: Option<String>, point: &[u8]) -> Result<Self, KeyError> {
        check_uncompressed_point(point, 65)?;
        Ok(Self {
            kid,
            material: KeyMaterial::EcP256(point.to_vec()),
        })
    }

    /// An ECDSA P-384 trusted key from a SEC1 uncompressed point
    /// (`0x04 || x || y`, 97 bytes).
    ///
    /// # Errors
    ///
    /// [`KeyError::BadLength`] if `point` is not 97 bytes, or
    /// [`KeyError::BadEncoding`] if it is not an uncompressed point.
    pub fn ecdsa_p384_point(kid: Option<String>, point: &[u8]) -> Result<Self, KeyError> {
        check_uncompressed_point(point, 97)?;
        Ok(Self {
            kid,
            material: KeyMaterial::EcP384(point.to_vec()),
        })
    }

    /// An RSA trusted key from its modulus and exponent (big-endian).
    ///
    /// The same key verifies both the `RS*` (PKCS1-v1_5) and `PS*` (PSS)
    /// algorithms; which one runs is fixed by the token's allowlisted `alg`.
    ///
    /// # Errors
    ///
    /// [`KeyError::BadLength`] if the modulus is shorter than 2048 bits, which
    /// `ring` refuses to verify; smaller RSA keys are not accepted.
    pub fn rsa(kid: Option<String>, n: &[u8], e: &[u8]) -> Result<Self, KeyError> {
        let n_trimmed = strip_leading_zeros(n);
        // ring's RSA verifiers accept 2048..=8192-bit moduli. Reject smaller keys
        // here so a weak key never reaches the crypto path.
        if n_trimmed.len() < 256 {
            return Err(KeyError::BadLength {
                expected: 256,
                actual: n_trimmed.len(),
            });
        }
        // Check the STRIPPED exponent: an all-zero exponent (for example
        // `[0x00]`) strips to empty and is not a valid RSA public exponent.
        let e_trimmed = strip_leading_zeros(e);
        if e_trimmed.is_empty() {
            return Err(KeyError::BadLength {
                expected: 1,
                actual: 0,
            });
        }
        Ok(Self {
            kid,
            material: KeyMaterial::Rsa {
                n: n_trimmed.to_vec(),
                e: e_trimmed.to_vec(),
            },
        })
    }

    /// The `kid` this key answers to, if any.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The family of this key.
    #[must_use]
    pub fn family(&self) -> KeyFamily {
        self.material.family()
    }
}

fn sec1_point(x: &[u8], y: &[u8], coord_len: usize) -> Result<Vec<u8>, KeyError> {
    if x.len() != coord_len {
        return Err(KeyError::BadLength {
            expected: coord_len,
            actual: x.len(),
        });
    }
    if y.len() != coord_len {
        return Err(KeyError::BadLength {
            expected: coord_len,
            actual: y.len(),
        });
    }
    let mut point = Vec::with_capacity(1 + 2 * coord_len);
    point.push(0x04);
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    Ok(point)
}

fn check_uncompressed_point(point: &[u8], expected: usize) -> Result<(), KeyError> {
    if point.len() != expected {
        return Err(KeyError::BadLength {
            expected,
            actual: point.len(),
        });
    }
    if point[0] != 0x04 {
        return Err(KeyError::BadEncoding);
    }
    Ok(())
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// A caller-side error constructing a [`TrustedKey`].
///
/// These describe caller misuse (bad key material), not a token verification
/// outcome, so they are safe to surface and describe; they carry no oracle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum KeyError {
    /// The key material had the wrong length for its type.
    BadLength {
        /// The required length in bytes.
        expected: usize,
        /// The length that was supplied.
        actual: usize,
    },
    /// The key material was structurally invalid (for example an EC point that
    /// is not in uncompressed form).
    BadEncoding,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::BadLength { expected, actual } => {
                write!(
                    f,
                    "trusted key has wrong length: expected {expected}, got {actual}"
                )
            }
            KeyError::BadEncoding => f.write_str("trusted key material is not validly encoded"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Pre-processing caps, enforced before any base64, JSON, or crypto work.
///
/// Env-dependent knobs with safe defaults (the tunability principle): tighten
/// them for a known token profile, but they can never be raised to admit a
/// compressed or PBES2 input, which are rejected structurally regardless of the
/// numbers here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerificationCaps {
    /// Maximum raw token size in bytes. Checked first of all, before decoding.
    pub max_token_bytes: usize,
    /// Maximum DECODED protected-header size in bytes.
    pub max_header_bytes: usize,
    /// Maximum DECODED claims size in bytes.
    pub max_payload_bytes: usize,
    /// Maximum tolerated base64 expansion ratio. Documented guard for any future
    /// compression path; today compression (`zip`) is rejected outright, so this
    /// bounds nothing that is ever inflated, and exists so the knob is present
    /// and tunable if compression is ever admitted.
    pub max_decompression_ratio: u32,
    /// Maximum PBES2 iteration count (`p2c`). PBES2 is rejected outright; a `p2c`
    /// above this cap is rejected cheaply, before any key derivation, so a
    /// bomb-shaped iteration count cannot cost work.
    pub max_pbes2_count: u32,
}

impl VerificationCaps {
    /// Safe defaults: 16 KiB token, 4 KiB header, 16 KiB claims, ratio 10,
    /// 10000 PBES2 iterations.
    pub const DEFAULT: Self = Self {
        max_token_bytes: 16 * 1024,
        max_header_bytes: 4 * 1024,
        max_payload_bytes: 16 * 1024,
        max_decompression_ratio: 10,
        max_pbes2_count: 10_000,
    };
}

impl Default for VerificationCaps {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The complete, caller-supplied policy for one verification.
///
/// Built through [`VerificationPolicy::new`], which requires a non-empty
/// algorithm allowlist, at least one trusted key, and both an expected issuer
/// and audience. The mandatory issuer and audience are how "a caller cannot opt
/// out of claim enforcement" is made structural: there is no way to construct a
/// policy that skips them.
#[derive(Clone, Debug)]
pub struct VerificationPolicy {
    pub(crate) algorithms: Vec<JwsAlgorithm>,
    pub(crate) keys: Vec<TrustedKey>,
    pub(crate) expected_iss: String,
    pub(crate) expected_aud: String,
    pub(crate) max_skew: Duration,
    pub(crate) caps: VerificationCaps,
    pub(crate) require_iat: bool,
}

impl VerificationPolicy {
    /// The default clock skew tolerance: 60 seconds.
    pub const DEFAULT_SKEW: Duration = Duration::from_secs(60);

    /// Build a policy.
    ///
    /// `algorithms` is the allowlist a token's `alg` must belong to; `keys` are
    /// the trusted keys (the only key source); `expected_iss` and `expected_aud`
    /// are matched EXACTLY against the token's `iss` and `aud`. Skew defaults to
    /// [`VerificationPolicy::DEFAULT_SKEW`] and caps to
    /// [`VerificationCaps::DEFAULT`]; adjust them with the `with_*` setters.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] if the allowlist is empty, no keys are supplied, or the
    /// expected issuer or audience is empty.
    pub fn new(
        algorithms: Vec<JwsAlgorithm>,
        keys: Vec<TrustedKey>,
        expected_iss: impl Into<String>,
        expected_aud: impl Into<String>,
    ) -> Result<Self, PolicyError> {
        if algorithms.is_empty() {
            return Err(PolicyError::EmptyAllowlist);
        }
        if keys.is_empty() {
            return Err(PolicyError::NoKeys);
        }
        let expected_iss = expected_iss.into();
        let expected_aud = expected_aud.into();
        if expected_iss.is_empty() {
            return Err(PolicyError::EmptyIssuer);
        }
        if expected_aud.is_empty() {
            return Err(PolicyError::EmptyAudience);
        }
        Ok(Self {
            algorithms,
            keys,
            expected_iss,
            expected_aud,
            max_skew: Self::DEFAULT_SKEW,
            caps: VerificationCaps::DEFAULT,
            require_iat: false,
        })
    }

    /// Set the clock-skew tolerance for `exp`, `nbf`, and `iat`.
    #[must_use]
    pub fn with_skew(mut self, skew: Duration) -> Self {
        self.max_skew = skew;
        self
    }

    /// Set the pre-processing caps.
    #[must_use]
    pub fn with_caps(mut self, caps: VerificationCaps) -> Self {
        self.caps = caps;
        self
    }

    /// Require the `iat` claim to be present (it is always enforced when
    /// present; this additionally makes its absence a rejection).
    #[must_use]
    pub fn require_iat(mut self, required: bool) -> Self {
        self.require_iat = required;
        self
    }

    /// The algorithm allowlist.
    #[must_use]
    pub fn algorithms(&self) -> &[JwsAlgorithm] {
        &self.algorithms
    }

    /// The expected issuer.
    #[must_use]
    pub fn expected_iss(&self) -> &str {
        &self.expected_iss
    }

    /// The expected audience.
    #[must_use]
    pub fn expected_aud(&self) -> &str {
        &self.expected_aud
    }

    /// The clock-skew tolerance.
    #[must_use]
    pub fn max_skew(&self) -> Duration {
        self.max_skew
    }

    /// The pre-processing caps.
    #[must_use]
    pub fn caps(&self) -> VerificationCaps {
        self.caps
    }
}

/// A caller-side error building a [`VerificationPolicy`].
///
/// Like [`KeyError`], these are caller misuse and safe to describe.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PolicyError {
    /// The algorithm allowlist was empty; there would be nothing to accept.
    EmptyAllowlist,
    /// No trusted key was supplied; there would be nothing to verify against.
    NoKeys,
    /// The expected issuer was empty; issuer enforcement cannot be opted out of.
    EmptyIssuer,
    /// The expected audience was empty; audience enforcement cannot be opted out
    /// of.
    EmptyAudience,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PolicyError::EmptyAllowlist => "verification policy has an empty algorithm allowlist",
            PolicyError::NoKeys => "verification policy has no trusted keys",
            PolicyError::EmptyIssuer => "verification policy has an empty expected issuer",
            PolicyError::EmptyAudience => "verification policy has an empty expected audience",
        })
    }
}

impl std::error::Error for PolicyError {}
