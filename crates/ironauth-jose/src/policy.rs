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
    ///
    /// `Ed25519` is accepted as an alias of the polymorphic `EdDSA` identifier.
    /// It is the fully-specified name (draft-ietf-jose-fully-specified-algorithms)
    /// for the exact same primitive: `PureEdDSA` over Curve25519, verified with
    /// the exact same `ring` Ed25519 path and key family. It introduces no new
    /// trust and no new family, so accepting it cannot enable any downgrade or
    /// confusion; the signer emits it only when its fully-specified toggle is on.
    #[must_use]
    pub fn from_jose_name(name: &str) -> Option<Self> {
        Some(match name {
            "EdDSA" | "Ed25519" => JwsAlgorithm::EdDsa,
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

    /// The fully-specified JOSE `alg` name for this algorithm.
    ///
    /// Identical to [`JwsAlgorithm::as_jose_name`] for every algorithm except
    /// `EdDSA`, whose fully-specified name is `Ed25519`
    /// (draft-ietf-jose-fully-specified-algorithms). The rest of the matrix is
    /// already fully specified. Used by the signer only when its emission toggle
    /// is on; the polymorphic [`JwsAlgorithm::as_jose_name`] remains the default.
    #[must_use]
    pub fn fully_specified_name(self) -> &'static str {
        match self {
            JwsAlgorithm::EdDsa => "Ed25519",
            other => other.as_jose_name(),
        }
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

/// The `application/` prefix a JOSE `typ` may carry. RFC 7515 section 4.1.9
/// permits omitting it for a media type with no other `/`, and both spellings
/// name the same media type, so the verifier strips it before comparing.
const MEDIA_TYPE_PREFIX: &str = "application/";

/// Declare the token profiles IronAuth mints ONCE: the variant, its documentation,
/// and the RFC media type that names it.
///
/// From that one list this generates the [`TokenTyp`] enum, [`TokenTyp::media_type`]
/// (an exhaustive match, so a profile cannot exist without a media type), and
/// [`TokenTyp::ALL`], whose length is COUNTED from the same list.
///
/// `ALL` is generated rather than written out beside the enum, and that is the whole
/// reason this macro exists. A hand-written array is a thing an author adding a
/// profile can forget, and forgetting it is invisible: the exhaustive match still
/// forces a media type to be declared, but every check that iterates the profiles
/// (above all `no_two_profiles_share_a_media_type`, which is what makes `typ` a
/// separator at all) would simply never see the new one and would keep passing. There
/// is no way to add a variant except through this list, so there is no way to add one
/// the pairwise check does not compare.
macro_rules! token_profiles {
    ($( $(#[$profile_doc:meta])* $variant:ident => $media_type:literal ),+ $(,)?) => {
        /// A token profile IronAuth MINTS, and the JOSE `typ` media type that names it.
        ///
        /// This enum is the ONE declaration binding a profile to its media type. Both
        /// sides read it: the mint stamps [`TokenTyp::media_type`] into the protected
        /// header (through [`crate::EmissionOptions::with_token_typ`]) and the verifier
        /// requires it (through [`ExpectedTyp::Required`]). A profile therefore cannot be
        /// minted under one spelling and required under another, which two independent
        /// string literals at two call sites would permit and which no test comparing the
        /// mint to itself would catch.
        ///
        /// Generated by the `token_profiles!` declaration list, which also generates
        /// [`TokenTyp::media_type`] and [`TokenTyp::ALL`], so a new profile is
        /// simultaneously given a media type and added to every check that iterates them.
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
        #[non_exhaustive]
        pub enum TokenTyp {
            $( $(#[$profile_doc])* $variant, )+
        }

        impl TokenTyp {
            /// EVERY profile, generated from the same declaration list as the enum, so
            /// this array cannot fall behind the variants.
            ///
            /// A check that iterates the profiles reads this, never a second list of its
            /// own: a second list would silently shrink to a subset the moment a profile
            /// was added, and a check over a subset of the profiles passes for exactly
            /// the profile nobody thought about.
            pub const ALL: [TokenTyp; 0 $( + { let _ = stringify!($variant); 1 } )+] =
                [ $( TokenTyp::$variant, )+ ];

            /// The JOSE `typ` media type that names this profile.
            ///
            /// Exhaustive with no wildcard arm on purpose: this match, not a list a future
            /// author has to remember to extend, is what makes a new profile declare its
            /// media type before the crate compiles.
            #[must_use]
            pub const fn media_type(self) -> &'static str {
                match self {
                    $( TokenTyp::$variant => $media_type, )+
                }
            }
        }
    };
}

token_profiles! {
    /// An OAuth 2.0 access token in JWT form: `at+jwt` (RFC 9068 section 2.1).
    /// RFC 9068 section 4 REQUIRES a resource server to reject a JWT presented as
    /// an access token whose `typ` is anything else.
    AccessToken => "at+jwt",
    /// An OpenID Connect ID Token: `JWT` (RFC 7519 section 5.1, the generic JWT
    /// media type; OpenID Connect Core 1.0 section 2 defines no ID-token-specific
    /// media type, so the generic one is the correct and only spelling).
    IdToken => "JWT",
    /// An OpenID Connect Back-Channel Logout Token: `logout+jwt` (OpenID Connect
    /// Back-Channel Logout 1.0 section 2.4, which registers the
    /// `application/logout+jwt` media type). RFC 8471 is the Token Binding
    /// Protocol and has nothing to do with logout tokens.
    LogoutToken => "logout+jwt",
    /// A signed journey interchange archive (issue #347): `iaj+jws`, the media type
    /// of the `.iaj` bundle carrying a journey artifact, its sub-flows, and its
    /// safety manifest. Unlike the three profiles above there is no RFC to cite: no
    /// standards body names this document, so the media type is IronAuth's own and
    /// is deliberately NOT registered with IANA. Its whole job is to be a value no
    /// other profile in this declaration answers to, which
    /// `no_two_profiles_share_a_media_type` checks, so an access token, an ID token,
    /// or a logout token can never be presented where an archive is expected and an
    /// archive can never be presented as a token. The archive is minted by THIS
    /// system (a per-environment Ed25519 key), so the importer states
    /// [`ExpectedTyp::Required`] and never [`ExpectedTyp::ForeignIssuer`]: the
    /// exporter is a foreign ORGANIZATION, but the header shape is IronAuth's, so
    /// `typ` stays a separator here.
    JourneyInterchange => "iaj+jws",
    /// A TOKENIZED SESSION JWT (issue #119): `session+jwt`, the short-lived token a session
    /// tokenizer template mints from a valid opaque session so a service mesh, a third-party
    /// API, or an edge worker can verify an identity with no database call.
    ///
    /// Like `iaj+jws` this media type is IronAuth's own and deliberately NOT registered with
    /// IANA: no standards body names this document. Unlike `iaj+jws` the separation it provides
    /// is load bearing on a token that travels, so it is worth saying what it separates.
    ///
    /// A tokenized session JWT and an RFC 9068 access token can share an issuer, a subject and
    /// an audience, and a resource server behind a mesh may be handed either. They authorize
    /// differently: an access token carries `scope` and was issued through an OAuth grant a
    /// client and a user consented to, while this one carries whatever claim set an operator's
    /// template maps and was issued because a browser session existed. Presenting one as the
    /// other would let a session stand in for a consented grant. RFC 8725 section 3.11 is what
    /// this implements, and `typ` is the field that carries it: the mint stamps this and the
    /// verifier requires it, so neither token answers to the other's policy.
    SessionToken => "session+jwt",
    /// A TRANSACTION TOKEN: `txn_token` (draft-ietf-oauth-transaction-tokens-09 section 6).
    ///
    /// PROTOTYPE (issue #133). Declared here rather than stamped as a bare string at the mint
    /// site because it is a profile IronAuth MINTS, and the whole point of this list is that
    /// the spelling the minter stamps and the spelling a verifier requires come from one
    /// declaration. The draft's media type carries no `+jwt` suffix, which is the draft's
    /// choice and not a typo.
    TransactionToken => "txn_token",
}

/// Whether a protected header's `typ` names `expected`, for a media type IronAuth does NOT mint.
///
/// The same comparison [`TokenTyp::matches`] performs, and deliberately the same function
/// rather than a third copy of it: case-insensitive per RFC 2045 section 5.1, with the optional
/// `application/` prefix stripped first per RFC 7515 section 4.1.9, and an ABSENT `typ` never
/// matching.
///
/// [`TokenTyp`] names only profiles this system mints, so a FOREIGN party's media type -- an
/// IETF draft's, a peer IdP's -- has no variant to compare against and needs this. Two
/// prototypes hand-rolled it before this existed, and the first of them shipped a divergence:
/// it stripped the two literal spellings `application/` and `APPLICATION/`, so a conforming
/// attester sending `Application/oauth-client-attestation+jwt` was refused. Fail-closed, and
/// still a vetted comparison drifting one copy at a time.
#[must_use]
pub fn foreign_media_type_is(header_typ: Option<&str>, expected: &str) -> bool {
    let Some(candidate) = header_typ else {
        return false;
    };
    let bare = match candidate.get(..MEDIA_TYPE_PREFIX.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(MEDIA_TYPE_PREFIX) => {
            &candidate[MEDIA_TYPE_PREFIX.len()..]
        }
        _ => candidate,
    };
    bare.eq_ignore_ascii_case(expected)
}

impl TokenTyp {
    /// Whether a protected header's `typ` names this profile.
    ///
    /// A media type is compared case-insensitively (RFC 2045 section 5.1 makes the
    /// type and subtype case-insensitive, and RFC 8725 section 3.11 relies on that
    /// when it recommends `typ`-based disambiguation), with an optional
    /// `application/` prefix stripped first (RFC 7515 section 4.1.9). An ABSENT
    /// `typ` never matches: a profile this system mints always stamps one, so its
    /// absence is a token that did not come from the mint.
    #[must_use]
    pub fn matches(self, header_typ: Option<&str>) -> bool {
        foreign_media_type_is(header_typ, self.media_type())
    }
}

/// What a verification policy requires of the protected header's `typ`.
///
/// Stating this is MANDATORY: it is a positional argument of
/// [`VerificationPolicy::new`], so a policy that does not say what media type it
/// accepts does not compile. That is deliberate. `typ` is the only thing
/// separating two IronAuth tokens that share an issuer, a subject, an audience,
/// and a signing key, so a verify site that silently accepted any media type
/// would be the confusion, and an `Option` defaulting to "no opinion" would let
/// an author reintroduce it by omission.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ExpectedTyp {
    /// The header `typ` MUST be present and name this profile. Every other media
    /// type, and an absent `typ`, is rejected.
    Required(TokenTyp),
    /// The token is minted by a FOREIGN party (an upstream OP, a client's
    /// `private_key_jwt` assertion, a registered risk-signal transmitter) whose
    /// header this deployment does not control, so `typ` cannot be the separator
    /// here and is not enforced.
    ///
    /// This is safe at exactly the sites it names, and only because something else
    /// does the separating there: the trusted keys are the foreign party's own, and
    /// the issuer and audience are pinned to that one relationship. How strong that
    /// is varies by site and is worth stating honestly. Where the pinned issuer is a
    /// value no IronAuth issuer can take (a client assertion pins `iss == client_id`,
    /// and a client id is a prefix-tagged identifier, never a URL) it is structural.
    /// At the sites that take both the keys and the issuer from OPERATOR
    /// CONFIGURATION (a registered upstream OP, an RFC 7523 issuer, a risk-signal
    /// transmitter) it is a configuration property instead: a deployment that
    /// registered its own issuer and JWKS as a foreign party would have its own
    /// tokens reach the signature check with `typ` unread. Choosing this where the
    /// keys are IronAuth's OWN environment keys reintroduces the confusion.
    ForeignIssuer,
}

impl ExpectedTyp {
    /// Whether a protected header's `typ` satisfies this expectation.
    #[must_use]
    pub fn accepts(self, header_typ: Option<&str>) -> bool {
        match self {
            ExpectedTyp::Required(typ) => typ.matches(header_typ),
            ExpectedTyp::ForeignIssuer => true,
        }
    }
}

/// The complete, caller-supplied policy for one verification.
///
/// Built through [`VerificationPolicy::new`], which requires a non-empty
/// algorithm allowlist, at least one trusted key, both an expected issuer and
/// audience, and an [`ExpectedTyp`]. The mandatory issuer, audience, and media
/// type are how "a caller cannot opt out of claim enforcement" is made structural:
/// there is no way to construct a policy that skips them.
#[derive(Clone, Debug)]
pub struct VerificationPolicy {
    pub(crate) algorithms: Vec<JwsAlgorithm>,
    pub(crate) keys: Vec<TrustedKey>,
    pub(crate) expected_iss: String,
    pub(crate) expected_aud: String,
    pub(crate) expected_typ: ExpectedTyp,
    pub(crate) max_skew: Duration,
    pub(crate) caps: VerificationCaps,
    pub(crate) require_iat: bool,
    pub(crate) allow_expired: bool,
}

impl VerificationPolicy {
    /// The default clock skew tolerance: 60 seconds.
    pub const DEFAULT_SKEW: Duration = Duration::from_secs(60);

    /// Build a policy.
    ///
    /// `algorithms` is the allowlist a token's `alg` must belong to; `keys` are
    /// the trusted keys (the only key source); `expected_iss` and `expected_aud`
    /// are matched EXACTLY against the token's `iss` and `aud`; `expected_typ`
    /// says which token profile this verification is for. Skew defaults to
    /// [`VerificationPolicy::DEFAULT_SKEW`] and caps to
    /// [`VerificationCaps::DEFAULT`]; adjust them with the `with_*` setters.
    ///
    /// `expected_typ` is positional and has no default. Naming the profile is the
    /// point: two IronAuth tokens can share `iss`, `sub`, `aud`, and signing key,
    /// and then the media type is the only thing left that tells them apart.
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
        expected_typ: ExpectedTyp,
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
            expected_typ,
            max_skew: Self::DEFAULT_SKEW,
            caps: VerificationCaps::DEFAULT,
            require_iat: false,
            allow_expired: false,
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

    /// Accept a token whose `exp` is in the PAST (opt-in, default OFF).
    ///
    /// This relaxes ONE check and nothing else: the `exp` claim is still REQUIRED to
    /// be present and well formed (a missing or absurd `exp` still rejects), and the
    /// signature, algorithm allowlist, key selection, issuer, audience, `nbf`, and
    /// `iat` checks all remain fully enforced. The single legitimate caller is OIDC
    /// RP-Initiated Logout, whose `id_token_hint` is a PAST id token presented ONLY to
    /// IDENTIFY a session to end, never to authorize access: the spec requires an
    /// expired hint to still validate for logout targeting. It confers no access, so
    /// accepting a past `exp` here cannot extend a token's usable lifetime anywhere a
    /// token grants a capability. Left OFF, `exp` is enforced exactly as before.
    #[must_use]
    pub fn allow_expired(mut self, allow: bool) -> Self {
        self.allow_expired = allow;
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

    /// The token profile this policy verifies for.
    #[must_use]
    pub fn expected_typ(&self) -> ExpectedTyp {
        self.expected_typ
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

#[cfg(test)]
mod tests {
    use super::{ExpectedTyp, JwsAlgorithm, TokenTyp};

    /// Every profile's media type, spelled out ONE more time, in an EXHAUSTIVE
    /// match that the compiler checks against the enum.
    ///
    /// This is the witness [`TokenTyp::media_type`] cannot be its own: a test that
    /// iterated a list of variants and compared each to `media_type` would compare
    /// the function to itself and pass for any value it returned, and a list is
    /// something an author adding a variant can forget. A match with no wildcard
    /// arm cannot be forgotten, because a new variant stops this file compiling
    /// until its media type is written here too, against the RFC.
    #[test]
    fn every_profile_declares_its_rfc_media_type() {
        for typ in TokenTyp::ALL {
            let expected = match typ {
                // RFC 9068 section 2.1.
                TokenTyp::AccessToken => "at+jwt",
                // RFC 7519 section 5.1.
                TokenTyp::IdToken => "JWT",
                // OpenID Connect Back-Channel Logout 1.0 section 2.4.
                TokenTyp::LogoutToken => "logout+jwt",
                // Issue #347. No RFC: an IronAuth-defined, deliberately
                // unregistered media type for the signed `.iaj` journey archive.
                TokenTyp::JourneyInterchange => "iaj+jws",
                TokenTyp::SessionToken => "session+jwt",
                // draft-ietf-oauth-transaction-tokens-09 section 6. No `+jwt` suffix: that is
                // the draft's spelling, transcribed rather than tidied.
                TokenTyp::TransactionToken => "txn_token",
            };
            assert_eq!(typ.media_type(), expected, "{typ:?}");
        }
    }

    /// No two profiles share a media type, so `typ` really does separate them.
    ///
    /// Compared pairwise over [`TokenTyp::ALL`], which the `token_profiles!`
    /// declaration GENERATES from the same list as the variants themselves. That is
    /// what makes this check keep up: a fourth profile that aliased an existing media
    /// type would be in `ALL` the moment it existed and would fail here, where a
    /// hand-written array of the original three would have gone on comparing only
    /// those three and passing.
    #[test]
    fn no_two_profiles_share_a_media_type() {
        let all = TokenTyp::ALL;
        for (index, left) in all.iter().enumerate() {
            for right in &all[index + 1..] {
                assert!(
                    !left.matches(Some(right.media_type())),
                    "{left:?} accepts {right:?}'s media type"
                );
            }
        }
    }

    #[test]
    fn a_media_type_matches_case_insensitively_and_with_the_application_prefix() {
        for spelling in [
            "at+jwt",
            "AT+JWT",
            "At+Jwt",
            "application/at+jwt",
            "APPLICATION/at+jwt",
        ] {
            assert!(
                TokenTyp::AccessToken.matches(Some(spelling)),
                "{spelling} should name an access token"
            );
        }
        // The prefix is stripped ONCE and only as a prefix: a media type that
        // merely CONTAINS the word, or doubles the prefix, is not the access token.
        for spelling in [
            "application/application/at+jwt",
            "at+jwt+extra",
            "xat+jwt",
            "",
            " at+jwt",
            "application/",
        ] {
            assert!(
                !TokenTyp::AccessToken.matches(Some(spelling)),
                "{spelling} should not name an access token"
            );
        }
    }

    /// A multi-byte leading character must not panic the prefix strip. `get(..n)`
    /// on a non-boundary index yields `None`, which falls through to the whole
    /// candidate; the assertion here is that the call returns at all.
    #[test]
    fn a_multibyte_typ_is_rejected_without_panicking() {
        assert!(!TokenTyp::AccessToken.matches(Some("\u{e9}pplication/at+jwt")));
        assert!(!TokenTyp::IdToken.matches(Some("\u{1f600}")));
    }

    #[test]
    fn an_absent_typ_never_satisfies_a_required_profile() {
        for typ in TokenTyp::ALL {
            assert!(
                !ExpectedTyp::Required(typ).accepts(None),
                "{typ:?} must not accept a header with no typ"
            );
        }
    }

    #[test]
    fn the_foreign_issuer_expectation_accepts_any_media_type_including_none() {
        for candidate in [None, Some("JWT"), Some("at+jwt"), Some("anything")] {
            assert!(
                ExpectedTyp::ForeignIssuer.accepts(candidate),
                "{candidate:?}"
            );
        }
    }

    #[test]
    fn ed25519_is_a_fully_specified_alias_of_eddsa() {
        assert_eq!(
            JwsAlgorithm::from_jose_name("Ed25519"),
            Some(JwsAlgorithm::EdDsa)
        );
        assert_eq!(
            JwsAlgorithm::from_jose_name("EdDSA"),
            Some(JwsAlgorithm::EdDsa)
        );
    }

    #[test]
    fn hmac_none_and_unsupported_names_are_never_parsed() {
        for name in [
            "HS256", "HS384", "HS512", "none", "None", "", " ", "Ed448", "ES512", "ed25519",
        ] {
            assert!(JwsAlgorithm::from_jose_name(name).is_none(), "{name}");
        }
    }

    #[test]
    fn fully_specified_name_only_rewrites_eddsa() {
        assert_eq!(JwsAlgorithm::EdDsa.fully_specified_name(), "Ed25519");
        assert_eq!(JwsAlgorithm::EdDsa.as_jose_name(), "EdDSA");
        for alg in [
            JwsAlgorithm::Es256,
            JwsAlgorithm::Es384,
            JwsAlgorithm::Rs256,
            JwsAlgorithm::Ps512,
        ] {
            assert_eq!(alg.fully_specified_name(), alg.as_jose_name());
        }
    }
}
