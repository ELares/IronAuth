// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client authentication for the token endpoint, and the reusable
//! [`authenticate_client`] seam every credential-consuming endpoint shares (issues
//! #20 and #25).
//!
//! Five `token_endpoint_auth_method`s are represented. Three are secret based and
//! predate this module's #25 growth: `client_secret_basic`, `client_secret_post`,
//! and `none` (a public, PKCE-only client). Two are JWT-assertion methods (#25):
//! `private_key_jwt` (RFC 7523, an assertion signed with the client's asymmetric
//! key, verified against keys resolved from its registered `jwks`/`jwks_uri`) and
//! `client_secret_jwt` (OIDC Core 9, an assertion HMAC'd with the shared secret).
//! A client is registered for EXACTLY ONE method, and the endpoint enforces the
//! registered method: a client that presents any other method fails with the
//! spec-exact, opaque `invalid_client` (RFC 6749 5.2), never a different error and
//! never an oracle for which check failed.
//!
//! # `client_secret_jwt` and the hashed-secret posture (the #25 tradeoff)
//!
//! Verifying a `client_secret_jwt` assertion requires the RAW client secret as the
//! HMAC key. IronAuth stores a client secret ONLY as its SHA-256 hash, which is
//! irreversible: the plaintext is unrecoverable after creation (see
//! [`hash_secret`]). Supporting `client_secret_jwt` would therefore require storing
//! a RETRIEVABLE secret (plaintext, or encrypted under a server-managed key), which
//! is a broader key-management change and a real weakening of the "a database dump
//! contains nothing replayable" posture the rest of the provider is built around
//! (the digest-only opaque tokens, the hashed client secrets, the hashed
//! management keys). Rather than weaken that posture, `client_secret_jwt` is a
//! DOCUMENTED, CORRECTLY-ERRORING path: a client registered for it authenticates
//! nothing, failing closed with the uniform `invalid_client` and a recorded
//! diagnostic ([`ClientAuthDiagnosticReason::ClientSecretJwtUnsupported`]). It is
//! deliberately NOT advertised in discovery ([`ClientAuthMethod::ALL`]).
//! `private_key_jwt`, which stores only PUBLIC keys, is fully implemented and is
//! the recommended asymmetric method (and the FAPI 2.0 choice). Enabling
//! `client_secret_jwt` later means adding retrievable secret storage behind an
//! at-rest-encryption seam; the verification wiring here is otherwise ready.
//!
//! # The `client_secret_basic` encoding landmine
//!
//! RFC 6749 2.3.1 requires the client to `application/x-www-form-urlencode` the
//! client id and secret BEFORE base64-encoding them into the `Authorization:
//! Basic` value, and the server to form-urldecode both halves after base64
//! decoding. Real client libraries disagree: some encode, some send the raw
//! bytes, and a strict server rejects a secret with a character that changes
//! under form-encoding. IronAuth sidesteps the ambiguity by GENERATING URL-safe
//! secrets ([`generate_secret`]): a 64-byte base64url value contains only
//! `A-Za-z0-9-_`, none of which form-encoding alters, so the raw and the
//! form-encoded interpretations are byte-identical. This module is nonetheless
//! spec-correct: it form-urldecodes both halves after base64 decoding, so a client
//! that DID encode still authenticates. The behavior is pinned by tests.
//!
//! # Secret storage
//!
//! A generated secret is shown once at creation and stored only as its SHA-256
//! hash. A 64-byte (512-bit) uniformly random secret carries far more entropy
//! than any password, so it does not need a slow password KDF: a single
//! cryptographic hash is sound and is exactly what the management-key credential
//! path uses. The plaintext is unrecoverable after creation.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ironauth_env::Env;
use ironauth_jose::{JwsAlgorithm, RejectReason, TrustedKey, VerificationPolicy, verify};
use ironauth_store::{
    ClientAuthDiagnosticReason, ClientAuthRecord, ClientId, JtiOutcome, NewClientAuthDiagnostic,
    Scope, StoreError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::state::OidcState;

/// Bytes of entropy in a generated client secret. 64 bytes is 512 bits, well
/// beyond guessing, and base64url encodes to a URL-safe string so the two Basic
/// interpretations coincide.
const SECRET_BYTES: usize = 64;

/// The RFC 7521 `client_assertion_type` a JWT-bearer client assertion MUST carry.
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The asymmetric JWS algorithms a `private_key_jwt` assertion may be signed with
/// when the client registered no explicit `token_endpoint_auth_signing_alg`. This
/// is exactly the JOSE verify matrix, which EXCLUDES ES512 by construction (it is
/// unrepresentable in [`JwsAlgorithm`]), so an ES512 assertion is always rejected.
const ASYMMETRIC_ALGS: &[JwsAlgorithm] = &[
    JwsAlgorithm::EdDsa,
    JwsAlgorithm::Es256,
    JwsAlgorithm::Es384,
    JwsAlgorithm::Rs256,
    JwsAlgorithm::Rs384,
    JwsAlgorithm::Rs512,
    JwsAlgorithm::Ps256,
    JwsAlgorithm::Ps384,
    JwsAlgorithm::Ps512,
];

/// The asymmetric JWS algorithms the token endpoint accepts for a `private_key_jwt`
/// client assertion, as their JOSE names, for discovery's
/// `token_endpoint_auth_signing_alg_values_supported` (OIDC Discovery 1.0 section 3,
/// which REQUIRES this field whenever `private_key_jwt`/`client_secret_jwt` is
/// advertised). This is exactly [`ASYMMETRIC_ALGS`] (the JOSE verify matrix used to
/// validate assertions), so discovery advertises precisely what the token endpoint
/// will verify. `none` is excluded (it is not asymmetric) and ES512 is excluded by
/// construction (unrepresentable in [`JwsAlgorithm`]).
#[must_use]
pub fn assertion_signing_alg_values() -> Vec<String> {
    ASYMMETRIC_ALGS
        .iter()
        .map(|alg| alg.as_jose_name().to_owned())
        .collect()
}

/// A client's token-endpoint authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthMethod {
    /// `client_secret_basic`: the secret arrives in the `Authorization: Basic`
    /// header (RFC 6749 2.3.1).
    Basic,
    /// `client_secret_post`: the secret arrives as a `client_secret` form field.
    Post,
    /// `private_key_jwt`: an assertion signed with the client's asymmetric key,
    /// verified against its registered `jwks`/`jwks_uri` (RFC 7523, issue #25).
    PrivateKeyJwt,
    /// `client_secret_jwt`: an assertion HMAC'd with the shared secret (OIDC Core
    /// 9). Recognized but a documented, correctly-erroring path (see the module
    /// docs): IronAuth stores no retrievable secret to key the HMAC, so a client
    /// registered for it fails closed.
    ClientSecretJwt,
    /// `none`: a public client (PKCE only), no secret.
    None,
}

impl ClientAuthMethod {
    /// Every token-endpoint authentication method this build ADVERTISES, in the
    /// order discovery lists them (issue #18 sources
    /// `token_endpoint_auth_methods_supported` from here). `client_secret_jwt` is
    /// deliberately ABSENT: it is recognized but not offered (see the module docs),
    /// so discovery never advertises a method IronAuth will refuse.
    pub const ALL: &'static [ClientAuthMethod] = &[
        ClientAuthMethod::Basic,
        ClientAuthMethod::Post,
        ClientAuthMethod::PrivateKeyJwt,
        ClientAuthMethod::None,
    ];

    /// The wire / stored string for this method.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ClientAuthMethod::Basic => "client_secret_basic",
            ClientAuthMethod::Post => "client_secret_post",
            ClientAuthMethod::PrivateKeyJwt => "private_key_jwt",
            ClientAuthMethod::ClientSecretJwt => "client_secret_jwt",
            ClientAuthMethod::None => "none",
        }
    }

    /// Parse a stored/registered method string. An unknown value returns `None`,
    /// and the token endpoint then fails closed on an unrecognized registered
    /// method rather than guessing.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "client_secret_basic" => Some(ClientAuthMethod::Basic),
            "client_secret_post" => Some(ClientAuthMethod::Post),
            "private_key_jwt" => Some(ClientAuthMethod::PrivateKeyJwt),
            "client_secret_jwt" => Some(ClientAuthMethod::ClientSecretJwt),
            "none" => Some(ClientAuthMethod::None),
            _ => None,
        }
    }
}

/// Generate a fresh client secret: 64 random bytes from the entropy seam, encoded
/// URL-safe base64 with no padding. URL-safe so the `client_secret_basic`
/// form-encoded and raw interpretations coincide.
#[must_use]
pub fn generate_secret(env: &Env) -> String {
    let mut bytes = [0_u8; SECRET_BYTES];
    env.entropy().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The SHA-256 hex of a secret, the stored form. A high-entropy random secret
/// does not need a slow KDF; a single cryptographic hash is sound.
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The credentials a token (or introspection/revocation) request presented for
/// client authentication, after parsing the `Authorization` header and the form.
#[derive(Debug, Clone)]
pub enum PresentedClientAuth {
    /// A secret-based or public credential: `client_secret_basic`,
    /// `client_secret_post`, or `none`.
    Secret {
        /// The client identifier the request authenticated as.
        client_id: String,
        /// Which secret method the credentials arrived by (Basic/Post/None).
        method: ClientAuthMethod,
        /// The presented secret, if any (absent for a public client).
        secret: Option<String>,
    },
    /// A JWT client assertion (`private_key_jwt` / `client_secret_jwt`).
    Assertion {
        /// The client identifier (from a `client_id` form field, or the
        /// assertion's `sub`); the assertion verification binds it cryptographically.
        client_id: String,
        /// The compact JWS assertion.
        assertion: String,
    },
}

impl PresentedClientAuth {
    /// The client identifier the request claims to be.
    #[must_use]
    pub fn client_id(&self) -> &str {
        match self {
            PresentedClientAuth::Secret { client_id, .. }
            | PresentedClientAuth::Assertion { client_id, .. } => client_id,
        }
    }

    /// Whether the request attempted authentication via the `Authorization` header
    /// (a Basic attempt), which mandates a 401 with `WWW-Authenticate` on failure.
    #[must_use]
    pub fn via_basic(&self) -> bool {
        matches!(
            self,
            PresentedClientAuth::Secret {
                method: ClientAuthMethod::Basic,
                ..
            }
        )
    }
}

/// Why client authentication could not even be parsed into a coherent attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthParseError {
    /// More than one authentication method was presented (for example a Basic
    /// header and a `client_secret` field, or a secret and a `client_assertion`),
    /// which RFC 6749 2.3 forbids.
    MultipleMethods,
    /// The `Authorization` header was present but not a decodable Basic credential.
    MalformedBasic,
    /// No client identifier was presented at all.
    MissingClientId,
    /// A Basic userid and a form `client_id` were both present but disagreed, or a
    /// form `client_id` disagreed with the assertion's `sub`.
    ClientIdMismatch,
    /// A `client_assertion` was presented without the RFC 7521 `client_assertion_type`,
    /// or with an unsupported one.
    UnsupportedAssertionType,
    /// A `client_assertion_type` was presented without a `client_assertion`.
    MissingAssertion,
}

/// The outcome of the reusable client-authentication seam: the authenticated
/// client on success.
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    /// The authenticated client identifier (the caller re-checks it against any
    /// binding, for example the authorization code's `client_id`).
    pub client_id: String,
}

/// Why the reusable client-authentication seam rejected a request. The caller maps
/// it to its endpoint's error object (at the token endpoint: `invalid_request` or
/// the opaque `invalid_client`).
#[derive(Debug, Clone)]
pub enum ClientAuthError {
    /// The request could not be parsed into a coherent authentication attempt (a
    /// request problem, `invalid_request`). Carries a fixed, generic message.
    InvalidRequest(&'static str),
    /// Authentication failed: an unknown client, a credential that did not satisfy
    /// the registered method, a mismatched method, an invalid or replayed
    /// assertion, or the unsupported `client_secret_jwt`. The spec-exact,
    /// OPAQUE `invalid_client`; `via_basic` drives the 401 `WWW-Authenticate`.
    InvalidClient {
        /// Whether the client attempted Basic authentication.
        via_basic: bool,
    },
}

/// The raw request inputs the reusable seam authenticates from. The token endpoint
/// fills these from the `Authorization` header and the form body; the future
/// introspection and revocation endpoints (#22) fill them the same way, so the
/// enforcement is IDENTICAL across all three.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientAuthInputs<'a> {
    /// The `Authorization` header value, if present.
    pub authorization: Option<&'a str>,
    /// The `client_id` form field, if present.
    pub client_id: Option<&'a str>,
    /// The `client_secret` form field, if present.
    pub client_secret: Option<&'a str>,
    /// The `client_assertion` form field, if present.
    pub client_assertion: Option<&'a str>,
    /// The `client_assertion_type` form field, if present.
    pub client_assertion_type: Option<&'a str>,
}

/// Authenticate a client from the presented request inputs (issues #20 and #25).
///
/// This is the ONE reusable client-authentication seam. The token endpoint uses it
/// now; the introspection and revocation endpoints (#22) will call it with the
/// same [`ClientAuthInputs`], so every credential-consuming endpoint enforces the
/// client's single registered `token_endpoint_auth_method` identically, returns
/// the same opaque `invalid_client`, and records the same out-of-band diagnostic.
///
/// It parses the credentials, resolves the client's registered method within
/// `scope`, and verifies the presented credentials against that method: a secret
/// against its stored hash, or a JWT assertion against the client's registered keys
/// (with `iss`/`sub` == `client_id`, the audience policy, `exp` within skew, and a
/// single-use `jti`). Every FAILURE returns the opaque [`ClientAuthError`] and
/// records a rich, structured diagnostic out of band (never on the wire).
///
/// # Errors
///
/// [`ClientAuthError::InvalidRequest`] if the credentials cannot be parsed into one
/// coherent attempt; [`ClientAuthError::InvalidClient`] for every authentication
/// failure (unknown client, wrong or replayed credential, mismatched or
/// unsupported method).
pub async fn authenticate_client(
    state: &OidcState,
    scope: Scope,
    inputs: ClientAuthInputs<'_>,
) -> Result<AuthenticatedClient, ClientAuthError> {
    let presented = match parse_presented(
        inputs.authorization,
        inputs.client_id,
        inputs.client_secret,
        inputs.client_assertion,
        inputs.client_assertion_type,
    ) {
        Ok(presented) => presented,
        Err(error) => {
            // A parse failure is recorded out of band too, so the M9 view sees a
            // malformed/dual-method attempt. The client id is best effort.
            let (alg, kid) = inputs
                .client_assertion
                .map_or((None, None), peek_assertion_header);
            record_diagnostic(
                state,
                scope,
                &best_effort_client_id(&inputs).unwrap_or_else(|| "unknown".to_owned()),
                "unknown",
                ClientAuthDiagnosticReason::Unparsable,
                kid.as_deref(),
                alg.as_deref(),
            )
            .await;
            return Err(map_parse_error(error));
        }
    };

    authenticate_presented(state, scope, &presented).await
}

/// The post-parse half of [`authenticate_client`]: resolve the client and verify
/// the presented credentials against its registered method.
async fn authenticate_presented(
    state: &OidcState,
    scope: Scope,
    presented: &PresentedClientAuth,
) -> Result<AuthenticatedClient, ClientAuthError> {
    let via_basic = presented.via_basic();
    let client_id_str = presented.client_id().to_owned();
    let (assertion_alg, assertion_kid) = match presented {
        PresentedClientAuth::Assertion { assertion, .. } => peek_assertion_header(assertion),
        PresentedClientAuth::Secret { .. } => (None, None),
    };

    // A helper that records the diagnostic and returns the opaque invalid_client.
    // Confining the borrow of `presented`/`client_id_str` to owned values here
    // keeps this a plain async closure over Copy-ish data.
    macro_rules! fail {
        ($method:expr, $reason:expr) => {{
            record_diagnostic(
                state,
                scope,
                &client_id_str,
                $method,
                $reason,
                assertion_kid.as_deref(),
                assertion_alg.as_deref(),
            )
            .await;
            return Err(ClientAuthError::InvalidClient { via_basic });
        }};
    }

    // Resolve the client's registered auth record within scope. A malformed or
    // unknown client is the uniform invalid_client (never an existence oracle).
    let Ok(client_id) = ClientId::parse_in_scope(&client_id_str, &scope) else {
        fail!("unknown", ClientAuthDiagnosticReason::UnknownClient);
    };
    let record = match state
        .store()
        .scoped(scope)
        .clients()
        .auth_record(&client_id)
        .await
    {
        Ok(record) => record,
        Err(StoreError::NotFound) => {
            fail!("unknown", ClientAuthDiagnosticReason::UnknownClient);
        }
        // A transient store fault is not an authentication decision. Surface it as
        // invalid_client (fail closed) without a misleading diagnostic reason.
        Err(_) => return Err(ClientAuthError::InvalidClient { via_basic }),
    };
    let method_str = record.auth_method.clone();

    // Fail closed on an unrecognized registered method rather than guessing.
    let Some(registered) = ClientAuthMethod::parse(&record.auth_method) else {
        fail!(&method_str, ClientAuthDiagnosticReason::MethodMismatch);
    };

    match (registered, presented) {
        // Secret / public registered method with a secret / public presentation.
        (
            ClientAuthMethod::Basic | ClientAuthMethod::Post | ClientAuthMethod::None,
            PresentedClientAuth::Secret { method, secret, .. },
        ) => match authenticate_secret(&record, registered, *method, secret.as_deref()) {
            Ok(()) => Ok(AuthenticatedClient {
                client_id: client_id_str,
            }),
            Err(SecretAuthError::MethodMismatch) => {
                fail!(&method_str, ClientAuthDiagnosticReason::MethodMismatch)
            }
            Err(SecretAuthError::BadSecret) => {
                fail!(&method_str, ClientAuthDiagnosticReason::BadSecret)
            }
        },

        // private_key_jwt registered, an assertion presented: verify it.
        (ClientAuthMethod::PrivateKeyJwt, PresentedClientAuth::Assertion { assertion, .. }) => {
            match verify_private_key_assertion(state, scope, &client_id_str, &record, assertion)
                .await
            {
                Ok(()) => Ok(AuthenticatedClient {
                    client_id: client_id_str,
                }),
                Err(AssertionAuthError::Invalid) => {
                    fail!(&method_str, ClientAuthDiagnosticReason::AssertionInvalid)
                }
                Err(AssertionAuthError::Replayed) => {
                    fail!(&method_str, ClientAuthDiagnosticReason::ReplayedJti)
                }
            }
        }

        // client_secret_jwt registered: the documented, correctly-erroring path.
        // IronAuth stores no retrievable secret to key the HMAC (see module docs),
        // so it fails closed regardless of what was presented.
        (ClientAuthMethod::ClientSecretJwt, _) => {
            fail!(
                &method_str,
                ClientAuthDiagnosticReason::ClientSecretJwtUnsupported
            )
        }

        // Every remaining combination is a method mismatch (a secret registered
        // client presenting an assertion, or an assertion-registered client
        // presenting a secret).
        _ => fail!(&method_str, ClientAuthDiagnosticReason::MethodMismatch),
    }
}

/// Parse the presented client credentials from the `Authorization` header and the
/// form fields, enforcing that at most one authentication method is used.
///
/// # Errors
///
/// [`ClientAuthParseError`] if more than one method is presented, the Basic header
/// is malformed, no client id is present, a Basic userid / form `client_id` /
/// assertion `sub` disagree, or a `client_assertion`/`client_assertion_type`
/// pairing is incomplete.
pub fn parse_presented(
    authorization: Option<&str>,
    body_client_id: Option<&str>,
    body_client_secret: Option<&str>,
    body_client_assertion: Option<&str>,
    body_client_assertion_type: Option<&str>,
) -> Result<PresentedClientAuth, ClientAuthParseError> {
    let basic = match authorization {
        Some(value) if is_basic(value) => {
            Some(parse_basic(value).ok_or(ClientAuthParseError::MalformedBasic)?)
        }
        // A non-Basic Authorization scheme is ignored: mTLS client auth (M16) and
        // bearer are not client-authentication inputs here.
        _ => None,
    };
    let body_id = trimmed(body_client_id);
    let body_secret = trimmed(body_client_secret);
    let assertion = trimmed(body_client_assertion);
    let assertion_type = trimmed(body_client_assertion_type);

    // The JWT-assertion path (#25): a `client_assertion` is present. It is
    // mutually exclusive with a Basic header and with a `client_secret` field.
    if let Some(assertion) = assertion {
        if basic.is_some() || body_secret.is_some() {
            return Err(ClientAuthParseError::MultipleMethods);
        }
        if assertion_type != Some(JWT_BEARER_ASSERTION_TYPE) {
            return Err(ClientAuthParseError::UnsupportedAssertionType);
        }
        // The client id is the form `client_id` if present, else the assertion's
        // `sub` (which the verification then binds cryptographically to the key).
        let sub = assertion_subject(assertion);
        let client_id = match (body_id, sub.as_deref()) {
            (Some(form), Some(sub)) if form != sub => {
                return Err(ClientAuthParseError::ClientIdMismatch);
            }
            (Some(form), _) => form.to_owned(),
            (None, Some(sub)) => sub.to_owned(),
            (None, None) => return Err(ClientAuthParseError::MissingClientId),
        };
        return Ok(PresentedClientAuth::Assertion {
            client_id,
            assertion: assertion.to_owned(),
        });
    }
    // A `client_assertion_type` without an assertion is an incomplete attempt.
    if assertion_type.is_some() {
        return Err(ClientAuthParseError::MissingAssertion);
    }

    // The secret / public path (#20).
    if let Some((basic_id, basic_secret)) = basic {
        // A body client_secret alongside Basic is two methods: forbidden.
        if body_secret.is_some() {
            return Err(ClientAuthParseError::MultipleMethods);
        }
        // A body client_id alongside Basic is allowed only if it agrees.
        if let Some(body_id) = body_id {
            if body_id != basic_id {
                return Err(ClientAuthParseError::ClientIdMismatch);
            }
        }
        return Ok(PresentedClientAuth::Secret {
            client_id: basic_id,
            method: ClientAuthMethod::Basic,
            secret: Some(basic_secret),
        });
    }

    let client_id = body_id
        .ok_or(ClientAuthParseError::MissingClientId)?
        .to_owned();
    match body_secret {
        Some(secret) => Ok(PresentedClientAuth::Secret {
            client_id,
            method: ClientAuthMethod::Post,
            secret: Some(secret.to_owned()),
        }),
        None => Ok(PresentedClientAuth::Secret {
            client_id,
            method: ClientAuthMethod::None,
            secret: None,
        }),
    }
}

/// Why a secret-based authentication failed (for the out-of-band diagnostic).
enum SecretAuthError {
    /// The presented method did not match the client's registered secret method.
    MethodMismatch,
    /// The presented secret did not match the stored hash (or a required secret
    /// was absent / not stored).
    BadSecret,
}

/// Verify a secret-based (or public) presentation against the client's registered
/// method. Only called when the registered method is Basic/Post/None.
fn authenticate_secret(
    record: &ClientAuthRecord,
    registered: ClientAuthMethod,
    presented_method: ClientAuthMethod,
    presented_secret: Option<&str>,
) -> Result<(), SecretAuthError> {
    if presented_method != registered {
        return Err(SecretAuthError::MethodMismatch);
    }
    match registered {
        ClientAuthMethod::None => {
            // Public client: no secret must be presented (guaranteed by the method
            // match above, but assert defensively).
            if presented_secret.is_some() {
                return Err(SecretAuthError::MethodMismatch);
            }
            Ok(())
        }
        ClientAuthMethod::Basic | ClientAuthMethod::Post => {
            let stored = record
                .secret_hash
                .as_deref()
                .ok_or(SecretAuthError::BadSecret)?;
            let presented = presented_secret.ok_or(SecretAuthError::BadSecret)?;
            let presented_hash = hash_secret(presented);
            if constant_time_eq(presented_hash.as_bytes(), stored.as_bytes()) {
                Ok(())
            } else {
                Err(SecretAuthError::BadSecret)
            }
        }
        // Unreachable: the caller only routes secret methods here.
        ClientAuthMethod::PrivateKeyJwt | ClientAuthMethod::ClientSecretJwt => {
            Err(SecretAuthError::MethodMismatch)
        }
    }
}

/// Why a `private_key_jwt` assertion failed (for the out-of-band diagnostic).
enum AssertionAuthError {
    /// The assertion did not verify (signature, `iss`/`sub`/`aud`, `exp`, algorithm,
    /// keys, or a missing `jti`).
    Invalid,
    /// The assertion's `jti` was replayed (already used).
    Replayed,
}

/// Verify a `private_key_jwt` assertion for `client_id` and enforce single use.
async fn verify_private_key_assertion(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    record: &ClientAuthRecord,
    assertion: &str,
) -> Result<(), AssertionAuthError> {
    // Resolve the client's verification keys (inline `jwks` or fetched `jwks_uri`).
    let keys = resolve_client_keys(state, record).await;
    let algorithms = allowed_assertion_algs(record);
    let audiences = state.client_assertion_audiences(&scope);
    let skew = state.client_assertion_skew();

    let verified = verify_assertion_claims(
        assertion,
        &keys,
        &algorithms,
        client_id,
        &audiences,
        skew,
        state.env().clock(),
    )
    .ok_or(AssertionAuthError::Invalid)?;

    // A jti is REQUIRED for single use (OIDC Core 9): without it the assertion
    // could be replayed, so an assertion that omits it is rejected.
    let jti = verified.jti.ok_or(AssertionAuthError::Invalid)?;
    // Retain the jti until its assertion can no longer be accepted, PLUS one whole
    // second. Acceptance (enforce_exp) floors `now` to whole seconds and rejects only
    // once `now_secs > exp + skew`, so the assertion stays acceptable for the ENTIRE
    // wall-clock second [exp+skew, exp+skew+1). The store prunes at MICROSECOND
    // precision, so retaining only to `exp + skew` would drop the row partway through
    // that final acceptable second and re-admit the single-use assertion as fresh.
    // The extra `+ 1s` makes retention strictly OUTLAST acceptance, closing the window.
    let skew_secs = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
    let expires_secs = verified.exp.saturating_add(skew_secs).saturating_add(1);
    let expires_micros = expires_secs.saturating_mul(1_000_000);

    match state
        .store()
        .scoped(scope)
        .client_assertion_jtis()
        .record(state.env(), client_id, &jti, expires_micros)
        .await
    {
        Ok(JtiOutcome::Recorded) => Ok(()),
        Ok(JtiOutcome::Replayed) => Err(AssertionAuthError::Replayed),
        // A store fault recording the jti fails closed: we will not let an
        // assertion through without recording its single use.
        Err(_) => Err(AssertionAuthError::Invalid),
    }
}

/// A verified `private_key_jwt` assertion's replay-relevant fields.
struct VerifiedAssertion {
    /// The `jti`, if the assertion carried one.
    jti: Option<String>,
    /// The `exp` in seconds since the epoch (always present: `verify` requires it).
    exp: i64,
}

/// Verify an assertion's signature and the RFC 7523 claim rules through the ONE
/// hardened JOSE [`verify`] path, trying each acceptable audience in turn.
///
/// The `iss` is enforced to equal `client_id` by the policy; the `sub` is checked
/// to equal `client_id` here; `exp`/`nbf`/`iat` are enforced within `skew`; the
/// algorithm must be in `algorithms` (which excludes ES512). Returns `None` on any
/// failure (uniform), or the verified replay fields on success. Pure and
/// synchronous: the key resolution and the jti recording are the caller's async
/// concerns.
fn verify_assertion_claims(
    assertion: &str,
    keys: &[TrustedKey],
    algorithms: &[JwsAlgorithm],
    client_id: &str,
    audiences: &[String],
    skew: Duration,
    clock: &dyn ironauth_env::Clock,
) -> Option<VerifiedAssertion> {
    if keys.is_empty() || algorithms.is_empty() || audiences.is_empty() {
        return None;
    }
    for audience in audiences {
        let Ok(policy) = VerificationPolicy::new(
            algorithms.to_vec(),
            keys.to_vec(),
            client_id,
            audience.clone(),
        ) else {
            return None;
        };
        let policy = policy.with_skew(skew);
        match verify(assertion, &policy, clock) {
            Ok(verified) => {
                // RFC 7523: sub MUST equal the client id (iss already did, via the
                // policy). An assertion whose sub is another value is rejected.
                if verified.claims().subject() != Some(client_id) {
                    return None;
                }
                let exp = verified.claims().expiration()?;
                // An empty or whitespace-only jti is no jti (RFC 7523 intends a real
                // token identifier): treat it as absent so the single-use rule below
                // rejects it, rather than recording a blank single-use key.
                let jti = verified
                    .claims()
                    .get("jti")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|jti| !jti.is_empty())
                    .map(str::to_owned);
                return Some(VerifiedAssertion { jti, exp });
            }
            // An audience mismatch under one acceptable audience just means try the
            // next; any other failure is a hard, uniform rejection.
            Err(error) if error.reason() == RejectReason::AudienceMismatch => {}
            Err(_) => return None,
        }
    }
    None
}

/// The JWS algorithms a client's `private_key_jwt` assertion may be signed with:
/// exactly its registered `token_endpoint_auth_signing_alg` when set (a per-client
/// allowlist), otherwise the supported asymmetric set. A pinned algorithm this
/// core does not implement (for example ES512) yields an EMPTY allowlist, so the
/// assertion is rejected.
fn allowed_assertion_algs(record: &ClientAuthRecord) -> Vec<JwsAlgorithm> {
    match record.token_endpoint_auth_signing_alg.as_deref() {
        Some(name) => JwsAlgorithm::from_jose_name(name)
            .filter(|alg| ASYMMETRIC_ALGS.contains(alg))
            .into_iter()
            .collect(),
        None => ASYMMETRIC_ALGS.to_vec(),
    }
}

/// Resolve a `private_key_jwt` client's verification keys: inline `jwks` if
/// registered, otherwise its `jwks_uri` fetched (and cached) through the hardened
/// fetcher. Returns an empty set (fail closed) when neither is available or the
/// resolution yields no usable key.
async fn resolve_client_keys(state: &OidcState, record: &ClientAuthRecord) -> Vec<TrustedKey> {
    if let Some(inline) = &record.jwks {
        return ironauth_jose::trusted_keys_from_jwks(inline.as_bytes());
    }
    if let Some(uri) = &record.jwks_uri {
        if let Some(resolver) = state.client_key_resolver() {
            return resolver.resolve(state.now(), uri).await;
        }
    }
    Vec::new()
}

/// Record a client-authentication failure diagnostic out of band, best effort. A
/// failure to record is logged and swallowed: the diagnostic is a side channel for
/// operators, never a gate on the authentication decision, and must not turn a
/// clean `invalid_client` into a `server_error`.
async fn record_diagnostic(
    state: &OidcState,
    scope: Scope,
    client_id: &str,
    auth_method: &str,
    reason: ClientAuthDiagnosticReason,
    key_id: Option<&str>,
    signing_alg: Option<&str>,
) {
    if let Err(error) = state
        .store()
        .scoped(scope)
        .client_auth_diagnostics()
        .record(
            state.env(),
            NewClientAuthDiagnostic {
                client_id,
                auth_method,
                reason,
                key_id,
                signing_alg,
            },
        )
        .await
    {
        tracing::warn!(%error, "could not record a client-auth diagnostic");
    }
}

/// Map a parse error to the seam's error: a malformed Basic credential is an
/// authentication failure via Basic (401 + `WWW-Authenticate`); the rest are
/// request problems, with fixed generic messages that never echo input.
fn map_parse_error(error: ClientAuthParseError) -> ClientAuthError {
    match error {
        ClientAuthParseError::MalformedBasic => ClientAuthError::InvalidClient { via_basic: true },
        ClientAuthParseError::MultipleMethods => {
            ClientAuthError::InvalidRequest("more than one client authentication method")
        }
        ClientAuthParseError::MissingClientId => {
            ClientAuthError::InvalidRequest("client_id is required")
        }
        ClientAuthParseError::ClientIdMismatch => {
            ClientAuthError::InvalidRequest("conflicting client_id")
        }
        ClientAuthParseError::UnsupportedAssertionType => {
            ClientAuthError::InvalidRequest("unsupported client_assertion_type")
        }
        ClientAuthParseError::MissingAssertion => {
            ClientAuthError::InvalidRequest("client_assertion is required")
        }
    }
}

/// The best-effort client id for a diagnostic on a parse failure: a form
/// `client_id`, else a Basic userid, else the assertion's `sub`.
fn best_effort_client_id(inputs: &ClientAuthInputs<'_>) -> Option<String> {
    if let Some(id) = trimmed(inputs.client_id) {
        return Some(id.to_owned());
    }
    if let Some(auth) = inputs.authorization {
        if is_basic(auth) {
            if let Some((id, _)) = parse_basic(auth) {
                return Some(id);
            }
        }
    }
    inputs.client_assertion.and_then(assertion_subject)
}

/// The `sub` claim of a compact JWS assertion's (unverified) payload, for deriving
/// the client id to LOOK UP. The verification then binds it cryptographically, so
/// reading it before verification introduces no trust.
fn assertion_subject(assertion: &str) -> Option<String> {
    let payload = assertion.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value.get("sub").and_then(Value::as_str).map(str::to_owned)
}

/// The `(alg, kid)` of a compact JWS assertion's (unverified) protected header,
/// for the out-of-band diagnostic only (never for trust).
fn peek_assertion_header(assertion: &str) -> (Option<String>, Option<String>) {
    let Some(header_b64) = assertion.split('.').next() else {
        return (None, None);
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(header_b64) else {
        return (None, None);
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return (None, None);
    };
    let alg = value.get("alg").and_then(Value::as_str).map(str::to_owned);
    let kid = value.get("kid").and_then(Value::as_str).map(str::to_owned);
    (alg, kid)
}

/// Trim an optional form value and drop it if empty.
fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

/// Whether `value` is an `Authorization: Basic` header (case-insensitive scheme).
fn is_basic(value: &str) -> bool {
    // `get(..5)` (not `value[..5]`) so a non-ASCII byte straddling index 5 returns
    // None instead of panicking on a char boundary; the len check keeps `[5]` valid.
    value.len() >= 6
        && value
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("basic"))
        && value.as_bytes()[5] == b' '
}

/// Parse an `Authorization: Basic` value into its (`client_id`, secret), applying
/// RFC 6749 2.3.1: base64-decode, split on the FIRST colon, then form-urldecode
/// each half. Accepts both padded and unpadded base64 for robustness.
fn parse_basic(value: &str) -> Option<(String, String)> {
    let encoded = value.get(6..)?.trim();
    let decoded = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((form_urldecode(id), form_urldecode(secret)))
}

/// Decode an `application/x-www-form-urlencoded` component: `+` becomes a space
/// and `%XX` becomes the byte. A malformed escape (`%` not followed by two ASCII hex
/// digits, or truncated at the end) is passed through verbatim. IronAuth's own
/// URL-safe credentials contain neither `+` nor `%`, so this is a no-op for them; it
/// exists so a client that DID form-encode still authenticates (RFC 6749 2.3.1).
///
/// Decoding operates on the BYTES: a `%` followed by a multi-byte UTF-8 character
/// (for example the euro sign in `%<char>`) must never be string-sliced at
/// `value[i+1..i+3]`, which would land inside a char boundary and PANIC on an
/// unauthenticated request. The two escape digits are hex-decoded directly from the
/// bytes and a non-hex pair is rejected (passed through), so no slice ever straddles
/// a char boundary.
fn form_urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 3 <= bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    // Not a valid `%XX`: pass the `%` through and continue past it.
                    out.push(b'%');
                    i += 1;
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The value of a single ASCII hex digit (`0-9`, `a-f`, `A-F`), or `None` for any
/// other byte. Operates on a byte so a `%XX` escape is decoded without slicing the
/// input string at a non-char-boundary.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Compare two byte strings in time independent of where they first differ. A
/// length difference short-circuits to `false`; the stored and presented values
/// here are both fixed-length SHA-256 hex, so equal-length is the normal path.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;

    /// Base64 (standard, padded) of `client_id:client_secret`, the raw form.
    fn basic_header(client_id: &str, secret: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
    }

    fn secret_record(method: ClientAuthMethod, secret: Option<&str>) -> ClientAuthRecord {
        ClientAuthRecord {
            display_name: "test".to_owned(),
            auth_method: method.as_str().to_owned(),
            secret_hash: secret.map(hash_secret),
            jwks: None,
            jwks_uri: None,
            token_endpoint_auth_signing_alg: None,
        }
    }

    #[test]
    fn generated_secret_is_64_byte_url_safe_base64() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 5);
        let secret = generate_secret(&env);
        let decoded = URL_SAFE_NO_PAD.decode(&secret).expect("url-safe base64");
        assert_eq!(decoded.len(), 64, "64 random bytes");
        assert!(
            secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "url-safe alphabet: {secret}"
        );
    }

    #[test]
    fn basic_method_authenticates_and_wrong_secret_is_bad_secret() {
        let rec = secret_record(ClientAuthMethod::Basic, Some("s3cr3t"));
        let ok = parse_presented(
            Some(&basic_header("cli_x", "s3cr3t")),
            None,
            None,
            None,
            None,
        )
        .expect("parse");
        let PresentedClientAuth::Secret { method, secret, .. } = &ok else {
            panic!("secret variant");
        };
        assert!(
            authenticate_secret(&rec, ClientAuthMethod::Basic, *method, secret.as_deref()).is_ok()
        );

        let bad = parse_presented(
            Some(&basic_header("cli_x", "wrong")),
            None,
            None,
            None,
            None,
        )
        .expect("parse");
        let PresentedClientAuth::Secret { method, secret, .. } = &bad else {
            panic!("secret variant");
        };
        assert!(matches!(
            authenticate_secret(&rec, ClientAuthMethod::Basic, *method, secret.as_deref()),
            Err(SecretAuthError::BadSecret)
        ));
    }

    #[test]
    fn a_mismatched_method_is_a_method_mismatch_both_directions() {
        // Registered basic, presented post.
        let basic_client = secret_record(ClientAuthMethod::Basic, Some("s"));
        let via_post = parse_presented(None, Some("cli_x"), Some("s"), None, None).expect("parse");
        let PresentedClientAuth::Secret { method, secret, .. } = &via_post else {
            panic!("secret variant");
        };
        assert!(matches!(
            authenticate_secret(
                &basic_client,
                ClientAuthMethod::Basic,
                *method,
                secret.as_deref()
            ),
            Err(SecretAuthError::MethodMismatch)
        ));
    }

    #[test]
    fn public_client_authenticates_without_a_secret_but_rejects_one() {
        let public = secret_record(ClientAuthMethod::None, None);
        let no_secret = parse_presented(None, Some("cli_x"), None, None, None).expect("parse");
        let PresentedClientAuth::Secret { method, secret, .. } = &no_secret else {
            panic!("secret variant");
        };
        assert!(
            authenticate_secret(&public, ClientAuthMethod::None, *method, secret.as_deref())
                .is_ok()
        );

        let with_secret =
            parse_presented(None, Some("cli_x"), Some("unexpected"), None, None).expect("parse");
        // A public client that presents a secret parses as Post, so the method
        // does not match the registered None.
        let PresentedClientAuth::Secret { method, secret, .. } = &with_secret else {
            panic!("secret variant");
        };
        assert!(matches!(
            authenticate_secret(&public, ClientAuthMethod::None, *method, secret.as_deref()),
            Err(SecretAuthError::MethodMismatch)
        ));
    }

    #[test]
    fn presenting_a_secret_and_an_assertion_is_multiple_methods() {
        let err = parse_presented(
            None,
            Some("cli_x"),
            Some("s"),
            Some("a.b.c"),
            Some(JWT_BEARER_ASSERTION_TYPE),
        )
        .expect_err("secret and assertion");
        assert_eq!(err, ClientAuthParseError::MultipleMethods);
    }

    #[test]
    fn presenting_basic_and_an_assertion_is_multiple_methods() {
        let err = parse_presented(
            Some(&basic_header("cli_x", "s")),
            None,
            None,
            Some("a.b.c"),
            Some(JWT_BEARER_ASSERTION_TYPE),
        )
        .expect_err("basic and assertion");
        assert_eq!(err, ClientAuthParseError::MultipleMethods);
    }

    #[test]
    fn an_assertion_without_the_bearer_type_is_rejected() {
        let err = parse_presented(None, Some("cli_x"), None, Some("a.b.c"), None)
            .expect_err("missing type");
        assert_eq!(err, ClientAuthParseError::UnsupportedAssertionType);

        let err = parse_presented(None, Some("cli_x"), None, Some("a.b.c"), Some("wrong"))
            .expect_err("wrong type");
        assert_eq!(err, ClientAuthParseError::UnsupportedAssertionType);
    }

    #[test]
    fn an_assertion_type_without_an_assertion_is_missing_assertion() {
        let err = parse_presented(
            None,
            Some("cli_x"),
            None,
            None,
            Some(JWT_BEARER_ASSERTION_TYPE),
        )
        .expect_err("type without assertion");
        assert_eq!(err, ClientAuthParseError::MissingAssertion);
    }

    #[test]
    fn assertion_client_id_comes_from_form_or_sub_and_a_conflict_is_rejected() {
        // A JWS whose payload is {"sub":"cli_sub"} (base64url, no signature needed
        // for this parse-only test).
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"cli_sub"}"#);
        let assertion = format!("aGVhZGVy.{payload}.c2ln");

        // No form client_id: the sub supplies it.
        let parsed = parse_presented(
            None,
            None,
            None,
            Some(&assertion),
            Some(JWT_BEARER_ASSERTION_TYPE),
        )
        .expect("parse");
        assert_eq!(parsed.client_id(), "cli_sub");

        // A form client_id that disagrees with the sub is a conflict.
        let err = parse_presented(
            None,
            Some("cli_other"),
            None,
            Some(&assertion),
            Some(JWT_BEARER_ASSERTION_TYPE),
        )
        .expect_err("id conflict");
        assert_eq!(err, ClientAuthParseError::ClientIdMismatch);
    }

    #[test]
    fn a_conflicting_body_client_id_is_rejected() {
        let err = parse_presented(
            Some(&basic_header("cli_a", "s")),
            Some("cli_b"),
            None,
            None,
            None,
        )
        .expect_err("mismatched client_id");
        assert_eq!(err, ClientAuthParseError::ClientIdMismatch);
    }

    #[test]
    fn missing_client_id_is_a_parse_error() {
        let err = parse_presented(None, None, None, None, None).expect_err("no client id");
        assert_eq!(err, ClientAuthParseError::MissingClientId);
    }

    #[test]
    fn peek_header_reads_alg_and_kid_for_diagnostics() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES512","kid":"k9"}"#);
        let assertion = format!("{header}.cGF5.c2ln");
        let (alg, kid) = peek_assertion_header(&assertion);
        assert_eq!(alg.as_deref(), Some("ES512"));
        assert_eq!(kid.as_deref(), Some("k9"));
    }

    #[test]
    fn client_secret_jwt_is_recognized_but_not_advertised() {
        assert_eq!(
            ClientAuthMethod::parse("client_secret_jwt"),
            Some(ClientAuthMethod::ClientSecretJwt)
        );
        assert!(
            !ClientAuthMethod::ALL.contains(&ClientAuthMethod::ClientSecretJwt),
            "client_secret_jwt is not advertised"
        );
        assert!(
            ClientAuthMethod::ALL.contains(&ClientAuthMethod::PrivateKeyJwt),
            "private_key_jwt is advertised"
        );
    }

    #[test]
    fn a_pinned_es512_signing_alg_yields_an_empty_allowlist() {
        let mut record = secret_record(ClientAuthMethod::PrivateKeyJwt, None);
        record.token_endpoint_auth_signing_alg = Some("ES512".to_owned());
        assert!(
            allowed_assertion_algs(&record).is_empty(),
            "ES512 is unrepresentable, so the allowlist is empty and the assertion is rejected"
        );

        record.token_endpoint_auth_signing_alg = Some("EdDSA".to_owned());
        assert_eq!(allowed_assertion_algs(&record), vec![JwsAlgorithm::EdDsa]);
    }

    #[test]
    fn form_urldecode_does_not_panic_on_a_multibyte_char_after_percent() {
        // A `%` followed by a multi-byte UTF-8 character (the euro sign, 3 bytes) must
        // NOT be string-sliced at value[i+1..i+3]: that lands inside a char boundary
        // and panics on an unauthenticated request. The escape is not two ASCII hex
        // digits, so it is passed through verbatim and the rest decodes cleanly.
        let decoded = form_urldecode("a%\u{20ac}b");
        assert!(
            decoded.starts_with('a') && decoded.ends_with('b'),
            "the surrounding text survives without a panic: {decoded:?}"
        );
        // A genuine escape still decodes; a valid `%2B` becomes '+'.
        assert_eq!(form_urldecode("%2Bx"), "+x");
        // A non-hex escape passes the `%` through.
        assert_eq!(form_urldecode("%zz"), "%zz");
    }

    #[test]
    fn a_basic_credential_with_a_multibyte_char_after_percent_parses_without_panic() {
        // The reachable-unauthenticated path: an Authorization: Basic value whose
        // decoded secret is `%<euro>` must parse (form-urldecoding each half) without
        // panicking on the char boundary. Before the fix this reached a 500 via the
        // catch-panic layer.
        let header = format!("Basic {}", STANDARD.encode("a:%\u{20ac}"));
        let parsed = parse_basic(&header).expect("credential parses without a panic");
        assert_eq!(parsed.0, "a", "the client id half decodes");
    }

    #[test]
    fn verify_with_no_keys_fails_closed() {
        // A keyless private_key_jwt client is rejected at registration now, but if one
        // somehow existed, verification fails CLOSED: no key means no acceptance, so
        // the assertion can never authenticate.
        let clock = ironauth_env::ManualClock::new(SystemTime::UNIX_EPOCH);
        let result = verify_assertion_claims(
            "aGVhZGVy.cGF5.c2ln",
            &[],
            ASYMMETRIC_ALGS,
            "cli_x",
            &["https://issuer.test".to_owned()],
            Duration::from_secs(60),
            &clock,
        );
        assert!(result.is_none(), "empty key set fails closed");
    }
}
