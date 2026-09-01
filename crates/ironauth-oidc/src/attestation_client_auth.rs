// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation-based client authentication, PROTOTYPE (issue #133).
//!
//! # What this is, and what it is not
//!
//! This is one of the five version-tagged prototypes issue #133 asks for. It is
//! EXPERIMENTAL, off by default, and enabling it requires acknowledging the exact
//! draft revision named by [`ATTESTATION_CLIENT_AUTH_DRAFT`]. It is not a supported
//! authentication method: it is not in [`ClientAuthMethod::ALL`], so discovery never
//! advertises it, and no registered client can select it until the surface graduates.
//!
//! # The mechanism
//!
//! `draft-ietf-oauth-attestation-based-client-auth` lets a client instance that holds
//! no registered secret authenticate with TWO JWTs carried in headers:
//!
//! - `OAuth-Client-Attestation`: minted by an ATTESTER (the client's backend, a
//!   platform attestation service) that the authorization server trusts. It names the
//!   `client_id` in `sub` and BINDS a public key in `cnf.jwk`.
//! - `OAuth-Client-Attestation-PoP`: minted by the client instance and signed with the
//!   key the attestation bound, proving the instance holds it.
//!
//! Neither alone authenticates anything. The attestation says "the party holding this
//! key is an instance of this client"; the proof says "I hold that key". The
//! authorization server learns the client id from the attester it already trusts, and
//! never from the client instance, which is the whole point: an instance that could
//! name its own `client_id` would be able to impersonate any client whose attester it
//! could reach.
//!
//! # What this refuses, and why each refusal is a real attack
//!
//! Every check below exists because its absence is exploitable, and each has a test.
//!
//! - **A PoP signed by a key the attestation did not bind.** Without this an attacker
//!   replays somebody else's attestation with their own key and becomes that client.
//!   The PoP is verified against the `cnf.jwk` key and NOTHING else: the trusted set
//!   for that verification has exactly one member.
//! - **An attestation whose `sub` is not the client that is authenticating.** Without
//!   this an attester's attestation for client A authenticates client B.
//! - **An attestation from an issuer the deployment does not trust.** Trust is
//!   per-issuer and explicit: an unknown `iss` has no keys, so nothing verifies.
//! - **The two JWTs swapped.** They share an issuer relationship and a key chain, and
//!   `typ` is the only thing separating them, which is why the media type is checked
//!   rather than assumed. RFC 8725 section 3.11 is the general form of this.
//! - **A PoP minted for a different authorization server.** `aud` is the issuer
//!   identifier, matched exactly, so a PoP harvested at one deployment is inert at
//!   another that trusts the same attester.
//! - **Anything expired.** Both JWTs carry `exp`, and the verification seam enforces it.
//!
//! # A deliberate deviation from the draft, and the upgrade risk it carries
//!
//! The draft makes `aud` OPTIONAL on the client attestation JWT (it is required only
//! on the PoP). IronAuth REQUIRES it on both, because [`VerificationPolicy`] has no
//! optional-audience mode by construction: a policy that does not name an expected
//! audience does not compile, and that is a property worth keeping. The security
//! effect is additive rather than harmful (an attestation naming this deployment
//! cannot be presented at another that trusts the same attester, which the PoP's own
//! `aud` already prevents), but the INTEROP effect is real: an attester that follows
//! the draft literally and omits `aud` is refused here.
//!
//! That is the prototype's headline upgrade risk and it is recorded rather than
//! smoothed over. See `docs/experimental/attestation-client-auth.md`. Closing it at
//! graduation means either an optional-audience mode in the JOSE seam or a documented
//! profile requirement on the attester.
//!
//! # What a graduation still needs
//!
//! Stated plainly so nothing here reads as finished:
//!
//! - **`jti` replay recording.** The PoP's `jti` is REQUIRED and returned in
//!   [`AttestedClient::pop_jti`], but this module does not record it. A replayed PoP
//!   inside its own lifetime is therefore accepted. The store seam that
//!   `private_key_jwt` uses for exactly this exists and is where the wiring goes;
//!   until it is wired, `attestation_client_auth` is not a supported method, which is
//!   why it is not advertised. The bound in the meantime is on the CLAIMED lifetime
//!   (`exp - iat`), not on the reuse window: the verifier allows 60 seconds of skew at
//!   each end, so a captured proof is replayable for about seven minutes rather than five.
//! - **Client REGISTRATION.** Nothing in this build can register a client for
//!   `attest_jwt_client_auth`: dynamic registration admits only methods in
//!   [`ClientAuthMethod::ALL`], the snapshot importer's list excludes it, and the management
//!   API does not write `token_endpoint_auth_method` at all. So the seam below is reachable
//!   from the test suite and from nothing else. That is the right posture for a draft, and it
//!   means the two configuration conditions are not the whole story.
//! - **Attester key rotation, and attester SCOPE.** Trust is a static inline key set, held once
//!   per DEPLOYMENT rather than per tenant, so a listed attester can vouch for a client in any
//!   scope. The comparable anchor for the jwt-bearer grant is a per-scope store row with its own
//!   enable switch; this is not that. Both are graduation work.
//! - **The attestation's optional claims** (`aal`, `key_type`, `user_authentication`,
//!   `status`) are not read. They carry assurance level and revocation, and a
//!   deployment that made authorization decisions on them would need them enforced.

use std::time::Duration;

use base64::Engine as _;

use ironauth_env::Clock;
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, TrustedKey, VerificationPolicy, trusted_keys_from_jwks, verify,
};
use serde_json::{Value, json};

/// The EXACT draft revision this prototype implements.
///
/// It doubles as the experimental acknowledgment version: an operator enabling the
/// feature acknowledges this string, and a revision that changes the wire shape bumps
/// it and invalidates every acknowledgment in the wild. That is the maturity ladder's
/// entire purpose, and a draft-stage surface without it is an upgrade trap.
pub const ATTESTATION_CLIENT_AUTH_DRAFT: &str = "draft-ietf-oauth-attestation-based-client-auth-10";

/// The header carrying the attester's client attestation JWT.
pub const ATTESTATION_HEADER: &str = "OAuth-Client-Attestation";

/// The header carrying the client instance's proof of possession.
pub const ATTESTATION_POP_HEADER: &str = "OAuth-Client-Attestation-PoP";

/// The media type of the client attestation JWT.
pub const ATTESTATION_TYP: &str = "oauth-client-attestation+jwt";

/// The media type of the proof-of-possession JWT.
pub const ATTESTATION_POP_TYP: &str = "oauth-client-attestation-pop+jwt";

/// The `token_endpoint_auth_method` name this draft registers.
///
/// Spelled here, in [`crate::ClientAuthMethod::as_str`] and in
/// [`crate::ClientAuthMethod::parse`], which is three literals for one wire string. They are
/// pinned against each other by a test rather than deduplicated, because the enum's two arms
/// are `match` limbs on a `&'static str` and routing them through a constant would make the
/// method table read less clearly than the drift it prevents. The test is the deduplication.
pub const ATTESTATION_AUTH_METHOD: &str = "attest_jwt_client_auth";

/// The maximum lifetime a proof of possession may claim.
///
/// The draft says a `PoP` is short lived without naming a number. Bounded here because
/// replay recording is NOT yet wired (see the module docs): until it is, this bound is
/// the only thing limiting the window in which a captured `PoP` can be reused, so it is
/// deliberately tight rather than generous.
pub const MAX_POP_LIFETIME: Duration = Duration::from_secs(300);

/// One attester this deployment trusts, and the keys that verify its attestations.
///
/// Trust is PER ISSUER and explicit. There is no "any issuer with a valid signature"
/// mode, because the attester is the party that decides which `client_id` an
/// instance may claim: an unlisted issuer that could mint attestations would be able
/// to mint any client's identity.
#[derive(Debug, Clone)]
pub struct TrustedAttester {
    issuer: String,
    keys: Vec<TrustedKey>,
}

impl TrustedAttester {
    /// A trusted attester from its issuer identifier and its JWKS bytes.
    ///
    /// Returns `None` when the issuer is empty or the JWKS yields no usable key: an
    /// attester with no keys would sit in the registry verifying nothing, which is a
    /// configuration error that should be visible at load rather than a silent refusal
    /// at every authentication.
    #[must_use]
    pub fn from_jwks(issuer: impl Into<String>, jwks: &[u8]) -> Option<Self> {
        let issuer = issuer.into();
        if issuer.is_empty() {
            return None;
        }
        let keys = trusted_keys_from_jwks(jwks);
        if keys.is_empty() {
            return None;
        }
        Some(Self { issuer, keys })
    }
}

/// The attesters this deployment trusts.
#[derive(Debug, Clone, Default)]
pub struct AttesterRegistry {
    attesters: Vec<TrustedAttester>,
}

impl AttesterRegistry {
    /// An empty registry: every attestation is refused.
    ///
    /// This is the DEFAULT, and it is the correct default. A deployment that enabled
    /// the feature without registering an attester authenticates nobody, rather than
    /// trusting whoever signed first.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted attester.
    #[must_use]
    pub fn with(mut self, attester: TrustedAttester) -> Self {
        self.attesters.push(attester);
        self
    }

    /// The attester registered under `issuer`, if any.
    fn get(&self, issuer: &str) -> Option<&TrustedAttester> {
        self.attesters
            .iter()
            .find(|attester| attester.issuer == issuer)
    }

    /// Whether any attester is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attesters.is_empty()
    }
}

/// Why an attestation-based authentication was refused.
///
/// Carried for DIAGNOSTICS only. The token endpoint answers the uniform
/// `invalid_client` (RFC 6749 section 5.2) for every variant, exactly as the other
/// client-authentication methods do: a caller that learned which check failed would
/// have an oracle for how far a forged attestation got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationRejection {
    /// The feature is enabled but no attester is registered.
    NoAttesterRegistered,
    /// One of the two headers was absent. Both are required.
    MissingHeader,
    /// The attestation named an issuer this deployment does not trust.
    UntrustedAttester,
    /// The attestation did not verify against its attester's keys.
    AttestationInvalid,
    /// The attestation carried no `sub`, so it named no client.
    AttestationNamesNoClient,
    /// The attestation's `sub` is not the client that is authenticating.
    ClientMismatch,
    /// The attestation carried no usable `cnf.jwk`, so it bound no key.
    NoBoundKey,
    /// The proof of possession did not verify against the bound key.
    ProofInvalid,
    /// The proof's `iss` is not the attested client.
    ProofIssuerMismatch,
    /// The proof carried no `jti`, which the draft requires.
    ProofMissingJti,
    /// The proof claimed a lifetime longer than [`MAX_POP_LIFETIME`].
    ProofLifetimeTooLong,
    /// A JWT's media type was not the one its position requires.
    TypMismatch,
    /// A policy could not be built, which means the inputs were degenerate.
    PolicyUnbuildable,
}

/// A client instance that authenticated with an attestation and its proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedClient {
    /// The `client_id`, taken from the ATTESTER's `sub`, never from the instance.
    pub client_id: String,
    /// The attester that vouched for it.
    pub attester: String,
    /// The proof's `jti`.
    ///
    /// Returned so a caller CAN record it for replay detection. This module does not:
    /// see the module docs. It is on the struct rather than dropped precisely so the
    /// wiring has something to wire.
    pub pop_jti: String,
}

/// Authenticate a client instance from its attestation and proof of possession.
///
/// `audience` is this deployment's issuer identifier, matched exactly against both
/// JWTs' `aud`. `presented_client_id` is the `client_id` the request claims; it is
/// CHECKED against the attestation rather than trusted.
///
/// # Errors
///
/// [`AttestationRejection`] naming which check refused it, for diagnostics only. The
/// caller answers the uniform `invalid_client`.
pub fn authenticate_attested_client(
    attestation: &str,
    proof: &str,
    presented_client_id: &str,
    audience: &str,
    registry: &AttesterRegistry,
    clock: &dyn Clock,
) -> Result<AttestedClient, AttestationRejection> {
    if registry.is_empty() {
        return Err(AttestationRejection::NoAttesterRegistered);
    }
    if attestation.is_empty() || proof.is_empty() {
        return Err(AttestationRejection::MissingHeader);
    }

    // The issuer is read from the UNVERIFIED attestation only to SELECT which trusted
    // key set to verify against. That is the same shape as a `kid`: it can narrow the
    // trusted set, never extend it, and an issuer naming no registered attester
    // selects nothing and is refused here rather than verified against everything.
    let claimed_issuer =
        unverified_issuer(attestation).ok_or(AttestationRejection::AttestationInvalid)?;
    let attester = registry
        .get(&claimed_issuer)
        .ok_or(AttestationRejection::UntrustedAttester)?;

    let attestation_policy = VerificationPolicy::new(
        attestation_algorithms(),
        attester.keys.clone(),
        attester.issuer.clone(),
        audience.to_owned(),
        // The attester is a FOREIGN party whose header shape this deployment does not
        // control, so the policy cannot require a `TokenTyp` (that enum names only
        // profiles IronAuth mints). The media type is checked below instead, on the
        // VERIFIED token, which is why this is not a hole: the draft's own two
        // profiles still have to be told apart, and `typ` is what tells them apart.
        ExpectedTyp::ForeignIssuer,
    )
    .map_err(|_| AttestationRejection::PolicyUnbuildable)?;

    let attestation = verify(attestation, &attestation_policy, clock)
        .map_err(|_| AttestationRejection::AttestationInvalid)?;
    if !media_type_is(attestation.token_typ(), ATTESTATION_TYP) {
        return Err(AttestationRejection::TypMismatch);
    }

    let attested_client = attestation
        .claims()
        .subject()
        .ok_or(AttestationRejection::AttestationNamesNoClient)?;
    if attested_client != presented_client_id {
        // The attester decides which client an instance may claim. Without this an
        // attestation minted for one client authenticates any other.
        return Err(AttestationRejection::ClientMismatch);
    }
    let attested_client = attested_client.to_owned();

    let bound_key =
        bound_key(attestation.claims().get("cnf")).ok_or(AttestationRejection::NoBoundKey)?;

    // EXACTLY ONE trusted key: the one the attestation bound. The attester's own keys
    // are deliberately not in this set, so an attester that also holds the instance
    // key cannot prove possession on the instance's behalf, and a second attestation's
    // key cannot verify this proof.
    let proof_policy = VerificationPolicy::new(
        attestation_algorithms(),
        vec![bound_key],
        attested_client.clone(),
        audience.to_owned(),
        ExpectedTyp::ForeignIssuer,
    )
    .map_err(|_| AttestationRejection::PolicyUnbuildable)?;

    let proof =
        verify(proof, &proof_policy, clock).map_err(|_| AttestationRejection::ProofInvalid)?;
    if !media_type_is(proof.token_typ(), ATTESTATION_POP_TYP) {
        return Err(AttestationRejection::TypMismatch);
    }
    // The policy already matched `iss` exactly against the attested client, so this
    // cannot fail; it is asserted rather than assumed because the policy's issuer
    // argument and this claim are two different lines that a refactor could separate.
    if proof.claims().issuer() != attested_client {
        return Err(AttestationRejection::ProofIssuerMismatch);
    }

    let pop_jti = proof
        .claims()
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty())
        .ok_or(AttestationRejection::ProofMissingJti)?
        .to_owned();

    // A PoP whose `exp` is far in the future is a long-lived bearer credential wearing
    // a proof's clothes. With replay recording unwired this bound is the only limit on
    // the reuse window, so it is enforced rather than documented.
    let expiration = proof
        .claims()
        .expiration()
        .ok_or(AttestationRejection::ProofInvalid)?;
    // An `iat` is what the lifetime is measured FROM, and a proof without one has no
    // measurable lifetime: falling back to "now" would make an unbounded `exp` look
    // short-lived to a server that received it late, which is the bound inverted.
    let issued = proof
        .claims()
        .issued_at()
        .ok_or(AttestationRejection::ProofInvalid)?;
    let lifetime = expiration.saturating_sub(issued);
    if lifetime > i64::try_from(MAX_POP_LIFETIME.as_secs()).unwrap_or(i64::MAX) {
        return Err(AttestationRejection::ProofLifetimeTooLong);
    }

    Ok(AttestedClient {
        client_id: attested_client,
        attester: claimed_issuer,
        pop_jti,
    })
}

/// The algorithms an attestation or proof may be signed with.
///
/// Asymmetric only. A symmetric algorithm here would mean the verifier holds the
/// signing key, which defeats the point of an attestation entirely.
fn attestation_algorithms() -> Vec<JwsAlgorithm> {
    vec![
        JwsAlgorithm::Es256,
        JwsAlgorithm::Es384,
        JwsAlgorithm::EdDsa,
        JwsAlgorithm::Rs256,
        JwsAlgorithm::Ps256,
    ]
}

/// Whether a verified header's `typ` names `expected`.
///
/// Case-insensitive with an optional `application/` prefix, per RFC 7515 section 4.1.9
/// and RFC 2045 section 5.1, matching how [`ironauth_jose::TokenTyp`] compares its own.
/// An ABSENT `typ` never matches: the draft requires both media types explicitly, so
/// its absence is a token that did not come from a conforming minter.
fn media_type_is(header_typ: Option<&str>, expected: &str) -> bool {
    // The `application/` prefix is OPTIONAL and case-insensitive, which is what
    // `ironauth_jose::TokenTyp::matches` does with `eq_ignore_ascii_case`. The first version
    // stripped two literal spellings, `application/` and `APPLICATION/`, so a conforming
    // attester sending `Application/oauth-client-attestation+jwt` was refused -- fail-closed,
    // and still a second hand-rolled copy of a vetted comparison that had already drifted from
    // it in the doc comment claiming parity.
    let Some(candidate) = header_typ else {
        return false;
    };
    let stripped = candidate
        .get(..12)
        .filter(|prefix| prefix.eq_ignore_ascii_case("application/"))
        .map_or(candidate, |_| &candidate[12..]);
    stripped.eq_ignore_ascii_case(expected)
}

/// The `iss` of an UNVERIFIED compact JWS, for attester SELECTION only.
///
/// This reads no trust from the token. The returned issuer can only narrow the trusted
/// key set to one registered attester's keys; it can never introduce a key, and an
/// issuer that matches no attester is refused. Bounded so a hostile token cannot force
/// a large decode here.
fn unverified_issuer(token: &str) -> Option<String> {
    /// A generous cap for a payload segment carrying an `iss`, small enough that this
    /// pre-verification read costs nothing an attacker can exploit.
    const MAX_SELECTION_PAYLOAD_B64: usize = 8192;

    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() || payload.len() > MAX_SELECTION_PAYLOAD_B64 {
        return None;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("iss")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty())
        .map(ToOwned::to_owned)
}

/// The single trusted key a `cnf` claim binds.
///
/// Only `cnf.jwk` is accepted. `cnf.jkt` (a thumbprint) names a key without carrying
/// it, so there would be nothing to verify with, and `cnf.kid` would resolve against a
/// key set this deployment does not have. Reusing the vetted JWKS parser rather than
/// reading the JWK by hand means the key material goes through exactly the validation
/// every other key in the system does.
fn bound_key(cnf: Option<&Value>) -> Option<TrustedKey> {
    let jwk = cnf?.get("jwk")?;
    if !jwk.is_object() {
        return None;
    }
    let keys = trusted_keys_from_jwks(json!({ "keys": [jwk] }).to_string().as_bytes());
    // EXACTLY one. A `cnf.jwk` that somehow produced two keys would mean two keys could
    // satisfy one proof, which is not a binding.
    if keys.len() != 1 {
        return None;
    }
    keys.into_iter().next()
}
