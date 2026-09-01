// SPDX-License-Identifier: MIT OR Apache-2.0

//! Attestation-based client authentication, the PROTOTYPE's adversarial suite (issue #133).
//!
//! # Why every test here is a negative with a control beside it
//!
//! The module's doc comment lists six refusals and says each exists because its absence is
//! exploitable. That sentence was written before this file existed, which made it a claim
//! about code rather than a fact about it. Each refusal below is driven by MINTING the
//! attack: a real attestation, a real proof, and exactly one thing changed. A negative that
//! differs from the happy path on more than one dimension proves only that something was
//! wrong, not which check caught it, so each case varies ONE.
//!
//! The happy path runs first in every test that needs it, because a suite of refusals against
//! a function that refuses everything passes completely.
//!
//! # Database
//!
//! None. This is a pure verification seam over two JWTs and a key set.

use ironauth_env::ManualClock;
use ironauth_jose::{EmissionOptions, JwkSet, SigningKey, sign_jws};
use ironauth_oidc::attestation_client_auth::{
    ATTESTATION_POP_TYP, ATTESTATION_TYP, AttestationRejection, AttesterRegistry, TrustedAttester,
    authenticate_attested_client,
};
use serde_json::{Value, json};

/// This deployment's issuer identifier: what both JWTs must be addressed to.
const AUDIENCE: &str = "https://ironauth.example.test";
/// The attester the deployment trusts.
const ATTESTER: &str = "https://attester.example.test";
/// The client the attester vouches for.
const CLIENT: &str = "cli_instance_under_test";

/// A clock frozen at [`NOW`], through the env seam rather than a hand-rolled one.
///
/// `ManualClock` is what the rest of this tree uses for exactly this. A hand-rolled `Clock`
/// impl here would have to reach for the monotonic system source directly, which is the
/// `time-via-env` invariant broken in a test -- and this is the place a deterministic clock
/// matters most, because a fixture minted against wall time starts failing at a date boundary
/// rather than when something breaks. (The rule is a TEXT scan, so naming the forbidden call
/// in prose trips it as surely as writing it: this sentence is phrased around that.)
fn clock() -> ManualClock {
    ManualClock::new(std::time::UNIX_EPOCH + std::time::Duration::from_secs(NOW))
}

/// The instant every fixture is minted around. Fixed rather than `now()` so a test that
/// passes today cannot start failing at a date boundary.
const NOW: u64 = 1_800_000_000;

/// A signing key from a fixed seed, so a fixture is byte-identical across runs.
fn key(kid: &str, seed: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed; 32]).expect("an ed25519 key")
}

/// The public JWKS for `key`, as the attester would publish it.
fn jwks_of(key: &SigningKey) -> Vec<u8> {
    JwkSet::from_signing_keys([key])
        .expect("a jwk set")
        .to_json()
        .expect("jwks json")
        .into_bytes()
}

/// The public JWK of `key`, as an attestation's `cnf.jwk`.
fn public_jwk(key: &SigningKey) -> Value {
    let set: Value = serde_json::from_slice(&jwks_of(key)).expect("jwks parses");
    set["keys"][0].clone()
}

/// Sign `claims` with `key` under media type `typ`.
fn jwt(key: &SigningKey, typ: &str, claims: &Value) -> String {
    sign_jws(
        key,
        serde_json::to_vec(claims)
            .expect("claims serialize")
            .as_slice(),
        &EmissionOptions::new().with_typ(typ), // invariant-allow: typ-via-declaration -- the DRAFT's two media types, dictated by draft-ietf-oauth-attestation-based-client-auth, not IronAuth profiles
    )
    .expect("sign")
}

/// The parts a full authentication needs: the attester's key, the instance's key, and the
/// registry that trusts the attester.
struct Fixture {
    attester_key: SigningKey,
    instance_key: SigningKey,
    registry: AttesterRegistry,
}

fn fixture() -> Fixture {
    let attester_key = key("attester-kid", 11);
    let instance_key = key("instance-kid", 22);
    let registry = AttesterRegistry::new().with(
        TrustedAttester::from_jwks(ATTESTER, &jwks_of(&attester_key)).expect("a trusted attester"),
    );
    Fixture {
        attester_key,
        instance_key,
        registry,
    }
}

/// The attestation an honest attester mints: it names the client and BINDS the instance's key.
fn attestation(f: &Fixture) -> String {
    attestation_for(f, CLIENT, &public_jwk(&f.instance_key))
}

fn attestation_for(f: &Fixture, subject: &str, bound: &Value) -> String {
    jwt(
        &f.attester_key,
        ATTESTATION_TYP,
        &json!({
            "iss": ATTESTER,
            "sub": subject,
            "aud": AUDIENCE,
            "iat": NOW - 10,
            "exp": NOW + 600,
            "cnf": { "jwk": bound },
        }),
    )
}

/// The proof an honest instance mints, signed with the key the attestation bound.
fn proof(f: &Fixture) -> String {
    proof_signed_by(&f.instance_key, CLIENT, AUDIENCE, NOW + 60)
}

fn proof_signed_by(signer: &SigningKey, issuer: &str, audience: &str, expiry: u64) -> String {
    jwt(
        signer,
        ATTESTATION_POP_TYP,
        &json!({
            "iss": issuer,
            "aud": audience,
            "jti": "pop-0001",
            "iat": NOW - 5,
            "exp": expiry,
        }),
    )
}

fn authenticate(
    f: &Fixture,
    attestation: &str,
    proof: &str,
) -> Result<String, AttestationRejection> {
    authenticate_attested_client(attestation, proof, CLIENT, AUDIENCE, &f.registry, &clock())
        .map(|attested| attested.client_id)
}

#[test]
fn an_attested_instance_authenticates_and_the_client_comes_from_the_attester() {
    let f = fixture();
    let attested = authenticate_attested_client(
        &attestation(&f),
        &proof(&f),
        CLIENT,
        AUDIENCE,
        &f.registry,
        &clock(),
    )
    .expect("the honest pair authenticates");
    assert_eq!(attested.client_id, CLIENT);
    assert_eq!(attested.attester, ATTESTER);
    assert_eq!(
        attested.pop_jti, "pop-0001",
        "the jti is carried out so a caller CAN record it for replay detection"
    );
}

#[test]
fn a_proof_signed_by_a_key_the_attestation_did_not_bind_is_refused() {
    // THE HEADLINE ATTACK: replay somebody else's attestation with your own key. If the proof
    // were verified against the attester's keys, or against any set wider than the one bound
    // key, this would authenticate the attacker AS the attested client.
    let f = fixture();
    let attacker = key("attacker-kid", 33);
    let stolen = proof_signed_by(&attacker, CLIENT, AUDIENCE, NOW + 60);
    assert_eq!(
        authenticate(&f, &attestation(&f), &stolen),
        Err(AttestationRejection::ProofInvalid),
        "a proof must verify against the BOUND key and nothing else"
    );
}

#[test]
fn an_attestation_for_a_different_client_does_not_authenticate_this_one() {
    // Without this an attester's attestation for client A authenticates client B, which turns
    // any attested client into every attested client.
    let f = fixture();
    let elsewhere = attestation_for(&f, "cli_some_other_client", &public_jwk(&f.instance_key));
    assert_eq!(
        authenticate(&f, &elsewhere, &proof(&f)),
        Err(AttestationRejection::ClientMismatch)
    );
}

#[test]
fn an_attestation_from_an_unregistered_attester_verifies_against_nothing() {
    // Trust is per-issuer and explicit. An "any valid signature" mode would let anyone who can
    // mint a JWT name any client_id they like.
    let f = fixture();
    let rogue_key = key("rogue-kid", 44);
    let rogue = jwt(
        &rogue_key,
        ATTESTATION_TYP,
        &json!({
            "iss": "https://rogue.example.test",
            "sub": CLIENT,
            "aud": AUDIENCE,
            "iat": NOW - 10,
            "exp": NOW + 600,
            "cnf": { "jwk": public_jwk(&f.instance_key) },
        }),
    );
    assert_eq!(
        authenticate(&f, &rogue, &proof(&f)),
        Err(AttestationRejection::UntrustedAttester)
    );
}

#[test]
fn an_attestation_signed_by_the_wrong_key_of_a_trusted_attester_is_refused() {
    // The issuer is read UNVERIFIED to select a key set, so this is the case that proves
    // selecting is not accepting: same issuer, different key.
    let f = fixture();
    let impostor = key("impostor-kid", 55);
    let forged = jwt(
        &impostor,
        ATTESTATION_TYP,
        &json!({
            "iss": ATTESTER,
            "sub": CLIENT,
            "aud": AUDIENCE,
            "iat": NOW - 10,
            "exp": NOW + 600,
            "cnf": { "jwk": public_jwk(&f.instance_key) },
        }),
    );
    assert_eq!(
        authenticate(&f, &forged, &proof(&f)),
        Err(AttestationRejection::AttestationInvalid)
    );
}

#[test]
fn the_two_jwts_cannot_be_swapped() {
    // They share an issuer relationship and a key chain, and `typ` is the only thing that
    // separates them (RFC 8725 section 3.11). Swapping them is the cross-profile confusion
    // the media-type check exists for.
    let f = fixture();
    // The refusal lands EARLIER than the media-type check, and that is worth recording rather
    // than asserting around: a proof's `iss` is the client, which is not a registered
    // attester, so the swap is refused before anything is verified at all. The media type is
    // what catches the narrower case below, where the two are minted by the same party.
    assert_eq!(
        authenticate(&f, &proof(&f), &attestation(&f)),
        Err(AttestationRejection::UntrustedAttester),
        "the attestation and the proof must not be interchangeable"
    );
}

#[test]
fn an_attestation_wearing_the_proofs_media_type_is_refused() {
    // The narrower half of the swap, varying ONLY the typ so the refusal cannot be blamed on
    // the signing key or the claims.
    let f = fixture();
    let mistyped = jwt(
        &f.attester_key,
        ATTESTATION_POP_TYP,
        &json!({
            "iss": ATTESTER,
            "sub": CLIENT,
            "aud": AUDIENCE,
            "iat": NOW - 10,
            "exp": NOW + 600,
            "cnf": { "jwk": public_jwk(&f.instance_key) },
        }),
    );
    assert_eq!(
        authenticate(&f, &mistyped, &proof(&f)),
        Err(AttestationRejection::TypMismatch)
    );
}

#[test]
fn a_proof_minted_for_another_deployment_is_inert_here() {
    // A PoP harvested at one deployment must not authenticate at another that trusts the same
    // attester, which is the whole reason `aud` is matched exactly.
    let f = fixture();
    let elsewhere = proof_signed_by(
        &f.instance_key,
        CLIENT,
        "https://other-ironauth.example.test",
        NOW + 60,
    );
    assert_eq!(
        authenticate(&f, &attestation(&f), &elsewhere),
        Err(AttestationRejection::ProofInvalid)
    );
}

#[test]
fn a_proof_claiming_a_long_lifetime_is_refused_because_replay_recording_is_unwired() {
    // The bound exists because the `jti` is NOT recorded yet: until it is, this is the only
    // limit on the window in which a captured proof can be reused. A test is what keeps the
    // bound honest, since the module documents it as enforced rather than aspirational.
    let f = fixture();
    let long = proof_signed_by(&f.instance_key, CLIENT, AUDIENCE, NOW + 86_400);
    assert_eq!(
        authenticate(&f, &attestation(&f), &long),
        Err(AttestationRejection::ProofLifetimeTooLong)
    );

    // The control: one second inside the bound still authenticates, so the refusal above is
    // the LIFETIME and not the expiry, the clock, or the signature.
    let inside = proof_signed_by(&f.instance_key, CLIENT, AUDIENCE, NOW + 290);
    assert!(authenticate(&f, &attestation(&f), &inside).is_ok());
}

#[test]
fn a_proof_with_no_jti_is_refused_so_replay_recording_has_something_to_record() {
    let f = fixture();
    let anonymous = jwt(
        &f.instance_key,
        ATTESTATION_POP_TYP,
        &json!({
            "iss": CLIENT,
            "aud": AUDIENCE,
            "iat": NOW - 5,
            "exp": NOW + 60,
        }),
    );
    assert_eq!(
        authenticate(&f, &attestation(&f), &anonymous),
        Err(AttestationRejection::ProofMissingJti)
    );
}

#[test]
fn a_proof_issued_by_someone_other_than_the_attested_client_is_refused() {
    let f = fixture();
    let wrong_issuer = proof_signed_by(&f.instance_key, "cli_someone_else", AUDIENCE, NOW + 60);
    // `ProofInvalid`, not `ProofIssuerMismatch`: the proof POLICY already names the attested
    // client as the expected issuer, so verification refuses it and the explicit check after
    // it never runs. That check is a defensive assert against a refactor separating the policy
    // argument from the claim, and this assertion records which layer actually refuses today
    // -- an expectation of the later variant would have quietly documented the wrong one.
    assert_eq!(
        authenticate(&f, &attestation(&f), &wrong_issuer),
        Err(AttestationRejection::ProofInvalid)
    );
}

#[test]
fn an_attestation_that_binds_no_key_authenticates_nobody() {
    // Without a bound key there is nothing for the proof to prove against, and accepting the
    // attestation alone would make it a bearer token: whoever holds it is the client.
    let f = fixture();
    let unbound = jwt(
        &f.attester_key,
        ATTESTATION_TYP,
        &json!({
            "iss": ATTESTER,
            "sub": CLIENT,
            "aud": AUDIENCE,
            "iat": NOW - 10,
            "exp": NOW + 600,
        }),
    );
    assert_eq!(
        authenticate(&f, &unbound, &proof(&f)),
        Err(AttestationRejection::NoBoundKey)
    );
}

#[test]
fn the_default_registry_trusts_nobody() {
    // The default posture, and the one an operator who enables the flag without configuring an
    // attester lands in. Trusting whoever signed first would be the opposite failure.
    let f = fixture();
    let empty = AttesterRegistry::new();
    assert!(empty.is_empty());
    assert_eq!(
        authenticate_attested_client(
            &attestation(&f),
            &proof(&f),
            CLIENT,
            AUDIENCE,
            &empty,
            &clock(),
        )
        .map(|attested| attested.client_id),
        Err(AttestationRejection::NoAttesterRegistered)
    );
}

#[test]
fn both_headers_are_required() {
    let f = fixture();
    assert_eq!(
        authenticate(&f, "", &proof(&f)),
        Err(AttestationRejection::MissingHeader)
    );
    assert_eq!(
        authenticate(&f, &attestation(&f), ""),
        Err(AttestationRejection::MissingHeader)
    );
}

#[test]
fn an_attester_with_no_usable_key_is_refused_at_load_rather_than_at_every_request() {
    // A registry entry that verifies nothing is a configuration error, and one that sat in the
    // registry would refuse silently at every authentication with no way to tell it from a
    // forged attestation.
    assert!(TrustedAttester::from_jwks(ATTESTER, b"{\"keys\":[]}").is_none());
    assert!(TrustedAttester::from_jwks(ATTESTER, b"not json").is_none());
    assert!(
        TrustedAttester::from_jwks("", &jwks_of(&key("k", 66))).is_none(),
        "an empty issuer identifies no attester"
    );
}

#[test]
fn an_expired_attestation_or_proof_is_refused() {
    // An HOUR past expiry, not a second: the verification policy allows 60 seconds of clock
    // skew, so `exp = now - 1` is still live and a test written that way passes against a
    // verifier that ignores `exp` entirely. The first draft of this test did exactly that.
    let f = fixture();
    let stale = jwt(
        &f.attester_key,
        ATTESTATION_TYP,
        &json!({
            "iss": ATTESTER,
            "sub": CLIENT,
            "aud": AUDIENCE,
            "iat": NOW - 4_000,
            "exp": NOW - 3_600,
            "cnf": { "jwk": public_jwk(&f.instance_key) },
        }),
    );
    assert_eq!(
        authenticate(&f, &stale, &proof(&f)),
        Err(AttestationRejection::AttestationInvalid)
    );

    let stale_proof = proof_signed_by(&f.instance_key, CLIENT, AUDIENCE, NOW - 3_600);
    assert_eq!(
        authenticate(&f, &attestation(&f), &stale_proof),
        Err(AttestationRejection::ProofInvalid)
    );
}

/// The revision this module pins is the one the feature registry acknowledges.
///
/// The other half of the pair in `ironauth-config`'s own suite. `ironauth-config` cannot import
/// this crate (the dependency runs the other way), so the two constants are checked against one
/// shared literal from both sides. Without both halves a drift is invisible: the registry could
/// bump the acknowledgment while the verifier still implemented the old revision, and an
/// operator would acknowledge one wire format and get another.
#[test]
fn the_pinned_draft_revision_is_the_one_the_acknowledgment_names() {
    assert_eq!(
        ironauth_oidc::attestation_client_auth::ATTESTATION_CLIENT_AUTH_DRAFT,
        "draft-ietf-oauth-attestation-based-client-auth-10"
    );
    assert_eq!(
        ironauth_oidc::attestation_client_auth::ATTESTATION_CLIENT_AUTH_DRAFT,
        ironauth_config::ATTESTATION_CLIENT_AUTH_VERSION,
        "the implementing module and the acknowledgment must name the SAME revision"
    );
}
