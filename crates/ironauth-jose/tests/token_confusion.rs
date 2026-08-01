// SPDX-License-Identifier: MIT OR Apache-2.0

//! One token is never another token (issue #192).
//!
//! Every other suite in this crate varies the algorithm, the key, the structure,
//! or a claim. This one holds ALL of those fixed and varies only the media type,
//! because that is the shape of the confusion: IronAuth signs an ID token, an
//! access token, and a Logout Token with ONE environment key, under ONE issuer,
//! and the code flow gives the first two the same `aud`. Strip the `typ` header
//! and they are, byte for byte in every field a verifier looks at, the same
//! token. RFC 9068 section 4 is the specific rule (a resource server MUST reject
//! a JWT whose `typ` is not `at+jwt`); the general property is that no profile is
//! spendable where another is expected.
//!
//! The suite is a full CROSS PRODUCT rather than the one pair the issue named.
//! Asserting only "an ID token fails an access-token policy" would leave a Logout
//! Token, which carries `aud = client_id` and the `sid` the logout endpoint
//! reads, free to stand in for either.

mod common;

use ironauth_env::ManualClock;
use ironauth_jose::{
    EmissionOptions, ExpectedTyp, JwsAlgorithm, RejectReason, SigningKey, TokenTyp, TrustedKey,
    VerificationPolicy, sign_jws, verify,
};

/// The profiles IronAuth mints, as the cross product's axis.
///
/// Read from `TokenTyp::ALL`, which the crate's `token_profiles!` declaration
/// generates from the same list as the variants, rather than written out again here.
/// A second list would look stricter and be weaker: it would go on naming the
/// original three after a fourth profile was added, so the cross product would
/// silently stop covering the very profile nobody had thought about yet. Reading the
/// generated array means a fourth profile enters this suite the moment it exists, and
/// an aliasing one fails here.
const PROFILES: [TokenTyp; TokenTyp::ALL.len()] = TokenTyp::ALL;

/// A deterministic Ed25519 signer, from the fixed non-secret test seed.
fn signer() -> SigningKey {
    // A 32-byte Ed25519 seed in PKCS#8 v1 form is what the key loader takes; the
    // crate's own generator is used instead so this suite carries no key bytes.
    let (env, _clock) = ironauth_env::Env::deterministic(
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(common::NOW),
        7,
    );
    SigningKey::generate_ed25519(Some("confusion-1".to_owned()), env.entropy())
        .expect("the deterministic Ed25519 key generates")
}

fn trusted(key: &SigningKey) -> TrustedKey {
    key.verifying_key().expect("the signer publishes a key")
}

fn clock() -> ManualClock {
    common::now_clock()
}

/// The IDENTICAL claim set for every profile. Same `iss`, same `sub`, same `aud`,
/// same window: nothing but the header's media type distinguishes these tokens,
/// which is the point of the suite and is also what the real mint produces.
fn shared_claims() -> Vec<u8> {
    common::standard_claims().into_bytes()
}

/// Mint the shared claims under `typ`, through the same `with_token_typ` stamp
/// production uses.
fn mint(key: &SigningKey, typ: TokenTyp) -> String {
    sign_jws(
        key,
        &shared_claims(),
        &EmissionOptions::new().with_token_typ(typ),
    )
    .expect("sign")
}

fn policy_for(key: &SigningKey, expected: ExpectedTyp) -> VerificationPolicy {
    VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![trusted(key)],
        common::ISS,
        common::AUD,
        expected,
    )
    .expect("valid policy")
}

/// THE acceptance property: over the full cross product of the profiles IronAuth
/// mints, a token verifies under a policy if and only if the policy asked for
/// that exact profile.
///
/// Both directions are asserted in one loop on purpose. A suite that checked only
/// the rejections would pass if `typ` matching rejected everything, and a suite
/// that checked only the acceptances would pass if it enforced nothing at all.
#[test]
fn a_token_verifies_under_exactly_one_profile_policy_and_no_other() {
    let key = signer();
    for minted in PROFILES {
        let token = mint(&key, minted);
        for expected in PROFILES {
            let policy = policy_for(&key, ExpectedTyp::Required(expected));
            let outcome = verify(&token, &policy, &clock());
            if minted == expected {
                outcome.unwrap_or_else(|error| {
                    panic!(
                        "{minted:?} must verify under its own policy: {:?}",
                        error.reason()
                    )
                });
            } else {
                let error = outcome.err().unwrap_or_else(|| {
                    panic!("{minted:?} must NOT verify under a {expected:?} policy")
                });
                assert_eq!(
                    error.reason(),
                    RejectReason::TypMismatch,
                    "{minted:?} presented as {expected:?} is rejected FOR the media type, not \
                     incidentally by some other check"
                );
            }
        }
    }
}

/// The pair the issue names, spelled out on its own so the specific RFC 9068
/// section 4 rule has a test that says so by name and cannot be lost in a
/// refactor of the loop above.
#[test]
fn an_id_token_is_not_spendable_where_an_access_token_is_expected() {
    let key = signer();
    let id_token = mint(&key, TokenTyp::IdToken);
    let access_token = mint(&key, TokenTyp::AccessToken);

    let access_policy = policy_for(&key, ExpectedTyp::Required(TokenTyp::AccessToken));
    let id_policy = policy_for(&key, ExpectedTyp::Required(TokenTyp::IdToken));

    // The two tokens are otherwise indistinguishable: identical claims, identical
    // signing key. Asserting that here is what makes the rejections below mean
    // "the media type did it" rather than "some claim differed".
    assert_eq!(
        id_token.split('.').nth(1),
        access_token.split('.').nth(1),
        "the two profiles carry byte-identical claims, so typ is the only difference"
    );

    assert_eq!(
        verify(&id_token, &access_policy, &clock())
            .expect_err("an ID token is not an access token")
            .reason(),
        RejectReason::TypMismatch
    );
    assert_eq!(
        verify(&access_token, &id_policy, &clock())
            .expect_err("an access token is not an ID token")
            .reason(),
        RejectReason::TypMismatch
    );

    // And each still verifies as itself, so the check is a separator and not a
    // blanket refusal.
    verify(&id_token, &id_policy, &clock()).expect("the ID token is an ID token");
    verify(&access_token, &access_policy, &clock()).expect("the access token is an access token");
}

/// A token with NO `typ` at all satisfies no profile. Every IronAuth mint stamps
/// one, so an unstamped token did not come from the mint.
#[test]
fn a_token_with_no_typ_satisfies_no_profile() {
    let key = signer();
    let untyped = sign_jws(&key, &shared_claims(), &EmissionOptions::new()).expect("sign");
    for expected in PROFILES {
        let policy = policy_for(&key, ExpectedTyp::Required(expected));
        assert_eq!(
            verify(&untyped, &policy, &clock())
                .expect_err("a bare JWS names no profile")
                .reason(),
            RejectReason::TypMismatch,
            "{expected:?}"
        );
    }
}

/// The `ForeignIssuer` expectation is the ONLY way to accept an arbitrary media
/// type, and it is a value an author has to write. Asserting what it admits is
/// what keeps the escape hatch honest: it accepts every profile AND the untyped
/// token, so nobody can believe it is doing a partial check.
#[test]
fn the_foreign_issuer_expectation_admits_every_media_type() {
    let key = signer();
    let policy = policy_for(&key, ExpectedTyp::ForeignIssuer);
    for minted in PROFILES {
        verify(&mint(&key, minted), &policy, &clock())
            .unwrap_or_else(|_| panic!("{minted:?} verifies under a foreign-issuer policy"));
    }
    let untyped = sign_jws(&key, &shared_claims(), &EmissionOptions::new()).expect("sign");
    verify(&untyped, &policy, &clock()).expect("an untyped token verifies under ForeignIssuer");
}

/// The media type is matched as a MEDIA TYPE (RFC 2045 case-insensitive subtype,
/// RFC 7515 section 4.1.9 optional `application/` prefix), not as a byte string,
/// so a spec-legal spelling of the right profile is accepted and a spelling of a
/// DIFFERENT profile still is not.
#[test]
fn a_spec_legal_spelling_of_the_right_profile_is_accepted_and_a_wrong_one_is_not() {
    let key = signer();
    let access_policy = policy_for(&key, ExpectedTyp::Required(TokenTyp::AccessToken));

    for spelling in ["at+jwt", "AT+JWT", "application/at+jwt"] {
        let options = EmissionOptions::new().with_typ(spelling); // invariant-allow: typ-via-declaration -- the subject of this vector IS the alternative spellings a TokenTyp cannot itself produce
        let token = sign_jws(&key, &shared_claims(), &options).expect("sign");
        verify(&token, &access_policy, &clock())
            .unwrap_or_else(|_| panic!("{spelling} is a legal spelling of at+jwt"));
    }

    for spelling in ["JWT", "application/JWT", "logout+jwt", "at+jwt ", "atjwt"] {
        let options = EmissionOptions::new().with_typ(spelling); // invariant-allow: typ-via-declaration -- a deliberately wrong media type, which is the point
        let token = sign_jws(&key, &shared_claims(), &options).expect("sign");
        assert_eq!(
            verify(&token, &access_policy, &clock())
                .expect_err("not an access token")
                .reason(),
            RejectReason::TypMismatch,
            "{spelling}"
        );
    }
}

/// The media-type guard is a NARROWING check, never a widening one: it runs
/// before the signature check, so it can refuse a token early, but it can never
/// carry one past the signature. A forged header on an unsigned body is still a
/// rejection, and the reason proves which guard fired.
#[test]
fn the_media_type_guard_never_admits_an_unsigned_token() {
    let key = signer();
    let token = mint(&key, TokenTyp::AccessToken);
    // Corrupt the signature segment, leaving the (correct) `at+jwt` header alone.
    let mut segments: Vec<&str> = token.split('.').collect();
    let forged = format!("{}{}", segments.pop().expect("signature"), "AA");
    let tampered = format!("{}.{}.{forged}", segments[0], segments[1]);

    let policy = policy_for(&key, ExpectedTyp::Required(TokenTyp::AccessToken));
    assert_eq!(
        verify(&tampered, &policy, &clock())
            .expect_err("a right-typ token with a wrong signature is still rejected")
            .reason(),
        RejectReason::SignatureInvalid,
        "the media type passed and the signature check still ran"
    );
}

/// A non-string `typ` is malformed, not "no typ". A header that answered
/// `{"typ": 0}` with a silent `None` would let a hostile header choose between
/// two rejections; more importantly, a future relaxation of the absent case would
/// then silently relax the malformed one too.
#[test]
fn a_non_string_typ_is_malformed() {
    let signer = common::Ed25519Signer::new();
    let token = common::signed_ed25519(
        &signer,
        r#"{"alg":"EdDSA","kid":"ed25519-1","typ":0}"#,
        &common::standard_claims(),
    );
    let key = TrustedKey::ed25519(Some(common::ED25519_KID.to_owned()), signer.public_key())
        .expect("key");
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![key],
        common::ISS,
        common::AUD,
        ExpectedTyp::Required(TokenTyp::AccessToken),
    )
    .expect("valid policy");
    assert_eq!(
        verify(&token, &policy, &clock())
            .expect_err("a non-string typ is malformed")
            .reason(),
        RejectReason::HeaderMalformed
    );
}
