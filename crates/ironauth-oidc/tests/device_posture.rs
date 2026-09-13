// SPDX-License-Identifier: MIT OR Apache-2.0

//! Posture predicates over signed MDM claims (issue #145 criterion 5, EXPLORATORY).
//!
//! > Exploratory posture predicates evaluate signed claims from a fixture MDM source and deny
//! > on unsigned or stale claims.
//!
//! # How these are built, and why each negative varies ONE thing
//!
//! Every denial below starts from the SAME claim the allow case uses and changes exactly one
//! property of it: the signing key, the issuer, the `iat`, the signature's presence, a signal.
//! A negative that differs in two ways cannot say which one the module refused it for, and a
//! posture gate that denies for the wrong reason is indistinguishable from one that works
//! until the day the reason matters.
//!
//! The allow case comes FIRST for the same reason: every `Deny` assertion here is satisfied by
//! a module that denies everything.

use std::time::Duration;

use ironauth_env::ManualClock;
use ironauth_jose::{sign_jws, EmissionOptions, JwsAlgorithm, SigningKey};
use ironauth_oidc::device_posture::{
    now_secs, DenyReason, EdrState, PolicyBuildError, PostureSignals, PosturePolicy,
    PostureVerdict,
};
use serde_json::{json, Value};

const MDM: &str = "https://mdm.example.test";
const AUDIENCE: &str = "https://ironauth.example.test";
/// Five minutes. Short enough that a posture claim means "now" rather than "this week".
const MAX_AGE: i64 = 300;
/// Managed, encrypted, patched, and the agent actually reporting.
const STRICT: &str =
    "device.managed && device.encrypted && device.patched && device.edr == 'healthy'";

fn key(seed: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(format!("mdm-{seed}")), &[seed; 32]).expect("an ed25519 key")
}

fn policy(signer: &SigningKey, predicate: &str) -> PosturePolicy {
    PosturePolicy::new(
        MDM,
        AUDIENCE,
        vec![signer.verifying_key().expect("a public key")],
        vec![JwsAlgorithm::EdDsa],
        MAX_AGE,
        predicate,
    )
    .expect("the policy builds")
}

/// Healthy signals, as a compliant laptop would report them.
fn healthy() -> PostureSignals {
    PostureSignals {
        managed: true,
        encrypted: true,
        patched: true,
        edr: EdrState::Healthy,
    }
}

/// The claim body, with everything the allow case needs.
fn claims(issuer: &str, issued_at: i64, signals: &PostureSignals) -> Value {
    json!({
        "iss": issuer,
        "aud": AUDIENCE,
        "sub": "device-1",
        "iat": issued_at,
        "exp": issued_at + 86_400,
        "device_posture": serde_json::to_value(signals).expect("signals serialize"),
    })
}

fn signed(signer: &SigningKey, body: &Value) -> String {
    sign_jws(
        signer,
        serde_json::to_vec(body).expect("claims serialize").as_slice(),
        &EmissionOptions::new(),
    )
    .expect("sign")
}

/// A clock fixed far enough past the epoch that a claim can be BACKDATED without going
/// negative, which a claim minted at the epoch itself cannot.
fn clock() -> ManualClock {
    ManualClock::new(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
}

#[test]
fn a_fresh_signed_claim_from_the_mdm_is_allowed() {
    let signer = key(1);
    let clock = clock();
    let token = signed(&signer, &claims(MDM, now_secs(&clock), &healthy()));
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Allow,
        "the control: without this every denial below passes against a module that denies \
         everything"
    );
}

#[test]
fn an_absent_claim_is_denied_rather_than_skipped() {
    let signer = key(1);
    assert_eq!(
        policy(&signer, STRICT).evaluate(None, &clock()),
        PostureVerdict::Deny(DenyReason::Absent),
        "a posture gate that passes when the signal is missing enforces nothing on exactly \
         the devices that never reported"
    );
}

#[test]
fn an_unsigned_claim_is_denied() {
    let signer = key(1);
    let clock = clock();
    let body = claims(MDM, now_secs(&clock), &healthy());
    // `alg: none` with an EMPTY signature: the shape a forger reaches for first, and the one
    // a verifier that reads the header's own `alg` would accept.
    let unsigned = format!(
        "{}.{}.",
        base64_url(br#"{"alg":"none","typ":"JWT"}"#),
        base64_url(serde_json::to_vec(&body).expect("claims serialize").as_slice()),
    );
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&unsigned), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable)
    );
}

#[test]
fn a_claim_signed_by_another_key_is_denied() {
    let clock = clock();
    let token = signed(&key(2), &claims(MDM, now_secs(&clock), &healthy()));
    assert_eq!(
        policy(&key(1), STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "only the signing key differs from the allow case"
    );
}

#[test]
fn a_claim_from_another_issuer_is_denied() {
    let signer = key(1);
    let clock = clock();
    // SIGNED BY THE TRUSTED KEY and issued by somebody else. A vendor that runs one signing
    // key across tenants is the realistic version of this, and pinning the key alone would
    // admit every one of them.
    let token = signed(
        &signer,
        &claims("https://other-mdm.example.test", now_secs(&clock), &healthy()),
    );
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "only the issuer differs from the allow case"
    );
}

#[test]
fn a_stale_observation_is_denied_even_though_the_token_is_valid() {
    let signer = key(1);
    let clock = clock();
    let stale_at = now_secs(&clock) - MAX_AGE - 1;
    // `exp` IS A DAY OUT, deliberately. This is the case `ironauth_jose::verify` cannot catch
    // and the whole reason this module enforces an age of its own: the TOKEN is valid and the
    // OBSERVATION is old. An MDM minting week-long assertions over a Monday scan is not a
    // contrived fixture, it is the ordinary shape.
    let token = signed(&signer, &claims(MDM, stale_at, &healthy()));
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Stale {
            age_secs: MAX_AGE + 1,
            max_age_secs: MAX_AGE,
        }),
        "only `iat` differs from the allow case"
    );
}

#[test]
fn a_claim_one_second_inside_the_bound_is_still_allowed() {
    let signer = key(1);
    let clock = clock();
    // THE OTHER SIDE of the bound, so the staleness test above is measuring the bound rather
    // than the sign of a subtraction.
    let token = signed(&signer, &claims(MDM, now_secs(&clock) - MAX_AGE, &healthy()));
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Allow,
        "the bound is inclusive: a claim exactly at the limit has not yet exceeded it"
    );
}

#[test]
fn a_claim_with_no_issued_at_is_denied_rather_than_treated_as_fresh() {
    let signer = key(1);
    let clock = clock();
    let mut body = claims(MDM, now_secs(&clock), &healthy());
    body.as_object_mut().expect("an object").remove("iat");
    let token = signed(&signer, &body);
    // Refused by the VERIFIER, because the policy sets `require_iat`. Asserted here anyway:
    // what matters is that an unevaluable age denies, and this test fails if somebody relaxes
    // that flag believing the age check below would still catch it.
    assert!(
        matches!(
            policy(&signer, STRICT).evaluate(Some(&token), &clock),
            PostureVerdict::Deny(DenyReason::Unverifiable | DenyReason::NoIssuedAt)
        ),
        "a claim whose age cannot be decided must not be treated as fresh"
    );
}

#[test]
fn signals_that_do_not_satisfy_the_predicate_are_denied() {
    let signer = key(1);
    let clock = clock();
    let unpatched = PostureSignals {
        patched: false,
        ..healthy()
    };
    let token = signed(&signer, &claims(MDM, now_secs(&clock), &unpatched));
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::PredicateUnsatisfied),
        "only one signal differs from the allow case"
    );
}

#[test]
fn a_silent_agent_is_distinguishable_from_an_absent_one() {
    let signer = key(1);
    let clock = clock();
    // THE REASON `EdrState` IS NOT A BOOLEAN. A policy that cares about the difference can
    // express it; one that does not can write `!= 'absent'`. Collapsing the two states in the
    // schema would have decided this for every operator.
    let tolerant = policy(&signer, "device.edr != 'absent'");
    for (state, expected) in [
        (EdrState::Healthy, PostureVerdict::Allow),
        (EdrState::Silent, PostureVerdict::Allow),
        (
            EdrState::Absent,
            PostureVerdict::Deny(DenyReason::PredicateUnsatisfied),
        ),
    ] {
        let signals = PostureSignals {
            edr: state,
            ..healthy()
        };
        let token = signed(&signer, &claims(MDM, now_secs(&clock), &signals));
        assert_eq!(
            tolerant.evaluate(Some(&token), &clock),
            expected,
            "a tolerant predicate should separate {state:?} from the others"
        );
    }
    // And the STRICT predicate keeps them apart the other way.
    let strict = policy(&signer, STRICT);
    let silent = PostureSignals {
        edr: EdrState::Silent,
        ..healthy()
    };
    let token = signed(&signer, &claims(MDM, now_secs(&clock), &silent));
    assert_eq!(
        strict.evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::PredicateUnsatisfied),
        "a silent agent is not a healthy one"
    );
}

#[test]
fn a_claim_missing_a_signal_is_malformed_rather_than_false() {
    let signer = key(1);
    let clock = clock();
    let mut body = claims(MDM, now_secs(&clock), &healthy());
    body["device_posture"]
        .as_object_mut()
        .expect("an object")
        .remove("patched");
    let token = signed(&signer, &body);
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Malformed),
        "a MISSING signal must not decode as `false`: the verdict would be right by accident \
         here and wrong the moment a predicate says `!device.compromised`"
    );
}

#[test]
fn a_predicate_returning_a_non_boolean_is_refused_rather_than_coerced() {
    let signer = key(1);
    let clock = clock();
    let token = signed(&signer, &claims(MDM, now_secs(&clock), &healthy()));
    // CEL yields a string here. Every truthiness rule somebody might pick for that is a rule
    // the operator did not write.
    let odd = policy(&signer, "'yes'");
    assert_eq!(
        odd.evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::PredicateUnsatisfied)
    );
}

#[test]
fn a_freshness_bound_of_zero_is_refused_at_build() {
    let signer = key(1);
    assert_eq!(
        PosturePolicy::new(
            MDM,
            AUDIENCE,
            vec![signer.verifying_key().expect("a public key")],
            vec![JwsAlgorithm::EdDsa],
            0,
            STRICT,
        )
        .err(),
        Some(PolicyBuildError::MaxAgeNotPositive),
        "zero denies a claim minted this instant, which is a policy nobody can satisfy rather \
         than a strict one"
    );
}

/// Base64url without padding, for hand-building the unsigned token.
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
