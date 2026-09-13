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
    // TWO INDEPENDENT GUARDS refuse this, and the assertion tolerates either because the
    // behaviour is what matters: `require_iat` on the policy makes `verify` refuse it, and
    // `DenyReason::NoIssuedAt` refuses it if the flag is ever relaxed.
    //
    // MEASURED, and worth stating rather than leaving to be discovered: turning `require_iat`
    // off does NOT fail any test here, because the module's own check catches the same claim.
    // The flag is kept anyway -- the module should not depend on a policy setting for a fact
    // it can establish itself, and vice versa -- so its mutant is equivalent BY DESIGN rather
    // than by an oversight. Tightening this assertion to name which layer refused would pin an
    // internal division of labour instead of a guarantee.
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
fn a_predicate_that_cannot_evaluate_denies_rather_than_passing() {
    let signer = key(1);
    let clock = clock();
    let token = signed(&signer, &claims(MDM, now_secs(&clock), &healthy()));
    // THE ARM A REVIEWER FOUND UNTESTED, and it is a FAIL-OPEN if it goes wrong: replacing
    // `Err(_) => Deny` with `Err(_) => Allow` passed all thirteen tests that existed before
    // this one, while making every predicate below allow.
    //
    // The path is ordinary rather than exotic. `compile_within_budget` checks cost, not names,
    // so a predicate naming a signal the schema does not carry compiles and then fails at
    // EVALUATION -- and `!device.compromised`, which this file's own comment names as the
    // motivating future case, is exactly that shape. An operator who writes it against a
    // schema that has no `compromised` field gets a policy that would have admitted every
    // device.
    for predicate in [
        "!device.compromised",   // a field the schema does not carry
        "device.unknown",        // likewise
        "user.x",                // an unbound name entirely
        "device.managed + 1 == 2", // a type error
    ] {
        assert_eq!(
            policy(&signer, predicate).evaluate(Some(&token), &clock),
            PostureVerdict::Deny(DenyReason::PredicateFailed),
            "a predicate that cannot evaluate must DENY: {predicate}"
        );
    }
}

#[test]
fn a_verified_fresh_claim_carrying_no_signals_is_denied() {
    let signer = key(1);
    let clock = clock();
    // THE OTHER UNTESTED ARM, and the same shape: a token that verifies and is fresh and
    // simply has no `device_posture` claim at all. Mutating its deny to an allow also passed
    // the whole suite. An MDM that changed its claim name, or a token minted for another
    // purpose by the same issuer, lands here.
    let mut body = claims(MDM, now_secs(&clock), &healthy());
    body.as_object_mut()
        .expect("an object")
        .remove("device_posture");
    let token = signed(&signer, &body);
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Malformed),
        "a claim with no signals at all carries no evidence, and no evidence is not consent"
    );
}

#[test]
fn the_signals_reaching_the_predicate_are_the_decoded_ones() {
    let signer = key(1);
    let clock = clock();
    // The module decodes into `PostureSignals` and re-serialises THAT, rather than binding the
    // vendor's raw object. Measured: replacing the round trip with the raw claim passes every
    // other test, because every other fixture's claim happens to be exactly the schema.
    //
    // This one is not. It carries an extra vendor field and a differently-typed one, and the
    // predicate names the extra field: bound raw it would evaluate, bound decoded it cannot,
    // which is the whole point of having a schema.
    let mut body = claims(MDM, now_secs(&clock), &healthy());
    body["device_posture"]["vendor_risk_score"] = json!(11);
    let token = signed(&signer, &body);
    assert_eq!(
        policy(&signer, "device.vendor_risk_score < 50").evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::PredicateFailed),
        "a predicate naming a field OUTSIDE the schema must not silently start working \
         because one vendor happens to send it: that is how a vendor's field name becomes \
         part of our contract without anybody deciding it"
    );
    // And the schema's own fields still reach it from the same claim.
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Allow,
        "an unknown extra field is ignored rather than fatal"
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
fn a_claim_minted_for_another_audience_is_denied() {
    let signer = key(1);
    let clock = clock();
    // THE AUDIENCE PIN, which the module names as one of the things that makes
    // `ExpectedTyp::ForeignIssuer` safe here and which nothing was measuring. One MDM signing
    // for several relying parties is the ordinary deployment, so a posture assertion minted
    // for somebody else's tenant must not be replayable into this one.
    let mut body = claims(MDM, now_secs(&clock), &healthy());
    body["aud"] = json!("https://someone-else.example.test");
    let token = signed(&signer, &body);
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "only the audience differs from the allow case"
    );
}

#[test]
fn an_expensive_predicate_is_refused_at_build_rather_than_at_evaluation() {
    let signer = key(1);
    // THE COST BUDGET, the other named guarantee with no negative. A posture predicate reads a
    // handful of booleans off one flat object; anything that has to iterate is doing something
    // this surface is not for. Refusing at BUILD means an operator hears about it when they
    // write the policy rather than on the request that needed it.
    let expensive = "[1,2,3].all(a, [1,2,3].all(b, [1,2,3].all(c, \
                     [1,2,3].all(d, [1,2,3].all(e, a + b + c + d + e > 0)))))";
    assert!(
        matches!(
            PosturePolicy::new(
                MDM,
                AUDIENCE,
                vec![signer.verifying_key().expect("a public key")],
                vec![JwsAlgorithm::EdDsa],
                MAX_AGE,
                expensive,
            ),
            Err(PolicyBuildError::Predicate(_))
        ),
        "an expression past the budget has to be refused where it is written"
    );
    // AND AN ORDINARY PREDICATE IS NOT, so the budget is a ceiling rather than a wall.
    assert!(
        PosturePolicy::new(
            MDM,
            AUDIENCE,
            vec![signer.verifying_key().expect("a public key")],
            vec![JwsAlgorithm::EdDsa],
            MAX_AGE,
            STRICT,
        )
        .is_ok(),
        "the predicate this file uses everywhere else must fit the budget"
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
        "the bound is INCLUSIVE, so zero would allow a claim dated this second and deny one a \
         second older: a race against the clock's resolution rather than the strictest \
         possible policy it reads as"
    );
}

/// Base64url without padding, for hand-building the unsigned token.
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
