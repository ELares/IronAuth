// SPDX-License-Identifier: MIT OR Apache-2.0

//! Posture predicates over signed MDM claims (issue #145 criterion 5, EXPLORATORY).
//!
//! > Exploratory posture predicates evaluate signed claims from a fixture MDM source and deny
//! > on unsigned or stale claims.
//!
//! # How these are built, and why each negative varies ONE thing
//!
//! Most denials below start from the SAME claim the allow case uses and change exactly one
//! property of it: the key material, the key identifier, the issuer, the audience, the `iat`,
//! one signal. A negative that differs in two ways cannot say which one the module refused it
//! for, and a posture gate that denies for the wrong reason is indistinguishable from one that
//! works until the day the reason matters.
//!
//! MOST, not all, and the exceptions are worth naming because the first version of this
//! paragraph said "every" and was wrong about six of them. The unsigned case rebuilds the
//! token by hand rather than varying a field. The predicate cases vary the POLICY instead of
//! the claim. The malformed cases remove or add a member of the signals object. None of those
//! can be expressed as one changed field of a signed claim, and pretending otherwise was how
//! `a_claim_signed_by_another_key_is_denied` came to vary two properties and measure neither:
//! it was refused at key SELECTION, and no signature was ever checked.
//!
//! The allow case comes FIRST for the same reason: every `Deny` assertion here is satisfied by
//! a module that denies everything.

use std::time::Duration;

use ironauth_env::ManualClock;
use ironauth_jose::{EmissionOptions, JwsAlgorithm, SigningKey, sign_jws};
use ironauth_oidc::device_posture::{
    DenyReason, EdrState, PolicyBuildError, PosturePolicy, PostureSignals, PostureVerdict, now_secs,
};
use serde_json::{Value, json};

const MDM: &str = "https://mdm.example.test";
const AUDIENCE: &str = "https://ironauth.example.test";
/// Five minutes. Short enough that a posture claim means "now" rather than "this week".
const MAX_AGE: i64 = 300;
/// Managed, encrypted, patched, and the agent actually reporting.
const STRICT: &str =
    "device.managed && device.encrypted && device.patched && device.edr == 'healthy'";

fn key(seed: u8) -> SigningKey {
    keyed(&format!("mdm-{seed}"), seed)
}

/// A key with the `kid` and the MATERIAL chosen separately.
///
/// The two are decoupled because tying them made a negative vary two dimensions at once:
/// `key(2)` differs from `key(1)` in both, so jose refused it at key SELECTION -- `UnknownKid`,
/// before any signature was checked -- and the test that claimed to measure a forgery measured
/// a lookup. `SignatureInvalid` was produced by nothing in this file.
fn keyed(kid: &str, seed: u8) -> SigningKey {
    SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[seed; 32]).expect("an ed25519 key")
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
        serde_json::to_vec(body)
            .expect("claims serialize")
            .as_slice(),
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
        base64_url(
            serde_json::to_vec(&body)
                .expect("claims serialize")
                .as_slice()
        ),
    );
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&unsigned), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable)
    );
}

#[test]
fn a_claim_signed_by_another_key_is_denied() {
    let clock = clock();
    // THE SAME `kid`, DIFFERENT MATERIAL. That is what makes this a forgery rather than a
    // lookup failure: the token names the key the policy trusts, so verification proceeds to
    // the signature and refuses it there. Signed by `key(2)` instead, this test passed without
    // any signature ever being checked.
    let forger = keyed("mdm-1", 2);
    let token = signed(&forger, &claims(MDM, now_secs(&clock), &healthy()));
    assert_eq!(
        policy(&key(1), STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "only the key MATERIAL differs from the allow case"
    );
}

#[test]
fn a_claim_naming_a_key_the_policy_does_not_hold_is_denied() {
    let clock = clock();
    // The lookup failure, kept as its own case now that it is no longer standing in for the
    // forgery above. An MDM rotating to a key this deployment has not been given lands here.
    //
    // `keyed("mdm-unknown", 1)` and not `key(2)`: the SAME material under an unknown name, so
    // this varies the identifier alone. Written with `key(2)` it varied both, which is the
    // exact defect round 2 fixed one test up and left standing here -- and the helper that
    // makes the one-dimension form available was already sitting there unused.
    let rotated = keyed("mdm-unknown", 1);
    let token = signed(&rotated, &claims(MDM, now_secs(&clock), &healthy()));
    assert_eq!(
        policy(&key(1), STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "only the key IDENTIFIER differs from the allow case"
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
        &claims(
            "https://other-mdm.example.test",
            now_secs(&clock),
            &healthy(),
        ),
    );
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "only the issuer differs from the allow case"
    );
}

#[test]
fn a_clock_that_cannot_be_read_denies_rather_than_dating_everything_to_the_epoch() {
    let signer = key(1);
    // A HOST whose clock is set before 1970. `SystemTime` permits it and `duration_since`
    // reports it as an error, and the first version answered that error with `map_or(0, ..)`
    // -- making `now` the epoch, every age negative, and the freshness bound inert. A fallback
    // that silences an error by choosing a value is a fail-open wearing a default's clothes.
    //
    // Measured: without this test, replacing the refusal with `unwrap_or_default()` passes the
    // whole suite, because every other fixture's clock is after the epoch.
    let broken = ManualClock::new(std::time::UNIX_EPOCH - Duration::from_secs(1));
    let good = clock();
    // The claim itself is impeccable: minted now, by the trusted key, for this audience.
    let token = signed(&signer, &claims(MDM, now_secs(&good), &healthy()));
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &broken),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "a host that cannot say what time it is cannot say whether an observation is fresh"
    );
    // THE REASON IS THE VERIFIER'S, and that is the third time in this PR the layer below
    // turned out to enforce the thing a new arm was written for. `verify` reads the SAME clock
    // to check `iat`, so a claim minted in 2023 is wildly outside skew against a 1969 clock and
    // never reaches this module's own check.
    //
    // The module's `UnreadableClock` arm is kept anyway, and the difference from the other two
    // is the whole point: `NoIssuedAt` and `FutureDated` were removed because an unreachable
    // arm that DENIES is redundant with a guard that already denies. This one replaced a
    // `map_or(0, ..)` that failed OPEN -- it made `now` the epoch and every age negative, so
    // the freshness bound went inert. Unreachable-and-fail-closed is a backstop; the thing it
    // replaced was unreachable-and-fail-open, which is a bug. Keeping it costs a branch and
    // removes the chance that a future refactor reintroduces the default.
}

#[test]
fn a_future_dated_observation_is_denied_rather_than_counted_as_fresh() {
    let signer = key(1);
    let clock = clock();
    // `age_secs` GOES NEGATIVE for a claim dated ahead of this clock, and `age > max_age` is
    // then false -- so before this, a posture assertion stamped a year from now passed the
    // freshness bound. That is the claim an MDM with a broken clock emits, and the one anybody
    // who can choose `iat` would emit on purpose.
    let ahead = now_secs(&clock) + 86_400;
    let token = signed(&signer, &claims(MDM, ahead, &healthy()));
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
        "only `iat` differs from the allow case, and it is in the future. `verify` refuses it \
         before this module sees it, which is why the module has no arm of its own: one was \
         written, found unreachable, and removed -- the same two-guards shape that made the \
         `NoIssuedAt` arm unmeasurable a round earlier"
    );
    // WITHIN SKEW IS STILL FRESH, so the bound above is the skew allowance rather than a
    // refusal of every clock disagreement.
    let slightly_ahead = now_secs(&clock) + 5;
    let token = signed(&signer, &claims(MDM, slightly_ahead, &healthy()));
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Allow,
        "two clocks a few seconds apart is the ordinary case, not an attack"
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
    let token = signed(
        &signer,
        &claims(MDM, now_secs(&clock) - MAX_AGE, &healthy()),
    );
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
    // ONE GUARD, and naming it is the point. The first version had two -- `require_iat` on the
    // policy and a `NoIssuedAt` arm in the module -- and a reviewer measured what that cost:
    // each made the other unmeasurable. Dropping `require_iat` failed nothing, because the arm
    // caught the same claim; and the arm was UNREACHABLE, so mutating it to an allow also
    // failed nothing. Two guards for one fact, neither pinned.
    //
    // So `require_iat` is the guard, the arm is gone, and this asserts the reason it produces.
    // Dropping the flag now fails here.
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&token), &clock),
        PostureVerdict::Deny(DenyReason::Unverifiable),
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
fn every_signal_is_read_from_its_own_name_and_reaches_the_predicate() {
    let signer = key(1);
    let clock = clock();
    // THE FINDING THIS EXISTS FOR, and it is the sharpest of the three rounds. Before it, only
    // `patched` and `edr` were ever presented as anything but healthy, so `managed` and
    // `encrypted` were unmeasured from the wire to the verdict. A reviewer measured what that
    // permitted: hardcoding `"managed": true` and `"encrypted": true` in the CEL binding left
    // all twenty tests green while an UNENROLLED, UNENCRYPTED device was allowed. So did
    // hardcoding them in the decoder, and so did swapping any two of the three booleans at
    // either site.
    //
    // Worse, round 2 caused half of it: hand-writing `Deserialize` to close the positional
    // array hole DOUBLED the number of places a name is paired with a value by hand, and the
    // doc block justifying that change is the one warning about exactly this swap.
    //
    // One case per signal, each under a predicate naming only that signal, so a pairing that
    // stops reading its field or starts reading a neighbour's fails HERE rather than in a
    // deployment.
    for (name, predicate, signals) in [
        (
            "managed",
            "device.managed",
            PostureSignals {
                managed: false,
                ..healthy()
            },
        ),
        (
            "encrypted",
            "device.encrypted",
            PostureSignals {
                encrypted: false,
                ..healthy()
            },
        ),
        (
            "patched",
            "device.patched",
            PostureSignals {
                patched: false,
                ..healthy()
            },
        ),
        (
            "edr",
            "device.edr == 'healthy'",
            PostureSignals {
                edr: EdrState::Absent,
                ..healthy()
            },
        ),
    ] {
        let token = signed(&signer, &claims(MDM, now_secs(&clock), &signals));
        assert_eq!(
            policy(&signer, predicate).evaluate(Some(&token), &clock),
            PostureVerdict::Deny(DenyReason::PredicateUnsatisfied),
            "a device reporting {name} as unhealthy was allowed by a predicate that reads \
             only {name}"
        );
        // AND THE SAME PREDICATE ADMITS THE HEALTHY DEVICE, so the denial above is this
        // signal's value and not a predicate that refuses everything.
        let healthy_token = signed(&signer, &claims(MDM, now_secs(&clock), &healthy()));
        assert_eq!(
            policy(&signer, predicate).evaluate(Some(&healthy_token), &clock),
            PostureVerdict::Allow,
            "the predicate reading only {name} must admit a device that is healthy in it"
        );
    }
}

#[test]
fn the_wire_names_are_the_contract() {
    let signer = key(1);
    let clock = clock();
    // THE JSON AN MDM ACTUALLY SENDS, spelled out once. Every other fixture builds the signals
    // through `PostureSignals`, so both sides of the pairing move together and renaming a
    // field on both would pass: measured, `managed` -> `enrolled` in the decoder AND the
    // binding left the suite green. A vendor integrating against this needs to know which
    // spellings we read, and this is where that is written down.
    let body = json!({
        "iss": MDM,
        "aud": AUDIENCE,
        "sub": "device-1",
        "iat": now_secs(&clock),
        "exp": now_secs(&clock) + 86_400,
        "device_posture": {
            "managed": true,
            "encrypted": true,
            "patched": true,
            "edr": "healthy",
        },
    });
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&signed(&signer, &body)), &clock),
        PostureVerdict::Allow,
        "the wire form an MDM sends has to be the one this reads"
    );
    // And a claim spelling one of them differently is NOT read as that signal.
    let mut renamed = body.clone();
    let posture = renamed["device_posture"]
        .as_object_mut()
        .expect("an object");
    let value = posture.remove("managed").expect("managed present");
    posture.insert("enrolled".to_owned(), value);
    assert_eq!(
        policy(&signer, STRICT).evaluate(Some(&signed(&signer, &renamed)), &clock),
        PostureVerdict::Deny(DenyReason::Malformed),
        "a signal under a different name is a MISSING signal, not a present one"
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
            "a tolerant predicate admits healthy AND silent and refuses absent; it does not \
             separate the first two, which is the point of it being tolerant: {state:?}"
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
        "!device.compromised",     // a field the schema does not carry
        "device.unknown",          // likewise
        "user.x",                  // an unbound name entirely
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
    // This one is not. It carries an extra vendor field, and the predicate names that field:
    // bound raw it would evaluate, bound decoded it cannot, which is the whole point of having
    // a schema. (An earlier version of this comment also claimed a "differently-typed" field;
    // the fixture never had one.)
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
    // THE COST BUDGET, and the expression is chosen to pin THIS budget rather than any budget.
    //
    // The first version used a five-deep comprehension estimating 262 billion, which is over
    // every plausible ceiling: measured, raising `PREDICATE_BUDGET` from 1_000 all the way to
    // the crate's own default of 1_000_000_000 left the whole suite green, and the first value
    // that failed was 262_144_000_000. The test named the module's budget and pinned the range
    // [1, 262_143_999_999].
    //
    // A TWO-DEEP comprehension estimates 4_096: over 1_000, and far under the crate default.
    // So this now fails if the module's budget is relaxed to the default, which is the only
    // change anybody is likely to make.
    let expensive = "[device.managed].all(x, [device.encrypted].all(y, x && y))";
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
    //
    // Worth being exact about what the ceiling bites on: `estimate_parsed_cost` returns 1 for
    // any comprehension-free expression, so no flat predicate over these signals can ever
    // exceed it at any budget. The budget constrains ITERATION depth and nothing else, and a
    // single-level comprehension still fits. The module comment used to imply more than that.
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

#[test]
fn signals_do_not_decode_from_a_positional_array() {
    // A reviewer found this: serde's derived `Deserialize` for a struct ACCEPTS a JSON array,
    // matching fields by POSITION. If that holds here then field ORDER is part of the wire
    // contract -- reordering two booleans in the struct silently reinterprets every array-form
    // claim, and `[true,true,false,"healthy"]` means something different after a refactor that
    // touched no serialisation code at all.
    let from_array: Result<PostureSignals, _> =
        serde_json::from_str(r#"[true,true,true,"healthy"]"#);
    assert!(
        from_array.is_err(),
        "a posture claim has to be an OBJECT: decoding an array by position makes field order \
         a contract nobody wrote down"
    );
}
