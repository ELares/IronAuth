// SPDX-License-Identifier: MIT OR Apache-2.0
//! The custom challenge triad, end to end against a real component (issue #114 criterion 6).
//!
//! > The custom challenge define/create/verify sample adds a working custom factor without
//! > modifications to the flow engine.
//!
//! This file holds the first half: the FACTOR works, driven exactly as a host would drive it.
//! Nothing here touches the flow engine, and that is the point being demonstrated rather than a
//! limitation of the test -- the whole factor is a component plus the three calls below.
//!
//! ## What a mock would not have caught
//!
//! Every test runs the component built from `guests/wordmark-challenge`, through the same
//! `HookEngine` and the same linker the `token.customize` hooks use. That shared path is the
//! claim most worth testing: a second world with its own engine would be a second sandbox to
//! audit, and the `with` clause in `challenge.rs` exists so there is only one.

use std::collections::BTreeMap;

use ironauth_hooks::{
    ChallengeAnswer, ChallengeContext, ChallengeDecision, ChallengeGrants, HookEngine, HookError,
    Limits,
};

const WORDMARK_CHALLENGE: &str = env!("IRONAUTH_GUEST_WORDMARK_CHALLENGE");

/// The tenant's configured word list, as the granted secret carries it.
const WORDS: &str = "harbour, lantern, meridian";

fn guest() -> Vec<u8> {
    std::fs::read(WORDMARK_CHALLENGE)
        .unwrap_or_else(|error| panic!("reading the wordmark guest: {error}"))
}

/// The grants a configured tenant would have made: the word list, nothing else.
fn granted() -> ChallengeGrants {
    ChallengeGrants {
        secrets: BTreeMap::from([("wordmark_list".to_owned(), WORDS.to_owned())]),
        fetch: None,
    }
}

fn context(round: u32, previous_passed: Option<bool>) -> ChallengeContext {
    ChallengeContext {
        payload_version: 1,
        subject: Some("sub_wordmark".to_owned()),
        client_id: "cli_wordmark".to_owned(),
        round,
        previous_passed,
    }
}

/// Run one call of the triad on its own thread with a deadline, so a MISSING bound fails rather
/// than hangs.
///
/// The bounds tests below assert that a runaway factor was STOPPED. If the mechanism they guard
/// regresses -- `store_for` stops setting fuel, say -- the call never returns, and a test that
/// simply awaited it would hang: CI would report a job timeout rather than the one-line failure
/// naming the bound that went missing. Mutation confirmed exactly that shape, which is why this
/// exists. It is the same guard `sandbox.rs` puts around `customize`, for the same reason.
fn bounded<T: Send>(
    call: impl FnOnce() -> Result<T, HookError> + Send,
) -> Result<Result<T, HookError>, &'static str> {
    std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let _ = sender.send(call());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .map_err(|_| "the call did not return within 20s, so its bound is not being applied")
    })
}

/// THE EXIT CRITERION: a whole factor runs, over two rounds, and the host learns nothing about
/// what the challenge is.
///
/// The loop below is what a flow engine would do, and it is written as a loop deliberately: the
/// host asks `define` what happens next, renders whatever `create` names, collects answers, and
/// asks `verify`. It never inspects `private_params`, never parses `public_params`, and has no
/// idea the factor is about words.
#[test]
fn a_custom_factor_runs_a_two_round_challenge_to_success() {
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&guest()).expect("load the factor");
    let limits = Limits::default();

    let mut round = 0_u32;
    let mut previous: Option<bool> = None;
    let mut prompts: Vec<String> = Vec::new();

    let outcome = loop {
        let ctx = context(round, previous);
        let decision = hook
            .define_challenge(&engine, &limits, &ctx, granted())
            .expect("define");
        match decision {
            ChallengeDecision::Succeed | ChallengeDecision::Fail(_) => break decision,
            ChallengeDecision::Challenge => {}
        }

        let spec = hook
            .create_challenge(&engine, &limits, &ctx, granted())
            .expect("create");
        prompts.push(spec.prompt.clone());

        // WHAT THE HOST WOULD RENDER, and all it knows: a prompt, some fields, and an opaque
        // public blob. The expected answer is in `private_params`, which is never read here.
        assert_eq!(spec.fields.len(), 1, "one input per round");
        assert_eq!(spec.fields[0].name, "wordmark");
        assert!(
            spec.fields[0].secret,
            "a shared-secret answer must be marked for masking, or it lands in a screenshot"
        );

        // THE USER ANSWERS. The test knows the word list because it configured the secret, which
        // is exactly the knowledge a real user has and the host does not.
        let expected = WORDS
            .split(',')
            .map(str::trim)
            .nth(usize::try_from(round).expect("small"))
            .expect("a word for this round");
        let passed = hook
            .verify_challenge(
                &engine,
                &limits,
                &ctx,
                &spec.private_params,
                &[ChallengeAnswer {
                    name: "wordmark".to_owned(),
                    value: expected.to_owned(),
                }],
                granted(),
            )
            .expect("verify");
        assert!(passed, "the right word must pass round {round}");

        previous = Some(passed);
        round += 1;
        assert!(round < 8, "the factor must terminate, not loop forever");
    };

    assert_eq!(
        outcome,
        ChallengeDecision::Succeed,
        "two correct rounds satisfy the factor"
    );
    assert_eq!(
        round, 2,
        "and it took TWO rounds: a factor that succeeded on the first would pass a test that \
         only asserted the outcome, and would not be exercising `define`'s round counting"
    );
    assert_eq!(
        prompts,
        vec!["wordmark.prompt".to_owned(), "wordmark.prompt".to_owned()],
        "each round rendered its own challenge"
    );
}

/// A WRONG ANSWER IS `Ok(false)`, AND IT ENDS THE FACTOR.
///
/// Two separate facts, and they are asserted separately because they live in different halves of
/// the component. `verify` returning false is the answer being wrong; `define` turning that into
/// `Fail` is the factor's POLICY, which another factor could write differently.
///
/// A wrong answer must not be an `Err`: that is reserved for the component failing to decide at
/// all, which gets the per-hook failure policy. Collapsing the two would mean a fail-open
/// deployment let a wrong answer through.
#[test]
fn a_wrong_answer_is_a_verdict_rather_than_an_error_and_ends_the_factor() {
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&guest()).expect("load the factor");
    let limits = Limits::default();
    let ctx = context(0, None);

    let spec = hook
        .create_challenge(&engine, &limits, &ctx, granted())
        .expect("create");
    let passed = hook
        .verify_challenge(
            &engine,
            &limits,
            &ctx,
            &spec.private_params,
            &[ChallengeAnswer {
                name: "wordmark".to_owned(),
                value: "not-the-word".to_owned(),
            }],
            granted(),
        )
        .expect("a wrong answer is a verdict, not an error");
    assert!(!passed, "the wrong word must not pass");

    let decision = hook
        .define_challenge(&engine, &limits, &context(0, Some(false)), granted())
        .expect("define");
    assert_eq!(
        decision,
        ChallengeDecision::Fail("the wordmark answer was wrong".to_owned()),
        "this factor ends on a wrong answer rather than retrying, and the reason it gives is \
         for the operator rather than the user"
    );
}

/// THE PRIVATE PARAMETERS ARE WHAT MAKE THE ANSWER CHECKABLE, AND THEY ARE NOT THE PUBLIC ONES.
///
/// The separation is the security property of the whole triad: put the expected answer in the
/// public half and the challenge publishes its own solution. This asserts the expected word is
/// in `private_params` and is NOT in `public_params`, which is the direction that fails if a
/// component author swaps them.
#[test]
fn the_expected_answer_rides_the_private_parameters_only() {
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&guest()).expect("load the factor");
    let spec = hook
        .create_challenge(&engine, &Limits::default(), &context(0, None), granted())
        .expect("create");

    assert!(
        spec.private_params.contains("harbour"),
        "the expected word must reach `verify`, which only gets the private half: {}",
        spec.private_params
    );
    assert!(
        !spec.public_params.contains("harbour"),
        "and it must NOT be in the half the client is shown, or the challenge ships its own \
         answer: {}",
        spec.public_params
    );
    assert!(
        spec.public_params.contains("position"),
        "the public half still has to carry enough for the user to answer at all: {}",
        spec.public_params
    );
}

/// A HANDED-BACK PARAMETER FROM ANOTHER ROUND DOES NOT VERIFY.
///
/// The host holds `private_params` and is trusted to hand back THIS round's. That trust is worth
/// a test, because the failure it guards against is silent: a host that reused round zero's
/// parameters forever would make the second round ask for a word the first round's answer
/// already satisfied, and the factor would still report success.
#[test]
fn a_round_verifies_against_its_own_parameters_and_not_another_rounds() {
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&guest()).expect("load the factor");
    let limits = Limits::default();

    let first = hook
        .create_challenge(&engine, &limits, &context(0, None), granted())
        .expect("create round 0");
    let second = hook
        .create_challenge(&engine, &limits, &context(1, Some(true)), granted())
        .expect("create round 1");
    assert_ne!(
        first.private_params, second.private_params,
        "the two rounds must ask for different words, or nothing here distinguishes them"
    );

    // Round 1's answer against round 0's parameters: the shape of a replay.
    let passed = hook
        .verify_challenge(
            &engine,
            &limits,
            &context(1, Some(true)),
            &first.private_params,
            &[ChallengeAnswer {
                name: "wordmark".to_owned(),
                value: "lantern".to_owned(),
            }],
            granted(),
        )
        .expect("verify");
    assert!(
        !passed,
        "round 1's answer must not satisfy round 0's challenge"
    );
}

/// DENY BY DEFAULT REACHES THE SECOND WORLD TOO.
///
/// The factor reads its word list from a GRANTED secret. Granted nothing, the component cannot
/// build a challenge at all and declines -- so a deployment that forgot the grant gets a clean
/// refusal with a reason, rather than a factor that quietly works with an empty list or one that
/// traps.
///
/// This is the criterion-2 property re-asserted on the criterion-6 world, and it is not
/// redundant: the two worlds are bound by separate `bindgen!` invocations, and a `with` clause
/// that had reused the wrong types would give this world its own, unpopulated `secrets` host.
#[test]
fn an_ungranted_factor_declines_rather_than_running_with_no_secret() {
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&guest()).expect("load the factor");

    let error = hook
        .create_challenge(
            &engine,
            &Limits::default(),
            &context(0, None),
            ChallengeGrants::none(),
        )
        .expect_err("a factor with no word list must not build a challenge");
    match error {
        HookError::Declined(reason) => assert!(
            reason.contains("wordmark_list"),
            "the refusal must name the secret the operator has to grant: {reason}"
        ),
        other @ HookError::Aborted { .. } => {
            panic!("expected a deliberate decline, got {other:?}")
        }
    }
}

/// EACH CALL IS ITS OWN INVOCATION, WITH ITS OWN BOUNDS.
///
/// `define` runs before `create`, and nothing survives between them. A component that stashed
/// the expected answer in a global would find it gone -- which is the correct outcome rather
/// than an inconvenience, because two concurrent logins in one process must not be able to see
/// each other's challenge.
///
/// Asserted through the observable consequence: two `create` calls with the SAME context produce
/// the same challenge, and the second one works with no `define` before it. A component holding
/// per-invocation state would need the sequence.
#[test]
fn the_three_calls_share_no_state() {
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&guest()).expect("load the factor");
    let limits = Limits::default();

    let first = hook
        .create_challenge(&engine, &limits, &context(0, None), granted())
        .expect("create with no define before it");
    let second = hook
        .create_challenge(&engine, &limits, &context(0, None), granted())
        .expect("create again");
    assert_eq!(
        first.private_params, second.private_params,
        "the same context must produce the same challenge: this factor is a pure function of \
         what it is handed, which is what makes holding the parameters host-side sound"
    );
}

/// EVERY ONE OF THE THREE CALLS IS BOUNDED BY FUEL.
///
/// Criterion 3's property, on criterion 6's world. The three entry points build three separate
/// stores, and the bounds are applied per store -- so this drives all three rather than one,
/// because a helper that set fuel for two of them would leave a hole exactly the size of the
/// third and every other test in this file would stay green.
///
/// FUEL RATHER THAN THE DEADLINE, deliberately: fuel is deterministic (it counts instructions),
/// while the deadline bounds wall time and needs a driver thread. The deadline has its own test
/// below; this one is the bound that cannot go flaky under CPU contention.
///
/// # What this test alone does NOT establish, measured rather than assumed
///
/// It does not distinguish "fuel was set to a small number" from "fuel was never set". Mutation
/// showed why: with `consume_fuel` configured, a store that is never given fuel starts at ZERO,
/// so a runaway aborts with the same `OutOfFuel` kind and this test still passes. Removing the
/// `set_fuel` line leaves it green.
///
/// What catches that is the HEALTHY-PATH tests above -- seven of them fail on the same mutant,
/// because a factor with no fuel cannot complete a challenge either. That is the right division
/// of labour and it is written down so a later reader does not over-credit this one: this test
/// pins that a runaway is STOPPED, and the working-factor tests pin that the bound is not so
/// tight it stops everything.
#[test]
fn fuel_bounds_all_three_calls_of_a_custom_factor() {
    let runaway = std::fs::read(env!("IRONAUTH_GUEST_RUNAWAY_CHALLENGE"))
        .unwrap_or_else(|error| panic!("reading the runaway guest: {error}"));
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&runaway).expect("load the runaway factor");
    // SMALL, so the abort arrives in milliseconds rather than seconds. The default is sized for
    // a real hook; a spinner needs only enough fuel to prove the meter is running.
    let limits = Limits {
        fuel: 2_000_000,
        ..Limits::default()
    };
    let ctx = context(0, None);

    let define = bounded(|| hook.define_challenge(&engine, &limits, &ctx, ChallengeGrants::none()))
        .expect("`define` must return")
        .expect_err("`define` must be bounded");
    let create = bounded(|| hook.create_challenge(&engine, &limits, &ctx, ChallengeGrants::none()))
        .expect("`create` must return")
        .expect_err("`create` must be bounded");
    let verify = bounded(|| {
        hook.verify_challenge(&engine, &limits, &ctx, "{}", &[], ChallengeGrants::none())
    })
    .expect("`verify` must return")
    .expect_err("`verify` must be bounded");

    for (name, error) in [("define", define), ("create", create), ("verify", verify)] {
        assert_eq!(
            error.abort_kind(),
            Some(ironauth_hooks::AbortKind::OutOfFuel),
            "`{name}` must abort on fuel rather than return or hang: {error}"
        );
    }
}

/// THE EPOCH DEADLINE REACHES THIS WORLD TOO.
///
/// The other half of criterion 3. Driven on one call rather than three: what this proves is that
/// `store_for` sets the deadline at all, and the fuel test above already proves the helper runs
/// for each of the three. Repeating a ticker thread three times would add wall-clock time to the
/// suite and assert the same line of code.
///
/// The fuel here is deliberately enormous so that fuel CANNOT be what stops the guest -- without
/// that, a passing test would say nothing about the deadline.
#[test]
fn the_epoch_deadline_bounds_a_custom_factor() {
    let runaway = std::fs::read(env!("IRONAUTH_GUEST_RUNAWAY_CHALLENGE"))
        .unwrap_or_else(|error| panic!("reading the runaway guest: {error}"));
    let engine = HookEngine::new().expect("build the engine");
    let hook = engine.load(&runaway).expect("load the runaway factor");
    let limits = Limits {
        fuel: 100_000_000_000,
        ..Limits::default()
    };

    let ticker_engine = engine.clone();
    let ticker = std::thread::spawn(move || {
        for _ in 0..200 {
            std::thread::sleep(std::time::Duration::from_millis(5));
            ticker_engine.tick();
        }
    });
    let error = bounded(|| {
        hook.define_challenge(&engine, &limits, &context(0, None), ChallengeGrants::none())
    })
    .expect("the deadline must stop it")
    .expect_err("a factor past its deadline must not return");
    ticker.join().expect("ticker");
    assert_eq!(
        error.abort_kind(),
        Some(ironauth_hooks::AbortKind::DeadlineExceeded),
        "the deadline, not fuel, must be what stopped it: {error}"
    );
}
