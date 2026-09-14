// SPDX-License-Identifier: MIT OR Apache-2.0

//! The corpus an INDEPENDENT receiver judges our CAEP events against (issue #144 criterion 1).
//!
//! # What this owes, and how it differs from `ssf_set_corpus`
//!
//! Criterion 1 asks that a public receiver "accepts and validates" the CAEP events this build
//! emits, with the evidence captured. `ssf_set_corpus` already hands an independent library one
//! SET per signing algorithm, and what that library judges is the ENVELOPE: is this a well
//! formed, correctly signed JWS whose claims verify against the published JWKS.
//!
//! A receiver judges something else. It reads the `events` map, finds a CAEP type it recognises,
//! and acts on what that event's own members say. An envelope can be flawless while the event
//! inside it is one no receiver can use -- two members under `events`, a subject in a format the
//! stream did not negotiate, an `event_timestamp` in milliseconds, a body that is not an object.
//! Those are exactly the divergences the CAEP Interoperability Profile exists to remove, and
//! none of them is a signature problem.
//!
//! So this mints one SET PER EMITTED CAEP EVENT TYPE, through the same mapping functions the
//! fan-out calls, and `scripts/validate-caep-receiver.py` judges them with rules written from
//! the profile rather than from this repository's code.
//!
//! # One type today, and the reason the others are absent is the point
//!
//! `session-revoked` is the only CAEP event this build emits. The other three in the vocabulary
//! have no producer, which `ssf_set::EVENTS_SUPPORTED` states and `caep`'s own tests enforce --
//! and the corpus covering exactly the advertised set is the same rule one level out. A case for
//! a type nothing emits would be validating a fixture.
//!
//! # Why a public receiver is not what runs in CI
//!
//! The criterion names caep.dev "or an equivalent". A build gate that posted to somebody else's
//! service would fail when that service was down, would say nothing when it changed, and would
//! send this deployment's events to a third party on every pull request. What it would buy is an
//! INDEPENDENT judgement, and that is what the validator is: it shares no line of code with this
//! repository, and its expectations come from the profile text rather than from the emitter.
//!
//! WHAT THIS IS NOT is a conformance certificate, exactly as
//! `caep_interop_profile.rs` says of itself. It is this deployment asserting, in CI and against
//! an outside judgement, that the events it emits are the shape a receiver can act on.
//!
//! # Every case is the EMITTER'S OWN OUTPUT
//!
//! The event bodies come from `caep::session_end_event` and `caep::map_domain_event`, not from
//! JSON written here. A corpus that hand-built its events would validate the fixture rather than
//! the emitter, and would go on passing after the emitter changed.

#![cfg(feature = "testing")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, KeySet, SigningKey, SigningPolicy, VerificationPolicy, verify,
};
use ironauth_oidc::ssf_set::{SecurityEvent, SetToMint, SubjectIdentifier, mint_set};
use ironauth_oidc::{IssuerEntry, IssuerRegistry, JwksCacheWindow, PairwiseSalt, caep};
use ironauth_store::{EnvironmentId, Scope, SessionEndCause, TenantId};

const ISSUER_BASE: &str = "https://issuer.example";
const AUDIENCE: &str = "https://receiver.example/set-endpoint";

/// One case: a CAEP event this build emits, produced by the code that emits it.
struct Case {
    /// Lowercase, filesystem-safe, and what the validator reports failures under.
    label: &'static str,
    event: SecurityEvent,
}

/// Every CAEP event type this build emits, each built by its own producer.
///
/// # The list is written here and CHECKED against the advertised set, in both directions
///
/// An earlier version of this doc said the list was "derived, not written twice". It was not:
/// this is a second hand-written list, and the only assertion over it compared the loop's own
/// push count to the list it had just iterated, which cannot fail. What keeps it honest is the
/// pair of checks in the test below -- every case must be ADVERTISED, and every advertised CAEP
/// type must have a CASE -- and the second is the one that catches a type this build starts
/// emitting and nobody adds here.
///
/// A LIST RATHER THAN A DERIVATION because each case needs its own PRODUCER: the point is that
/// the corpus is the emitter's output, and `EVENTS_SUPPORTED` carries type strings rather than
/// the functions that make them.
fn cases() -> Vec<Case> {
    vec![Case {
        label: "session-revoked",
        // THE REAL MAPPER, with a cause a real revocation carries. `Revoked` is the individual
        // case; the mapping's own tests cover all six, and what this corpus needs is one
        // instance of the event's SHAPE.
        event: caep::session_end_event(SessionEndCause::Revoked, "user", 1_700_000_000_000_000),
    }]
}

/// The CAEP types this build advertises, which is what the corpus must cover.
fn advertised_caep_types() -> Vec<&'static str> {
    ironauth_oidc::ssf_set::EVENTS_SUPPORTED
        .iter()
        .copied()
        .filter(|event_type| {
            event_type.starts_with("https://schemas.openid.net/secevent/caep/event-type/")
        })
        .collect()
}

/// Where the corpus lands. The gate sets `CAEP_RECEIVER_CORPUS_DIR`; a bare `cargo test` does not.
fn corpus_dir() -> PathBuf {
    std::env::var_os("CAEP_RECEIVER_CORPUS_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("caep-receiver-corpus"),
        PathBuf::from,
    )
}

/// Mint one SET per emitted CAEP event type and write each with the JWKS that environment
/// publishes.
///
/// The assertions here are the PRECONDITIONS of the external judgement rather than the judgement
/// itself: a corpus that is unsigned, or published under a JWKS missing the signing key, would
/// make the validator fail for a reason that says nothing about interoperability.
#[tokio::test]
async fn the_caep_receiver_corpus_is_minted_and_written() {
    let env = Env::system();
    let dir = corpus_dir();
    // A DROPPED CASE MUST NOT SURVIVE. Removing the tree first means the validator can treat
    // every directory it finds as this run's output; otherwise an event type removed from the
    // emitter would go on being validated from the last run's leftovers.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the corpus directory");

    let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(600));
    // ONE ALGORITHM, unlike `ssf_set_corpus`, and the difference is what each corpus is for.
    // That one varies the signature because the ENVELOPE is what it validates; this one varies
    // the EVENT and holds the envelope still, so a failure names the event rather than the key.
    let key = SigningKey::ed25519_from_seed(Some("caep-corpus".to_owned()), &[0x2c; 32])
        .expect("an Ed25519 key");
    let public = key.verifying_key().expect("the public projection");
    let policy = SigningPolicy::new(vec![JwsAlgorithm::EdDsa]).expect("a one-algorithm policy");
    registry.insert(
        scope,
        IssuerEntry::new(
            KeySet::bootstrap(key, SystemTime::UNIX_EPOCH),
            policy,
            PairwiseSalt::new(Vec::new()),
            ironauth_store::GuardrailSet::for_kind(ironauth_store::EnvironmentType::Dev),
        ),
    );
    let registry = Arc::new(registry);
    let issuer = registry.issuer_for(&scope);
    let jwks = registry
        .jwks_json(&scope, SystemTime::UNIX_EPOCH)
        .await
        .expect("the environment resolves")
        .expect("the JWKS renders");

    let mut written = Vec::new();
    for case in cases() {
        // ADVERTISED, or a receiver could not have asked for it. The other direction is pinned
        // in `caep`'s own tests; this is the one a corpus can see.
        assert!(
            ironauth_oidc::ssf_set::EVENTS_SUPPORTED.contains(&case.event.event_type.as_str()),
            "{} is in the corpus but not advertised, so no receiver could subscribe to it",
            case.event.event_type
        );

        let audience = vec![AUDIENCE.to_owned()];
        let subject = SubjectIdentifier::IssSub {
            iss: issuer.clone(),
            sub: format!("usr_{}", case.label),
        };
        let jti = format!("evt_caep_{}", case.label);
        let token = mint_set(
            &registry,
            &env,
            scope,
            &SetToMint {
                audience: &audience,
                jti: &jti,
                subject: &subject,
                event: &case.event,
            },
        )
        .await
        .expect("mint the SET");

        // PRECONDITION: it really is signed by the key the JWKS publishes. Checked through our
        // own verifier, which is what makes it a precondition rather than the test: if this
        // fails the corpus is broken and the external result would be meaningless.
        let verification = VerificationPolicy::new(
            vec![JwsAlgorithm::EdDsa],
            vec![public.clone()],
            issuer.clone(),
            AUDIENCE.to_owned(),
            ExpectedTyp::Required(ironauth_jose::TokenTyp::SecurityEventToken),
        )
        .expect("a verification policy")
        .allow_absent_exp(true);
        verify(&token, &verification, env.clock())
            .unwrap_or_else(|error| panic!("the {} SET does not verify: {error:?}", case.label));

        let case_dir = dir.join(case.label);
        std::fs::create_dir_all(&case_dir).expect("create the case directory");
        std::fs::write(case_dir.join("set.jwt"), &token).expect("write the token");
        std::fs::write(case_dir.join("jwks.json"), &jwks).expect("write the JWKS");
        // WHAT THE VALIDATOR COMPARES AGAINST, written by the MINTING side in the same run. A
        // validator holding its own copy of the issuer would keep passing after the issuer
        // stopped matching -- the same reason `ssf_set_corpus` writes this file.
        std::fs::write(
            case_dir.join("expect.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "iss": issuer,
                "aud": AUDIENCE,
                "jti": jti,
                "event_type": case.event.event_type,
                "subject_format": "iss_sub",
                "subject_sub": format!("usr_{}", case.label),
                "typ": "secevent+jwt",
            }))
            .expect("render the expectations"),
        )
        .expect("write the expectations");
        written.push(case.label);
    }

    // THE DIRECTION THAT CAN ACTUALLY FAIL: every CAEP type a receiver may subscribe to must
    // have a case here. The earlier version compared the loop's own push count to the list it
    // had just iterated, which is the same number by construction -- it would have gone on
    // passing while a newly emitted type was validated by nothing.
    for advertised in advertised_caep_types() {
        assert!(
            cases()
                .iter()
                .any(|case| case.event.event_type == advertised),
            "{advertised} is advertised to receivers and no corpus case validates it"
        );
    }
    assert!(
        !written.is_empty(),
        "an empty corpus would let the validator report success having judged nothing"
    );
}
