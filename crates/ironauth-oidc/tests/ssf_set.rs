// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security Event Token minting (issue #143).
//!
//! # What this owes
//!
//! A SET is the only thing a receiver ever sees, so the properties that matter are the ones a
//! receiver's parser depends on and cannot negotiate:
//!
//! - the RFC 8417 SHAPE: `iss`, `iat`, `jti`, `aud`, and an `events` object keyed by the event
//!   type URI. The claims are asserted DIRECTLY rather than read back through the verifier,
//!   because a test that only round-trips is comparing the mint to itself;
//! - the subject renders in the RFC 9493 format its stream negotiated, with the `format` member
//!   agreeing with the stored enum. A subject rendered under one format and labelled another is
//!   one the receiver resolves to the wrong person;
//! - the token really is signed by the environment's key and really carries `secevent+jwt`,
//!   which is checked by VERIFYING it through the same hardened core a relying party would.

use std::sync::Arc;
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, KeySet, SigningKey, SigningPolicy, VerificationPolicy, verify,
};
use ironauth_oidc::ssf_set::{
    EVENTS_SUPPORTED, SecurityEvent, SetToMint, SubjectIdentifier, build_set_claims, mint_set,
};
use ironauth_oidc::{IssuerEntry, IssuerRegistry, JwksCacheWindow, PairwiseSalt};
use ironauth_store::{EnvironmentId, Scope, SsfSubjectFormat, TenantId};

const ISSUER_BASE: &str = "https://issuer.example";

fn subject() -> SubjectIdentifier {
    SubjectIdentifier::IssSub {
        iss: "https://issuer.example/t/ten_x/e/env_x".to_owned(),
        sub: "usr_alice".to_owned(),
    }
}

fn event() -> SecurityEvent {
    SecurityEvent {
        event_type: "https://example.test/event-type/probe".to_owned(),
        payload: serde_json::Map::from_iter([(
            "reason".to_owned(),
            serde_json::Value::String("probe".to_owned()),
        )]),
    }
}

#[test]
fn the_claim_set_is_the_rfc_8417_shape() {
    let audience = vec!["https://receiver.example".to_owned()];
    let subject = subject();
    let event = event();
    let claims = build_set_claims(
        "https://issuer.example/t/ten_x/e/env_x",
        1_767_323_045,
        &SetToMint {
            audience: &audience,
            jti: "evt_0",
            subject: &subject,
            event: &event,
        },
    );

    assert_eq!(claims["iss"], "https://issuer.example/t/ten_x/e/env_x");
    assert_eq!(claims["iat"], 1_767_323_045_i64);
    assert_eq!(claims["jti"], "evt_0");

    // THE EVENT IS KEYED BY ITS TYPE URI, which is what a receiver dispatches on.
    let body = &claims["events"]["https://example.test/event-type/probe"];
    assert!(
        body.is_object(),
        "the event body must be an object: {claims}"
    );
    assert_eq!(body["reason"], "probe", "the caller's payload survives");
    assert_eq!(claims["sub_id"]["sub"], "usr_alice");

    // NO `exp`: SSF 1.0 section 4.1.7 makes that a MUST NOT, and RFC 8417 section 2.2 gives the
    // reason -- a SET is historical, and a receiver that was down through the window needs the
    // events it missed.
    assert!(claims.get("exp").is_none(), "a SET must not expire");
    // AND NO TOP-LEVEL `sub`. SSF 1.0 section 4.1.2 requires a SET's subject to travel as
    // `sub_id`; `sub` is the ID-token spelling and a receiver seeing it may read the token as
    // an authentication statement about that principal.
    assert!(
        claims.get("sub").is_none(),
        "the subject travels as sub_id, never as sub"
    );
}

#[test]
fn the_audience_is_an_array_even_when_there_is_one() {
    let audience = vec!["https://receiver.example".to_owned()];
    let subject = subject();
    let event = event();
    let claims = build_set_claims(
        "https://issuer.example",
        1,
        &SetToMint {
            audience: &audience,
            jti: "evt_0",
            subject: &subject,
            event: &event,
        },
    );
    // RFC 7519 permits the bare-string form for a single audience and receivers differ on
    // which they accept. Switching shapes on the COUNT would work against a receiver right up
    // to the day a second audience was configured, so the shape never varies.
    assert_eq!(
        claims["aud"],
        serde_json::json!(["https://receiver.example"])
    );
}

#[test]
fn each_format_renders_its_rfc_9493_members_and_labels_itself_with_the_stored_one() {
    let cases = [
        (
            SubjectIdentifier::Email {
                email: "alice@example.test".to_owned(),
            },
            SsfSubjectFormat::Email,
            serde_json::json!({ "format": "email", "email": "alice@example.test" }),
        ),
        (
            SubjectIdentifier::IssSub {
                iss: "https://issuer.example".to_owned(),
                sub: "usr_alice".to_owned(),
            },
            SsfSubjectFormat::IssSub,
            serde_json::json!({
                "format": "iss_sub",
                "iss": "https://issuer.example",
                "sub": "usr_alice",
            }),
        ),
        (
            SubjectIdentifier::Opaque {
                id: "opaque-handle".to_owned(),
            },
            SsfSubjectFormat::Opaque,
            serde_json::json!({ "format": "opaque", "id": "opaque-handle" }),
        ),
    ];
    for (identifier, stored, expected) in cases {
        assert_eq!(identifier.format(), stored, "{identifier:?}");
        assert_eq!(identifier.render(), expected, "{identifier:?}");
        // THE PAIRING. The rendered `format` and the stored enum are two spellings of one fact,
        // and this is the assertion that keeps them one: a subject rendered under one format
        // while labelled another is a subject the receiver resolves to the wrong person.
        assert_eq!(
            identifier.render()["format"],
            serde_json::Value::String(stored.as_str().to_owned()),
            "{identifier:?}"
        );
    }
}

#[test]
fn the_subject_is_a_top_level_sub_id_and_not_an_in_event_member() {
    // SSF 1.0 section 3.1.2 makes the top-level `sub_id` a MUST for a new event type and says
    // such a type MUST NOT name its primary subject with an in-event `subject`. The carve-out
    // in 3.1.1 is for event types already defined in CAEP or RISC; this build defines none.
    let audience = vec!["https://receiver.example.com".to_owned()];
    let subject = subject();
    let event = event();
    let claims = build_set_claims(
        "https://issuer.example",
        1,
        &SetToMint {
            audience: &audience,
            jti: "evt_0",
            subject: &subject,
            event: &event,
        },
    );
    assert_eq!(claims["sub_id"]["sub"], "usr_alice");
    assert_eq!(claims["sub_id"]["format"], "iss_sub");

    let body = &claims["events"]["https://example.test/event-type/probe"];
    assert_eq!(body["reason"], "probe", "the caller's payload survives");
    assert!(
        body.get("subject").is_none(),
        "the event carries an in-event subject, which 3.1.2 forbids: {claims}"
    );
}

#[test]
fn an_empty_audience_omits_the_claim_rather_than_minting_one_nobody_matches() {
    // An empty `aud` array is strictly worse than its absence: no receiver's audience check can
    // match it, so the SET would be undeliverable to everyone while looking well formed.
    let subject = subject();
    let event = event();
    let claims = build_set_claims(
        "https://issuer.example",
        1,
        &SetToMint {
            audience: &[],
            jti: "evt_0",
            subject: &subject,
            event: &event,
        },
    );
    assert!(claims.get("aud").is_none(), "{claims}");
}

/// The advertised event list is exactly what the surface emits, and nothing from a vocabulary.
///
/// The list was empty while nothing produced a SET. The verification endpoint changed that, so
/// this pins the new shape from BOTH sides: the verification type is present, and no CAEP or
/// RISC type is, because those vocabularies are the next issue's. Asserting only that the list
/// is non-empty would pass the day somebody advertised a type nothing emits, which is the
/// failure the original empty assertion existed to prevent.
#[test]
fn the_advertised_events_are_exactly_the_ones_this_build_emits() {
    assert_eq!(
        EVENTS_SUPPORTED,
        [ironauth_oidc::ssf_set::VERIFICATION_EVENT_TYPE],
        "the advertised event list is not the set this build can produce"
    );
    for advertised in EVENTS_SUPPORTED {
        assert!(
            !advertised.contains("/caep/") && !advertised.contains("/risc/"),
            "a CAEP or RISC event type is advertised before its vocabulary lands: {advertised}"
        );
    }
}

#[tokio::test]
async fn a_minted_set_verifies_against_the_environment_key_and_is_typed_secevent() {
    let env = Env::system();
    let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
    let registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(600));
    let key = SigningKey::ed25519_from_seed(Some("ssf-kid".to_owned()), &[0x21; 32]).expect("key");
    let public = key.verifying_key().expect("the public projection");
    registry.insert(
        scope,
        IssuerEntry::new(
            KeySet::bootstrap(key, SystemTime::UNIX_EPOCH),
            SigningPolicy::eddsa_default(),
            PairwiseSalt::new(Vec::new()),
            ironauth_store::GuardrailSet::for_kind(ironauth_store::EnvironmentType::Dev),
        ),
    );
    let registry = Arc::new(registry);

    let audience = vec!["https://receiver.example".to_owned()];
    let subject = subject();
    let event = event();
    let token = mint_set(
        &registry,
        &env,
        scope,
        &SetToMint {
            audience: &audience,
            jti: "evt_signed",
            subject: &subject,
            event: &event,
        },
    )
    .await
    .expect("mint the SET");

    // VERIFIED THROUGH THE SAME HARDENED CORE a relying party uses, against the key the
    // environment published, with the `typ` REQUIRED. A test that only decoded the payload
    // would pass over an unsigned token, a wrong key, and a missing media type alike.
    let issuer = registry.issuer_for(&scope);
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        vec![public],
        issuer.clone(),
        "https://receiver.example".to_owned(),
        ExpectedTyp::Required(ironauth_jose::TokenTyp::SecurityEventToken),
    )
    .expect("policy")
    // A SET CARRIES NO `exp`, so verifying one requires opting into its absence. Everything
    // else stays enforced: the signature, the EdDSA-only allowlist, the key, `iss`, `aud`, and
    // the required `secevent+jwt`.
    .allow_absent_exp(true);
    let verified = verify(&token, &policy, env.clock()).expect("the minted SET verifies");

    let claims = verified.claims();
    assert_eq!(
        claims.get("iss").and_then(serde_json::Value::as_str),
        Some(issuer.as_str())
    );
    assert_eq!(
        claims.get("jti").and_then(serde_json::Value::as_str),
        Some("evt_signed")
    );
    let events = claims.get("events").expect("the SET carries events");
    assert_eq!(
        events["https://example.test/event-type/probe"]["reason"],
        "probe"
    );
    assert_eq!(
        claims.get("sub_id").expect("the SET names its subject")["sub"],
        "usr_alice"
    );
}
