// SPDX-License-Identifier: MIT OR Apache-2.0

//! The corpus an INDEPENDENT library validates our Security Event Tokens against (issue #143).
//!
//! # What this owes
//!
//! #143's criterion is that emitted SETs "validate with an external, independent JWT/SET library
//! against the environment JWKS". `ssf_set.rs` already verifies a minted SET, but it verifies it
//! through `ironauth-jose` -- the same code that signed it. One implementation checked against
//! itself agrees with itself: a shared misreading of RFC 8417 or RFC 7515 passes both directions,
//! and a receiver built on any other library is the first to find out.
//!
//! So this file MINTS and WRITES, and `scripts/validate-set-external.py` reads what it wrote and
//! validates with `PyJWT`, which shares no line of code with this repository. The split is
//! deliberate: the assertions here are the ones a corpus must satisfy to be worth validating (it
//! is signed, it is the right shape, the JWKS really carries the key that signed it), and the
//! external judgement lives outside this process entirely.
//!
//! # The matrix is the one an environment actually gets
//!
//! `DayOneSigningKeys` provisions `EdDSA`, ES256 and RS256, so those are the three families a
//! deployment can sign a SET with, and each is minted here under a policy that PREFERS it. A
//! corpus covering only the default would leave the other two unvalidated while the discovery
//! document went on advertising them.
//!
//! # Where it writes
//!
//! `SSF_SET_CORPUS_DIR` when set, which is how the gate script points it at a temporary
//! directory it then hands to the validator; otherwise `CARGO_TARGET_TMPDIR`, so running this
//! test on its own still produces a corpus somebody can look at.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use ironauth_env::Env;
use ironauth_jose::{
    ExpectedTyp, JwsAlgorithm, KeySet, SigningKey, SigningPolicy, VerificationPolicy, verify,
};
use ironauth_oidc::ssf_set::{SecurityEvent, SetToMint, SubjectIdentifier, mint_set};
use ironauth_oidc::{IssuerEntry, IssuerRegistry, JwksCacheWindow, PairwiseSalt};
use ironauth_store::{EnvironmentId, Scope, TenantId};

const ISSUER_BASE: &str = "https://issuer.example";
const AUDIENCE: &str = "https://receiver.example/set-endpoint";
const EVENT_TYPE: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

/// One entry in the corpus: an algorithm, and the key an environment would hold for it.
struct Case {
    alg: JwsAlgorithm,
    /// Lowercase, filesystem-safe, and what the validator reports failures under.
    label: &'static str,
    key: SigningKey,
}

fn cases(env: &Env) -> Vec<Case> {
    // DETERMINISTIC WHERE IT CAN BE. The Ed25519 seed is fixed so a corpus diff is readable;
    // ECDSA and RSA keys are generated because this repository has no fixed-key constructor for
    // them, and a hand-pasted DER blob in a test file is a key nobody can regenerate.
    let ed25519 = SigningKey::ed25519_from_seed(Some("set-eddsa".to_owned()), &[0x4c; 32])
        .expect("an Ed25519 key");
    let p256_der =
        ironauth_jose::generate_ecdsa_p256_pkcs8_der(env.entropy()).expect("generate a P-256 key");
    let es256 = SigningKey::ecdsa_p256_from_pkcs8(Some("set-es256".to_owned()), &p256_der)
        .expect("a P-256 key");
    let rsa_der =
        ironauth_jose::generate_rsa_pkcs1_der(env.entropy()).expect("generate an RSA key");
    let rs256 =
        SigningKey::rsa_from_pkcs1_der(Some("set-rs256".to_owned()), JwsAlgorithm::Rs256, &rsa_der)
            .expect("an RSA key");

    vec![
        Case {
            alg: JwsAlgorithm::EdDsa,
            label: "eddsa",
            key: ed25519,
        },
        Case {
            alg: JwsAlgorithm::Es256,
            label: "es256",
            key: es256,
        },
        Case {
            alg: JwsAlgorithm::Rs256,
            label: "rs256",
            key: rs256,
        },
    ]
}

/// Where the corpus lands. The gate sets `SSF_SET_CORPUS_DIR`; a bare `cargo test` does not.
fn corpus_dir() -> PathBuf {
    std::env::var_os("SSF_SET_CORPUS_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ssf-set-corpus"),
        PathBuf::from,
    )
}

/// Mint one SET per signing algorithm an environment can hold, and write each with the JWKS that
/// environment publishes.
///
/// The assertions here are the PRECONDITIONS of the external check rather than the check itself.
/// A corpus that is unsigned, misshapen, or published under a JWKS missing the signing key would
/// make the validator fail for a reason that says nothing about interoperability, so each is
/// ruled out before the file is written.
#[tokio::test]
async fn the_external_validation_corpus_is_minted_and_written() {
    let env = Env::system();
    let dir = corpus_dir();
    // A STALE CASE MUST NOT SURVIVE A RENAME. Removing the tree first means the validator can
    // treat every directory it finds as this run's output; otherwise an algorithm dropped from
    // the matrix would go on being validated from the last run's leftovers.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the corpus directory");

    let mut written = Vec::new();
    for case in cases(&env) {
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        let registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(600));
        let public = case.key.verifying_key().expect("the public projection");
        // ONE ALGORITHM PER ENVIRONMENT, so the preferred signer is the one under test. A policy
        // listing all three would mint three EdDSA tokens and report them as a matrix.
        let policy = SigningPolicy::new(vec![case.alg]).expect("a one-algorithm policy");
        registry.insert(
            scope,
            IssuerEntry::new(
                KeySet::bootstrap(case.key, SystemTime::UNIX_EPOCH),
                policy,
                PairwiseSalt::new(Vec::new()),
                ironauth_store::GuardrailSet::for_kind(ironauth_store::EnvironmentType::Dev),
            ),
        );
        let registry = Arc::new(registry);
        let issuer = registry.issuer_for(&scope);

        let audience = vec![AUDIENCE.to_owned()];
        let subject = SubjectIdentifier::IssSub {
            iss: issuer.clone(),
            sub: format!("usr_{}", case.label),
        };
        let event = SecurityEvent {
            event_type: EVENT_TYPE.to_owned(),
            payload: serde_json::Map::from_iter([(
                "initiating_entity".to_owned(),
                serde_json::Value::String("policy".to_owned()),
            )]),
        };
        let jti = format!("evt_corpus_{}", case.label);
        let token = mint_set(
            &registry,
            &env,
            scope,
            &SetToMint {
                audience: &audience,
                jti: &jti,
                subject: &subject,
                event: &event,
            },
        )
        .await
        .expect("mint the SET");

        // PRECONDITION 1: it is really signed with this algorithm, by this key. Checked through
        // our own verifier, which is exactly what makes it a precondition and not the test: if
        // this fails, the corpus is broken and the external result would be meaningless.
        let verification = VerificationPolicy::new(
            vec![case.alg],
            vec![public],
            issuer.clone(),
            AUDIENCE.to_owned(),
            ExpectedTyp::Required(ironauth_jose::TokenTyp::SecurityEventToken),
        )
        .expect("a verification policy")
        .allow_absent_exp(true);
        verify(&token, &verification, env.clock())
            .unwrap_or_else(|error| panic!("the {} SET does not verify: {error:?}", case.label));

        // PRECONDITION 2: the JWKS an external validator would fetch really carries the key that
        // signed it. Published through the registry rather than assembled here, so this is the
        // document the environment actually serves at its `jwks_uri`.
        let jwks = registry
            .jwks_json(&scope, SystemTime::UNIX_EPOCH)
            .await
            .expect("the environment resolves")
            .expect("the JWKS renders");
        let parsed: serde_json::Value = serde_json::from_str(&jwks).expect("the JWKS is JSON");
        let keys = parsed["keys"].as_array().expect("the JWKS has a key array");
        assert_eq!(
            keys.len(),
            1,
            "the {} environment published {} keys; the corpus assumes the one it signed with",
            case.label,
            keys.len()
        );

        let case_dir = dir.join(case.label);
        std::fs::create_dir_all(&case_dir).expect("create the case directory");
        std::fs::write(case_dir.join("set.jwt"), &token).expect("write the token");
        std::fs::write(case_dir.join("jwks.json"), &jwks).expect("write the JWKS");
        // WHAT THE VALIDATOR MUST FIND, written by the minting side so the validator asserts
        // against this run rather than against constants it keeps its own copy of. A validator
        // holding its own expected `iss` would keep passing after the issuer stopped matching.
        let expectations = serde_json::json!({
            "alg": case.alg.as_jose_name(),
            "iss": issuer,
            "aud": AUDIENCE,
            "jti": jti,
            "event_type": EVENT_TYPE,
            "subject_format": "iss_sub",
            "subject_sub": format!("usr_{}", case.label),
            "typ": "secevent+jwt",
        });
        std::fs::write(
            case_dir.join("expect.json"),
            serde_json::to_string_pretty(&expectations).expect("render the expectations"),
        )
        .expect("write the expectations");
        written.push(case.label);
    }

    assert_eq!(
        written,
        vec!["eddsa", "es256", "rs256"],
        "the corpus does not cover the algorithms a provisioned environment holds"
    );
}
