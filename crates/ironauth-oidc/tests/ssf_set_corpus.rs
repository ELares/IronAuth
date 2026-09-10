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

/// One entry in the corpus: an algorithm, the key an environment holds for it, and a DECOY.
struct Case {
    alg: JwsAlgorithm,
    /// Lowercase, filesystem-safe, and what the validator reports failures under.
    label: &'static str,
    key: SigningKey,
    /// A second key of the SAME algorithm, which signed nothing.
    ///
    /// THIS IS WHAT MAKES THE WRONG-KEY CONTROL MEAN ANYTHING. The first version of the
    /// validator offered each token another CASE's key, and every one of those six controls was
    /// rejected before verification ever ran: `PyJWT` raised `InvalidKeyError` or `TypeError`
    /// because an Ed25519 key is not an elliptic-curve key and an RSA key is not either. The
    /// control passed, proved nothing about the signature, and would have gone on passing
    /// against a validator that never checked one. A key of the same TYPE reaches the signature
    /// check and fails there.
    decoy: SigningKey,
}

/// One signing key of `alg`, named `kid`.
fn key_of(env: &Env, alg: JwsAlgorithm, kid: &str, ed_seed: u8) -> SigningKey {
    match alg {
        // A FIXED SEED, so the EdDSA case is reproducible across runs. The corpus itself is
        // not: `iat` moves, so every run produces a different token and a different signature.
        // The other families are generated because this repository has no fixed-key constructor
        // for them, and a hand-pasted DER blob in a test file is a key nobody can regenerate.
        JwsAlgorithm::EdDsa => SigningKey::ed25519_from_seed(Some(kid.to_owned()), &[ed_seed; 32])
            .expect("an Ed25519 key"),
        JwsAlgorithm::Es256 => {
            let der = ironauth_jose::generate_ecdsa_p256_pkcs8_der(env.entropy())
                .expect("generate a P-256 key");
            SigningKey::ecdsa_p256_from_pkcs8(Some(kid.to_owned()), &der).expect("a P-256 key")
        }
        JwsAlgorithm::Rs256 => {
            let der =
                ironauth_jose::generate_rsa_pkcs1_der(env.entropy()).expect("generate an RSA key");
            SigningKey::rsa_from_pkcs1_der(Some(kid.to_owned()), JwsAlgorithm::Rs256, &der)
                .expect("an RSA key")
        }
        other => panic!("the corpus has no key generator for {other:?}"),
    }
}

fn cases(env: &Env) -> Vec<Case> {
    [
        (JwsAlgorithm::EdDsa, "eddsa", 0x4c_u8),
        (JwsAlgorithm::Es256, "es256", 0x00),
        (JwsAlgorithm::Rs256, "rs256", 0x00),
    ]
    .into_iter()
    .map(|(alg, label, seed)| Case {
        alg,
        label,
        key: key_of(env, alg, &format!("set-{label}"), seed),
        decoy: key_of(env, alg, &format!("decoy-{label}"), seed ^ 0xff),
    })
    .collect()
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
        // BY KID, not by count. Counting the keys was the first version and it asserted almost
        // nothing: a JWKS holding exactly one key that did not sign this token would have
        // passed, and the external validator selects by `kid`, so that is the tie that has to
        // hold for it to find anything at all.
        let header_kid = header_of(&token)["kid"]
            .as_str()
            .expect("the token header names a kid")
            .to_owned();
        assert!(
            keys.iter()
                .any(|key| key["kid"].as_str() == Some(header_kid.as_str())),
            "the {} environment's published JWKS carries no key with kid {header_kid}, so an \
             external validator could not select one: {jwks}",
            case.label
        );

        let expectations = expectations(case.alg, case.label, &issuer, &jti);
        let decoy_jwks = publish_decoy(&env, case.alg, case.decoy).await;

        let case_dir = dir.join(case.label);
        write_case(&case_dir, &token, &jwks, &decoy_jwks, &expectations);
        written.push(case.label);
    }

    assert_matrix_covers_three_distinct_algorithms(&dir, &written);
}

/// A key set holding one key of `alg` that signed nothing, rendered as a published JWKS.
///
/// A DECOY OF THE SAME ALGORITHM is what makes the wrong-key control mean anything: a token
/// offered another CASE's key is refused by `PyJWT`'s key-type check before signature math runs,
/// so that control cannot tell you the signature is verified. This one reaches it.
async fn publish_decoy(env: &Env, alg: JwsAlgorithm, decoy: SigningKey) -> String {
    let registry = IssuerRegistry::new(ISSUER_BASE, JwksCacheWindow::clamped(600));
    let scope = Scope::new(TenantId::generate(env), EnvironmentId::generate(env));
    registry.insert(
        scope,
        IssuerEntry::new(
            KeySet::bootstrap(decoy, SystemTime::UNIX_EPOCH),
            SigningPolicy::new(vec![alg]).expect("a one-algorithm policy"),
            PairwiseSalt::new(Vec::new()),
            ironauth_store::GuardrailSet::for_kind(ironauth_store::EnvironmentType::Dev),
        ),
    );
    registry
        .jwks_json(&scope, SystemTime::UNIX_EPOCH)
        .await
        .expect("the decoy environment resolves")
        .expect("the decoy JWKS renders")
}

/// The corpus really is three DIFFERENT algorithms, read back off the tokens on disk.
///
/// The first version asserted `written == ["eddsa", "es256", "rs256"]` where `written` was pushed
/// from those same three literals a few lines above: it had no input that could make it fire, and
/// its message named a cross-crate property ("the algorithms a provisioned environment holds")
/// that the file never read. A reviewer built a corpus of three `EdDSA` tokens in directories named
/// eddsa, es256 and rs256; it passed, and the external lane printed "3 algorithms validated".
fn assert_matrix_covers_three_distinct_algorithms(dir: &std::path::Path, written: &[&str]) {
    let mut seen: Vec<String> = Vec::new();
    for label in written {
        let token = std::fs::read_to_string(dir.join(label).join("set.jwt"))
            .expect("read back the token just written");
        let alg = header_of(&token)["alg"]
            .as_str()
            .expect("the header names an alg")
            .to_owned();
        assert_eq!(
            alg.to_lowercase(),
            **label,
            "the corpus case named {label} holds a {alg} token"
        );
        assert!(
            !seen.contains(&alg),
            "two corpus cases are the same algorithm ({alg}), so the matrix is one algorithm \
             repeated rather than the set a provisioned environment holds"
        );
        seen.push(alg);
    }
    assert_eq!(
        seen.len(),
        3,
        "the corpus does not cover the three algorithms DayOneSigningKeys provisions"
    );
}

/// What the validator must find, written by the MINTING side.
///
/// So the validator asserts against this run rather than against constants it keeps its own copy
/// of: one holding its own expected `iss` would keep passing after the issuer stopped matching.
/// The ALGORITHM is the exception and is checked on both sides, because a directory name is a
/// claim about the algorithm and `expect.json` agreeing with the token proves nothing about it.
fn expectations(alg: JwsAlgorithm, label: &str, issuer: &str, jti: &str) -> serde_json::Value {
    serde_json::json!({
        "alg": alg.as_jose_name(),
        "iss": issuer,
        "aud": AUDIENCE,
        "jti": jti,
        "event_type": EVENT_TYPE,
        "subject_format": "iss_sub",
        "subject_sub": format!("usr_{label}"),
        "typ": "secevent+jwt",
    })
}

/// Write one case's four files.
fn write_case(
    case_dir: &std::path::Path,
    token: &str,
    jwks: &str,
    decoy_jwks: &str,
    expectations: &serde_json::Value,
) {
    std::fs::create_dir_all(case_dir).expect("create the case directory");
    std::fs::write(case_dir.join("set.jwt"), token).expect("write the token");
    std::fs::write(case_dir.join("jwks.json"), jwks).expect("write the JWKS");
    std::fs::write(case_dir.join("decoy_jwks.json"), decoy_jwks).expect("write the decoy JWKS");
    std::fs::write(
        case_dir.join("expect.json"),
        serde_json::to_string_pretty(expectations).expect("render the expectations"),
    )
    .expect("write the expectations");
}

/// The decoded JOSE header of a compact JWS.
fn header_of(token: &str) -> serde_json::Value {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let segment = token.split('.').next().expect("a compact JWS has a header");
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("the header is base64url");
    serde_json::from_slice(&bytes).expect("the header is JSON")
}
