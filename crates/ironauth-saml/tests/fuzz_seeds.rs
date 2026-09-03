// SPDX-License-Identifier: MIT OR Apache-2.0

//! The fuzz seed corpus is real, and it reaches the code it is a seed for.
//!
//! # Why a seed needs its own test
//!
//! A corpus entry that does not PARSE teaches the fuzzer nothing about the canonicalizer or the
//! verifier: those run only on a document the parser accepted, so an unparseable seed explores
//! the first refusal and stops. The seeds would still be committed, the lane would still run, and
//! the coverage claim would be false in a way no count could show.
//!
//! This is also the stable-CI half of the fuzz lane. The scheduled workflow needs a nightly
//! toolchain and does not run on a pull request, so without this file nothing on the merge path
//! looks at the corpus at all.
//!
//! Needs no database.

use std::path::PathBuf;

/// The corpus directory for one target.
fn corpus(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target)
}

/// Every committed seed, as bytes.
fn seeds(target: &str) -> Vec<(String, Vec<u8>)> {
    let directory = corpus(target);
    let mut found: Vec<(String, Vec<u8>)> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{} must exist: {error}", directory.display()))
        .map(|entry| {
            let entry = entry.expect("a corpus entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = std::fs::read(entry.path()).expect("a corpus entry is readable");
            (name, bytes)
        })
        .filter(|(name, _)| name.starts_with("seed_"))
        .collect();
    found.sort();
    found
}

/// Each target has seeds, and they are the ones tracking allows.
///
/// The `.gitignore` keeps `seed_*` and drops everything libFuzzer generates, so a seed added
/// under any other name is silently untracked: it works on the machine that wrote it and does not
/// exist for anybody else. The floors here are what turn that into a failure.
#[test]
fn every_fuzz_target_has_a_tracked_seed_corpus() {
    for (target, floor) in [
        ("saml_parse", 5),
        ("saml_canonicalize", 4),
        ("saml_verify", 3),
    ] {
        let found = seeds(target);
        assert!(
            found.len() >= floor,
            "{target}: {} tracked seeds, expected at least {floor}. A seed not named seed_* is \
             ignored by fuzz/.gitignore and exists only on the machine that wrote it.",
            found.len()
        );
        for (name, bytes) in &found {
            assert!(!bytes.is_empty(), "{target}/{name} is empty");
        }
    }
}

/// Every canonicalization seed PARSES, because the canonicalizer only ever runs on one that did.
///
/// # The measurement, not the intention
///
/// A seed is a claim that the fuzzer starts somewhere interesting. For `saml_canonicalize` that
/// claim is only true if the document survives `parse`, and it is easy to commit one that does
/// not: three of the parse seeds are deliberately malformed, and copying one across would look
/// right and explore nothing.
#[test]
fn every_canonicalization_seed_reaches_the_canonicalizer() {
    let limits = ironauth_saml::Limits::default();
    for (name, bytes) in seeds("saml_canonicalize") {
        let document = ironauth_saml::parse(&bytes, &limits)
            .unwrap_or_else(|error| panic!("saml_canonicalize/{name} must parse: {error}"));
        let text = core::str::from_utf8(&bytes).expect("a seed is UTF-8");
        ironauth_saml::test_util::canonicalize(text, document.root().name())
            .unwrap_or_else(|error| panic!("saml_canonicalize/{name} must canonicalise: {error}"));
    }
}

/// The parse corpus covers BOTH answers, and the verify corpus reaches the signature path.
///
/// # A corpus of only-refusals is a corpus of one code path
///
/// If every parse seed were malformed, the fuzzer would start from five documents that all stop
/// at the same refusal. If every one were well formed, the refusal paths would go unexplored.
/// Both floors are asserted, and they are measured by RUNNING the parser rather than by reading
/// the file names.
#[test]
fn the_corpus_covers_both_answers_and_reaches_the_verifier() {
    let limits = ironauth_saml::Limits::default();
    let mut accepted = 0_usize;
    let mut refused = 0_usize;
    for (_, bytes) in seeds("saml_parse") {
        if ironauth_saml::parse(&bytes, &limits).is_ok() {
            accepted += 1;
        } else {
            refused += 1;
        }
    }
    assert!(
        accepted >= 1,
        "no parse seed is a document the parser accepts"
    );
    assert!(
        refused >= 1,
        "no parse seed is a document the parser refuses"
    );

    // AND THE VERIFY SEEDS REACH THE SIGNATURE PATH. `SignatureMissing` or later means the
    // candidate was found and the signature was looked for; `Malformed` or `ReferenceRefused`
    // means the run stopped earlier. At least one seed has to get past selection, or the target
    // explores nothing but the parser a second time.
    let anchors: [ironauth_saml::TrustAnchor; 0] = [];
    let reached = seeds("saml_verify").into_iter().filter(|(_, bytes)| {
        matches!(
            ironauth_saml::verify(
                bytes,
                &limits,
                &anchors,
                ironauth_saml::ASSERTION_NS,
                "Assertion",
            ),
            Err(ironauth_saml::VerifyError::SignatureInvalid
                | ironauth_saml::VerifyError::SignatureMissing
                | ironauth_saml::VerifyError::AlgorithmRefused)
        )
    });
    assert!(
        reached.count() >= 1,
        "no verify seed gets past candidate selection, so the target only re-explores the parser"
    );
}
