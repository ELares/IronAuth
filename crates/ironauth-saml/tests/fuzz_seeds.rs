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
        // NOT MERELY NON-EMPTY. A count plus a non-emptiness check is satisfied by a corpus of
        // five files holding one junk byte each -- a corpus that teaches the fuzzer nothing and
        // passes every floor. Being a plausible XML document is the cheapest property a junk
        // byte cannot satisfy; the per-target tests below then measure what each one REACHES.
        for (name, bytes) in &found {
            assert!(bytes.len() >= 8, "{target}/{name} is {} bytes", bytes.len());
            let text = core::str::from_utf8(bytes)
                .unwrap_or_else(|_| panic!("{target}/{name} is not UTF-8"));
            assert!(
                text.trim_start().starts_with('<') && text.contains('>'),
                "{target}/{name} is not an XML document"
            );
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
    // AND THE REFUSALS ARE THE INTERESTING ONES. A corpus whose only refusals are "not XML"
    // explores the first branch and stops; the shapes worth seeding are the ones carrying a
    // payload a weaker parser would have executed.
    let doctypes = seeds("saml_parse")
        .into_iter()
        .filter(|(_, bytes)| {
            matches!(
                ironauth_saml::parse(bytes, &limits),
                Err(ironauth_saml::SamlError::DoctypeForbidden)
            )
        })
        .count();
    assert!(
        doctypes >= 2,
        "the parse corpus carries {doctypes} DOCTYPE seeds; the XXE and expansion shapes are the \
         ones a weaker parser would have executed"
    );

    // AND ONE VERIFY SEED VERIFIES. Not "gets past candidate selection", which an earlier
    // version asserted and which a document with `<ds:DigestValue>AAAA</ds:DigestValue>`
    // satisfies: that stops at the digest comparison, so the base64 decode of SignatureValue,
    // the canonicalization of SignedInfo and the whole signature primitive are never reached by
    // any seed, and mutation cannot get there either -- it would need a SHA-256 preimage.
    //
    // `seed_genuinely_signed` is signed by the key `fuzz_targets/saml_verify.rs` embeds, so the
    // accept path is reachable from the corpus. This test re-derives the anchor from that same
    // embedded key rather than storing a second copy, so the two cannot drift apart.
    let key = ironauth_jose::xmldsig::test_util::XmlTestKey::from_pkcs8(&fuzz_key())
        .expect("the embedded key loads");
    let anchors = [ironauth_saml::TrustAnchor::EcdsaP256(key.public_point())];
    let verified = seeds("saml_verify")
        .into_iter()
        .filter(|(_, bytes)| {
            ironauth_saml::verify(
                bytes,
                &limits,
                &anchors,
                ironauth_saml::ASSERTION_NS,
                "Assertion",
            )
            .is_ok()
        })
        .count();
    assert!(
        verified >= 1,
        "no verify seed VERIFIES under the key the fuzz target embeds, so the target's accept \
         path is unreachable from the corpus and every assertion about what comes back is \
         vacuous"
    );
}

/// The PKCS#8 key the `saml_verify` fuzz target embeds, read out of the target itself.
///
/// # Why it is parsed rather than duplicated
///
/// The corpus seed and the target have to agree about the key, and two copies of a key are two
/// things that can drift. Reading the literal out of the target's own source means a change
/// there fails HERE, loudly, rather than silently making a seed stop verifying.
fn fuzz_key() -> Vec<u8> {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fuzz/fuzz_targets/saml_verify.rs"
    ))
    .expect("the fuzz target is readable");
    let start = source
        .find("const FUZZ_KEY_PKCS8: &[u8] = &[")
        .expect("the target embeds a key")
        + "const FUZZ_KEY_PKCS8: &[u8] = &[".len();
    let end = start + source[start..].find("];").expect("the literal closes");
    source[start..end]
        .split(',')
        .filter_map(|byte| {
            let byte = byte.trim();
            byte.strip_prefix("0x")
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        })
        .collect()
}
