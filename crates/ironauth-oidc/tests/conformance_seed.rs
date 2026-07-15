// SPDX-License-Identifier: MIT OR Apache-2.0

//! The conformance seed credential is real, and stays real (issue #37).
//!
//! `deploy/conformance/seed.sh` used to compute the cert user's Argon2id hash at
//! run time by pulling a MUTABLE alpine tag and installing a package FROM THE
//! NETWORK inside the gate lane. That is not determinism, and it is not something
//! a gate should execute. The hash is committed instead
//! (`deploy/conformance/cert-user-password.phc`), so seeding pulls no image and
//! reaches no network.
//!
//! A committed hash is only safe if it is not taken on trust, because a wrong one
//! fails far from its cause: the OP boots, discovery works, and the suite dies at
//! the login step of every plan. So these tests re-derive the claim with the
//! PRODUCT'S OWN verifier, the very code path a real login takes:
//!
//!   1. the committed PHC string verifies against the committed cert password,
//!      and rejects a wrong one;
//!   2. the password the two harness scripts declare has not drifted apart, or
//!      from the password the hash was made for.
//!
//! No clock and no entropy are read here (both are banned outside `ironauth-env`);
//! verification takes its parameters from the stored PHC string.

use std::path::{Path, PathBuf};

use ironauth_oidc::verify_password;

/// The throwaway cert credential. It is committed on purpose: the whole cert
/// environment is disposable and never reachable outside a conformance run.
const CERT_PASSWORD: &str = "conformance-cert-password";

/// Absolute path to a repo-root-relative file. The crate manifest dir is
/// `<repo>/crates/ironauth-oidc`, so the repo root is two levels up.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(relative)
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

/// The committed PHC string, trimmed of its trailing newline.
fn committed_hash() -> String {
    read("deploy/conformance/cert-user-password.phc")
        .trim()
        .to_owned()
}

#[test]
fn committed_seed_hash_verifies_the_committed_cert_password() {
    let hash = committed_hash();
    assert!(
        hash.starts_with("$argon2id$"),
        "the seed hash must be an Argon2id PHC string, got {hash}"
    );
    assert!(
        verify_password(CERT_PASSWORD, &hash),
        "the committed seed hash does NOT verify the committed cert password. \
         Seeding it would make every conformance plan fail at the login step."
    );
}

#[test]
fn committed_seed_hash_rejects_the_wrong_password() {
    // Belt and braces: a hash that verifies everything (a malformed one that the
    // verifier fails open on, say) would pass the test above vacuously.
    let hash = committed_hash();
    assert!(!verify_password("not-the-cert-password", &hash));
    assert!(!verify_password("", &hash));
}

#[test]
fn the_harness_scripts_agree_on_the_cert_password() {
    // seed.sh installs the committed hash for this password, and
    // run-conformance.sh exports the same value for the suite's browser login.
    // If either drifts from the other (or from the password the committed hash
    // was actually made for) the suite logs in with the wrong credential and
    // every plan fails at the login step, far from the edit that caused it.
    let seed = read("deploy/conformance/seed.sh");
    let run = read("deploy/conformance/run-conformance.sh");

    assert!(
        seed.contains(&format!("DEFAULT_CERT_USER_PASSWORD=\"{CERT_PASSWORD}\"")),
        "seed.sh no longer declares the cert password the committed hash covers"
    );
    assert!(
        run.contains(&format!("CERT_USER_PASSWORD:-{CERT_PASSWORD}")),
        "run-conformance.sh no longer exports the cert password the committed \
         hash covers"
    );
}
