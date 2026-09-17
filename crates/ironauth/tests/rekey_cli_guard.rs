// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ironauth storage rekey` refusing a rotation that would orphan every lookup (issue #153).
//!
//! The library's rekey logic is tested in `ironauth-store`. What is only reachable here is the
//! COMMAND: whether the refusal actually fires for an operator, what it tells them, and what it
//! exits with. A guard that is only verified by hand is one a later edit removes silently, and
//! this one stands between a deployment and every account failing login as an unknown user.
//!
//! NO DATABASE. The guard runs before the DSN is opened, deliberately, so these drive the binary
//! with an unreachable address: reaching the refusal without a database is itself part of the
//! contract, because an operator preparing a rotation should get the answer before they point the
//! command at production.

use std::io::Write;
use std::process::Command;

/// Write a secret to its own file and return the path, the way `database.master_key` names one.
///
/// Per process, so two checkouts running their suites at once do not share a path.
fn secret_file(name: &str, secret: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rekey-guard");
    std::fs::create_dir_all(&dir).expect("a temp directory");
    let path = dir.join(format!("{name}-{}.secret", std::process::id()));
    let mut file = std::fs::File::create(&path).expect("create the secret file");
    file.write_all(secret.as_bytes()).expect("write the secret");
    path
}

/// Run `storage rekey` between two named keys and return (success, stdout, stderr).
fn rekey(from: &str, to: &str, extra: &[&str]) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ironauth"))
        .args(["storage", "rekey", "--url"])
        // AN ADDRESS NOTHING LISTENS ON: port 1 needs root to bind, so this is an immediate
        // refusal rather than a timeout, and any test that gets as far as connecting fails fast.
        .arg("postgres://ironauth@127.0.0.1:1/ironauth")
        .args(["--from-master-key", from, "--to-master-key", to])
        .args(extra)
        .output()
        .expect("run the ironauth binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// THE GUARD FIRES on a change of key material, before any database is touched.
///
/// This is the case that would otherwise leave every existing account unable to log in, with no
/// error anywhere: the lookup simply misses and reports an unknown user.
#[test]
fn a_change_of_material_is_refused_before_the_database_is_opened() {
    let old = secret_file("refuse-old", "the-old-secret");
    let new = secret_file("refuse-new", "a-different-secret");

    let (ok, _stdout, stderr) = rekey(
        &format!("master-1:file:{}", old.display()),
        &format!("master-2:file:{}", new.display()),
        &[],
    );

    assert!(!ok, "a change of material must not succeed unacknowledged");
    assert!(
        stderr.contains("REFUSING"),
        "the operator has to be told this was refused: {stderr}"
    );
    assert!(
        stderr.contains("--i-will-rebuild-lookups"),
        "and told the one way past it: {stderr}"
    );
    // NOT A CONNECTION ERROR. If this reached the DSN the guard ran too late, and an operator
    // rehearsing a rotation against an unreachable address would get the wrong answer.
    assert!(
        !stderr.contains("cannot connect"),
        "the refusal must precede opening the database: {stderr}"
    );
}

/// A RENAME IS NOT REFUSED. Same secret, different generation name: every lookup keeps working,
/// so the guard must let it through.
///
/// Without this the test above would pass against a command that refused every rotation, which
/// would take away the one shape that is safe today.
#[test]
fn a_rename_with_the_same_secret_is_not_refused() {
    let secret = secret_file("rename", "the-same-secret");
    let named = format!("file:{}", secret.display());

    let (ok, _stdout, stderr) = rekey(
        &format!("master-1:{named}"),
        &format!("master-2:{named}"),
        &[],
    );

    assert!(!ok, "it still fails, but on the unreachable database");
    assert!(
        !stderr.contains("REFUSING"),
        "a rename must not be refused: {stderr}"
    );
    assert!(
        stderr.contains("cannot connect"),
        "it should have got as far as the database: {stderr}"
    );
}

/// THE ACKNOWLEDGEMENT GETS PAST IT, and says so rather than proceeding quietly.
#[test]
fn the_acknowledgement_flag_allows_a_change_of_material_and_warns() {
    let old = secret_file("ack-old", "the-old-secret");
    let new = secret_file("ack-new", "a-different-secret");

    let (ok, stdout, stderr) = rekey(
        &format!("master-1:file:{}", old.display()),
        &format!("master-2:file:{}", new.display()),
        &["--i-will-rebuild-lookups"],
    );

    assert!(!ok, "it still fails, but on the unreachable database");
    assert!(
        !stderr.contains("REFUSING"),
        "the acknowledgement must get past the guard: {stderr}"
    );
    assert!(
        stdout.contains("CHANGE OF MATERIAL"),
        "and it must still say what is about to happen: {stdout}"
    );
    assert!(stderr.contains("cannot connect"), "{stderr}");
}
