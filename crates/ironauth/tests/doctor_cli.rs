// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `ironauth doctor` CLI, end to end against a real Postgres (issue #148).
//!
//! The preflight's logic is tested in `ironauth-store`. What is only reachable here is
//! the command itself: which DSN it picks, what it refuses to do, what it prints, and
//! what it exits with. An operator's upgrade script reads the EXIT CODE, so a preflight
//! that finds the rows and exits 0 has found nothing as far as the deployment is
//! concerned.

use std::process::Command;
use std::time::SystemTime;

use ironauth_env::Env;

use ironauth_store::test_support::TestDatabase;

/// Run `ironauth doctor --url <dsn>` and return (exit success, stdout, stderr).
fn doctor(dsn: &str) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ironauth"))
        .arg("doctor")
        .arg("--url")
        .arg(dsn)
        .output()
        .expect("run the ironauth binary");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The acceptance criterion at the surface an operator actually uses.
///
/// The setup makes ONE shipped migration pending again and puts a row in front of it:
/// drop `tenants_status_valid`, set a tenant's status to a value that CHECK forbids, and
/// delete migration 30's ledger row. The database is then exactly what it looks like
/// mid-upgrade: a migration to apply, and data that will not let it.
#[tokio::test]
async fn doctor_blocks_and_names_the_rows_when_a_pending_constraint_would_be_rejected() {
    let database = TestDatabase::start().await;
    // A fixed seed and epoch: the scope only has to exist, so nothing here needs a clock.
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D0C_7015);
    database.seed_scope(&env).await;

    database
        .execute_owner_sql("ALTER TABLE tenants DROP CONSTRAINT tenants_status_valid")
        .await;
    database
        .execute_owner_sql("UPDATE tenants SET status = 'not_a_real_status'")
        .await;
    database
        .execute_owner_sql("DELETE FROM _schema_migrations WHERE version = 30")
        .await;

    let (success, stdout, stderr) = doctor(database.owner_url());

    assert!(
        !success,
        "doctor must exit non-zero so an upgrade script stops.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("migration 30"), "{stdout}");
    assert!(stdout.contains("tenants_status_valid"), "{stdout}");
    assert!(stdout.contains("1 row(s) in the way"), "{stdout}");
    assert!(
        stdout.contains("SELECT count(*) AS n FROM tenants WHERE"),
        "the report must hand over the query that lists the rows: {stdout}"
    );
    assert!(stdout.contains("UPGRADE BLOCKED"), "{stdout}");
}

/// The same database with the offending row corrected. Without this the test above is
/// satisfied by a doctor that refuses everything.
#[tokio::test]
async fn doctor_passes_once_the_offending_row_is_corrected() {
    let database = TestDatabase::start().await;
    // A fixed seed and epoch: the scope only has to exist, so nothing here needs a clock.
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D0C_7015);
    database.seed_scope(&env).await;

    database
        .execute_owner_sql("ALTER TABLE tenants DROP CONSTRAINT tenants_status_valid")
        .await;
    database
        .execute_owner_sql("UPDATE tenants SET status = 'not_a_real_status'")
        .await;
    database
        .execute_owner_sql("DELETE FROM _schema_migrations WHERE version = 30")
        .await;

    let (succeeded, _, _) = doctor(database.owner_url());
    assert!(
        !succeeded,
        "precondition: the doctor must block before the row is corrected"
    );

    database
        .execute_owner_sql("UPDATE tenants SET status = 'active'")
        .await;

    let (success, stdout, stderr) = doctor(database.owner_url());
    assert!(
        success,
        "with the row corrected the doctor must pass.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("no row in this database would reject a pending migration"),
        "{stdout}"
    );
}

/// The false-pass guard at the CLI.
///
/// `database.url` names `ironauth_app`, which FORCE ROW LEVEL SECURITY applies to, so
/// every probe on that connection returns zero rows whatever the data holds. Pointed at
/// it, the doctor must refuse rather than report the clean bill that blindness produces:
/// this is the one failure mode where being wrong looks exactly like being right.
#[tokio::test]
async fn doctor_refuses_a_role_that_row_level_security_applies_to() {
    let database = TestDatabase::start().await;

    let (success, stdout, stderr) = doctor(database.app_url());

    assert!(!success, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stderr.contains("REFUSING to report"), "{stderr}");
    assert!(
        stderr.contains("row-level security"),
        "the refusal must say why: {stderr}"
    );
    assert!(
        !stdout.contains("no row in this database would reject"),
        "it must not print a clean verdict it cannot support: {stdout}"
    );
}

/// A fully migrated database has nothing pending, and must say so rather than report a
/// clean scan of constraints it never probed.
#[tokio::test]
async fn doctor_reports_nothing_pending_on_a_current_database() {
    let database = TestDatabase::start().await;

    let (success, stdout, stderr) = doctor(database.owner_url());

    assert!(success, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("nothing is pending"), "{stdout}");
}
