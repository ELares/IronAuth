// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `ironauth step-up-policy` CLI, end to end against a real Postgres (RFC 9470,
//! issue #72).
//!
//! Pins the MEDIUM-3 fix: before this the declarative step-up policy write-path
//! (`ActingScopeStepUpPolicyRepo::set` / `ActingClientRepo::set_step_up_policy`) had NO
//! non-test caller, so an operator could not enable a policy without writing Rust or SQL.
//! These drive the COMPILED `ironauth` binary as a subprocess against a throwaway
//! database and confirm the write lands in the SAME audited repository the enforcement
//! path reads (the per-scope `scope_step_up_policies` row `requirement_for_request` folds
//! into the authorization/token/refresh gate, whose gating the `step_up` integration
//! suite proves). Canonicalization of the `--acr mfa` alias to the value the enforcement
//! path compares against is asserted here too.

use std::process::Command;
use std::time::SystemTime;

use ironauth_env::Env;
// SystemTime is used only to seed the deterministic Env below, not for wall-clock logic.
use ironauth_store::test_support::TestDatabase;

/// Write a minimal config that points the CLI at the throwaway database's low-privilege
/// data-plane role, returning the file path. An empty config is valid, so only the
/// `[database]` url override is needed. The temp filename is unique per test PROCESS (the
/// pid), so no wall clock is needed.
fn write_config(app_url: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("ironauth-step-up-cli-{}.toml", std::process::id()));
    std::fs::write(&path, format!("[database]\nurl = \"{app_url}\"\n")).expect("write config");
    path
}

/// Run `ironauth step-up-policy <args...>` against `config` and return (success, stdout).
fn run_cli(config: &std::path::Path, scope_args: &[&str]) -> (bool, String) {
    let binary = env!("CARGO_BIN_EXE_ironauth");
    let mut command = Command::new(binary);
    command.arg("step-up-policy");
    command.args(scope_args);
    command.arg("--config");
    command.arg(config);
    let output = command.output().expect("run the ironauth binary");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    (output.status.success(), stdout)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cli_sets_lists_and_removes_a_per_scope_step_up_policy_the_enforcement_path_reads() {
    let db = TestDatabase::start().await;
    let (env, _clock) = Env::deterministic(SystemTime::UNIX_EPOCH, 0x0D1C_5EED);
    let scope = db.seed_scope(&env).await;
    let tenant = scope.tenant().to_string();
    let environment = scope.environment().to_string();
    let config = write_config(db.app_url());

    // 1. SET a per-scope policy through the CLI: payments:write requires acr mfa within
    //    300 seconds (the finding's worked example).
    let (ok, _out) = run_cli(
        &config,
        &[
            "set",
            "--tenant",
            &tenant,
            "--environment",
            &environment,
            "--scope",
            "payments:write",
            "--acr",
            "mfa",
            "--max-age",
            "300",
        ],
    );
    assert!(ok, "the CLI set must succeed");

    // The write landed in the SAME repository the enforcement path reads, and the `mfa`
    // alias was canonicalized to the value the achieved acr carries, so it actually gates.
    let policies = db
        .store()
        .scoped(scope)
        .scope_step_up_policies()
        .list()
        .await
        .expect("list policies");
    assert_eq!(policies.len(), 1, "exactly one policy was written");
    assert_eq!(policies[0].scope_token, "payments:write");
    assert_eq!(
        policies[0].min_acr.as_deref(),
        Some("urn:ironauth:acr:mfa"),
        "the --acr mfa alias is canonicalized to the enforced acr value"
    );
    assert_eq!(policies[0].max_auth_age_secs, Some(300));

    // 2. LIST through the CLI shows the policy.
    let (ok, out) = run_cli(
        &config,
        &["list", "--tenant", &tenant, "--environment", &environment],
    );
    assert!(ok, "the CLI list must succeed");
    assert!(
        out.contains("payments:write"),
        "the CLI list shows the policy: {out}"
    );

    // 3. REMOVE through the CLI clears the policy the enforcement path reads.
    let (ok, _out) = run_cli(
        &config,
        &[
            "remove",
            "--tenant",
            &tenant,
            "--environment",
            &environment,
            "--scope",
            "payments:write",
        ],
    );
    assert!(ok, "the CLI remove must succeed");
    let policies = db
        .store()
        .scoped(scope)
        .scope_step_up_policies()
        .list()
        .await
        .expect("list policies after remove");
    assert!(
        policies.is_empty(),
        "the CLI remove cleared the enforced policy"
    );

    let _ = std::fs::remove_file(&config);
}
