// SPDX-License-Identifier: MIT OR Apache-2.0

//! Terraform provider acceptance tests (issue #51, criterion 1), against a REAL management
//! API driven by a REAL `OpenTofu` binary.
//!
//! The criterion asks for the provider driven "against a live compose stack in CI, including
//! import and destroy". There is no compose stack here and none is needed: the management
//! router is bound to a real TCP port in-process over a migrated throwaway database, which
//! is a live server by every measure that matters to a provider. `OpenTofu` is a Go binary,
//! so it needs no container either.
//!
//! What this proves that a unit test cannot: that the provider's schema is accepted by a
//! real Terraform-protocol handshake, that an apply reaches the real API and creates a real
//! row, that a second plan is EMPTY (no perpetual diff, the defect that makes a provider
//! unusable while every individual function looks right), that import adopts an existing
//! resource, and that destroy converges.
//!
//! It SKIPS when `tofu` or the Go toolchain is absent, naming what to install.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::Harness;

/// Locate a binary on PATH, or in the Go bin directory a `go install` would use.
fn find_binary(name: &str) -> Option<PathBuf> {
    if let Ok(output) = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    let home = std::env::var("HOME").ok()?;
    for candidate in [
        format!("{home}/go/bin/{name}"),
        format!("{home}/.local/go/bin/{name}"),
    ] {
        let path = PathBuf::from(&candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// The provider source directory, from this crate's manifest.
fn provider_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("terraform-provider-ironauth")
}

/// Run a command, returning (success, combined output).
fn run(command: &mut Command) -> (bool, String) {
    let output = command.output().expect("spawning the command");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), combined)
}

/// Build the provider and lay out a working directory whose CLI config points
/// `registry.opentofu.org/ELares/ironauth` at the freshly built binary.
///
/// `dev_overrides` rather than a local registry mirror, because it is the ONE mechanism
/// that needs no `tofu init` and no published artifact: the acceptance test must work from a
/// clean checkout with nothing published anywhere.
fn stage(tofu: &Path, go: &Path, work: &Path, endpoint: &str, token: &str) -> Result<(), String> {
    let bin_dir = work.join("bin");
    std::fs::create_dir_all(&bin_dir).map_err(|e| e.to_string())?;
    let (ok, out) = run(Command::new(go)
        .current_dir(provider_dir())
        .env("GOFLAGS", "-mod=mod")
        .arg("build")
        .arg("-o")
        .arg(bin_dir.join("terraform-provider-ironauth"))
        .arg("."));
    if !ok {
        return Err(format!("building the provider failed:\n{out}"));
    }
    std::fs::write(
        work.join("dev.tfrc"),
        format!(
            "provider_installation {{\n  dev_overrides {{\n    \
             \"registry.opentofu.org/ELares/ironauth\" = \"{}\"\n  }}\n  \
             direct {{}}\n}}\n",
            bin_dir.display()
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        work.join("main.tf"),
        format!(
            r#"terraform {{
  required_providers {{
    ironauth = {{
      source = "registry.opentofu.org/ELares/ironauth"
    }}
  }}
}}

provider "ironauth" {{
  endpoint = "{endpoint}"
  token    = "{token}"
}}

resource "ironauth_tenant" "acme" {{
  display_name = "Acme via Terraform"
}}
"#
        ),
    )
    .map_err(|e| e.to_string())?;
    let _ = tofu;
    Ok(())
}

fn tofu_command(tofu: &Path, work: &Path) -> Command {
    let mut command = Command::new(tofu);
    command
        .current_dir(work)
        .env("TF_CLI_CONFIG_FILE", work.join("dev.tfrc"))
        // dev_overrides makes tofu print a warning on every command; the tests read exit
        // codes and specific substrings, so the noise is harmless but the input must be
        // non-interactive or a prompt would hang the suite forever.
        .env("TF_IN_AUTOMATION", "1")
        .arg("-chdir=.");
    command
}

/// Apply, prove no perpetual diff, import, and destroy: criterion 1 end to end.
// MULTI-THREAD, and it is load-bearing. This test blocks on `Command::output()` while
// `tofu` runs, and on the default current-thread runtime a blocking call never yields, so
// the spawned server task would never accept a connection and every apply would fail with
// "connection refused". That is exactly how the first run of this test failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_provider_applies_imports_and_destroys_against_a_live_management_api() {
    let (Some(tofu), Some(go)) = (find_binary("tofu"), find_binary("go")) else {
        eprintln!(
            "terraform_provider: SKIPPED, needs `tofu` and `go` on PATH. \
             Build tofu with: git clone --branch v1.12.5 https://github.com/opentofu/opentofu \
             && go build -o ~/go/bin/tofu ./cmd/tofu"
        );
        return;
    };

    let harness = Harness::start(50).await;
    let (addr, _server) = harness.serve_on_a_port().await;
    let endpoint = format!("http://{addr}");
    let work = tempdir();

    if let Err(error) = stage(&tofu, &go, &work, &endpoint, common::OPERATOR_TOKEN) {
        panic!("staging the provider failed: {error}");
    }

    // APPLY.
    let (ok, out) = run(tofu_command(&tofu, &work).arg("apply").arg("-auto-approve"));
    assert!(ok, "tofu apply failed:\n{out}");

    // The tenant really exists, read back through the API rather than believed from
    // Terraform's own output: a provider that reported success while writing nothing would
    // pass any assertion made against its state file.
    let (status, _, listed) = harness.get("/v1/tenants").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{listed}");
    assert!(
        listed.contains("Acme via Terraform"),
        "the applied tenant is not in the API listing: {listed}"
    );

    // NO PERPETUAL DIFF. `-detailed-exitcode` answers 0 for no changes and 2 for changes; a
    // provider whose read does not round-trip its own write reports 2 forever, which is the
    // defect that makes a provider unusable while every individual function looks correct.
    let (_, plan_out) = run(tofu_command(&tofu, &work)
        .arg("plan")
        .arg("-detailed-exitcode"));
    assert!(
        plan_out.contains("No changes"),
        "a second plan is not empty, so the provider has a perpetual diff:\n{plan_out}"
    );

    // IMPORT. The resource is removed from state and re-adopted by id, which is what an
    // operator does when a resource was created through the console.
    let (ok, out) = run(tofu_command(&tofu, &work)
        .arg("state")
        .arg("rm")
        .arg("ironauth_tenant.acme"));
    assert!(ok, "state rm failed:\n{out}");
    let id = tenant_id(&listed);
    let (ok, out) = run(tofu_command(&tofu, &work)
        .arg("import")
        .arg("ironauth_tenant.acme")
        .arg(&id));
    assert!(ok, "tofu import failed:\n{out}");
    let (_, plan_out) = run(tofu_command(&tofu, &work)
        .arg("plan")
        .arg("-detailed-exitcode"));
    assert!(
        plan_out.contains("No changes"),
        "the IMPORTED resource plans a change, so import adopted it incompletely:\n{plan_out}"
    );

    // DESTROY converges, and the API agrees.
    let (ok, out) = run(tofu_command(&tofu, &work)
        .arg("destroy")
        .arg("-auto-approve"));
    assert!(ok, "tofu destroy failed:\n{out}");
    let (_, _, after) = harness.get("/v1/tenants").await;
    assert!(
        !after.contains("Acme via Terraform"),
        "the tenant survived destroy: {after}"
    );
}

/// The operator token never reaches the state file, the plan output, or the logs.
///
/// Issue #51 criterion 2. `Sensitive: true` on the attribute is what does it, and this is
/// the assertion that says so: a schema flag nobody checks is a flag somebody removes.
// Multi-thread for the reason given on the test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_operator_token_never_appears_in_state_or_plan_output() {
    let (Some(tofu), Some(go)) = (find_binary("tofu"), find_binary("go")) else {
        eprintln!("terraform_provider: SKIPPED, needs `tofu` and `go` on PATH");
        return;
    };
    let harness = Harness::start(50).await;
    let (addr, _server) = harness.serve_on_a_port().await;
    let work = tempdir();
    if let Err(error) = stage(
        &tofu,
        &go,
        &work,
        &format!("http://{addr}"),
        common::OPERATOR_TOKEN,
    ) {
        panic!("staging failed: {error}");
    }

    let (ok, apply_out) = run(tofu_command(&tofu, &work).arg("apply").arg("-auto-approve"));
    assert!(ok, "apply failed:\n{apply_out}");
    assert!(
        !apply_out.contains(common::OPERATOR_TOKEN),
        "the operator token appeared in APPLY OUTPUT, which lands in CI logs"
    );

    let state = std::fs::read_to_string(work.join("terraform.tfstate")).unwrap_or_default();
    assert!(
        !state.is_empty(),
        "no state file was written, so this test would pass for the wrong reason"
    );
    assert!(
        !state.contains(common::OPERATOR_TOKEN),
        "the operator token was written into TERRAFORM STATE, which is committed, backed \
         up, and read by everyone with access to the state backend"
    );

    let (_, plan_out) = run(tofu_command(&tofu, &work).arg("plan"));
    assert!(
        !plan_out.contains(common::OPERATOR_TOKEN),
        "the operator token appeared in PLAN OUTPUT, which is pasted into pull requests"
    );

    let _ = run(tofu_command(&tofu, &work)
        .arg("destroy")
        .arg("-auto-approve"));
}

/// The first `ten_` id in a tenants listing.
fn tenant_id(listing: &str) -> String {
    let parsed: serde_json::Value = serde_json::from_str(listing).expect("json");
    parsed["items"]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|item| item["id"].as_str())
        .expect("a tenant id")
        .to_owned()
}

/// A throwaway working directory, unique per test in this process.
///
/// A counter rather than a clock read: this repo forbids reading the wall clock outside the
/// `Env` seam, and a per-process counter is both sufficient here and deterministic.
fn tempdir() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nth = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!("ironauth-tf-{}-{nth}", std::process::id()));
    std::fs::create_dir_all(&base).expect("creating the working directory");
    base
}
