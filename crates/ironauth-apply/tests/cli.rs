// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for the `ironauth apply` config-as-code CLI (issue #51, CLI
//! half), driven end to end against an in-process management API over a real
//! database (`DATABASE_URL`).
//!
//! The tests stand up the real management router on a loopback socket and drive
//! the CLI's REAL HTTP client against it (not a mock), so the production
//! request/response path is exercised. They prove the acceptance surface:
//!
//! - `validate` accepts a good document and rejects a secret-bearing one;
//! - `plan` and `apply --dry-run` render the SERVER-computed plan, and the plan id
//!   matches the plan the server computes for the same document and target (dry-run
//!   parity);
//! - `apply` is transactional and idempotent (a re-apply of an unchanged target is
//!   a no-op, exit 0), and an apply gated on a stale revision reports drift and
//!   exits nonzero;
//! - the `drift` subcommand exits 0 in sync and nonzero on drift;
//! - an unresolved reference is a plan-time error with a nonzero exit; and
//! - a write-only secret's value never appears in any CLI output.

#![allow(clippy::items_after_statements)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ironauth_admin::{AdminState, management_router};
use ironauth_config::{AdminConfig, Secret, SecretString};
use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, SNAPSHOT_SCHEMA_VERSION, Scope, export_snapshot, plan_promotion,
    promotion_revision, validate_document,
};

use ironauth_apply::{Command, CommandOutput, Credential, ExitCode, Invocation, Target, execute};

/// The bootstrap operator token the in-process server trusts.
const OPERATOR_TOKEN: &str = "test-bootstrap-operator-token";

/// A distinctive secret value that must never appear in any CLI output.
const SECRET_SENTINEL: &str = "S3cr3t-SENTINEL-VALUE-must-never-leak-42";

/// A running management API over a fresh database, plus the seeded target scope.
struct Fixture {
    db: TestDatabase,
    env: Env,
    base_url: String,
    scope: Scope,
}

impl Fixture {
    /// Start a fresh database, mount the management router on a loopback socket,
    /// and seed one empty target environment.
    async fn start() -> Self {
        let env = Env::system();
        let db = TestDatabase::start().await;
        let config = AdminConfig {
            bootstrap_operator_token: Some(Secret::Literal(SecretString::new(OPERATOR_TOKEN))),
            max_page_size: 200,
            default_page_size: 20,
            ..AdminConfig::default()
        };
        let state = AdminState::new(db.control_store().clone(), env.clone(), &config)
            .expect("admin state builds");
        let router = management_router(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let scope = db.seed_scope(&env).await;
        Self {
            db,
            env,
            base_url: format!("http://{addr}"),
            scope,
        }
    }

    /// The `tenant/environment` selector for the seeded scope.
    fn target(&self) -> Target {
        Target::parse(&format!(
            "{}/{}",
            self.scope.tenant(),
            self.scope.environment()
        ))
        .expect("valid target")
    }

    /// Seed an environment variable in the target scope (control plane).
    async fn set_var(&self, name: &str, value: &str) {
        self.db
            .control_store()
            .scoped(self.scope)
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .environment_variables()
            .set(&self.env, name, value, None)
            .await
            .expect("set variable");
    }

    /// Seed an environment secret in the target scope (data plane; sealing needs
    /// the master key).
    async fn put_secret(&self, name: &str, value: &[u8]) {
        self.db
            .store()
            .scoped(self.scope)
            .acting(
                self.db.test_actor(&self.env),
                CorrelationId::generate(&self.env),
            )
            .environment_secrets()
            .put(&self.env, &self.db.master_key(), name, value, None)
            .await
            .expect("put secret");
    }

    /// The current promotable-config revision of the target (exported through the
    /// control store, exactly as the server computes it).
    async fn current_revision(&self) -> String {
        let snapshot = export_snapshot(&self.db.control_store().scoped(self.scope))
            .await
            .expect("export snapshot");
        promotion_revision(&snapshot).expect("revision")
    }

    /// The server-computed plan id for `document` against the target, computed the
    /// same way the plan endpoint does. Used to assert dry-run parity.
    async fn server_plan_id(&self, document: &str) -> String {
        let source = validate_document(document.as_bytes()).expect("valid document");
        plan_promotion(&self.db.control_store().scoped(self.scope), &source)
            .await
            .expect("plan runs")
            .expect("plan builds")
            .plan_id()
            .to_owned()
    }

    /// An invocation against this server with the operator credential.
    fn invoke(&self, command: Command, json: bool) -> Invocation {
        Invocation {
            command,
            api_base: Some(self.base_url.clone()),
            credential: Some(Credential::new(OPERATOR_TOKEN)),
            json,
        }
    }
}

/// A monotonic counter so parallel tests never share a temp document path.
static DOC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `contents` to a fresh temp file and return its path.
fn write_doc(contents: &str) -> PathBuf {
    let unique = DOC_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "ironauth-apply-{}-{unique}.json",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write temp document");
    path
}

/// A minimal valid snapshot document carrying one variable.
fn variable_doc(name: &str, value: &str) -> String {
    format!(
        r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"variable":[{{"name":"{name}","value":"{value}"}}]}}}}"#
    )
}

/// Assert an output leaks no secret sentinel on stdout or stderr.
fn assert_no_secret_leak(output: &CommandOutput) {
    assert!(
        !output.stdout.contains(SECRET_SENTINEL),
        "secret value leaked to stdout: {}",
        output.stdout
    );
    assert!(
        !output.stderr.contains(SECRET_SENTINEL),
        "secret value leaked to stderr: {}",
        output.stderr
    );
}

#[tokio::test]
async fn validate_accepts_a_good_document_and_rejects_a_secret_bearing_one() {
    // A good document validates locally (no server needed).
    let good = write_doc(&variable_doc("greeting", "hello"));
    let output = execute(&Invocation {
        command: Command::Validate { document: good },
        api_base: None,
        credential: None,
        json: false,
    })
    .await;
    assert_eq!(output.exit, ExitCode::Success, "stderr: {}", output.stderr);
    assert!(output.stdout.contains("valid"));

    // A document carrying raw secret material (a `client_secret` inline value) is
    // rejected, and the inline value never appears in the CLI output.
    let secret_bearing = write_doc(&format!(
        r#"{{"schema_version":"{SNAPSHOT_SCHEMA_VERSION}","resources":{{"client":[{{"client_id":"c1","display_name":"c","token_endpoint_auth_method":"none","client_secret":"{SECRET_SENTINEL}"}}]}}}}"#
    ));
    let output = execute(&Invocation {
        command: Command::Validate {
            document: secret_bearing,
        },
        api_base: None,
        credential: None,
        json: false,
    })
    .await;
    assert_eq!(output.exit, ExitCode::Failure);
    assert!(
        output.stderr.contains("client_secret"),
        "stderr: {}",
        output.stderr
    );
    assert_no_secret_leak(&output);
}

#[tokio::test]
async fn plan_and_dry_run_render_the_server_plan_with_parity() {
    let fixture = Fixture::start().await;
    let doc_text = variable_doc("greeting", "hello");
    let doc = write_doc(&doc_text);
    let server_plan_id = fixture.server_plan_id(&doc_text).await;

    // `plan --json` renders the server's plan; its id matches the server's.
    let plan_out = execute(&fixture.invoke(
        Command::Plan {
            document: doc.clone(),
            target: fixture.target(),
        },
        true,
    ))
    .await;
    assert_eq!(
        plan_out.exit,
        ExitCode::Success,
        "stderr: {}",
        plan_out.stderr
    );
    let plan_json: serde_json::Value =
        serde_json::from_str(plan_out.stdout.trim()).expect("plan json");
    assert_eq!(
        plan_json.get("plan_id").and_then(serde_json::Value::as_str),
        Some(server_plan_id.as_str())
    );

    // `apply --dry-run --json` renders the SAME plan (id and content), and applies
    // nothing.
    let dry_out = execute(&fixture.invoke(
        Command::Apply {
            document: doc.clone(),
            target: fixture.target(),
            dry_run: true,
            expect_revision: None,
        },
        true,
    ))
    .await;
    assert_eq!(dry_out.exit, ExitCode::Success);
    let dry_json: serde_json::Value =
        serde_json::from_str(dry_out.stdout.trim()).expect("dry-run json");
    assert_eq!(dry_json, plan_json, "dry-run must match plan byte for byte");

    // The dry run applied nothing: the target is still empty.
    let after = export_snapshot(&fixture.db.control_store().scoped(fixture.scope))
        .await
        .expect("export");
    assert!(
        after.resources.variable.is_empty(),
        "dry-run must not apply"
    );
}

#[tokio::test]
async fn apply_is_transactional_and_idempotent() {
    let fixture = Fixture::start().await;
    let doc = write_doc(&variable_doc("greeting", "hello"));

    // First apply creates the variable.
    let applied = execute(&fixture.invoke(
        Command::Apply {
            document: doc.clone(),
            target: fixture.target(),
            dry_run: false,
            expect_revision: None,
        },
        false,
    ))
    .await;
    assert_eq!(
        applied.exit,
        ExitCode::Success,
        "stderr: {}",
        applied.stderr
    );
    assert!(
        applied.stdout.contains("applied"),
        "stdout: {}",
        applied.stdout
    );

    let snapshot = export_snapshot(&fixture.db.control_store().scoped(fixture.scope))
        .await
        .expect("export");
    assert_eq!(snapshot.resources.variable.len(), 1);
    assert_eq!(snapshot.resources.variable[0].value, "hello");

    // Re-applying the unchanged document is a no-op, exit 0.
    let reapplied = execute(&fixture.invoke(
        Command::Apply {
            document: doc,
            target: fixture.target(),
            dry_run: false,
            expect_revision: None,
        },
        false,
    ))
    .await;
    assert_eq!(reapplied.exit, ExitCode::Success);
    assert!(
        reapplied.stdout.contains("no changes"),
        "stdout: {}",
        reapplied.stdout
    );
}

#[tokio::test]
async fn apply_gated_on_a_stale_revision_reports_drift_and_exits_nonzero() {
    let fixture = Fixture::start().await;

    // Establish a baseline (greeting=hello) and capture its revision.
    let v1 = write_doc(&variable_doc("greeting", "hello"));
    let _ = execute(&fixture.invoke(
        Command::Apply {
            document: v1,
            target: fixture.target(),
            dry_run: false,
            expect_revision: None,
        },
        false,
    ))
    .await;
    let stale_revision = fixture.current_revision().await;

    // Mutate the target out of band (greeting=world), so the captured revision is
    // now stale.
    let v2 = write_doc(&variable_doc("greeting", "world"));
    let _ = execute(&fixture.invoke(
        Command::Apply {
            document: v2,
            target: fixture.target(),
            dry_run: false,
            expect_revision: None,
        },
        false,
    ))
    .await;

    // Apply a third document gated on the STALE revision: the server detects drift.
    let v3 = write_doc(&variable_doc("greeting", "drifted"));
    let output = execute(&fixture.invoke(
        Command::Apply {
            document: v3,
            target: fixture.target(),
            dry_run: false,
            expect_revision: Some(stale_revision),
        },
        false,
    ))
    .await;
    assert_eq!(output.exit, ExitCode::Drift, "stdout: {}", output.stdout);
    assert!(output.stderr.contains("drift"), "stderr: {}", output.stderr);

    // The drifted apply changed nothing: the out-of-band value stands.
    let snapshot = export_snapshot(&fixture.db.control_store().scoped(fixture.scope))
        .await
        .expect("export");
    assert_eq!(snapshot.resources.variable[0].value, "world");
}

#[tokio::test]
async fn drift_subcommand_exit_codes() {
    let fixture = Fixture::start().await;
    fixture.set_var("greeting", "hello").await;

    // In sync: the document matches the live target.
    let in_sync = execute(&fixture.invoke(
        Command::Drift {
            document: write_doc(&variable_doc("greeting", "hello")),
            target: fixture.target(),
        },
        false,
    ))
    .await;
    assert_eq!(
        in_sync.exit,
        ExitCode::Success,
        "stderr: {}",
        in_sync.stderr
    );
    assert!(
        in_sync.stdout.contains("in sync"),
        "stdout: {}",
        in_sync.stdout
    );

    // Drifted: the document differs from the live target.
    let drifted = execute(&fixture.invoke(
        Command::Drift {
            document: write_doc(&variable_doc("greeting", "world")),
            target: fixture.target(),
        },
        false,
    ))
    .await;
    assert_eq!(drifted.exit, ExitCode::Drift);
    assert!(
        drifted.stderr.contains("drift"),
        "stderr: {}",
        drifted.stderr
    );
}

#[tokio::test]
async fn unresolved_reference_is_a_plan_time_error() {
    let fixture = Fixture::start().await;
    // A variable referencing a secret the target does not carry.
    let doc = write_doc(&variable_doc("db_url", "${secret:missing_secret}"));

    let plan_out = execute(&fixture.invoke(
        Command::Plan {
            document: doc.clone(),
            target: fixture.target(),
        },
        false,
    ))
    .await;
    assert_eq!(plan_out.exit, ExitCode::Failure);
    assert!(
        plan_out.stderr.contains("resolve") || plan_out.stderr.contains("reference"),
        "stderr: {}",
        plan_out.stderr
    );

    // Apply surfaces the same plan-time failure and exits nonzero.
    let apply_out = execute(&fixture.invoke(
        Command::Apply {
            document: doc,
            target: fixture.target(),
            dry_run: false,
            expect_revision: None,
        },
        false,
    ))
    .await;
    assert_eq!(apply_out.exit, ExitCode::Failure);
}

#[tokio::test]
async fn write_only_secret_value_never_appears_in_output() {
    let fixture = Fixture::start().await;
    // Seed a secret whose VALUE is the sentinel, and reference it (never inline it).
    fixture
        .put_secret("db_password", SECRET_SENTINEL.as_bytes())
        .await;
    let doc_text = variable_doc("db_url", "${secret:db_password}");
    let doc = write_doc(&doc_text);

    // Plan resolves the reference (the secret exists) and renders the plan; the
    // reference NAME may appear, the VALUE must not.
    let plan_out = execute(&fixture.invoke(
        Command::Plan {
            document: doc.clone(),
            target: fixture.target(),
        },
        false,
    ))
    .await;
    assert_eq!(
        plan_out.exit,
        ExitCode::Success,
        "stderr: {}",
        plan_out.stderr
    );
    assert!(
        plan_out.stdout.contains("${secret:db_password}"),
        "the reference token should render: {}",
        plan_out.stdout
    );
    assert_no_secret_leak(&plan_out);

    // Apply the document; scan its output too.
    let apply_out = execute(&fixture.invoke(
        Command::Apply {
            document: doc.clone(),
            target: fixture.target(),
            dry_run: false,
            expect_revision: None,
        },
        false,
    ))
    .await;
    assert_eq!(
        apply_out.exit,
        ExitCode::Success,
        "stderr: {}",
        apply_out.stderr
    );
    assert_no_secret_leak(&apply_out);

    // And the json rendering of the plan is secret-free as well.
    let json_out = execute(&fixture.invoke(
        Command::Plan {
            document: doc,
            target: fixture.target(),
        },
        true,
    ))
    .await;
    assert_no_secret_leak(&json_out);
}
