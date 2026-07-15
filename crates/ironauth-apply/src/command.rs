// SPDX-License-Identifier: MIT OR Apache-2.0

//! The command model and executor: what each subcommand does and how the
//! server's response becomes rendered output plus a stable exit code.
//!
//! Every subcommand is a THIN wrapper over a server-side primitive. `validate`
//! reuses the snapshot validator (issue #43); `plan`, the `--dry-run` mode of
//! `apply`, and `drift` all POST to the server's promotion PLAN endpoint (issue
//! #44) and render the SERVER-computed plan verbatim (no client-side diffing);
//! `apply` POSTs to the promotion APPLY endpoint. The CLI decides nothing about
//! diffing, plan ids, or drift semantics: it submits documents and renders what
//! the server returns.
//!
//! # Write-only secrets
//!
//! A promotion document is secret-free by construction (issue #43): a secret is a
//! REFERENCE (`${secret:NAME}`), never an inline value, and the validator rejects
//! inline secret material. The server's plan and apply responses carry only that
//! secret-free projection, so rendering them cannot echo a secret value. This
//! executor never prints the source document back, never prints the operator
//! credential, and renders only server-returned fields (reference NAMES, resource
//! keys, revisions, and change kinds), so a secret-scan over its output finds no
//! secret value.

use std::fmt::Write as _;
use std::path::PathBuf;

use ironauth_store::validate_document;

use crate::client::{Credential, ManagementClient, ServerResponse};
use crate::error::{ClientError, ExitCode};

/// A target environment, addressed by its tenant and environment identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The tenant identifier.
    pub tenant: String,
    /// The environment identifier.
    pub environment: String,
}

impl Target {
    /// Parse a `tenant/environment` target selector.
    ///
    /// # Errors
    ///
    /// A message describing the malformed selector.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((tenant, environment)) = raw.split_once('/') else {
            return Err(format!(
                "target must be TENANT/ENVIRONMENT (for example acme/prod); got {raw:?}"
            ));
        };
        if tenant.is_empty() || environment.is_empty() || environment.contains('/') {
            return Err(format!(
                "target must be TENANT/ENVIRONMENT (for example acme/prod); got {raw:?}"
            ));
        }
        Ok(Self {
            tenant: tenant.to_owned(),
            environment: environment.to_owned(),
        })
    }

    /// The promotion PLAN endpoint path for this target.
    #[must_use]
    pub fn plan_path(&self) -> String {
        format!(
            "/v1/tenants/{}/environments/{}/config/promotion/plan",
            self.tenant, self.environment
        )
    }

    /// The promotion APPLY endpoint path for this target.
    #[must_use]
    pub fn apply_path(&self) -> String {
        format!(
            "/v1/tenants/{}/environments/{}/config/promotion/apply",
            self.tenant, self.environment
        )
    }

    /// This target rendered `tenant/environment` for messages.
    fn display(&self) -> String {
        format!("{}/{}", self.tenant, self.environment)
    }
}

/// A single subcommand and its inputs.
#[derive(Debug, Clone)]
pub enum Command {
    /// Validate a local document against the published snapshot format.
    Validate {
        /// The document to validate.
        document: PathBuf,
    },
    /// Submit a document to the promotion plan endpoint and render the plan.
    Plan {
        /// The source document.
        document: PathBuf,
        /// The target environment.
        target: Target,
    },
    /// Apply a document to a target, or (with `dry_run`) render the plan without
    /// applying.
    Apply {
        /// The source document.
        document: PathBuf,
        /// The target environment.
        target: Target,
        /// When true, render the server plan and apply nothing (`--dry-run`).
        dry_run: bool,
        /// When set, apply only if the target still carries this revision (the
        /// `base_revision` of a previously reviewed plan); otherwise the CLI first
        /// asks the server for the current plan and applies against that revision.
        expect_revision: Option<String>,
    },
    /// Compare a document against the live target and report drift.
    Drift {
        /// The desired document.
        document: PathBuf,
        /// The target environment.
        target: Target,
    },
}

/// A fully parsed invocation: the subcommand plus the endpoint and credential the
/// networked subcommands need.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// The subcommand to run.
    pub command: Command,
    /// The management API base URL (required by `plan`, `apply`, and `drift`).
    pub api_base: Option<String>,
    /// The operator bearer credential (required by `plan`, `apply`, and `drift`).
    pub credential: Option<Credential>,
    /// When true, emit the server's JSON verbatim instead of a human summary.
    pub json: bool,
}

/// The captured result of running a command: an exit code and the text written to
/// stdout and stderr. Returning the text (rather than printing directly) lets the
/// integration tests scan every byte of output for a leaked secret.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// The process exit code.
    pub exit: ExitCode,
    /// Text destined for standard output.
    pub stdout: String,
    /// Text destined for standard error.
    pub stderr: String,
}

impl CommandOutput {
    /// A success carrying stdout text.
    fn ok(stdout: impl Into<String>) -> Self {
        Self {
            exit: ExitCode::Success,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// A failure carrying stderr text.
    fn fail(exit: ExitCode, stderr: impl Into<String>) -> Self {
        Self {
            exit,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

/// Run an invocation to completion, returning its captured output and exit code.
pub async fn execute(invocation: &Invocation) -> CommandOutput {
    match &invocation.command {
        Command::Validate { document } => validate(document, invocation.json),
        Command::Plan { document, target } => plan(invocation, document, target).await,
        Command::Apply {
            document,
            target,
            dry_run,
            expect_revision,
        } => {
            if *dry_run {
                plan(invocation, document, target).await
            } else {
                apply(invocation, document, target, expect_revision.as_deref()).await
            }
        }
        Command::Drift { document, target } => drift(invocation, document, target).await,
    }
}

/// Read a document from disk, mapping an IO error to a failure output.
fn read_document(document: &PathBuf) -> Result<Vec<u8>, CommandOutput> {
    std::fs::read(document).map_err(|error| {
        CommandOutput::fail(
            ExitCode::Failure,
            format!("cannot read document {}: {error}", document.display()),
        )
    })
}

/// `validate`: reuse the snapshot validator on a local document. Prints only the
/// violation paths and messages the validator returns, never the document itself.
fn validate(document: &PathBuf, json: bool) -> CommandOutput {
    let bytes = match read_document(document) {
        Ok(bytes) => bytes,
        Err(output) => return output,
    };
    match validate_document(&bytes) {
        Ok(snapshot) => {
            if json {
                CommandOutput::ok(r#"{"valid":true}"#)
            } else {
                let resources = &snapshot.resources;
                CommandOutput::ok(format!(
                    "valid: {} conforms to the snapshot format ({} client, {} resource_server, \
                     {} dcr_policy, {} variable)\n",
                    document.display(),
                    resources.client.len(),
                    resources.resource_server.len(),
                    resources.dcr_policy.len(),
                    resources.variable.len(),
                ))
            }
        }
        Err(violations) => {
            let mut body = String::new();
            if json {
                let items: Vec<serde_json::Value> = violations
                    .iter()
                    .map(|violation| {
                        serde_json::json!({
                            "path": violation.path,
                            "message": violation.message,
                        })
                    })
                    .collect();
                let payload = serde_json::json!({ "valid": false, "violations": items });
                body.push_str(&payload.to_string());
                body.push('\n');
            } else {
                let _ = writeln!(
                    body,
                    "invalid: {} has {} violation(s)",
                    document.display(),
                    violations.len()
                );
                for violation in &violations {
                    let path = if violation.path.is_empty() {
                        "(document)"
                    } else {
                        violation.path.as_str()
                    };
                    let _ = writeln!(body, "  {path}: {}", violation.message);
                }
            }
            CommandOutput::fail(ExitCode::Failure, body)
        }
    }
}

/// Build a client for the networked subcommands, or a usage failure if the base
/// URL or credential is missing.
fn client_for(invocation: &Invocation) -> Result<ManagementClient, CommandOutput> {
    let Some(base) = invocation.api_base.as_deref() else {
        return Err(CommandOutput::fail(
            ExitCode::Usage,
            "no management API endpoint: pass --api-url or set IRONAUTH_API_URL\n",
        ));
    };
    let Some(credential) = invocation.credential.clone() else {
        return Err(CommandOutput::fail(
            ExitCode::Usage,
            "no management credential: pass --token or set IRONAUTH_TOKEN\n",
        ));
    };
    ManagementClient::new(base, credential).map_err(|error| {
        CommandOutput::fail(ExitCode::Failure, format!("client setup failed: {error}\n"))
    })
}

/// Map a transport error to a failure output.
fn transport_failure(error: &ClientError) -> CommandOutput {
    CommandOutput::fail(
        ExitCode::Failure,
        format!("could not reach the management API: {error}\n"),
    )
}

/// `plan` (and `apply --dry-run`): POST the document to the plan endpoint and
/// render the server-computed plan. Renders exactly what the server returns.
async fn plan(invocation: &Invocation, document: &PathBuf, target: &Target) -> CommandOutput {
    let bytes = match read_document(document) {
        Ok(bytes) => bytes,
        Err(output) => return output,
    };
    let client = match client_for(invocation) {
        Ok(client) => client,
        Err(output) => return output,
    };
    let response = match client.post_json(&target.plan_path(), bytes).await {
        Ok(response) => response,
        Err(error) => return transport_failure(&error),
    };
    render_plan_response(&response, invocation.json)
}

/// Render a plan endpoint response for `plan`/`--dry-run`.
fn render_plan_response(response: &ServerResponse, json: bool) -> CommandOutput {
    if json {
        return match response.status {
            200 => CommandOutput::ok(format!("{}\n", response.body)),
            _ => CommandOutput::fail(ExitCode::Failure, format!("{}\n", response.body)),
        };
    }
    match response.status {
        200 => CommandOutput::ok(render_plan_text(&response.body)),
        400 => CommandOutput::fail(
            ExitCode::Failure,
            render_server_error("invalid document", response),
        ),
        422 => CommandOutput::fail(ExitCode::Failure, render_plan_failed(&response.body)),
        _ => CommandOutput::fail(
            ExitCode::Failure,
            render_server_error("plan failed", response),
        ),
    }
}

/// `apply`: obtain the base revision (from `--expect-revision`, else from a fresh
/// server plan), then POST the apply. Renders the server's outcome.
async fn apply(
    invocation: &Invocation,
    document: &PathBuf,
    target: &Target,
    expect_revision: Option<&str>,
) -> CommandOutput {
    let bytes = match read_document(document) {
        Ok(bytes) => bytes,
        Err(output) => return output,
    };
    let source: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => {
            return CommandOutput::fail(
                ExitCode::Failure,
                format!("document is not valid JSON: {error}\n"),
            );
        }
    };
    let client = match client_for(invocation) {
        Ok(client) => client,
        Err(output) => return output,
    };

    // Determine the base revision the apply is gated on. An explicit
    // --expect-revision is a CI gate: apply only if the target still carries that
    // reviewed revision. Otherwise ask the server for the current plan and apply
    // against its base revision (a one-shot converge).
    let base_revision = if let Some(revision) = expect_revision {
        revision.to_owned()
    } else {
        let plan_response = match client.post_json(&target.plan_path(), bytes).await {
            Ok(response) => response,
            Err(error) => return transport_failure(&error),
        };
        if plan_response.status != 200 {
            // Surface the plan-time failure (validation or unresolved reference)
            // exactly as `plan` would.
            return render_plan_response(&plan_response, invocation.json);
        }
        match plan_response
            .body
            .get("base_revision")
            .and_then(serde_json::Value::as_str)
        {
            Some(revision) => revision.to_owned(),
            None => {
                return CommandOutput::fail(
                    ExitCode::Failure,
                    "the server plan did not carry a base revision\n",
                );
            }
        }
    };

    let request = serde_json::json!({ "source": source, "base_revision": base_revision });
    let request_bytes = request.to_string().into_bytes();
    let response = match client.post_json(&target.apply_path(), request_bytes).await {
        Ok(response) => response,
        Err(error) => return transport_failure(&error),
    };
    render_apply_response(&response, invocation.json)
}

/// Render an apply endpoint response.
fn render_apply_response(response: &ServerResponse, json: bool) -> CommandOutput {
    if json {
        return match response.status {
            200 => CommandOutput::ok(format!("{}\n", response.body)),
            409 => CommandOutput::fail(ExitCode::Drift, format!("{}\n", response.body)),
            _ => CommandOutput::fail(ExitCode::Failure, format!("{}\n", response.body)),
        };
    }
    match response.status {
        200 => {
            let status = response
                .body
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            match status {
                "no_op" => CommandOutput::ok(
                    "no changes: the target already matches the document\n".to_owned(),
                ),
                "applied" => {
                    let changes = response
                        .body
                        .get("diff")
                        .and_then(serde_json::Value::as_array)
                        .map_or(0, Vec::len);
                    let mut body = format!("applied: {changes} change(s)\n");
                    if let Some(diff) = response.body.get("diff") {
                        body.push_str(&render_diff(diff));
                    }
                    CommandOutput::ok(body)
                }
                _ => CommandOutput::ok(format!("{}\n", response.body)),
            }
        }
        409 => CommandOutput::fail(ExitCode::Drift, render_drift_conflict(&response.body)),
        400 => CommandOutput::fail(
            ExitCode::Failure,
            render_server_error("invalid document", response),
        ),
        422 => CommandOutput::fail(ExitCode::Failure, render_unresolved(&response.body)),
        _ => CommandOutput::fail(
            ExitCode::Failure,
            render_server_error("apply failed", response),
        ),
    }
}

/// `drift`: POST the document to the plan endpoint and report whether the target
/// is in sync (empty diff, exit 0) or drifted (a non-empty diff, exit nonzero).
async fn drift(invocation: &Invocation, document: &PathBuf, target: &Target) -> CommandOutput {
    let bytes = match read_document(document) {
        Ok(bytes) => bytes,
        Err(output) => return output,
    };
    let client = match client_for(invocation) {
        Ok(client) => client,
        Err(output) => return output,
    };
    let response = match client.post_json(&target.plan_path(), bytes).await {
        Ok(response) => response,
        Err(error) => return transport_failure(&error),
    };

    if invocation.json {
        return match response.status {
            200 => {
                let empty = response
                    .body
                    .get("diff")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(Vec::is_empty);
                let output = format!("{}\n", response.body);
                if empty {
                    CommandOutput::ok(output)
                } else {
                    CommandOutput::fail(ExitCode::Drift, output)
                }
            }
            _ => CommandOutput::fail(ExitCode::Failure, format!("{}\n", response.body)),
        };
    }

    match response.status {
        200 => {
            let changes = response
                .body
                .get("diff")
                .and_then(serde_json::Value::as_array);
            let count = changes.map_or(0, Vec::len);
            if count == 0 {
                CommandOutput::ok(format!(
                    "in sync: {} matches the document\n",
                    target.display()
                ))
            } else {
                let mut body = format!(
                    "drift: {count} difference(s) between the document and {}\n",
                    target.display()
                );
                if let Some(diff) = response.body.get("diff") {
                    body.push_str(&render_diff(diff));
                }
                CommandOutput::fail(ExitCode::Drift, body)
            }
        }
        422 => CommandOutput::fail(ExitCode::Failure, render_plan_failed(&response.body)),
        400 => CommandOutput::fail(
            ExitCode::Failure,
            render_server_error("invalid document", &response),
        ),
        _ => CommandOutput::fail(
            ExitCode::Failure,
            render_server_error("drift check failed", &response),
        ),
    }
}

/// Render a successful plan as human-readable text. Renders reference NAMES and
/// change keys only, never a resource value that is not already in the secret-free
/// plan the server returned.
fn render_plan_text(plan: &serde_json::Value) -> String {
    let mut body = String::new();
    let plan_id = plan
        .get("plan_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(unknown)");
    let _ = writeln!(body, "plan {plan_id}");
    if let Some(base) = plan
        .get("base_revision")
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(body, "  base revision:   {base}");
    }
    if let Some(result) = plan
        .get("result_revision")
        .and_then(serde_json::Value::as_str)
    {
        let _ = writeln!(body, "  result revision: {result}");
    }
    if let Some(references) = plan.get("references").and_then(serde_json::Value::as_array) {
        let _ = writeln!(body, "  references: {}", references.len());
        for reference in references {
            if let Some(token) = reference.as_str() {
                let _ = writeln!(body, "    {token}");
            }
        }
    }
    let changes = plan.get("diff").and_then(serde_json::Value::as_array);
    let count = changes.map_or(0, Vec::len);
    let _ = writeln!(body, "  changes: {count}");
    if let Some(diff) = plan.get("diff") {
        body.push_str(&render_diff(diff));
    }
    body
}

/// Render a diff array as `  <change> <resource_type>/<key>` lines. Uses only the
/// change kind, resource type, and natural key; never the before/after values, so
/// no resource value is echoed even though the server's projection is secret-free.
fn render_diff(diff: &serde_json::Value) -> String {
    let mut body = String::new();
    if let Some(changes) = diff.as_array() {
        for change in changes {
            let kind = change
                .get("change")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let resource_type = change
                .get("resource_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let key = change
                .get("key")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let _ = writeln!(body, "    {kind} {resource_type}/{key}");
        }
    }
    body
}

/// Render the server's `plan_failed` (unresolved-reference) body (422 at plan).
fn render_plan_failed(body: &serde_json::Value) -> String {
    let mut out =
        String::from("plan failed: one or more references do not resolve in the target\n");
    if let Some(errors) = body.get("errors").and_then(serde_json::Value::as_array) {
        for error in errors {
            if let Some(text) = error.as_str() {
                let _ = writeln!(out, "  {text}");
            }
        }
    }
    out
}

/// Render the apply-time unresolved-reference body (422 at apply).
fn render_unresolved(body: &serde_json::Value) -> String {
    let reference = body
        .get("reference")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(unknown)");
    format!(
        "unresolved reference: {reference} does not resolve in the target; nothing was applied\n"
    )
}

/// Render the apply-time drift conflict body (409).
fn render_drift_conflict(body: &serde_json::Value) -> String {
    let expected = body
        .get("expected_revision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(unknown)");
    let actual = body
        .get("actual_revision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(unknown)");
    format!(
        "drift: the target changed since the expected revision (expected {expected}, found \
         {actual}); nothing was applied\n"
    )
}

/// Render a generic server error body, falling back to the status code.
fn render_server_error(context: &str, response: &ServerResponse) -> String {
    let message = response
        .body
        .get("message")
        .or_else(|| response.body.get("error"))
        .and_then(serde_json::Value::as_str);
    match message {
        Some(text) => format!("{context} (HTTP {}): {text}\n", response.status),
        None => format!("{context} (HTTP {})\n", response.status),
    }
}

#[cfg(test)]
mod tests {
    use super::Target;

    #[test]
    fn target_parses_tenant_and_environment() {
        let target = Target::parse("acme/prod").expect("parses");
        assert_eq!(target.tenant, "acme");
        assert_eq!(target.environment, "prod");
        assert!(target.plan_path().ends_with("/config/promotion/plan"));
        assert!(target.apply_path().ends_with("/config/promotion/apply"));
    }

    #[test]
    fn target_rejects_malformed_selectors() {
        assert!(Target::parse("acme").is_err());
        assert!(Target::parse("/prod").is_err());
        assert!(Target::parse("acme/").is_err());
        assert!(Target::parse("acme/prod/extra").is_err());
    }
}
