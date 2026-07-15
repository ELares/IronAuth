// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ironauth`'s config-as-code CLI (issue #51, CLI half): a THIN client over the
//! server-side snapshot and promotion primitives.
//!
//! The subcommands manage a target environment's promotable configuration
//! declaratively:
//!
//! - `validate <document>` checks a local document against the published snapshot
//!   format (issue #43), reusing the server's own validator so the client can
//!   never drift from the server's notion of a valid document. It touches no
//!   network.
//! - `plan <document> --target T/E` submits the document to the server's promotion
//!   PLAN endpoint (issue #44) and renders the SERVER-computed plan verbatim: the
//!   same plan id, revisions, resolved references, and diff the server returns.
//!   The CLI performs no local diffing.
//! - `apply <document> --target T/E` applies the document through the transactional
//!   promotion APPLY endpoint. `--dry-run` renders the same plan `plan` would and
//!   applies nothing (dry-run parity). A re-apply of an unchanged target is a
//!   no-op (exit 0); a target that drifted since the reviewed revision fails with
//!   the drift exit code and changes nothing.
//! - `drift <document> --target T/E` reports whether the live target matches the
//!   document, with exit codes suitable for a CI gate (0 in sync, nonzero drift).
//!
//! All diff, plan, and apply semantics live in the server; this crate submits
//! documents and renders responses. See [`command`] for the per-subcommand flow
//! and the write-only-secret guarantee, and [`client`] for why the CLI carries its
//! own control-plane HTTP client rather than the server's SSRF-hardened fetcher.

mod args;
mod client;
mod command;
mod error;

pub use args::{ParseFailure, parse};
pub use client::{Credential, ManagementClient, ServerResponse};
pub use command::{Command, CommandOutput, Invocation, Target, execute};
pub use error::{ClientError, ExitCode};

/// Run one config-as-code subcommand end to end and return its process exit code.
///
/// `argv[0]` is the verb (`validate`, `plan`, `apply`, or `drift`) and the rest
/// are its arguments. The endpoint and credential are resolved from the flags or,
/// when absent, from `IRONAUTH_API_URL` and `IRONAUTH_TOKEN`. Output goes to
/// stdout, diagnostics to stderr; the credential is never printed.
#[must_use]
pub fn run(argv: &[String]) -> std::process::ExitCode {
    let invocation = match parse(argv, |key| std::env::var(key).ok()) {
        Ok(invocation) => invocation,
        Err(failure) => {
            // An explicit --help is a success printed to stdout; a usage error goes
            // to stderr with a nonzero exit.
            if failure.help {
                print!("{}", failure.message);
                return std::process::ExitCode::from(ExitCode::Success.code());
            }
            eprint!("{}", failure.message);
            return std::process::ExitCode::from(ExitCode::Usage.code());
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ironauth: cannot start async runtime: {error}");
            return std::process::ExitCode::from(ExitCode::Failure.code());
        }
    };

    let output = runtime.block_on(execute(&invocation));
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }
    std::process::ExitCode::from(output.exit.code())
}
