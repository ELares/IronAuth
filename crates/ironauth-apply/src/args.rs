// SPDX-License-Identifier: MIT OR Apache-2.0

//! Argument parsing for the config-as-code subcommands.
//!
//! Hand-rolled to match the existing `ironauth` binary's dependency-light style
//! (no argument-parser crate enters the graph). The parser is a pure function of
//! its argument vector and an injected environment lookup, so the integration
//! tests exercise it hermetically without touching the process environment.
//!
//! The management credential is sourced from `--token` or `IRONAUTH_TOKEN` and is
//! never echoed; the environment variable is preferred because a `--token` value
//! is visible in the process table.

use std::path::PathBuf;

use crate::client::Credential;
use crate::command::{Command, Invocation, Target};

/// The environment variable holding the management API base URL.
const ENV_API_URL: &str = "IRONAUTH_API_URL";
/// The environment variable holding the management bearer credential.
const ENV_TOKEN: &str = "IRONAUTH_TOKEN";

/// A parse that did not yield an [`Invocation`]: either an explicit help request
/// (printed to stdout, exit 0) or a usage error (printed to stderr, exit nonzero).
#[derive(Debug, Clone)]
pub struct ParseFailure {
    /// The text to print (already newline-terminated).
    pub message: String,
    /// True for an explicit `--help`/`-h`, false for a usage error.
    pub help: bool,
}

impl ParseFailure {
    /// A usage error (stderr, nonzero exit).
    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            help: false,
        }
    }

    /// A help request (stdout, exit 0).
    fn help(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            help: true,
        }
    }
}

/// The raw flags gathered before they are shaped into a [`Command`].
#[derive(Default)]
struct Gathered {
    /// The positional document path.
    document: Option<PathBuf>,
    /// The `--target` selector.
    target: Option<String>,
    /// The `--api-url` override.
    api_url: Option<String>,
    /// The `--token` override.
    token: Option<String>,
    /// The `--expect-revision` value (apply only).
    expect_revision: Option<String>,
    /// Whether `--dry-run` was set (apply only).
    dry_run: bool,
    /// Whether `--json` was set.
    json: bool,
}

/// Parse a subcommand argument vector (with `argv[0]` the verb) into an
/// [`Invocation`], resolving the endpoint and credential from `env` when a flag is
/// absent.
///
/// # Errors
///
/// A usage message (already newline-terminated) when the verb or an argument is
/// missing, unknown, or invalid for the chosen subcommand.
pub fn parse<F>(argv: &[String], env: F) -> Result<Invocation, ParseFailure>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(verb) = argv.first() else {
        return Err(ParseFailure::usage(usage()));
    };

    let mut gathered = Gathered::default();
    let mut index = 1;
    while index < argv.len() {
        let arg = &argv[index];
        // Support both `--flag value` and `--flag=value`.
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_owned())),
            None => (arg.as_str(), None),
        };
        match flag {
            "--target" => gathered.target = Some(take_value(argv, &mut index, inline, "--target")?),
            "--api-url" => {
                gathered.api_url = Some(take_value(argv, &mut index, inline, "--api-url")?);
            }
            "--token" => gathered.token = Some(take_value(argv, &mut index, inline, "--token")?),
            "--expect-revision" => {
                gathered.expect_revision =
                    Some(take_value(argv, &mut index, inline, "--expect-revision")?);
            }
            "--dry-run" => {
                reject_inline(inline.is_some(), "--dry-run")?;
                gathered.dry_run = true;
            }
            "--json" => {
                reject_inline(inline.is_some(), "--json")?;
                gathered.json = true;
            }
            "--help" | "-h" => return Err(ParseFailure::help(help(verb))),
            other if other.starts_with('-') => {
                return Err(ParseFailure::usage(format!(
                    "ironauth {verb}: unknown option {other}\n{}",
                    help(verb)
                )));
            }
            _ => {
                if gathered.document.is_some() {
                    return Err(ParseFailure::usage(format!(
                        "ironauth {verb}: unexpected extra argument {arg:?}\n{}",
                        help(verb)
                    )));
                }
                gathered.document = Some(PathBuf::from(arg));
            }
        }
        index += 1;
    }

    build(verb, gathered, &env)
}

/// Consume the value for `flag`: the inline `=value`, or the next argument.
fn take_value(
    argv: &[String],
    index: &mut usize,
    inline: Option<String>,
    flag: &str,
) -> Result<String, ParseFailure> {
    if let Some(value) = inline {
        return Ok(value);
    }
    *index += 1;
    match argv.get(*index) {
        Some(value) => Ok(value.clone()),
        None => Err(ParseFailure::usage(format!(
            "ironauth: {flag} requires a value\n"
        ))),
    }
}

/// Reject an `=value` attached to a boolean flag.
fn reject_inline(has_value: bool, flag: &str) -> Result<(), ParseFailure> {
    if has_value {
        Err(ParseFailure::usage(format!(
            "ironauth: {flag} takes no value\n"
        )))
    } else {
        Ok(())
    }
}

/// Shape the gathered flags into a validated [`Invocation`] for `verb`.
fn build<F>(verb: &str, gathered: Gathered, env: &F) -> Result<Invocation, ParseFailure>
where
    F: Fn(&str) -> Option<String>,
{
    let document = gathered.document.ok_or_else(|| {
        ParseFailure::usage(format!(
            "ironauth {verb}: a document argument is required\n{}",
            help(verb)
        ))
    })?;

    let api_base = gathered.api_url.or_else(|| env(ENV_API_URL));
    let credential = gathered
        .token
        .or_else(|| env(ENV_TOKEN))
        .map(Credential::new);
    let json = gathered.json;

    // Flags valid only for `apply`.
    if verb != "apply" && (gathered.dry_run || gathered.expect_revision.is_some()) {
        return Err(ParseFailure::usage(format!(
            "ironauth {verb}: --dry-run and --expect-revision are only valid for 'apply'\n"
        )));
    }

    let command = match verb {
        "validate" => {
            if gathered.target.is_some() {
                return Err(ParseFailure::usage(
                    "ironauth validate: --target is not used (validation is local)\n",
                ));
            }
            Command::Validate { document }
        }
        "plan" => Command::Plan {
            document,
            target: parse_target(gathered.target.as_deref(), verb)?,
        },
        "apply" => Command::Apply {
            document,
            target: parse_target(gathered.target.as_deref(), verb)?,
            dry_run: gathered.dry_run,
            expect_revision: gathered.expect_revision,
        },
        "drift" => Command::Drift {
            document,
            target: parse_target(gathered.target.as_deref(), verb)?,
        },
        other => {
            return Err(ParseFailure::usage(format!(
                "ironauth: unknown subcommand {other:?}\n{}",
                usage()
            )));
        }
    };

    Ok(Invocation {
        command,
        api_base,
        credential,
        json,
    })
}

/// Parse the required `--target` selector for a networked subcommand.
fn parse_target(raw: Option<&str>, verb: &str) -> Result<Target, ParseFailure> {
    let Some(raw) = raw else {
        return Err(ParseFailure::usage(format!(
            "ironauth {verb}: --target TENANT/ENVIRONMENT is required\n"
        )));
    };
    Target::parse(raw)
        .map_err(|message| ParseFailure::usage(format!("ironauth {verb}: {message}\n")))
}

/// The top-level usage summary for the config-as-code subcommands.
fn usage() -> String {
    "\
usage: ironauth <validate|plan|apply|drift> <document> [options]

  validate <document>                    validate a document against the snapshot format (local)
  plan <document> --target T/E           render the server-computed promotion plan
  apply <document> --target T/E          apply a document to a target environment
    [--dry-run] [--expect-revision REV]
  drift <document> --target T/E          report whether the target has drifted

options:
  --api-url URL     management API base URL (or IRONAUTH_API_URL)
  --token TOKEN     management bearer credential (or IRONAUTH_TOKEN; env preferred)
  --json            emit the server's JSON verbatim
"
    .to_owned()
}

/// Per-verb help text.
fn help(verb: &str) -> String {
    match verb {
        "validate" => "\
usage: ironauth validate <document> [--json]

Validate a local declarative document against the published snapshot format.
Reuses the server's validator; performs no network call. Exits 0 when valid,
nonzero with the violations when invalid.
"
        .to_owned(),
        "plan" => "\
usage: ironauth plan <document> --target TENANT/ENVIRONMENT [--json]
       [--api-url URL] [--token TOKEN]

Submit a document to the server's promotion plan endpoint and render the
server-computed plan (its plan id, revisions, references, and diff). No local
diffing. Exits nonzero on a validation error or an unresolved reference.
"
        .to_owned(),
        "apply" => "\
usage: ironauth apply <document> --target TENANT/ENVIRONMENT
       [--dry-run] [--expect-revision REV] [--json] [--api-url URL] [--token TOKEN]

Apply a document to a target environment through the transactional promotion
apply endpoint. --dry-run renders the same plan as 'plan' and applies nothing.
--expect-revision gates the apply on a reviewed plan's base revision (a CI gate):
a target that drifted since then fails with exit code 2 and changes nothing.
A re-apply of an unchanged target is a no-op and exits 0.
"
        .to_owned(),
        "drift" => "\
usage: ironauth drift <document> --target TENANT/ENVIRONMENT [--json]
       [--api-url URL] [--token TOKEN]

Compare a document against the live target via the server plan endpoint. Exits 0
when in sync, exit code 2 when the target has drifted (suitable for a CI gate).
"
        .to_owned(),
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::command::Command;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn validate_needs_only_a_document() {
        let invocation = parse(&argv(&["validate", "doc.json"]), no_env).expect("parses");
        assert!(matches!(invocation.command, Command::Validate { .. }));
        assert!(invocation.api_base.is_none());
    }

    #[test]
    fn validate_rejects_target() {
        assert!(parse(&argv(&["validate", "doc.json", "--target", "a/b"]), no_env).is_err());
    }

    #[test]
    fn plan_requires_target() {
        assert!(parse(&argv(&["plan", "doc.json"]), no_env).is_err());
        let invocation = parse(
            &argv(&["plan", "doc.json", "--target", "acme/prod"]),
            no_env,
        )
        .expect("parses");
        assert!(matches!(invocation.command, Command::Plan { .. }));
    }

    #[test]
    fn apply_flags_shape_the_command() {
        let invocation = parse(
            &argv(&[
                "apply",
                "doc.json",
                "--target",
                "acme/prod",
                "--dry-run",
                "--expect-revision",
                "rev123",
            ]),
            no_env,
        )
        .expect("parses");
        match invocation.command {
            Command::Apply {
                dry_run,
                expect_revision,
                ..
            } => {
                assert!(dry_run);
                assert_eq!(expect_revision.as_deref(), Some("rev123"));
            }
            _ => panic!("expected apply"),
        }
    }

    #[test]
    fn dry_run_rejected_for_non_apply() {
        assert!(
            parse(
                &argv(&["plan", "doc.json", "--target", "a/b", "--dry-run"]),
                no_env
            )
            .is_err()
        );
    }

    #[test]
    fn endpoint_and_token_fall_back_to_env() {
        let env = |key: &str| match key {
            "IRONAUTH_API_URL" => Some("http://127.0.0.1:9000".to_owned()),
            "IRONAUTH_TOKEN" => Some("tok".to_owned()),
            _ => None,
        };
        let invocation =
            parse(&argv(&["plan", "doc.json", "--target", "acme/prod"]), env).expect("parses");
        assert_eq!(
            invocation.api_base.as_deref(),
            Some("http://127.0.0.1:9000")
        );
        assert!(invocation.credential.is_some());
    }

    #[test]
    fn inline_equals_form_is_accepted() {
        let invocation = parse(
            &argv(&[
                "plan",
                "doc.json",
                "--target=acme/prod",
                "--api-url=http://h:1",
            ]),
            no_env,
        )
        .expect("parses");
        assert_eq!(invocation.api_base.as_deref(), Some("http://h:1"));
    }

    #[test]
    fn unknown_flag_is_a_usage_error() {
        assert!(parse(&argv(&["plan", "doc.json", "--nope"]), no_env).is_err());
    }

    #[test]
    fn missing_document_is_a_usage_error() {
        assert!(parse(&argv(&["validate"]), no_env).is_err());
    }
}
