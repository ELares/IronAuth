// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth binary entry point.
//!
//! `ironauth serve [--config PATH]` loads and strictly validates config, wires
//! telemetry, and runs the dual-plane server until `SIGTERM`/`SIGINT`, draining
//! in-flight requests within the configured grace period. `--version` and
//! `--help` stay dependency-light and never touch the async runtime.

use std::process::ExitCode;

use axum::Router;
use ironauth_admin::AdminState;
use ironauth_config::{Config, Loaded};
use ironauth_env::Env;
use ironauth_server::Server;
use ironauth_store::Store;

/// Semantic version of this build, injected by Cargo.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => serve(&mut args),
        Some("--version" | "-V" | "version") => {
            println!("ironauth {VERSION}");
            ExitCode::SUCCESS
        }
        Some("--help" | "-h" | "help") | None => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("ironauth: unknown argument '{other}'");
            eprintln!("run 'ironauth --help' for usage");
            ExitCode::FAILURE
        }
    }
}

/// Run the `serve` subcommand.
fn serve(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let config_path = match parse_config_path(args) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ironauth serve: {message}");
            eprintln!("usage: ironauth serve [--config PATH]");
            return ExitCode::FAILURE;
        }
    };

    // Load and strictly validate config before touching the runtime. A default
    // (empty) config is valid for local development.
    let loaded = match &config_path {
        Some(path) => Config::load(path),
        None => Config::from_toml_str("", "<defaults>"),
    };
    let Loaded { config, warnings } = match loaded {
        Ok(loaded) => loaded,
        Err(error) => {
            eprintln!("ironauth: {error}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ironauth: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move {
        // Telemetry is initialized inside the runtime so the (optional) OTLP
        // batch exporter has a reactor to spawn on. The guard flushes on drop.
        let _telemetry = ironauth_server::telemetry::init(&config.telemetry);

        for warning in &warnings {
            tracing::warn!(%warning, "configuration warning");
        }

        let env = Env::system();

        // Build the management API router (issue #11) before moving config into
        // the server. It mounts on the management plane only when a bootstrap
        // operator token is configured; otherwise the server boots exactly as the
        // DB-free skeleton it was, serving only health, readiness, and metrics.
        let management = build_management_router(&config, &env).await;

        let mut server = match Server::new(config, env) {
            Ok(server) => server,
            Err(error) => {
                tracing::error!(%error, "failed to build server");
                return ExitCode::FAILURE;
            }
        };
        if let Some(router) = management {
            server = server.mount_management(router);
        }
        tracing::info!(base_url = %server.base_url(), "starting ironauth");

        match server.run(ironauth_server::shutdown_signal()).await {
            Ok(()) => {
                tracing::info!("ironauth stopped cleanly");
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "server exited with error");
                ExitCode::FAILURE
            }
        }
    })
}

/// Build the management API router, or `None` if it should not be mounted.
///
/// The management API mounts only when a bootstrap operator token is configured,
/// so the default (token unset) config still boots without a database, exactly
/// like the server skeleton. When configured, it connects a control-plane store
/// with the DSN chosen by [`select_control_dsn`] (per the D2 policy). A failure
/// to connect or an invalid admin config is logged and the server continues to
/// serve health, readiness, and metrics rather than refusing to boot.
async fn build_management_router(config: &Config, env: &Env) -> Option<Router> {
    if config.admin.bootstrap_operator_token.is_none() {
        tracing::info!(
            "management API not mounted: admin.bootstrap_operator_token is unset (operator plane \
             would be unauthorized)"
        );
        return None;
    }
    // Fail closed in production when the control DSN is unset; the selector logs
    // the reason (loud error in production, warning on the dev fallback).
    let control_dsn = select_control_dsn(config)?;
    let store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(
                %error,
                "management API not mounted: cannot connect the control-plane store"
            );
            return None;
        }
    };
    match AdminState::new(store, env.clone(), &config.admin) {
        Ok(state) => {
            tracing::info!("management API mounted on the management plane");
            Some(ironauth_admin::management_router(state))
        }
        Err(error) => {
            tracing::error!(%error, "management API not mounted: invalid admin config");
            None
        }
    }
}

/// Choose the control-plane database DSN for the management store (D2).
///
/// - `admin.control_database_url` set: use it (the least-privilege
///   `ironauth_control` DSN). A resolution failure logs and returns `None`.
/// - unset and `dev_mode`: fall back to `database.url` with a loud warning that
///   the `ironauth_control` role separation and the `management_credentials`
///   FORCE-RLS backstop are NOT enforced.
/// - unset and production (`dev_mode == false`): return `None` (fail closed);
///   the caller leaves the API unmounted. The operator must set the knob.
fn select_control_dsn(config: &Config) -> Option<String> {
    if let Some(secret) = &config.admin.control_database_url {
        return match secret.resolve() {
            Ok(dsn) => Some(dsn.expose().to_owned()),
            Err(error) => {
                tracing::error!(
                    %error,
                    "management API not mounted: cannot resolve admin.control_database_url"
                );
                None
            }
        };
    }
    if config.dev_mode {
        tracing::warn!(
            "admin.control_database_url is unset; in dev_mode the management API falls back to \
             database.url. The ironauth_control role separation and the management_credentials \
             FORCE row-level-security backstop are NOT enforced. Set admin.control_database_url \
             to a least-privilege ironauth_control DSN before production."
        );
        return Some(config.database.url.expose().to_owned());
    }
    tracing::error!(
        "management API not mounted: admin.control_database_url is unset and dev_mode is false. \
         Set it to a least-privilege ironauth_control DSN (the management plane must connect as \
         ironauth_control, not the data-plane role)."
    );
    None
}

/// Parse `--config PATH` (or `--config=PATH`) out of the serve arguments.
fn parse_config_path(
    args: &mut impl Iterator<Item = String>,
) -> Result<Option<String>, &'static str> {
    let mut config_path = None;
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--config=") {
            config_path = Some(value.to_owned());
        } else if arg == "--config" {
            config_path = Some(args.next().ok_or("--config requires a PATH")?);
        } else {
            return Err("unrecognized argument");
        }
    }
    Ok(config_path)
}

fn print_help() {
    println!("ironauth {VERSION}");
    println!("A standards-first OpenID Connect identity platform.");
    println!();
    println!("USAGE:");
    println!("  ironauth serve [--config PATH]   Run the server until SIGTERM/SIGINT");
    println!("  ironauth --version               Print the version");
    println!("  ironauth --help                  Print this help");
    println!();
    println!("The server serves a public data plane and a private management plane");
    println!("(health, readiness, metrics) on separate ports; see docs/CONFIG.md.");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        Config::from_toml_str(toml, "<test>")
            .expect("valid config")
            .config
    }

    #[test]
    fn control_dsn_uses_the_explicit_knob_when_set() {
        // Set: use control_database_url regardless of dev_mode.
        let cfg = config(
            "[admin]\nbootstrap_operator_token = \"t\"\n\
             control_database_url = \"postgres://ironauth_control@h/d\"\n",
        );
        assert_eq!(
            select_control_dsn(&cfg).as_deref(),
            Some("postgres://ironauth_control@h/d")
        );
    }

    #[test]
    fn control_dsn_falls_back_to_database_url_only_in_dev_mode() {
        let cfg = config("dev_mode = true\n[admin]\nbootstrap_operator_token = \"t\"\n");
        assert_eq!(
            select_control_dsn(&cfg).as_deref(),
            Some("postgres://ironauth@localhost:5432/ironauth"),
            "dev_mode falls back to database.url"
        );
    }

    #[test]
    fn control_dsn_refuses_in_production_when_unset() {
        // Unset + production: fail closed (do not mount).
        let cfg = config("[admin]\nbootstrap_operator_token = \"t\"\n");
        assert!(
            select_control_dsn(&cfg).is_none(),
            "production without the control DSN must refuse to mount"
        );
    }
}
