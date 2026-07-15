// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth binary entry point.
//!
//! `ironauth serve [--config PATH]` loads and strictly validates config, wires
//! telemetry, and runs the dual-plane server until `SIGTERM`/`SIGINT`, draining
//! in-flight requests within the configured grace period. `--version` and
//! `--help` stay dependency-light and never touch the async runtime.

use std::process::ExitCode;
use std::sync::Arc;

use axum::Router;
use ironauth_admin::AdminState;
use ironauth_config::{
    Config, FeatureRegistry, GLOBAL_TOKEN_REVOCATION_FEATURE, Loaded, OidcConfig, QuotaConfig,
};
use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_oidc::{
    BackChannelLogoutWorker, DiscoveryCapabilities, DiscoveryState, FetchLogoutSender,
    IssuerRegistry, IssuerState, JwksCacheWindow, OidcState, WorkerSettings, discovery_router,
    issuer_router, oidc_router,
};
use ironauth_quota::QuotaEnforcer;
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

        // The strict feature-maturity gate (issue #4): every `[features]` entry must
        // name a feature this build knows, and an enabled EXPERIMENTAL feature must
        // acknowledge its exact current version. A violation fails the boot with the
        // changelog pointer rather than silently changing behavior (for example arming
        // the experimental global-token-revocation receiver without an ack).
        let features = FeatureRegistry::builtin();
        if let Err(error) = features.validate(&config) {
            tracing::error!(%error, "refusing to boot on a feature-gate violation");
            return ExitCode::FAILURE;
        }
        // The experimental Global Token Revocation receiver (issue #36) mounts only when
        // its feature is enabled AND acknowledged; the gate is the ladder, never a plain
        // [oidc] toggle, so the ack can never be bypassed.
        let global_revocation_enabled =
            features.is_enabled(&config, GLOBAL_TOKEN_REVOCATION_FEATURE);

        let env = Env::system();

        // Build the management API router (issue #11) before moving config into
        // the server. It mounts on the management plane only when a bootstrap
        // operator token is configured; otherwise the server boots exactly as the
        // DB-free skeleton it was, serving only health, readiness, and metrics.
        let management = build_management_router(&config, &env).await;

        // Capture what the OIDC mount (issue #12) needs before config and env
        // move into the server: the OIDC settings, the data-plane DSN, and an env
        // handle. The public issuer root is taken from the built server below.
        let oidc_inputs = if config.oidc.enabled {
            Some((
                config.oidc.clone(),
                config.database.url.expose().to_owned(),
                env.clone(),
                resolve_master_key(&config),
                config.quota.clone(),
            ))
        } else {
            None
        };

        // Capture what the Back-Channel Logout delivery worker (issue #34) needs before
        // config moves into the server (only when OIDC is mounted AND the switch is on).
        let backchannel_inputs = backchannel_worker_inputs(&config, &env);

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
        // Mount the OIDC provider on the PUBLIC plane when enabled. The issuer root
        // is the server's config-derived base URL, so issuers are per environment.
        if let Some((oidc_config, dsn, oidc_env, master_key, quota_config)) = oidc_inputs {
            let issuer_base = server.base_url();
            if let Some(router) = build_oidc_router(
                &oidc_config,
                &dsn,
                oidc_env,
                issuer_base,
                global_revocation_enabled,
                master_key,
                &quota_config,
            )
            .await
            {
                server = server.mount_public(router);
            }
        } else {
            tracing::info!("OIDC provider not mounted: oidc.enabled is false");
        }
        // The OIDC Back-Channel Logout delivery worker (issue #34), spawned only when the
        // OIDC provider is mounted AND its posture switch is on. Off by default (the
        // covenant: no mandatory background infrastructure).
        if let Some(inputs) = backchannel_inputs {
            spawn_backchannel_logout_worker(inputs, server.base_url()).await;
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

/// Build the OIDC provider router (issue #12), or `None` if it should not be
/// mounted.
///
/// Mounts only when `oidc.enabled` is set (checked by the caller), connecting the
/// DATA-plane store with `database.url` (the least-privilege `ironauth_app` DSN in
/// production). A failure to connect is logged and the server keeps serving the
/// rest of the public plane rather than refusing to boot.
///
/// Per-environment signing keys load LAZILY from the store (issue #194): the ONE
/// shared [`IssuerRegistry`] reads a scope's keys through the RLS-forced
/// [`Store::scoped`] on the first request for that issuer, and caches the result.
/// The token mint (through [`OidcState`]), the JWKS serving (through
/// [`IssuerState`]), AND discovery (through [`DiscoveryState`]) all read that SAME
/// registry, so a signed `kid` is in the published JWKS and the discovery document
/// advertises the environment's real signing algorithms by construction. An
/// environment with no provisioned key resolves to an empty key set: its token
/// endpoint fails closed with `server_error` and its JWKS AND discovery return 404,
/// which is the correct behavior for a provider with no signing key. The
/// authorization endpoint and every binding, single-use, and revocation guarantee
/// work regardless.
///
/// All three surfaces mount on the public plane: the protocol router
/// (`/authorize`, `/token`, `/userinfo`), discovery (both well-known forms), and
/// the per-environment JWKS, all over that one store-backed registry. Discovery
/// resolves the per-environment algorithm policy from the loaded keys and returns
/// 404 for an unprovisioned OR cross-tenant scope, exactly like the JWKS surface.
/// The JWKS/discovery cache window is derived from `oidc.jwks_cache_max_age_secs`
/// and carried by the registry, so the served `Cache-Control: max-age` reflects the
/// configured value (AC #4).
async fn build_oidc_router(
    oidc_config: &OidcConfig,
    data_plane_dsn: &str,
    env: Env,
    issuer_base: String,
    global_revocation_enabled: bool,
    master_key: Option<Arc<MasterKey>>,
    quota_config: &QuotaConfig,
) -> Option<Router> {
    let store = match Store::connect(data_plane_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(
                %error,
                "OIDC provider not mounted: cannot connect the data-plane store"
            );
            return None;
        }
    };
    // Attach the platform envelope master key so the login, registration, and
    // UserInfo surfaces can seal and open the classified PII columns (issue #48).
    // Without it those paths fail closed (never plaintext); resolve_master_key has
    // already logged when it is unset or unreadable.
    let store = match master_key {
        Some(master) => store.with_master_key(master),
        None => store,
    };

    // The JWKS cache window from config (validated into the 300..=900s range, so
    // `clamped` is a no-op here); it governs the JWKS AND discovery Cache-Control.
    let cache = JwksCacheWindow::clamped(oidc_config.jwks_cache_max_age_secs);

    // The ONE shared registry: store-backed and lazy. The Store is cheap to clone
    // (it wraps a reference-counted pool), so the mint (via OidcState) and the
    // JWKS/discovery serving (via IssuerState) share one registry Arc.
    let registry = Arc::new(IssuerRegistry::store_backed(
        issuer_base.clone(),
        cache,
        store.clone(),
    ));

    // The discovery surface (both well-known forms) resolves the per-environment
    // signing policy from the SAME store-backed registry the mint and the JWKS read
    // (issue #194), so discovery, JWKS, and minted tokens can never advertise
    // divergent algorithms; an unprovisioned or cross-tenant scope resolves to no
    // entry and returns 404, exactly like the JWKS surface.
    let capabilities = DiscoveryCapabilities::from_config(oidc_config);
    let discovery = discovery_router(DiscoveryState::new(
        issuer_base.clone(),
        cache,
        capabilities,
        Arc::clone(&registry),
    ));

    // The per-environment JWKS surface, over the SAME registry the mint reads.
    let issuer_state = IssuerState::new(Arc::clone(&registry), env.clone());
    let jwks = issuer_router(issuer_state);

    // The data-plane quota enforcer (issue #50): one shared, in-memory nested
    // token-bucket engine seeded from the [quota] config and the SAME env clock, so
    // the tenant-fairness spend on the authorization path refills deterministically.
    // A dimension with a burst of 0 is unlimited, which is how a self-hoster who
    // wants no quota expresses it; enforcement then admits every request.
    let quota_enforcer = Arc::new(QuotaEnforcer::from_config(quota_config, env.clock_arc()));

    let state = OidcState::new(store, env, registry, oidc_config, issuer_base)
        .with_global_token_revocation_enabled(global_revocation_enabled)
        .with_quota_enforcer(quota_enforcer);
    if global_revocation_enabled {
        tracing::info!(
            "experimental Global Token Revocation receiver mounted (issue #36); the draft \
             is not WG-adopted and the wire shape may change between releases"
        );
    }
    tracing::info!(
        "OIDC provider, discovery, and per-environment JWKS mounted on the public plane; \
         per-environment signing keys load lazily from the store on first use"
    );
    Some(oidc_router(state).merge(discovery).merge(jwks))
}

/// What the Back-Channel Logout delivery worker (issue #34) needs to start, captured
/// before `config` moves into the server.
struct BackChannelWorkerInputs {
    /// The OIDC settings (the worker tuning knobs and the JWKS cache window).
    oidc: OidcConfig,
    /// The data-plane DSN the worker drains and signs through (the least-privilege
    /// `ironauth_app` role in production).
    data_plane_dsn: String,
    /// The control-plane DSN the worker enumerates `(tenant, environment)` scopes on (the
    /// non-RLS `environments` table only the control role can read); [`None`] disables the
    /// worker, since without it the worker cannot discover the scopes to drain.
    control_dsn: Option<String>,
    /// The environment seam (deterministic clock and entropy).
    env: Env,
}

/// Capture the Back-Channel Logout worker inputs from config (issue #34), or `None` when
/// the OIDC provider is not mounted or the posture switch is off. Pulled out of `serve` so
/// that function stays within the readable-length lint. The control-plane DSN is resolved
/// here (the worker enumerates scopes on the control plane).
fn backchannel_worker_inputs(config: &Config, env: &Env) -> Option<BackChannelWorkerInputs> {
    if !(config.oidc.enabled && config.oidc.backchannel_logout_enabled) {
        return None;
    }
    Some(BackChannelWorkerInputs {
        oidc: config.oidc.clone(),
        data_plane_dsn: config.database.url.expose().to_owned(),
        control_dsn: select_control_dsn(config),
        env: env.clone(),
    })
}

/// Spawn the OIDC Back-Channel Logout delivery worker (issue #34) as a detached
/// background task.
///
/// The worker drains the durable session-ended outbox per scope, builds one signed
/// Logout Token per participating relying party, and POSTs it through the SSRF-hardened
/// outbound fetcher, with bounded-backoff retries and a dead-letter state. Scope
/// enumeration is a CONTROL-plane read (the data-plane role cannot see the non-RLS
/// `environments` table), so the worker needs both a data-plane store (to drain and sign)
/// and a control-plane store (to enumerate). Any failure to connect or a missing control
/// DSN is logged and the worker is simply not spawned; the rest of the server runs
/// unaffected (the delivery queue is provisional and deliberately minimal, per issue #34,
/// and M11 migrates it onto the shared job-queue substrate).
async fn spawn_backchannel_logout_worker(inputs: BackChannelWorkerInputs, issuer_base: String) {
    let BackChannelWorkerInputs {
        oidc,
        data_plane_dsn,
        control_dsn,
        env,
    } = inputs;

    let Some(control_dsn) = control_dsn else {
        tracing::error!(
            "back-channel logout worker not started: no control-plane DSN to enumerate scopes \
             (set admin.control_database_url, or run in dev_mode). The delivery queue is durable, \
             so nothing is lost; enable the control plane to drain it."
        );
        return;
    };

    let data_store = match Store::connect(&data_plane_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "back-channel logout worker not started: data-plane connect failed");
            return;
        }
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "back-channel logout worker not started: control-plane connect failed");
            return;
        }
    };

    let cache = JwksCacheWindow::clamped(oidc.jwks_cache_max_age_secs);
    let registry = Arc::new(IssuerRegistry::store_backed(
        issuer_base,
        cache,
        data_store.clone(),
    ));
    let request_timeout =
        std::time::Duration::from_secs(oidc.backchannel_logout_request_timeout_secs);
    let sender = match FetchLogoutSender::with_timeout(request_timeout) {
        Ok(sender) => sender,
        Err(error) => {
            tracing::error!(%error, "back-channel logout worker not started: fetcher setup failed");
            return;
        }
    };
    let settings = WorkerSettings {
        max_attempts: oidc.backchannel_logout_max_attempts,
        retry_base: std::time::Duration::from_secs(oidc.backchannel_logout_retry_base_secs),
        lease: std::time::Duration::from_secs(oidc.backchannel_logout_request_timeout_secs.max(30)),
        batch: 64,
    };
    let poll = std::time::Duration::from_secs(oidc.backchannel_logout_poll_interval_secs);
    let worker = BackChannelLogoutWorker::new(data_store, env, registry, sender, settings);

    tracing::info!(
        "back-channel logout delivery worker started; draining the session-ended outbox per scope"
    );
    tokio::spawn(async move {
        loop {
            match control_store.management().list_environment_scopes().await {
                Ok(scopes) => {
                    for scope in scopes {
                        if let Err(error) = worker.run_once(scope).await {
                            tracing::warn!(%error, "back-channel logout drain pass failed for a scope");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "back-channel logout worker could not enumerate scopes");
                }
            }
            tokio::time::sleep(poll).await;
        }
    });
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

/// Resolve the platform envelope master key from config (issue #48).
///
/// Returns the derived key when `database.master_key` is set and readable, so the
/// OIDC store can seal and open classified PII columns. When the secret is unset
/// or unreadable, logs and returns `None`; the encrypted-PII paths then fail
/// closed (never plaintext) and a production deployment must set the key. The key
/// is DERIVED from the secret (a domain-separated HMAC), so any-length
/// high-entropy secret works and the same secret always yields the same key
/// (stable across restarts, which every wrapped tenant key depends on).
fn resolve_master_key(config: &Config) -> Option<Arc<MasterKey>> {
    let Some(secret) = &config.database.master_key else {
        tracing::warn!(
            "database.master_key is unset: the encrypted-PII paths (registration, login, \
             UserInfo) will fail closed rather than store plaintext. Set database.master_key to a \
             high-entropy secret (kept stable across restarts) before production."
        );
        return None;
    };
    match secret.resolve() {
        Ok(material) => Some(Arc::new(MasterKey::derive(
            "master-1",
            material.expose().as_bytes(),
        ))),
        Err(error) => {
            tracing::error!(
                %error,
                "cannot resolve database.master_key: the encrypted-PII paths will fail closed"
            );
            None
        }
    }
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
