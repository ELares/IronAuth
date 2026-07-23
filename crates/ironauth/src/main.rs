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
use ironauth_admin::{AdminOidcBridge, AdminState};
use ironauth_config::{
    ADVANCED_RECOVERY_FEATURE, Config, DiagnosticsConfig, FEDCM_FEATURE,
    FIRST_PARTY_CHALLENGE_FEATURE, FeatureRegistry, GLOBAL_TOKEN_REVOCATION_FEATURE, Loaded,
    OidcConfig, PasswordHashingConfig, PasswordPolicyConfig, QuotaConfig, RISK_SIGNALS_FEATURE,
    SIGNUP_QUARANTINE_FEATURE, ScreeningFailurePolicy, ScreeningProvider,
};
use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_oidc::{
    BackChannelLogoutWorker, CredentialClass, DiscoveryCapabilities, DiscoveryState,
    FederationKeyResolver, FederationRuntime, FetchLogoutSender, IssuerRegistry, IssuerState,
    JwksCacheWindow, LazyMigrationHook, OidcState, WorkerSettings, canonical_login_identifier,
    canonical_step_up_acr, discovery_router, issuer_router, oidc_router,
};
use ironauth_quota::QuotaEnforcer;
use ironauth_server::{Server, SiteContext};
use ironauth_store::{
    AbuseBanId, AbuseSubject, AbuseSubjectKind, ActorRef, AuthPath, ClientId, CorrelationId,
    EnvironmentId, NewBan, Scope, ServiceId, Store, TenantId,
};

/// Semantic version of this build, injected by Cargo.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => serve(&mut args),
        // The config-as-code subcommands (issue #51) dispatch into ironauth-apply.
        // The verb is re-prepended so that crate parses its own argument vector.
        Some(verb @ ("validate" | "plan" | "apply" | "drift")) => {
            let mut subcommand_args = vec![verb.to_owned()];
            subcommand_args.extend(args);
            ironauth_apply::run(&subcommand_args)
        }
        // The Argon2id tuning probe (issue #62): a headless-install helper that
        // measures the host and recommends parameters. The same probe backs the
        // in-admin tuning helper; both call ironauth_oidc::run_probe.
        Some("hash-probe") => hash_probe(&mut args),
        // Credential-abuse ban management (issue #64): place, lift, and list durable
        // bans directly against the data-plane store, each an audited write. The admin
        // API (crates/ironauth-admin) offers the same operations over HTTP for remote
        // management; both write through the SAME audited store repository.
        Some(verb @ ("ban" | "unban" | "bans")) => manage_bans(verb, &mut args),
        // Declarative step-up authentication policy management (RFC 9470, issue #72):
        // set, list, and remove the per-scope and per-client (acr floor, max auth age)
        // requirement directly against the data-plane store, each an audited write
        // through the same Acting* repositories the enforcement path reads. This is the
        // operator surface that makes the declarative policy usable without hand-writing
        // Rust or SQL; a hosted admin HTTP CRUD can layer on later.
        Some("step-up-policy") => manage_step_up_policy(&mut args),
        // Declarative credential-class policy management (issue #66): set, list, and
        // remove the per-scope minimum-credential-class ladder row for a subject (the
        // tenant, a group, or an org), each an audited write through the same Acting
        // repository the authentication path composes from. This is the operator surface
        // that makes the declarative policy usable; a hosted admin HTTP CRUD can layer on
        // later (as #262 did for step-up).
        Some("credential-class-policy") => manage_credential_class_policy(&mut args),
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
// The boot sequence is one linear wiring list (config, telemetry, the migration hook,
// the management and OIDC routers, the background worker, then run); it reads top to
// bottom with no extractable unit, so the length lint is not meaningful here.
#[allow(clippy::too_many_lines)]
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
        // The experimental IdP-side FedCM surface (issue #83) is armed only when its
        // feature is enabled AND acknowledged; the gate is the ladder, never a plain
        // [oidc] toggle, so the ack can never be bypassed. Resolved to a bool here and
        // injected through the OIDC state builder (never OidcConfig), so every FedCM
        // route stays a 404 and discovery advertises nothing until an operator opts in.
        let fedcm_enabled = features.is_enabled(&config, FEDCM_FEATURE);
        // The experimental third-party risk-signal ingestion surface (issue #82, PR 1) is
        // armed only when its feature is enabled AND acknowledged; the gate is the ladder,
        // never a plain [oidc] toggle, so the ack can never be bypassed. Resolved to a bool
        // here and injected through the OIDC state builder (never OidcConfig), so the
        // ingestion endpoint stays a 404 and the engine reads no external signal until an
        // operator opts in.
        let risk_signals_enabled = features.is_enabled(&config, RISK_SIGNALS_FEATURE);
        // The experimental signup fraud-review-queue surface (issue #82, PR 2) is armed only
        // when its feature is enabled AND acknowledged; the gate is the ladder, never a plain
        // config toggle, so the ack can never be bypassed. Resolved to a bool here and
        // injected through BOTH the OIDC state builder (the register hook and the quarantined
        // authorize restrictions) and the admin state builder (the review-queue endpoints),
        // so the register path keeps BLOCKING a risky signup and the review-queue endpoints
        // stay 404s until an operator opts in.
        let signup_quarantine_enabled = features.is_enabled(&config, SIGNUP_QUARANTINE_FEATURE);
        // The experimental advanced-recovery-modes surface (issue #82, PR 3) is armed only
        // when its feature is enabled AND acknowledged; the gate is the ladder, never a plain
        // config toggle, so the ack can never be bypassed. Resolved to a bool here and
        // injected through BOTH the OIDC state builder (the recovery-method seam and the
        // trusted-contact / IDV data-plane routes) and the admin state builder (the
        // recovery-approval review queue), so every advanced-recovery path stays a 404 and
        // standard recovery is unchanged until an operator opts in.
        let advanced_recovery_enabled = features.is_enabled(&config, ADVANCED_RECOVERY_FEATURE);
        // The experimental OAuth 2.0 Authorization Challenge Endpoint (issue #93, Bet 3) is served
        // only when its feature is enabled AND acknowledged at the exact draft revision; the gate is
        // the ladder, never a plain [oidc] toggle, so the ack can never be bypassed. Resolved to a
        // bool here and injected through the OIDC state builder (never OidcConfig), so the
        // challenge endpoint stays a 404 and no browserless code can be minted until an operator
        // opts in AND acknowledges the draft.
        let first_party_challenge_enabled =
            features.is_enabled(&config, FIRST_PARTY_CHALLENGE_FEATURE);

        // The headless flow API (issue #84): a plain top-level operator toggle (like
        // `oidc.enabled`), off by default, resolved here before `config` is moved so the flow
        // routes answer a uniform 404 until an operator turns it on.
        let flows_enabled = config.flows.enabled;

        // The hosted-page render app cutover (issue #85): a plain top-level operator toggle,
        // off by default, resolved here before `config` is moved. It retargets the `/authorize`
        // login and registration interaction redirects onto the flow browser page, but ONLY in
        // composition with `flows_enabled` (the pages render through the flow engine), which the
        // state builder enforces via `hosted_pages_cutover`. A config that arms the pages without
        // the flow engine is surfaced as a load-time warning (see the config `collect_warnings`).
        let hosted_pages_enabled = config.hosted_pages.enabled;

        // The admin console SPA (issue #90): a plain top-level operator toggle, off by
        // default, resolved here before `config` is moved. When on, the embedded console is
        // mounted on the PUBLIC plane under /admin; while off nothing is mounted there and
        // every /admin path is a uniform 404.
        let admin_spa_enabled = config.admin_spa.enabled;
        // Whether the OIDC bridge is configured for the console (oidc on plus an admin
        // issuer scope plus a management audience). The same-origin management proxy is
        // wired ONLY when this holds, so enabling the console shell without configuring
        // its OIDC login does NOT expose the management API on the public plane. This is
        // the config level gate; `install_admin_oidc_bridge` re-checks it and arms the
        // verifying arm.
        let admin_bridge_configured = config.oidc.enabled
            && [
                config.admin_spa.admin_issuer_tenant.as_deref(),
                config.admin_spa.admin_issuer_environment.as_deref(),
                config.admin_spa.management_audience.as_deref(),
            ]
            .iter()
            .all(|v| v.is_some_and(|s| !s.trim().is_empty()));

        // The per environment runtime config the served console document carries in
        // its `<meta>` tags (issue #323), captured here before `config` moves into
        // the server. Populated ONLY when the OIDC bridge is configured; the admin
        // issuer is a SAME ORIGIN scoped path (`/t/{tenant}/e/{env}`) the SPA does
        // discovery against, so the embedded deploy needs no cross origin exception
        // (the issuer and management base stay empty, defaulting to this origin and
        // the /admin/api proxy). These are bounded, NON-secret operator identifiers;
        // the serving crate HTML escapes each before injecting it. When the bridge is
        // not configured every value is empty, leaving sign in unavailable.
        let admin_spa_runtime = if admin_bridge_configured {
            let trimmed = |v: &Option<String>| v.as_deref().unwrap_or_default().trim().to_owned();
            ironauth_admin_ui::RuntimeConfig {
                admin_issuer_path: format!(
                    "/t/{}/e/{}",
                    config
                        .admin_spa
                        .admin_issuer_tenant
                        .as_deref()
                        .unwrap_or_default()
                        .trim(),
                    config
                        .admin_spa
                        .admin_issuer_environment
                        .as_deref()
                        .unwrap_or_default()
                        .trim(),
                ),
                console_client_id: trimmed(&config.admin_spa.console_client_id),
                management_audience: trimmed(&config.admin_spa.management_audience),
            }
        } else {
            ironauth_admin_ui::RuntimeConfig::default()
        };

        // When advanced-recovery is armed, an IDV callback's signature is verified against each
        // provider's REGISTERED JWKS through the JOSE core. The config layer can only prove the
        // JWKS is NON-EMPTY (it carries no jose dep); parse it HERE, where jose IS available, so
        // a non-empty but MALFORMED JWKS (or one that yields zero usable keys) fails boot
        // CLEANLY instead of booting and then failing closed at every IDV recovery callback.
        // Only checked when the feature is armed (a malformed JWKS with the feature off is
        // inert), and only for enabled providers (mirroring the config non-empty check).
        if advanced_recovery_enabled {
            if let Err(error) = validate_idv_provider_jwks(&config.oidc.advanced_recovery) {
                tracing::error!(%error, "advanced-recovery IDV provider JWKS is invalid");
                return ExitCode::FAILURE;
            }
        }

        let env = Env::system();

        // The inbound lazy-migration hook (issue #56), built once and shared: it arms the
        // login path (OIDC data plane) to verify an unknown identifier's first login
        // against a legacy store, and the SAME Arc is handed to the management plane so the
        // migration-progress endpoint reports this node's circuit-breaker state. Built only
        // when the OIDC provider is mounted (the login path it guards) AND the hook is
        // enabled; disabled or misconfigured yields `None` (the login path is unchanged).
        let migration_hook = if config.oidc.enabled {
            ironauth_oidc::build_lazy_migration_hook(&config.oidc.lazy_migration, &env)
        } else {
            None
        };

        // The generic OIDC UPSTREAM federation runtime (issue #75), built once and shared: it
        // powers the /federation login legs (OIDC data plane) AND its per-connector health
        // registry (issue #76) is the SAME Arc handed to the management plane, so the admin
        // health-diagnostics read reports the live health the login path records into. Built only
        // when OIDC is mounted and federation is enabled; otherwise `None`.
        let federation_runtime = if config.oidc.enabled {
            build_federation_runtime(&config.oidc)
        } else {
            None
        };

        // Build the management API router (issue #11) before moving config into
        // the server. It mounts on the management plane only when a bootstrap
        // operator token is configured; otherwise the server boots exactly as the
        // DB-free skeleton it was, serving only health, readiness, and metrics.
        let management = build_management_router(
            &config,
            &env,
            migration_hook.clone(),
            federation_runtime.clone(),
            signup_quarantine_enabled,
            advanced_recovery_enabled,
        )
        .await;

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
                config.password_hashing.clone(),
                config.password_policy.clone(),
                config.diagnostics.clone(),
            ))
        } else {
            None
        };

        // Capture what the Back-Channel Logout delivery worker (issue #34) needs before
        // config moves into the server (only when OIDC is mounted AND the switch is on).
        let backchannel_inputs = backchannel_worker_inputs(&config, &env);
        // Capture what the one-shot signing-algorithm backfill (issue #93) needs before
        // config moves into the server (only when its switch is on). Runs before serving.
        let signing_backfill_inputs = signing_backfill_inputs(&config, &env);

        let mut server = match Server::new(config, env) {
            Ok(server) => server,
            Err(error) => {
                tracing::error!(%error, "failed to build server");
                return ExitCode::FAILURE;
            }
        };
        // Keep a clone of the management router (if any) for the admin console's
        // same-origin proxy (issue #90, PR 2): the browser reaches the management
        // API through /admin/api on the PUBLIC plane, which the proxy forwards to
        // THIS in-process router. A Router is cheaply cloneable.
        let management_for_proxy = management.clone();
        if let Some(router) = management {
            server = server.mount_management(router);
        }
        // Mount the OIDC provider on the PUBLIC plane when enabled. The issuer root
        // is the server's config-derived base URL, so issuers are per environment.
        if let Some((
            oidc_config,
            dsn,
            oidc_env,
            master_key,
            quota_config,
            hashing_config,
            policy_config,
            diagnostics_config,
        )) = oidc_inputs
        {
            let issuer_base = server.base_url();
            if let Some(router) = build_oidc_router(
                &oidc_config,
                &dsn,
                oidc_env,
                issuer_base,
                global_revocation_enabled,
                fedcm_enabled,
                risk_signals_enabled,
                signup_quarantine_enabled,
                advanced_recovery_enabled,
                first_party_challenge_enabled,
                flows_enabled,
                hosted_pages_enabled,
                master_key,
                &quota_config,
                &hashing_config,
                &policy_config,
                &diagnostics_config,
                migration_hook,
                federation_runtime,
            )
            .await
            {
                server = server.mount_public(router);
            }
        } else {
            tracing::info!("OIDC provider not mounted: oidc.enabled is false");
        }
        // Mount the admin console SPA on the PUBLIC plane under /admin when enabled
        // (issue #90). mount_public MERGES with the OIDC router above, so both mount
        // independently; while off nothing is mounted and every /admin path is a
        // uniform 404. PR1 serves a static shell (no auth yet); PR2 wires the login
        // and the same origin management proxy.
        if admin_spa_enabled {
            // Wire the same-origin management proxy (issue #90, PR 2): /admin/api/*
            // on the public plane forwards to the in-process management router, but
            // ONLY when the OIDC bridge is configured. Absent that config the console
            // has no login and no reason to reach management, so the proxy target is
            // None and every /admin/api/* path is a uniform 404, keeping the management
            // API off the public plane until the console is genuinely set up. When the
            // management plane itself is not mounted (no bootstrap operator token) the
            // target is likewise None.
            let proxy_target = if admin_bridge_configured {
                management_for_proxy
            } else {
                None
            };
            server =
                server.mount_public(ironauth_admin_ui::router(proxy_target, admin_spa_runtime));
            tracing::info!(
                proxy = admin_bridge_configured,
                "admin console mounted on the public plane under /admin"
            );
        } else {
            tracing::info!("admin console not mounted: admin_spa.enabled is false");
        }
        // The one-shot day-one signing-algorithm backfill (issue #93), run to
        // completion BEFORE the server serves so this fresh process loads all three
        // algorithms on its first use of each environment. Gated off by default and
        // idempotent; the intended use is to enable it for one deploy rollout.
        if let Some(inputs) = signing_backfill_inputs {
            run_signing_algorithm_backfill(inputs).await;
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
async fn build_management_router(
    config: &Config,
    env: &Env,
    migration_hook: Option<Arc<LazyMigrationHook>>,
    federation_runtime: Option<Arc<FederationRuntime>>,
    signup_quarantine_enabled: bool,
    advanced_recovery_enabled: bool,
) -> Option<Router> {
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
    // The management plane manages users end to end (issue #52), which is a PII
    // surface: it seals, blind-indexes, and opens user PII through the envelope
    // substrate (issue #48) exactly as the data plane does, so attach the platform
    // master key. Without it the admin user create/read paths fail closed (never
    // plaintext); resolve_master_key logs when it is unset.
    let store = match resolve_master_key(config) {
        Some(master) => store.with_master_key(master),
        None => store,
    };
    match AdminState::new(store, env.clone(), &config.admin) {
        Ok(state) => {
            // Share the lazy-migration hook (issue #56) so the migration-progress endpoint
            // can report this node's circuit-breaker state alongside the DB progress counts.
            let state = match migration_hook {
                Some(hook) => state.with_migration_hook(hook),
                None => state,
            };
            // Share the federation runtime (issue #76) so the per-connector health-diagnostics
            // read reports the live health the OIDC data plane records into (the SAME Arc).
            let state = match federation_runtime {
                Some(runtime) => state.with_federation(runtime),
                None => state,
            };
            // Arm the experimental signup fraud-review-queue endpoints (issue #82, PR 2) only
            // when the ladder resolved the feature enabled AND acked; otherwise every
            // review-queue endpoint stays a uniform 404.
            let state = state.with_signup_quarantine_enabled(signup_quarantine_enabled);
            // Arm the experimental admin-approved recovery review-queue endpoints (issue #82,
            // PR 3) only when the ladder resolved the feature enabled AND acked; otherwise
            // every recovery-approval endpoint stays a uniform 404.
            let state = state.with_advanced_recovery_enabled(advanced_recovery_enabled);
            // Share a data-plane issuer registry (issue #93) so the compatibility wizard can
            // resolve an environment's actually signable ID-token algorithms and write the
            // per-client column through the data plane (the only role that can). Absent a
            // reachable data-plane store the wizard's write endpoint fails closed.
            let state = install_signing_registry(state, config).await;
            // Arm the OIDC-session credential bridge (issue #90, PR 2) when the operator has
            // configured an admin issuer and a management audience AND the OIDC data plane is
            // mounted (so signing keys exist to verify against). Absent config leaves the
            // bridge disarmed: the management API then accepts no at+jwt at all (fail closed).
            let state = install_admin_oidc_bridge(state, config).await;
            tracing::info!("management API mounted on the management plane");
            Some(ironauth_admin::management_router(state))
        }
        Err(error) => {
            tracing::error!(%error, "management API not mounted: invalid admin config");
            None
        }
    }
}

/// Share a data-plane issuer registry with the management state (issue #93).
///
/// The compatibility wizard resolves an environment's ACTUALLY signable ID-token
/// algorithms (the layer-2 security check) and writes the per-client
/// `id_token_signed_response_alg` column, both of which need the DATA plane: the
/// signable set comes from the per-environment signing keys, and that column is
/// data-plane writable only (the control role holds no grant on it). This builds a
/// store-backed [`IssuerRegistry`] over the SAME data-plane store and issuer base the
/// OIDC plane serves its JWKS from, master-keyed so sealed PII opens (signing key
/// material itself is not sealed), and installs it. Any failure to derive the issuer
/// base or connect the data-plane store leaves the registry uninstalled, and the
/// wizard's write endpoint then fails closed (it cannot confirm signability).
async fn install_signing_registry(state: AdminState, config: &Config) -> AdminState {
    let issuer_base = match SiteContext::derive(&config.server) {
        Ok(site) => site.base_url(),
        Err(error) => {
            tracing::error!(%error, "compatibility wizard signing registry NOT installed: cannot derive the issuer base");
            return state;
        }
    };
    let store = match Store::connect(config.database.url.expose()).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "compatibility wizard signing registry NOT installed: cannot connect the data-plane store");
            return state;
        }
    };
    let store = match resolve_master_key(config) {
        Some(master) => store.with_master_key(master),
        None => store,
    };
    let cache = JwksCacheWindow::clamped(config.oidc.jwks_cache_max_age_secs);
    let registry = Arc::new(IssuerRegistry::store_backed(issuer_base, cache, store));
    tracing::info!(
        "compatibility wizard signing registry installed (issue #93): the per-client \
         signing-algorithm endpoint validates against the environment's actually signable set"
    );
    state.with_signing_registry(registry)
}

/// Arm the OIDC-session credential bridge on the management state (issue #90, PR 2).
///
/// The console dogfoods IronAuth's own OIDC: it signs in and presents a short-lived
/// `at+jwt`, which the management API's third resolution arm verifies against the
/// admin issuer's PUBLISHED signing keys and maps to the operator plane via the
/// fail-closed operator-subject allowlist. This installs the bridge when the
/// operator has named an admin issuer `(tenant, environment)` and a management
/// audience in `[admin_spa]` AND the OIDC data plane is enabled (so signing keys
/// exist to verify against). It reads those keys through a store-backed
/// [`IssuerRegistry`] over the SAME data-plane store and issuer base the OIDC plane
/// serves its JWKS from, so the verification keys are the identical RLS-scoped rows
/// (the registry seam reused, not a new key store). Any missing or unparseable
/// config leaves the bridge disarmed, and the management API then accepts no
/// `at+jwt` at all (fail closed).
async fn install_admin_oidc_bridge(state: AdminState, config: &Config) -> AdminState {
    // The bridge needs the OIDC data plane (its signing keys) and the admin-issuer
    // config. Absent either, leave it disarmed.
    if !config.oidc.enabled {
        return state;
    }
    let spa = &config.admin_spa;
    let (Some(tenant_id), Some(environment_id), Some(audience)) = (
        spa.admin_issuer_tenant
            .as_deref()
            .filter(|v| !v.trim().is_empty()),
        spa.admin_issuer_environment
            .as_deref()
            .filter(|v| !v.trim().is_empty()),
        spa.management_audience
            .as_deref()
            .filter(|v| !v.trim().is_empty()),
    ) else {
        return state;
    };
    let Some(admin_scope) = resolve_admin_scope(&state, tenant_id, environment_id) else {
        tracing::error!(
            "admin console OIDC bridge NOT armed: admin_spa.admin_issuer_tenant / \
             admin_issuer_environment did not parse as identifiers"
        );
        return state;
    };
    // The issuer base the OIDC plane mints issuers under (server.public_url derived),
    // so the enforced `iss` matches exactly what the shared registry publishes.
    let issuer_base = match SiteContext::derive(&config.server) {
        Ok(site) => site.base_url(),
        Err(error) => {
            tracing::error!(%error, "admin console OIDC bridge NOT armed: cannot derive the issuer base");
            return state;
        }
    };
    // A store-backed registry over the DATA-plane store (the app role reads signing
    // keys under forced RLS), master-keyed so sealed key material opens.
    let store = match Store::connect(config.database.url.expose()).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "admin console OIDC bridge NOT armed: cannot connect the data-plane store");
            return state;
        }
    };
    let store = match resolve_master_key(config) {
        Some(master) => store.with_master_key(master),
        None => store,
    };
    let cache = JwksCacheWindow::clamped(config.oidc.jwks_cache_max_age_secs);
    let registry = Arc::new(IssuerRegistry::store_backed(issuer_base, cache, store));
    // Trim each allowlist entry ONCE at load (operator convenience against a stray
    // space in config) and drop empties; the token subject is then matched byte
    // exact against these canonical entries.
    let subjects: Vec<String> = spa
        .operator_subjects
        .iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if subjects.is_empty() {
        tracing::warn!(
            "admin console OIDC bridge armed with an EMPTY operator_subjects allowlist: no \
             subject can reach the management plane until one is listed"
        );
    }
    let bridge = AdminOidcBridge::new(registry, admin_scope, audience.to_owned(), subjects);
    tracing::info!(
        "admin console OIDC credential bridge armed (issue #90): the management API accepts an \
         at+jwt from the configured admin issuer, bound to the management audience and carrying \
         the ironauth.manage scope, mapped to an operator via the fail-closed allowlist"
    );
    state.with_admin_oidc_bridge(bridge)
}

/// Parse the admin-issuer `(tenant, environment)` from config through the canonical
/// scoped-id parses (issue #90, PR 2). Returns `None` if either identifier is
/// malformed, which leaves the bridge disarmed.
fn resolve_admin_scope(state: &AdminState, tenant_id: &str, environment_id: &str) -> Option<Scope> {
    let tenant = state
        .store()
        .management()
        .tenants(state.bootstrap_operator_id())
        .parse_id(tenant_id)
        .ok()?;
    let environment = state
        .store()
        .management()
        .environments(tenant)
        .parse_id(environment_id)
        .ok()?;
    Some(Scope::new(tenant, environment))
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
// The mount takes the data-plane inputs, the two experimental/quota installs, and now
// the optional lazy-migration hook; each is an independent input to the one OidcState
// build, so bundling them into a struct would not make the wiring clearer.
#[allow(clippy::too_many_arguments)]
// One flat sequence of independent state-builder installs and startup notices; splitting
// it would scatter the single OIDC mount the boot path performs.
// The mount flags are each resolved from the strict feature ladder (never a plain config
// toggle) and injected here, so the several experimental-surface booleans are inherent to the
// boot wiring rather than a design smell.
#[allow(clippy::too_many_lines, clippy::fn_params_excessive_bools)]
async fn build_oidc_router(
    oidc_config: &OidcConfig,
    data_plane_dsn: &str,
    env: Env,
    issuer_base: String,
    global_revocation_enabled: bool,
    fedcm_enabled: bool,
    risk_signals_enabled: bool,
    signup_quarantine_enabled: bool,
    advanced_recovery_enabled: bool,
    first_party_challenge_enabled: bool,
    flows_enabled: bool,
    hosted_pages_enabled: bool,
    master_key: Option<Arc<MasterKey>>,
    quota_config: &QuotaConfig,
    hashing_config: &PasswordHashingConfig,
    policy_config: &PasswordPolicyConfig,
    diagnostics_config: &DiagnosticsConfig,
    migration_hook: Option<Arc<LazyMigrationHook>>,
    federation_runtime: Option<Arc<FederationRuntime>>,
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
    let capabilities = DiscoveryCapabilities::from_config(oidc_config)
        .with_first_party_challenge_endpoint(first_party_challenge_enabled);
    let discovery = discovery_router(DiscoveryState::new(
        issuer_base.clone(),
        cache,
        capabilities,
        Arc::clone(&registry),
        env.clone(),
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

    // The dedicated, admission-controlled Argon2id hashing pool (issue #62): Argon2
    // runs ONLY on these threads, never a tokio protocol-I/O worker, and each hash
    // is admission-controlled through the SAME quota enforcer (the PasswordHashing
    // dimension), so one tenant's credential-stuffing storm degrades only that
    // tenant. The parameters (OWASP defaults, tunable per environment in spirit via
    // the tuning probe) apply to NEW hashes; existing hashes upgrade on next login.
    let pool_threads = if hashing_config.pool_threads == 0 {
        ironauth_oidc::default_pool_threads()
    } else {
        hashing_config.pool_threads
    };
    let hashing_pool = Arc::new(ironauth_oidc::HashingPool::new(
        env.clone(),
        ironauth_oidc::Argon2Params::new(
            hashing_config.memory_kib,
            hashing_config.iterations,
            hashing_config.parallelism,
        ),
        pool_threads,
        hashing_config.max_queue_depth,
        Some(Arc::clone(&quota_enforcer)),
    ));
    ironauth_oidc::describe_hashing_pool_metrics();
    tracing::info!(
        pool_threads,
        memory_kib = hashing_config.memory_kib,
        iterations = hashing_config.iterations,
        parallelism = hashing_config.parallelism,
        "Argon2id hashing pool started with per-tenant fair-share admission (issue #62)"
    );

    // Breached-password screening and the NIST SP 800-63B-4 policy (issue #63): the
    // shipped defaults are the modern 63B-4 posture (15/8/64 length, no composition, no
    // rotation, screening MANDATORY over the free HIBP k-anonymity provider). The policy
    // (length floors, legacy overrides, fail-open/closed) always installs; the provider
    // installs only when screening is enabled and its input is available.
    let (password_policy, screening_failure, screen_on_login) =
        build_password_policy(policy_config);
    ironauth_oidc::describe_screening_metrics();
    // Register the per-connector federation health metric descriptions (issue #76), so the
    // connector-labeled health gauge and success/error counters carry help/type text.
    ironauth_oidc::describe_connector_health_metrics();

    let mut state = OidcState::new(store, env, registry, oidc_config, issuer_base)
        .with_global_token_revocation_enabled(global_revocation_enabled)
        .with_fedcm_enabled(fedcm_enabled)
        .with_risk_signals_enabled(risk_signals_enabled)
        .with_signup_quarantine_enabled(signup_quarantine_enabled)
        .with_advanced_recovery_enabled(advanced_recovery_enabled)
        .with_first_party_challenge_enabled(first_party_challenge_enabled)
        .with_flows_enabled(flows_enabled)
        .with_hosted_pages_enabled(hosted_pages_enabled)
        .with_diagnostics(diagnostics_config)
        .with_quota_enforcer(quota_enforcer)
        .with_hashing_pool(hashing_pool)
        .with_password_policy(password_policy, screening_failure, screen_on_login)
        // The email-OTP / magic-link factors (issue #68) deliver through the verification
        // seam. Until a real email provider is wired (M11 messaging), ship the dev
        // transport: it records deliveries on the observability plane and emits the code /
        // link only at the `debug` trace level, so the OTP and magic-link logic works end
        // to end without a mail server. A production deployment installs its own
        // `VerificationSender` here.
        .with_verification_sender(std::sync::Arc::new(
            ironauth_oidc::LoggingVerificationSender,
        ))
        // The guarded SMS-OTP factor (issue #70) delivers through a SEPARATE provider
        // seam. Until a real SMS provider (Twilio Verify, Vonage, SNS) is wired (M11
        // messaging), ship the dev stub: it records deliveries and emits the code only at
        // the `debug` trace level, so the guarded SMS logic works end to end without an
        // SMS gateway. A production deployment installs its own `SmsSender` here. SMS OTP
        // is off by default, so this stub is inert until a tenant explicitly enables SMS.
        .with_sms_sender(std::sync::Arc::new(ironauth_oidc::LoggingSmsSender));
    // Wire the production custom-journey source (issue #92, PR 5): a store-backed
    // CompiledJourneySource over the RLS-scoped flow_versions registry, with a compile cache
    // keyed by version id. It replaces PR 4's test-only embedded source, so a custom flow created
    // from a STORED, PINNED journey version executes end to end. It is inert until a journey
    // version is authored and pinned (an unpinned or unknown journey is a uniform not-found), so
    // installing it by default perturbs no built-in flow.
    let custom_journey_source = std::sync::Arc::new(
        ironauth_oidc::flow::FlowVersionJourneySource::new(state.store().clone()),
    );
    state = state.with_custom_journey_source(custom_journey_source);
    if let Some(provider) = build_breach_provider(policy_config) {
        state = state.with_breach_provider(provider);
    }
    // Arm the inbound lazy-migration hook on the login path (issue #56) when one is
    // configured; without it an unknown-identifier login is the uniform failure.
    if let Some(hook) = migration_hook {
        state = state.with_migration_hook(hook);
    }
    // Wire the generic OIDC UPSTREAM federation runtime (issue #75), built once by the boot
    // path and shared with the management plane (issue #76). OFF by default, so a deployment
    // that has not enabled federation leaves the `/federation` routes a uniform not-found.
    if let Some(federation) = federation_runtime {
        state = state.with_federation(federation);
        tracing::info!(
            "inbound OIDC federation wired (issue #75); the /federation routes are live for \
             stored connectors, over a dedicated SSRF-hardened fetcher"
        );
    }
    if global_revocation_enabled {
        tracing::info!(
            "experimental Global Token Revocation receiver mounted (issue #36); the draft \
             is not WG-adopted and the wire shape may change between releases"
        );
    }
    if fedcm_enabled {
        tracing::info!(
            "experimental FedCM IdP surface mounted (issue #83); Chrome only (Firefox \
             paused, Safari absent), the W3C draft may change between releases, and \
             redirect flows are unaffected"
        );
    }
    if risk_signals_enabled {
        tracing::info!(
            "experimental third-party risk-signal ingestion mounted (issue #82); a signed \
             Security Event Token is verified per-source through the JOSE core and folded \
             into the risk engine as a WEIGHTED policy input (never a verdict); the wire \
             contract may change between releases"
        );
    }
    if advanced_recovery_enabled {
        tracing::info!(
            "experimental advanced recovery modes mounted (issue #82); admin-approved, \
             trusted-contact, and IDV-gated recovery each complete THROUGH the recovery delay \
             window and downgrade invariant; IDV consumes a signed provider callback and \
             IronAuth never verifies documents in house; the wire contract may change between \
             releases"
        );
    }
    if first_party_challenge_enabled {
        tracing::info!(
            "experimental OAuth 2.0 Authorization Challenge Endpoint mounted (issue #93, \
             draft-ietf-oauth-first-party-apps): the browserless first-party native login surface; \
             a first-party native client completes login in one request and receives an \
             authorization code redeemed at the token endpoint with no redirect_uri; the wire shape \
             may change between releases"
        );
    }
    tracing::info!(
        "OIDC provider, discovery, and per-environment JWKS mounted on the public plane; \
         per-environment signing keys load lazily from the store on first use"
    );
    Some(oidc_router(state).merge(discovery).merge(jwks))
}

/// Build the generic OIDC upstream federation runtime (issue #75, PR B) from
/// `oidc.federation`, or [`None`] when federation is disabled (the default).
///
/// When enabled, the runtime gets its OWN SSRF-hardened outbound fetcher (every federation
/// outbound -- discovery, JWKS, token exchange -- rides `ironauth-fetch`, never an ad hoc
/// client) and the configured discovery / JWKS cache TTLs, read against the same env clock
/// so they advance deterministically (the runtime reads the application clock at call time
/// through the state). A fetcher-setup failure logs and yields [`None`] (federation then
/// stays a uniform not-found rather than mounting a broken surface).
fn build_federation_runtime(cfg: &OidcConfig) -> Option<Arc<FederationRuntime>> {
    if !cfg.federation.enabled {
        return None;
    }
    let fetcher = match ironauth_fetch::Fetcher::new(ironauth_fetch::FetchLimits::default()) {
        Ok(fetcher) => Arc::new(fetcher),
        Err(error) => {
            tracing::error!(
                %error,
                "inbound OIDC federation: outbound fetcher setup failed; federation is not \
                 mounted (issue #75)"
            );
            return None;
        }
    };
    let jwks_ttl = std::time::Duration::from_secs(cfg.federation.jwks_ttl_secs);
    let discovery_ttl = std::time::Duration::from_secs(cfg.federation.discovery_ttl_secs);
    let probe_window = std::time::Duration::from_secs(cfg.federation.health_probe_window_secs);
    let keys = Arc::new(FederationKeyResolver::new(Arc::clone(&fetcher), jwks_ttl));
    Some(Arc::new(FederationRuntime::new(
        fetcher,
        keys,
        discovery_ttl,
        probe_window,
    )))
}

/// Parse each ENABLED IDV provider's registered JWKS through the JOSE core (issue #82, PR 3),
/// so a non-empty but MALFORMED JWKS (or one that yields zero usable keys) is a clean BOOT
/// error rather than a per-callback fail-closed surprise at runtime.
///
/// The config layer already proves the JWKS is non-empty, but it carries no `ironauth-jose`
/// dependency, so it structurally cannot prove the JWKS PARSES. This runs at boot where jose
/// IS available, and only for enabled providers (mirroring the config non-empty check); the
/// caller gates it on the advanced-recovery feature being armed.
///
/// # Errors
///
/// A message naming the first provider whose JWKS does not parse into at least one usable key
/// (the exact fault the callback would otherwise fail closed on).
fn validate_idv_provider_jwks(cfg: &ironauth_config::AdvancedRecoveryConfig) -> Result<(), String> {
    for provider in &cfg.idv_providers {
        if !provider.enabled {
            continue;
        }
        if ironauth_jose::trusted_keys_from_jwks(provider.jwks.as_bytes()).is_empty() {
            return Err(format!(
                "oidc.advanced_recovery.idv_providers[{}].jwks does not parse into any usable \
                 key: an enabled IDV provider must carry a well-formed JWKS with at least one \
                 supported public key, or every IDV recovery for it would fail at callback",
                provider.slug
            ));
        }
    }
    Ok(())
}

/// Resolve the top-level `[password_policy]` config into the runtime 800-63B-4 policy
/// value, the provider-failure policy, and the on-login-screen flag (issue #63). The
/// lengths and any legacy composition/rotation overrides map straight across; the shipped
/// defaults are the modern 63B-4 posture.
fn build_password_policy(
    cfg: &PasswordPolicyConfig,
) -> (
    ironauth_screening::PasswordPolicy,
    ironauth_screening::FailurePolicy,
    bool,
) {
    let policy = ironauth_screening::PasswordPolicy::new(
        cfg.min_length_sole_factor,
        cfg.min_length_mfa_factor,
        cfg.max_length,
        cfg.require_lowercase,
        cfg.require_uppercase,
        cfg.require_digit,
        cfg.require_symbol,
        cfg.rotation_max_age_days,
        cfg.screening_enabled,
        cfg.min_password_strength_score,
    );
    let failure = match cfg.screening_failure_policy {
        ScreeningFailurePolicy::FailOpen => ironauth_screening::FailurePolicy::FailOpen,
        ScreeningFailurePolicy::FailClosed => ironauth_screening::FailurePolicy::FailClosed,
    };
    (policy, failure, cfg.screen_on_login)
}

/// Build the breached-password screening provider from config (issue #63): the online HIBP
/// range provider over a fresh SSRF-hardened fetcher, or the offline corpus provider loaded
/// from the operator dataset. `None` when screening is disabled. A provider whose input is
/// unavailable (a fetcher-setup failure, an unreadable corpus) logs and yields `None`, so
/// the state then treats screening as provider-unavailable and applies the fail-open/closed
/// policy rather than silently no-opping the mandatory default.
fn build_breach_provider(
    cfg: &PasswordPolicyConfig,
) -> Option<Arc<dyn ironauth_screening::BreachRangeProvider>> {
    if !cfg.screening_enabled {
        return None;
    }
    match cfg.screening_provider {
        ScreeningProvider::Hibp => {
            let fetcher = match ironauth_fetch::Fetcher::new(ironauth_fetch::FetchLimits::default())
            {
                Ok(fetcher) => Arc::new(fetcher),
                Err(error) => {
                    tracing::error!(
                        %error,
                        "breached-password screening: HIBP fetcher setup failed; the \
                         provider is unavailable and the fail-open/closed policy applies"
                    );
                    return None;
                }
            };
            let provider = match &cfg.hibp_base_url {
                Some(base) => {
                    ironauth_screening::HibpRangeProvider::with_base_url(fetcher, base.clone())
                }
                None => ironauth_screening::HibpRangeProvider::new(fetcher),
            };
            tracing::info!(
                "breached-password screening enabled over the online HIBP k-anonymity range \
                 API (issue #63); only a 5-char SHA-1 prefix leaves the process"
            );
            Some(Arc::new(provider) as Arc<dyn ironauth_screening::BreachRangeProvider>)
        }
        ScreeningProvider::Offline => {
            // Config load guarantees the path is set when the offline provider is enabled.
            let path = cfg.offline_corpus_path.as_deref()?;
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    let provider = ironauth_screening::OfflineCorpusProvider::from_text(&text);
                    tracing::info!(
                        entries = provider.len(),
                        path,
                        "breached-password screening enabled over the offline corpus (issue #63)"
                    );
                    Some(Arc::new(provider) as Arc<dyn ironauth_screening::BreachRangeProvider>)
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        path,
                        "breached-password screening: offline corpus unreadable; the provider \
                         is unavailable and the fail-open/closed policy applies"
                    );
                    None
                }
            }
        }
    }
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

/// What the one-shot signing-algorithm backfill (issue #93) needs to run, captured
/// before `config` moves into the server.
struct SigningBackfillInputs {
    /// The data-plane DSN the backfill provisions through (the least-privilege
    /// `ironauth_app` role in production, which holds the scoped INSERT on
    /// `signing_keys`).
    data_plane_dsn: String,
    /// The control-plane DSN the backfill enumerates `(tenant, environment)` scopes
    /// on (the non-RLS `environments` table only the control role can read);
    /// [`None`] disables the backfill (without it there is no way to discover the
    /// environments to provision into).
    control_dsn: Option<String>,
    /// The environment seam (deterministic clock and entropy).
    env: Env,
}

/// Capture the signing-algorithm backfill inputs from config (issue #93), or `None`
/// when the switch is off (the default). The control-plane DSN is resolved here
/// (the backfill enumerates scopes on the control plane).
fn signing_backfill_inputs(config: &Config, env: &Env) -> Option<SigningBackfillInputs> {
    if !config.admin.backfill_signing_algorithms_on_start {
        return None;
    }
    Some(SigningBackfillInputs {
        data_plane_dsn: config.database.url.expose().to_owned(),
        control_dsn: select_control_dsn(config),
        env: env.clone(),
    })
}

/// Run the one-shot day-one signing-algorithm backfill (issue #93) to completion.
///
/// Provisions the missing `ES256`/`RS256` keys into every environment that predates
/// the all-three-at-creation change, idempotently. Enumeration is a CONTROL-plane
/// read (the data-plane role cannot see the non-RLS `environments` table), so it
/// needs both a data-plane store (to provision) and a control-plane store (to
/// enumerate). Any connect failure or a missing control DSN is logged and the
/// backfill is simply skipped; the rest of the server runs unaffected.
async fn run_signing_algorithm_backfill(inputs: SigningBackfillInputs) {
    let SigningBackfillInputs {
        data_plane_dsn,
        control_dsn,
        env,
    } = inputs;

    let Some(control_dsn) = control_dsn else {
        tracing::error!(
            "signing-algorithm backfill skipped: no control-plane DSN to enumerate scopes \
             (set admin.control_database_url, or run in dev_mode)"
        );
        return;
    };
    let data_store = match Store::connect(&data_plane_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "signing-algorithm backfill skipped: data-plane connect failed");
            return;
        }
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "signing-algorithm backfill skipped: control-plane connect failed");
            return;
        }
    };

    match ironauth_admin::backfill_signing_algorithms(&env, &control_store, &data_store).await {
        Ok(report) => tracing::info!(
            scopes_scanned = report.scopes_scanned,
            keys_provisioned = report.keys_provisioned,
            scopes_failed = report.scopes_failed,
            "signing-algorithm backfill complete"
        ),
        Err(error) => {
            tracing::error!(%error, "signing-algorithm backfill failed to enumerate scopes");
        }
    }
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

/// The parsed flags of a `ban` / `unban` / `bans` invocation (issue #64).
#[derive(Default)]
struct BanArgs {
    config: Option<String>,
    tenant: Option<String>,
    environment: Option<String>,
    kind: Option<String>,
    subject: Option<String>,
    path: Option<String>,
    reason: Option<String>,
    expires_secs: Option<i64>,
}

/// Parse the shared flags of the ban subcommands. Supports both `--flag value` and
/// `--flag=value`.
fn parse_ban_args(args: &mut impl Iterator<Item = String>) -> Result<BanArgs, String> {
    let mut parsed = BanArgs::default();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag.to_owned(), Some(value.to_owned())),
            None => (arg, None),
        };
        let mut take = |inline: Option<String>| -> Result<String, String> {
            match inline {
                Some(value) => Ok(value),
                None => args
                    .next()
                    .ok_or_else(|| format!("{flag} requires a value")),
            }
        };
        match flag.as_str() {
            "--config" => parsed.config = Some(take(inline)?),
            "--tenant" => parsed.tenant = Some(take(inline)?),
            "--environment" => parsed.environment = Some(take(inline)?),
            "--kind" => parsed.kind = Some(take(inline)?),
            "--subject" => parsed.subject = Some(take(inline)?),
            "--path" => parsed.path = Some(take(inline)?),
            "--reason" => parsed.reason = Some(take(inline)?),
            "--expires-secs" => {
                let value = take(inline)?;
                let secs = value
                    .parse::<i64>()
                    .map_err(|_| "--expires-secs expects a whole number of seconds".to_owned())?;
                parsed.expires_secs = Some(secs);
            }
            other => return Err(format!("unrecognized argument '{other}'")),
        }
    }
    Ok(parsed)
}

/// Resolve the scope, data-plane DSN, and envelope master key a ban subcommand needs:
/// parse the tenant/environment ids, load config, and require the master key (a ban
/// subject is sealed under it).
fn prepare_ban(parsed: &BanArgs) -> Result<(Scope, String, Arc<MasterKey>), String> {
    let tenant_raw = parsed.tenant.as_deref().ok_or("--tenant is required")?;
    let environment_raw = parsed
        .environment
        .as_deref()
        .ok_or("--environment is required")?;
    let tenant = TenantId::parse(tenant_raw).map_err(|_| "invalid --tenant id".to_owned())?;
    let environment =
        EnvironmentId::parse(environment_raw).map_err(|_| "invalid --environment id".to_owned())?;
    let scope = Scope::new(tenant, environment);
    let config = match &parsed.config {
        Some(path) => {
            Config::load(path)
                .map_err(|error| format!("cannot load config: {error}"))?
                .config
        }
        None => Config::default(),
    };
    let master = resolve_master_key(&config)
        .ok_or("database.master_key must be set to seal a ban subject")?;
    let dsn = config.database.url.expose().to_owned();
    Ok((scope, dsn, master))
}

/// Run the `ban` / `unban` / `bans` subcommands (issue #64): place, lift, and list durable
/// credential-abuse bans directly against the data-plane store, each an audited write. The
/// admin API offers the same operations over HTTP; both write through the SAME repository.
fn manage_bans(verb: &str, args: &mut impl Iterator<Item = String>) -> ExitCode {
    let parsed = match parse_ban_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("ironauth {verb}: {message}");
            return ExitCode::FAILURE;
        }
    };
    let (scope, dsn, master) = match prepare_ban(&parsed) {
        Ok(prepared) => prepared,
        Err(message) => {
            eprintln!("ironauth {verb}: {message}");
            return ExitCode::FAILURE;
        }
    };
    let env = Env::system();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ironauth {verb}: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let store = match Store::connect(&dsn).await {
            Ok(store) => store.with_master_key(master),
            Err(error) => {
                eprintln!("ironauth {verb}: cannot connect the data-plane store: {error}");
                return ExitCode::FAILURE;
            }
        };
        match verb {
            "bans" => list_bans(&store, scope, &env).await,
            "ban" => place_ban(&store, scope, &env, &parsed).await,
            "unban" => lift_ban(&store, scope, &env, &parsed).await,
            _ => unreachable!("dispatch guarantees the verb"),
        }
    })
}

/// Build the regulated subject for a ban subcommand: an identifier subject is
/// CANONICALIZED through the same seam the login path keys on (issue #54/#64), so a CLI
/// ban matches the exact form the request path checks.
fn ban_subject(parsed: &BanArgs) -> Result<AbuseSubject, String> {
    let kind_raw = parsed.kind.as_deref().ok_or("--kind is required")?;
    let subject_raw = parsed.subject.as_deref().ok_or("--subject is required")?;
    let kind = AbuseSubjectKind::from_wire(kind_raw)
        .ok_or("--kind must be one of ip | account | identifier")?;
    let value = match kind {
        AbuseSubjectKind::Identifier => canonical_login_identifier(subject_raw).as_str().to_owned(),
        AbuseSubjectKind::Ip | AbuseSubjectKind::Account => subject_raw.to_owned(),
    };
    Ok(AbuseSubject { kind, value })
}

/// Parse the `--path` flag, defaulting to the password path.
fn ban_path(parsed: &BanArgs) -> Result<AuthPath, String> {
    match parsed.path.as_deref() {
        None => Ok(AuthPath::Password),
        Some(raw) => AuthPath::from_wire(raw).ok_or_else(|| {
            "--path must be one of password | passkey | recovery | register | second_factor | all"
                .to_owned()
        }),
    }
}

/// Place a ban (issue #64).
async fn place_ban(store: &Store, scope: Scope, env: &Env, parsed: &BanArgs) -> ExitCode {
    let subject = match ban_subject(parsed) {
        Ok(subject) => subject,
        Err(message) => {
            eprintln!("ironauth ban: {message}");
            return ExitCode::FAILURE;
        }
    };
    let path = match ban_path(parsed) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ironauth ban: {message}");
            return ExitCode::FAILURE;
        }
    };
    let reason = parsed.reason.as_deref().unwrap_or("operator ban (CLI)");
    let now = now_micros(env);
    let expires = parsed
        .expires_secs
        .map(|secs| now.saturating_add(secs.saturating_mul(1_000_000)));
    let id = AbuseBanId::generate(env, &scope);
    let actor = ActorRef::service(ServiceId::generate(env));
    let result = store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .abuse()
        .ban(
            env,
            NewBan {
                id: &id,
                subject: &subject,
                auth_path: path,
                reason,
                expires_at_unix_micros: expires,
            },
            now,
        )
        .await;
    match result {
        Ok(id) => {
            println!(
                "banned {} '{}' on the {} path ({})",
                subject.kind.as_str(),
                subject.value,
                path.as_str(),
                id
            );
            ExitCode::SUCCESS
        }
        Err(ironauth_store::StoreError::Conflict) => {
            println!(
                "already banned: {} on the {} path",
                subject.kind.as_str(),
                path.as_str()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth ban: cannot place ban: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Lift a ban (issue #64).
async fn lift_ban(store: &Store, scope: Scope, env: &Env, parsed: &BanArgs) -> ExitCode {
    let subject = match ban_subject(parsed) {
        Ok(subject) => subject,
        Err(message) => {
            eprintln!("ironauth unban: {message}");
            return ExitCode::FAILURE;
        }
    };
    let path = match ban_path(parsed) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("ironauth unban: {message}");
            return ExitCode::FAILURE;
        }
    };
    let actor = ActorRef::service(ServiceId::generate(env));
    match store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .abuse()
        .lift(env, &subject, path)
        .await
    {
        Ok(true) => {
            println!(
                "lifted ban on {} '{}' for the {} path",
                subject.kind.as_str(),
                subject.value,
                path.as_str()
            );
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!(
                "no active ban on {} '{}' for the {} path",
                subject.kind.as_str(),
                subject.value,
                path.as_str()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth unban: cannot lift ban: {error}");
            ExitCode::FAILURE
        }
    }
}

/// List active bans (issue #64).
async fn list_bans(store: &Store, scope: Scope, env: &Env) -> ExitCode {
    match store
        .scoped(scope)
        .abuse()
        .list_active(now_micros(env))
        .await
    {
        Ok(bans) => {
            if bans.is_empty() {
                println!("no active bans");
            }
            for ban in bans {
                let expires = ban.expires_at_unix_micros.map_or_else(
                    || "never".to_owned(),
                    |micros| (micros / 1_000_000).to_string(),
                );
                println!(
                    "{id}\t{kind}\t{subject}\t{path}\texpires_unix={expires}\treason={reason}",
                    id = ban.id,
                    kind = ban.subject_kind.as_str(),
                    subject = ban.subject,
                    path = ban.auth_path.as_str(),
                    reason = ban.reason,
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth bans: cannot list bans: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The parsed flags of a `step-up-policy` invocation (RFC 9470 step-up, issue #72).
#[derive(Default)]
struct StepUpPolicyArgs {
    config: Option<String>,
    tenant: Option<String>,
    environment: Option<String>,
    scope_token: Option<String>,
    client: Option<String>,
    acr: Option<String>,
    max_age: Option<i64>,
}

/// Parse the shared flags of the step-up-policy subcommands. Supports both
/// `--flag value` and `--flag=value`.
fn parse_step_up_policy_args(
    args: &mut impl Iterator<Item = String>,
) -> Result<StepUpPolicyArgs, String> {
    let mut parsed = StepUpPolicyArgs::default();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag.to_owned(), Some(value.to_owned())),
            None => (arg, None),
        };
        let mut take = |inline: Option<String>| -> Result<String, String> {
            match inline {
                Some(value) => Ok(value),
                None => args
                    .next()
                    .ok_or_else(|| format!("{flag} requires a value")),
            }
        };
        match flag.as_str() {
            "--config" => parsed.config = Some(take(inline)?),
            "--tenant" => parsed.tenant = Some(take(inline)?),
            "--environment" => parsed.environment = Some(take(inline)?),
            "--scope" => parsed.scope_token = Some(take(inline)?),
            "--client" => parsed.client = Some(take(inline)?),
            "--acr" => parsed.acr = Some(take(inline)?),
            "--max-age" => {
                let value = take(inline)?;
                let secs = value
                    .parse::<i64>()
                    .map_err(|_| "--max-age expects a whole number of seconds".to_owned())?;
                parsed.max_age = Some(secs);
            }
            other => return Err(format!("unrecognized argument '{other}'")),
        }
    }
    Ok(parsed)
}

/// Resolve the scope and data-plane DSN a step-up-policy subcommand needs. Unlike a ban,
/// a step-up policy stores no sealed PII column, so no envelope master key is required.
fn prepare_step_up_policy(parsed: &StepUpPolicyArgs) -> Result<(Scope, String), String> {
    let tenant_raw = parsed.tenant.as_deref().ok_or("--tenant is required")?;
    let environment_raw = parsed
        .environment
        .as_deref()
        .ok_or("--environment is required")?;
    let tenant = TenantId::parse(tenant_raw).map_err(|_| "invalid --tenant id".to_owned())?;
    let environment =
        EnvironmentId::parse(environment_raw).map_err(|_| "invalid --environment id".to_owned())?;
    let scope = Scope::new(tenant, environment);
    let config = match &parsed.config {
        Some(path) => {
            Config::load(path)
                .map_err(|error| format!("cannot load config: {error}"))?
                .config
        }
        None => Config::default(),
    };
    let dsn = config.database.url.expose().to_owned();
    Ok((scope, dsn))
}

/// Run the `step-up-policy set | list | remove` subcommands (RFC 9470, issue #72): set,
/// list, and remove the declarative per-scope and per-client step-up authentication
/// policy directly against the data-plane store, each an audited write through the SAME
/// `Acting*` repositories the enforcement path reads. This is the lightest operator
/// surface that makes the declarative policy actually usable.
fn manage_step_up_policy(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(action) = args.next() else {
        eprintln!("ironauth step-up-policy: expected a subcommand (set | list | remove)");
        return ExitCode::FAILURE;
    };
    if !matches!(action.as_str(), "set" | "list" | "remove") {
        eprintln!(
            "ironauth step-up-policy: unknown subcommand '{action}' (expected set | list | remove)"
        );
        return ExitCode::FAILURE;
    }
    let parsed = match parse_step_up_policy_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("ironauth step-up-policy {action}: {message}");
            return ExitCode::FAILURE;
        }
    };
    let (scope, dsn) = match prepare_step_up_policy(&parsed) {
        Ok(prepared) => prepared,
        Err(message) => {
            eprintln!("ironauth step-up-policy {action}: {message}");
            return ExitCode::FAILURE;
        }
    };
    let env = Env::system();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ironauth step-up-policy {action}: cannot start async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let store = match Store::connect(&dsn).await {
            Ok(store) => store,
            Err(error) => {
                eprintln!(
                    "ironauth step-up-policy {action}: cannot connect the data-plane store: {error}"
                );
                return ExitCode::FAILURE;
            }
        };
        match action.as_str() {
            "set" => set_step_up_policy(&store, scope, &env, &parsed).await,
            "list" => list_step_up_policies(&store, scope).await,
            "remove" => remove_step_up_policy(&store, scope, &env, &parsed).await,
            _ => unreachable!("dispatch guarantees the subcommand"),
        }
    })
}

/// A human display of an optional value, or `-` when absent.
fn or_dash(value: Option<String>) -> String {
    value.unwrap_or_else(|| "-".to_owned())
}

/// Set (create or update) a per-scope or per-client step-up policy (issue #72). Exactly
/// one of `--scope` / `--client` selects the target; at least one of `--acr` /
/// `--max-age` must constrain something.
async fn set_step_up_policy(
    store: &Store,
    scope: Scope,
    env: &Env,
    parsed: &StepUpPolicyArgs,
) -> ExitCode {
    // A short acr alias (mfa/pwd/phr/phrh) is canonicalized to the value the enforcement
    // path compares against, so `--acr mfa` actually gates.
    let acr = parsed.acr.as_deref().map(canonical_step_up_acr);
    let acr_ref = acr.as_deref();
    let max_age = parsed.max_age;
    if acr_ref.is_none() && max_age.is_none() {
        eprintln!("ironauth step-up-policy set: at least one of --acr / --max-age is required");
        return ExitCode::FAILURE;
    }
    let actor = ActorRef::service(ServiceId::generate(env));
    let acting = store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env));
    match (&parsed.scope_token, &parsed.client) {
        (Some(scope_token), None) => {
            match acting
                .scope_step_up_policies()
                .set(env, scope_token, acr_ref, max_age)
                .await
            {
                Ok(id) => {
                    println!(
                        "set per-scope step-up policy for '{scope_token}' \
                         (acr={acr}, max_age={age}) {id}",
                        acr = acr_ref.unwrap_or("-"),
                        age = or_dash(max_age.map(|s| s.to_string())),
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ironauth step-up-policy set: cannot set scope policy: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        (None, Some(client_raw)) => {
            let Ok(client_id) = ClientId::parse_in_scope(client_raw, &scope) else {
                eprintln!("ironauth step-up-policy set: invalid --client id");
                return ExitCode::FAILURE;
            };
            match acting
                .clients()
                .set_step_up_policy(env, &client_id, acr_ref, max_age)
                .await
            {
                Ok(()) => {
                    println!(
                        "set per-client step-up floor for '{client_raw}' \
                         (acr={acr}, max_age={age})",
                        acr = acr_ref.unwrap_or("-"),
                        age = or_dash(max_age.map(|s| s.to_string())),
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ironauth step-up-policy set: cannot set client floor: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        (Some(_), Some(_)) => {
            eprintln!("ironauth step-up-policy set: specify exactly one of --scope / --client");
            ExitCode::FAILURE
        }
        (None, None) => {
            eprintln!("ironauth step-up-policy set: one of --scope / --client is required");
            ExitCode::FAILURE
        }
    }
}

/// List the per-scope step-up policies in a scope (issue #72). Per-client floors live on
/// the client registration row (managed with `set --client` / `remove --client`), so they
/// are not enumerated here.
async fn list_step_up_policies(store: &Store, scope: Scope) -> ExitCode {
    match store.scoped(scope).scope_step_up_policies().list().await {
        Ok(policies) => {
            if policies.is_empty() {
                println!("no per-scope step-up policies");
            }
            for policy in policies {
                println!(
                    "{id}\tscope={scope_token}\tacr={acr}\tmax_age={age}",
                    id = policy.id,
                    scope_token = policy.scope_token,
                    acr = policy.min_acr.as_deref().unwrap_or("-"),
                    age = or_dash(policy.max_auth_age_secs.map(|s| s.to_string())),
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth step-up-policy list: cannot list policies: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Remove a per-scope policy, or clear a per-client floor (issue #72). Exactly one of
/// `--scope` / `--client` selects the target.
async fn remove_step_up_policy(
    store: &Store,
    scope: Scope,
    env: &Env,
    parsed: &StepUpPolicyArgs,
) -> ExitCode {
    let actor = ActorRef::service(ServiceId::generate(env));
    let acting = store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env));
    match (&parsed.scope_token, &parsed.client) {
        (Some(scope_token), None) => match acting
            .scope_step_up_policies()
            .remove(env, scope_token)
            .await
        {
            Ok(()) => {
                println!("removed per-scope step-up policy for '{scope_token}'");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ironauth step-up-policy remove: cannot remove scope policy: {error}");
                ExitCode::FAILURE
            }
        },
        (None, Some(client_raw)) => {
            let Ok(client_id) = ClientId::parse_in_scope(client_raw, &scope) else {
                eprintln!("ironauth step-up-policy remove: invalid --client id");
                return ExitCode::FAILURE;
            };
            // Clearing a per-client floor sets both step-up columns to NULL.
            match acting
                .clients()
                .set_step_up_policy(env, &client_id, None, None)
                .await
            {
                Ok(()) => {
                    println!("cleared per-client step-up floor for '{client_raw}'");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("ironauth step-up-policy remove: cannot clear client floor: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("ironauth step-up-policy remove: specify exactly one of --scope / --client");
            ExitCode::FAILURE
        }
    }
}

/// The parsed flags of a `credential-class-policy` invocation (issue #66).
#[derive(Default)]
struct CredentialClassPolicyArgs {
    config: Option<String>,
    tenant: Option<String>,
    environment: Option<String>,
    subject: Option<String>,
    subject_ref: Option<String>,
    class: Option<String>,
}

/// Parse the shared flags of the credential-class-policy subcommands. Supports both
/// `--flag value` and `--flag=value`.
fn parse_credential_class_policy_args(
    args: &mut impl Iterator<Item = String>,
) -> Result<CredentialClassPolicyArgs, String> {
    let mut parsed = CredentialClassPolicyArgs::default();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) => (flag.to_owned(), Some(value.to_owned())),
            None => (arg, None),
        };
        let mut take = |inline: Option<String>| -> Result<String, String> {
            match inline {
                Some(value) => Ok(value),
                None => args
                    .next()
                    .ok_or_else(|| format!("{flag} requires a value")),
            }
        };
        match flag.as_str() {
            "--config" => parsed.config = Some(take(inline)?),
            "--tenant" => parsed.tenant = Some(take(inline)?),
            "--environment" => parsed.environment = Some(take(inline)?),
            "--subject" => parsed.subject = Some(take(inline)?),
            "--subject-ref" => parsed.subject_ref = Some(take(inline)?),
            "--class" => parsed.class = Some(take(inline)?),
            other => return Err(format!("unrecognized argument '{other}'")),
        }
    }
    Ok(parsed)
}

/// Resolve the scope and data-plane DSN a credential-class-policy subcommand needs.
/// Like a step-up policy, a credential-class policy stores no sealed PII column, so
/// no envelope master key is required.
fn prepare_credential_class_policy(
    parsed: &CredentialClassPolicyArgs,
) -> Result<(Scope, String), String> {
    let tenant_raw = parsed.tenant.as_deref().ok_or("--tenant is required")?;
    let environment_raw = parsed
        .environment
        .as_deref()
        .ok_or("--environment is required")?;
    let tenant = TenantId::parse(tenant_raw).map_err(|_| "invalid --tenant id".to_owned())?;
    let environment =
        EnvironmentId::parse(environment_raw).map_err(|_| "invalid --environment id".to_owned())?;
    let scope = Scope::new(tenant, environment);
    let config = match &parsed.config {
        Some(path) => {
            Config::load(path)
                .map_err(|error| format!("cannot load config: {error}"))?
                .config
        }
        None => Config::default(),
    };
    let dsn = config.database.url.expose().to_owned();
    Ok((scope, dsn))
}

/// Resolve the (`subject_kind`, `subject_ref`) pair from the parsed flags, applying the
/// tenant-default and the kind<->ref presence rule the storage CHECK also enforces.
fn resolve_policy_subject(
    parsed: &CredentialClassPolicyArgs,
) -> Result<(String, Option<String>), String> {
    let subject = parsed.subject.as_deref().unwrap_or("tenant");
    if !matches!(subject, "tenant" | "group" | "org") {
        return Err(format!(
            "invalid --subject '{subject}' (expected tenant | group | org)"
        ));
    }
    match (subject, parsed.subject_ref.as_deref()) {
        ("tenant", Some(_)) => {
            Err("--subject-ref is not allowed for the tenant-wide policy".to_owned())
        }
        ("tenant", None) => Ok(("tenant".to_owned(), None)),
        (kind, Some(reference)) if !reference.is_empty() => {
            Ok((kind.to_owned(), Some(reference.to_owned())))
        }
        (kind, _) => Err(format!("--subject-ref is required for a {kind} policy")),
    }
}

/// Run the `credential-class-policy set | list | remove` subcommands (issue #66): set,
/// list, and remove the declarative per-scope minimum-credential-class ladder row for a
/// subject, each an audited write through the SAME `Acting` repository the authentication
/// path composes from with strictest-wins.
fn manage_credential_class_policy(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Some(action) = args.next() else {
        eprintln!("ironauth credential-class-policy: expected a subcommand (set | list | remove)");
        return ExitCode::FAILURE;
    };
    if !matches!(action.as_str(), "set" | "list" | "remove") {
        eprintln!(
            "ironauth credential-class-policy: unknown subcommand '{action}' \
             (expected set | list | remove)"
        );
        return ExitCode::FAILURE;
    }
    let parsed = match parse_credential_class_policy_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("ironauth credential-class-policy {action}: {message}");
            return ExitCode::FAILURE;
        }
    };
    let (scope, dsn) = match prepare_credential_class_policy(&parsed) {
        Ok(prepared) => prepared,
        Err(message) => {
            eprintln!("ironauth credential-class-policy {action}: {message}");
            return ExitCode::FAILURE;
        }
    };
    let env = Env::system();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!(
                "ironauth credential-class-policy {action}: cannot start async runtime: {error}"
            );
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let store = match Store::connect(&dsn).await {
            Ok(store) => store,
            Err(error) => {
                eprintln!(
                    "ironauth credential-class-policy {action}: cannot connect the data-plane \
                     store: {error}"
                );
                return ExitCode::FAILURE;
            }
        };
        match action.as_str() {
            "set" => set_credential_class_policy(&store, scope, &env, &parsed).await,
            "list" => list_credential_class_policies(&store, scope).await,
            "remove" => remove_credential_class_policy(&store, scope, &env, &parsed).await,
            _ => unreachable!("dispatch guarantees the subcommand"),
        }
    })
}

/// Set (create or update) a minimum-credential-class policy for a subject (issue #66).
async fn set_credential_class_policy(
    store: &Store,
    scope: Scope,
    env: &Env,
    parsed: &CredentialClassPolicyArgs,
) -> ExitCode {
    let Some(class) = parsed.class.as_deref() else {
        eprintln!(
            "ironauth credential-class-policy set: --class is required (any | mfa | passkey | attested_passkey)"
        );
        return ExitCode::FAILURE;
    };
    if CredentialClass::from_token(class).is_none() {
        eprintln!(
            "ironauth credential-class-policy set: invalid --class '{class}' \
             (expected any | mfa | passkey | attested_passkey)"
        );
        return ExitCode::FAILURE;
    }
    let (subject_kind, subject_ref) = match resolve_policy_subject(parsed) {
        Ok(subject) => subject,
        Err(message) => {
            eprintln!("ironauth credential-class-policy set: {message}");
            return ExitCode::FAILURE;
        }
    };
    let actor = ActorRef::service(ServiceId::generate(env));
    let acting = store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env));
    match acting
        .credential_class_policies()
        .set(env, &subject_kind, subject_ref.as_deref(), class)
        .await
    {
        Ok(id) => {
            println!(
                "set credential-class policy (subject={subject_kind}, ref={reference}, \
                 min_class={class}) {id}",
                reference = subject_ref.as_deref().unwrap_or("-"),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth credential-class-policy set: cannot set policy: {error}");
            ExitCode::FAILURE
        }
    }
}

/// List the credential-class policies in a scope (issue #66).
async fn list_credential_class_policies(store: &Store, scope: Scope) -> ExitCode {
    match store.scoped(scope).credential_class_policies().list().await {
        Ok(policies) => {
            if policies.is_empty() {
                println!("no credential-class policies");
            }
            for policy in policies {
                println!(
                    "{id}\tsubject={subject_kind}\tref={reference}\tmin_class={min_class}",
                    id = policy.id,
                    subject_kind = policy.subject_kind,
                    reference = policy.subject_ref.as_deref().unwrap_or("-"),
                    min_class = policy.min_class,
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth credential-class-policy list: cannot list policies: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Remove a credential-class policy for a subject (issue #66).
async fn remove_credential_class_policy(
    store: &Store,
    scope: Scope,
    env: &Env,
    parsed: &CredentialClassPolicyArgs,
) -> ExitCode {
    let (subject_kind, subject_ref) = match resolve_policy_subject(parsed) {
        Ok(subject) => subject,
        Err(message) => {
            eprintln!("ironauth credential-class-policy remove: {message}");
            return ExitCode::FAILURE;
        }
    };
    let actor = ActorRef::service(ServiceId::generate(env));
    let acting = store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env));
    match acting
        .credential_class_policies()
        .remove(env, &subject_kind, subject_ref.as_deref())
        .await
    {
        Ok(()) => {
            println!(
                "removed credential-class policy (subject={subject_kind}, ref={reference})",
                reference = subject_ref.as_deref().unwrap_or("-"),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth credential-class-policy remove: cannot remove policy: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The current instant in epoch microseconds, drawn from the determinism seam.
fn now_micros(env: &Env) -> i64 {
    let now = env.clock().now_utc();
    let micros = now
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros());
    i64::try_from(micros).unwrap_or(i64::MAX)
}

/// Run the `hash-probe` subcommand (issue #62): measure Argon2id on this host and
/// recommend parameters that meet the target per-hash latency, showing projected
/// logins/s per core. Reads the target latency from `[password_hashing]` when
/// `--config PATH` is given, else the shipped default; the per-hash memory budget
/// defaults to a fraction of total host RAM (issue #62 LOW-6) and is overridable
/// with `--memory-budget KIB`. Prints a human-readable report, or machine-readable
/// JSON with `--json`.
fn hash_probe(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let mut config_path: Option<String> = None;
    let mut json = false;
    let mut memory_budget_override: Option<u64> = None;
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--config=") {
            config_path = Some(value.to_owned());
        } else if arg == "--config" {
            let Some(path) = args.next() else {
                eprintln!("ironauth hash-probe: --config requires a PATH");
                return ExitCode::FAILURE;
            };
            config_path = Some(path);
        } else if let Some(value) = arg.strip_prefix("--memory-budget=") {
            let Ok(kib) = value.parse::<u64>() else {
                eprintln!("ironauth hash-probe: --memory-budget expects KiB (a u64)");
                return ExitCode::FAILURE;
            };
            memory_budget_override = Some(kib);
        } else if arg == "--memory-budget" {
            let Some(value) = args.next() else {
                eprintln!("ironauth hash-probe: --memory-budget requires a KiB value");
                return ExitCode::FAILURE;
            };
            let Ok(kib) = value.parse::<u64>() else {
                eprintln!("ironauth hash-probe: --memory-budget expects KiB (a u64)");
                return ExitCode::FAILURE;
            };
            memory_budget_override = Some(kib);
        } else if arg == "--json" {
            json = true;
        } else {
            eprintln!("ironauth hash-probe: unrecognized argument '{arg}'");
            eprintln!("usage: ironauth hash-probe [--config PATH] [--memory-budget KIB] [--json]");
            return ExitCode::FAILURE;
        }
    }

    let loaded = match &config_path {
        Some(path) => Config::load(path),
        None => Config::from_toml_str("", "<defaults>"),
    };
    let config = match loaded {
        Ok(Loaded { config, .. }) => config,
        Err(error) => {
            eprintln!("ironauth hash-probe: {error}");
            return ExitCode::FAILURE;
        }
    };

    let hashing = &config.password_hashing;
    // The per-hash memory budget the probe caps candidates at. Default: a sensible
    // fraction of TOTAL host memory (Linux MemTotal / 2) or a fixed 1 GiB fallback
    // on hosts without a dependency-free total-RAM read (issue #62 LOW-6), so the
    // default probe can explore the full ladder and recommend STRONGER parameters
    // than the deployment is presently configured for. An operator caps it
    // explicitly with --memory-budget. The probe also caps against measurable host
    // memory (Linux MemAvailable / 2) on its own.
    let memory_budget_kib =
        memory_budget_override.unwrap_or_else(ironauth_oidc::default_memory_budget_kib);
    let env = Env::system();
    let report = ironauth_oidc::run_probe(&env, hashing.probe_target_latency_ms, memory_budget_kib);

    if json {
        println!("{}", probe_report_json(&report));
    } else {
        print_probe_report(&report);
    }
    ExitCode::SUCCESS
}

/// Render a probe report as a machine-readable JSON object for `--json`.
fn probe_report_json(report: &ironauth_oidc::ProbeReport) -> String {
    let available = report
        .available_memory_kib
        .map_or_else(|| "null".to_owned(), |kib| kib.to_string());
    format!(
        "{{\"memory_kib\":{},\"iterations\":{},\"parallelism\":{},\
         \"measured_latency_ms\":{:.3},\"target_latency_ms\":{},\"within_target\":{},\
         \"projected_logins_per_sec_per_core\":{:.3},\"projected_logins_per_sec_total\":{:.3},\
         \"host_threads\":{},\"available_memory_kib\":{},\"memory_budget_kib\":{}}}",
        report.recommended.memory_kib(),
        report.recommended.iterations(),
        report.recommended.parallelism(),
        report.measured_latency_ms,
        report.target_latency_ms,
        report.within_target,
        report.projected_logins_per_sec_per_core,
        report.projected_logins_per_sec_total,
        report.host_threads,
        available,
        report.memory_budget_kib,
    )
}

/// Print a probe report as a human-readable summary.
fn print_probe_report(report: &ironauth_oidc::ProbeReport) {
    println!("Argon2id tuning probe (issue #62)");
    println!(
        "  recommended:  memory_kib={} iterations={} parallelism={}",
        report.recommended.memory_kib(),
        report.recommended.iterations(),
        report.recommended.parallelism(),
    );
    println!(
        "  measured:     {:.1} ms/hash (target {} ms; {})",
        report.measured_latency_ms,
        report.target_latency_ms,
        if report.within_target {
            "within target"
        } else {
            "host too slow for target: recommending the memory floor"
        },
    );
    println!(
        "  throughput:   {:.1} logins/s per core, {:.1} logins/s across {} core(s)",
        report.projected_logins_per_sec_per_core,
        report.projected_logins_per_sec_total,
        report.host_threads,
    );
    match report.available_memory_kib {
        Some(kib) => println!(
            "  host memory:  {kib} KiB available; per-hash budget {} KiB",
            report.memory_budget_kib
        ),
        None => println!(
            "  host memory:  unavailable on this platform; per-hash budget {} KiB",
            report.memory_budget_kib
        ),
    }
    println!();
    println!("Set these under [password_hashing] in your config; they apply to NEW hashes.");
    println!("An existing user's hash upgrades on their next successful login.");
}

fn print_help() {
    println!("ironauth {VERSION}");
    println!("A standards-first OpenID Connect identity platform.");
    println!();
    println!("USAGE:");
    println!("  ironauth serve [--config PATH]   Run the server until SIGTERM/SIGINT");
    println!("  ironauth hash-probe [--config PATH] [--memory-budget KIB] [--json]");
    println!("                                   Measure Argon2id on this host and");
    println!("                                   recommend parameters (issue #62)");
    println!("  ironauth validate <document>     Validate a config document (local)");
    println!("  ironauth plan <document> ...      Render the server-computed promotion plan");
    println!("  ironauth apply <document> ...     Apply a config document to a target");
    println!("  ironauth drift <document> ...     Report whether a target has drifted");
    println!("  ironauth ban --config PATH --tenant TID --environment EID \\");
    println!("               --kind ip|account|identifier --subject VALUE \\");
    println!("               [--path password|passkey|recovery|register|second_factor|all] \\");
    println!("               [--reason TEXT] [--expires-secs N]");
    println!("                                   Place a durable credential-abuse ban (issue #64)");
    println!("  ironauth unban --config PATH --tenant TID --environment EID \\");
    println!("               --kind ... --subject VALUE [--path ...]");
    println!("                                   Lift a ban");
    println!("  ironauth bans --config PATH --tenant TID --environment EID");
    println!("                                   List active bans");
    println!("  ironauth step-up-policy set --config PATH --tenant TID --environment EID \\");
    println!("               (--scope SCOPE | --client CLIENT_ID) \\");
    println!("               [--acr pwd|mfa|phr|phrh] [--max-age SECONDS]");
    println!("                                   Set a step-up policy (RFC 9470, issue #72)");
    println!("  ironauth step-up-policy list --config PATH --tenant TID --environment EID");
    println!("                                   List per-scope step-up policies");
    println!("  ironauth step-up-policy remove --config PATH --tenant TID --environment EID \\");
    println!("               (--scope SCOPE | --client CLIENT_ID)");
    println!("                                   Remove a per-scope policy / clear a client floor");
    println!(
        "  ironauth credential-class-policy set --config PATH --tenant TID --environment EID \\"
    );
    println!("               [--subject tenant|group|org] [--subject-ref ID] \\");
    println!("               --class any|mfa|passkey|attested_passkey");
    println!(
        "                                   Set a minimum-credential-class policy (issue #66)"
    );
    println!(
        "  ironauth credential-class-policy list --config PATH --tenant TID --environment EID"
    );
    println!("                                   List credential-class policies");
    println!(
        "  ironauth credential-class-policy remove --config PATH --tenant TID --environment EID \\"
    );
    println!("               [--subject tenant|group|org] [--subject-ref ID]");
    println!("                                   Remove a credential-class policy");
    println!("  ironauth --version               Print the version");
    println!("  ironauth --help                  Print this help");
    println!();
    println!("The server serves a public data plane and a private management plane");
    println!("(health, readiness, metrics) on separate ports; see docs/CONFIG.md.");
    println!("The config-as-code subcommands are a thin client of the management API;");
    println!("run 'ironauth <subcommand> --help' for their usage.");
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

    #[test]
    fn federation_runtime_is_off_by_default_and_built_when_enabled() {
        // MEDIUM-1: the boot path must actually install the federation runtime. By default
        // federation is disabled, so no runtime is built (the /federation routes 404).
        let default = config("");
        assert!(
            build_federation_runtime(&default.oidc).is_none(),
            "federation is off by default, so the boot path installs no runtime"
        );

        // When `oidc.federation.enabled` is set, the boot path builds a runtime, which is
        // then installed on the OidcState via with_federation so the routes go live.
        let enabled = config("[oidc.federation]\nenabled = true\n");
        assert!(
            build_federation_runtime(&enabled.oidc).is_some(),
            "an enabled federation config builds the runtime the boot path installs"
        );
    }

    #[test]
    fn advanced_recovery_rejects_a_malformed_idv_jwks_at_boot() {
        use ironauth_config::{AdvancedRecoveryConfig, IdvProvider};

        // A well-formed single Ed25519 JWKS (the jose inbound parser recovers one usable key).
        let good_jwks = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"ok"}]}"#;
        let ok = AdvancedRecoveryConfig {
            idv_enabled: true,
            idv_providers: vec![IdvProvider {
                slug: "acme".to_owned(),
                enabled: true,
                jwks: good_jwks.to_owned(),
                ..IdvProvider::default()
            }],
            ..AdvancedRecoveryConfig::default()
        };
        validate_idv_provider_jwks(&ok).expect("a well-formed IDV JWKS boots");

        // A non-empty but MALFORMED JWKS passes the config non-empty check yet parses to zero
        // usable keys: it must FAIL boot cleanly, naming the offending provider, rather than
        // failing closed at every IDV recovery callback.
        let bad = AdvancedRecoveryConfig {
            idv_enabled: true,
            idv_providers: vec![IdvProvider {
                slug: "acme".to_owned(),
                enabled: true,
                jwks: "definitely not a jwks".to_owned(),
                ..IdvProvider::default()
            }],
            ..AdvancedRecoveryConfig::default()
        };
        let err =
            validate_idv_provider_jwks(&bad).expect_err("a malformed IDV JWKS must fail boot");
        assert!(
            err.contains("acme") && err.contains("does not parse"),
            "the boot error must name the provider and the parse fault: {err}"
        );

        // A DISABLED provider with a malformed JWKS is inert: it is never parsed (a malformed
        // JWKS on a disabled provider need not fail boot).
        let disabled = AdvancedRecoveryConfig {
            idv_providers: vec![IdvProvider {
                slug: "acme".to_owned(),
                enabled: false,
                jwks: "definitely not a jwks".to_owned(),
                ..IdvProvider::default()
            }],
            ..AdvancedRecoveryConfig::default()
        };
        validate_idv_provider_jwks(&disabled)
            .expect("a disabled provider's JWKS is not parsed at boot");
    }
}
