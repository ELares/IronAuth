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
use ironauth_admin::events::WebhookFanoutConsumer;
use ironauth_admin::offboarding_worker::OffboardingConsumer;
use ironauth_admin::trait_migration_worker::TraitMigrationConsumer;
use ironauth_admin::webhook_delivery::{
    FetchWebhookSender, WebhookDeliveryConsumer, WebhookReplayConsumer,
};
use ironauth_admin::{AdminOidcBridge, AdminState};
use ironauth_config::{
    ADVANCED_RECOVERY_FEATURE, Config, FEDCM_FEATURE, FIRST_PARTY_CHALLENGE_FEATURE,
    FeatureRegistry, GLOBAL_TOKEN_REVOCATION_FEATURE, Loaded, ORG_SCOPED_CLIENTS_FEATURE,
    OidcConfig, OutboxConfig, PasswordPolicyConfig, RISK_SIGNALS_FEATURE, ScreeningFailurePolicy,
    ScreeningProvider, WebhooksConfig,
};
use ironauth_env::Env;
use ironauth_jose::MasterKey;
use ironauth_oidc::{
    BackChannelLogoutConsumer, CredentialClass, DiscoveryCapabilities, DiscoveryState,
    FederationKeyResolver, FederationRuntime, FetchLogoutSender, IssuerRegistry, IssuerState,
    JwksCacheWindow, OidcState, SessionEndedExplodeConsumer, canonical_login_identifier,
    canonical_step_up_acr, discovery_router, is_known_step_up_acr, issuer_router,
    known_step_up_acrs, oidc_router,
};
use ironauth_quota::QuotaEnforcer;
use ironauth_server::{Server, ServerError};
use std::collections::{BTreeMap, BTreeSet};

use ironauth_store::{
    AbuseBanId, AbuseSubject, AbuseSubjectKind, ActorRef, AuthPath, ClientId, CorrelationId,
    EnvironmentId, NewBan, RetryPolicy, SESSION_ENDED_CONSUMER, Scope, ServiceId, Store,
    StoreError, TenantId,
    audit_retention::{
        AuditReapStats, AuditReaper, AuditRetentionObserver, AuditRetentionSettings,
        AuditRetentionSweeper,
    },
    outbox::{
        ConsumerRegistry, ControlPlaneScopes, DrainStats, OutboxBackbone, OutboxConsumer,
        OutboxObserver, OutboxReaper, OutboxWorker, OutboxWorkerPool, PollOnly, RetentionObserver,
        RetentionSettings, RetentionStats, RetentionSweeper, ScopeSource, WorkerSettings,
    },
};

use ironauth_admin::log_shipper::{
    DatadogSink, HttpLogSink, LogShipper, LogShipperObserver, LogSink, S3LogSink, SplunkHecSink,
    StreamObservation,
};

use crate::shared_config::SharedPlaneInputs;

/// The config sections both planes must receive identically (issue #414).
mod shared_config;

/// The boot-wiring harness (issue #414): assembles both plane states from one config
/// and observes what they actually hold. DB-backed, so it rides the `testing` feature
/// exactly as the CLI integration suite does.
#[cfg(all(test, feature = "testing"))]
mod boot_wiring_tests;

/// The outbox boot seam (issue #104, PR 2): drives the REAL `spawn_consumer_pools` and
/// `outbox_worker_settings` against a real database, because a pool loop that covers a
/// subset of the registry compiles, lints and tests clean. DB-backed, so it rides the
/// `testing` feature exactly as the boot-wiring harness does.
#[cfg(all(test, feature = "testing"))]
mod outbox_wiring_tests;

/// Semantic version of this build, injected by Cargo.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The RFC 8628 device-flow polling state machine for `ironauth login` (issue #120).
///
/// Pure logic, kept out of `main` so the section 3.5 rules are tested as a table rather
/// than through a mocked HTTP exchange.
mod device_login;

/// Choosing between the loopback and device flows for `ironauth login` (issue #120).
///
/// A SECURITY default: loopback has no cross-device phishing exposure, so it is preferred
/// whenever a browser can be opened and the device flow is the fallback.
mod login_flow;

/// Building the loopback redirect URI for `ironauth login` (issue #120), per RFC 8252 7.3.
mod loopback;

/// The RFC 8252 loopback half of `ironauth login` (issue #120).
mod loopback_flow;

/// Where `ironauth login` stores what it obtains (issue #120): the platform keychain, with
/// a trait seam so the command's logic is testable on a runner that has no keychain.
mod capture;
mod credentials;

/// `ironauth dev`: the local emulator (issue #121).
mod dev;

/// `ironauth login`: the RFC 8628 device flow (issue #120).
mod login;

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
        // Remove every credential this machine stored for a deployment (issue #120).
        // Deliberately independent of `login`: a machine has to be able to reach a known
        // state without first being able to reach a server, which is exactly the situation
        // a user is in when they are logging out because something is wrong.
        // Sign in to a deployment (issue #120). The device flow: it needs no listener, no
        // browser on this machine, and no open port, so it is the flow that works on the
        // headless boxes and over the SSH sessions where a CLI login most often happens.
        // The local emulator (issue #121): the REAL server on loopback, with deterministic
        // secrets and a throwaway database, refusing to run anywhere it could be reached.
        Some("dev") => dev_command(&mut args),
        Some("login") => login(&mut args),
        Some("logout") => logout(&mut args),
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
        // The verdict is the SAME pure ladder question the carrier resolves it from,
        // asked of the same unmutated config, so the two cannot disagree; it is asked
        // here because this refusal must happen before any store is opened.
        if features.is_enabled(&config, ADVANCED_RECOVERY_FEATURE) {
            if let Err(error) = validate_idv_provider_jwks(&config.oidc.advanced_recovery) {
                tracing::error!(%error, "advanced-recovery IDV provider JWKS is invalid");
                return ExitCode::FAILURE;
            }
        }

        // Deterministic entropy in dev mode, a REAL clock in both. See `DEV_ENTROPY_SEED`.
        let env = dev::boot_env(DEV_ENTROPY_SEED.get().copied());

        // Install the process-wide Prometheus recorder BEFORE anything describes a
        // metric. The data-plane assembly below registers the help and type text for
        // the hashing-pool, screening, and connector-health metrics, and a `describe`
        // that runs while the global recorder is still the no-op one is silently
        // dropped, leaving those metrics on `/metrics` with no HELP or TYPE. `Server::new`
        // used to be the first caller by accident of ordering; this makes it explicit,
        // and the call is idempotent (it hands back the same handle the server takes).
        let _recorder = ironauth_server::metrics::recorder_handle();

        // BOTH planes, assembled from the ONE loaded config through the ONE capture
        // (issue #414), before `config` moves into the server. Every value the two
        // planes must agree on is resolved inside that capture and read off the one
        // carrier, so this call site has nothing to hand a plane and no second
        // derivation to get wrong. A malformed `server.public_url` refuses to boot here,
        // exactly as `Server::new` would, only earlier and before any store is opened.
        let planes = match assemble_planes(&config, &env, &features).await {
            Ok(planes) => planes,
            Err(error) => {
                tracing::error!(%error, "failed to derive the public site context");
                return ExitCode::FAILURE;
            }
        };

        // Capture what the Back-Channel Logout delivery worker (issue #34) needs before
        // config moves into the server (only when OIDC is mounted AND the switch is on).
        let backchannel_inputs = backchannel_worker_inputs(&config, &env);
        // Capture what the outbox RETENTION sweeper (issue #104, PR 3) needs, before config
        // moves into the server. Deliberately INDEPENDENT of `backchannel_inputs` above:
        // the queue's producer is unconditional and its consumers are not, so a reaper
        // gated on the consumer switch would be missing from the deployment where the table
        // grows fastest. The only switch is `outbox.reap_enabled`, which defaults ON.
        let retention_inputs = retention_sweeper_inputs(&config, &env);
        let audit_retention_inputs = audit_retention_inputs(&config, &env);
        let log_shipper_inputs = log_shipper_inputs(&config, &env);
        let metrics_sampler_inputs_captured = metrics_sampler_inputs(&config, &env);
        let webhook_inputs = webhook_delivery_inputs(&config, &env);
        let trait_migration = trait_migration_inputs(&config, &env);
        let offboarding = offboarding_inputs(&config, &env);
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
        // Mount the management API (issue #11) on the management plane. The state was
        // assembled above; mounting is all this adds, which is why the assembly is a
        // separate step the boot-wiring harness can observe.
        let management = planes.management.map(|state| {
            tracing::info!("management API mounted on the management plane");
            ironauth_admin::management_router(state)
        });
        // Keep a clone of the management router (if any) for the admin console's
        // same-origin proxy (issue #90, PR 2): the browser reaches the management
        // API through /admin/api on the PUBLIC plane, which the proxy forwards to
        // THIS in-process router. A Router is cheaply cloneable.
        let management_for_proxy = management.clone();
        if let Some(router) = management {
            server = server.mount_management(router);
        }
        // Mount the OIDC provider on the PUBLIC plane when enabled. Its three surfaces
        // read the SAME issuer registry, under the ONE config-derived base URL the
        // management plane also took, so issuers are per environment and the two planes
        // cannot disagree about what `iss` is.
        if let Some(plane) = planes.oidc {
            tracing::info!(
                "OIDC provider, discovery, and per-environment JWKS mounted on the public plane; \
                 per-environment signing keys load lazily from the store on first use"
            );
            server = server.mount_public(
                oidc_router(plane.state)
                    .merge(plane.discovery)
                    .merge(plane.jwks),
            );
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
        // The pools are BOUND rather than detached, so the shutdown below can await them.
        // Dropping them here instead would stop the workers at the next flag check, which
        // is the opposite of what a graceful stop wants.
        let logout_pools = match backchannel_inputs {
            Some(inputs) => spawn_backchannel_logout_pools(inputs, server.base_url()).await,
            None => Vec::new(),
        };
        // The webhook delivery worker (issue #105), behind its OWN switch. It is spawned
        // here rather than inside the block above because webhook delivery is not an OIDC
        // feature: gating it on the logout switches would make a deployment that uses no
        // OIDC unable to deliver webhooks it can already register endpoints for.
        // BOUND rather than detached, so the shutdown below can await it.
        let webhook_pools = match webhook_inputs {
            Some(inputs) => spawn_webhook_delivery_pools(inputs).await,
            None => Vec::new(),
        };
        // The trait migration worker (issue #53), behind its own switch for the same
        // reason webhook delivery is: it is a different subsystem and must not require
        // another one's configuration to run. BOUND so the shutdown below can await it.
        let trait_migration_pools = match trait_migration {
            Some(inputs) => spawn_trait_migration_pools(inputs).await,
            None => Vec::new(),
        };
        // The scheduled-offboarding worker (issue #52). ON by default, unlike the others,
        // because the management API already accepts a scheduled offboarding on every
        // deployment; without this the request is taken and silently never honoured.
        let offboarding_pools = match offboarding {
            Some(inputs) => spawn_offboarding_pools(inputs).await,
            None => Vec::new(),
        };
        // The outbox retention sweeper (issue #104, PR 3), started here and not inside the
        // block above: the outbox is a GENERIC substrate whose next consumer will run
        // behind a different switch, so the reaper must not share the back-channel logout
        // gate. It is NOT started unconditionally, and the two things that stop it are
        // named where they are decided: `outbox.reap_enabled` in `retention_sweeper_inputs`
        // and a missing control-plane DSN in `start_retention_sweeper`. BOUND rather than
        // detached, so the shutdown below can await it.
        let log_shipper = match log_shipper_inputs {
            Some(inputs) => start_log_shipper(inputs).await,
            None => None,
        };
        let audit_retention_sweeper = match audit_retention_inputs {
            Some(inputs) => start_audit_retention_sweeper(inputs).await,
            None => None,
        };
        let retention_sweeper = if let Some(inputs) = retention_inputs {
            start_retention_sweeper(inputs).await
        } else {
            tracing::warn!(
                "outbox retention is DISABLED (outbox.reap_enabled = false); \
                 outbox_messages will grow without bound unless something outside this \
                 process reaps it"
            );
            None
        };

        // The depth and lag gauges (issue #104), started beside the reaper and for the same
        // reason: the outbox is a GENERIC substrate, so its observability must not sit
        // behind any one consumer's switch. It has no switch of its own; see
        // `metrics_sampler_inputs`.
        let metrics_sampler = start_metrics_sampler(metrics_sampler_inputs_captured).await;

        tracing::info!(base_url = %server.base_url(), "starting ironauth");

        let outcome = match server.run(ironauth_server::shutdown_signal()).await {
            Ok(()) => {
                tracing::info!("ironauth stopped cleanly");
                ExitCode::SUCCESS
            }
            Err(error) => {
                tracing::error!(%error, "server exited with error");
                ExitCode::FAILURE
            }
        };
        // Stop the outbox pools and WAIT for their in-flight passes. A claimed message
        // that is not completed is not lost: its lease lapses and the next boot re-claims
        // it, which is the same path a crash takes.
        for pool in logout_pools
            .into_iter()
            .chain(webhook_pools)
            .chain(trait_migration_pools)
            .chain(offboarding_pools)
        {
            pool.shutdown().await;
        }
        // Stopped alongside the pools. Nothing is lost by stopping a retention pass part
        // way through: the delete is bounded and idempotent, and the rows this pass did not
        // reach are still there for the next boot.
        if let Some(sweeper) = retention_sweeper {
            sweeper.shutdown().await;
        }
        if let Some(sweeper) = audit_retention_sweeper {
            sweeper.shutdown().await;
        }
        if let Some(shipper) = log_shipper {
            shipper.shutdown().await;
        }
        // Stopped last: it reads the same table the pools and the reaper write, and a
        // sample racing their shutdown would publish a reading of a queue mid-drain.
        if let Some(sampler) = metrics_sampler {
            sampler.shutdown().await;
        }
        outcome
    })
}

/// The data-plane-only surface verdicts, resolved ONCE.
///
/// Named fields rather than a positional list of booleans: each is set beside the
/// exact ladder entry or config toggle it comes from, in one place, so no call site
/// can fill one of them in from another's source. None of these reaches the management
/// plane; the two verdicts that DO are declared in the `shared_plane_inputs!`
/// invocation and travel on the shared carrier instead.
// Six independent verdicts, and NAMED fields are the point: the alternative here was six
// positional booleans threaded through two call sites, where any two could be swapped
// silently. A state machine would model a composition these do not have.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
struct DataPlaneSurfaces {
    /// The experimental Global Token Revocation receiver (issue #36).
    global_revocation: bool,
    /// The experimental IdP-side FedCM surface (issue #83).
    fedcm: bool,
    /// The experimental third-party risk-signal ingestion surface (issue #82, PR 1).
    risk_signals: bool,
    /// The experimental org-scoped-clients surface (issue #103, milestone M10).
    org_scoped_clients: bool,
    /// The experimental OAuth 2.0 Authorization Challenge Endpoint (issue #93, Bet 3).
    first_party_challenge: bool,
    /// The headless flow API (issue #84), a plain operator toggle.
    flows: bool,
    /// The hosted-page render app cutover (issue #85), a plain operator toggle.
    hosted_pages: bool,
}

impl DataPlaneSurfaces {
    /// Resolve every data-plane surface verdict from the validated ladder and config.
    ///
    /// Each experimental surface is armed only when its feature is enabled AND
    /// acknowledged at its exact current version; the gate is the ladder, never a plain
    /// `[oidc]` toggle, so the ack can never be bypassed. Each verdict is injected
    /// through the OIDC state builder (never `OidcConfig`), so the routes stay uniform
    /// 404s until an operator opts in. The last two are ordinary top-level operator
    /// toggles, off by default, and are resolved here so they travel with the rest.
    fn resolve(features: &FeatureRegistry, config: &Config) -> Self {
        Self {
            global_revocation: features.is_enabled(config, GLOBAL_TOKEN_REVOCATION_FEATURE),
            fedcm: features.is_enabled(config, FEDCM_FEATURE),
            risk_signals: features.is_enabled(config, RISK_SIGNALS_FEATURE),
            org_scoped_clients: features.is_enabled(config, ORG_SCOPED_CLIENTS_FEATURE),
            first_party_challenge: features.is_enabled(config, FIRST_PARTY_CHALLENGE_FEATURE),
            flows: config.flows.enabled,
            // The hosted pages retarget the `/authorize` login and registration
            // interaction redirects onto the flow browser page, but ONLY in composition
            // with `flows` (the pages render through the flow engine), which the state
            // builder enforces via `hosted_pages_cutover`. A config that arms the pages
            // without the flow engine is surfaced as a load-time warning.
            hosted_pages: config.hosted_pages.enabled,
        }
    }
}

/// Both plane states, assembled from ONE config through ONE capture.
///
/// Returned rather than mounted so the boot-wiring harness (issue #414) can OBSERVE
/// what each plane actually holds. Mounting turns both into opaque `Router`s, which is
/// why deleting an install, or handing one plane a different value than the other, used
/// to build with zero warnings.
struct AssembledPlanes {
    /// The management plane's state, or `None` when the management API does not mount.
    management: Option<AdminState>,
    /// The OIDC data plane, or `None` when it is disabled or cannot mount.
    oidc: Option<OidcPlane>,
}

/// Assemble BOTH planes from the one loaded config (issue #414).
///
/// This is the whole cross-plane seam, and it exists as ONE function for one reason:
/// everything both planes must agree on is captured here, ONCE, and each plane is
/// built from that one carrier. A harness that drove the two builders itself would be
/// asserting a discipline it had just supplied; driving THIS function is what makes the
/// single-carrier discipline an observed property of the production path.
///
/// Neither plane failing to mount is fatal: the management API stays off when no
/// bootstrap operator token is configured or its store is unreachable, and the data
/// plane stays off when `oidc.enabled` is false or its store is unreachable. The server
/// then serves what remains rather than refusing to boot.
///
/// # Errors
///
/// [`ServerError::InvalidPublicUrl`] if `server.public_url` is set but is not a valid
/// `http`/`https` base URL, which is the one input both planes need and neither can
/// substitute for.
async fn assemble_planes(
    config: &Config,
    env: &Env,
    features: &FeatureRegistry,
) -> Result<AssembledPlanes, ServerError> {
    // The ONE capture. Every cross-plane value is resolved inside it, from this config,
    // this ladder, and this env seam; both planes below are handed `&shared` and take
    // every shared value off it. There is no second carrier to hand a plane and no
    // argument here that could be filled from the wrong source.
    let shared = SharedPlaneInputs::capture(config, features, env)?;
    let management = build_admin_state(config, env, &shared).await;
    let oidc = if config.oidc.enabled {
        build_oidc_plane(
            config,
            env,
            DataPlaneSurfaces::resolve(features, config),
            &shared,
        )
        .await
    } else {
        tracing::info!("OIDC provider not mounted: oidc.enabled is false");
        None
    };
    Ok(AssembledPlanes { management, oidc })
}

/// Assemble the management plane's [`AdminState`], or `None` if it should not mount.
///
/// The management API mounts only when a bootstrap operator token is configured, so the
/// default (token unset) config still boots without a database, exactly like the server
/// skeleton. When configured, it connects a control-plane store with the DSN chosen by
/// [`select_control_dsn`] (per the D2 policy). A failure to connect or an invalid admin
/// config is logged and the server continues to serve health, readiness, and metrics
/// rather than refusing to boot.
///
/// Every cross-plane value comes off `shared` rather than being derived here, so the
/// console credential bridge enforces the `iss` the mint stamps, this plane opens the
/// PII the data plane sealed, and one cache key has one value.
async fn build_admin_state(
    config: &Config,
    env: &Env,
    shared: &SharedPlaneInputs,
) -> Option<AdminState> {
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
    // plaintext); resolve_master_key logged once at boot when it is unset.
    let store = match shared.master_key() {
        Some(master) => store.with_master_key(Arc::clone(master)),
        None => store,
    };
    match AdminState::new(store, env.clone(), &config.admin) {
        Ok(state) => {
            // The ONE data-plane issuer registry this plane reads signing keys through
            // (issue #414). Two installs need it, the compatibility wizard's
            // signable-algorithm resolution (issue #93) and the console credential
            // bridge (issue #90), and each used to open its OWN data-plane pool and
            // build its OWN registry from its OWN derivation of the issuer base and the
            // cache window. That was two connection pools where one does, two caches of
            // the same keys, and two chances for one operator-visible value to be
            // derived differently. `None` when the data-plane store is unreachable,
            // which leaves both installs off (each fails closed).
            let data_plane_registry = connect_data_plane_registry(config, shared).await;
            // Everything that reaches BOTH planes (issue #414): the two config sections
            // that live outside `[admin]` because both planes consume them (the
            // `[organizations]` group nesting bound, issue #97, and the `[token_claims]`
            // budget, issue #98), the two feature-ladder verdicts that arm this plane's
            // review-queue endpoints and the data plane's enforcement (issue #82), and
            // the two runtime objects this plane must hold the SAME Arc of (the
            // lazy-migration hook, issue #56, and the federation runtime, issue #76).
            // All six come from the SAME captured carrier the data plane installs,
            // through the SAME generic install body, so the two planes cannot be handed
            // different values. The budget is read here only to report an approach
            // warning; it never refuses a write, and the depth bound caps nothing that
            // is counted.
            let state = shared.install(state);
            // The login-identifier uniqueness policy (issue #54, epic #514). This is the
            // first reader the `[identifiers]` section has ever had: migration 0041 named
            // it as the source of every identifier row's uniqueness discriminator, and the
            // store enforced whatever mode it was handed, but no boot path read it, so an
            // operator who set `org_scoped` silently got environment-wide behaviour
            // (issue #459).
            //
            // Installed HERE rather than through `shared_plane_inputs!` because it reaches
            // ONE plane: the management identifier surface is the only production writer of
            // `user_identifiers`, so the data plane has nothing to hand it to. When a
            // data-plane writer lands it moves into the shared carrier, so the two planes
            // cannot then be handed different modes.
            let state = state.with_identifiers(&config.identifiers);
            // The outbox visibility lease (issue #104), so the queue-depth read can say
            // what "in flight" means. Installed HERE for the same reason `[identifiers]`
            // is: it reaches ONE plane. The data plane drains the queue and never reports
            // on it, so it has nothing to hand this to.
            //
            // It is the SAME value the worker pools are built from, which is what makes
            // the report agree with the drain: a lease shorter than the drain's would
            // count live work as ready, and a longer one would count lapsed work as in
            // flight.
            let state = state.with_outbox_visibility_timeout(config.outbox.visibility_timeout_secs);
            // Share the data-plane issuer registry (issue #93) so the compatibility wizard
            // can resolve an environment's actually signable ID-token algorithms and write
            // the per-client column through the data plane (the only role that can).
            // Absent a reachable data-plane store the wizard's write endpoint fails closed.
            let state = install_signing_registry(state, data_plane_registry.clone());
            // Arm the OIDC-session credential bridge (issue #90, PR 2) when the operator has
            // configured an admin issuer and a management audience AND the OIDC data plane is
            // mounted (so signing keys exist to verify against). Absent config leaves the
            // bridge disarmed: the management API then accepts no at+jwt at all (fail closed).
            let state = install_admin_oidc_bridge(state, config, data_plane_registry);
            // Domain verification (issue #96): without a resolver the verify endpoint
            // answers 503 rather than reporting a domain unverified.
            let state = arm_domain_verification(state, env);
            Some(state)
        }
        Err(error) => {
            tracing::error!(%error, "management API not mounted: invalid admin config");
            None
        }
    }
}

/// Open the ONE data-plane issuer registry the management plane reads signing keys
/// through, or `None` when the data-plane store is unreachable.
///
/// Two management-plane installs need it and both get THIS one (issue #414): the
/// compatibility wizard's signable-algorithm resolution (issue #93) and the console
/// credential bridge (issue #90). One store-backed [`IssuerRegistry`] over one
/// data-plane pool, under the ONE issuer base and the ONE clamped cache window the
/// boot path derived, master-keyed so sealed material opens. Sharing it is not merely
/// thrift: a registry built from a second derivation of the issuer base could enforce
/// an `iss` the mint never stamps, which would fail every console login while the data
/// plane looked healthy.
///
/// `None` leaves both installs off, and each fails closed on its own terms: the
/// wizard's write endpoint cannot confirm signability, and the management API accepts
/// no `at+jwt` at all.
async fn connect_data_plane_registry(
    config: &Config,
    shared: &SharedPlaneInputs,
) -> Option<Arc<IssuerRegistry>> {
    let store = match Store::connect(config.database.url.expose()).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(
                %error,
                "management-plane data-plane registry NOT opened: cannot connect the \
                 data-plane store. The compatibility wizard's signing-algorithm endpoint and \
                 the admin console OIDC bridge both stay off (each fails closed)."
            );
            return None;
        }
    };
    let store = match shared.master_key() {
        Some(master) => store.with_master_key(Arc::clone(master)),
        None => store,
    };
    Some(Arc::new(IssuerRegistry::store_backed(
        shared.issuer_base().clone(),
        *shared.jwks_cache(),
        store,
    )))
}

/// Share the data-plane issuer registry with the management state (issue #93).
///
/// The compatibility wizard resolves an environment's ACTUALLY signable ID-token
/// algorithms (the layer-2 security check) and writes the per-client
/// `id_token_signed_response_alg` column, both of which need the DATA plane: the
/// signable set comes from the per-environment signing keys, and that column is
/// data-plane writable only (the control role holds no grant on it). The registry is
/// the one [`connect_data_plane_registry`] opened. Absent it the registry stays
/// uninstalled and the wizard's write endpoint fails closed (it cannot confirm
/// signability).
fn install_signing_registry(
    state: AdminState,
    registry: Option<Arc<IssuerRegistry>>,
) -> AdminState {
    let Some(registry) = registry else {
        return state;
    };
    tracing::info!(
        "compatibility wizard signing registry installed (issue #93): the per-client \
         signing-algorithm endpoint validates against the environment's actually signable set"
    );
    state.with_signing_registry(registry)
}

/// Install the DNS TXT lookup domain verification performs (issue #96).
///
/// Without this the verify endpoint answers 503 rather than reporting a domain
/// unverified: a deployment with no resolver cannot prove domain control, and saying
/// "not verified" would send an operator to debug their DNS instead of their deployment.
///
/// A resolver that cannot be built is NOT fatal to boot. Domain verification is one
/// optional feature, and refusing to start the whole identity provider because
/// `/etc/resolv.conf` is unreadable would take down authentication to protect a
/// convenience.
fn arm_domain_verification(state: AdminState, env: &ironauth_env::Env) -> AdminState {
    match ironauth_fetch::txt::SystemTxtLookup::from_system_conf(env.clone()) {
        Ok(lookup) => {
            tracing::info!(
                "domain verification armed (issue #96): enterprise routing rules can prove \
                 domain control through a DNS TXT record"
            );
            state.with_txt_lookup(std::sync::Arc::new(lookup))
        }
        Err(error) => {
            tracing::warn!(
                %error,
                "no DNS resolver: enterprise domain verification will answer 503 until one \
                 is available (issue #96)"
            );
            state
        }
    }
}

/// Arm the OIDC-session credential bridge on the management state (issue #90, PR 2).
///
/// The console dogfoods IronAuth's own OIDC: it signs in and presents a short-lived
/// `at+jwt`, which the management API's third resolution arm verifies against the
/// admin issuer's PUBLISHED signing keys and maps to the operator plane via the
/// fail-closed operator-subject allowlist. This installs the bridge when the
/// operator has named an admin issuer `(tenant, environment)` and a management
/// audience in `[admin_spa]` AND the OIDC data plane is enabled (so signing keys
/// exist to verify against). It reads those keys through the ONE store-backed
/// [`IssuerRegistry`] [`connect_data_plane_registry`] opened, over the SAME data-plane
/// store and the SAME issuer base the OIDC plane serves its JWKS from, so the
/// verification keys are the identical RLS-scoped rows and the enforced `iss` is the
/// one the mint stamps (the registry seam reused, not a new key store). Any missing or
/// unparseable config, or an unreachable data-plane store, leaves the bridge disarmed,
/// and the management API then accepts no `at+jwt` at all (fail closed).
fn install_admin_oidc_bridge(
    state: AdminState,
    config: &Config,
    registry: Option<Arc<IssuerRegistry>>,
) -> AdminState {
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
    // The ONE data-plane registry, carrying the ONE derived issuer base, so the enforced
    // `iss` matches exactly what the mint stamps and the JWKS publishes.
    let Some(registry) = registry else {
        tracing::error!(
            "admin console OIDC bridge NOT armed: the data-plane issuer registry is not open"
        );
        return state;
    };
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
        .environments(state.bootstrap_operator_id(), tenant)
        .parse_id(environment_id)
        .ok()?;
    Some(Scope::new(tenant, environment))
}

/// The assembled OIDC data plane: the mint state and the two surfaces that read the
/// SAME issuer registry it does.
///
/// Returned rather than mounted so the boot-wiring harness (issue #414) can OBSERVE
/// what the assembled [`OidcState`] holds. Merging the three into one `Router` hides
/// every install behind an opaque type, which is why deleting an install, or handing
/// this plane a different section than the management plane, used to build with zero
/// warnings.
struct OidcPlane {
    /// The mint state: everything the protocol router runs on.
    state: OidcState,
    /// The discovery surface (both well-known forms).
    discovery: Router,
    /// The per-environment JWKS surface.
    jwks: Router,
}

/// Assemble the OIDC data plane (issue #12), or `None` if it cannot mount.
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
/// configured value (AC #4). It is clamped ONCE, on the shared carrier, so the
/// management plane's registry caches under the same window.
///
/// The caller merges the three surfaces into one `Router`; see [`OidcPlane`] for why
/// this returns them instead of mounting them.
/// The ONE data-plane-to-control-plane crossing (issue #96, criterion 5), or [`None`].
///
/// Built only when the deployment asked for it AND a control DSN exists. Both conditions matter:
/// without the toggle the capability must be ABSENT rather than merely disabled, and without a
/// control DSN there is no role holding INSERT on `organizations`, so a seam over the data-plane
/// store would fail at the write with a bare permission error.
///
/// # Every failure here is [`None`], never a refusal to boot
///
/// A separate function precisely so the early returns mean "no seam" rather than "no OIDC plane".
/// Inlined in [`build_oidc_plane`], which returns `Option<OidcPlane>`, the same `return None`
/// would have aborted the whole data plane: a deployment that turned this on and forgot the
/// control DSN would have failed to serve ANY traffic, turning a configuration typo into an
/// outage. That is how the first version of this was written.
///
/// A configured-but-unusable combination is logged loudly instead, matching how the management
/// API treats the same missing DSN. An operator should learn about it from a startup line, not
/// from a refused login and certainly not from a dead server.
async fn connect_org_provisioning(
    config: &Config,
) -> Option<std::sync::Arc<ironauth_store::org_provisioning::OrgProvisioningSeam>> {
    if !config.oidc.self_service_organizations {
        return None;
    }
    let Some(dsn) = select_control_dsn(config) else {
        tracing::error!(
            "self-service organizations disabled: oidc.self_service_organizations is on but no \
             control-plane DSN is configured, and creating an organization is a control-plane \
             write"
        );
        return None;
    };
    match Store::connect(&dsn).await {
        Ok(control) => Some(std::sync::Arc::new(
            ironauth_store::org_provisioning::OrgProvisioningSeam::new(control),
        )),
        Err(error) => {
            tracing::error!(
                %error,
                "self-service organizations disabled: cannot connect the control-plane store"
            );
            None
        }
    }
}

// One flat sequence of independent state-builder installs and startup notices; splitting
// it would scatter the single OIDC mount the boot path performs.
#[allow(clippy::too_many_lines)]
async fn build_oidc_plane(
    config: &Config,
    env: &Env,
    surfaces: DataPlaneSurfaces,
    shared: &SharedPlaneInputs,
) -> Option<OidcPlane> {
    let oidc_config = &config.oidc;
    let policy_config = &config.password_policy;
    let hashing_config = &config.password_hashing;
    let env = env.clone();
    let store = match Store::connect(config.database.url.expose()).await {
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
    let store = match shared.master_key() {
        Some(master) => store.with_master_key(Arc::clone(master)),
        None => store,
    };

    // The issuer root and the JWKS cache window, each derived ONCE on the shared carrier
    // (issue #414) and read off it here. The window governs the JWKS AND discovery
    // Cache-Control on this plane and sizes the management plane's registry cache on
    // that one, so one operator-visible key has one value; the issuer root is what this
    // plane stamps as `iss` and what the console credential bridge over there enforces
    // `iss` against.
    let issuer_base = shared.issuer_base().clone();
    let cache = *shared.jwks_cache();

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
        .with_first_party_challenge_endpoint(surfaces.first_party_challenge);
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
    let quota_enforcer = Arc::new(QuotaEnforcer::from_config(&config.quota, env.clock_arc()));

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

    let org_provisioning = connect_org_provisioning(config).await;

    // The claims-enrichment hook (issue #100): the seam an external policy decision point
    // or FGA merges extra token claims through at issuance.
    //
    // Built HERE and not through `shared_plane_inputs!` for the reason `[identifiers]` is:
    // it reaches ONE plane. Only the data plane mints tokens, so the management plane has
    // nothing to hand this to, and a shared carrier would make AdminState hold a field it
    // never reads. The boot-wiring guard rejects exactly that, correctly.
    // A fetcher that will not build is a TLS trust-store fault, which must not take the
    // whole OIDC plane down: it disables the hook and issuance carries on without the extra
    // claims, which is the same fail-open direction the hook itself takes.
    let claims_enrichment_hook =
        match crate::shared_config::outbound_fetcher(ironauth_fetch::FetchLimits::default()) {
            Ok(fetcher) => ironauth_oidc::enrichment::ClaimsEnrichmentHook::from_config(
                &config.oidc.claims_enrichment,
                std::sync::Arc::new(fetcher),
            )
            .map(std::sync::Arc::new),
            Err(error) => {
                if config.oidc.claims_enrichment.enabled {
                    tracing::warn!(
                        %error,
                        "the claims-enrichment hook is enabled but its outbound fetcher could \
                         not be built; tokens are issued without the enriched claims"
                    );
                }
                None
            }
        };
    let state = OidcState::new(store, env, registry, oidc_config, issuer_base)
        .with_org_provisioning(org_provisioning)
        .with_global_token_revocation_enabled(surfaces.global_revocation)
        .with_fedcm_enabled(surfaces.fedcm)
        .with_risk_signals_enabled(surfaces.risk_signals)
        .with_org_scoped_clients_enabled(surfaces.org_scoped_clients)
        .with_first_party_challenge_enabled(surfaces.first_party_challenge)
        .with_flows_enabled(surfaces.flows)
        .with_hosted_pages_enabled(surfaces.hosted_pages)
        .with_diagnostics(&config.diagnostics)
        .with_quota_enforcer(quota_enforcer)
        .with_hashing_pool(hashing_pool)
        .with_password_policy(password_policy, screening_failure, screen_on_login)
        // The email-OTP / magic-link factors (issue #68) deliver through the verification
        // seam. Until a real email provider is wired (M11 messaging), ship the dev
        // transport: it records deliveries on the observability plane and emits the code /
        // link only at the `debug` trace level, so the OTP and magic-link logic works end
        // to end without a mail server. A production deployment installs its own
        // `VerificationSender` here.
        // In dev mode the capture sink replaces the logging transport, so a CI script can
        // read the code back rather than scraping a debug log. Everywhere else this is
        // `None` and the logging transport is installed exactly as before.
        .with_verification_sender(DEV_CAPTURE.get().map_or_else(
            || {
                std::sync::Arc::new(ironauth_oidc::LoggingVerificationSender)
                    as std::sync::Arc<dyn ironauth_oidc::VerificationSender>
            },
            |sink| {
                std::sync::Arc::clone(sink) as std::sync::Arc<dyn ironauth_oidc::VerificationSender>
            },
        ))
        // The guarded SMS-OTP factor (issue #70) delivers through a SEPARATE provider
        // seam. Until a real SMS provider (Twilio Verify, Vonage, SNS) is wired (M11
        // messaging), ship the dev stub: it records deliveries and emits the code only at
        // the `debug` trace level, so the guarded SMS logic works end to end without an
        // SMS gateway. A production deployment installs its own `SmsSender` here. SMS OTP
        // is off by default, so this stub is inert until a tenant explicitly enables SMS.
        .with_sms_sender(DEV_CAPTURE.get().map_or_else(
            || {
                std::sync::Arc::new(ironauth_oidc::LoggingSmsSender)
                    as std::sync::Arc<dyn ironauth_oidc::SmsSender>
            },
            |sink| std::sync::Arc::clone(sink) as std::sync::Arc<dyn ironauth_oidc::SmsSender>,
        ));
    // Installed after the chain because it is CONDITIONAL: a disabled hook, or one whose
    // allowlist is empty, resolves to `None` and issuance is byte-for-byte unchanged.
    let state = match &claims_enrichment_hook {
        Some(hook) => state.with_claims_enrichment_hook(std::sync::Arc::clone(hook)),
        None => state,
    };
    // Everything that reaches BOTH planes (issue #414): the two config sections that
    // live outside `[oidc]` because both planes consume them (the `[organizations]`
    // group nesting bound, issue #97, which bounds the ancestor walk the mint-path
    // effective-role resolution performs, and the `[token_claims]` budget, issue #98,
    // which bounds a TOKEN's size and what ONE claim carries), the two feature-ladder
    // verdicts that arm this plane's enforcement and the management plane's review
    // queues (issue #82), and the two runtime objects both planes must hold the SAME
    // Arc of (the lazy-migration hook on the login path, issue #56, and the federation
    // runtime whose per-connector health registry the admin read reports, issue #76).
    // All six come from the SAME captured carrier the management plane installs,
    // through the SAME generic install body, so the two planes cannot be handed
    // different values. Neither bound caps anything that is stored or counted.
    let mut state = shared.install(state);
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
    if surfaces.global_revocation {
        tracing::info!(
            "experimental Global Token Revocation receiver mounted (issue #36); the draft \
             is not WG-adopted and the wire shape may change between releases"
        );
    }
    if surfaces.fedcm {
        tracing::info!(
            "experimental FedCM IdP surface mounted (issue #83); Chrome only (Firefox \
             paused, Safari absent), the W3C draft may change between releases, and \
             redirect flows are unaffected"
        );
    }
    if surfaces.risk_signals {
        tracing::info!(
            "experimental third-party risk-signal ingestion mounted (issue #82); a signed \
             Security Event Token is verified per-source through the JOSE core and folded \
             into the risk engine as a WEIGHTED policy input (never a verdict); the wire \
             contract may change between releases"
        );
    }
    // Read off the built state rather than a parameter, so the notice reports what this
    // plane actually holds rather than a value that could disagree with it.
    if state.advanced_recovery_enabled() {
        tracing::info!(
            "experimental advanced recovery modes mounted (issue #82); admin-approved, \
             trusted-contact, and IDV-gated recovery each complete THROUGH the recovery delay \
             window and downgrade invariant; IDV consumes a signed provider callback and \
             IronAuth never verifies documents in house; the wire contract may change between \
             releases"
        );
    }
    if surfaces.first_party_challenge {
        tracing::info!(
            "experimental OAuth 2.0 Authorization Challenge Endpoint mounted (issue #93, \
             draft-ietf-oauth-first-party-apps): the browserless first-party native login surface; \
             a first-party native client completes login in one request and receives an \
             authorization code redeemed at the token endpoint with no redirect_uri; the wire shape \
             may change between releases"
        );
    }
    Some(OidcPlane {
        state,
        discovery,
        jwks,
    })
}

/// The federation runtime over an injected fetcher builder (issues #75 and #674).
///
/// The seam exists so a test can assert the DECISION the config flag controls without the host
/// trust store deciding the outcome for it. Before it, an enabled config on a machine whose
/// keychain refused produced `None`, and the test read that as "the flag did not build a
/// runtime" while the log line naming the real cause scrolled past in a gate log thousands of
/// lines long.
///
/// Production passes the real builder, so the fail-closed behaviour is unchanged: a fetcher
/// that cannot be built still means federation is not mounted, loudly.
fn build_federation_runtime_with<F>(
    cfg: &OidcConfig,
    build_fetcher: F,
) -> Option<Arc<FederationRuntime>>
where
    F: FnOnce() -> Result<ironauth_fetch::Fetcher, ironauth_fetch::TlsSetupError>,
{
    if !cfg.federation.enabled {
        return None;
    }
    let fetcher = match build_fetcher() {
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
    /// The OIDC settings (the per-delivery HTTP budget and the JWKS cache window).
    oidc: OidcConfig,
    /// The shared `[outbox]` tuning every consumer's pool is built from (issue #104):
    /// concurrency, the visibility lease, the poll cadence, the claim batch and the
    /// retry schedule. Back-channel logout no longer carries its own copy of any of them.
    outbox: OutboxConfig,
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

/// What the webhook delivery worker (issue #105) needs, captured before `config` moves
/// into the server.
struct WebhookDeliveryInputs {
    /// The webhook consumer's own settings (the per-delivery HTTP budget).
    webhooks: WebhooksConfig,
    /// The shared `[outbox]` tuning the pool is built from, exactly as every other
    /// consumer's pool is.
    outbox: OutboxConfig,
    /// The data-plane DSN the worker drains and reads endpoints through.
    data_plane_dsn: String,
    /// The control-plane DSN the worker enumerates `(tenant, environment)` scopes on;
    /// [`None`] disables the worker, since without it there are no scopes to drain.
    control_dsn: Option<String>,
    /// The master key the sealed signing secret is opened under. [`None`] disables the
    /// worker: a deliverer that cannot open a secret cannot sign, and the alternative to
    /// refusing to start would be a worker that burns every message's attempt budget.
    master: Option<Arc<MasterKey>>,
    /// The environment seam (deterministic clock and entropy).
    env: Env,
}

/// What the scheduled-offboarding worker (issue #52) needs, captured before `config` moves.
struct OffboardingInputs {
    /// The shared `[outbox]` tuning the pool is built from.
    outbox: OutboxConfig,
    /// The data-plane DSN the worker drains and offboards through.
    data_plane_dsn: String,
    /// The control-plane DSN the worker enumerates scopes on; [`None`] disables it.
    control_dsn: Option<String>,
    /// The environment seam.
    env: Env,
}

/// Capture the offboarding worker inputs from config (issue #52), or `None` when it is off.
fn offboarding_inputs(config: &Config, env: &Env) -> Option<OffboardingInputs> {
    if !config.users.offboarding_worker_enabled {
        return None;
    }
    Some(OffboardingInputs {
        outbox: config.outbox.clone(),
        data_plane_dsn: config.database.url.expose().to_owned(),
        control_dsn: select_control_dsn(config),
        env: env.clone(),
    })
}

/// Start the scheduled-offboarding worker (issue #52) on the generic outbox worker pool.
///
/// The FOURTH production consumer of the #104 framework, extending the generic parts
/// rather than copying them. No master key is needed: executing an offboarding flips state
/// and cascades sessions, and reads no sealed value.
async fn spawn_offboarding_pools(inputs: OffboardingInputs) -> Vec<OutboxWorkerPool> {
    let OffboardingInputs {
        outbox,
        data_plane_dsn,
        control_dsn,
        env,
    } = inputs;

    let Some(control_dsn) = control_dsn else {
        tracing::error!(
            "scheduled offboarding worker not started: no control-plane DSN to enumerate \
             scopes (set admin.control_database_url, or run in dev_mode). Scheduled \
             offboardings are durable queue rows, so none is lost; enable the control \
             plane to execute them."
        );
        return Vec::new();
    };
    let data_store = match Store::connect(&data_plane_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "scheduled offboarding worker not started: data-plane connect failed");
            return Vec::new();
        }
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "scheduled offboarding worker not started: control-plane connect failed");
            return Vec::new();
        }
    };

    let mut consumers = ConsumerRegistry::new();
    if let Err(error) = consumers
        .register(Arc::new(OffboardingConsumer::new(data_store.clone())) as Arc<dyn OutboxConsumer>)
    {
        tracing::error!(%error, "scheduled offboarding worker not started: duplicate consumer name");
        return Vec::new();
    }

    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store));
    let observer = outbox_observer();
    let pools = spawn_consumer_pools(&consumers, &data_store, &env, &outbox, &scopes, &observer);

    tracing::info!(
        consumers = ?consumers.names(),
        pools = pools.len(),
        "scheduled offboarding execution started on the outbox consumer pools"
    );
    pools
}

/// What the trait migration worker (issue #53) needs, captured before `config` moves.
struct TraitMigrationInputs {
    /// How many identities ONE batch processes.
    batch_size: u32,
    /// The shared `[outbox]` tuning the pool is built from.
    outbox: OutboxConfig,
    /// The data-plane DSN the worker drains and migrates through.
    data_plane_dsn: String,
    /// The control-plane DSN the worker enumerates scopes on; [`None`] disables it.
    control_dsn: Option<String>,
    /// The master key: a migration reads and re-seals every identity's traits, so without
    /// one every batch fails at the unseal.
    master: Option<Arc<MasterKey>>,
    /// The environment seam.
    env: Env,
}

/// Capture the trait migration worker inputs from config (issue #53), or `None` when the
/// worker is switched off.
fn trait_migration_inputs(config: &Config, env: &Env) -> Option<TraitMigrationInputs> {
    if !config.traits.migration_worker_enabled {
        return None;
    }
    Some(TraitMigrationInputs {
        batch_size: config.traits.migration_batch_size,
        outbox: config.outbox.clone(),
        data_plane_dsn: config.database.url.expose().to_owned(),
        control_dsn: select_control_dsn(config),
        master: resolve_master_key(config),
        env: env.clone(),
    })
}

/// Capture the webhook delivery worker inputs from config (issue #105), or `None` when the
/// consumer is switched off.
///
/// Gated on `webhooks.delivery_enabled` ALONE, deliberately. Webhook delivery is not an
/// OIDC feature and must not inherit `oidc.enabled`: a deployment using IronAuth purely as
/// a user store still registers endpoints and still expects them delivered.
fn webhook_delivery_inputs(config: &Config, env: &Env) -> Option<WebhookDeliveryInputs> {
    if !config.webhooks.delivery_enabled {
        return None;
    }
    Some(WebhookDeliveryInputs {
        webhooks: config.webhooks.clone(),
        outbox: config.outbox.clone(),
        data_plane_dsn: config.database.url.expose().to_owned(),
        control_dsn: select_control_dsn(config),
        master: resolve_master_key(config),
        env: env.clone(),
    })
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
        outbox: config.outbox.clone(),
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

/// The attempts budget a FAN-OUT consumer runs under (issue #104): effectively unbounded.
///
/// It is not a tuning preference, it is the difference between losing one notification and
/// losing all of them, and it is worth spelling the derivation out.
///
/// `outbox.max_attempts` is the right bound for a DELIVERY message. One such message is one
/// relying party, its retryable failures are an unreachable network endpoint, and a finite
/// bound is exactly what turns a permanently dead RP into a dead letter instead of an
/// infinite retry.
///
/// A `session_ended` message is the opposite in every one of those respects. It is the
/// WHOLE fan-out of one ended session, and it is the whole fan-out at a moment when no
/// per-RP message exists yet, so dead-lettering it leaves every relying party of that
/// session un-notified, with no per-RP record anywhere to replay from and nothing an
/// operator would ever see except a row in a dead-letter tail. Its handler makes no
/// outbound call at all: it reads participants and enqueues rows, both against the local
/// database, so the ONLY failure it can classify as retryable is a database fault. A
/// database fault is transient by construction (a permanent one has already taken the whole
/// process with it), which means a bound on this consumer cannot distinguish "give up on
/// bad work" from "give up because the database was unwell for a few minutes". At the
/// shipped defaults it is the latter: five attempts on a 10 second base is about 150
/// seconds of trouble, after which a session's entire logout fan-out is discarded forever.
///
/// The bound cannot be doing the OTHER job a finite bound does either, which is escaping a
/// poison message. Every input this handler cannot process (an unreadable payload, a
/// session id that does not parse in its scope) is already classified `permanent` and
/// dead-letters on its FIRST attempt whatever this number is. What is left for the bound to
/// catch is a `consumer_panic`, and retrying that forever is the better failure: the panic
/// is a code defect that will affect every session, so dead-lettering would discard all of
/// them permanently rather than replaying them once the defect is fixed.
///
/// Unbounded retry is also what this consumer did BEFORE it moved onto the substrate. The
/// deleted hand-rolled worker propagated a store fault out of its loop, logged it, let the
/// lease lapse, and re-claimed the message on the next pass, forever. Migrating to a generic
/// substrate is what introduced a terminal state here, so this restores the property rather
/// than inventing one.
///
/// The objection `OutboxConfig::max_attempts` states against an unlimited value, that "a
/// message that shares an ordering key with others BLOCKS them until it reaches a terminal
/// state, so the dead letter is what releases the aggregate", does not reach this consumer,
/// and that is why the exemption is safe HERE and is not offered as a configuration value
/// for consumers in general. A `session_ended` message's ordering key is the ended session
/// id, and a session ends once, so every group is a SINGLETON: there is nothing behind it
/// to block. A consumer whose producers share ordering keys must keep the finite bound.
///
/// "Effectively" unbounded and not literally so: the retry schedule caps its backoff at one
/// hour, so this budget is roughly two billion hourly attempts. Nothing reaches it, and
/// nothing here has to reason about what an unbounded loop would mean.
const FANOUT_MAX_ATTEMPTS: u32 = u32::MAX;

/// Map the shared `[outbox]` section to the worker tuning ONE consumer's pool is built
/// from (issue #104), in ONE place.
///
/// Every pool reads the same numbers, so translating them per call site is how two pools
/// end up with different leases from one configuration. `claim_batch` is a `u32` in
/// configuration and an `i64` on the claim, and the widening is infallible.
///
/// EXACTLY ONE number varies by consumer, the attempts budget, and it varies here rather
/// than at a call site so that "the lease, the cadence, the batch and the backoff base are
/// the same for every pool" stays a property of one function a reader can check.
/// [`FANOUT_MAX_ATTEMPTS`] argues why the fan-out consumer is the one that differs.
fn outbox_worker_settings(outbox: &OutboxConfig, consumer: &str) -> WorkerSettings {
    let max_attempts = if consumer == SESSION_ENDED_CONSUMER {
        FANOUT_MAX_ATTEMPTS
    } else {
        outbox.max_attempts
    };
    WorkerSettings {
        concurrency: outbox.worker_concurrency,
        visibility_timeout: std::time::Duration::from_secs(outbox.visibility_timeout_secs),
        poll_interval: std::time::Duration::from_secs(outbox.poll_interval_secs),
        batch: i64::from(outbox.claim_batch),
        retry: RetryPolicy {
            max_attempts,
            retry_base: std::time::Duration::from_secs(outbox.retry_base_secs),
        },
    }
}

/// The observer EVERY outbox pool in this binary reports through (issue #104).
///
/// It exists because there are four separate boot seams that spawn pools (session ended and
/// offboarding, back-channel logout, webhook delivery, trait migration), and each one used to
/// construct its own observer. Four copies of a wiring decision is four places to forget it,
/// and forgetting it in one is not visible as an error: the pool runs, the dashboard has
/// series on it, and only the consumers nobody thought about are missing. One constructor
/// makes "every pool reports the same way" a property of the code rather than of four edits
/// staying in agreement.
///
/// Logging and metrics are composed here rather than merged into one type because their
/// policies genuinely differ. [`TracingOutboxObserver`] is deliberately SILENT on a healthy
/// pass, since one line per pool per scope per poll interval would bury the lines that
/// matter. The metrics observer must count every pass including the healthy ones, because a
/// counter that skips the healthy case cannot express a rate. Entangling the two would force
/// one of those policies to give.
fn outbox_observer() -> Arc<dyn OutboxObserver> {
    Arc::new(PairObserver::new(
        TracingOutboxObserver,
        MetricsOutboxObserver,
    ))
}

/// Fan every observer hook out to two observers (issue #104).
///
/// Deliberately a pair rather than a `Vec<Arc<dyn OutboxObserver>>`: the composition this
/// binary needs is exactly two, and a list would invite an empty one, which is silence that
/// reads as configuration.
struct PairObserver<A, B> {
    first: A,
    second: B,
}

impl<A, B> PairObserver<A, B> {
    /// Report to `first`, then `second`, for every hook.
    const fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A, B> OutboxObserver for PairObserver<A, B>
where
    A: OutboxObserver,
    B: OutboxObserver,
{
    fn pass_finished(&self, consumer: &str, scope: Scope, stats: &DrainStats) {
        self.first.pass_finished(consumer, scope, stats);
        self.second.pass_finished(consumer, scope, stats);
    }

    fn pass_failed(&self, consumer: &str, scope: Scope, error: &StoreError) {
        self.first.pass_failed(consumer, scope, error);
        self.second.pass_failed(consumer, scope, error);
    }

    fn scopes_unavailable(&self, consumer: &str, error: &StoreError) {
        self.first.scopes_unavailable(consumer, error);
        self.second.scopes_unavailable(consumer, error);
    }
}

/// Count what the outbox pools are doing into the Prometheus registry (issue #104).
///
/// Every series here is labeled by CONSUMER ONLY. The scope is deliberately dropped: a label
/// per tenant on a multi-tenant deployment is an unbounded cardinality time series, which is
/// the standard way to take down a Prometheus instance, and the per-scope numbers already
/// have a home on the authenticated queues API where they can be afforded. The cost of that
/// choice, stated so nobody has to rediscover it: these counters can tell an operator that a
/// consumer is dead-lettering, and cannot tell them which tenant it is dead-lettering for.
/// The log line from [`TracingOutboxObserver`] carries the scope, and is the intended next
/// stop when a counter moves.
struct MetricsOutboxObserver;

impl OutboxObserver for MetricsOutboxObserver {
    fn pass_finished(&self, consumer: &str, _scope: Scope, stats: &DrainStats) {
        let consumer = consumer.to_owned();
        metrics::counter!(
            ironauth_server::metrics::OUTBOX_MESSAGES_CLAIMED_TOTAL,
            "consumer" => consumer.clone()
        )
        .increment(stats.claimed);
        // Emitted even when the count is zero, so the series EXISTS from the first pass. A
        // counter that appears only once it has something to say is indistinguishable from a
        // pool that was never started, which is precisely the condition an operator wants to
        // tell apart.
        for (outcome, count) in [
            ("completed", stats.completed),
            ("retried", stats.retried),
            ("dead_lettered", stats.dead_lettered),
            ("lease_lost", stats.lease_lost),
        ] {
            metrics::counter!(
                ironauth_server::metrics::OUTBOX_MESSAGES_TOTAL,
                "consumer" => consumer.clone(),
                "outcome" => outcome
            )
            .increment(count);
        }
    }

    fn pass_failed(&self, consumer: &str, _scope: Scope, _error: &StoreError) {
        metrics::counter!(
            ironauth_server::metrics::OUTBOX_PASS_FAILURES_TOTAL,
            "consumer" => consumer.to_owned(),
            "kind" => "drain"
        )
        .increment(1);
    }

    fn scopes_unavailable(&self, consumer: &str, _error: &StoreError) {
        // A separate `kind` rather than the same counter, because the two failures are not
        // the same size: a drain failure lost one scope's pass, and this lost EVERY scope's.
        metrics::counter!(
            ironauth_server::metrics::OUTBOX_PASS_FAILURES_TOTAL,
            "consumer" => consumer.to_owned(),
            "kind" => "scopes"
        )
        .increment(1);
    }
}

/// Report what the outbox pools are doing, from the side of the process that has a logging
/// framework (issue #104).
///
/// ironauth-store deliberately takes no tracing dependency, and its pool loop used to
/// discard every outcome with a `let _ =`. That made a dead-lettered logout, a drain pass
/// failing on a persistence fault, and a scope sweep that never returned a scope all
/// invisible: the pool reported full health throughout, because its workers were alive and
/// looping. This is the binary half of the seam that ends that.
struct TracingOutboxObserver;

/// How loud one finished drain pass deserves to be (issue #104). Split out from the log
/// call so the decision is a value a test can assert on rather than a side effect it would
/// have to capture a subscriber to observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassSeverity {
    /// Nothing an operator needs to see: work happened, or none was due.
    Quiet,
    /// Work was GIVEN UP ON. A dead letter never happens unless somebody replays it, and
    /// for the fan-out consumer one of them is an entire session's worth of logouts.
    Alert,
}

/// The severity of one finished pass.
fn pass_severity(stats: &DrainStats) -> PassSeverity {
    if stats.dead_lettered > 0 {
        PassSeverity::Alert
    } else {
        PassSeverity::Quiet
    }
}

impl OutboxObserver for TracingOutboxObserver {
    fn pass_finished(&self, consumer: &str, scope: Scope, stats: &DrainStats) {
        match pass_severity(stats) {
            // Deliberately not logged at all: one line per pool per scope per poll
            // interval is a log the useful lines below would be lost in.
            PassSeverity::Quiet => {}
            PassSeverity::Alert => tracing::error!(
                consumer,
                tenant = %scope.tenant(),
                environment = %scope.environment(),
                dead_lettered = stats.dead_lettered,
                claimed = stats.claimed,
                "outbox messages were DEAD-LETTERED and will not be retried; replay them"
            ),
        }
    }

    fn pass_failed(&self, consumer: &str, scope: Scope, error: &StoreError) {
        tracing::warn!(
            consumer,
            tenant = %scope.tenant(),
            environment = %scope.environment(),
            %error,
            "outbox drain pass failed for a scope; the work is still queued and will be retried"
        );
    }

    fn scopes_unavailable(&self, consumer: &str, error: &StoreError) {
        tracing::warn!(
            consumer,
            %error,
            "outbox worker could not enumerate scopes; NO scope was drained this pass"
        );
    }
}

/// Map the shared `[outbox]` section to the retention windows the sweeper runs to
/// (issue #104, PR 3), in ONE place, for the same reason [`outbox_worker_settings`] exists.
///
/// The one translation worth naming is `dead_letter_retention_secs`: `0` in configuration
/// means NEVER, and it becomes `None` here rather than a zero-second window. A zero
/// duration would mean "every dead letter is older than the window", which is the exact
/// inversion of the shipped posture, so the sentinel is resolved at this single seam
/// instead of at whatever call site reads the number.
fn outbox_retention_settings(outbox: &OutboxConfig) -> RetentionSettings {
    RetentionSettings {
        completed_retention: std::time::Duration::from_secs(outbox.completed_retention_secs),
        dead_letter_retention: match outbox.dead_letter_retention_secs {
            0 => None,
            secs => Some(std::time::Duration::from_secs(secs)),
        },
        batch: i64::from(outbox.reap_batch),
        interval: std::time::Duration::from_secs(outbox.reap_interval_secs),
    }
}

/// Report what the retention sweeper is doing (issue #104, PR 3), the counterpart to
/// [`TracingOutboxObserver`] for the reaper.
struct TracingRetentionObserver;

impl RetentionObserver for TracingRetentionObserver {
    fn pass_finished(&self, scope: Scope, consumer: &str, stats: &RetentionStats) {
        if stats.saturated {
            // The one finished-pass outcome that is loud. A saturated pass removed its
            // whole budget and stopped because it ran out of budget, not out of work, so
            // the table is growing faster than the sweeper is allowed to shrink it. This is
            // the difference between "keeping up" and "falling behind forever", which
            // "removed N rows" alone cannot express.
            tracing::warn!(
                consumer,
                tenant = %scope.tenant(),
                environment = %scope.environment(),
                completed_reaped = stats.completed_reaped,
                dead_letters_reaped = stats.dead_letters_reaped,
                "outbox retention pass hit its batch bound; the backlog is larger than one \
                 pass can remove, so raise outbox.reap_batch or shorten outbox.reap_interval_secs"
            );
        } else if stats.completed_reaped > 0 || stats.dead_letters_reaped > 0 {
            tracing::debug!(
                consumer,
                tenant = %scope.tenant(),
                environment = %scope.environment(),
                completed_reaped = stats.completed_reaped,
                dead_letters_reaped = stats.dead_letters_reaped,
                "outbox retention pass removed retired messages"
            );
        } else {
            // A pass that removed NOTHING still says so, and this branch is the reason the
            // `if` above is not the whole method. Without it a healthy idle reaper and a
            // dead one produce identical output (none), so the only way to tell a working
            // deployment from one whose sweeper task unwound an hour ago would be to look
            // at the table. At debug rather than info because on a healthy deployment this
            // is every consumer of every scope every hour, and it is the line an operator
            // turns on precisely when they are asking "is it running at all".
            tracing::debug!(
                consumer,
                tenant = %scope.tenant(),
                environment = %scope.environment(),
                "outbox retention pass found nothing to remove"
            );
        }
    }

    fn pass_failed(&self, scope: Scope, consumer: Option<&str>, error: &StoreError) {
        tracing::warn!(
            consumer = consumer.unwrap_or("<scope>"),
            tenant = %scope.tenant(),
            environment = %scope.environment(),
            %error,
            "outbox retention pass failed; the table keeps growing until this is resolved. \
             A permission failure here means the control-plane role is missing the DELETE \
             grant migration 0102 adds"
        );
    }

    fn scopes_unavailable(&self, error: &StoreError) {
        tracing::warn!(
            %error,
            "outbox retention could not enumerate scopes; NO scope was reaped this pass"
        );
    }
}

/// Spawn ONE pool per registered consumer (issue #104), each with the tuning its own name
/// selects, all sweeping the same scopes and reporting to the same observer.
///
/// This is the loop the whole framework exists to be driven by, so it is a named function
/// with the store, the scopes and the observer as arguments rather than a closure buried in
/// `spawn_backchannel_logout_pools`: that is what lets a test in this crate drive the REAL
/// seam against a real database, instead of re-implementing it and asserting about the copy.
/// Measured, with `.take(1)` dropped into this iterator so that the binary spawns the
/// fan-out pool and never the delivery pool: with `outbox_wiring_tests` SKIPPED, all 17
/// remaining tests of this crate pass and
/// `cargo clippy --workspace --all-targets --all-features -- -D warnings` is clean. A build
/// that fans every ended session out into per-relying-party messages and then POSTs not one
/// Logout Token passes the whole local gate. With the suite present the same mutation turns
/// `every_registered_consumer_gets_a_pool_that_actually_drains_it` RED.
///
/// It covers the registry EXHAUSTIVELY by construction, and `every_registered_consumer_gets_a_pool`
/// is the assertion that it still does.
fn spawn_consumer_pools(
    consumers: &ConsumerRegistry,
    store: &Store,
    env: &Env,
    outbox: &OutboxConfig,
    scopes: &Arc<dyn ScopeSource>,
    observer: &Arc<dyn OutboxObserver>,
) -> Vec<OutboxWorkerPool> {
    // Resolve the wake-up backbone ONCE, not per consumer: one broker connection pair is
    // shared by every pool in the process, and a broker that is unreachable is resolved to
    // Postgres-only here rather than being retried per pool.
    let backbone = resolve_outbox_backbone(outbox);
    consumers
        .all()
        .into_iter()
        .map(|consumer| {
            let settings = outbox_worker_settings(outbox, consumer.name());
            let worker = OutboxWorker::new(store.clone(), env.clone(), consumer, settings);
            OutboxWorkerPool::spawn_with_backbone(&worker, scopes, observer, &backbone)
        })
        .collect()
}

/// Resolve the configured outbox wake-up backbone (issue #104), falling back to
/// [`PollOnly`] whenever a broker is not configured, not compiled in, or not reachable.
///
/// # An unreachable broker is not a startup failure
///
/// This is the whole point of an OPTIONAL backbone: its absence is a supported mode, so a
/// broker that is down must not stop the process from serving. It degrades to the
/// Postgres-only drain, which is slower by the poll interval and identical in every other
/// respect, and it says so once at boot rather than silently.
///
/// The alternative (refusing to start) would make adding a latency optimisation a new way
/// for the whole deployment to be down, which is a bad trade for something that cannot
/// affect correctness.
fn resolve_outbox_backbone(outbox: &OutboxConfig) -> Arc<dyn OutboxBackbone> {
    let Some(addr) = outbox.ironbus_addr.as_deref().filter(|a| !a.is_empty()) else {
        return Arc::new(PollOnly);
    };
    #[cfg(feature = "ironbus")]
    {
        match ironauth_store::outbox_ironbus::IronBusBackbone::connect(addr) {
            Ok(backbone) => {
                tracing::info!(%addr, "outbox wake-up backbone: IronBus");
                Arc::new(backbone)
            }
            Err(error) => {
                tracing::warn!(
                    %addr,
                    %error,
                    "outbox IronBus backbone unreachable; draining on the poll interval"
                );
                Arc::new(PollOnly)
            }
        }
    }
    #[cfg(not(feature = "ironbus"))]
    {
        tracing::warn!(
            %addr,
            "outbox.ironbus_addr is set but this build has no `ironbus` feature; \
             draining on the poll interval"
        );
        Arc::new(PollOnly)
    }
}

/// Spawn the outbox RETENTION sweeper (issue #104, PR 3), reaping the terminal tail of
/// `outbox_messages` on a cadence.
///
/// A named function with the store, the scopes and the observer as ARGUMENTS, for the
/// reason [`spawn_consumer_pools`] states about itself: it is what lets a test in this
/// crate drive the REAL seam against a real database instead of re-implementing it and
/// asserting about the copy.
///
/// `store` must be a CONTROL-plane store. `0102_outbox_retention.sql` grants DELETE on
/// `outbox_messages` to `ironauth_control` alone, because `ironauth_app` holds the
/// column-scoped UPDATE that writes `dead_lettered_at` and one role must not be able to
/// both give up on a message and erase the record of having given up.
///
/// # This is NOT gated on the consumer pools, and why that is right
///
/// The pools are spawned behind `oidc.enabled && oidc.backchannel_logout_enabled`, both of
/// which default FALSE. The outbox is a GENERIC substrate: the next consumer to register
/// (webhook delivery, a SIEM sink, a migration job) will run behind a different switch
/// again, and retention must not have to be re-wired for each one. A sweeper on the logout
/// pools' path would be one feature switch away from being present, reviewed, tested and
/// inert. `retention_is_not_gated_on_the_back_channel_logout_switch` is what turns RED if
/// such a gate is added.
///
/// What this does NOT buy, because an earlier draft of this comment claimed it did: it does
/// not make a default deployment's `outbox_messages` stop growing. Nothing but a consumer
/// writes a terminal column, both reap predicates key on terminal columns, and they must,
/// so with the logout switch off this sweeper removes zero rows forever. It bounds the
/// deployment where consumers DO run, which is the `1 + N_relying_parties` volume PR 2
/// introduced. The rest is a producer-side owner decision, recorded in
/// `docs/design/RETENTION.md`.
fn spawn_retention_sweeper(
    store: &Store,
    env: &Env,
    outbox: &OutboxConfig,
    scopes: &Arc<dyn ScopeSource>,
    observer: &Arc<dyn RetentionObserver>,
) -> RetentionSweeper {
    let reaper = OutboxReaper::new(
        store.clone(),
        env.clone(),
        outbox_retention_settings(outbox),
    );
    RetentionSweeper::spawn(&reaper, scopes, observer)
}

/// What the outbox retention sweeper (issue #104, PR 3) needs to run, captured before
/// `config` moves into the server.
struct RetentionSweeperInputs {
    /// The shared `[outbox]` section, whose retention half this sweeper reads.
    outbox: OutboxConfig,
    /// The control-plane DSN. The sweeper both enumerates scopes on it and DELETEs through
    /// it, because `ironauth_control` is the only role migration 0102 grants DELETE on
    /// `outbox_messages` to. [`None`] disables retention entirely.
    control_dsn: Option<String>,
    /// The environment seam (deterministic clock and entropy).
    env: Env,
}

/// Capture the retention sweeper's inputs from config (issue #104, PR 3), or `None` when
/// `outbox.reap_enabled` is off.
///
/// The ONLY switch consulted here is `outbox.reap_enabled`. In particular this does NOT
/// look at `oidc.enabled` or `oidc.backchannel_logout_enabled`, unlike
/// [`backchannel_worker_inputs`] beside it, and the asymmetry is deliberate rather than an
/// oversight: those two gate ONE consumer of a generic queue, and the reaper's job spans
/// every consumer that ever had rows in it, including consumers this binary does not run.
///
/// Returning `Some` is not the same as a sweeper running. The control-plane DSN is resolved
/// here but only CONSUMED in [`start_retention_sweeper`], which refuses (at error) when
/// there is none, and there is none in a default deployment. See that function.
fn retention_sweeper_inputs(config: &Config, env: &Env) -> Option<RetentionSweeperInputs> {
    if !config.outbox.reap_enabled {
        return None;
    }
    Some(RetentionSweeperInputs {
        outbox: config.outbox.clone(),
        control_dsn: select_control_dsn(config),
        env: env.clone(),
    })
}

/// Start the outbox retention sweeper (issue #104, PR 3), returning the RUNNING sweeper so
/// the caller can shut it down, or `None` when it could not be started.
///
/// Every early return says, at error, WHAT is not running and WHY, matching the specificity
/// [`spawn_backchannel_logout_pools`] uses for its own. A silent absence here is the worst
/// outcome available: the queue keeps growing, nothing fails, and the first symptom is a
/// disk.
async fn start_retention_sweeper(inputs: RetentionSweeperInputs) -> Option<RetentionSweeper> {
    let RetentionSweeperInputs {
        outbox,
        control_dsn,
        env,
    } = inputs;

    let Some(control_dsn) = control_dsn else {
        tracing::error!(
            "outbox retention NOT running: no control-plane DSN (set \
             admin.control_database_url, or run in dev_mode). Only the ironauth_control \
             role is granted DELETE on outbox_messages, so with no control-plane \
             connection NOTHING reaps the queue and outbox_messages grows without bound: \
             every ended session enqueues one message plus one per participating relying \
             party, and no other path removes any of them."
        );
        return None;
    };

    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(
                %error,
                "outbox retention NOT running: control-plane connect failed. \
                 outbox_messages will grow without bound until this is resolved."
            );
            return None;
        }
    };

    // ONE store for both halves, deliberately: the scope enumeration reads `environments`,
    // which only the control role may read, and the delete needs the control role's 0102
    // grant. A second connection would be a second role to get wrong.
    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store.clone()));
    let observer: Arc<dyn RetentionObserver> = Arc::new(TracingRetentionObserver);
    let sweeper = spawn_retention_sweeper(&control_store, &env, &outbox, &scopes, &observer);

    tracing::info!(
        completed_retention_secs = outbox.completed_retention_secs,
        dead_letter_retention_secs = outbox.dead_letter_retention_secs,
        reap_batch = outbox.reap_batch,
        reap_interval_secs = outbox.reap_interval_secs,
        "outbox retention started; a dead_letter_retention_secs of 0 means dead letters \
         are kept FOREVER"
    );
    Some(sweeper)
}

/// A running outbox metrics sampler (issue #104), and the means to stop it.
struct MetricsSampler {
    /// Flipped to stop the loop at its next wake or mid-sleep, whichever comes first.
    stop: tokio::sync::watch::Sender<bool>,
    /// The sampling task, awaited by [`shutdown`](MetricsSampler::shutdown).
    task: tokio::task::JoinHandle<()>,
}

impl MetricsSampler {
    /// Stop sampling and wait for the in-flight pass.
    ///
    /// Nothing is lost by stopping part way through a pass: a gauge holds its last written
    /// value, and the process is going away regardless.
    async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// What the outbox metrics sampler needs to run, captured before `config` moves into the
/// server.
struct MetricsSamplerInputs {
    /// The shared `[outbox]` section, for the sampling interval and the lease width the
    /// depth read needs to tell an in-flight message from a reclaimable one.
    outbox: OutboxConfig,
    /// The control-plane DSN. As with the reaper, ONE store serves both halves: scope
    /// enumeration reads `environments`, which only the control role may read, and 0099
    /// grants that same role SELECT on `outbox_messages`. [`None`] means no gauges.
    control_dsn: Option<String>,
    /// The environment seam, whose clock turns a due time into an age.
    env: Env,
}

/// Capture the metrics sampler's inputs from config (issue #104).
///
/// There is no switch to consult. Unlike the reaper beside it, this has no `enabled` flag:
/// sampling costs a bounded read and produces the only queue-depth signal that leaves the
/// process, and an operator who wants less of it lengthens
/// `outbox.metrics_sample_interval_secs`. A boolean would add a state in which the gauges
/// are absent, and an absent gauge is indistinguishable from a dead process to whatever
/// alerts on it.
fn metrics_sampler_inputs(config: &Config, env: &Env) -> MetricsSamplerInputs {
    MetricsSamplerInputs {
        outbox: config.outbox.clone(),
        control_dsn: select_control_dsn(config),
        env: env.clone(),
    }
}

/// Start the outbox metrics sampler (issue #104), or return [`None`] with the reason logged.
///
/// This is the reader that `OutboxDepth` was built for and did not have. The counters on
/// [`MetricsOutboxObserver`] say what the workers DID; these gauges say what is still
/// waiting, which is the half no amount of counting can reconstruct: a queue being drained
/// steadily and a queue falling behind produce identical completion counts.
async fn start_metrics_sampler(inputs: MetricsSamplerInputs) -> Option<MetricsSampler> {
    let MetricsSamplerInputs {
        outbox,
        control_dsn,
        env,
    } = inputs;

    let Some(control_dsn) = control_dsn else {
        tracing::warn!(
            "outbox depth and lag gauges NOT running: no control-plane DSN (set \
             admin.control_database_url, or run in dev_mode). Scope enumeration reads \
             `environments`, which only the ironauth_control role may read. The outbox \
             itself is unaffected and nothing is lost; what is missing is the only signal \
             that distinguishes a queue being drained from a queue falling behind."
        );
        return None;
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::warn!(
                %error,
                "outbox depth and lag gauges NOT running: control-plane connect failed"
            );
            return None;
        }
    };

    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store.clone()));
    let interval = std::time::Duration::from_secs(outbox.metrics_sample_interval_secs);
    let lease = std::time::Duration::from_secs(outbox.visibility_timeout_secs);
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        // Every consumer name this process has EVER seen carrying a message. It only grows,
        // and that is the point: a consumer that drains to empty keeps reporting zero
        // instead of dropping off the exposition. `consumers_in_scope` answers "who has rows
        // here", so without this set an idle consumer and an unstarted one look identical to
        // an alert, which is the exact confusion the gauge exists to prevent.
        //
        // What it cannot do, stated because the ceiling is real: a consumer that has never
        // enqueued a single message in any scope has no name to learn, so it reports nothing
        // until its first message. The queue is the only source of names here, deliberately,
        // because the four pool seams register their consumers separately and a registry
        // threaded through all of them would be a fifth thing to keep in agreement.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        loop {
            let sampled = sample_outbox_depth(&control_store, &env, &scopes, lease).await;
            match sampled {
                Ok(totals) => {
                    seen.extend(totals.keys().cloned());
                    publish_outbox_depth(&seen, &totals);
                }
                Err(error) => tracing::warn!(
                    %error,
                    "outbox depth sample failed; the gauges hold their previous values"
                ),
            }
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                _ = stopped.changed() => break,
            }
            if *stopped.borrow() {
                break;
            }
        }
    });

    tracing::info!(
        metrics_sample_interval_secs = outbox.metrics_sample_interval_secs,
        "outbox depth and lag gauges started"
    );
    Some(MetricsSampler { stop, task })
}

/// The application clock as microseconds since the Unix epoch.
///
/// Time comes from the SEAM, never from the system clock directly, so the age this sampler
/// reports is measured against the same clock that stamped the due time it subtracts.
fn epoch_micros(at: std::time::SystemTime) -> i64 {
    i64::try_from(
        at.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
    )
    .unwrap_or(i64::MAX)
}

/// One consumer's queue position, summed across every scope in one sampling pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DepthTotals {
    /// Messages due and unleased: the backlog a worker would claim right now.
    ready: i64,
    /// Messages held under an unexpired lease.
    in_flight: i64,
    /// Messages whose retry gate is still in the future.
    scheduled: i64,
    /// Messages given up on, which no worker will retry.
    dead_lettered: i64,
    /// The WORST lag across scopes, in seconds, rather than a sum or a mean.
    ///
    /// A sum would grow with the number of tenants and mean nothing; a mean would let one
    /// badly stuck scope disappear behind a thousand healthy ones. The worst case is the
    /// number an operator would act on, and it is the only one of the three that keeps its
    /// meaning as scopes are added.
    oldest_ready_age_secs: i64,
}

/// Read every scope's depth for every consumer with rows in it, folded per consumer.
///
/// Errors from ONE scope abort the pass rather than being skipped, so a partial reading is
/// never published as a whole one: a gauge that silently dropped half the fleet would read
/// as a queue that had drained.
async fn sample_outbox_depth(
    store: &Store,
    env: &Env,
    scopes: &Arc<dyn ScopeSource>,
    lease: std::time::Duration,
) -> Result<BTreeMap<String, DepthTotals>, StoreError> {
    let now_micros = epoch_micros(env.clock().now_utc());
    let mut totals: BTreeMap<String, DepthTotals> = BTreeMap::new();
    for scope in scopes.scopes().await? {
        let queue = store.scoped(scope);
        let queue = queue.outbox();
        for consumer in queue.consumers_in_scope().await? {
            let depth = queue.depth(env, &consumer, lease).await?;
            let entry = totals.entry(consumer).or_default();
            entry.ready += depth.ready;
            entry.in_flight += depth.in_flight;
            entry.scheduled += depth.scheduled;
            entry.dead_lettered += depth.dead_lettered;
            // Saturating and floored at zero: a due time in the FUTURE would be a clock
            // going backwards between the read and this subtraction, and a negative lag is
            // not a thing an operator can act on.
            let age_secs = depth
                .oldest_ready_at_unix_micros
                .map_or(0, |due| (now_micros.saturating_sub(due) / 1_000_000).max(0));
            entry.oldest_ready_age_secs = entry.oldest_ready_age_secs.max(age_secs);
        }
    }
    Ok(totals)
}

/// Write one sampling pass into the gauges, reporting zero for every consumer seen before
/// and absent now.
fn publish_outbox_depth(seen: &BTreeSet<String>, totals: &BTreeMap<String, DepthTotals>) {
    for consumer in seen {
        let totals = totals.get(consumer).copied().unwrap_or_default();
        for (state, value) in [
            ("ready", totals.ready),
            ("in_flight", totals.in_flight),
            ("scheduled", totals.scheduled),
            ("dead_lettered", totals.dead_lettered),
        ] {
            metrics::gauge!(
                ironauth_server::metrics::OUTBOX_DEPTH,
                "consumer" => consumer.clone(),
                "state" => state
            )
            .set(as_gauge(value));
        }
        metrics::gauge!(
            ironauth_server::metrics::OUTBOX_OLDEST_READY_AGE_SECONDS,
            "consumer" => consumer.clone()
        )
        .set(as_gauge(totals.oldest_ready_age_secs));
    }
}

/// A queue count as a gauge value.
///
/// Prometheus gauges are `f64`, and every value here is a row count or a whole number of
/// seconds, so the conversion is exact far past any depth a database will hold.
#[expect(
    clippy::cast_precision_loss,
    reason = "row counts and second counts are exact in f64 well past any real queue depth"
)]
fn as_gauge(value: i64) -> f64 {
    value as f64
}

/// Start the OIDC Back-Channel Logout consumers (issue #34) on the generic outbox worker
/// pool (issue #104), returning the RUNNING pools so the caller can shut them down.
///
/// This is the first production wiring of the outbox consumer framework. What is
/// BACK-CHANNEL LOGOUT specific is here: the two logout consumers, the issuer registry and
/// the SSRF-hardened sender they need, and the two stores. What is GENERIC is deliberately
/// not, so the second subsystem to arrive extends it rather than copying it:
/// [`outbox_worker_settings`] maps the configuration section, [`spawn_consumer_pools`]
/// turns a [`ConsumerRegistry`] into one running pool each, [`ControlPlaneScopes`] resolves
/// the scopes, and [`TracingOutboxObserver`] is what makes any of it visible.
///
/// TWO consumers, and the split is a safety property rather than a decomposition
/// preference. [`SessionEndedExplodeConsumer`] turns one ended session into one message
/// per participating relying party; [`BackChannelLogoutConsumer`] delivers exactly one of
/// them. Fusing them would give every RP of a session a shared attempts counter, so one
/// dead RP would dead-letter the whole session's logout, including the RPs that would have
/// succeeded.
///
/// Scope enumeration is a CONTROL-plane read (the data-plane role cannot see the non-RLS
/// `environments` table), so this needs both a data-plane store (to drain, resolve and
/// sign) and a control-plane store (to enumerate). Any failure to connect or a missing
/// control DSN is logged and NOTHING is started; the rest of the server runs unaffected
/// and the queue is durable, so the work waits rather than being lost.
///
/// Returns an empty vector on every early return, which the caller shuts down as a no-op.
async fn spawn_backchannel_logout_pools(
    inputs: BackChannelWorkerInputs,
    issuer_base: String,
) -> Vec<OutboxWorkerPool> {
    let BackChannelWorkerInputs {
        oidc,
        outbox,
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
        return Vec::new();
    };

    let data_store = match Store::connect(&data_plane_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "back-channel logout worker not started: data-plane connect failed");
            return Vec::new();
        }
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "back-channel logout worker not started: control-plane connect failed");
            return Vec::new();
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
            return Vec::new();
        }
    };

    let mut consumers = ConsumerRegistry::new();
    // A duplicate name is refused by the registry, and refusing to start is the right
    // answer to it: two consumers under one name means one subsystem's messages vanish
    // into another's handler. It cannot happen with these two fixed registrations, so it
    // is reported and treated as fatal for the pools rather than silently tolerated.
    for consumer in [
        Arc::new(SessionEndedExplodeConsumer::new(data_store.clone())) as Arc<dyn OutboxConsumer>,
        Arc::new(BackChannelLogoutConsumer::new(
            Arc::clone(&registry),
            sender,
        )) as Arc<dyn OutboxConsumer>,
    ] {
        if let Err(error) = consumers.register(consumer) {
            tracing::error!(%error, "back-channel logout worker not started: duplicate consumer name");
            return Vec::new();
        }
    }

    // ONE mapping of the `[outbox]` section for every pool, in `outbox_worker_settings`,
    // so two pools can never be handed different leases from one configuration.
    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store));
    let observer = outbox_observer();
    let pools = spawn_consumer_pools(&consumers, &data_store, &env, &outbox, &scopes, &observer);

    tracing::info!(
        consumers = ?consumers.names(),
        pools = pools.len(),
        "back-channel logout delivery started on the outbox consumer pools"
    );
    pools
}

/// Start the webhook delivery consumer (issue #105) on the generic outbox worker pool,
/// returning the RUNNING pools so the caller can shut them down.
///
/// The SECOND production wiring of the consumer framework, and it deliberately extends the
/// generic parts rather than copying them: [`spawn_consumer_pools`], [`ControlPlaneScopes`]
/// and [`TracingOutboxObserver`] are shared with back-channel logout, and only the
/// consumer, its sender and its master key are webhook specific.
///
/// It is a SEPARATE function from [`spawn_backchannel_logout_pools`] rather than another
/// registration inside it, because the two run behind different switches. Registering the
/// webhook consumer there would have made webhook delivery require the OIDC provider and
/// its logout posture switch, which are unrelated to it.
///
/// Every early return is logged and starts NOTHING; the rest of the server runs unaffected
/// and the queue is durable, so the work waits rather than being lost.
async fn spawn_webhook_delivery_pools(inputs: WebhookDeliveryInputs) -> Vec<OutboxWorkerPool> {
    let WebhookDeliveryInputs {
        webhooks,
        outbox,
        data_plane_dsn,
        control_dsn,
        master,
        env,
    } = inputs;

    let Some(control_dsn) = control_dsn else {
        tracing::error!(
            "webhook delivery worker not started: no control-plane DSN to enumerate scopes \
             (set admin.control_database_url, or run in dev_mode). The delivery queue is \
             durable, so nothing is lost; enable the control plane to drain it."
        );
        return Vec::new();
    };
    // Refusing to start beats starting a worker that cannot sign. Without a master key
    // every endpoint read fails at the unseal, so each message would burn its whole
    // attempt budget and dead-letter, turning a missing configuration value into
    // permanently discarded deliveries.
    let Some(master) = master else {
        tracing::error!(
            "webhook delivery worker not started: database.master_key is unset, so an \
             endpoint's sealed signing secret cannot be opened and no delivery could be \
             signed. The queue is durable; set database.master_key to drain it."
        );
        return Vec::new();
    };

    let data_store = match Store::connect(&data_plane_dsn).await {
        Ok(store) => store.with_master_key(master),
        Err(error) => {
            tracing::error!(%error, "webhook delivery worker not started: data-plane connect failed");
            return Vec::new();
        }
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "webhook delivery worker not started: control-plane connect failed");
            return Vec::new();
        }
    };

    let timeout = std::time::Duration::from_secs(webhooks.delivery_timeout_secs);
    let sender = match FetchWebhookSender::with_timeout(timeout) {
        Ok(sender) => sender,
        Err(error) => {
            tracing::error!(%error, "webhook delivery worker not started: fetcher setup failed");
            return Vec::new();
        }
    };

    // TWO consumers, and the split is a privilege property rather than a decomposition
    // preference. Delivery signs and POSTs; replay revives dead letters an operator asked
    // for. The second exists at all because the management plane holds no UPDATE on the
    // queue (migration 0099), so its replay request has to be EXECUTED by the plane that
    // does, which is this one.
    let mut consumers = ConsumerRegistry::new();
    for consumer in [
        Arc::new(WebhookDeliveryConsumer::with_auto_disable(
            data_store.clone(),
            sender,
            webhooks.auto_disable_after_consecutive_failures,
        )) as Arc<dyn OutboxConsumer>,
        Arc::new(WebhookReplayConsumer::new(data_store.clone())) as Arc<dyn OutboxConsumer>,
        // The FAN-OUT (issues #105, #108): one domain event becomes one delivery per
        // active endpoint. It runs behind the same switch as delivery because a fan-out
        // with nothing to drain its output would only build a backlog.
        Arc::new(WebhookFanoutConsumer::new(data_store.clone())) as Arc<dyn OutboxConsumer>,
    ] {
        if let Err(error) = consumers.register(consumer) {
            tracing::error!(%error, "webhook delivery worker not started: duplicate consumer name");
            return Vec::new();
        }
    }

    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store));
    let observer = outbox_observer();
    let pools = spawn_consumer_pools(&consumers, &data_store, &env, &outbox, &scopes, &observer);

    tracing::info!(
        consumers = ?consumers.names(),
        pools = pools.len(),
        "webhook delivery started on the outbox consumer pools"
    );
    pools
}

/// Start the trait migration worker (issue #53) on the generic outbox worker pool.
///
/// The THIRD production consumer of the #104 framework, and the one that issue named
/// explicitly ("migration jobs"). It extends the generic parts rather than copying them:
/// [`spawn_consumer_pools`], [`ControlPlaneScopes`] and [`TracingOutboxObserver`] are
/// shared, and only the consumer and its batch size are trait specific.
///
/// Every early return is logged and starts NOTHING. A job's progress lives in its own row
/// and its next batch lives on a durable queue, so a job created while no worker runs is
/// picked up unchanged whenever one starts.
async fn spawn_trait_migration_pools(inputs: TraitMigrationInputs) -> Vec<OutboxWorkerPool> {
    let TraitMigrationInputs {
        batch_size,
        outbox,
        data_plane_dsn,
        control_dsn,
        master,
        env,
    } = inputs;

    let Some(control_dsn) = control_dsn else {
        tracing::error!(
            "trait migration worker not started: no control-plane DSN to enumerate scopes \
             (set admin.control_database_url, or run in dev_mode). Jobs and their batches \
             are durable, so nothing is lost; enable the control plane to run them."
        );
        return Vec::new();
    };
    // Refusing to start beats starting a worker that cannot read a trait. Without a master
    // key every batch fails at the unseal, so each message would burn its attempt budget
    // and dead-letter, turning a missing configuration value into a job that can never run.
    let Some(master) = master else {
        tracing::error!(
            "trait migration worker not started: database.master_key is unset, so sealed \
             identity traits cannot be read. Jobs are durable; set database.master_key."
        );
        return Vec::new();
    };

    let data_store = match Store::connect(&data_plane_dsn).await {
        Ok(store) => store.with_master_key(master),
        Err(error) => {
            tracing::error!(%error, "trait migration worker not started: data-plane connect failed");
            return Vec::new();
        }
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "trait migration worker not started: control-plane connect failed");
            return Vec::new();
        }
    };

    let mut consumers = ConsumerRegistry::new();
    if let Err(error) = consumers.register(Arc::new(TraitMigrationConsumer::new(
        data_store.clone(),
        batch_size,
    )) as Arc<dyn OutboxConsumer>)
    {
        tracing::error!(%error, "trait migration worker not started: duplicate consumer name");
        return Vec::new();
    }

    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store));
    let observer = outbox_observer();
    let pools = spawn_consumer_pools(&consumers, &data_store, &env, &outbox, &scopes, &observer);

    tracing::info!(
        consumers = ?consumers.names(),
        pools = pools.len(),
        batch_size,
        "trait migration jobs started on the outbox consumer pools"
    );
    pools
}

/// Publishes each shipping pass as gauges.
///
/// Aggregated to (sink type, status) HERE rather than in the shipper, because that is the
/// step that keeps cardinality bounded and it belongs next to the exporter. A gauge per
/// stream id would be unbounded on a multi-tenant deployment.
struct MetricsShipperObserver;

impl LogShipperObserver for MetricsShipperObserver {
    fn observed(&self, streams: &[StreamObservation]) {
        use std::collections::BTreeMap;

        let mut by_state: BTreeMap<(&'static str, &'static str), f64> = BTreeMap::new();
        let mut dead_letters: BTreeMap<&'static str, f64> = BTreeMap::new();
        for stream in streams {
            let sink = stream.sink_type.as_str();
            let status = match stream.status {
                ironauth_store::log_stream::StreamStatus::Healthy => "healthy",
                ironauth_store::log_stream::StreamStatus::Degraded => "degraded",
                ironauth_store::log_stream::StreamStatus::Failing => "failing",
            };
            *by_state.entry((sink, status)).or_default() += 1.0;
            #[expect(
                clippy::cast_precision_loss,
                reason = "a dead-letter count is far below the f64 integer range, and a \
                          gauge is f64"
            )]
            let outstanding = stream.outstanding_dead_letters as f64;
            *dead_letters.entry(sink).or_default() += outstanding;
        }
        for ((sink, status), count) in by_state {
            metrics::gauge!(
                ironauth_server::metrics::LOG_STREAMS,
                "sink_type" => sink,
                "status" => status,
            )
            .set(count);
        }
        for (sink, count) in dead_letters {
            metrics::gauge!(
                ironauth_server::metrics::LOG_STREAM_DEAD_LETTERS,
                "sink_type" => sink,
            )
            .set(count);
        }
    }
}

/// What the SIEM log stream shipper (issue #110) needs, captured before `config` moves
/// into the server.
struct LogShipperInputs {
    /// The `[log_streams]` section.
    log_streams: ironauth_config::LogStreamsConfig,
    /// The DATA-plane DSN. The shipper reads audit rows and advances a stream's cursor
    /// and health, which is exactly the column-scoped grant 0137 gives `ironauth_app`.
    data_dsn: Option<String>,
    /// The CONTROL-plane DSN, used only to enumerate scopes: listing environments is a
    /// control-plane read the data role cannot do.
    control_dsn: Option<String>,
    /// The environment seam (deterministic clock and entropy).
    env: Env,
}

/// Capture the shipper's inputs, or `None` when shipping is switched off.
fn log_shipper_inputs(config: &Config, env: &Env) -> Option<LogShipperInputs> {
    if !config.log_streams.shipping_enabled {
        return None;
    }
    Some(LogShipperInputs {
        log_streams: config.log_streams.clone(),
        data_dsn: Some(config.database.url.expose().to_owned()),
        control_dsn: select_control_dsn(config),
        env: env.clone(),
    })
}

/// Start the SIEM log stream shipper, or `None` when it could not be started.
///
/// Every early return says WHAT is not running and WHY. A silent absence here means a
/// configured export quietly stops advancing, and the operator's first symptom is a gap in
/// their SIEM rather than an error anywhere.
async fn start_log_shipper(inputs: LogShipperInputs) -> Option<LogShipper> {
    let LogShipperInputs {
        log_streams,
        data_dsn,
        control_dsn,
        env,
    } = inputs;

    let (Some(data_dsn), Some(control_dsn)) = (data_dsn, control_dsn) else {
        tracing::error!(
            "log stream shipping NOT running: it needs BOTH a data-plane DSN (to read \
             audit rows and advance a stream's cursor) and a control-plane DSN (to \
             enumerate scopes, which only the control role may read). Configured streams \
             will not advance."
        );
        return None;
    };
    let (Ok(data_store), Ok(control_store)) = (
        Store::connect(&data_dsn).await,
        Store::connect(&control_dsn).await,
    ) else {
        tracing::error!("log stream shipping NOT running: a database connect failed");
        return None;
    };
    let fetcher = match ironauth_fetch::Fetcher::new(ironauth_fetch::FetchLimits::default()) {
        Ok(fetcher) => Arc::new(fetcher),
        Err(error) => {
            tracing::error!(%error, "log stream shipping NOT running: TLS setup failed");
            return None;
        }
    };

    // Every sink this build implements. A stream configured for one that is absent
    // records that it cannot ship rather than failing silently.
    let sinks: Vec<Arc<dyn LogSink>> = vec![
        Arc::new(HttpLogSink::new(Arc::clone(&fetcher))),
        Arc::new(DatadogSink::new(Arc::clone(&fetcher))),
        Arc::new(SplunkHecSink::new(Arc::clone(&fetcher))),
        Arc::new(S3LogSink::new(fetcher, env.clone())),
    ];
    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store));
    let observer: Arc<dyn LogShipperObserver> = Arc::new(MetricsShipperObserver);
    let shipper = LogShipper::spawn(
        data_store,
        env,
        scopes,
        sinks,
        observer,
        std::time::Duration::from_secs(log_streams.interval_secs),
    );
    tracing::info!(
        interval_secs = log_streams.interval_secs,
        "SIEM log stream shipping started"
    );
    Some(shipper)
}

/// What the audit retention sweeper (issue #109) needs, captured before `config` moves
/// into the server.
struct AuditRetentionInputs {
    /// The `[audit_retention]` section, whose two windows this sweeper runs to.
    audit: ironauth_config::AuditRetentionConfig,
    /// The CONTROL-plane DSN, used ONLY to enumerate scopes: listing environments is a
    /// control-plane read and the retention role cannot do it.
    control_dsn: Option<String>,
    /// The RETENTION role's DSN, used only to delete. Separate from the control DSN on
    /// purpose: see migration 0136. A role that can both write and remove an audit row
    /// could erase one and write a replacement.
    retention_dsn: Option<String>,
    /// The environment seam (deterministic clock and entropy).
    env: Env,
}

/// Capture the audit retention sweeper's inputs, or `None` when it is switched off.
fn audit_retention_inputs(config: &Config, env: &Env) -> Option<AuditRetentionInputs> {
    if !config.audit_retention.enabled {
        return None;
    }
    let retention_dsn = match &config.audit_retention.database_url {
        Some(secret) => match secret.resolve() {
            Ok(dsn) => Some(dsn.expose().to_owned()),
            Err(error) => {
                tracing::error!(
                    %error,
                    "audit retention NOT running: cannot resolve \
                     audit_retention.database_url"
                );
                None
            }
        },
        None => None,
    };
    Some(AuditRetentionInputs {
        audit: config.audit_retention.clone(),
        control_dsn: select_control_dsn(config),
        retention_dsn,
        env: env.clone(),
    })
}

/// Start the audit retention sweeper, returning the RUNNING sweeper so the caller can shut
/// it down, or `None` when it could not be started.
///
/// Every early return says WHAT is not running and WHY, because the failure this guards
/// against is a silent one: nothing errors, the audit tables simply keep growing, and the
/// first symptom is a disk.
async fn start_audit_retention_sweeper(
    inputs: AuditRetentionInputs,
) -> Option<AuditRetentionSweeper> {
    let AuditRetentionInputs {
        audit,
        control_dsn,
        retention_dsn,
        env,
    } = inputs;

    let Some(retention_dsn) = retention_dsn else {
        tracing::error!(
            "audit retention NOT running: no retention DSN (set \
             audit_retention.database_url). Only the ironauth_audit_retention role is \
             granted DELETE on audit_log and audit_chain, and it is deliberately the only \
             role NOT granted INSERT on them, so no other connection can be substituted."
        );
        return None;
    };
    let Some(control_dsn) = control_dsn else {
        tracing::error!(
            "audit retention NOT running: no control-plane DSN (set \
             admin.control_database_url). Scopes are enumerated from `environments`, \
             which only the control role may read."
        );
        return None;
    };
    if audit.admin_action_retention_secs == 0 && audit.authentication_retention_secs == 0 {
        tracing::warn!(
            "audit retention is enabled but BOTH windows are 0, which means keep forever; \
             nothing will be deleted. Set audit_retention.admin_action_retention_secs or \
             audit_retention.authentication_retention_secs to a nonzero number of seconds."
        );
    }

    let retention_store = match Store::connect(&retention_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(%error, "audit retention NOT running: retention connect failed");
            return None;
        }
    };
    let control_store = match Store::connect(&control_dsn).await {
        Ok(store) => store,
        Err(error) => {
            tracing::error!(
                %error,
                "audit retention NOT running: control-plane connect failed, so scopes \
                 cannot be enumerated"
            );
            return None;
        }
    };

    let settings = AuditRetentionSettings {
        admin_action: window(audit.admin_action_retention_secs),
        authentication: window(audit.authentication_retention_secs),
        batch: audit.batch,
    };
    let reaper = AuditReaper::new(retention_store, env, settings);
    let scopes: Arc<dyn ScopeSource> = Arc::new(ControlPlaneScopes::new(control_store));
    let observer: Arc<dyn AuditRetentionObserver> = Arc::new(TracingAuditRetentionObserver);
    let sweeper = AuditRetentionSweeper::spawn(
        reaper,
        scopes,
        observer,
        std::time::Duration::from_secs(audit.interval_secs),
    );
    tracing::info!(
        admin_action_retention_secs = audit.admin_action_retention_secs,
        authentication_retention_secs = audit.authentication_retention_secs,
        batch = audit.batch,
        interval_secs = audit.interval_secs,
        "audit retention started; a window of 0 means that stream is kept FOREVER"
    );
    Some(sweeper)
}

/// A retention window in seconds as a [`Duration`], where `0` is FOREVER rather than
/// "immediately". See the config section for why that direction is the safe one.
fn window(secs: u64) -> Option<std::time::Duration> {
    if secs == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(secs))
    }
}

/// Reports each audit retention pass through `tracing`.
struct TracingAuditRetentionObserver;

impl AuditRetentionObserver for TracingAuditRetentionObserver {
    fn pass_completed(&self, _scope: Scope, stats: AuditReapStats) {
        if stats.admin_action_removed > 0 || stats.authentication_removed > 0 {
            tracing::info!(
                admin_action_removed = stats.admin_action_removed,
                authentication_removed = stats.authentication_removed,
                saturated = stats.saturated,
                "audit retention pass removed rows"
            );
        }
    }

    fn pass_failed(&self, _scope: Scope, error: &StoreError) {
        tracing::error!(
            %error,
            "audit retention pass FAILED for a scope; if this says permission denied, the \
             configured audit_retention.database_url is not the ironauth_audit_retention role"
        );
    }

    fn enumeration_failed(&self, error: &StoreError) {
        tracing::error!(%error, "audit retention could not enumerate scopes");
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
             FORCE row-level-security backstop are NOT enforced. A development database is \
             usually a full-privilege one, so this fallback can also make the management \
             surface look healthier than it is: a route the control role holds no privilege \
             for answers normally here and fails on every deployment that sets this knob \
             (issue #441). Set admin.control_database_url to a least-privilege \
             ironauth_control DSN before production."
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
            None,
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
        .lift(env, &subject, path, None)
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
                // A negative bound is silently dropped by the unsigned conversion at the
                // enforcement read, so the CLI would report success while storing a floor
                // that never gates anything: fail OPEN on a nonsense value (issue #286).
                // Zero is VALID and means always reauthenticate.
                if secs < 0 {
                    return Err("--max-age must be zero or greater (0 means always \
                                reauthenticate)"
                        .to_owned());
                }
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
    // An unrecognized acr becomes an UNRANKED floor, which the enforcement path can only
    // ever match exactly, so the ceremony it gates is unsatisfiable and the operator has
    // locked the client out rather than tightened it (issue #286). Refuse it here, at the
    // one write path, rather than by a database CHECK: this column has held operator-set
    // values since #72 and a CHECK would fail the migration on boot for a deployment that
    // already carries one.
    if let Some(value) = parsed.acr.as_deref() {
        if !is_known_step_up_acr(value) {
            eprintln!(
                "ironauth step-up-policy set: unknown --acr '{value}'; expected one of {}",
                known_step_up_acrs().join(", ")
            );
            return ExitCode::FAILURE;
        }
    }
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
                .set(env, scope_token, acr_ref, max_age, None)
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

/// `ironauth login --issuer URL --client-id ID [--account NAME]`.
///
/// Drives the RFC 8628 device flow and stores the result in the platform keychain. The
/// loop itself lives in `login.rs` over injected endpoints, so it is tested without a
/// network; this function is the production wiring of those endpoints.
/// The dev entropy seed, installed by `ironauth dev` before the server boots.
///
/// Set means "make every generated secret reproducible": OTP codes, identifiers, client
/// secrets. That is what the issue means by deterministic secrets, and it is the whole
/// reason `dev` refuses a non-loopback bind, because a deployment whose secrets are a
/// function of a published seed has no secrets at all.
///
/// The CLOCK stays real. `Env::deterministic` would freeze time, and a server whose clock
/// never advances cannot expire a token or a code, so the emulator would diverge from
/// production in exactly the behaviour most tests are about. Only the entropy is replaced.
static DEV_ENTROPY_SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// The dev capture sink, installed by `ironauth dev` before the server boots.
///
/// A process-global set ONCE, rather than an `Option` threaded through `serve`,
/// `SharedPlaneInputs`, and `build_oidc_plane`. That is a deliberate trade: the alternative
/// changes three production signatures for a dev-only switch, and every future caller then
/// carries a parameter that is `None` in every real deployment. A `OnceLock` says exactly
/// what this is, which is one process-lifetime decision made before anything boots.
///
/// Nothing reads it unless `ironauth dev` set it, so a production `serve` behaves as if it
/// did not exist.
static DEV_CAPTURE: std::sync::OnceLock<std::sync::Arc<capture::CaptureSink>> =
    std::sync::OnceLock::new();

/// Serve the captured messages on `listener` until the process exits.
///
/// Its own listener rather than a route on the OIDC router: this hands out live one-time
/// codes in plaintext, so the goal is that the production router has no such route to leak.
/// See the module docs in `capture.rs`.
fn serve_capture_sink(listener: std::net::TcpListener, sink: std::sync::Arc<capture::CaptureSink>) {
    std::thread::spawn(move || {
        use std::io::Write as _;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // The request is not read: there is exactly one resource here, and reading a
            // body this never uses would only add a way to block on a client that sends
            // headers and waits.
            let _ = stream.write_all(capture::sink_response(&sink).as_bytes());
            let _ = stream.flush();
        }
    });
}

/// Write the generated dev configuration and return its path.
///
/// The management port is EPHEMERAL. Its default is a fixed 9443, and a collision there does
/// not merely degrade the emulator, it exits the server: measured by running `ironauth dev`
/// on a machine already using that port and watching the whole process die with "Address
/// already in use".
///
/// # Errors
///
/// A message naming the step that failed.
fn write_dev_config(database_url: &str, bind: &str) -> Result<std::path::PathBuf, String> {
    let management_bind = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| format!("127.0.0.1:{}", addr.port()))
        .map_err(|error| format!("could not reserve a management port: {error}"))?;

    let dir = std::env::temp_dir().join("ironauth-dev");
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let config_path = dir.join("ironauth-dev.toml");
    std::fs::write(
        &config_path,
        dev::dev_config_toml(database_url, bind, &management_bind),
    )
    .map_err(|error| format!("cannot write {}: {error}", config_path.display()))?;
    Ok(config_path)
}

/// Print what a developer needs to drive a flow against the emulator.
///
/// Both values, because a flow needs each and neither is derivable by the caller: the issuer
/// URL is SCOPED, so it cannot be constructed without the seeded tenant and environment, and
/// an emulator that seeds a client without saying which one has made the developer read the
/// database to use it.
fn print_dev_scope(bind: &str, scope: &dev::SeededScope) {
    println!(
        "ironauth dev: issuer http://{bind}/t/{}/e/{}",
        scope.tenant, scope.environment
    );
    println!(
        "ironauth dev: client_id {} (public, redirect {})",
        scope.client,
        dev::DEV_REDIRECT_URI
    );
    println!(
        "ironauth dev: user {} / {}",
        dev::DEV_USER_IDENTIFIER,
        dev::DEV_USER_PASSWORD
    );
}

/// Provision the schema roles and apply the schema, before the server boots.
///
/// Nothing else does this. `serve` does not migrate, and a freshly `initdb`-ed cluster has
/// neither the roles the GRANTs name nor a single table, so without this step `ironauth dev`
/// brings up a database the server cannot use and the failure surfaces as an
/// unrelated-looking error deep in the boot rather than as "the schema is not there".
///
/// # Errors
///
/// A message naming the step that failed.
fn prepare_dev_schema(
    bin_dir: &std::path::Path,
    database_url: &str,
    seed: u64,
) -> Result<dev::SeededScope, String> {
    dev::provision_roles(bin_dir, database_url)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    // Seeds come AFTER the schema, for the obvious reason, and before the server boots so
    // the scoped OIDC surfaces exist the moment it answers. Without them the server starts
    // and every scoped endpoint is a 404, which reads as a broken emulator rather than an
    // empty one.
    let scope = dev::seed_ids(seed);
    runtime.block_on(async {
        // The master key is ATTACHED here, not merely present in the generated config. The
        // envelope paths (a sealed user identifier, a sealed connector secret) read it off
        // the STORE, so a `Store::connect` without it fails with "envelope decryption
        // failed" -- measured, and it is a failure of the seed rather than of the config.
        // It derives from the same literal the generated config carries, so the seeded and
        // the served store agree.
        let store = ironauth_store::Store::connect(database_url)
            .await
            .map_err(|error| error.to_string())?
            .with_master_key(std::sync::Arc::new(MasterKey::derive(
                "master-1",
                dev::DEV_MASTER_KEY.as_bytes(),
            )));
        store
            .migrate()
            .await
            .map_err(|error| format!("could not apply the schema: {error}"))?;

        // The rows first (they are the signing key's foreign keys), then the key, which is
        // what gives the environment an issuer entry at all.
        dev::apply_seeds(bin_dir, database_url, &scope)?;

        let env = dev::boot_env(Some(seed));
        let parsed = ironauth_store::Scope::new(
            ironauth_store::TenantId::parse(&scope.tenant)
                .map_err(|error| format!("the seeded tenant id does not parse: {error:?}"))?,
            ironauth_store::EnvironmentId::parse(&scope.environment)
                .map_err(|error| format!("the seeded environment id does not parse: {error:?}"))?,
        );
        dev::provision_signing_key(&store, &env, parsed, seed).await?;
        // The user goes through the repository for the same reason the key does: its
        // identifier is SEALED, so it cannot be a seed statement.
        dev::seed_user(&store, &env, parsed).await
    })?;
    Ok(scope)
}

/// `ironauth dev [--bind ADDR]`: run the emulator.
///
/// Prepares the environment and hands off to the SAME `serve` path production uses, rather
/// than carrying a second boot sequence. A second one would drift, and the drift would be
/// invisible precisely because dev is where nobody looks for a production difference.
fn dev_command(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let mut bind = "127.0.0.1:8080".to_owned();
    // A FIXED default, not a random one: two runs on two machines must produce the same
    // codes, or a CI script cannot name the value it expects.
    let mut seed = 1_u64;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--seed" => {
                let Some(value) = args.next() else {
                    eprintln!("ironauth dev: --seed needs a value");
                    return ExitCode::FAILURE;
                };
                let Ok(parsed) = value.parse::<u64>() else {
                    eprintln!("ironauth dev: --seed must be a number, got '{value}'");
                    return ExitCode::FAILURE;
                };
                seed = parsed;
            }
            "--bind" => {
                let Some(value) = args.next() else {
                    eprintln!("ironauth dev: --bind needs a value");
                    return ExitCode::FAILURE;
                };
                bind = value;
            }
            other => {
                eprintln!("ironauth dev: unknown argument '{other}'");
                return ExitCode::FAILURE;
            }
        }
    }

    // BEFORE anything is started. The guard exists because dev mode's deterministic secrets
    // are safe only on loopback, so the check belongs ahead of every side effect.
    if let Err(refusal) = dev::guard_loopback_only(&bind) {
        eprintln!("ironauth dev: {refusal}");
        return ExitCode::FAILURE;
    }

    // An existing DATABASE_URL wins: a developer who already has a database should not have
    // a second one started underneath them. Otherwise a throwaway cluster is brought up for
    // this process and discarded when it exits.
    //
    // `_cluster` is bound rather than dropped immediately, and that binding IS the
    // lifetime: dropping it stops the server and deletes the directory, so letting it fall
    // out of scope here would tear the database down before the server ever booted.
    let mut _cluster = None;
    // Set only when THIS process brought the database up, which is also when it is ours to
    // migrate.
    let mut dev_bin_dir = None;
    let database_url = if let Ok(url) = std::env::var("DATABASE_URL") {
        url
    } else {
        {
            let Some(bin_dir) = dev::locate_bin_dir(std::env::var("PG_BIN").ok().as_deref()) else {
                eprintln!("ironauth dev: {}", dev::missing_postgres_message());
                return ExitCode::FAILURE;
            };
            let unique = std::process::id().to_string();
            dev_bin_dir = Some(bin_dir.clone());
            match dev::DevCluster::start(&bin_dir, &unique) {
                Ok(cluster) => {
                    let url = cluster.database_url.clone();
                    _cluster = Some(cluster);
                    url
                }
                Err(error) => {
                    eprintln!("ironauth dev: could not start the throwaway database: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
    };

    // Skipped when the developer supplied their own DATABASE_URL: that database is theirs,
    // already managed by whatever manages it.
    if let Some(bin_dir) = &dev_bin_dir {
        match prepare_dev_schema(bin_dir, &database_url, seed) {
            Ok(scope) => print_dev_scope(&bind, &scope),
            Err(error) => {
                eprintln!("ironauth dev: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    let config_path = match write_dev_config(&database_url, &bind) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("ironauth dev: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Deterministic secrets, installed BEFORE the server boots. The guard above has already
    // refused a non-loopback bind, which is what makes this safe to do at all.
    let _ = DEV_ENTROPY_SEED.set(seed);

    // The capture sink, installed BEFORE the server boots so `build_oidc_plane` sees it.
    let sink = std::sync::Arc::new(capture::CaptureSink::default());
    let _ = DEV_CAPTURE.set(std::sync::Arc::clone(&sink));

    // Its own loopback listener on an ephemeral port. Failing to bind it is not fatal: the
    // codes are printed to the console too, so the emulator is still usable, and refusing
    // to start over a diagnostic surface would be the wrong trade.
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            match listener.local_addr() {
                Ok(addr) => println!("ironauth dev: captured messages at http://{addr}/"),
                Err(_) => println!("ironauth dev: capture sink listening"),
            }
            serve_capture_sink(listener, sink);
        }
        Err(error) => {
            eprintln!("ironauth dev: no capture sink endpoint ({error}); codes still print here");
        }
    }

    print!("{}", dev::banner(&bind));

    // The real boot path, with the generated config.
    let mut serve_args = vec!["--config".to_owned(), config_path.display().to_string()].into_iter();
    serve(&mut serve_args)
}

/// The parsed `ironauth login` arguments.
struct LoginArgs {
    issuer: String,
    client_id: String,
    account: String,
    redirect: Option<String>,
    preference: login_flow::FlowPreference,
}

/// Parse `ironauth login`'s arguments, or report what is missing.
fn parse_login_args(args: &mut impl Iterator<Item = String>) -> Result<LoginArgs, ()> {
    let mut issuer = None;
    let mut client_id = None;
    let mut account = "default".to_owned();
    let mut redirect = None;
    let mut preference = login_flow::FlowPreference::Detect;
    while let Some(flag) = args.next() {
        let mut take = |name: &str| {
            let Some(value) = args.next() else {
                eprintln!("ironauth login: {name} needs a value");
                return Err(());
            };
            Ok(value)
        };
        match flag.as_str() {
            "--issuer" => issuer = Some(take("--issuer")?),
            "--client-id" => client_id = Some(take("--client-id")?),
            "--account" => account = take("--account")?,
            "--redirect" => redirect = Some(take("--redirect")?),
            // An explicit flag wins over the heuristic, INCLUDING when it selects the
            // device flow on a machine that could have used loopback. That is a downgrade
            // and it is the caller's to make; what the CLI must not do is make it silently.
            "--device" => preference = login_flow::FlowPreference::ForceDevice,
            "--loopback" => preference = login_flow::FlowPreference::ForceLoopback,
            other => {
                eprintln!("ironauth login: unknown argument '{other}'");
                return Err(());
            }
        }
    }
    let (Some(issuer), Some(client_id)) = (issuer, client_id) else {
        eprintln!("ironauth login: --issuer and --client-id are required");
        return Err(());
    };
    Ok(LoginArgs {
        issuer,
        client_id,
        account,
        redirect,
        preference,
    })
}

fn login(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let Ok(parsed) = parse_login_args(args) else {
        return ExitCode::FAILURE;
    };
    let LoginArgs {
        issuer,
        client_id,
        account,
        redirect,
        preference,
    } = parsed;

    // Which flow. An explicit flag wins; otherwise the host decides, and loopback is
    // preferred wherever it can run because it has no cross-device step for an attacker to
    // solicit a code through.
    let (flow, reason) = login_flow::choose_flow(login_flow::signals_from_env(), preference);
    println!("ironauth: {}", flow_explanation(flow, reason));

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ironauth login: could not start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let store = credentials::KeyringStore;
        // Through the Env clock seam, never the host clock directly: the stored expiry
        // is derived from this instant, so it is protocol-adjacent state that has to stay
        // deterministic under a manual clock. `invariant-lints.sh` enforces the rule and
        // caught this exact line taking the shortcut.
        let now = login::epoch_secs(&ironauth_env::SystemClock);

        // The loopback attempt, when it was chosen AND a redirect was registered. A bind
        // failure falls back to the device flow, which is what the criterion asks for: the
        // host heuristic cannot know whether a listener will actually bind, so the decision
        // has to be made at the bind and not before it.
        let mut result = None;
        if flow == login_flow::LoginFlow::Loopback {
            match redirect.as_deref() {
                Some(registered) => {
                    match loopback_flow::prepare(registered, &ironauth_env::OsEntropy) {
                        Ok(prepared) => {
                            result = Some(
                                run_loopback(&issuer, &client_id, &account, &store, now, prepared)
                                    .await,
                            );
                        }
                        Err(loopback_flow::PrepareError::Bind) => {
                            println!(
                                "ironauth: could not bind a loopback listener; \
                                 using the device flow instead"
                            );
                        }
                        // A registration that cannot support loopback is a CONFIGURATION
                        // problem. Downgrading silently would hide it behind a flow that
                        // happens to work, leaving it undiagnosable.
                        Err(loopback_flow::PrepareError::Registration(cause)) => {
                            eprintln!("ironauth login: {}", cause.message());
                            return ExitCode::FAILURE;
                        }
                    }
                }
                None => {
                    println!(
                        "ironauth: no --redirect registered for a loopback login; \
                         using the device flow instead"
                    );
                }
            }
        }

        let result = match result {
            Some(result) => result,
            None => {
                login::run_device_flow(
                    &issuer,
                    &account,
                    &store,
                    now,
                    || login::request_device_authorization(&issuer, &client_id),
                    |device_code| login::request_token(&issuer, &client_id, device_code),
                    |duration| async move { tokio::time::sleep(duration).await },
                )
                .await
            }
        };

        match result {
            Ok(()) => {
                println!("ironauth: signed in as '{account}'");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("ironauth login: {error}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Run the loopback leg: open the browser, wait for the redirect, exchange the code.
async fn run_loopback(
    issuer: &str,
    client_id: &str,
    account: &str,
    store: &impl credentials::CredentialStore,
    now: i64,
    prepared: loopback_flow::Prepared,
) -> Result<(), login::LoginError> {
    let url = login::authorize_url(
        issuer,
        client_id,
        &prepared.redirect_uri,
        &prepared.code_challenge,
        &prepared.state,
        "openid profile offline_access",
    );

    // Printed BEFORE the browser is opened, and unconditionally. Opening a browser can
    // fail silently on a host with no handler registered, and a user staring at a terminal
    // that only says "waiting" has no way to continue; with the URL in front of them they
    // can paste it anywhere.
    println!("Opening your browser to sign in. If it does not open, visit:");
    println!("  {url}");
    open_browser(&url);

    let redirect =
        tokio::task::block_in_place(|| loopback_flow::await_redirect(&prepared.listener))
            .map_err(login::LoginError::Authorization)?;

    let (code, state) = match redirect {
        loopback_flow::Redirect::Code { code, state } => (code, state),
        loopback_flow::Redirect::Failed(_) => {
            return Err(login::LoginError::Refused(
                "the sign-in was refused in the browser; run the command again",
            ));
        }
    };

    // CSRF: the echoed state must be the one we sent. A mismatch means this redirect
    // belongs to a different authorization request, so the code in it is not ours to
    // redeem, and redeeming it is exactly the attack `state` exists to stop.
    if state != prepared.state {
        return Err(login::LoginError::Refused(
            "the browser returned a response for a different sign-in request",
        ));
    }

    let answer = login::exchange_code(
        issuer,
        client_id,
        &code,
        &prepared.redirect_uri,
        &prepared.code_verifier,
    )
    .await;
    login::store_issued(answer, issuer, account, store, now)
}

/// Ask the platform to open `url`. Best effort: a failure is not fatal, because the URL
/// was already printed for the user to open themselves.
fn open_browser(url: &str) {
    let (program, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[])
    } else if cfg!(target_os = "windows") {
        ("cmd", &["/C", "start", ""])
    } else {
        ("xdg-open", &[])
    };
    let _ = std::process::Command::new(program)
        .args(args)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Say which flow was chosen and why, so the CLI does not appear to guess.
fn flow_explanation(flow: login_flow::LoginFlow, reason: login_flow::FlowReason) -> String {
    let flow = match flow {
        login_flow::LoginFlow::Loopback => "loopback",
        login_flow::LoginFlow::Device => "device",
    };
    let reason = match reason {
        login_flow::FlowReason::Requested => "you asked for it",
        login_flow::FlowReason::BrowserAvailable => "a browser can be opened here",
        login_flow::FlowReason::SshSession => "this is an SSH session",
        login_flow::FlowReason::NoDisplay => "no display server was found",
    };
    format!("using the {flow} flow ({reason})")
}

/// `ironauth logout [--account NAME]`: remove every credential stored for a deployment.
///
/// Exits SUCCESS when there was nothing to remove. That is the contract `logout` needs: a
/// user runs it to reach a known state, and reporting failure because the machine was
/// already in that state would tell them something is still stored when nothing is.
///
/// A keychain that refuses is a real failure and does exit non-zero, because then the
/// credential may still be there and saying otherwise would be a lie about a credential.
fn logout(args: &mut impl Iterator<Item = String>) -> ExitCode {
    let mut account = "default".to_owned();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--account" => {
                let Some(value) = args.next() else {
                    eprintln!("ironauth logout: --account needs a value");
                    return ExitCode::FAILURE;
                };
                account = value;
            }
            other => {
                eprintln!("ironauth logout: unknown argument '{other}'");
                return ExitCode::FAILURE;
            }
        }
    }
    logout_with(&credentials::KeyringStore, &account)
}

/// The logout logic, over an injected store.
///
/// Split out so the behaviour is testable without a platform keychain: see the module docs
/// in `credentials.rs` for why the seam is the store rather than the keychain.
fn logout_with(store: &impl credentials::CredentialStore, account: &str) -> ExitCode {
    match store.delete(account) {
        Ok(()) => {
            println!("ironauth: removed stored credentials for '{account}'");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ironauth logout: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod logout_tests {
    use super::credentials::testing::{MemoryStore, RefusingStore};
    use super::logout_with;
    use std::process::ExitCode;

    fn is_success(code: ExitCode) -> bool {
        format!("{code:?}") == format!("{:?}", ExitCode::SUCCESS)
    }

    /// Criterion 5, through the COMMAND rather than the store beneath it.
    #[test]
    fn logout_removes_the_stored_credential() {
        let store = MemoryStore::default();
        store.seed("default");

        assert!(is_success(logout_with(&store, "default")));
        assert!(
            !store.holds("default"),
            "the command must leave nothing stored"
        );
    }

    /// Logging out of a machine that never logged in SUCCEEDS. A user runs this to reach a
    /// known state; failing because the machine was already in it would report that
    /// something is still stored when nothing is.
    #[test]
    fn logout_succeeds_when_there_was_nothing_stored() {
        assert!(is_success(logout_with(&MemoryStore::default(), "default")));
    }

    /// A keychain that REFUSES exits non-zero, because the credential may still be there.
    /// Reporting success would be a lie about a credential.
    #[test]
    fn a_refusing_keychain_fails_the_command() {
        assert!(!is_success(logout_with(&RefusingStore, "default")));
    }

    /// Logging out of one deployment must not remove another's credential.
    #[test]
    fn logout_is_scoped_to_its_account() {
        let store = MemoryStore::default();
        store.seed("prod");
        store.seed("staging");

        logout_with(&store, "prod");

        assert!(!store.holds("prod"));
        assert!(
            store.holds("staging"),
            "another deployment's credential must survive"
        );
    }
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
    println!("  ironauth dev [--bind ADDR] [--seed N]");
    println!("                                   Run the local emulator (loopback only)");
    println!("  ironauth login --issuer URL --client-id ID [--account NAME]");
    println!("                                   Sign in via the RFC 8628 device flow");
    println!("  ironauth logout [--account NAME] Remove stored credentials for a");
    println!("                                   deployment (issue #120)");
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
            build_federation_runtime_with(&default.oidc, || Ok(
                ironauth_fetch::Fetcher::for_tests(ironauth_fetch::FetchLimits::default())
            ))
            .is_none(),
            "federation is off by default, so the boot path installs no runtime"
        );

        // When `oidc.federation.enabled` is set, the boot path builds a runtime, which is
        // then installed on the OidcState via with_federation so the routes go live.
        // Through the SEAM with a hermetic fetcher (issue #674). What this asserts is that the
        // config flag decides; the host trust store must not get a vote. Reading it made this
        // test fail on a machine whose keychain was refusing, reported as "the flag did not
        // build a runtime", which is not what had happened.
        let enabled = config("[oidc.federation]\nenabled = true\n");
        assert!(
            build_federation_runtime_with(&enabled.oidc, || Ok(
                ironauth_fetch::Fetcher::for_tests(ironauth_fetch::FetchLimits::default())
            ))
            .is_some(),
            "an enabled federation config builds the runtime the boot path installs"
        );

        // The fail-closed half, which the seam makes testable for the first time: a fetcher
        // that cannot be built leaves federation UNMOUNTED rather than mounted with a broken
        // outbound path.
        assert!(
            build_federation_runtime_with(&enabled.oidc, || Err(
                ironauth_fetch::TlsSetupError::NoTrustRoots { causes: Vec::new() }
            ))
            .is_none(),
            "a fetcher that cannot be built must leave federation unmounted"
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

    /// A finished pass writes every outcome into the registry, including the ZERO ones.
    ///
    /// This drives the observer rather than a pool, because the thing at risk is the
    /// translation: `DrainStats` already carried all five numbers and the pool already
    /// reported them, and what did not exist was anything turning them into a series. A
    /// test that spun up a pool would exercise the queue and prove nothing about that.
    ///
    /// The consumer name is unique to this test because the recorder is process-global and
    /// shared with every other test in this binary.
    #[test]
    fn a_finished_pass_counts_every_outcome_including_the_zero_ones() {
        let handle = ironauth_server::metrics::recorder_handle();
        // The scope is DISCARDED by this observer by design (labels are consumer-only), so
        // any well formed one will do; it is generated rather than written out because ids
        // carry a checksum and a literal would only ever pin the literal.
        let env = Env::system();
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        MetricsOutboxObserver.pass_finished(
            "metrics.pin.finished",
            scope,
            &DrainStats {
                claimed: 7,
                completed: 4,
                retried: 2,
                dead_lettered: 1,
                lease_lost: 0,
            },
        );
        let text = ironauth_server::metrics::render(&handle);
        let series = |needle: &str| {
            text.lines()
                .find(|line| line.contains("metrics.pin.finished") && line.contains(needle))
                .unwrap_or_else(|| panic!("no {needle} series for the pass; exposition:\n{text}"))
                .to_owned()
        };
        assert!(
            series("ironauth_outbox_messages_claimed_total").ends_with(" 7"),
            "the claim count is what says work was PICKED UP at all, and a pool that \
             claims nothing looks exactly like a pool with nothing to do"
        );
        assert!(series("outcome=\"completed\"").ends_with(" 4"), "completed");
        assert!(series("outcome=\"retried\"").ends_with(" 2"), "retried");
        assert!(
            series("outcome=\"dead_lettered\"").ends_with(" 1"),
            "the dead-letter count is the one an alert fires on"
        );
        assert!(
            series("outcome=\"lease_lost\"").ends_with(" 0"),
            "a zero outcome must still EXIST as a series: a counter that appears only once \
             it has something to say cannot be told apart from a pool that never started, \
             which is the exact question an operator asks it"
        );
    }

    /// The two failure hooks are separate `kind` labels, because they are not the same size.
    #[test]
    fn a_failed_pass_and_an_unavailable_scope_sweep_count_separately() {
        let handle = ironauth_server::metrics::recorder_handle();
        // The scope is DISCARDED by this observer by design (labels are consumer-only), so
        // any well formed one will do; it is generated rather than written out because ids
        // carry a checksum and a literal would only ever pin the literal.
        let env = Env::system();
        let scope = Scope::new(TenantId::generate(&env), EnvironmentId::generate(&env));
        MetricsOutboxObserver.pass_failed("metrics.pin.failed", scope, &StoreError::NotFound);
        MetricsOutboxObserver.scopes_unavailable("metrics.pin.failed", &StoreError::NotFound);
        let text = ironauth_server::metrics::render(&handle);
        for kind in ["drain", "scopes"] {
            let needle = format!("kind=\"{kind}\"");
            assert!(
                text.lines()
                    .any(|line| line.contains("metrics.pin.failed") && line.contains(&needle)),
                "a {kind} failure went uncounted; losing one scope's pass and losing EVERY \
                 scope's pass are different sizes of outage and must not share a series"
            );
        }
    }
}
