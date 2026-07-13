// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth HTTP server skeleton.
//!
//! This crate is the structural foundation every later endpoint inherits from.
//! It ships four properties before any protocol surface exists, because they
//! cannot be retrofitted safely once endpoints are in the wild:
//!
//! - **Dual-plane isolation.** Two listeners on two ports serve disjoint route
//!   sets: a PUBLIC data plane (`server.bind`) and a MANAGEMENT plane
//!   (`server.management_bind`). Liveness, readiness, and metrics live only on
//!   the management plane, so the data plane is never probed publicly.
//! - **Observability.** Structured JSON logs with an async writer, a Prometheus
//!   `/metrics` endpoint, and (behind the non-default `otlp` feature) OTLP trace
//!   export. See [`telemetry`] and [`metrics`].
//! - **Log hygiene.** Request logging carries route templates and safe fields
//!   only; sensitive runtime values travel wrapped in [`Redacted`]. See
//!   [`observe`] and [`redact`].
//! - **Trusted-proxy policy.** Scheme, host, and issuer derive from config,
//!   never from request headers; forwarding headers are honored only under an
//!   explicit trusted-hop topology and fail closed on any ambiguity. See
//!   [`proxy`].
//!
//! The runtime is tokio + axum (see `docs/adr/0001-http-runtime.md`). No TLS
//! crate is pulled: the server runs behind a terminating proxy and the scheme
//! derives from config.
//!
//! Time and entropy flow through [`ironauth_env`]; this crate never reads the
//! clock directly (request latency is measured via the injected [`ironauth_env::Env`]).

mod error;
mod logwriter;
pub mod metrics;
mod observe;
pub mod proxy;
mod readiness;
mod redact;
mod routes;
pub mod telemetry;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use ironauth_config::Config;
use ironauth_env::Env;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;

pub use error::ServerError;
pub use proxy::{
    ClientContext, ClientResolution, FailClosedReason, ForwardDecision, ProxyPolicy, SiteContext,
};
pub use readiness::{Readiness, ReadinessProbe};
pub use redact::Redacted;

/// Cheaply cloneable state shared by every handler on both planes.
#[derive(Clone)]
pub(crate) struct AppState {
    env: Env,
    policy: ProxyPolicy,
    site: Arc<SiteContext>,
    readiness: Arc<ReadinessProbe>,
    metrics: PrometheusHandle,
}

/// The IronAuth server, built from validated config and an environment seam.
///
/// Construct with [`Server::new`], mount the routers with [`Server::app`] and
/// [`Server::management_app`] (both testable in isolation), and serve with
/// [`Server::run`] until a shutdown future resolves.
pub struct Server {
    config: Config,
    site: Arc<SiteContext>,
    policy: ProxyPolicy,
    readiness: Arc<ReadinessProbe>,
    metrics: PrometheusHandle,
    env: Env,
}

impl Server {
    /// Build a server from config and the environment seam.
    ///
    /// Installs (once per process) the Prometheus recorder and sets the `up`
    /// gauge. Derives the config-sourced site context and the trusted-proxy
    /// policy up front so no request path ever recomputes them.
    ///
    /// # Errors
    ///
    /// [`ServerError::InvalidPublicUrl`] if `server.public_url` is set but not
    /// a valid `http`/`https` base URL.
    pub fn new(config: Config, env: Env) -> Result<Self, ServerError> {
        let site = Arc::new(SiteContext::derive(&config.server)?);
        let policy = ProxyPolicy::from_config(&config.proxy);
        let readiness = Arc::new(ReadinessProbe::from_config(&config.database));
        let handle = metrics::recorder_handle();
        ::metrics::gauge!(metrics::UP).set(1.0);
        Ok(Self {
            config,
            site,
            policy,
            readiness,
            metrics: handle,
            env,
        })
    }

    /// The config-derived base URL (issuer root); always config-sourced.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.site.base_url()
    }

    fn state(&self) -> AppState {
        AppState {
            env: self.env.clone(),
            policy: self.policy,
            site: Arc::clone(&self.site),
            readiness: Arc::clone(&self.readiness),
            metrics: self.metrics.clone(),
        }
    }

    /// The PUBLIC data-plane router. Serves only the skeleton surfaces; health,
    /// readiness, and metrics are intentionally absent here.
    pub fn app(&self) -> Router {
        Router::new()
            .route("/", get(routes::root))
            .route("/.well-known/security.txt", get(routes::security_txt))
            .layer(axum::middleware::from_fn_with_state(
                self.state(),
                observe::observe,
            ))
            .with_state(self.state())
    }

    /// The MANAGEMENT-plane router. Serves liveness, readiness, and metrics
    /// only; bind it to a private interface.
    pub fn management_app(&self) -> Router {
        Router::new()
            .route("/healthz", get(routes::healthz))
            .route("/readyz", get(routes::readyz))
            .route("/metrics", get(routes::metrics))
            .layer(axum::middleware::from_fn_with_state(
                self.state(),
                observe::observe,
            ))
            .with_state(self.state())
    }

    /// Serve both planes until `shutdown` resolves, then drain in-flight
    /// requests within `server.shutdown_grace_secs` and return.
    ///
    /// # Errors
    ///
    /// [`ServerError::Bind`] if either listener cannot bind its address.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), ServerError> {
        let public_bind = self.config.server.bind.clone();
        let mgmt_bind = self.config.server.management_bind.clone();
        let grace = Duration::from_secs(self.config.server.shutdown_grace_secs);

        let public_listener = TcpListener::bind(public_bind.as_str())
            .await
            .map_err(|source| ServerError::Bind {
                field: "server.bind",
                addr: public_bind.clone(),
                source,
            })?;
        let mgmt_listener = TcpListener::bind(mgmt_bind.as_str())
            .await
            .map_err(|source| ServerError::Bind {
                field: "server.management_bind",
                addr: mgmt_bind.clone(),
                source,
            })?;

        let public_local = public_listener.local_addr().ok();
        let mgmt_local = mgmt_listener.local_addr().ok();

        let public_app = self
            .app()
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        let mgmt_app = self
            .management_app()
            .into_make_service_with_connect_info::<std::net::SocketAddr>();

        // One shutdown fan-out for both servers.
        let (tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let public_serve = axum::serve(public_listener, public_app)
            .with_graceful_shutdown(wait_for_broadcast(tx.subscribe()));
        let mgmt_serve = axum::serve(mgmt_listener, mgmt_app)
            .with_graceful_shutdown(wait_for_broadcast(tx.subscribe()));
        let public_task = tokio::spawn(async move { public_serve.await });
        let mgmt_task = tokio::spawn(async move { mgmt_serve.await });

        tracing::info!(
            "server.public.addr" = ?public_local,
            "server.management.addr" = ?mgmt_local,
            base_url = %self.site.base_url(),
            "ironauth serving"
        );

        shutdown.await;
        tracing::info!(
            grace_secs = self.config.server.shutdown_grace_secs,
            "draining"
        );
        let _ = tx.send(());

        let drain = async {
            let _ = public_task.await;
            let _ = mgmt_task.await;
        };
        if grace.is_zero() {
            // Grace of zero: signal stop and return without waiting to drain.
        } else if tokio::time::timeout(grace, drain).await.is_err() {
            tracing::warn!(
                grace_secs = self.config.server.shutdown_grace_secs,
                "shutdown grace deadline exceeded; forcing exit"
            );
        }

        ::metrics::gauge!(metrics::UP).set(0.0);
        Ok(())
    }
}

/// Resolve when the broadcast channel signals shutdown.
async fn wait_for_broadcast(mut rx: tokio::sync::broadcast::Receiver<()>) {
    let _ = rx.recv().await;
}

/// A future that resolves on the first `SIGTERM` or `SIGINT` (`Ctrl-C`).
///
/// Pass this to [`Server::run`] in the binary; tests pass their own future to
/// drive shutdown deterministically.
///
/// # Panics
///
/// Panics if the OS signal handlers cannot be installed, which indicates a
/// broken process environment rather than a recoverable condition.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut interrupt = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
