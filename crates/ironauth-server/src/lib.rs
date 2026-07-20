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
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use ironauth_config::Config;
use ironauth_env::Env;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;
use tower_http::catch_panic::CatchPanicLayer;

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
    management_extension: Option<Router>,
    public_extension: Option<Router>,
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
            management_extension: None,
            public_extension: None,
        })
    }

    /// Mount an additional router on the PUBLIC data plane.
    ///
    /// The public-facing protocol surfaces (the OIDC provider, `ironauth-oidc`,
    /// issue #12; the admin console SPA, `ironauth-admin-ui`, issue #90) are built
    /// as self-contained `Router`s and mounted here, so the server crate stays
    /// decoupled from them (it accepts any router, not a specific type). The
    /// routes are merged into the PUBLIC plane only, never the management plane,
    /// and inherit the plane's observability and panic-catching layers. The caller
    /// owns the router's state, auth, and middleware.
    ///
    /// Calling this more than once MERGES the routers (the OIDC provider and the
    /// admin console each mount independently), rather than the later call
    /// replacing the earlier one.
    #[must_use]
    pub fn mount_public(mut self, router: Router) -> Self {
        self.public_extension = Some(match self.public_extension.take() {
            Some(existing) => existing.merge(router),
            None => router,
        });
        self
    }

    /// Mount an additional router on the MANAGEMENT plane.
    ///
    /// The management API (`ironauth-admin`, issue #11) is built as a
    /// self-contained `Router` and mounted here, so the server crate stays
    /// decoupled from it (it accepts any router, not a specific type). The routes
    /// are merged into the management plane only, never the public data plane,
    /// and inherit the plane's observability and panic-catching layers. The
    /// caller is responsible for the router's own state, auth, and middleware.
    #[must_use]
    pub fn mount_management(mut self, router: Router) -> Self {
        self.management_extension = Some(router);
        self
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

    /// The PUBLIC data-plane router. Serves the skeleton surfaces plus any router
    /// mounted via [`Server::mount_public`] (the OIDC provider); health,
    /// readiness, and metrics are intentionally absent here.
    pub fn app(&self) -> Router {
        let mut router = Router::new()
            .route("/", get(routes::root))
            .route("/.well-known/security.txt", get(routes::security_txt))
            .with_state(self.state());
        // Merge the mounted public API (already carrying its own state), if any,
        // onto the public plane. Merging keeps the skeleton routes and adds the
        // protocol routes; both then share the observe and panic layers.
        if let Some(extension) = &self.public_extension {
            router = router.merge(extension.clone());
        }
        router
            // CatchPanicLayer is added before observe so it sits INSIDE it: a
            // handler panic becomes an opaque 500 that still flows back through
            // request logging and metrics rather than resetting the connection.
            .layer(CatchPanicLayer::custom(on_panic))
            .layer(axum::middleware::from_fn_with_state(
                self.state(),
                observe::observe,
            ))
    }

    /// The MANAGEMENT-plane router. Serves liveness, readiness, and metrics, plus
    /// any router mounted via [`Server::mount_management`] (the management API);
    /// bind it to a private interface.
    pub fn management_app(&self) -> Router {
        let mut router = Router::new()
            .route("/healthz", get(routes::healthz))
            .route("/readyz", get(routes::readyz))
            .route("/metrics", get(routes::metrics))
            .with_state(self.state());
        // Merge the mounted management API (already carrying its own state), if
        // any, onto the management plane. Merging keeps the health/metrics routes
        // and adds the API routes; both then share the observe and panic layers.
        if let Some(extension) = &self.management_extension {
            router = router.merge(extension.clone());
        }
        router
            .layer(CatchPanicLayer::custom(on_panic))
            .layer(axum::middleware::from_fn_with_state(
                self.state(),
                observe::observe,
            ))
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

/// Turn a caught handler panic into an opaque 500.
///
/// The panic payload is never rendered: it may carry request-derived data, and
/// rendering it would bypass the log-scrubbing guarantee. The panic location is
/// reported separately by the scrubbing-safe panic hook (see
/// `telemetry::install_panic_hook`); here the client only ever sees a generic
/// error.
fn on_panic(_payload: Box<dyn std::any::Any + Send + 'static>) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
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

#[cfg(test)]
mod tests {
    use super::on_panic;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use tower_http::catch_panic::CatchPanicLayer;

    async fn boom() -> StatusCode {
        panic!("SENTINEL_PANIC_PAYLOAD_secret")
    }

    #[tokio::test]
    async fn caught_panic_becomes_opaque_500() {
        // A handler that panics with request-derived data must not reset the
        // connection or render the payload; the layer returns a generic 500.
        let app = Router::new()
            .route("/boom", get(boom))
            .layer(CatchPanicLayer::custom(on_panic));

        let response = app
            .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
            .await
            .expect("service responds rather than resetting");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);
        assert!(
            !text.contains("SENTINEL_PANIC_PAYLOAD"),
            "payload leaked: {text}"
        );
        assert_eq!(text, "internal server error");
    }
}
