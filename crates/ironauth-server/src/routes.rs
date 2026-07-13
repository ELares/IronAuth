// SPDX-License-Identifier: MIT OR Apache-2.0

//! The route handlers for both planes.
//!
//! The two planes serve disjoint route sets. The management plane carries
//! liveness, readiness, and metrics; the public plane carries only the
//! self-contained skeleton surfaces (`security.txt` and a root liveness page).
//! Health, readiness, and metrics are deliberately absent from the public
//! plane so the data plane is never probed publicly (an adversarial test
//! asserts they 404 there). Protocol endpoints arrive in M2.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

use crate::AppState;
use crate::readiness::Readiness;

/// The repository's RFC 9116 `security.txt`, embedded so the binary is
/// self-contained. Its validity and expiry are checked in CI.
const SECURITY_TXT: &str = include_str!("../../../docs/well-known/security.txt");

/// `GET /` on the public plane: a minimal liveness page. Unknown public paths
/// fall through to the default 404.
pub async fn root() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "IronAuth is running.\n",
    )
}

/// `GET /.well-known/security.txt` on the public plane.
pub async fn security_txt() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        SECURITY_TXT,
    )
}

/// `GET /healthz` on the management plane: liveness, always 200 once serving.
pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "ok\n",
    )
}

/// `GET /readyz` on the management plane: 200 when the database address is
/// TCP-reachable, 503 otherwise. Provisional until issue #7 replaces the TCP
/// probe with a real pool health check.
pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.readiness.probe().await {
        Readiness::Ready => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "ready\n",
        ),
        Readiness::DatabaseUnreachable => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "not ready: database address unreachable (provisional check until #7)\n",
        ),
    }
}

/// `GET /metrics` on the management plane: Prometheus text exposition.
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        crate::metrics::render(&state.metrics),
    )
}
