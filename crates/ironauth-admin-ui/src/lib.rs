// SPDX-License-Identifier: MIT OR Apache-2.0

//! In-process serving of the IronAuth admin console single page app (issue #90).
//!
//! The admin console is a Preact single page app (`packages/admin-spa`) that
//! speaks the public management API through one generated typed client. This
//! crate is the serving half: it embeds the built `dist/` with `rust-embed` and
//! exposes a [`Router`] that the server mounts on the PUBLIC plane under
//! [`MOUNT_PREFIX`] via `Server::mount_public`, exactly as the OIDC provider
//! mounts. Mounting is gated by the caller on `admin_spa.enabled` (default off),
//! so a default deployment never mounts these routes and every `/admin` path is
//! a uniform 404, the same posture the flow and hosted-page gates take.
//!
//! Two properties are structural here:
//!
//! - **Its own Content Security Policy.** Every response carries
//!   [`CONTENT_SECURITY_POLICY`], the console CSP, which is distinct from (and
//!   looser than) the strict auth-page CSP: the console loads its hashed script
//!   and stylesheet from `'self'` and talks to the management API on `'self'`.
//!   Because the Vite build ships only content hashed, external assets (no
//!   inline script or style), the policy needs no `unsafe-inline`.
//! - **A SPA fallback.** A request under [`MOUNT_PREFIX`] that names an existing
//!   embedded asset gets that asset; a request that looks like a client route
//!   (no file extension) gets `index.html` so the in browser router can take
//!   over; a missing static asset is a real 404.
//!
//! PR1 embeds a committed placeholder shell so `cargo build` is green without a
//! Node toolchain; the CI `admin-spa` job produces the real Vite `dist/`, and a
//! later change wires the embed to it. Auth dogfooding (the login and the same
//! origin management proxy) lands in PR2.

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Router, extract::Path};
use rust_embed::RustEmbed;

/// The public plane path the admin console is served under. The Vite build sets
/// its `base` to `/admin/` so every built asset URL is prefixed to match.
pub const MOUNT_PREFIX: &str = "/admin";

/// The Content Security Policy served on every admin console response.
///
/// This is the console CSP, deliberately SEPARATE from the strict auth-page CSP
/// (issue #89): the console runs its own hashed script and stylesheet from
/// `'self'` and calls the management API on `'self'`. It carries no
/// `unsafe-inline` because the Vite build emits only external, content hashed
/// assets. `img-src` allows `data:` for small inlined icons; everything else is
/// locked to `'self'` or `'none'`. `form-action 'self'` is explicit because it
/// does NOT fall back to `default-src`, so without it a form could POST to an
/// external host; here it confines every form submission to the same origin.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'";

/// The built admin console assets, baked into the binary at compile time.
#[derive(RustEmbed)]
#[folder = "embedded/"]
struct Assets;

/// Build the admin console router for mounting on the PUBLIC plane.
///
/// The caller mounts the returned router with `Server::mount_public` ONLY when
/// `admin_spa.enabled` is true; when it is false the router is never mounted, so
/// every `/admin` path answers a uniform 404. The router owns no state and adds
/// no middleware beyond serving the embedded assets with the console CSP.
pub fn router() -> Router {
    Router::new()
        .route(MOUNT_PREFIX, get(serve_index))
        .route("/admin/", get(serve_index))
        .route("/admin/{*path}", get(serve_path))
}

/// Serve the SPA entry document (`/admin` and `/admin/`).
async fn serve_index() -> Response {
    index_response()
}

/// Serve an embedded asset by its path under the mount, or fall back to the SPA
/// entry document for a client route.
async fn serve_path(Path(path): Path<String>) -> Response {
    let rel = path.trim_start_matches('/');
    if let Some(asset) = Assets::get(rel) {
        return asset_response(rel, asset.data.into_owned());
    }
    // A path whose final segment carries a file extension is a static asset
    // request; when it is not embedded it is a real 404. Any other path is a
    // client route, so the SPA entry document is served and the in browser
    // router resolves it.
    let last = rel.rsplit('/').next().unwrap_or("");
    if last.contains('.') {
        return not_found();
    }
    index_response()
}

/// The SPA entry document response, or a 404 if the entry document is somehow
/// absent from the embed (it never is in a built binary).
fn index_response() -> Response {
    Assets::get("index.html").map_or_else(not_found, |asset| {
        asset_response("index.html", asset.data.into_owned())
    })
}

/// Build a response for an embedded asset: the body, the extension derived
/// content type, a cache directive, and the console CSP.
fn asset_response(path: &str, body: Vec<u8>) -> Response {
    let is_entry = path == "index.html";
    let cache = if is_entry {
        // The entry document names the hashed assets, so it must never be cached
        // stale; the hashed assets under it are immutable.
        "no-store"
    } else {
        "public, max-age=31536000, immutable"
    };
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type(path));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // Belt and suspenders with `frame-ancestors 'none'` for a legacy browser that
    // ignores CSP, matching the auth pages (issue #89): the console is never framed.
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// A uniform 404 that still carries the console CSP.
fn not_found() -> Response {
    let mut response = (StatusCode::NOT_FOUND, Body::empty()).into_response();
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    response
}

/// Map a file extension to its response content type. The set covers exactly
/// what the Vite build emits; anything else is served as opaque bytes.
fn content_type(path: &str) -> HeaderValue {
    let ext = path.rsplit('.').next().unwrap_or("");
    let value = match ext {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "png" => "image/png",
        "webp" => "image/webp",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    };
    HeaderValue::from_static(value)
}

#[cfg(test)]
mod tests {
    use super::{CONTENT_SECURITY_POLICY, router};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn get(uri: &str) -> axum::response::Response {
        router()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("router responds")
    }

    #[tokio::test]
    async fn serves_the_entry_document_at_the_mount_root() {
        let response = get("/admin").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            CONTENT_SECURITY_POLICY
        );
        // The CSP confines form submissions to the same origin (form-action does
        // not fall back to default-src), and the console is never framed.
        assert!(CONTENT_SECURITY_POLICY.contains("form-action 'self'"));
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("id=\"app\""));
    }

    #[tokio::test]
    async fn falls_back_to_the_entry_document_for_a_client_route() {
        // A deep client route with no file extension is served the SPA entry so
        // the in browser router can resolve it.
        let response = get("/admin/tenants/some-id").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("id=\"app\""));
    }

    #[tokio::test]
    async fn a_missing_static_asset_is_a_real_404() {
        let response = get("/admin/assets/does-not-exist.js").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Even the 404 carries the console CSP.
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            CONTENT_SECURITY_POLICY
        );
    }

    #[tokio::test]
    async fn does_not_answer_outside_its_mount() {
        // The router only owns paths under /admin; a path outside it has no
        // route here, so the server's own 404 handles it (never the SPA
        // fallback), which is what keeps the SPA off every other public path.
        let response = get("/authorize").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
