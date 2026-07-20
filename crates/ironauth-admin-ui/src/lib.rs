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
//! - **A same-origin management proxy (issue #90, PR 2).** A request under
//!   [`API_PREFIX`] (`/admin/api/...`) is forwarded to the IN-PROCESS management
//!   [`Router`] this crate is handed, with the path rewritten to drop the
//!   `/admin/api` prefix and EVERYTHING ELSE (method, headers including the SPA's
//!   `Authorization: Bearer`, and body) forwarded VERBATIM. The console runs on the
//!   PUBLIC plane, whose CSP `connect-src 'self'` confines it to its own origin, so
//!   this same-origin hop is how the browser reaches the management API without a
//!   cross-origin exception. It is NOT an open proxy: it targets only the one
//!   management router passed in, never a caller-named host, and it attaches nothing
//!   privileged (the SPA's own bearer is the sole credential). When no management
//!   router is provided (the OIDC/management planes are not mounted in this process)
//!   every `/admin/api/*` path is a uniform 404.
//!
//! PR1 embeds a committed placeholder shell so `cargo build` is green without a
//! Node toolchain; the CI `admin-spa` job produces the real Vite `dist/`, and a
//! later change wires the embed to it.

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use rust_embed::RustEmbed;
use tower::ServiceExt;

/// The public plane path the admin console is served under. The Vite build sets
/// its `base` to `/admin/` so every built asset URL is prefixed to match.
pub const MOUNT_PREFIX: &str = "/admin";

/// The same-origin management proxy prefix (issue #90, PR 2). A request whose path
/// begins with this is forwarded to the in-process management router with this
/// prefix stripped (so `/admin/api/v1/tenants` reaches the management router as
/// `/v1/tenants`).
pub const API_PREFIX: &str = "/admin/api";

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

/// The router state: the OPTIONAL in-process management router the same-origin
/// proxy forwards `/admin/api/*` to. `None` leaves every `/admin/api/*` path a
/// uniform 404 (the management/OIDC planes are not mounted in this process).
#[derive(Clone)]
struct UiState {
    management: Option<Router>,
}

/// Build the admin console router for mounting on the PUBLIC plane.
///
/// The caller mounts the returned router with `Server::mount_public` ONLY when
/// `admin_spa.enabled` is true; when it is false the router is never mounted, so
/// every `/admin` path answers a uniform 404.
///
/// `management` is the in-process management [`Router`] the same-origin proxy
/// forwards `/admin/api/*` to (issue #90, PR 2). Pass a clone of the SAME router
/// mounted on the management plane; the proxy strips the `/admin/api` prefix and
/// forwards the request VERBATIM (method, headers, body). Pass `None` to leave the
/// proxy off (every `/admin/api/*` is a uniform 404), which is correct when this
/// process does not run the management plane.
pub fn router(management: Option<Router>) -> Router {
    Router::new()
        .route(MOUNT_PREFIX, get(serve_index))
        .route("/admin/", get(serve_index))
        // ONE handler owns every deeper path so the static-asset serving and the
        // `/admin/api/*` proxy never register overlapping catch-all routes (which
        // axum would reject). The handler dispatches on the raw path. `any` so the
        // proxy can carry every method; the serving branch answers only GET.
        .route("/admin/{*path}", any(serve_or_proxy))
        .with_state(UiState { management })
}

/// Serve the SPA entry document (`/admin` and `/admin/`).
async fn serve_index() -> Response {
    index_response()
}

/// Dispatch a deep `/admin/...` request: forward `/admin/api/*` to the in-process
/// management router (the same-origin proxy), otherwise serve a static asset or the
/// SPA entry document.
///
/// The raw request path is used (never a percent-decoded capture), so the path
/// rewritten for the proxy is byte-faithful to what the client sent. The SPA's
/// `Authorization` header and body ride along verbatim; nothing privileged is
/// attached here.
async fn serve_or_proxy(State(state): State<UiState>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    if path == API_PREFIX || path.starts_with(&format!("{API_PREFIX}/")) {
        return match &state.management {
            Some(management) => proxy_to_management(management.clone(), request).await,
            // No management router in this process: the proxy surface does not exist.
            None => not_found(),
        };
    }
    // The serving branch answers only GET; a write to a static/route path is a 404.
    if request.method() != Method::GET {
        return not_found();
    }
    let rel = path
        .strip_prefix("/admin/")
        .unwrap_or("")
        .trim_start_matches('/');
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

/// Forward `request` to the in-process `management` router with the `/admin/api`
/// prefix stripped from the path (issue #90, PR 2).
///
/// The rewritten target is `path[/admin/api..]` plus the original query, so
/// `/admin/api/v1/tenants?limit=1` reaches the management router as
/// `/v1/tenants?limit=1`. Method, headers (including `Authorization`), and body are
/// forwarded unchanged. The management router is driven as a `tower` Service
/// (`oneshot`) IN PROCESS, so this proxy can reach ONLY that router, never an
/// arbitrary host: it is structurally not an SSRF surface.
async fn proxy_to_management(management: Router, request: Request) -> Response {
    let (mut parts, body) = request.into_parts();
    // Strip the `/admin/api` prefix; the remainder already carries its leading
    // slash (the prefix has none trailing), so `/admin/api/v1/x` -> `/v1/x` and the
    // bare `/admin/api` -> `` (an empty path, rejected below).
    let stripped = parts
        .uri
        .path()
        .strip_prefix(API_PREFIX)
        .unwrap_or_default();
    if stripped.is_empty() {
        return not_found();
    }
    let target = match parts.uri.query() {
        Some(query) => format!("{stripped}?{query}"),
        None => stripped.to_owned(),
    };
    let Ok(uri) = target.parse::<Uri>() else {
        return (StatusCode::BAD_REQUEST, Body::empty()).into_response();
    };
    parts.uri = uri;
    // A Router's Service error is Infallible, so this await never yields an Err.
    management
        .oneshot(Request::from_parts(parts, body))
        .await
        .into_response()
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
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::any;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn get(uri: &str) -> axum::response::Response {
        router(None)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("router responds")
    }

    /// A stand-in management router that echoes the path and method it received, so
    /// the proxy tests can assert the rewrite and the verbatim forward.
    fn echo_management() -> Router {
        Router::new().route(
            "/{*rest}",
            any(|request: Request<Body>| async move {
                let auth = request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("<none>")
                    .to_owned();
                format!(
                    "{} {} auth={auth}",
                    request.method(),
                    request.uri().path_and_query().map_or("", |pq| pq.as_str())
                )
            }),
        )
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

    #[tokio::test]
    async fn proxies_admin_api_to_the_management_router_with_the_prefix_stripped() {
        // A /admin/api/* request reaches the management router with /admin/api
        // dropped and the query preserved, and the Authorization header verbatim.
        let router = router(Some(echo_management()));
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/api/v1/tenants?limit=2")
                    .header(header::AUTHORIZATION, "Bearer at.jwt.token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            String::from_utf8_lossy(&body),
            "POST /v1/tenants?limit=2 auth=Bearer at.jwt.token"
        );
    }

    #[tokio::test]
    async fn admin_api_is_a_uniform_404_when_no_management_router_is_wired() {
        // With no management router (this process does not run the management
        // plane), the proxy surface does not exist: every /admin/api/* is a 404.
        let response = get("/admin/api/v1/tenants").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_client_route_still_falls_back_to_the_spa_even_with_the_proxy_wired() {
        // The proxy only claims /admin/api/*; every other deep path still serves
        // the SPA entry (a client route) or an asset, so wiring the proxy does not
        // shadow the SPA fallback.
        let router = router(Some(echo_management()));
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/admin/tenants/some-id")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("id=\"app\""));
    }
}
