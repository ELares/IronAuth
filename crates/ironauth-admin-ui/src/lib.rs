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
//! The real built Vite `dist/` is COMMITTED under `embedded/` (issue #323), so a
//! plain `cargo build` with no Node toolchain bakes the real working console into
//! the binary; a CI freshness gate (`scripts/admin-spa-embed.sh`) rebuilds and
//! git-diffs it so the committed embed can never go stale.
//!
//! - **Server injected runtime config (issue #323).** The served entry document
//!   carries the per environment runtime config the SPA reads from `<meta>` tags:
//!   the admin issuer as a same origin scoped path (`/t/{tenant}/e/{env}`) the SPA
//!   does discovery against, the console's public OAuth client id, and the
//!   management API audience. These are injected into the served `index.html` at
//!   serve time (never baked into the committed embed) and every injected value is
//!   HTML attribute escaped, so a config value can never break out of the
//!   `content="..."` attribute. When the bridge is not configured the values are
//!   empty and the tags stay empty (sign in stays unavailable). None of these is a
//!   secret: the client id, audience, and issuer path are bounded operator
//!   identifiers, and the browser only ever holds the short lived `at+jwt` it
//!   obtains through the Authorization Code + PKCE login.

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

/// The per environment runtime config injected into the served entry document's
/// `<meta>` tags at serve time (issue #323), so the browser SPA can read it from
/// `loadConfig()` and start the Authorization Code + PKCE login.
///
/// Every field is a bounded, NON-secret operator identifier. The values are
/// injected HTML attribute escaped (see [`escape_attribute`]); the browser only
/// ever holds the short lived `at+jwt` it obtains through the login, never a
/// secret. The [`Default`] (all fields empty) leaves every tag empty, so sign in
/// stays unavailable exactly as when the OIDC bridge is not configured.
#[derive(Clone, Default)]
pub struct RuntimeConfig {
    /// The admin issuer as a SAME ORIGIN scoped path (`/t/{tenant}/e/{env}`) the
    /// SPA does OIDC discovery against. Empty leaves sign in unavailable.
    ///
    /// Injected into `<meta name="ironauth-admin-issuer">`. It is a same origin
    /// path (not an absolute URL), so the embedded deploy needs no cross origin
    /// exception; `ironauth-issuer` and `ironauth-management-base` stay empty (the
    /// SPA then defaults to its own origin and the `/admin/api` proxy).
    pub admin_issuer_path: String,

    /// The PUBLIC OAuth client id the console authenticates as. A public client
    /// holds no secret, so this is a bounded identifier, never a credential. Empty
    /// leaves sign in unavailable. Injected into
    /// `<meta name="ironauth-console-client-id">`.
    pub console_client_id: String,

    /// The management API audience (RFC 8707) the console's access token is bound
    /// to. Injected into `<meta name="ironauth-management-audience">`. Empty omits
    /// the resource parameter on the SPA side.
    pub management_audience: String,
}

/// The router state: the OPTIONAL in-process management router the same-origin
/// proxy forwards `/admin/api/*` to, plus the runtime config injected into the
/// served entry document. `None` management leaves every `/admin/api/*` path a
/// uniform 404 (the management/OIDC planes are not mounted in this process).
#[derive(Clone)]
struct UiState {
    management: Option<Router>,
    config: RuntimeConfig,
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
///
/// `config` is the per environment runtime config (issue #323) injected into the
/// served entry document's `<meta>` tags so the browser SPA can start the login.
/// Pass [`RuntimeConfig::default`] (all fields empty) to leave the tags empty when
/// the OIDC bridge is not configured (sign in stays unavailable).
pub fn router(management: Option<Router>, config: RuntimeConfig) -> Router {
    Router::new()
        .route(MOUNT_PREFIX, get(serve_index))
        .route("/admin/", get(serve_index))
        // ONE handler owns every deeper path so the static-asset serving and the
        // `/admin/api/*` proxy never register overlapping catch-all routes (which
        // axum would reject). The handler dispatches on the raw path. `any` so the
        // proxy can carry every method; the serving branch answers only GET.
        .route("/admin/{*path}", any(serve_or_proxy))
        .with_state(UiState { management, config })
}

/// Serve the SPA entry document (`/admin` and `/admin/`).
async fn serve_index(State(state): State<UiState>) -> Response {
    index_response(&state.config)
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
    index_response(&state.config)
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

/// The SPA entry document response with the per environment runtime config
/// injected into its `<meta>` tags (issue #323), or a 404 if the entry document is
/// somehow absent from the embed (it never is in a built binary).
///
/// The embedded `index.html` ships with the config meta tags empty; this injects
/// `config`'s values, HTML attribute escaped, at serve time so no config value is
/// ever baked into the committed embed and none can break out of the `content`
/// attribute. When `config` is [`RuntimeConfig::default`] (all empty) the tags are
/// left empty, exactly as the committed embed ships them.
fn index_response(config: &RuntimeConfig) -> Response {
    let Some(asset) = Assets::get("index.html") else {
        return not_found();
    };
    // The embed is valid UTF-8 HTML the build produced; `from_utf8_lossy` never
    // alters it in practice and keeps this total (no panic on a malformed embed).
    let html = String::from_utf8_lossy(&asset.data);
    let injected = inject_runtime_config(&html, config);
    asset_response("index.html", injected.into_bytes())
}

/// Inject the runtime config into the served entry document by replacing the
/// `content` of the three config `<meta>` tags, keyed on the tag's `name` (issue
/// #323). Every value is HTML attribute escaped so it cannot break out of the
/// `content="..."` attribute. `ironauth-issuer` and `ironauth-management-base`
/// stay empty (the embedded same origin defaults). A value that is empty leaves
/// its tag empty (the replacement is a no-op).
fn inject_runtime_config(html: &str, config: &RuntimeConfig) -> String {
    let mut out = html.to_owned();
    for (name, value) in [
        ("ironauth-admin-issuer", &config.admin_issuer_path),
        ("ironauth-console-client-id", &config.console_client_id),
        ("ironauth-management-audience", &config.management_audience),
    ] {
        out = set_meta_content(&out, name, &escape_attribute(value));
    }
    out
}

/// Replace the `content` attribute value of the `<meta name="{name}">` tag with
/// `escaped_value` (already HTML attribute escaped). The match is keyed on
/// `name="{name}"` and bounded to that single tag (the `content="` and its
/// closing quote must lie before the tag's `>`), so it is a targeted replace, not
/// a fragile blind string op, and it cannot spill into an adjacent tag. If the tag
/// or its `content` attribute is absent the html is returned unchanged.
fn set_meta_content(html: &str, name: &str, escaped_value: &str) -> String {
    let name_needle = format!("name=\"{name}\"");
    let Some(name_at) = html.find(&name_needle) else {
        return html.to_owned();
    };
    // Bound every sub search to this one tag: from the name attribute to the next
    // `>`. Because a well formed escaped value carries no raw `"` or `>`, this
    // cannot be fooled into spanning tags.
    let Some(tag_end_rel) = html[name_at..].find('>') else {
        return html.to_owned();
    };
    let tag_end = name_at + tag_end_rel;
    let content_needle = "content=\"";
    let Some(content_rel) = html[name_at..tag_end].find(content_needle) else {
        return html.to_owned();
    };
    let value_start = name_at + content_rel + content_needle.len();
    let Some(close_rel) = html[value_start..tag_end].find('"') else {
        return html.to_owned();
    };
    let value_end = value_start + close_rel;
    let mut out = String::with_capacity(html.len() + escaped_value.len());
    out.push_str(&html[..value_start]);
    out.push_str(escaped_value);
    out.push_str(&html[value_end..]);
    out
}

/// HTML attribute escape a config value (issue #323): `&`, `"`, `<`, `>`, and `'`
/// so the value can NEVER break out of the `content="..."` attribute it is
/// injected into. `&` is escaped first (it is the escape introducer) by virtue of
/// each character being mapped independently in one pass. Defense in depth: these
/// are bounded operator identifiers, but the escape makes a hostile config value
/// structurally inert in the served document.
fn escape_attribute(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
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
    use super::{CONTENT_SECURITY_POLICY, RuntimeConfig, escape_attribute, router};
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::any;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn get(uri: &str) -> axum::response::Response {
        router(None, RuntimeConfig::default())
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("router responds")
    }

    async fn body_string(response: axum::response::Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
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
        let router = router(Some(echo_management()), RuntimeConfig::default());
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
        let router = router(Some(echo_management()), RuntimeConfig::default());
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

    // ---- issue #323: the real console + server injected runtime config --------

    /// A populated runtime config, as the server threads it in when the OIDC
    /// bridge is configured.
    fn console_config() -> RuntimeConfig {
        RuntimeConfig {
            admin_issuer_path: "/t/acme/e/prod".to_owned(),
            console_client_id: "console-public-client".to_owned(),
            management_audience: "https://mgmt.example/api".to_owned(),
        }
    }

    async fn get_with(uri: &str, config: RuntimeConfig) -> axum::response::Response {
        router(None, config)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("router responds")
    }

    #[tokio::test]
    async fn serves_the_real_vite_console_not_the_placeholder_shell() {
        // The embedded document is the REAL built console: it references the
        // content hashed bundle under the /admin mount and carries none of the
        // committed placeholder shell prose that PR1 shipped.
        let response = get("/admin").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(
            body.contains("/admin/assets/"),
            "served document must reference the hashed assets under the mount"
        );
        assert!(
            body.contains("type=\"module\""),
            "served document must load the real console module bundle"
        );
        assert!(
            !body.contains("committed placeholder shell"),
            "served document must not be the PR1 placeholder"
        );
    }

    #[tokio::test]
    async fn injects_the_runtime_config_into_the_served_meta_tags() {
        // With the bridge configured, the served document carries the admin issuer
        // scoped path, the console client id, and the management audience in the
        // meta tags loadConfig() reads, so canSignIn() becomes true in the browser.
        let response = get_with("/admin", console_config()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_string(response).await;
        assert!(
            body.contains("<meta name=\"ironauth-admin-issuer\" content=\"/t/acme/e/prod\" />")
        );
        assert!(body.contains(
            "<meta name=\"ironauth-console-client-id\" content=\"console-public-client\" />"
        ));
        assert!(body.contains(
            "<meta name=\"ironauth-management-audience\" content=\"https://mgmt.example/api\" />"
        ));
        // The embedded same origin defaults stay empty (no issuer or management
        // base injected), so the SPA calls its own origin and the /admin/api proxy.
        assert!(body.contains("<meta name=\"ironauth-issuer\" content=\"\" />"));
        assert!(body.contains("<meta name=\"ironauth-management-base\" content=\"\" />"));
    }

    #[tokio::test]
    async fn leaves_the_config_meta_tags_empty_when_the_bridge_is_not_configured() {
        // The default (no bridge) leaves every config tag empty, so sign in stays
        // unavailable exactly as the committed embed ships.
        let response = get("/admin").await;
        let body = body_string(response).await;
        assert!(body.contains("<meta name=\"ironauth-admin-issuer\" content=\"\" />"));
        assert!(body.contains("<meta name=\"ironauth-console-client-id\" content=\"\" />"));
        assert!(body.contains("<meta name=\"ironauth-management-audience\" content=\"\" />"));
    }

    #[tokio::test]
    async fn serves_the_embedded_hashed_asset_the_document_references() {
        // The document names a hashed asset under /admin/assets; a follow up GET of
        // that exact path returns it from the embed with the right content type and
        // the immutable cache directive.
        let body = body_string(get("/admin").await).await;
        let marker = "src=\"/admin/assets/";
        let start = body
            .find(marker)
            .expect("document references a script asset")
            + "src=\"".len();
        let end = start + body[start..].find('"').expect("asset src is quoted");
        let asset_path = &body[start..end];
        assert!(
            asset_path.starts_with("/admin/assets/") && asset_path.rsplit('.').next() == Some("js")
        );

        let response = get(asset_path).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        // The asset carries the console CSP too (script-src 'self', no inline).
        assert!(
            CONTENT_SECURITY_POLICY.contains("script-src 'self'")
                && !CONTENT_SECURITY_POLICY.contains("unsafe-inline")
        );
    }

    #[tokio::test]
    async fn escapes_a_hostile_config_value_so_it_cannot_break_out_of_the_attribute() {
        // A config value that tries to close the content attribute and inject
        // markup is HTML attribute escaped: the escaped form appears, and the raw
        // breakout sequence never does.
        let hostile = RuntimeConfig {
            management_audience: "a\"><script>alert(1)</script>".to_owned(),
            ..RuntimeConfig::default()
        };
        let body = body_string(get_with("/admin", hostile).await).await;
        assert!(body.contains(
            "<meta name=\"ironauth-management-audience\" \
             content=\"a&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\" />"
        ));
        // The raw injected markup (an attribute breakout) never reaches the document.
        assert!(!body.contains("content=\"a\"><script>alert(1)"));
        assert!(!body.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn escape_attribute_escapes_every_breakout_character() {
        assert_eq!(escape_attribute("&\"<>'"), "&amp;&quot;&lt;&gt;&#x27;");
        // An ordinary bounded identifier is unchanged.
        assert_eq!(escape_attribute("/t/acme/e/prod"), "/t/acme/e/prod");
    }

    #[tokio::test]
    async fn the_admin_mount_is_a_uniform_404_when_the_flag_is_off() {
        // The crate router is mounted by the server ONLY when admin_spa.enabled is
        // true. This models that composition: when the flag is off the admin router
        // is never merged, so /admin is the server's own uniform 404.
        fn app(admin_spa_enabled: bool) -> Router {
            let mut app = Router::new();
            if admin_spa_enabled {
                app = app.merge(router(None, console_config()));
            }
            app
        }

        let off = app(false)
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responds");
        assert_eq!(off.status(), StatusCode::NOT_FOUND);

        // Sanity: with the flag on the same path serves the real console.
        let on = app(true)
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router responds");
        assert_eq!(on.status(), StatusCode::OK);
        assert!(body_string(on).await.contains("/admin/assets/"));
    }
}
