// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two transports (issue #84, FORK C): a thin shim over the ONE shared engine
//! ([`super::drive`] / [`super::create_flow`]). The state machine, node rendering,
//! message ids, error shaping, and anti enumeration recipe are ONE type, ONE state
//! machine, ONE code path (the found vs unknown equality holds WITHIN a transport; the
//! transport tag, `ui.action`, and browser hidden node differ by design); the transports
//! differ in EXACTLY two mechanical places:
//!
//! 1. submission ingestion: the browser decodes `application/x-www-form-urlencoded` and
//!    runs the [`same_origin_ok`](crate::interaction::same_origin_ok) CSRF check; the API
//!    decodes `application/json` and matches a per flow submit token;
//! 2. continuation: the browser sets the session cookie on a 303 redirect; the API returns
//!    a 200 JSON envelope (and sets the cookie for a client that holds cookies).
//!
//! Every route answers a uniform 404 when `flows.enabled` is off (FORK D), so a deployment
//! that does not use the flow API discloses nothing and the bootstrap pages are untouched.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use ironauth_store::{FlowId, Scope};
use serde::Deserialize;
use serde_json::{Value, json};

use super::localize::{LanguageTag, LocaleBundle, ResolvedLocale, resolve_locale};
use super::model::{Flow, Journey, Transport};
use super::render::{self, PageTheme};
use super::{
    Continuation, FLOW_CONTRACT_HEADER, FlowError, Submission, TransportAuth, create_flow, drive,
    message::Message, parse_api_submission, parse_form_transient_payload,
};
use crate::branding::{BrandCandidate, select_brand};
use crate::hints::InteractionHints;
use crate::interaction;
use crate::pages;
use crate::state::OidcState;
use crate::util::query_get;
use crate::wellknown::parse_scope;
use ironauth_store::BrandAssetKind;

/// The served flow stylesheet path (issue #85, FORK C): a scope routed, same origin
/// `text/css` asset the hosted flow render app links from its `<head>`, so the browser
/// fetches the ONE embedded stylesheet under the `style-src 'self'` CSP. Gated behind
/// `flows.enabled` like every flow route (a uniform 404 when off).
pub const FLOW_STYLESHEET_PATH: &str = "/t/{tenant_id}/e/{environment_id}/pages.css";

/// The served brand asset path (issue #86, PR 3): a scope routed, same origin GET that streams a
/// brand's stored raster (`{kind}` is `logo` or `favicon`) with SERVER-FIXED headers only (the
/// sniffed `Content-Type`, `nosniff`, and a sha256 `ETag`). The flow page's `<img>` and favicon
/// `<link>` point here, loaded under the page's `img-src 'self'`. Gated behind `flows.enabled`
/// like every flow route (a uniform 404 when off, or when the asset is absent).
pub const FLOW_BRAND_ASSET_PATH: &str = "/t/{tenant_id}/e/{environment_id}/brand/{slug}/{kind}";

/// The browser transport path (GET creates and renders, POST submits): scope routed under
/// the per environment issuer path so the flow runs under the right row level security
/// scope. The `{journey}` is the journey to start (`login` or `registration`; the MFA states
/// are reached from a login flow, recovery lands in a later PR).
pub const FLOW_BROWSER_PATH: &str = "/t/{tenant_id}/e/{environment_id}/flow/{journey}";

/// The API transport creation path: POST a JSON body to create a flow and receive the flow
/// object plus the first submit token.
pub const FLOW_CREATE_API_PATH: &str = "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}";

/// The API transport submission path: POST a JSON body with the flow id, the submit token,
/// and the node values.
pub const FLOW_API_SUBMIT_PATH: &str =
    "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}/submit";

/// Stamp the flow contract version response header (issue #84, FORK B) onto a response.
fn with_contract_header(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::HeaderName::from_static(FLOW_CONTRACT_HEADER),
        HeaderValue::from_static("1"),
    );
    response
}

/// The uniform 404 when the flow API is disabled (FORK D): a plain not found with no body,
/// so a deployment that does not use the flow API discloses nothing.
fn disabled_not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Render a typed flow error as JSON (the API transport). The body carries the numeric
/// message id so a client keys its copy on the number; [`FlowError::Store`] is the neutral
/// server error with no client facing id.
fn error_json(error: FlowError) -> Response {
    let body = match error.message_id() {
        Some(id) => {
            let message = Message::of(id);
            json!({ "error": { "id": message.id, "text": message.text } })
        }
        None => json!({ "error": { "text": "server_error" } }),
    };
    with_contract_header((error.status(), Json(body)).into_response())
}

/// Render a typed flow error as a hardened HTML notice (the browser transport).
fn error_html(error: FlowError) -> Response {
    let text = match error.message_id() {
        Some(id) => Message::of(id).text,
        None => "The request could not be processed.".to_owned(),
    };
    with_contract_header(pages::secure_html(
        error.status(),
        pages::notice_page("Sign in", &text),
    ))
}

/// The API create request body: the journey to start plus the optional resume target and
/// transient payload.
#[derive(Debug, Deserialize)]
pub struct ApiCreateBody {
    /// The resume target to complete back to, or absent.
    #[serde(default)]
    return_to: Option<String>,
    /// Arbitrary client context carried through the flow (never persisted on the identity).
    #[serde(default)]
    transient_payload: Option<Value>,
    /// The federation connector slug to launch (the "continue with {provider}" choice), for a
    /// federation flow. Ignored by the other journeys.
    #[serde(default)]
    connector: Option<String>,
}

/// The browser GET query: the optional resume target seeded at creation.
#[derive(Debug, Deserialize)]
pub struct BrowserCreateQuery {
    /// The resume target to complete back to, or absent.
    #[serde(default)]
    return_to: Option<String>,
    /// The federation connector slug to launch, for a federation flow. Ignored by the other
    /// journeys.
    #[serde(default)]
    connector: Option<String>,
}

/// The browser POST form: the flow id (a hidden field), the node values, and the optional
/// transient payload.
#[derive(Debug, Deserialize)]
pub struct BrowserSubmitForm {
    /// The flow id carried back from the hidden field.
    #[serde(default)]
    flow: String,
    /// The identifier field (login and registration).
    #[serde(default)]
    identifier: Option<String>,
    /// The password field (login and registration).
    #[serde(default)]
    password: Option<String>,
    /// The MFA code field (a TOTP or recovery code on the challenge/enroll states).
    #[serde(default)]
    code: Option<String>,
    /// The proof of work challenge id (issue #80), when a registration challenge is required.
    #[serde(default)]
    pow_challenge_id: Option<String>,
    /// The proof of work nonce (issue #80).
    #[serde(default)]
    pow_nonce: Option<String>,
    /// The proof of work request context (issue #80).
    #[serde(default)]
    pow_context: Option<String>,
    /// An external adapter response token (issue #80).
    #[serde(default)]
    pow_token: Option<String>,
    /// The transient payload as a JSON string, or absent.
    #[serde(default)]
    transient_payload: Option<String>,
}

// -------------------------------------------------------------------------------------
// API transport (application/json + submit token).
// -------------------------------------------------------------------------------------

/// `POST /t/{tenant}/e/{env}/flow/api/{journey}` (issue #84): create a flow and return the
/// flow object plus the first submit token as a 200 JSON envelope.
pub async fn flow_api_create(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, journey)): Path<(String, String, String)>,
    Json(body): Json<ApiCreateBody>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_json(FlowError::NotFound);
    };
    // The login and registration journeys are creation entries; the MFA states are reached
    // FROM a login flow and recovery lands in a later PR, so those are a typed not found.
    let Some(journey) = creation_journey(&journey) else {
        return error_json(FlowError::NotFound);
    };
    match create_flow(
        &state,
        scope,
        Transport::Api,
        journey,
        body.return_to.as_deref(),
        body.transient_payload.as_ref(),
        body.connector.as_deref(),
    )
    .await
    {
        Ok((_id, submit_token, flow)) => api_flow_envelope(StatusCode::OK, &flow, &submit_token),
        Err(error) => error_json(error),
    }
}

/// Parse a creation journey (issue #84): [`Journey::Login`], [`Journey::Registration`],
/// [`Journey::Recovery`], or [`Journey::Federation`], or [`None`] for an unknown journey or one
/// that is not a creation entry (the MFA states are reached from a login flow, never created
/// directly).
fn creation_journey(raw: &str) -> Option<Journey> {
    match Journey::parse(raw) {
        Some(
            journey @ (Journey::Login
            | Journey::Registration
            | Journey::Recovery
            | Journey::Federation),
        ) => Some(journey),
        _ => None,
    }
}

/// `POST /t/{tenant}/e/{env}/flow/api/{journey}/submit` (issue #84): advance a flow. Returns
/// the next flow state plus a rotated submit token, or a completion envelope with the
/// session cookie on success.
pub async fn flow_api_submit(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, _journey)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_json(FlowError::NotFound);
    };
    // Decode the JSON submit envelope through the ONE pure parser (the fuzz target's subject):
    // a malformed body or an oversized/malformed transient payload is a TYPED flow error here,
    // never a 500 and never a generic non flow rejection.
    let parsed = match parse_api_submission(&body) {
        Ok(parsed) => parsed,
        Err(error) => return error_json(error),
    };
    let Ok(flow_id) = FlowId::parse_in_scope(&parsed.id, &scope) else {
        return error_json(FlowError::NotFound);
    };
    let submission = parsed.submission;
    let auth = TransportAuth::Api {
        presented_submit_token: parsed.submit_token,
    };
    match drive(
        &state,
        scope,
        &flow_id,
        Transport::Api,
        auth,
        submission,
        &headers,
    )
    .await
    {
        Ok(Continuation::Render { flow, submit_token }) => {
            api_flow_envelope(StatusCode::OK, &flow, &submit_token)
        }
        Ok(Continuation::Complete { session, return_to }) => {
            let body = json!({
                "state": "completed",
                "continue_with": { "redirect_to": return_to },
            });
            let response = with_contract_header((StatusCode::OK, Json(body)).into_response());
            interaction::attach_session_cookies(response, &session)
        }
        // The federation launcher: return the authorize URL as a redirect affordance. A native
        // client opens it in a browser; the EXISTING federation callback finalizes the login
        // (the in JSON resume is honestly deferred, like PR 2's passkey deferral). No session is
        // minted here.
        Ok(Continuation::Redirect { url }) => {
            let body = json!({
                "state": "redirect",
                "continue_with": { "redirect_to": url },
            });
            with_contract_header((StatusCode::OK, Json(body)).into_response())
        }
        Err(error) => error_json(error),
    }
}

/// Build the API JSON envelope: the flow object plus the current submit token, with the
/// contract header.
fn api_flow_envelope(status: StatusCode, flow: &Flow, submit_token: &str) -> Response {
    let body = json!({ "flow": flow, "submit_token": submit_token });
    with_contract_header((status, Json(body)).into_response())
}

// -------------------------------------------------------------------------------------
// Browser transport (form urlencoded + same origin + cookie/redirect).
// -------------------------------------------------------------------------------------

/// `GET /t/{tenant}/e/{env}/flow/{journey}` (issue #84): create a flow and render its HTML
/// form. The flow id rides a hidden field so the POST carries it back.
pub async fn flow_browser_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, journey)): Path<(String, String, String)>,
    Query(query): Query<BrowserCreateQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_html(FlowError::NotFound);
    };
    let Some(journey) = creation_journey(&journey) else {
        return error_html(FlowError::NotFound);
    };
    match create_flow(
        &state,
        scope,
        Transport::Browser,
        journey,
        query.return_to.as_deref(),
        None,
        query.connector.as_deref(),
    )
    .await
    {
        Ok((_id, _submit_token, flow)) => with_contract_header(
            render_browser_flow(&state, scope, &tenant_id, &environment_id, &flow, &headers).await,
        ),
        Err(error) => error_html(error),
    }
}

/// `POST /t/{tenant}/e/{env}/flow/{journey}` (issue #84): submit the browser form. Runs the
/// same origin CSRF gate, then the SAME engine; re-renders the HTML form on a validation or
/// authentication failure, or 303 redirects setting the session cookie on completion.
pub async fn flow_browser_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, _journey)): Path<(String, String, String)>,
    headers: HeaderMap,
    Form(form): Form<BrowserSubmitForm>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    // The browser CSRF IO edge: the same origin gate (issue #196) BEFORE any state change,
    // exactly as the bootstrap login POST does.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return with_contract_header(interaction::forbidden_page());
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return error_html(FlowError::NotFound);
    };
    let Ok(flow_id) = FlowId::parse_in_scope(&form.flow, &scope) else {
        return error_html(FlowError::NotFound);
    };
    let transient_payload = match parse_form_transient_payload(form.transient_payload.as_deref()) {
        Ok(payload) => payload,
        Err(error) => return error_html(error),
    };
    let mut node_values = std::collections::BTreeMap::new();
    let mut insert = |name: &str, value: Option<String>| {
        if let Some(value) = value {
            node_values.insert(name.to_owned(), Value::String(value));
        }
    };
    insert("identifier", form.identifier);
    insert("password", form.password);
    insert("code", form.code);
    insert("pow_challenge_id", form.pow_challenge_id);
    insert("pow_nonce", form.pow_nonce);
    insert("pow_context", form.pow_context);
    insert("pow_token", form.pow_token);
    let submission = Submission {
        node_values,
        transient_payload,
    };
    match drive(
        &state,
        scope,
        &flow_id,
        Transport::Browser,
        TransportAuth::Browser,
        submission,
        &headers,
    )
    .await
    {
        Ok(Continuation::Render { flow, .. }) => with_contract_header(
            render_browser_flow(&state, scope, &tenant_id, &environment_id, &flow, &headers).await,
        ),
        Ok(Continuation::Complete { session, return_to }) => {
            if let Some(target) = return_to {
                with_contract_header(interaction::redirect_setting_cookie(&target, &session))
            } else {
                // No resume target: render a hardened success notice with the session cookie.
                let notice = pages::secure_html(
                    StatusCode::OK,
                    pages::notice_page(
                        "Signed in",
                        &Message::of(super::message::LOGIN_SUCCESS).text,
                    ),
                );
                with_contract_header(interaction::attach_session_cookies(notice, &session))
            }
        }
        // The federation launcher: 303 to the EXISTING outbound federation authorize leg (which
        // persists the correlation row and redirects to the upstream provider; the existing
        // callback finalizes the login). No session is minted here.
        Ok(Continuation::Redirect { url }) => with_contract_header(interaction::redirect(&url)),
        Err(error) => error_html(error),
    }
}

/// `GET /t/{tenant}/e/{env}/pages.css` (issue #85, FORK C; issue #86 branding): serve the
/// per environment flow stylesheet. Gated behind `flows.enabled` like every flow route, so a
/// deployment that does not use the flow render app answers a uniform 404 and discloses
/// nothing (no cutover, no live behavior change while the flag is off).
///
/// When the environment has a DEFAULT brand (issue #86), the stylesheet is the brand's TYPED
/// design tokens emitted as `:root` CSS custom properties (plus the dark variants) prepended
/// to the variable referencing layout rules. Because every emitted value passed the typed
/// token grammar, the served CSS is CSP-clean (no `url()`, no external host, no breakout),
/// so the strict `style-src 'self'` CSP (issue #89) is untouched. With NO brand installed
/// the response is the BYTE IDENTICAL neutral stylesheet, so an unbranded environment is
/// unchanged from issue #85.
pub async fn flow_stylesheet(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<StylesheetQuery>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    // A malformed scope (the route matched the shape but the ids do not parse) falls back to
    // the neutral stylesheet: the stylesheet is public chrome, so failing open to the neutral
    // default discloses nothing and never errors the page.
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return pages::stylesheet_response();
    };
    // The flow page routes the stylesheet to the SAME brand it rendered by threading the resolved
    // brand slug as `?b={slug}` (issue #86, PR 3): read that exact brand's tokens so the page and
    // its stylesheet never diverge under per-client / per-domain selection. An absent or unknown
    // slug (a bare stylesheet fetch, or an unbranded environment) falls back to the byte-identical
    // neutral stylesheet.
    let Some(slug) = query.b else {
        return pages::stylesheet_response();
    };
    match state.store().scoped(scope).brands().get(&slug).await {
        Ok(Some(record)) => {
            let brand = brand_from_record(record);
            pages::css_response(pages::brand_stylesheet(
                &brand.tokens,
                brand.tokens_dark.as_ref(),
            ))
        }
        _ => pages::stylesheet_response(),
    }
}

/// The brand asset serve GET (issue #86, PR 3): stream a brand's stored raster (`logo` or
/// `favicon`) with SERVER-FIXED headers only. Gated behind `flows.enabled` like every flow route
/// (a uniform 404 when off). An unknown scope, an unknown kind, or an absent asset is the SAME
/// uniform 404, so the serve path discloses nothing about which brands or assets exist.
pub async fn flow_brand_asset(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, slug, kind)): Path<(String, String, String, String)>,
) -> Response {
    if !state.flows_enabled() {
        return disabled_not_found();
    }
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return disabled_not_found();
    };
    let Some(kind) = BrandAssetKind::parse(&kind) else {
        return disabled_not_found();
    };
    match state
        .store()
        .scoped(scope)
        .brands()
        .get_asset(&slug, kind)
        .await
    {
        Ok(Some(asset)) => {
            pages::brand_asset_response(&asset.content_type, asset.bytes, &asset.sha256)
        }
        // An absent asset, or a store hiccup, is the uniform not found (no disclosure).
        _ => disabled_not_found(),
    }
}

/// The flow stylesheet query (issue #86, PR 3): the optional resolved brand slug the page routed
/// its stylesheet to, so the stylesheet resolves the SAME brand's tokens as the page.
#[derive(Debug, Deserialize)]
pub struct StylesheetQuery {
    /// The resolved brand slug (`b`), or absent for the neutral stylesheet.
    #[serde(default)]
    b: Option<String>,
}

/// Build a typed, sanitized [`crate::branding::Brand`] from a stored brand record.
fn brand_from_record(record: ironauth_store::BrandRecord) -> crate::branding::Brand {
    crate::branding::Brand::from_stored(
        record.product_name,
        record.show_wordmark,
        record.brand_token,
        &record.tokens_json,
        record.tokens_dark_json.as_deref(),
        &record.slots_json,
    )
}

/// The brand resolved for one flow request (issue #86, PR 3): the typed, sanitized brand plus its
/// slug (which routes the served stylesheet and the asset hrefs) and which assets are installed.
struct ResolvedBrand {
    /// The typed, sanitized brand (wordmark, slots, tokens).
    brand: crate::branding::Brand,
    /// The resolved brand's slug.
    slug: String,
    /// Whether the brand has a logo installed.
    has_logo: bool,
    /// Whether the brand has a favicon installed.
    has_favicon: bool,
}

/// Resolve the brand for one request by the per-CLIENT > per-DOMAIN > env-DEFAULT > NEUTRAL
/// precedence (issue #86, PR 3): read the scope's brands, run the pure [`select_brand`] precedence
/// over the request Host and `client_id`, and build the typed brand plus its installed-asset
/// flags. Returns [`None`] when the environment has no brand OR nothing matches and no default is
/// installed OR a read fails, so the render path uses the neutral default (unchanged from issue
/// #85) and a store hiccup never breaks a page.
async fn resolve_brand(
    state: &OidcState,
    scope: Scope,
    host: Option<&str>,
    client_id: Option<&str>,
) -> Option<ResolvedBrand> {
    let records = state
        .store()
        .scoped(scope)
        .brands()
        .list_all()
        .await
        .unwrap_or_default();
    if records.is_empty() {
        return None;
    }
    // Run the pure precedence over the candidate rows, then take the chosen owned record.
    let index = {
        let candidates: Vec<BrandCandidate<'_>> = records
            .iter()
            .map(|record| BrandCandidate {
                slug: &record.slug,
                is_default: record.is_default,
                host_pattern: record.host_pattern.as_deref(),
                client_id: record.client_id.as_deref(),
            })
            .collect();
        select_brand(&candidates, host, client_id)
    }?;
    let chosen = records.into_iter().nth(index)?;
    let slug = chosen.slug.clone();
    // Which assets are installed for the chosen brand (metadata only, no bytes): a store hiccup
    // fails safe to "no assets", so the page renders with no logo / favicon rather than erroring.
    let assets = state
        .store()
        .scoped(scope)
        .brands()
        .asset_metadata(&slug)
        .await
        .unwrap_or_default();
    let has_logo = assets.iter().any(|meta| meta.kind == BrandAssetKind::Logo);
    let has_favicon = assets
        .iter()
        .any(|meta| meta.kind == BrandAssetKind::Favicon);
    Some(ResolvedBrand {
        brand: brand_from_record(chosen),
        slug,
        has_logo,
        has_favicon,
    })
}

/// The request Host for per-domain brand selection (issue #86, PR 3): the `Host` header value as
/// a borrowed str, or [`None`] when absent or non-ASCII. [`select_brand`] normalizes it.
fn request_host(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
}

/// Resolve the end user's locale for rendering (issue #86, PR 2): read the environment's
/// installed locale bundles and its default locale, then run the RFC 4647 lookup over the
/// request's `ui_locales` (`fr-CA` to `fr` to the env default to the compiled `en` registry).
/// The `ui_locales` input already flows end-to-end (authorize to the resume `return_to` to the
/// reconstructed [`InteractionHints`]); this consumes it, adding no new request plumbing. A
/// bundle-less environment (or a store hiccup, which fails safe to no bundles) resolves to the
/// neutral English default, so the page is byte-identical to before PR 2.
async fn resolve_env_locale(
    state: &OidcState,
    scope: Scope,
    hints: &InteractionHints,
) -> ResolvedLocale {
    let records = state
        .store()
        .scoped(scope)
        .locale_bundles()
        .list_all()
        .await
        .unwrap_or_default();
    let mut installed = std::collections::BTreeMap::new();
    let mut env_default: Option<LanguageTag> = None;
    for record in records {
        let Some(tag) = LanguageTag::parse(&record.locale) else {
            continue;
        };
        if record.is_env_default {
            env_default = Some(tag.clone());
        }
        installed.insert(tag.clone(), LocaleBundle::parse(tag, &record.entries_json));
    }
    // No installed default falls back to English (the compiled registry language), so a scope
    // with bundles but no marked default still resolves sensibly.
    let env_default =
        env_default.unwrap_or_else(|| LanguageTag::parse("en").expect("en is a valid tag"));
    resolve_locale(hints.ui_locales(), &env_default, &installed)
}

/// Render a flow object into the full hosted page (issue #85, the render app). Threads the
/// neutral [`PageTheme`] seam, the request UX hints reconstructed from the resume
/// `/authorize` target (`ui_locales`/`display`), the resolved locale (issue #86), the issue #42
/// environment banner, and the passkey conditional-UI wiring (only when WebAuthn is enabled).
/// The strict headers are attached here by the flow response builder: the passkey ceremony CSP
/// when the passkey node group was rendered as the ceremony, else the plain flow CSP. This is
/// the ONLY thing the browser transport emits differently under `flows.enabled`; the flow
/// OBJECT is unchanged.
async fn render_browser_flow(
    state: &OidcState,
    scope: Scope,
    tenant_id: &str,
    environment_id: &str,
    flow: &Flow,
    headers: &HeaderMap,
) -> Response {
    let scope_path = format!("/t/{tenant_id}/e/{environment_id}");
    // The resume target is a local `/authorize?...` URL carrying the UX parameters through the
    // flow contract; split its query once and reuse it for both the hints and the per-client
    // brand selection (the `client_id` the request named).
    let request_query = flow
        .request_url
        .as_deref()
        .and_then(|url| url.split_once('?'))
        .map(|(_, query)| query);
    // Honor the authorization request UX parameters surfaced through the flow contract (absent or
    // unparsable falls back to the neutral default, an English `page` shell).
    let hints = request_query.map_or_else(InteractionHints::default, InteractionHints::from_query);
    // Resolve the locale from the SAME `ui_locales` the hints carry, against this environment's
    // installed bundles (issue #86). No bundles resolves to neutral English (byte-identical).
    let locale = resolve_env_locale(state, scope, &hints).await;
    let banner = state.environment_banner(&scope).await;
    // The per environment brand (issue #86, PR 3): resolve by the per-CLIENT > per-DOMAIN >
    // env-DEFAULT > NEUTRAL precedence over the request Host and the authorize `client_id`. The
    // resolved brand fills the wordmark fields and the sanitized rich-text slots, and its slug
    // routes the served stylesheet (`?b={slug}`) and the same origin asset hrefs; a NULL/absent
    // brand keeps the neutral default (byte-identical to before PR 3). The design tokens drive
    // the SERVED stylesheet (a separate request), never inline style, so the strict CSP is
    // untouched.
    let host = request_host(headers);
    let client_id = request_query.and_then(|query| query_get(query, "client_id"));
    let theme = match resolve_brand(state, scope, host, client_id.as_deref()).await {
        Some(resolved) => PageTheme {
            product_name: resolved.brand.product_name,
            show_wordmark: resolved.brand.show_wordmark,
            brand_token: resolved.brand.brand_token,
            slots: resolved.brand.slots,
            asset_slug: Some(resolved.slug),
            has_logo: resolved.has_logo,
            has_favicon: resolved.has_favicon,
        },
        None => PageTheme::default(),
    };
    // The passkey conditional-UI wiring, present only when WebAuthn is enabled for this
    // deployment (the SAME gate the bootstrap login page uses). The per response nonce is
    // drawn from the SAME entropy seam and hex scheme as the bootstrap ceremony.
    let nonce = state
        .webauthn_enabled()
        .then(|| crate::login::passkey_nonce(state));
    let passkey = nonce.as_deref().map(|nonce| pages::PasskeyUi {
        nonce,
        scope_path: &scope_path,
        signal_api: state.webauthn_signal_api_enabled(),
    });
    let rendered = render::render_flow_page(
        flow,
        &theme,
        &hints,
        &locale,
        banner,
        &scope_path,
        passkey.as_ref(),
    );
    match rendered.passkey_nonce {
        Some(nonce) => pages::flow_login_html(StatusCode::OK, rendered.body, &nonce),
        None => pages::flow_html(StatusCode::OK, rendered.body),
    }
}
