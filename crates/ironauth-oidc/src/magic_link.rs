// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scanner-safe magic-link factor (issue #68): send a single-use link, render a
//! confirmation page on the GET, and consume the link only on the POST from that page.
//!
//! # The scanner-safe design (the differentiator)
//!
//! Enterprise email security scanners PREFETCH URLs, consuming single-use magic links
//! before the human clicks. This module never lets a GET consume:
//!
//! - **GET renders a confirmation page only.** [`confirm_get`] returns an HTML page whose
//!   only action is a POST button. A scanner following the link (GET, HEAD, or a
//!   link-following bot) gets the page and changes NOTHING; the human POST path still
//!   succeeds afterward. This is the core acceptance property.
//! - **The token can ride the URL FRAGMENT.** Per deployment, the token is placed after
//!   `#`, which a browser NEVER sends to the server, so the token stays out of server
//!   access logs and scanner request paths. A nonce-guarded page script reads it from
//!   `location.hash` and submits it on the POST.
//! - **Same-device binding with a cross-device fallback.** A binding cookie set at send
//!   time ties consumption to the requesting browser. When the cookie is absent (the link
//!   was opened on another device), the POST renders the cross-device page and the user
//!   completes login by entering the short code printed in the same email on the
//!   originating device (which holds the cookie).
//! - **Digest-only, single-use tokens.** The token is `ira_mlk_<id>~<secret>` from CSPRNG
//!   entropy; only its SHA-256 digest is stored (issue #29), and consumption is a guarded
//!   single-use UPDATE. The short code is stored as an Argon2id hash (issue #62).

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ironauth_store::{
    CorrelationId, MagicLinkConsumeOutcome, MagicLinkTokenId, NewMagicLink, Scope, UserId,
    magic_link_binding_digest, magic_link_token_digest,
};
use serde::Deserialize;

use crate::authn::AuthenticationEvent;
use crate::email_otp::{attempt_context, generate_numeric_code, purpose_or_login};
use crate::interaction::{self, cookie_header};
use crate::pages;
use crate::session;
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::verification::MagicLinkMessage;
use crate::wellknown::parse_scope;

/// The magic-link token wire prefix (issue #68): `ira_mlk_<id>~<secret>`, mirroring the
/// other `ira_*` reference credentials. The `<id>` is the scope-declaring `mlk_` handle.
const MAGIC_LINK_PREFIX: &str = "ira_mlk_";
/// The token wire delimiter between the routing handle and the secret.
const MAGIC_LINK_DELIMITER: char = '~';
/// The token secret width in bytes (256 bits), like the opaque access/refresh tokens.
const MAGIC_LINK_SECRET_BYTES: usize = 32;
/// The same-device binding secret width in bytes (128 bits, hex-encoded for the cookie).
const MAGIC_BINDING_SECRET_BYTES: usize = 16;

/// The send-magic-link request body.
#[derive(Deserialize)]
pub struct SendBody {
    /// The recipient identifier (an email address). An identifier matching no account is
    /// SUPPRESSED with a uniform ack (the binding cookie is set either way, so cookie
    /// presence is never an existence oracle).
    pub identifier: Option<String>,
    /// The flow the link authorizes. Defaults to `login`.
    pub purpose: Option<String>,
}

/// The GET confirmation-page query (QUERY-token mode only).
#[derive(Deserialize)]
pub struct ConfirmQuery {
    /// The single-use token, when the deployment carries it in the query string. In
    /// FRAGMENT mode this is absent and the page reads the token from `location.hash`.
    pub token: Option<String>,
}

/// The POST consume form (from the confirmation page or the originating device).
#[derive(Deserialize)]
pub struct ConsumeForm {
    /// The single-use token (the same-device path).
    pub token: Option<String>,
    /// The cross-device short code entered on the originating device.
    pub short_code: Option<String>,
}

/// `POST /t/{tenant}/e/{environment}/magic/send`: issue and send a scanner-safe magic
/// link plus its cross-device short code, and SET the same-device binding cookie. The
/// binding cookie is set for EVERY request (present and unknown recipient alike), so its
/// presence is never an existence oracle. Abuse-throttled per recipient and per tenant;
/// a send to an unknown recipient is SUPPRESSED with an identical acknowledgment.
pub async fn send(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(body): Form<SendBody>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return interaction::invalid_link_page();
    };
    if !state.magic_link_enabled() {
        return interaction::invalid_link_page();
    }
    if let Some(response) = state.enforce_request_quota(&scope) {
        return response;
    }
    let Some(purpose) = purpose_or_login(body.purpose.as_deref()) else {
        return ack_page();
    };
    let identifier = body
        .identifier
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();

    // The binding secret and its cookie are minted for EVERY request, so cookie presence
    // never distinguishes a known from an unknown recipient.
    let binding_secret = generate_hex(&state, MAGIC_BINDING_SECRET_BYTES);
    let binding_cookie =
        session::build_magic_binding_cookie(&binding_secret, state.magic_link_ttl());

    if identifier.is_empty() {
        return set_cookie(ack_page(), &binding_cookie);
    }

    // Throttle the SEND per recipient and per tenant before resolving existence (#64).
    let ctx = attempt_context(scope, purpose, identifier, &headers);
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = ack_page();
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return set_cookie(response, &binding_cookie);
    }

    let user = state
        .store()
        .scoped(scope)
        .users()
        .by_identifier(identifier)
        .await
        .ok()
        .flatten();

    if let Some(user) = user {
        let id = MagicLinkTokenId::generate(state.env(), &scope);
        let token = generate_token(&state, &id);
        let short_code = generate_numeric_code(&state, state.magic_link_short_code_digits());
        let short_code_hash = match state.hash_password(&scope, &short_code).await {
            Ok(hash) => hash,
            Err(rejection) => return rejection.to_response(),
        };
        let ttl = state.magic_link_ttl();
        let now = epoch_micros(state.now());
        let expires = now.saturating_add(i64::try_from(ttl.as_micros()).unwrap_or(i64::MAX));
        let spec = NewMagicLink {
            id: &id,
            subject: &user.id,
            purpose,
            token_digest: &magic_link_token_digest(&token),
            short_code_hash: &short_code_hash,
            binding_digest: &magic_link_binding_digest(&binding_secret),
            recipient_email: identifier,
            expires_at_unix_micros: expires,
        };
        let issued = state
            .store()
            .scoped(scope)
            .acting(
                interaction::user_actor(&user.id),
                CorrelationId::generate(state.env()),
            )
            .magic_links()
            .issue(state.env(), spec, now)
            .await;
        if issued.is_err() {
            tracing::error!(target: "ironauth.verification", "magic link issue failed");
            return set_cookie(ack_page(), &binding_cookie);
        }
        let link = confirm_link(&state, scope, &token);
        let message = MagicLinkMessage {
            scope,
            purpose,
            recipient: identifier,
            link: &link,
            short_code: &short_code,
            ttl_secs: ttl.as_secs(),
        };
        state.deliver_magic_link(&message, true);
    } else {
        let message = MagicLinkMessage {
            scope,
            purpose,
            recipient: identifier,
            link: "",
            short_code: "",
            ttl_secs: state.magic_link_ttl().as_secs(),
        };
        state.deliver_magic_link(&message, false);
    }
    set_cookie(ack_page(), &binding_cookie)
}

/// `GET /t/{tenant}/e/{environment}/magic/confirm`: render the SCANNER-SAFE confirmation
/// page. This NEVER consumes the link (a prefetching scanner following the link changes
/// nothing); consumption happens only on the POST from this page. In FRAGMENT mode the
/// token is read from `location.hash` by the nonce-guarded page script, so the server
/// never sees it in the GET.
pub async fn confirm_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    Query(query): Query<ConfirmQuery>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return interaction::invalid_link_page();
    };
    if !state.magic_link_enabled() {
        return interaction::invalid_link_page();
    }
    let consume_action = format!(
        "/t/{}/e/{}/magic/consume",
        scope.tenant(),
        scope.environment()
    );
    let fragment_mode = state.magic_link_fragment_mode();
    if fragment_mode {
        // A per-response nonce authorizes exactly the one fragment-reading script.
        let nonce = script_nonce(&state);
        let body = pages::magic_confirm_page(&consume_action, None, true, &nonce);
        pages::login_html(StatusCode::OK, body, &nonce)
    } else {
        let token = query.token.as_deref();
        let body = pages::magic_confirm_page(&consume_action, token, false, "");
        pages::secure_html(StatusCode::OK, body)
    }
}

/// `POST /t/{tenant}/e/{environment}/magic/consume`: consume the single-use link and
/// establish a session. Same-origin gated (CSRF). With the binding cookie present, the
/// token path consumes; without it, the token path renders the cross-device page and the
/// user finishes with the short code on the originating device.
pub async fn consume_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<ConsumeForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return interaction::invalid_link_page();
    };
    if !state.magic_link_enabled() {
        return interaction::invalid_link_page();
    }
    if let Some(response) = state.enforce_request_quota(&scope) {
        return response;
    }
    // CSRF defense-in-depth: a conclusively cross-site POST is a generic 403, before any
    // consumption (issue #196). A scanner cannot forge a same-origin POST.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }

    // Throttle the consume per source IP (the token is high-entropy; this bounds abuse).
    let ctx = crate::abuse::AttemptContext {
        path: ironauth_store::AuthPath::Password,
        scope,
        ip: crate::abuse::resolved_client_ip(&headers),
        identifier: None,
        account_id: None,
        client_id: None,
    };
    if let crate::abuse::RegulationOutcome::Throttled(snapshot) = state.regulate_before(&ctx).await
    {
        let mut response = pages::secure_html(
            StatusCode::TOO_MANY_REQUESTS,
            pages::notice_page(
                "Too many attempts",
                "Too many attempts. Please wait a moment and try again.",
            ),
        );
        crate::abuse::stamp_rate_limit_headers(&mut response, &snapshot);
        return response;
    }

    let binding =
        session::magic_binding_from_cookie_header(cookie_header(&headers)).map(str::to_owned);
    let now = epoch_micros(state.now());

    let short_code = form
        .short_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let token = form
        .token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(short_code) = short_code {
        consume_cross_device(
            &state,
            scope,
            short_code,
            binding.as_deref(),
            &ctx,
            &headers,
            now,
        )
        .await
    } else if let Some(token) = token {
        consume_same_device(
            &state,
            scope,
            token,
            binding.as_deref(),
            &ctx,
            &headers,
            now,
        )
        .await
    } else {
        invalid_page()
    }
}

/// The CROSS-DEVICE short-code consume path (issue #68): entered on the ORIGINATING device
/// (which holds the binding cookie), so it requires the cookie, resolves the link by its
/// binding, verifies the printed short code through the hashing pool, and consumes it.
#[allow(clippy::too_many_arguments)]
async fn consume_cross_device(
    state: &OidcState,
    scope: Scope,
    short_code: &str,
    binding: Option<&str>,
    ctx: &crate::abuse::AttemptContext,
    headers: &HeaderMap,
    now: i64,
) -> Response {
    let Some(binding) = binding else {
        return invalid_page();
    };
    let binding_digest = magic_link_binding_digest(binding);
    let challenge = match state
        .store()
        .scoped(scope)
        .magic_links()
        .resolve_by_binding(&binding_digest, now)
        .await
    {
        Ok(Some(challenge)) => challenge,
        Ok(None) => {
            let _ = state.verify_absent(&scope, short_code).await;
            return invalid_page();
        }
        Err(_) => return interaction::server_error_page(),
    };
    let matched = match state
        .verify_password(&scope, short_code, &challenge.short_code_hash)
        .await
    {
        Ok(matched) => matched,
        Err(rejection) => return rejection.to_response(),
    };
    if !matched {
        return invalid_page();
    }
    finish_consume(state, scope, &challenge, ctx, headers, now).await
}

/// The SAME-DEVICE token consume path (issue #68). Without the binding cookie the link was
/// opened on a different device: DO NOT consume; render the cross-device fallback page.
#[allow(clippy::too_many_arguments)]
async fn consume_same_device(
    state: &OidcState,
    scope: Scope,
    token: &str,
    binding: Option<&str>,
    ctx: &crate::abuse::AttemptContext,
    headers: &HeaderMap,
    now: i64,
) -> Response {
    let Some(binding) = binding else {
        return pages::secure_html(StatusCode::OK, pages::magic_cross_device_page());
    };
    let binding_digest = magic_link_binding_digest(binding);
    let challenge = match state
        .store()
        .scoped(scope)
        .magic_links()
        .resolve_by_token(&magic_link_token_digest(token), &binding_digest, now)
        .await
    {
        Ok(Some(challenge)) => challenge,
        Ok(None) => return invalid_page(),
        Err(_) => return interaction::server_error_page(),
    };
    finish_consume(state, scope, &challenge, ctx, headers, now).await
}

/// Consume a resolved magic-link challenge single-use and, on success, establish the
/// session (issue #68). Shared by both consume paths.
async fn finish_consume(
    state: &OidcState,
    scope: Scope,
    challenge: &ironauth_store::MagicLinkChallenge,
    ctx: &crate::abuse::AttemptContext,
    headers: &HeaderMap,
    now: i64,
) -> Response {
    match state
        .store()
        .scoped(scope)
        .acting(
            interaction::subject_actor(state, scope, &challenge.subject),
            CorrelationId::generate(state.env()),
        )
        .magic_links()
        .consume_by_id(state.env(), challenge, now)
        .await
    {
        Ok(MagicLinkConsumeOutcome::Consumed { subject, .. }) => {
            establish_session_page(state, scope, &subject, ctx, headers).await
        }
        Ok(MagicLinkConsumeOutcome::NotFound) => invalid_page(),
        Err(_) => interaction::server_error_page(),
    }
}

/// Establish a session for a consumed magic link and render a success page that SETS the
/// session cookie, with the honest `amr` (issue #68).
async fn establish_session_page(
    state: &OidcState,
    scope: Scope,
    subject: &str,
    ctx: &crate::abuse::AttemptContext,
    headers: &HeaderMap,
) -> Response {
    // Defensive: the stored subject is a `usr_` id this bootstrap minted.
    if UserId::parse_in_scope(subject, &scope).is_err() {
        return interaction::server_error_page();
    }
    let event = AuthenticationEvent::email_otp(epoch_micros(state.now()));
    let actor = interaction::subject_actor(state, scope, subject);
    match interaction::establish_session(state, scope, subject, &event, actor, headers).await {
        Ok(cookies) => {
            state.reset_after_success(ctx).await;
            let page = pages::secure_html(
                StatusCode::OK,
                pages::notice_page(
                    "You are signed in",
                    "You have been signed in. You can close this page.",
                ),
            );
            interaction::attach_session_cookies(page, &cookies)
        }
        Err(_) => interaction::server_error_page(),
    }
}

/// Generate a magic-link token `ira_mlk_<id>~<secret>` (issue #68): the scope-declaring
/// handle plus 256 bits of CSPRNG entropy, mirroring the other `ira_*` reference tokens.
fn generate_token(state: &OidcState, id: &MagicLinkTokenId) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = [0_u8; MAGIC_LINK_SECRET_BYTES];
    state.env().entropy().fill_bytes(&mut bytes);
    format!(
        "{MAGIC_LINK_PREFIX}{id}{MAGIC_LINK_DELIMITER}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// A hex string of `bytes` random bytes from the CSPRNG entropy seam (issue #68), for the
/// binding secret and the CSP script nonce (both cookie-/token-safe characters).
fn generate_hex(state: &OidcState, bytes: usize) -> String {
    use std::fmt::Write as _;
    let mut buf = vec![0_u8; bytes];
    state.env().entropy().fill_bytes(&mut buf);
    let mut out = String::with_capacity(bytes * 2);
    for byte in buf {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A per-response CSP script nonce for the fragment-mode confirmation page (issue #68).
fn script_nonce(state: &OidcState) -> String {
    generate_hex(state, 16)
}

/// The absolute confirmation-page link the email carries (issue #68). In FRAGMENT mode the
/// token rides the `#` fragment (never sent to the server); otherwise the query string.
fn confirm_link(state: &OidcState, scope: Scope, token: &str) -> String {
    let base = state.self_origin().unwrap_or_default();
    let path = format!(
        "/t/{}/e/{}/magic/confirm",
        scope.tenant(),
        scope.environment()
    );
    if state.magic_link_fragment_mode() {
        format!("{base}{path}#{token}")
    } else {
        format!(
            "{base}{path}?token={}",
            crate::util::percent_encode_query(token)
        )
    }
}

/// Attach a `Set-Cookie` header to a response.
fn set_cookie(mut response: Response, cookie: &str) -> Response {
    if let Ok(value) = axum::http::HeaderValue::from_str(cookie) {
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, value);
    }
    response
}

/// The UNIFORM send acknowledgment page (issue #68): identical whether the recipient
/// exists, is unknown, or the send succeeded.
fn ack_page() -> Response {
    pages::secure_html(
        StatusCode::OK,
        pages::notice_page(
            "Check your email",
            "If an account exists for that address, we have sent a sign-in link and code.",
        ),
    )
}

/// The uniform, non-enumerating invalid / expired / already-consumed link page, with a
/// resend path (issue #68).
fn invalid_page() -> Response {
    pages::secure_html(
        StatusCode::BAD_REQUEST,
        pages::notice_page(
            "Link no longer valid",
            "This sign-in link is invalid, expired, or already used. Request a new one to continue.",
        ),
    )
}
