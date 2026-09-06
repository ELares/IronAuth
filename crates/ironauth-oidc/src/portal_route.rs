// SPDX-License-Identifier: MIT OR Apache-2.0

//! Redeeming a self-service portal link into a session (issue #140).
//!
//! # Two routes, and the split is the whole design
//!
//! `GET` renders a confirmation page and consumes NOTHING. `POST` consumes the link and opens
//! the session. That is not a REST nicety: an IT admin receives this link by email, and
//! enterprise mail scanners follow links in mail they are inspecting. A link burned on GET is
//! dead before its recipient clicks it, and because it is single-use by design there is no
//! second attempt -- the vendor mints another, and the onboarding this feature exists to make
//! self-service acquires a support ticket. Migration 0048 records the same failure for magic
//! links; this is that lesson applied on the way in.
//!
//! It is also what makes the POST safe to have side effects at all. The GET is a navigation
//! anybody's software may perform on a URL it merely saw; the POST is an act.
//!
//! # What the browser holds afterwards, and what it does not
//!
//! The session's authority is a `__Host-` cookie whose SHA-256 the row holds. The token from the
//! link is spent by the redemption and never stored, so the URL in the admin's history and in
//! every mail scanner's log is inert the moment this returns.
//!
//! THE COOKIE IS NOT THE SESSION'S REACH. The organization and the intent live on the row and
//! are copied there from the link inside the redeeming transaction, so nothing the browser
//! presents can widen them. A holder can prove which session they are; they cannot say what it
//! is for.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse as _;
use axum::response::Response;
use ironauth_store::{
    AuthenticatedPortalSession, NewPortalSession, OrganizationId, PortalLinkId, PortalSessionId,
    Scope, StoreError,
};
use serde::Deserialize;

use std::fmt::Write as _;

use crate::interaction;
use crate::pages::escape_html;
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::parse_scope;

/// How long a portal session lasts, in seconds.
///
/// THIRTY MINUTES, deliberately much longer than the link's five. The two horizons measure
/// different things: the link bounds how long somebody has to START, because it travels out of
/// band through tickets and mail that keep copies; the session bounds how long they may
/// CONTINUE, and an admin configuring SSO has to go and log into their identity provider, copy
/// values back and forth, and often wait for a colleague. Giving the session the link's five
/// minutes would time out the actual work; giving the link the session's thirty would leave a
/// redeemable credential sitting in a mailbox for half an hour.
const SESSION_TTL_SECS: i64 = 1800;

/// The cookie carrying a portal session.
///
/// `__Host-` forbids a `Domain` and pins `Path=/`, so the cookie cannot be written by a sibling
/// subdomain and is offered to exactly one origin. A FIXED NAME rather than one per session:
/// the name is a storage slot, and one slot means opening a second portal session in the same
/// browser replaces the first rather than leaving two cookies whose order decides which wins.
const SESSION_COOKIE: &str = "__Host-ironauth_portal_session";

/// The token a redemption presents.
#[derive(Debug, Deserialize)]
pub struct RedeemQuery {
    /// The link's bearer value, from the URL the vendor handed over.
    #[serde(default)]
    t: String,
}

/// `GET /t/{tenant_id}/e/{environment_id}/portal/{link_id}`: confirm before redeeming.
///
/// CONSUMES NOTHING, and it does not even look the link up. A lookup would answer differently
/// for a live link than for an unknown one, which hands anybody who can see the URL -- every
/// mail scanner between the vendor and the admin among them -- an oracle for whether the link
/// is still good. The page is the same for every id, and the POST is where the truth is.
pub async fn confirm_get(
    Path((tenant_id, environment_id, link_id)): Path<(String, String, String)>,
    Query(query): Query<RedeemQuery>,
) -> Response {
    // THE TOKEN IS ECHOED INTO A HIDDEN FIELD so the POST carries it without it having to
    // survive anywhere else. It is escaped because it lands in HTML; it is a base64url value in
    // every legitimate case, but "the only values that reach here are well formed" is exactly
    // the assumption an attacker is paid to break.
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Configure your organization</title>\
         <h1>Configure your organization</h1>\
         <p>Your identity provider settings are managed here. This link works once.</p>\
         <form method=\"post\" action=\"/t/{tenant}/e/{environment}/portal/{link}\">\
         <input type=\"hidden\" name=\"t\" value=\"{token}\">\
         <button type=\"submit\">Continue</button>\
         </form>",
        tenant = escape_html(&tenant_id),
        environment = escape_html(&environment_id),
        link = escape_html(&link_id),
        token = escape_html(&query.t),
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// The form the confirmation page posts.
#[derive(Debug, Deserialize)]
pub struct RedeemForm {
    /// The link's bearer value.
    #[serde(default)]
    t: String,
}

/// `POST /t/{tenant_id}/e/{environment_id}/portal/{link_id}`: redeem and open a session.
pub async fn redeem_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, link_id)): Path<(String, String, String)>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<RedeemForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    // CSRF, BEFORE ANY CONSUMPTION, and its absence was the defect. This is the crate's check --
    // roughly thirty state-changing browser POSTs call it -- and this handler extracted the
    // headers and threw them away.
    //
    // `SameSite=Lax` PROTECTS NOTHING HERE, which is the part worth stating because it looks
    // like it should. SameSite governs whether a browser SENDS an existing cookie; this request
    // sends none, it MINTS one. A cross-site top-level POST is allowed to store a Lax cookie,
    // and the 303's follow-up navigation then carries it. `register.rs` records the identical
    // reasoning for the identical handler shape.
    //
    // WHAT IT COSTS AN ATTACKER OTHERWISE: anyone holding an unredeemed link -- their own, or
    // one seen in a forwarded ticket or a mail scanner's log -- auto-submits it from a page a
    // victim opens. The victim's browser stores a portal session for the ATTACKER'S
    // organization, and because the cookie name is a single fixed slot it also overwrites the
    // victim's own live session, whose link is single-use and already spent. That is the exact
    // "spent link, dead page, no recovery" state this slice exists to prevent, handed to a
    // third party as a weapon.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let Ok(link) = PortalLinkId::parse_in_scope(&link_id, &scope) else {
        return refused();
    };
    // THE TOKEN MAY ARRIVE IN THE FORM, and only there. Accepting it from the query string on
    // the POST as well would let a bare link be turned into a redeeming request by anything that
    // can cause a navigation, which is the property the GET/POST split exists to have.
    if form.t.is_empty() {
        return refused();
    }

    let now = epoch_micros(state.env().clock().now_utc());
    let session_id = PortalSessionId::generate(state.env(), &scope);
    // THE COOKIE VALUE IS MINTED FROM THE ENTROPY SEAM, like every other unguessable value in
    // this workspace, and base64url so it survives a cookie header without escaping.
    let mut cookie_bytes = [0_u8; 32];
    state.env().entropy().fill_bytes(&mut cookie_bytes);
    let cookie = {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cookie_bytes)
    };

    let redeemed = state
        .store()
        .scoped(scope)
        .portal_links()
        .redeem_into_session(
            &link,
            &sha256(form.t.as_bytes()),
            NewPortalSession {
                id: &session_id,
                token_digest: &sha256(cookie.as_bytes()),
                expires_at_unix_micros: now + SESSION_TTL_SECS * 1_000_000,
            },
            now,
        )
        .await;
    match redeemed {
        Ok(_) => {}
        // UNKNOWN, EXPIRED, ALREADY USED AND WRONG TOKEN ARE ONE ANSWER. Telling them apart
        // would tell somebody replaying a captured link whether their first attempt worked.
        Err(StoreError::NotFound | StoreError::Conflict) => return refused(),
        Err(_) => return unavailable(),
    }

    // The old cookie, if the browser held one, is REPLACED rather than added to: one name is one
    // slot, so a second portal session in the same browser cannot leave two cookies whose order
    // decides which session a later request runs as.
    let set_cookie = format!(
        "{SESSION_COOKIE}={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; \
         Max-Age={SESSION_TTL_SECS}"
    );
    // 303, so the browser follows with a GET: a 302 after a POST leaves the method to the
    // client, and a re-POST here would present a token the redemption above already spent.
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, set_cookie),
            (header::LOCATION, portal_home(&scope)),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

/// A live portal session, resolved from the request's cookie.
///
/// # The three fences, in the order a request meets them
///
/// SCOPE, then ORGANIZATION, then INTENT. The scope comes from the path and bounds which
/// deployment's rows exist at all; the organization and the intent come from the SESSION ROW and
/// bound what this particular admin may touch. #140 requires the last two by name: "a portal
/// session for org A cannot read or mutate any org B state", and "an `sso` link cannot reach
/// SCIM or domain-verification surfaces".
///
/// NEITHER COMES FROM THE REQUEST, for a handler that takes a `PortalSession`: there is no
/// parameter to ask for a different organization with, so it receives the session's own or none.
///
/// THAT IS NOT THE SAME AS "or it does not compile", which an earlier version of this sentence
/// claimed and which is false. Nothing stops somebody mounting a portal route that takes the
/// organization from its own path and never mentions this type; it would compile, pass clippy,
/// and be outside every fence here. The type makes the safe path the easy one and makes an
/// unsafe one VISIBLE in a diff. It does not make it impossible, and saying otherwise is the
/// kind of claim that stops the next reader looking.
pub struct PortalSession {
    /// The session row, whose two fields are the whole authority.
    session: AuthenticatedPortalSession,
    /// The scope its path named, already agreed with the session's own.
    scope: Scope,
}

impl PortalSession {
    /// The ONE organization this session may act for.
    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.session.organization_id
    }

    /// The session row's handle, for attributing audit rows.
    #[must_use]
    pub fn id(&self) -> &PortalSessionId {
        &self.session.id
    }

    /// The scope this session belongs to.
    #[must_use]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The intent this session was opened for.
    ///
    /// A READ, for rendering. Deciding whether a surface may be reached is
    /// [`Self::require_intent`], which is a separate method on purpose: a handler that compares
    /// this itself and gets the comparison wrong looks exactly like one that got it right.
    #[must_use]
    pub fn intent(&self) -> &str {
        &self.session.intent
    }

    /// Refuse unless this session was opened for `intent`.
    ///
    /// THE INTENT FENCE, and it is a method rather than a field so that reaching a
    /// surface REQUIRES naming which surface it is. A handler that reads `self.intent` and
    /// forgets to compare it looks identical to one that compares it; a handler that never calls
    /// this has no intent check at all and says so by omission.
    ///
    /// # Errors
    ///
    /// The uniform not-found when the session carries a different intent. NOT a 403: a portal
    /// session that could tell "wrong surface" from "no such surface" would let an `sso` link
    /// enumerate which other surfaces this deployment serves.
    pub fn require_intent(&self, intent: &str) -> Result<(), PortalRefusal> {
        if self.session.intent == intent {
            return Ok(());
        }
        Err(PortalRefusal::NotFound)
    }
}

/// Resolve the request's cookie to a live session of `scope`, or refuse.
///
/// # Why this is a function and not a `FromRequestParts`
///
/// An axum extractor cannot see the path parameters of the route it is extracting for, and the
/// scope is in the path. An extractor that skipped the scope would resolve a cookie against
/// whatever environment it happened to belong to, which is precisely the confusion the
/// `authenticate` read exists to prevent: the digest is the lookup key, so a cookie from another
/// environment is a real row and only the scope predicate keeps it out.
///
/// So every portal handler passes the scope it parsed from its own path, and the two are
/// compared by the STATEMENT rather than by the caller.
///
/// # Errors
///
/// The uniform refusal for a missing cookie, an unknown one, an expired or revoked session, or
/// one belonging to another scope. Four different facts, one answer: distinguishing them tells
/// a holder of a stale cookie which of those it is.
pub async fn resolve_session(
    state: &OidcState,
    scope: Scope,
    headers: &HeaderMap,
) -> Result<PortalSession, PortalRefusal> {
    let Some(cookie) = cookie_value(headers, SESSION_COOKIE) else {
        return Err(PortalRefusal::NotFound);
    };
    let now = epoch_micros(state.env().clock().now_utc());
    match state
        .store()
        .scoped(scope)
        .portal_sessions()
        .authenticate(&sha256(cookie.as_bytes()), now)
        .await
    {
        Ok(session) => Ok(PortalSession { session, scope }),
        Err(StoreError::NotFound) => Err(PortalRefusal::NotFound),
        Err(_) => Err(PortalRefusal::Unavailable),
    }
}

/// One cookie's value out of the request headers.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|header| header.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
}

/// `POST /t/{tenant_id}/e/{environment_id}/portal/finish`: end this session now.
///
/// # Why it exists in this slice rather than the next
///
/// `PortalSessionRepo::revoke` shipped in the first draft of this change with NO caller, which
/// is a control nothing consults -- the shape this project has shipped repeatedly and the reason
/// the intent fence got a caller in the same commit. Either the method goes or something calls
/// it, and something should: an admin who has finished configuring should not be leaving a live
/// portal session in a browser on a machine that may be shared, for the remainder of half an
/// hour, with no way to end it.
///
/// SAME-ORIGIN GATED, like the redemption. Revocation is a smaller act than redemption -- the
/// worst a forged one does is log somebody out -- but it is still a state change a third party
/// should not be able to trigger, and the check costs nothing.
///
/// IT CLEARS THE COOKIE TOO, with a `Max-Age=0` on the same name. The row is what decides
/// authentication, so this is tidiness rather than the fence; leaving a cookie that names a
/// dead session behind would just mean the browser sends it and is refused.
pub async fn finish_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let session = match resolve_session(&state, scope, &headers).await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    let now = epoch_micros(state.env().clock().now_utc());
    if state
        .store()
        .scoped(scope)
        .portal_sessions()
        .revoke(session.id(), now)
        .await
        .is_err()
    {
        return unavailable();
    }
    let body = "<!doctype html><meta charset=\"utf-8\"><title>Finished</title>\
                <h1>You are signed out of the portal</h1>\
                <p>This session has ended. Ask your vendor for a new link if you need one.</p>"
        .to_owned();
    let cleared = format!("{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0");
    (
        [
            (header::SET_COOKIE, cleared),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        crate::pages::secure_html(StatusCode::OK, body),
    )
        .into_response()
}

/// `GET /t/{tenant_id}/e/{environment_id}/portal`: where a freshly opened session lands.
///
/// THE REDIRECT TARGET, and it exists in the same change as the redirect. A `303` to a path
/// nothing serves is a 404 at the end of a successful redemption: the link is spent, correctly,
/// and the admin sees a dead page with no way back -- the exact failure the atomic
/// redeem-and-open exists to prevent, reintroduced one layer up.
///
/// It shows the ONE surface this session's intent allows. A session cannot navigate outside its
/// intent, so offering the others would be offering doors that answer not-found.
pub async fn home_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    let session = match resolve_session(&state, scope, &headers).await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Your organization</title>\
         <h1>Configure your organization</h1>\
         <p>Organization: {organization}</p>\
         <p><a href=\"/t/{tenant}/e/{environment}/portal/s/{intent}\">{intent}</a></p>",
        organization = escape_html(&session.organization().to_string()),
        tenant = escape_html(&tenant_id),
        environment = escape_html(&environment_id),
        intent = escape_html(session.intent()),
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// `GET /t/{tenant_id}/e/{environment_id}/portal/s/{intent}`: one configuration surface.
///
/// # What this is for
///
/// The SCIM panel is here now (see `scim_surface` below). The others -- the SSO connection
/// editor and domain verification -- land in later slices of #140. What landed FIRST is the
/// FENCE they all sit behind, with a caller, because a fence shipped without one is a control
/// nothing consults and this project has shipped that shape repeatedly. An intent with no panel
/// yet renders a placeholder; what the fence proves either way is that a session opened for one
/// intent is refused at another, which is an acceptance criterion of #140.
pub async fn surface_get(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id, intent)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    let session = match resolve_session(&state, scope, &headers).await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    // THE INTENT FENCE. An `sso` session asking for `scim` gets the same not-found an unknown
    // surface gets, so a link cannot be used to enumerate which surfaces this deployment serves.
    if let Err(refusal) = session.require_intent(&intent) {
        return refusal.into_response();
    }
    if intent == "scim" {
        return scim_surface(&state, &session).await;
    }
    // THE OTHER INTENTS STILL RENDER THEIR PLACEHOLDER. `sso` and `domain-verification` land in
    // later slices of #140, and the fence above has already refused an intent this session does
    // not carry, so what reaches here is a surface this deployment serves and has not built yet.
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{intent}</title>\
         <h1>{intent}</h1>\
         <p>Organization: {organization}</p>",
        intent = escape_html(&intent),
        organization = escape_html(&session.organization().to_string()),
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// The SCIM configuration surface: what this organization's provisioning credentials are doing.
///
/// # What an IT admin came here to find out
///
/// Whether provisioning is working, and if it is going to stop, when. Those are two different
/// questions and the page answers them separately, because a connection with no working
/// credential and one whose credential never expires publish the same absent deadline and only
/// one of them needs somebody today.
///
/// THE ANSWERS ARE THE ROW'S OWN. `ScimConnection::no_live_credential` and
/// `stops_provisioning_soon` are what the management API's listing reports to the vendor's
/// operator, and this page calls the same two methods with the same lead time -- which reaches
/// this plane as a declared cross-plane value for exactly that reason. A copy of the rule here
/// would let one connection be "expiring" in the vendor's console and "healthy" in their
/// customer's portal, with nobody positioned to see both.
///
/// # It says nothing it cannot stand behind
///
/// The provisioning base URL is printed only when this deployment actually serves `/scim/v2`.
/// With the surface off it is a uniform 404, and nothing stops a `scim` portal link being minted
/// on such a deployment, so the page says the surface is unavailable rather than handing over an
/// address that answers nothing.
///
/// # It reads and does not write
///
/// Rotation is not offered, and its absence is deliberate rather than unfinished: this plane
/// authenticates as the data-plane role, which holds `SELECT` and nothing else on both SCIM
/// tables. Migration 0205 argues the case -- a provisioning credential that could mint another
/// provisioning credential is an escalation with no operator in the loop -- so offering rotation
/// from here is a grant decision, not a page.
async fn scim_surface(state: &OidcState, session: &PortalSession) -> Response {
    let now = epoch_micros(state.env().clock().now_utc());
    let read = state
        .store()
        .scoped(session.scope())
        .scim_connections()
        // ONE MORE THAN THE PAGE SHOWS, so a longer list can be REPORTED as longer rather than
        // silently cut. A page titled "your connections" that quietly drops some is worse than
        // one that admits its bound.
        .list_for_organization(session.organization(), PORTAL_LIST_LIMIT + 1, None, now)
        .await;
    // THE ORGANIZATION IS THE SESSION'S, so a failure here is not an addressing mistake a holder
    // could have made; it is this deployment failing to read its own row.
    let Ok(connections) = read else {
        return PortalRefusal::Unavailable.into_response();
    };

    let lead = state.scim_token_expiry_warning_secs();
    let truncated = connections.len() > usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX);
    let shown = connections
        .iter()
        .take(usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX));
    let mut rows = String::new();
    for connection in shown {
        let status = if connection.revoked {
            "Revoked".to_owned()
        } else if connection.no_live_credential() {
            "Provisioning has stopped: no working token".to_owned()
        } else if let Some(deadline) = connection.provisioning_stops_at_unix_micros {
            let when = crate::saml_start::rfc3339_utc(deadline / 1_000_000);
            if connection.stops_provisioning_soon(now, lead) {
                format!("Stops working {when}")
            } else {
                format!("Active until {when}")
            }
        } else {
            "Active".to_owned()
        };
        let _ = write!(
            rows,
            "<tr><td>{name}</td><td>{provider}</td><td>{status}</td></tr>",
            name = escape_html(&connection.display_name),
            provider = escape_html(&connection.provider),
            status = escape_html(&status),
        );
    }
    if connections.is_empty() {
        rows.push_str("<tr><td colspan=\"3\">No provisioning connections yet.</td></tr>");
    }
    if truncated {
        let _ = write!(
            rows,
            "<tr><td colspan=\"3\">Showing the first {PORTAL_LIST_LIMIT}. \
             Ask your vendor for the rest.</td></tr>"
        );
    }

    // THE URL IS PRINTED ONLY WHERE IT IS SERVED. With `scim.enabled` off, `/scim/v2` is a
    // uniform 404 on this deployment, and nothing stops a portal link with the `scim` intent
    // being minted anyway -- link minting never consults the flag. A page that printed the URL
    // regardless would send an IT admin to configure their identity provider against an endpoint
    // that answers nothing, and the failure would surface days later as "provisioning never
    // started" with the portal's own instructions as evidence that it should have.
    let endpoint = if state.scim_surface_enabled() {
        format!(
            "<h2>Where your provisioning client connects</h2><p><code>{base}/scim/v2</code></p>",
            base = escape_html(state.issuer_base()),
        )
    } else {
        "<h2>Where your provisioning client connects</h2>\
         <p>This deployment does not serve inbound provisioning. Ask your vendor to enable it.</p>"
            .to_owned()
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Provisioning</title>\
         <h1>Provisioning</h1>\
         <p>Organization: {organization}</p>\
         {endpoint}\
         <h2>Your connections</h2>\
         <table><thead><tr><th>Name</th><th>Provider</th><th>Status</th></tr></thead>\
         <tbody>{rows}</tbody></table>",
        organization = escape_html(&session.organization().to_string()),
        endpoint = endpoint,
        rows = rows,
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// How many connections one portal page renders.
///
/// An organization has a handful of provisioning connections, not a page of them, and this
/// surface has no pagination controls. The read asks for one MORE than this, so a longer list is
/// reported as truncated instead of quietly losing rows: a page an admin reads as "these are my
/// connections" must not be missing the one they came to look at without saying so.
const PORTAL_LIST_LIMIT: i64 = 100;

/// Where a freshly opened session lands.
fn portal_home(scope: &Scope) -> String {
    format!("/t/{}/e/{}/portal", scope.tenant(), scope.environment())
}

/// SHA-256, which is what every portal row stores in place of a bearer value.
fn sha256(value: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(value).to_vec()
}

/// Why a portal request was refused.
///
/// A TINY TYPE RATHER THAN A WHOLE `Response` IN THE `Err`, which is what this started as: a
/// `Result<_, Response>` carries a hundred-odd bytes of failure down every success path, and
/// clippy says so. It also reads better -- a fence answers WHY, and rendering is the caller's
/// job -- but the reason it changed is the lint, and the lint was right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortalRefusal {
    /// The uniform not-found. A missing cookie, an unknown or lapsed session, a foreign scope
    /// and a wrong intent are ALL this: distinguishing them tells a holder something they did
    /// not know.
    NotFound,
    /// A persistence fault, which is deliberately NOT the uniform not-found: a database that is
    /// down must not read as "your link is spent", or the admin asks for a new link and the
    /// vendor debugs the wrong thing.
    Unavailable,
}

impl axum::response::IntoResponse for PortalRefusal {
    fn into_response(self) -> Response {
        match self {
            Self::NotFound => refused(),
            Self::Unavailable => unavailable(),
        }
    }
}

/// The uniform refusal.
///
/// ONE STATUS AND ONE BODY for a malformed scope, an unparsable id, a missing token, an unknown
/// link, an expired one, a spent one and a wrong token alike. Each of those is a different fact
/// about the request, and distinguishing any of them tells somebody holding a captured URL
/// something they did not know.
fn refused() -> Response {
    let body = "<!doctype html><meta charset=\"utf-8\"><title>Link unavailable</title>\
                <h1>This link cannot be used</h1>\
                <p>It may have expired or already been used. Ask for a new one.</p>"
        .to_owned();
    crate::pages::secure_html(StatusCode::NOT_FOUND, body)
}

/// A persistence fault, which is NOT the uniform refusal.
///
/// A database that is down must not read as "your link is spent": the admin would ask for a new
/// link, which would fail the same way, and the vendor would be debugging the wrong thing.
fn unavailable() -> Response {
    let body = "<!doctype html><meta charset=\"utf-8\"><title>Temporarily unavailable</title>\
                <h1>Temporarily unavailable</h1>\
                <p>This did not work just now. Your link has not been used; try again.</p>"
        .to_owned();
    crate::pages::secure_html(StatusCode::SERVICE_UNAVAILABLE, body)
}
