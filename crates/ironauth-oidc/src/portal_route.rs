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
    Query(filters): Query<AuditFilterQuery>,
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
    if intent == "certificate-renewal" {
        return certificate_renewal_surface(&state, &session).await;
    }
    if intent == "contacts" {
        return contacts_surface(&state, &session).await;
    }
    if intent == "audit" {
        return audit_surface(&state, &session, &filters).await;
    }
    if intent == "sso" {
        return sso_surface(&state, &session).await;
    }
    // THE OTHER INTENTS STILL RENDER THEIR PLACEHOLDER: `domain-verification` and
    // `log-streams`, which land in later slices of #140. The fence has already refused an intent
    // this session does not carry, so what reaches here is a surface this deployment serves and
    // has not built yet.
    //
    // NO COUNT OF THE CLOSED SET HERE. This sentence used to enumerate it -- "those three, plus
    // `scim` and `certificate-renewal` above" -- and every new intent made it false in a way
    // nothing checks: #1151 had to rewrite it, and #1156 landed with it still naming five values
    // for a set of six. The arms above ARE the list, and `portal_links::INTENTS` plus the two
    // CHECK constraints are what pin it.
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{intent}</title>\
         <h1>{intent}</h1>\
         <p>Organization: {organization}</p>",
        intent = escape_html(&intent),
        organization = escape_html(&session.organization().to_string()),
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// One table row per connection, each saying which state that connection is in.
///
/// NO COUNT HERE, deliberately. An earlier version of this line said "which of the five states",
/// which was wrong by two the day it was written -- the branch that added it had itself added an
/// arm -- and a number in this sentence is the one thing a reader auditing arm coverage would key
/// on. The arms below are the list.
///
/// Split out of `scim_surface` so the handler reads as the shape of the page rather than as the
/// wording of its rows; the reasoning for each branch lives at the branch.
fn connection_rows<'a>(
    connections: impl Iterator<Item = &'a ironauth_store::ScimConnection>,
    now: i64,
    lead: u64,
) -> String {
    let mut rows = String::new();
    for connection in connections {
        let status = if connection.revoked {
            "Revoked".to_owned()
        } else if connection.no_live_credential() {
            // WHICH KIND OF STOPPED IT IS decides the remedy, exactly as the deadline arm below
            // does. A connection past its own expiry cannot be rotated -- `rotate_token` refuses
            // it -- so telling this customer their token stopped working would point them at the
            // wrong half of the problem and at a request their vendor cannot fulfil.
            if connection
                .expires_at_unix_micros
                .is_some_and(|expires_at| expires_at <= now)
            {
                "Provisioning has stopped: this connection expired and must be replaced".to_owned()
            } else {
                "Provisioning has stopped: no working token".to_owned()
            }
        } else if let Some(deadline) = connection.credential_expires_at_unix_micros {
            let when = crate::saml_start::rfc3339_utc(deadline / 1_000_000);
            // WHICH DEADLINE IT IS DECIDES WHAT THE ADMIN CAN DO ABOUT IT, and the row carries the
            // discriminator: the published deadline is the LEAST of the connection's own expiry
            // and its soonest live token's, so when it equals the connection's own expiry that is
            // the arm that produced it.
            //
            // A TOKEN deadline is cleared by rotating -- during an overlap the superseded token
            // dies on this date while the fresh one carries on, so an outage warning there would
            // be a false alarm at the exact moment a successful cutover guaranteed otherwise.
            //
            // THE CONNECTION'S OWN EXPIRY IS CLEARED BY NOTHING. No path in this system writes
            // `scim_connections.expires_at`: migration 0183 grants the control role
            // `UPDATE (revoked_at, updated_at)` and no more, and rotating mints a token with no
            // horizon while leaving that column exactly where it was. So "renew before" there
            // names a remedy the customer can perform forever without moving the date, and on it
            // provisioning stops for good. That one has to say so, and say what actually helps.
            if connection.expires_at_unix_micros == Some(deadline) {
                format!("Provisioning stops {when}: ask your vendor to replace this connection")
            } else if connection.credential_expiring_soon(now, lead) {
                format!("Renew before {when}")
            } else {
                format!("Next deadline {when}")
            }
        } else {
            "Active".to_owned()
        };
        // WHAT HAS ACTUALLY HAPPENED, beside what is configured. A connection can be healthy in
        // every other column and have never received a request -- which is what pasting a token
        // into the wrong field looks like, and there is nothing else on this page that would
        // tell an admin so.
        let activity = if connection.revoked {
            // Nothing to act on: the operator switched this off, and a last-used time would only
            // invite the reader to wonder whether it is still working.
            String::new()
        } else if let Some(seen) = connection.last_seen_at_unix_micros {
            // IT HAS BEEN USED AT LEAST ONCE, so the question becomes WHICH credential. A newest
            // token nobody has presented means a rotation the customer has not finished: the
            // connection is plainly in use on the OLD one, and "last request two minutes ago"
            // would report exactly the health that ends when the overlap does.
            if connection.newest_token_used == Some(false) {
                "New token not used yet".to_owned()
            } else {
                format!(
                    "Last request {}",
                    crate::saml_start::rfc3339_utc(seen / 1_000_000)
                )
            }
        } else if connection.usage_history_complete {
            // EVERY CREDENTIAL HAS BEEN WATCHED SINCE IT EXISTED, so an absent stamp means what it
            // looks like: nothing has ever presented one. That is the diagnosis this column exists
            // for -- a token pasted into the wrong field, or the right field of the wrong
            // application -- and it is only assertable here.
            "No requests yet".to_owned()
        } else {
            // NOT OBSERVED, WHICH IS NOT THE SAME AS NOT USED, and the page must not collapse them.
            // Three populations land here: a connection with no token rows, which authenticates
            // through the fallback on `scim_connections.token_digest` and leaves nothing to stamp;
            // a connection whose rows predate migration 0206, which is the entire installed base
            // on upgrade day; and one that has just adopted a legacy credential by rotation, whose
            // earlier life went unwatched.
            //
            // ALL THREE MAY BE PROVISIONING RIGHT NOW. Saying "no requests yet" about them reports
            // a working connection as dead, and the admin's remedy would be to reconfigure
            // something already correct. An earlier version of this page said exactly that to the
            // whole installed base, and then -- after that was fixed for connections with no rows
            // at all -- said it again to any of them the moment a rotation gave them one.
            "Not recorded".to_owned()
        };
        let _ = write!(
            rows,
            "<tr><td>{name}</td><td>{provider}</td><td>{status}</td><td>{activity}</td></tr>",
            name = escape_html(&connection.display_name),
            provider = escape_html(&connection.provider),
            status = escape_html(&status),
            activity = escape_html(&activity),
        );
    }
    // NO ROW WAS WRITTEN, which is the same fact as an empty listing and is one this function
    // can see for itself rather than taking on trust from its caller.
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"4\">No provisioning connections yet.</td></tr>");
    }
    rows
}

/// One setup guide per connection, keyed on that connection's own provider.
fn setup_guides(
    state: &OidcState,
    connections: &[ironauth_store::ScimConnection],
    scim_base: &str,
    now: i64,
) -> String {
    // ONE GUIDE PER CONNECTION, keyed on that connection's own provider (issue #140 criterion 4:
    // "setup guides render per IdP with correct copy-paste values for the specific connection
    // being configured").
    //
    // PER CONNECTION RATHER THAN PER DISTINCT PROVIDER, and the case that separates those is TWO
    // CONNECTIONS OF THE SAME PROVIDER -- a customer migrating between two Okta tenants, or
    // running one for staging. Per-provider rendering gives them a single "Okta" section and no
    // way to tell which of their two connections it configures, which is precisely where a
    // vendor's generic documentation already leaves them. An earlier version of this comment
    // offered an Okta-plus-Entra organization as the justification; those differ by provider too,
    // so it demonstrated nothing about the choice.
    //
    // ONLY WHERE THE ENDPOINT IS SERVED. With the surface off the steps would tell a customer to
    // paste a URL this deployment answers 404 for, which is the same defect the endpoint
    // paragraph above already refuses to commit.
    //
    // AND NOT FOR A CONNECTION NOTHING CAN REVIVE. Two states qualify and an earlier version of
    // this filter named only the first:
    //
    //   * REVOKED, which an operator did on purpose.
    //   * LAPSED, meaning the connection is past its OWN `expires_at`. That one arrives by itself
    //     with nobody acting, and it is the worse of the two to be wrong about: `authenticate`
    //     requires `c.expires_at > now`, so no token the admin pastes will ever work, and the
    //     guide's own closing sentence tells them to ask their vendor to ROTATE -- which
    //     `rotate_token` refuses with a not-found for exactly this connection. The customer would
    //     do the work, watch it fail with no explanation, and ask for a remedy the product
    //     answers 404 to.
    //
    // IT IS KEYED ON THE CONNECTION'S OWN EXPIRY, not on `no_live_credential()`. The other way a
    // row reports no live credential is that its TOKENS are gone while the connection itself is
    // fine -- and there rotation works, the admin pastes the fresh token, and these steps are
    // exactly what they need. Suppressing the guide on the broader condition would hide it from
    // the one row it helps most.
    let mut guides = String::new();
    if state.scim_surface_enabled() {
        for connection in connections
            .iter()
            .take(usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX))
            .filter(|connection| {
                let lapsed = connection
                    .expires_at_unix_micros
                    .is_some_and(|expires_at| expires_at <= now);
                !connection.revoked && !lapsed
            })
        {
            let guide = crate::portal_guides::guide_for(&connection.provider, scim_base);
            let mut steps = String::new();
            for step in &guide.steps {
                let _ = write!(steps, "<li>{}</li>", escape_html(step));
            }
            let _ = write!(
                guides,
                "<details><summary>Set up {name} in {provider}</summary>\
                 <p>{where_to_go}</p><ol>{steps}</ol></details>",
                name = escape_html(&connection.display_name),
                provider = escape_html(guide.provider_name),
                where_to_go = escape_html(guide.where_to_go),
                steps = steps,
            );
        }
        if !guides.is_empty() {
            guides.insert_str(0, "<h2>Setting up your identity provider</h2>");
        }
    }
    guides
}

/// The token-check form, one per connection the page shows.
///
/// PER CONNECTION rather than one form with a picker, for the reason `setup_guides` gives about
/// guides: the reader is looking at a row, and a control that makes them re-select what they are
/// already looking at is a place to pick the wrong one. It also means the connection id reaches
/// the handler from the page rather than from the reader.
///
/// ON EVERY ROW, INCLUDING THE BROKEN ONES. A revoked or lapsed connection is exactly where a
/// reader holding a token wants to know what it is: the handler answers "this connection was
/// revoked" rather than "your token is wrong", which is the distinction the whole surface exists
/// to draw.
fn token_check_forms(state: &OidcState, connections: &[ironauth_store::ScimConnection]) -> String {
    // ONLY WHERE THE ENDPOINT IS SERVED, exactly as the provisioning URL above it is. With
    // `scim.enabled` off this deployment answers `/scim/v2` with a uniform 404, so no token
    // authenticates anything here however healthy its row is -- and the check would have told a
    // reader "this token authenticates against this connection", which is a sentence about a
    // credential table rather than about provisioning. They would go away satisfied and nothing
    // would ever call.
    if !state.scim_surface_enabled() {
        return String::new();
    }
    let Some(scope) = state_scope(connections) else {
        return String::new();
    };
    let mut forms = String::new();
    for connection in connections
        .iter()
        .take(usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX))
    {
        let _ = write!(
            forms,
            "<form method=\"post\" \
             action=\"{base}/t/{tenant}/e/{environment}/portal/s/scim/test\">\
             <input type=\"hidden\" name=\"connection_id\" value=\"{connection}\">\
             <p><label>Paste the token you configured for {name} to find out what it is \
             here:<br><input type=\"password\" name=\"token\" size=\"60\"></label></p>\
             <p><button type=\"submit\">Check this token</button></p></form>",
            base = escape_html(state.issuer_base().trim_end_matches('/')),
            tenant = escape_html(&scope.tenant().to_string()),
            environment = escape_html(&scope.environment().to_string()),
            connection = escape_html(&connection.id.to_string()),
            name = escape_html(&connection.display_name),
        );
    }
    if !forms.is_empty() {
        forms.insert_str(0, "<h2>Check a token</h2>");
    }
    forms
}

/// The scope every connection on this page shares, or `None` when there are no connections.
///
/// TAKEN FROM A ROW rather than from the session, because the ids printed into the forms are
/// those rows' ids and a form whose path named a different scope than its `connection_id` would
/// be refused by the handler's own parse. They cannot differ today -- the listing is scoped --
/// and deriving it from the thing being printed is what keeps that true if the listing ever is
/// not.
fn state_scope(connections: &[ironauth_store::ScimConnection]) -> Option<ironauth_store::Scope> {
    connections.first().map(|connection| connection.id.scope())
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
/// `credential_expiring_soon` are what the management API's listing reports to the vendor's
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
/// authenticates as the data-plane role, which on the two SCIM tables holds `SELECT` plus exactly
/// one column-scoped write, `scim_connection_tokens.last_seen_at` (migration 0206), and nothing
/// that could mint or extend a credential. Migration 0205 argues the case -- a provisioning
/// credential that could mint another provisioning credential is an escalation with no operator
/// in the loop -- so offering rotation from here is a grant decision, not a page.
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
    // DERIVED ONCE, and used by the paragraph above the table AND by every setup guide below it.
    // Two derivations of one deployment's endpoint is how a page comes to print two different
    // URLs, and the guides are the half a customer actually pastes from.
    let scim_base = format!("{}/scim/v2", state.issuer_base());
    let truncated = connections.len() > usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX);
    let shown = connections
        .iter()
        .take(usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX));
    let mut rows = connection_rows(shown, now, lead);
    let guides = setup_guides(state, &connections, &scim_base, now);

    if truncated {
        let _ = write!(
            rows,
            "<tr><td colspan=\"4\">Showing the first {PORTAL_LIST_LIMIT}. \
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
            "<h2>Where your provisioning client connects</h2><p><code>{base}</code></p>",
            base = escape_html(&scim_base),
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
         <table><thead><tr><th>Name</th><th>Provider</th><th>Status</th><th>Activity</th>\
         </tr></thead>\
         <tbody>{rows}</tbody></table>\
         {checks}{guides}",
        organization = escape_html(&session.organization().to_string()),
        endpoint = endpoint,
        rows = rows,
        checks = token_check_forms(state, &connections),
        guides = guides,
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// The certificate-renewal surface (issue #141 criterion 2).
///
/// # What this page is for
///
/// It is handed to whoever administers the customer's IdP, usually because an expiry notice told
/// them to replace a signing certificate. That person is frequently not the person who set SSO
/// up, which is why this is its own intent rather than a corner of the `sso` page: a link that
/// lands on the full configuration surface would give its holder every other setting on the
/// connection as well.
///
/// # Overlap is the existing behaviour, not something this page adds
///
/// A connection may have several certificates pinned at once, and `saml_acs` verifies an
/// assertion against EVERY one of them. So the rollover a renewal needs -- old and new both
/// accepted while the IdP switches over -- is what pinning a second certificate already does.
/// What this page owes is showing the holder which certificates are currently trusted and when
/// each stops mattering, so they can tell whether the new one has landed.
///
/// # Two lists, and only one of them is unbounded
///
/// The CERTIFICATES on a connection are shown whole: that number is bounded by what an IdP
/// publishes -- one, or two during a rollover -- so a page bound there would bound nothing, and
/// truncating trust material quietly is exactly the wrong thing to do.
///
/// The CONNECTIONS are not. An organization can have more than a page of them, so this reads one
/// more than it shows and SAYS SO when there are more, the way the SCIM surface does. An earlier
/// version of this paragraph claimed the page had no bound at all, which was true of the inner
/// list and false of the outer one it actually pages.
async fn certificate_renewal_surface(state: &OidcState, session: &PortalSession) -> Response {
    let now = epoch_micros(state.env().clock().now_utc());
    let read = state
        .store()
        .scoped(session.scope())
        .saml_connections()
        .list_for_org(session.organization(), PORTAL_LIST_LIMIT + 1, None)
        .await;
    // THE ORGANIZATION IS THE SESSION'S, so a failure is this deployment failing to read its own
    // row rather than an addressing mistake the holder could have made.
    let Ok(connections) = read else {
        return PortalRefusal::Unavailable.into_response();
    };

    let mut body = String::from(
        "<!doctype html><meta charset=\"utf-8\"><title>Certificate renewal</title>\
         <h1>Certificate renewal</h1>",
    );
    if connections.is_empty() {
        // NOT A REFUSAL. An organization with no SAML connection has nothing to renew, and a
        // not-found here would read to the holder as "your link is broken" when the link is fine.
        body.push_str(
            "<p>This organization has no SAML connection, so there is no signing certificate \
             to replace.</p>",
        );
        return crate::pages::secure_html(StatusCode::OK, body);
    }

    let limit = usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX);
    if connections.len() > limit {
        // SAID, NOT SWALLOWED. A page titled with the customer's connections that quietly drops
        // some is worse than one admitting its bound: the holder renews what they can see and
        // believes they are finished.
        let _ = write!(
            body,
            "<p>Showing the first {limit} connections. Ask your vendor about the rest.</p>"
        );
    }
    for connection in connections.iter().take(limit) {
        let _ = write!(
            body,
            "<h2>{name}</h2><p>Identity provider: {idp}</p>",
            name = escape_html(&connection.display_name),
            idp = escape_html(&connection.idp_entity_id),
        );
        if !connection.active {
            // TURNED OFF BY THE VENDOR. Its certificates are still pinned and this page could
            // list them as "in use", which would be false in the way that matters: no assertion
            // for this connection is accepted at all, so a holder renewing its certificate would
            // fix nothing and not know why sign-in still failed.
            body.push_str(
                "<p>This connection is switched off, so sign-in through it is not accepted \
                 whatever is pinned to it. Ask your vendor to turn it back on.</p>",
            );
            continue;
        }
        let certificates = state
            .store()
            .scoped(session.scope())
            .saml_connections()
            .certificates(&connection.id)
            .await;
        let Ok(certificates) = certificates else {
            return PortalRefusal::Unavailable.into_response();
        };
        body.push_str(&certificate_rows(&certificates, now));
        // ONE FORM PER CONNECTION, carrying that connection's id. The page can list more than
        // one, and a single form with a dropdown would let a mis-click pin a certificate onto
        // the wrong connection -- which breaks a working connection rather than fixing a broken
        // one.
        let _ = write!(
            body,
            "<form method=\"post\" action=\"{action}\">\
             <input type=\"hidden\" name=\"connection\" value=\"{connection}\">\
             <label for=\"c-{connection}\">Paste the replacement certificate</label>\
             <textarea id=\"c-{connection}\" name=\"certificate\" rows=\"12\" required></textarea>\
             <button type=\"submit\">Pin this certificate</button></form>\
             <p>The certificate you are replacing stays trusted until somebody removes it, so \
             sign-in keeps working while your identity provider switches over.</p>",
            action = escape_html(&format!(
                "/t/{}/e/{}/portal/s/certificate-renewal/pin",
                session.scope().tenant(),
                session.scope().environment()
            )),
            connection = escape_html(&connection.id.to_string()),
        );
    }
    crate::pages::secure_html(StatusCode::OK, body)
}

/// One row per pinned certificate, saying whether it is still trusted and for how long.
///
/// NO FINGERPRINT AND NO KEY MATERIAL. The holder of a renewal link is not necessarily an
/// operator of this deployment, and what they need to decide "has my new certificate landed" is
/// how many are pinned and when each expires. A fingerprint would be the one value on the page
/// worth stealing.
fn certificate_rows(certificates: &[ironauth_store::SamlCertificate], now: i64) -> String {
    if certificates.is_empty() {
        // A CONNECTION WITH NOTHING PINNED IS NOT A RENEWAL PROBLEM, it is a connection that
        // cannot accept a login at all, and saying "no certificates expire soon" would be true
        // and useless.
        return "<p>No certificate is pinned to this connection, so sign-in cannot succeed \
                until one is.</p>"
            .to_owned();
    }
    let mut rows = String::from(
        "<table><tr><th>Certificate</th><th>Valid from</th><th>Expires</th><th>State</th></tr>",
    );
    for certificate in certificates {
        // EVERY PINNED CERTIFICATE IS TRUSTED, including an expired one: `saml_acs` verifies
        // against the pinned KEY and deliberately does not check `notAfter`, because the
        // alternative is an enterprise-wide lockout at midnight on a date nobody was watching.
        // So "expired" here means "the IdP will have stopped using it", not "we refuse it", and
        // the wording has to carry that or a reader will think this page is the enforcement.
        let state = if certificate.not_after_unix_micros <= now {
            "past its expiry; still accepted, so a rollover cannot lock anyone out"
        } else if certificate.not_before_unix_micros > now {
            "not yet valid at the identity provider"
        } else {
            "in use"
        };
        let _ = write!(
            rows,
            "<tr><td>{id}</td><td>{from}</td><td>{until}</td><td>{state}</td></tr>",
            id = escape_html(&certificate.id.to_string()),
            from = escape_html(&crate::saml_start::rfc3339_utc(
                certificate.not_before_unix_micros / 1_000_000
            )),
            until = escape_html(&crate::saml_start::rfc3339_utc(
                certificate.not_after_unix_micros / 1_000_000
            )),
            state = escape_html(state),
        );
    }
    rows.push_str("</table>");
    rows
}

/// The IT contacts surface (issue #141 criterion 3).
///
/// # What this page is for
///
/// #141 asks that operational notifications "land somewhere real: the person who set up SSO is
/// rarely the person watching the vendor's status page". This is where a customer's own
/// administrator sees who is on that list, without going through their vendor.
///
/// # It reads and does not write, and that is the grant rather than a decision
///
/// 0207 gives `ironauth_app` -- the role this plane authenticates as -- `SELECT` on
/// `org_contacts` and nothing else: INSERT and the soft-delete UPDATE are `ironauth_control`
/// only. Adding or removing a contact from here is therefore a control-plane write, and rides a
/// queue the way a pasted certificate does. That is the next slice; this one is the list, which
/// is what makes the queue's effect visible when it lands.
///
/// # No blind index, no bidx, no id an outsider can act on
///
/// The page shows the display name, the address and the category. The address is what the holder
/// is checking, so withholding it would defeat the page; everything else `org_contacts` holds --
/// the sealed columns' versions, the blind index -- is machinery this reader has no use for.
async fn contacts_surface(state: &OidcState, session: &PortalSession) -> Response {
    let read = state
        .store()
        .scoped(session.scope())
        .org_contacts()
        // ONE MORE THAN THE PAGE SHOWS, so a longer list is REPORTED as longer rather than
        // silently cut. A page titled "your contacts" that quietly drops some is how somebody
        // concludes a departed colleague was already removed.
        .list_for_organization(session.organization(), PORTAL_LIST_LIMIT + 1, None)
        .await;
    let Ok(contacts) = read else {
        return PortalRefusal::Unavailable.into_response();
    };

    let mut body = String::from(
        "<!doctype html><meta charset=\"utf-8\"><title>Notification contacts</title>\
         <h1>Notification contacts</h1>\
         <p>These are the people this organization's operational notices reach.</p>",
    );
    if contacts.is_empty() {
        // NOT A REFUSAL, and worth saying WHAT IT COSTS. An organization with nobody listed is
        // the state every organization starts in, and it is also the state in which a
        // certificate-expiry warning reaches no one at all.
        body.push_str(
            "<p>Nobody is listed yet, so operational notices -- including a warning before your \
             SSO certificate expires -- reach nobody at this organization. Ask your vendor to \
             add a technical contact.</p>",
        );
        return crate::pages::secure_html(StatusCode::OK, body);
    }

    let limit = usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX);
    let truncated = contacts.len() > limit;
    if truncated {
        let _ = write!(
            body,
            "<p>Showing the first {limit} contacts. Ask your vendor about the rest.</p>"
        );
    }
    body.push_str("<table><tr><th>Name</th><th>Address</th><th>Receives</th></tr>");
    // COUNTED OVER EVERYTHING READ, not over what is shown. The notice router loops the contact
    // list TO EXHAUSTION and mails every technical contact wherever it sorts, so counting only
    // the rendered page lets this page tell a customer nobody is warned while the router is
    // warning somebody -- an organization whose hundred security contacts sort ahead of its one
    // technical contact reads "nobody here is warned" and is in fact covered.
    let technical = contacts
        .iter()
        .filter(|contact| contact.category == "technical")
        .count();
    for contact in contacts.iter().take(limit) {
        let _ = write!(
            body,
            "<tr><td>{name}</td><td>{email}</td><td>{receives}</td>\
             <td><form method=\"post\" action=\"{action}\">\
             <input type=\"hidden\" name=\"action\" value=\"remove\">\
             <input type=\"hidden\" name=\"contact\" value=\"{id}\">\
             <button type=\"submit\">Remove</button></form></td></tr>",
            name = escape_html(&contact.display_name),
            email = escape_html(&contact.email),
            receives = escape_html(describes_category(&contact.category)),
            action = escape_html(&change_action(session)),
            id = escape_html(&contact.id.to_string()),
        );
    }
    body.push_str("</table>");
    let _ = write!(
        body,
        "<h2>Add a contact</h2><form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"action\" value=\"add\">\
         <label for=\"n\">Name</label><input id=\"n\" name=\"display_name\" required>\
         <label for=\"e\">Address</label><input id=\"e\" name=\"email\" type=\"email\" required>\
         <label for=\"c\">Receives</label>\
         <select id=\"c\" name=\"category\">{options}</select>\
         <button type=\"submit\">Add</button></form>\
         <p>A change can take a moment to appear here.</p>",
        action = escape_html(&change_action(session)),
        options = category_options(),
    );
    if technical == 0 {
        // THE ONE ABSENCE WORTH CALLING OUT. Certificate expiry notices go to the TECHNICAL
        // contacts only, so a list with none of them looks populated and warns nobody about the
        // thing most likely to break this organization's sign-in.
        //
        // ONLY WHEN THE WHOLE LIST WAS READ. Past the bound this page has not seen every
        // contact, and "nobody is warned" is a claim about all of them -- so a truncated list
        // says what it does not know instead of asserting something the router may contradict.
        body.push_str(if truncated {
            "<p>None of the contacts shown is a technical contact. There are more than this \
             page lists, so ask your vendor whether anyone is warned before your SSO \
             certificate expires.</p>"
        } else {
            "<p>None of these is a technical contact, so nobody here is warned before your SSO \
             certificate expires.</p>"
        });
    }
    crate::pages::secure_html(StatusCode::OK, body)
}

/// What a contact category means, in the words a customer's administrator would use.
///
/// The stored values are `technical`, `security` and `billing`, which are the vendor's words. A
/// page that printed them raw would make the reader guess which one receives a certificate
/// warning -- and guessing wrong there is how an organization ends up with a list that looks
/// complete and warns nobody.
fn describes_category(category: &str) -> &'static str {
    match category {
        "technical" => "SSO and provisioning problems, including certificate expiry",
        // NOT "security notices" AND NOT "billing notices". Those read as descriptions of a
        // routing that does not exist: `CertificateNoticeConsumer` is the only delivery path any
        // contact category feeds, it compares against `technical` alone, and no other producer
        // reads this table. Under a heading saying these are the people notices reach, a cell
        // promising a category of mail nothing sends is the same defect as an empty contact list
        // that looks populated -- it tells a customer they are covered.
        "security" => "recorded for future security notices; none are sent yet",
        "billing" => "recorded for future billing notices; none are sent yet",
        // A category the closed set does not hold. Unreachable through the management API, which
        // refuses anything else, and reported rather than hidden because the alternative is a
        // blank cell that reads as "receives nothing".
        _ => "an unrecognised category",
    }
}

/// Where the contacts forms post.
///
/// DERIVED ONCE and used by every form on the page. Two derivations of one path is how a page
/// comes to carry a remove button that posts somewhere the add button does not.
fn change_action(session: &PortalSession) -> String {
    format!(
        "/t/{}/e/{}/portal/s/contacts/change",
        session.scope().tenant(),
        session.scope().environment()
    )
}

/// The category choices on the add form, labelled by what each one actually receives.
///
/// DERIVED FROM `describes_category`, not written again. The two disagreed: the table said a
/// security contact is "recorded for future security notices; none are sent yet" while the
/// dropdown three lines below offered "security notices" as a thing to sign up for. Somebody
/// adding a contact reads the dropdown, so the page was promising exactly what the table had
/// just retracted -- the same defect the table's wording was corrected for, in the one place a
/// person makes the choice.
fn category_options() -> String {
    let mut out = String::new();
    for category in ["technical", "security", "billing"] {
        use std::fmt::Write as _;
        let _ = write!(
            out,
            "<option value=\"{category}\">{label}</option>",
            category = escape_html(category),
            label = escape_html(describes_category(category)),
        );
    }
    out
}

/// What the contacts form posts.
#[derive(serde::Deserialize)]
pub struct ContactChangeForm {
    /// `add` or `remove`.
    action: String,
    /// The contact's name. Required for `add`, ignored for `remove`.
    #[serde(default)]
    display_name: String,
    /// The address. Required for `add`, ignored for `remove`.
    #[serde(default)]
    email: String,
    /// Which notices they receive. Required for `add`, ignored for `remove`.
    #[serde(default)]
    category: String,
    /// The contact to remove. Required for `remove`, ignored for `add`.
    #[serde(default)]
    contact: String,
}

/// Add or remove an IT contact from the portal (issue #141 criterion 3).
///
/// # It enqueues, for the reason the certificate pin enqueues
///
/// 0207 reserves `org_contacts` INSERT and the soft-delete UPDATE to `ironauth_control`; the
/// portal serves on `ironauth_app`, which holds SELECT. So this validates, then queues, and
/// `CONTACT_CHANGE_CONSUMER` applies from the plane that may write.
///
/// # Validated HERE as well as there
///
/// `contact_is_acceptable` is checked before anything is queued, so somebody who mistypes an
/// address is told while they are still looking at the form rather than having the change
/// accepted and die later in a dead letter. The store re-checks; this is not the authority.
///
/// # The two a holder could probe with are the two that match
///
/// This said "a contact id from another organization, one that does not exist, and a malformed
/// field all render the same page", and that was wrong in a way worth correcting rather than
/// softening. The remove branch parses in scope and nothing more: the ORGANIZATION is checked by
/// the consumer, so a foreign handle and an absent one are both enqueued and both answered with
/// the same `303` a real removal gets. A malformed field is the odd one out, at `400`.
///
/// The anti-enumeration property still holds, and it is the grouping that was backwards: the two
/// indistinguishable answers are the SUCCESS-shaped ones, which is exactly the pair that matters.
/// The holder is frequently an outside administrator, and telling "no such contact" apart from
/// "that contact is not yours" is what would turn the form into a probe for handles in other
/// organizations. A malformed field being distinguishable reveals nothing about who exists.
pub async fn contacts_change_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<ContactChangeForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    // THE SAME ORIGIN GUARD the pin and the finish take. A cross-origin post that could add a
    // contact would redirect a customer's operational notices to an address of the attacker's
    // choosing, which is a quiet way to be told nothing when their certificate is about to
    // expire.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let session = match resolve_session(&state, scope, &headers).await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    if let Err(refusal) = session.require_intent("contacts") {
        return refusal.into_response();
    }

    let payload = match form.action.as_str() {
        "add" => {
            if !ironauth_store::contact_is_acceptable(
                &form.display_name,
                &form.email,
                &form.category,
            ) {
                return contacts_refusal("the name, address or category is not acceptable");
            }
            serde_json::json!({
                "action": "add",
                "organization_id": session.organization().to_string(),
                "display_name": form.display_name,
                "email": form.email,
                "category": form.category,
            })
        }
        "remove" => {
            // PARSED IN SCOPE, and the ORGANIZATION is checked by the consumer's `remove`, which
            // takes both. Proving the tenant and environment here is what stops a handle from
            // another deployment reaching the queue at all.
            let Ok(contact) = ironauth_store::OrgContactId::parse_in_scope(&form.contact, &scope)
            else {
                return contacts_refusal("the contact identifier does not parse in this scope");
            };
            serde_json::json!({
                "action": "remove",
                "organization_id": session.organization().to_string(),
                "contact_id": contact.to_string(),
            })
        }
        _ => return contacts_refusal("the form asked for neither add nor remove"),
    };

    if queue_contact_change(&state, &session, &payload)
        .await
        .is_err()
    {
        return PortalRefusal::Unavailable.into_response();
    }
    let surface = format!(
        "/t/{}/e/{}/portal/s/contacts",
        scope.tenant(),
        scope.environment()
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, surface),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

/// The one refusal the contacts surface gives, whatever went wrong.
fn contacts_refusal(reason: &str) -> Response {
    tracing::info!(target: "ironauth.portal", reason, "contact change refused");
    crate::pages::secure_html(
        StatusCode::BAD_REQUEST,
        "<!doctype html><meta charset=\"utf-8\"><title>Change not accepted</title>\
         <h1>That change was not accepted</h1>\
         <p>Check the name, the address and which notices they should receive, then try \
         again.</p>"
            .to_owned(),
    )
}

/// Queue one contact change for the control plane to apply.
///
/// THE ORDERING KEY IS THE ORGANIZATION, so one customer's changes apply in the order they were
/// made -- removing a contact and adding them back is a different outcome from the reverse --
/// while another customer's never wait behind them.
///
/// THE IDEMPOTENCY KEY IS THE PAYLOAD. Two identical submissions mean the same thing, so the
/// second collapses; two DIFFERENT changes, even to the same contact, are two facts and both
/// must land. Hashing the payload is what draws that line in the right place -- an earlier
/// design elsewhere in this file keyed on one field and made two customers collide.
async fn queue_contact_change(
    state: &OidcState,
    session: &PortalSession,
    payload: &serde_json::Value,
) -> Result<(), ironauth_store::StoreError> {
    use sha2::{Digest as _, Sha256};

    let scope = session.scope();
    let digest = Sha256::digest(payload.to_string().as_bytes());
    let mut key = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        use std::fmt::Write as _;
        let _ = write!(key, "{byte:02x}");
    }
    state
        .store()
        .scoped(scope)
        .outbox()
        // ALREADY QUEUED IS DONE, for the reason the pin uses this: a holder who double-submits
        // or reloads means the same thing every time, and telling them otherwise invites another
        // attempt and then a call to their vendor.
        .enqueue_once(
            state.env(),
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::CONTACT_CHANGE_CONSUMER,
                idempotency_key: &key,
                ordering_key: &session.organization().to_string(),
                payload: payload.clone(),
            },
        )
        .await
        .map(|_| ())
}

/// What the audit surface narrows on, read from the query string.
///
/// EVERY FIELD OPTIONAL and absent means "do not narrow", matching
/// [`ironauth_store::AuditSearch`]. The organization is deliberately not here and cannot be: it
/// comes from the SESSION, so no query string a holder can write reaches it.
#[derive(Debug, Default, serde::Deserialize)]
pub struct AuditFilterQuery {
    /// Inclusive lower bound, epoch SECONDS. Seconds because this is a value a person types or
    /// a link carries, and the store's microseconds would be six digits of noise in a URL.
    #[serde(default)]
    since: Option<i64>,
    /// Inclusive upper bound, epoch seconds.
    #[serde(default)]
    until: Option<i64>,
    /// An exact action, as the audit row spells it.
    #[serde(default)]
    action: Option<String>,
    /// An exact actor identifier.
    #[serde(default)]
    actor: Option<String>,
    /// An exact target identifier.
    #[serde(default)]
    target: Option<String>,
}

/// How many events one page of the audit surface shows.
const AUDIT_PAGE: i64 = 50;

/// The per-organization audit viewer (issue #141 criteria 4 and 5).
///
/// # The boundary is the session, not the request
///
/// `search_for_organization` takes the organization as a required argument and this passes
/// `session.organization()`, which came off the portal link. Nothing in the query string can
/// reach it, so there is no parameter for a holder to tamper with -- which is what makes the
/// IDOR question answerable by reading this function rather than by auditing every filter.
///
/// # What it does NOT show
///
/// `detail` and `correlation_id` are on every audit row and neither is here. `detail` is free
/// text the vendor's own handlers write for their own operators -- `event_types=a,b`, internal
/// counts, occasionally an identifier from another subsystem -- and putting it on a
/// customer-facing page publishes whatever a future handler happens to put in it. The
/// correlation id is an internal request handle that means nothing outside this deployment.
/// Both are omitted deliberately rather than forgotten.
async fn audit_surface(
    state: &OidcState,
    session: &PortalSession,
    filters: &AuditFilterQuery,
) -> Response {
    // SECONDS TO MICROSECONDS at the one seam that reads the query string. The store speaks
    // microseconds and a URL speaks seconds; converting here means no other line has to know.
    let to_micros = |seconds: Option<i64>| seconds.and_then(|s| s.checked_mul(1_000_000));
    let search = ironauth_store::AuditSearch {
        since_unix_micros: to_micros(filters.since),
        until_unix_micros: to_micros(filters.until),
        action: filters.action.as_deref(),
        actor_id: filters.actor.as_deref(),
        target_id: filters.target.as_deref(),
    };
    let read = state
        .store()
        .scoped(session.scope())
        .audit()
        .search_for_organization(session.organization(), &search, AUDIT_PAGE + 1)
        .await;
    let Ok(events) = read else {
        return PortalRefusal::Unavailable.into_response();
    };

    let mut body = String::from(
        "<!doctype html><meta charset=\"utf-8\"><title>Activity</title><h1>Activity</h1>\
         <p>What has happened to this organization's configuration.</p>",
    );
    if events.is_empty() {
        // WHICH EMPTY IT IS. "No events" and "no events MATCHING" are different answers, and a
        // page giving one message for both leaves a reader unable to tell an over-narrow filter
        // from a quiet month.
        let narrowed = filters.since.is_some()
            || filters.until.is_some()
            || filters.action.is_some()
            || filters.actor.is_some()
            || filters.target.is_some();
        body.push_str(if narrowed {
            "<p>No events match those filters. Widen them to see everything recorded for this \
             organization.</p>"
        } else {
            "<p>Nothing has been recorded for this organization yet.</p>"
        });
        return crate::pages::secure_html(StatusCode::OK, body);
    }

    let limit = usize::try_from(AUDIT_PAGE).unwrap_or(usize::MAX);
    if events.len() > limit {
        let _ = write!(
            body,
            "<p>Showing the {limit} most recent. Narrow the time range to see further back.</p>"
        );
    }
    body.push_str("<table><tr><th>When</th><th>What</th><th>Who</th><th>Target</th></tr>");
    for event in events.iter().take(limit) {
        let _ = write!(
            body,
            "<tr><td>{when}</td><td>{what}</td><td>{who}</td><td>{target}</td></tr>",
            when = escape_html(&crate::saml_start::rfc3339_utc(
                event.occurred_at_unix_micros / 1_000_000
            )),
            what = escape_html(&event.action),
            who = escape_html(&actor_label(&event.actor)),
            target = escape_html(&event.target_id),
        );
    }
    body.push_str("</table>");
    crate::pages::secure_html(StatusCode::OK, body)
}

/// The single sign-on surface: the values a customer's identity provider asks for.
///
/// # Read-only in this slice, and useful on its own
///
/// #140's first criterion is an IT admin completing SSO setup with no vendor-side action, which
/// needs a create path. What lands first is the half that create path would be useless without:
/// the values a provider's console asks for, printed beside the connection each one belongs to,
/// with the steps for the provider that connection actually names. An admin whose connection
/// already exists can finish the entire upstream side from this page, which is where the
/// vendor's onboarding support load actually sits.
///
/// # Two reads, because the two upstream kinds are named in different places
///
/// A SAML upstream is a `saml_connections` row that carries its own `organization_id`, and it
/// is where `acs_url` and `sp_entity_id` live -- the two values this page exists to hand over.
/// `certificate_renewal_surface` reads it the same way. An OIDC upstream is not a row of its
/// own: it is an `org_connections` binding naming a connector, so that table is the only place
/// an organization's OIDC upstream can be found.
///
/// Reading `org_connections` for BOTH would have been tidier and would have listed fewer SAML
/// connections than the organization has, because a `saml_connections` row does not require a
/// binding to exist. A page that omitted one would tell an admin a connection they can see on
/// the renewal page is not there.
async fn sso_surface(state: &OidcState, session: &PortalSession) -> Response {
    let scoped = state.store().scoped(session.scope());
    let saml = scoped
        .saml_connections()
        .list_for_org(session.organization(), PORTAL_LIST_LIMIT + 1, None)
        .await;
    let bindings = scoped
        .org_connections()
        .list_for_organization(session.organization(), PORTAL_LIST_LIMIT + 1)
        .await;
    // THE ORGANIZATION IS THE SESSION'S on both reads, so a failure is this deployment failing
    // to read its own rows rather than an addressing mistake the holder could have made.
    let (Ok(saml), Ok(bindings)) = (saml, bindings) else {
        return PortalRefusal::Unavailable.into_response();
    };
    let connectors: Vec<&str> = bindings
        .iter()
        .filter_map(|binding| binding.connector_id.as_deref())
        .collect();

    let mut body = String::from(
        "<!doctype html><meta charset=\"utf-8\"><title>Single sign-on</title>\
         <h1>Single sign-on</h1>",
    );
    if saml.is_empty() && connectors.is_empty() {
        // NOT A REFUSAL, for the reason the renewal surface gives: the link is fine, there is
        // simply nothing configured yet, and a not-found would read as a broken link.
        body.push_str(
            "<p>This organization has no sign-on connection yet. Ask your vendor to create one, \
             then come back here for the values your identity provider needs.</p>",
        );
        return crate::pages::secure_html(StatusCode::OK, body);
    }

    let limit = usize::try_from(PORTAL_LIST_LIMIT).unwrap_or(usize::MAX);
    if saml.len() > limit || connectors.len() > limit {
        // SAID, NOT SWALLOWED, as on the renewal page: an admin who configures what they can
        // see and believes they are finished is worse off than one told the list is cut.
        let _ = write!(
            body,
            "<p>Showing the first {limit} of each kind. Ask your vendor about the rest.</p>"
        );
    }
    for connection in saml.iter().take(limit) {
        sso_saml_section(state, session, connection, &mut body);
    }
    for raw in connectors.iter().take(limit) {
        sso_oidc_section(state, session, raw, &mut body).await;
    }
    crate::pages::secure_html(StatusCode::OK, body)
}

/// One SAML upstream: the two values its console asks for, and the guide for that provider.
fn sso_saml_section(
    state: &OidcState,
    session: &PortalSession,
    connection: &ironauth_store::SamlConnection,
    body: &mut String,
) {
    let scope = session.scope();
    // THE METADATA DOCUMENT IS THE SHORTEST PATH and the least error-prone, so it is offered
    // LAST, after the two values it replaces: an admin whose provider can import it never has
    // to transcribe them, and one whose provider cannot has already read them. The generic
    // guide's wording depends on this order -- it says "instead of typing the two values
    // above".
    //
    // AND IT IS OFFERED ONLY WHILE THE CONNECTION IS ON. `saml_metadata::metadata_get` reads
    // through `find_active`, so the document 404s for a switched-off connection while
    // `list_for_org` still lists it here. Printing the URL anyway would send an admin to
    // paste an address that answers nothing, and the failure surfaces days later as "the
    // import did not work" with this page as the evidence it should have.
    let metadata_url = format!(
        "{base}/t/{tenant}/e/{environment}/saml/metadata/{connection}",
        base = state.issuer_base().trim_end_matches('/'),
        tenant = scope.tenant(),
        environment = scope.environment(),
        connection = connection.id,
    );
    let _ = write!(
        body,
        "<h2>{name}</h2><p>Type: SAML</p>\
         <p>Sign-on URL (ACS): <code>{acs}</code></p>\
         <p>Audience (SP entity ID): <code>{audience}</code></p>",
        name = escape_html(&connection.display_name),
        acs = escape_html(&connection.acs_url),
        audience = escape_html(&connection.sp_entity_id),
    );
    // THE TEST FORM, on every connection whether or not it is switched on (issue #140
    // criterion 6). An admin whose connection is off is exactly the one still setting it up,
    // and telling them to come back later to find out why their response is refused is the
    // conversation this page exists to prevent.
    //
    // THE HANDLER HAS TO AGREE WITH THAT, and the first version did not: it resolved with
    // `find_active`, which cannot see a switched-off row, so this form led exactly that admin
    // to a refusal reading "no active connection with that id" -- the same sentence the
    // organization fence returns. It resolves with `find_in_org` now, and says separately that
    // sign-in is off, so the verdict on their document is not read as "you are finished".
    let _ = write!(
        body,
        "<form method=\"post\" action=\"{base}/t/{tenant}/e/{environment}/portal/s/sso/test\">\
         <input type=\"hidden\" name=\"connection_id\" value=\"{connection}\">\
         <p><label>Paste a SAMLResponse from your identity provider to find out what it would \
         do here:<br><textarea name=\"saml_response\" rows=\"4\" cols=\"60\"></textarea></label></p>\
         <p><button type=\"submit\">Test this connection</button></p></form>",
        base = escape_html(state.issuer_base().trim_end_matches('/')),
        tenant = escape_html(&scope.tenant().to_string()),
        environment = escape_html(&scope.environment().to_string()),
        connection = escape_html(&connection.id.to_string()),
    );
    if connection.active {
        let _ = write!(
            body,
            "<p>Metadata document: <code>{metadata}</code></p>",
            metadata = escape_html(&metadata_url),
        );
    } else {
        // THE TWO VALUES ABOVE STAY. They are stable properties of the connection and an
        // admin can configure their side before the vendor switches it on; what they must not
        // be given is an address that answers nothing and a guide that reads as if sign-in
        // would work at the end of it.
        body.push_str(
            "<p><strong>This connection is switched off.</strong> Your vendor has to enable \
             it before anyone can sign in through it, and its metadata document is not served \
             while it is off.</p>",
        );
    }
    render_guide(
        body,
        &crate::portal_guides::saml_guide_for(
            &connection.idp_entity_id,
            &connection.acs_url,
            &connection.sp_entity_id,
            connection.active.then_some(metadata_url.as_str()),
        ),
    );
}

/// One OIDC upstream: the redirect URI its console asks for, and the guide.
async fn sso_oidc_section(
    state: &OidcState,
    session: &PortalSession,
    raw_id: &str,
    body: &mut String,
) {
    let scope = session.scope();
    let scoped = state.store().scoped(scope);
    let found = match scoped.connectors().parse_id(raw_id) {
        Ok(id) => scoped.connectors().get(&id).await.ok(),
        Err(_) => None,
    };
    let Some(connector) = found else {
        body.push_str(
            "<h2>An OpenID Connect connection this page could not read</h2>\
             <p>Ask your vendor to check it.</p>",
        );
        return;
    };

    // DERIVED BY THE FUNCTION THE FLOW ITSELF USES, not composed here. A second spelling of
    // this URL is how a page comes to print an address the callback route does not serve, and
    // the admin would have no way to tell: the paste succeeds and the sign-in fails later.
    let redirect_uri = crate::federation::federation_callback_url(
        state,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        &connector.slug,
    );
    // THE PROTOCOL DECIDES BOTH THE LABEL AND THE STEPS. An OAuth2 connector (issue #74,
    // GitHub) binds through this same table, and calling it OpenID Connect sends its admin
    // looking for an issuer URL and an `openid` scope their provider does not have.
    let protocol = crate::portal_guides::connector_protocol(&connector.definition_json);
    let kind = match protocol.as_deref() {
        Some("oauth2") => "OAuth 2.0",
        Some("oidc") => "OpenID Connect",
        _ => "single sign-on",
    };
    let _ = write!(
        body,
        "<h2>{name}</h2><p>Type: {kind}</p>\
         <p>Redirect URI: <code>{redirect}</code></p>",
        name = escape_html(&connector.slug),
        kind = escape_html(kind),
        redirect = escape_html(&redirect_uri),
    );
    render_guide(
        body,
        &crate::portal_guides::upstream_guide(protocol.as_deref(), &redirect_uri),
    );
}

/// A guide rendered as a numbered list under the connection it belongs to.
fn render_guide(body: &mut String, guide: &crate::portal_guides::SetupGuide) {
    let _ = write!(
        body,
        "<h3>Setting this up in {provider}</h3><p>{where_to_go}</p><ol>",
        provider = escape_html(guide.provider_name),
        where_to_go = escape_html(guide.where_to_go),
    );
    for step in &guide.steps {
        let _ = write!(body, "<li>{}</li>", escape_html(step));
    }
    body.push_str("</ol>");
}

/// How an actor is named on the audit page.
///
/// THE KIND AND THE IDENTIFIER, because neither alone answers "who did this". An identifier with
/// no kind leaves a reader unable to tell one of their own administrators from the vendor's
/// automation, which on a page about their own configuration is the first thing they want to
/// know.
fn actor_label(actor: &ironauth_store::ActorRef) -> String {
    match actor {
        ironauth_store::ActorRef::Human(id) => format!("person {id}"),
        ironauth_store::ActorRef::Service(id) => format!("service {id}"),
        ironauth_store::ActorRef::Agent(id) => format!("agent {id}"),
    }
}

/// What the renewal form posts.
#[derive(serde::Deserialize)]
pub struct RenewalPinForm {
    /// Which connection the certificate belongs to.
    connection: String,
    /// The certificate, PEM-armoured or bare base64.
    certificate: String,
}

/// Pin a replacement certificate from the renewal surface (issue #141 criterion 2).
///
/// # `pin_certificate` gets its first production caller, though not this one
///
/// The store has been able to pin a SAML certificate since 0197 and nothing outside tests ever
/// did it, so the operational story the expiry alerting tells -- "your certificate is about to
/// expire, here is a link, replace it" -- ended at a page that could only describe the problem.
/// This handler is what starts the work; the caller is
/// `ironauth_admin::certificate_pin_requests`, on the control plane, for the reason below.
///
/// # Pinning ADDS, and that is the overlap
///
/// The replacement is pinned ALONGSIDE whatever is already there rather than replacing it, and
/// `saml_acs` verifies an assertion against every pinned certificate. So from the moment this
/// returns, both the old and the new certificate are accepted and the identity provider may cut
/// over whenever it likes. Unpinning the old one is a separate act, deliberately not done here:
/// doing it in the same request would close the overlap window at the exact instant the customer
/// needs it open.
///
/// # What it refuses, and why each refusal is the same page
///
/// A holder of a renewal link is frequently an outside administrator, so this must not become an
/// oracle. A connection in another organization, a connection that does not exist, and a
/// malformed certificate all render the same refusal with the same status: the distinctions are
/// in the log, not in the response.
pub async fn renewal_pin_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<RenewalPinForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    // THE SAME ORIGIN GUARD `finish_post` TAKES. This one writes trust material, so a
    // cross-origin form post that pinned an attacker's key would be the whole game.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let session = match resolve_session(&state, scope, &headers).await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    // THE FENCE, for the same reason `surface_get` takes it: a session opened for `scim` must
    // not be able to pin a certificate by posting to this path.
    if let Err(refusal) = session.require_intent("certificate-renewal") {
        return refusal.into_response();
    }

    let Ok(connection_id) =
        ironauth_store::SamlConnectionId::parse_in_scope(&form.connection, &scope)
    else {
        return renewal_refusal("the connection identifier does not parse in this scope");
    };
    // THE CONNECTION MUST BE THIS ORGANIZATION'S. `parse_in_scope` proves the tenant and the
    // environment, and nothing more: a link holder for one organization could otherwise pin a
    // key onto a neighbour's connection in the same environment, which is a total compromise of
    // that neighbour's SSO.
    let connection = match state
        .store()
        .scoped(scope)
        .saml_connections()
        .find_in_org(session.organization(), &connection_id)
        .await
    {
        Ok(Some(connection)) => connection,
        Ok(None) => return renewal_refusal("no such connection in this organization"),
        Err(_) => return PortalRefusal::Unavailable.into_response(),
    };

    let Some(der) = decode_certificate(&form.certificate) else {
        return renewal_refusal("the certificate is not base64 or is too large");
    };
    let Ok(parsed) = ironauth_saml::x509::pinned(&der) else {
        return renewal_refusal("the certificate does not parse as X.509");
    };

    // PARSED, THEN QUEUED. `parsed` is discarded here on purpose: the worker parses the DER
    // again from the row, because a value carried across a queue is a value the worker is
    // trusting a previous process to have got right. Parsing here is what lets the holder be
    // told NOW that their paste is not a certificate.
    let _ = &parsed;
    if queue_pin(&state, &session, &connection.id, &der)
        .await
        .is_err()
    {
        return PortalRefusal::Unavailable.into_response();
    }
    // BACK TO THE SURFACE, so the holder sees the new certificate listed beside the old one.
    // That is the whole confirmation they need: two rows, both trusted.
    let surface = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal",
        scope.tenant(),
        scope.environment()
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, surface),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
    )
        .into_response()
}

/// Queue the parsed certificate for the control plane to pin.
///
/// # Why this enqueues instead of writing
///
/// 0197 grants `saml_connection_certificates` INSERT to `ironauth_control` alone: "The data
/// plane READS, because the ACS verifies there. It never writes a trust anchor." The portal runs
/// on the data plane. Writing here needs either that grant widened or a control-plane connection
/// handed to a customer-facing surface, and both spend the separation that exists precisely for
/// the key every future assertion is checked against.
///
/// So this does what the data plane may do -- it validates, parses, and enqueues -- and
/// `CERTIFICATE_PIN_REQUEST_CONSUMER` performs the pin from the plane that is allowed to.
///
/// # The paste is parsed BEFORE it is queued
///
/// A queue is not a place to defer validation to. Enqueuing an unparsed blob would answer the
/// holder "accepted" and then fail in a worker, where nobody is looking and the only recourse is
/// a dead letter an operator has to notice. What is queued here is known to be a certificate.
///
/// # What the row carries
///
/// The DER and the connection, and nothing else. The DER is public material -- it is what an
/// identity provider publishes -- so it is not a secret riding a queue.
///
/// AN EARLIER VERSION ALSO CARRIED THE PORTAL SESSION ID, with a sentence saying it was there so
/// the audit the pin writes could name the link this came through. Nothing read it: the pin is
/// audited as a freshly-minted service actor either way, so the field was a durable payload
/// column supporting a property the code did not have. Removed rather than left as decoration.
/// Attributing the pin to the link is worth doing and is its own change: it needs an actor kind
/// the audit layer does not currently have.
async fn queue_pin(
    state: &OidcState,
    session: &PortalSession,
    connection: &ironauth_store::SamlConnectionId,
    der: &[u8],
) -> Result<(), ironauth_store::StoreError> {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let scope = session.scope();
    // THE CONNECTION AND THE FINGERPRINT, length-prefixed. A holder who double-submits, or whose
    // browser retries, must not queue the same certificate twice.
    //
    // AN EARLIER VERSION KEYED ON THE FINGERPRINT ALONE, which is wrong in a way that reaches
    // across customers: the outbox's uniqueness is per (tenant, environment, consumer, key), so
    // two organizations in one environment pasting the SAME certificate -- both federating with
    // the same identity provider, which is ordinary -- collided, and the second organization's
    // renewal could never be queued at all. Keying on the pair makes "the same paste for the same
    // connection" the thing that collapses, which is what idempotent means here.
    let mut hasher = Sha256::new();
    let connection_text = connection.to_string();
    // Length-prefixed for the reason `dedup_key` gives: joined plainly, a crafted identifier
    // could collide with a different (connection, certificate) pair and suppress its pin.
    hasher.update(
        u64::try_from(connection_text.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(connection_text.as_bytes());
    hasher.update(der);
    let digest = hasher.finalize();
    let mut key = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        use std::fmt::Write as _;
        let _ = write!(key, "{byte:02x}");
    }
    state
        .store()
        .scoped(scope)
        .outbox()
        .enqueue_once(
            state.env(),
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::CERTIFICATE_PIN_REQUEST_CONSUMER,
                idempotency_key: &key,
                // THE CONNECTION, so two pastes for one connection are applied in the order they
                // were made and pastes for different connections never wait on each other.
                ordering_key: &connection.to_string(),
                payload: serde_json::json!({
                    "saml_connection_id": connection.to_string(),
                    "certificate_der_base64":
                        base64::engine::general_purpose::STANDARD.encode(der),
                }),
            },
        )
        .await
        // ALREADY QUEUED IS DONE. `enqueue_once` reports which happened; the holder is told the
        // same thing either way, because to them both mean their certificate is on its way.
        .map(|_| ())
}

/// The one refusal this surface gives, whatever went wrong.
///
/// ONE PAGE AND ONE STATUS for every rejection. The holder is often not an operator of this
/// deployment, and telling them apart "no such connection" from "that connection is not yours"
/// turns a renewal link into a way to enumerate an environment's connections.
fn renewal_refusal(reason: &str) -> Response {
    tracing::info!(target: "ironauth.portal", reason, "certificate renewal refused");
    crate::pages::secure_html(
        StatusCode::BAD_REQUEST,
        "<!doctype html><meta charset=\"utf-8\"><title>Certificate not accepted</title>\
         <h1>That certificate was not accepted</h1>\
         <p>Check that you pasted the whole certificate, including the BEGIN and END lines, and \
         that it is the one for this connection.</p>"
            .to_owned(),
    )
}

/// Decode a pasted certificate to DER, accepting PEM or bare base64.
///
/// PEM IS WHAT AN IDP HANDS SOMEBODY. Okta and Entra both offer a `.pem` download and their
/// consoles show the armoured text, so requiring bare base64 would make the common case an
/// error. The armour lines and all whitespace are stripped and the rest is decoded.
fn decode_certificate(raw: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;

    // A CEILING BEFORE DECODING, not after. `x509::pinned` bounds the DER it accepts, but that
    // check happens after this function has already allocated whatever was posted.
    const MAX_PASTED_BYTES: usize = 64 * 1024;
    if raw.len() > MAX_PASTED_BYTES {
        return None;
    }
    let body: String = raw
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect();
    if body.is_empty() {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(&body).ok()
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

/// A connection test that could not be run, as a page.
///
/// SEPARATE FROM A DIAGNOSIS. These are problems with the REQUEST -- an id that is not a
/// connection, a paste that is not base64 -- and answering them with a verdict about the
/// connection would tell an operator their identity provider is broken when their clipboard is.
fn test_refusal(reason: &str) -> Response {
    crate::pages::secure_html(
        StatusCode::BAD_REQUEST,
        format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Connection test</title>\
             <h1>Connection test</h1><p>{reason}.</p>",
            reason = escape_html(reason)
        ),
    )
}

/// Turn a typed failure into the sentence that says what to change.
///
/// THE POINT OF THE WHOLE SURFACE (issue #140 criterion 6: "as actionable messages, not generic
/// errors"). Each arm names WHERE the fix is -- this deployment's configuration, the identity
/// provider's, or the document itself -- because an operator who is told "the signature did not
/// verify" when they have pinned nothing goes and looks at their identity provider, which is
/// fine, and stays there.
///
/// The two the criterion names by name are the first two. `NoTrustAnchor` is the setup step
/// nobody did; `WrongAudience` is the one an identity provider gets wrong by default, because
/// its own field for it is usually pre-filled with something else.
fn diagnose(
    error: &crate::saml_acs::AcsError,
    connection: &ironauth_store::SamlConnection,
) -> String {
    use crate::saml_acs::AcsError;

    // EXHAUSTIVE, AND THAT IS THE REPAIR. The first version had a catch-all whose sentence --
    // "nothing in this connection's configuration explains it" -- was false for four of the
    // variants that reached it, and a catch-all is exactly what let those variants arrive
    // unconsidered. With no `_` arm, a variant added to `AcsError` stops compiling here until
    // somebody decides what to tell an operator about it.
    match error {
        AcsError::NoTrustAnchor => format!(
            "<p><strong>No signing certificate is pinned for this connection.</strong> Until \
             one is, every response your identity provider sends will be refused, however \
             correct it is.</p><p>Export the signing certificate from your identity provider \
             and ask your vendor to pin it against <code>{name}</code>.</p>",
            name = escape_html(&connection.display_name)
        ),
        AcsError::AllCertificatesUnusable { pinned } => format!(
            "<p><strong>This connection has {pinned} certificate(s) pinned and none of them \
             can be read.</strong> That is a stored row this deployment should not be holding \
             rather than anything you configured. Send this page to your vendor.</p>"
        ),
        AcsError::Condition(condition) => diagnose_condition(condition, connection),
        AcsError::Signature(failure) => diagnose_signature(*failure, connection),
        // THE NAME IDENTIFIER FORMAT, and BOTH SIDES CAN BE THE FAULT. The expected value is a
        // column on this connection, and migration 0196 asks only that it be non-empty -- so a
        // single space is storable and collapses to nothing, which refuses every document. An
        // earlier version of this arm blamed the identity provider unconditionally.
        AcsError::WrongNameIdFormat { expected, found } => {
            if expected.trim().is_empty() {
                "<p><strong>This connection's name ID format is blank, so no document can \
                 match it.</strong></p><p>Nothing you send will get past this. Send this page \
                 to your vendor: the connection needs a real format configured.</p>"
                    .to_owned()
            } else {
                format!(
                    "<p><strong>The name identifier format does not match.</strong></p><p>Your \
                     identity provider sent <code>{found}</code>. This connection expects \
                     <code>{expected}</code>.</p><p>Set the name ID format in your identity \
                     provider to the expected value, or ask your vendor to change what this \
                     connection expects. The format is part of the identity: a transient \
                     identifier names somebody for one session only, and a persistent one names \
                     them forever, so the two are not interchangeable.</p>",
                    found = escape_html(found.as_deref().unwrap_or("nothing")),
                    expected = escape_html(expected)
                )
            }
        }
        AcsError::EncryptionRequired => {
            "<p><strong>This connection is configured to require an encrypted assertion, and \
             this deployment cannot accept one.</strong></p><p>Nothing you change in your \
             identity provider will get past this. Send this page to your vendor: either the \
             requirement comes off the connection, or encryption has to be finished here.</p>"
                .to_owned()
        }
        AcsError::EncryptedAttributes { count } => format!(
            "<p><strong>The assertion carries {count} encrypted attribute(s), and this \
             deployment cannot read them.</strong></p><p>An attribute it cannot read may be the \
             group membership that decides what the person is allowed to do, so it refuses \
             rather than signing them in with part of the document unknown. In your identity \
             provider, send these attributes unencrypted, or ask your vendor whether the \
             connection needs them at all.</p>"
        ),
        AcsError::Attributes(unreadable) => diagnose_attributes(unreadable),
        // EVERYTHING THE SIGNATURE AND THE CONDITIONS COVER HELD, and that is all this says.
        //
        // `examine` refuses an unsolicited response BEFORE it reaches the connection's remaining
        // controls -- the encryption requirement, the name ID format, and the attribute
        // statement -- so this page must not vouch for those.
        AcsError::UnsolicitedRefused => format!(
            "<p><strong>The certificate, issuer, audience and validity window all check \
             out.</strong></p><p>The test stops there. This response answers no sign-in that \
             this deployment started, and <code>{name}</code> accepts only responses to its own \
             requests -- which is the right setting, and which a real sign-in satisfies.</p>\
             <p>So this does not vouch for what comes after that point: the assertion's name ID \
             format, its attributes, and any encryption this connection requires are checked \
             during a real sign-in and not here.</p>",
            name = escape_html(&connection.display_name)
        ),
        // NEITHER OF THESE CAN REACH THIS PAGE, and they are written out rather than swept into
        // a catch-all so that stays true by construction. `examine` is the stateless half:
        // `NoConnection` is the ACS route's answer before it has a connection at all, and
        // `UnknownRequest`, `Replayed` and `Store` are `consume`'s, which this surface never
        // calls. `Store` matters most: its `Display` wraps a database error, and a catch-all
        // that rendered `Display` would have put one on a customer's screen.
        AcsError::NoConnection
        | AcsError::UnknownRequest
        | AcsError::Replayed
        | AcsError::Store(_) => "<p><strong>This response was refused for a reason this page \
             cannot reach.</strong> Send this page to your vendor.</p>"
            .to_owned(),
    }
}

/// The attribute-statement half of [`diagnose`].
///
/// NONE OF THESE IS FIXED BY CAPTURING AGAIN, which is what an earlier version of this advice
/// said. Every one is a property of what the identity provider emits or of which element was
/// verified, so the same capture repeated produces the same refusal.
fn diagnose_attributes(error: &ironauth_saml::Unreadable) -> String {
    use ironauth_saml::Unreadable;
    match error {
        // NOT REACHABLE FROM THIS SURFACE. `examine` hands `attributes` the element it
        // verified, and it verifies the assertion, so the guard this variant exists for -- a
        // caller holding a `samlp:Response` -- cannot arise on this path. A response signed only
        // at the response level lands in `Signature` long before here.
        //
        // IT IS STILL WRITTEN OUT rather than folded into a neighbour, because the match is
        // exhaustive on purpose and a sentence that named a cause would be a guess about a state
        // this deployment does not produce.
        Unreadable::NotAnAssertion => {
            "<p><strong>This deployment read something other than an assertion where an \
             assertion was verified.</strong></p><p>That is an internal inconsistency rather \
             than anything in your configuration. Send this page to your vendor.</p>"
                .to_owned()
        }
        Unreadable::NamelessAttribute => {
            "<p><strong>The assertion carries an attribute with no name.</strong></p><p>An \
             unnamed attribute cannot be mapped to anything, and this deployment will not guess \
             which one it was. Look at the attribute statement your identity provider is \
             configured to send: one of its entries has an empty name.</p>"
                .to_owned()
        }
        Unreadable::Duplicate { .. } => {
            // WHETHER THE TWO AGREE IS NOT CHECKED, and an earlier version of this sentence
            // said "with different values" as though it were. The producer refuses on the
            // second occurrence of a NAME; it never compares what they carry.
            "<p><strong>The assertion sends the same attribute name twice.</strong></p><p>This \
             deployment will not choose between them, whether or not they agree. In your \
             identity provider, remove the duplicate mapping -- usually one of a pair added at \
             different times.</p>"
                .to_owned()
        }
    }
}

/// The conditions half of [`diagnose`], split out only because the whole match outgrew one
/// screen. Each arm names WHERE the fix is, exactly as the parent's doc requires.
///
/// EVERY ARM PRINTS WHAT THE VARIANT CARRIES. Two of these variants name the exact attribute
/// that failed, and an earlier version discarded both and guessed a cause instead -- so a
/// missing `Conditions/@NotBefore` was reported as a missing `NotOnOrAfter`, and the operator
/// was sent to switch on something already in their document.
fn diagnose_condition(
    error: &ironauth_saml::ConditionError,
    connection: &ironauth_store::SamlConnection,
) -> String {
    use ironauth_saml::ConditionError;
    match error {
        ConditionError::WrongAudience { found } => format!(
            "<p><strong>Your identity provider is sending the wrong audience.</strong></p>\
             <p>It sent <code>{found}</code>. This connection expects <code>{expected}</code>.</p>\
             <p>In your identity provider, set the audience (sometimes called the SP entity ID, \
             or the Audience URI) to exactly the expected value above.</p>",
            found = escape_html(found.as_deref().unwrap_or("nothing")),
            // THE EXPECTED VALUE COMES FROM THE CONNECTION, not from the error. The variant
            // carries only what the document said, which is right: what we expect is ours to
            // know and the document has no business asserting it. Reading it from the row also
            // means the sentence names the value an operator can go and copy.
            expected = escape_html(&connection.sp_entity_id)
        ),
        ConditionError::WrongIssuer { found } => format!(
            "<p><strong>The response came from a different identity provider.</strong></p>\
             <p>It said it was <code>{found}</code>. This connection expects \
             <code>{expected}</code>.</p><p>Either you pasted a response from another \
             application, or the issuer (entity ID) configured here is not the one your \
             identity provider uses.</p>",
            // ABSENT IS NOT THE ONLY WAY THIS IS `None`. The variant declines to name what it
            // read when the document carries no `Issuer` AND when it carries more than one,
            // because an ambiguous read is no read. "nothing" is the honest rendering of both:
            // it says what this deployment could use, which is what the operator has to fix,
            // rather than picking one of two values to blame.
            found = escape_html(found.as_deref().unwrap_or("nothing usable")),
            expected = escape_html(&connection.idp_entity_id)
        ),
        // BOTH ENDS OF THE WINDOW, because one variant carries both. `check` returns this when
        // the clock is before `NotBefore` as well as after `NotOnOrAfter`, and an earlier
        // version said only "this response has expired" -- which sends an operator whose clocks
        // are ahead looking for a stale document.
        ConditionError::Expired => format!(
            "<p><strong>This response is outside its validity window.</strong></p><p>SAML \
             responses are valid for minutes, so a document captured a while ago lands here and \
             the remedy is to capture a fresh one.</p><p>If it was captured seconds ago, the \
             clock here and the clock on your identity provider disagree by more than the \
             {skew} seconds of tolerance this connection allows -- in either direction. A \
             response can be refused for being too NEW as easily as too old.</p>",
            skew = connection.clock_skew_secs
        ),
        // THE VARIANT NAMES THE ATTRIBUTE, so the page does too. Four different bounds produce
        // this, on two different elements, and the remedy is not the same for all of them: what
        // is common is that the named attribute is absent from what the provider emitted.
        ConditionError::MissingBound { attribute } => format!(
            "<p><strong>The assertion does not carry <code>{attribute}</code>.</strong></p>\
             <p>This deployment refuses an assertion whose lifetime it cannot bound, and that is \
             one of the bounds -- one of the four names it can be is a whole element rather than \
             an attribute of one, which is why the page prints the name instead of describing \
             it. In your identity provider, look at what it emits under that name; most emit all \
             of these by default and each can be turned off.</p>",
            attribute = escape_html(attribute)
        ),
        // AND THE VALUE, which is the whole point of the variant carrying it: "unreadable" with
        // nothing quoted leaves an operator looking at a timestamp that appears perfectly
        // ordinary. An earlier version named a numeric offset as the cause, which is one of
        // several and not the commonest.
        ConditionError::UnreadableBound { attribute, found } => format!(
            "<p><strong>This deployment cannot read <code>{attribute}</code>.</strong></p>\
             <p>It said <code>{found}</code>. SAML timestamps have to be UTC in the narrow \
             <code>xsd:dateTime</code> form, ending in <code>Z</code>, with a four-digit year \
             this side of 2200 and no leap second. A value that looks right on screen and is \
             refused here is usually one of those. Send this page to your vendor.</p>",
            attribute = escape_html(attribute),
            found = escape_html(found)
        ),
        // THE LIFETIME IS A COLUMN ON THIS CONNECTION, so "capture a fresh response" -- what the
        // catch-all used to say -- would have an operator recapturing forever: every document
        // their provider emits carries the same window.
        ConditionError::TooLongLived => format!(
            "<p><strong>Your identity provider issues assertions that stay valid for longer \
             than this connection will accept.</strong></p><p>This connection accepts at most \
             {seconds} seconds. Shorten the assertion lifetime in your identity provider, or \
             ask your vendor to raise the limit knowing what it costs: an assertion is a bearer \
             credential for as long as its window lasts.</p>",
            seconds = connection.max_assertion_age_secs
        ),
        // THE ACS URL IS A COPY-PASTE VALUE THIS PAGE ALREADY PRINTS, which makes this one of
        // the most actionable messages here: the two strings sit side by side and one of them is
        // wrong.
        ConditionError::WrongRecipient { found } => format!(
            "<p><strong>Your identity provider is sending the response to the wrong \
             address.</strong></p><p>The assertion names <code>{found}</code>. This connection \
             expects <code>{expected}</code>.</p><p>In your identity provider, set the \
             single sign-on URL (sometimes called the ACS URL, or the Reply URL) to exactly the \
             expected value above.</p>",
            found = escape_html(found.as_deref().unwrap_or("nothing")),
            expected = escape_html(&connection.acs_url)
        ),
        // THE VARIANT NAMES WHAT IT DID NOT UNDERSTAND, and the two producers are opposite in
        // where the fix lives, so the page prints the name and lets it distinguish them: an
        // unknown `Condition` element is a restriction this deployment does not implement, and
        // a `SubjectConfirmationData/@NotBefore` is an attribute an operator can remove.
        ConditionError::UnsupportedCondition { name } => format!(
            "<p><strong>The assertion carries <code>{name}</code>, which this deployment does \
             not implement.</strong></p><p>The specification requires refusing what we cannot \
             evaluate rather than ignoring it. If that names a setting in your identity \
             provider, turning it off is the fix; if it names an element of the specification, \
             send this page to your vendor.</p>",
            name = escape_html(name)
        ),
        // NOT REACHABLE FROM THIS SURFACE, and written out rather than swept into a catch-all.
        // `examine` passes the document's own `InResponseTo` as the expectation, so the
        // comparison can only agree; `saml_acs` records the same reachability at that call site.
        ConditionError::UnknownRequest => {
            "<p><strong>This response does not answer a sign-in this deployment \
             started.</strong></p><p>That is expected for a document captured earlier, and it \
             is not a fault in your configuration.</p>"
                .to_owned()
        }
        ConditionError::Malformed => {
            // NOT AN EXHAUSTIVE LIST, and it does not present itself as one. The variant is
            // returned from many places -- a root element that is not an assertion, a duplicated
            // element where one is allowed, a bearer confirmation that cannot be read, a window
            // whose ends are the wrong way round -- and an enumeration written as "either this
            // or that" would tell an operator their document is one of two things it may not be.
            "<p><strong>The assertion is not shaped the way the specification \
             requires.</strong></p><p>Something in it could not be read unambiguously: a common \
             case is two of an element the specification allows one of, and a document that says \
             two things is not read rather than having one half believed.</p><p>This is the \
             provider's own output rather than anything you pasted wrongly, so send this page to \
             your vendor.</p>"
                .to_owned()
        }
    }
}

/// The signature half of [`diagnose`].
///
/// # It names the observation, not a cause it cannot see
///
/// `VerifyError` has five variants and each covers SEVERAL producers -- `SignatureMissing`
/// alone has seven. An earlier version of this function printed one certificate-rotation
/// sentence for all five; the version that replaced it printed five sentences, each naming ONE
/// cause as if it were the only one, which is the same defect at finer grain. A reader told
/// "assertion signing is off" when their provider signs both elements goes and changes a setting
/// that was right.
///
/// So each arm says what this deployment OBSERVED, and offers the common causes as causes to
/// check rather than as the diagnosis.
fn diagnose_signature(
    error: ironauth_saml::VerifyError,
    connection: &ironauth_store::SamlConnection,
) -> String {
    use ironauth_saml::VerifyError;
    match error {
        VerifyError::SignatureMissing => {
            "<p><strong>This deployment could not find exactly one signature over the \
             assertion.</strong></p><p>It is not a certificate problem: nothing was compared \
             against what is pinned. The shapes that land here are an assertion with no \
             signature at all, a document carrying more than one where one was expected, and a \
             signature whose structure could not be read far enough to use.</p><p>In your \
             identity provider, check what it is configured to sign. Many can sign the response, \
             the assertion, or both, and this deployment reads the assertion's own \
             signature.</p>"
                .to_owned()
        }
        VerifyError::AlgorithmRefused => {
            "<p><strong>The signature uses something this deployment refuses.</strong></p>\
             <p>Also not a certificate problem. SHA-1 digests and RSA-SHA1 signatures land \
             here, and so does anything outside the narrow set of canonicalization methods and \
             transforms this deployment implements -- several shapes, all of them legal and \
             none of them read.</p><p>In your identity provider, set the signature algorithm to \
             RSA-SHA256 and the digest to SHA-256 first: that is by far the commonest of them \
             and the only one you can usually change. If it persists, the shape is one this \
             deployment does not implement and your vendor should see this page.</p>"
                .to_owned()
        }
        VerifyError::ReferenceRefused => {
            "<p><strong>The signature does not name the element this deployment needs to \
             read.</strong></p><p>The reference has to name exactly one element, that element \
             has to be the one being verified, and no other element may claim the same \
             identifier. A response carrying no assertion at all lands here too, which is what \
             an encrypted assertion looks like from outside.</p><p>This is the document's own \
             structure rather than a value you can correct, so send this page to your \
             vendor.</p>"
                .to_owned()
        }
        VerifyError::SignatureInvalid => format!(
            "<p><strong>The signature did not check out.</strong></p><p>This is the one that is \
             usually about the certificate: the likeliest cause by far is one rotated at your \
             identity provider and not re-pinned here, so export the current signing \
             certificate and compare it with what is pinned against <code>{name}</code>.</p>\
             <p>It is not the only cause. The digest over the signed element can fail before any \
             key is consulted, which is what a document altered in transit looks like -- copied \
             through something that reformatted it, most often. If the certificate matches, that \
             is the next thing to suspect.</p>",
            name = escape_html(&connection.display_name)
        ),
        VerifyError::Malformed(_) => {
            "<p><strong>This does not parse as a SAML document.</strong></p><p>If you pasted \
             it by hand, copy the value of the <code>SAMLResponse</code> form field exactly as \
             your browser sent it -- not the decoded XML, and not a value that has been through \
             an editor. If it came straight from a capture, the provider's own output is \
             malformed and your vendor should see this page.</p>"
                .to_owned()
        }
    }
}

/// The pasted document a connection test diagnoses.
#[derive(Debug, serde::Deserialize)]
pub struct ConnectionTestForm {
    /// Which SAML connection the response is supposed to be for.
    pub connection_id: String,
    /// The base64 `SAMLResponse` exactly as the identity provider produced it.
    pub saml_response: String,
}

/// Diagnose a SAML response the operator pasted, and say what to fix (issue #140 criterion 6).
///
/// # Why a paste rather than a round trip
///
/// The typed reasons already exist. `saml_acs::examine` returns a variant per fixable cause --
/// `NoTrustAnchor` for a certificate nobody pinned, `Condition(WrongAudience)` for an identity
/// provider sending the wrong audience -- and `saml_route`'s own doc says of them: "THAT FLOW IS
/// NOT BUILT ... today the variant reaches a Rust caller and nothing else". This is the flow.
///
/// The ACS cannot render those sentences. Its poster is anybody, and some of the variants quote
/// THIS DEPLOYMENT'S configuration back. Here the poster holds a portal session for the
/// organization that owns the connection, which makes them a reader entitled to their own
/// configuration -- the condition `saml_route` names for exactly this surface.
///
/// # It spends nothing
///
/// `examine` is the stateless half: it verifies the signature and checks the conditions and
/// never touches the store. So a test does not consume an outstanding request, does not record
/// a replay, and cannot burn a real sign-in that happens to be in flight. An operator may paste
/// the same document twice and get the same answer, which is what makes it a TEST rather than
/// a login attempt with the result printed.
pub async fn connection_test_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<ConnectionTestForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    // THE SAME ORIGIN GUARD every portal POST takes. This one reads a connection's pinned
    // certificates and reports on them, so a cross-origin post would let another site learn
    // whether a given organization has finished its SSO setup.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let session = match resolve_session(&state, scope, &headers).await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    if let Err(refusal) = session.require_intent("sso") {
        return refusal.into_response();
    }

    let read = state.store().scoped(scope);
    let Ok(connection_id) =
        ironauth_store::SamlConnectionId::parse_in_scope(&form.connection_id, &scope)
    else {
        return test_refusal("that is not a connection of this deployment");
    };
    // NOT `find_active`, WHICH IS THE WHOLE POINT OF THIS SURFACE. A switched-off connection is
    // invisible to that read, so the admin who is still SETTING THEIRS UP -- the one the form
    // beside it is rendered for -- posted this and was told "no active connection with that id",
    // which is also what the organization fence below answers. The sentence that came back read
    // as "that connection is not yours" and the page went quiet about the one fact that would
    // have helped.
    //
    // THE EXAMINATION IS WORTH RUNNING ON AN INACTIVE CONNECTION, and that is why this resolves
    // one rather than refusing it politely. `examine` reads the connection's columns and the
    // pinned certificates; none of that depends on the switch, so an operator can get their
    // audience and their certificate right BEFORE their vendor turns sign-in on. What they must
    // not get is a verdict that reads as "you are finished".
    let connection = match read
        .saml_connections()
        .find_in_org(session.organization(), &connection_id)
        .await
    {
        Ok(Some(connection)) => connection,
        // THE ORGANIZATION IS A PREDICATE OF THE READ, so a connection belonging to a neighbour
        // resolves to nothing here rather than to a row this handler must remember to check. A
        // portal session is bound to ONE organization and a connection id is guessable in the way
        // every id is: without this, a link issued for one customer diagnoses another's
        // connection and reports their audience and certificate count back.
        Ok(None) => return test_refusal("no connection with that id"),
        Err(_) => return PortalRefusal::Unavailable.into_response(),
    };
    let Ok(certificates) = read.saml_connections().certificates(&connection_id).await else {
        return PortalRefusal::Unavailable.into_response();
    };

    // THE SAME DECODER THE ACS USES, for the reason its doc gives: any input the two treat
    // differently makes this test lie about what a real sign-in would do. The first version here
    // called `.trim()` and decoded, which refused the line-wrapped field every identity provider
    // actually emits.
    let response = match crate::saml_route::decode_response_field(&form.saml_response) {
        Ok(response) => response,
        Err(crate::saml_route::ResponseDecodeError::TooLarge) => {
            return test_refusal(
                "that is larger than any SAMLResponse this deployment will read. Paste the \
                 value of the SAMLResponse form field rather than a whole captured trace",
            );
        }
        Err(crate::saml_route::ResponseDecodeError::NotBase64) => {
            return test_refusal(
                "that does not look like a SAMLResponse. Paste the base64 value of the \
                 SAMLResponse form field, not the URL and not the decoded XML",
            );
        }
    };

    let acs = crate::saml_acs::Acs {
        connection: &connection,
        certificates: &certificates,
        now_unix_secs: crate::saml_route::unix_seconds(state.now()),
        limits: &ironauth_saml::Limits::default(),
    };
    let verdict = match crate::saml_acs::examine(&acs, &response) {
        // EVERY CHECK `examine` MAKES, AND NOT ONE MORE, and the second sentence is what an
        // earlier version got wrong twice.
        //
        // IT DOES NOT MEAN THE CONNECTION ACCEPTS UNSOLICITED RESPONSES. Reaching here means the
        // unsolicited GUARD did not fire, and there are two ways that happens: the connection
        // allows them, or the document carries an `InResponseTo` -- which a captured response
        // from a real sign-in does, and that is the commonest thing an operator has to hand.
        // The earlier sentence asserted the first unconditionally, so a default connection was
        // told it accepted unsolicited responses when it refuses them.
        //
        // AND IT DOES NOT MEAN A REAL SIGN-IN WOULD SUCCEED. `examine` is the stateless half;
        // `consume` then spends the outstanding request and admits the assertion id, and a
        // captured document names a request that is already spent. So the same bytes in a real
        // sign-in end in `UnknownRequest` or `Replayed`. The earlier sentence said this reaches
        // "the end of the same path a real sign-in takes", which is exactly the half it does
        // not reach.
        Ok(_) => format!(
            "<p><strong>This response passes every check this deployment makes on the document \
             itself.</strong></p><p>Certificate, issuer, audience, validity window, name ID \
             format and attributes all hold.</p><p>{correlation}</p><p>What is NOT checked here \
             is the sign-in state: a real response also has to answer an outstanding request \
             that has not been spent, and a document captured earlier no longer does. That is \
             not a fault in your setup.</p>",
            correlation = if connection.allow_unsolicited {
                "This connection accepts a response it did not ask for, so a real sign-in does \
                 not have to carry a request reference either."
            } else {
                "This connection accepts only responses to its own requests. This document \
                 carries a request reference, which is why the check was reached at all -- a \
                 document without one would have stopped earlier."
            }
        ),
        Err(error) => diagnose(&error, &connection),
    };
    // WHAT THE VERDICT DOES NOT COVER, said above it rather than folded into it. A response can
    // be perfect and sign nobody in, because sign-in through this connection is switched off --
    // and a page that reported only the document's health would have an operator waiting for
    // something that is never going to start.
    let switched_off = if connection.active {
        String::new()
    } else {
        "<p><strong>Sign-in through this connection is switched off</strong>, whatever this \
         test says about the document. Your vendor has to enable it before anyone can use it.</p>"
            .to_owned()
    };
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Connection test</title>\
         <h1>Connection test</h1>{switched_off}{verdict}"
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// What an operator pastes into the SCIM connection check (issue #140 criterion 6).
#[derive(Debug, serde::Deserialize)]
pub struct ScimTokenCheckForm {
    /// The connection the token is supposed to belong to.
    pub connection_id: String,
    /// The bearer token as it was pasted into the identity provider.
    pub token: String,
}

/// Check a pasted SCIM bearer token against one connection and say what it is.
///
/// # The failure this exists for
///
/// A provisioning client that presents a bad token gets a 401, and nothing anywhere records
/// that it happened: `authenticate` stamps `last_seen_at` only on the row it ACCEPTED, and a
/// refusal resolves no row at all. So the portal's activity column says "No requests yet" --
/// which is true, and which is the same sentence it shows a customer who has not configured
/// their identity provider at all. The two states with completely different remedies are
/// indistinguishable, and that is precisely the generic error this criterion names.
///
/// Here the reader holds the token. Checking the one they hold against the one connection they
/// are entitled to read turns "nothing has happened" into "the value you pasted is the token we
/// superseded on the 4th", which names the fix.
///
/// # Why it is not a request to `/scim/v2`
///
/// The obvious design is to have the portal call its own SCIM endpoint with the pasted token.
/// It would answer a narrower question -- yes or no -- and it would answer it wrongly for this
/// reader, because `authenticate` deliberately collapses every refusal into the same `Unknown`
/// so a caller cannot tell a fenced tenant from an invented token. That uniformity is right for
/// an anonymous poster and useless to the person who owns the connection.
///
/// It would also STAMP. `authenticate` records a use, and an admin's test is not a use: the
/// click would land on the very column the page beside it reads to answer "has your identity
/// provider ever called?", so the page would start answering that question with the reader's own
/// button.
///
/// # What bounds the reach
///
/// TWO FENCES, AND THE LOOKUP IS THE ONE THAT DOES THE WORK. The connection the FORM names is
/// resolved with the session's organization as a PREDICATE, so a connection id belonging to a
/// neighbour resolves to nothing -- that is what stops this surface reading, stamping, or even
/// confirming the existence of a row outside the session's own organization, and it runs first.
///
/// The token then names a connection in its own id half, and `token_verdict` compares that
/// string to the connection already resolved. An earlier version of this paragraph said the
/// comparison happened "before any lookup runs", which is not the code's order and was not the
/// code's order when it was written. Saying so mattered: a reader would have taken the string
/// comparison for the cross-organization fence, and it is not -- it is the token-to-connection
/// binding, which refuses a token minted for a DIFFERENT connection of the SAME organization
/// without a second read.
pub async fn scim_token_check_post(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<ScimTokenCheckForm>,
) -> Response {
    let Some(scope) = parse_scope(&tenant_id, &environment_id) else {
        return refused();
    };
    // THE SAME ORIGIN GUARD every portal POST takes. A cross-origin post here would let another
    // site test tokens it holds against this customer's connection and read the answer.
    if !interaction::same_origin_ok(&headers, state.self_origin().as_deref()) {
        return interaction::forbidden_page();
    }
    let session = match resolve_session(&state, scope, &headers).await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    if let Err(refusal) = session.require_intent("scim") {
        return refusal.into_response();
    }
    // AND THE SURFACE MUST BE SERVED. The form is not rendered with `scim.enabled` off, but a
    // form not being rendered is not a fence: this path is reachable by anyone who can post. A
    // verdict here would be about a credential table on a deployment that answers `/scim/v2`
    // with a uniform 404, so "this token authenticates" would be true of the row and false of
    // everything the reader cares about.
    if !state.scim_surface_enabled() {
        return PortalRefusal::NotFound.into_response();
    }

    let Ok(connection_id) =
        ironauth_store::ScimConnectionId::parse_in_scope(&form.connection_id, &scope)
    else {
        return test_refusal("that is not a connection of this deployment");
    };
    let now = epoch_micros(state.env().clock().now_utc());
    let read = state.store().scoped(scope);
    let connection = match read
        .scim_connections()
        .find_in_organization(session.organization(), &connection_id, now)
        .await
    {
        Ok(Some(connection)) => connection,
        Ok(None) => return test_refusal("no connection with that id"),
        Err(_) => return PortalRefusal::Unavailable.into_response(),
    };

    let presented = form.token.trim();
    let Ok(verdict) = token_verdict(&read, &connection, &connection_id, presented, now).await
    else {
        return PortalRefusal::Unavailable.into_response();
    };
    // THE PASTED VALUE IS NEVER ECHOED, on any branch. It is a live credential in most of the
    // cases that reach here, and a page that quoted it back would put it into a browser history,
    // a screenshot, and whatever proxy sits between. Every sentence below is about the row it
    // matched, not about the string.
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Token check</title>\
         <h1>Token check</h1><p>Connection: {name}</p>{verdict}",
        name = escape_html(&connection.display_name),
    );
    crate::pages::secure_html(StatusCode::OK, body)
}

/// What to tell the reader about the token they pasted, as HTML.
///
/// `Err(())` is a read that did not happen, which is the deployment's failure rather than
/// anything about the token, and must not be reported as a verdict on it.
///
/// # The order is the order the remedies come in
///
/// The connection is examined before the token because a revoked or lapsed CONNECTION makes
/// every question about its tokens moot: no token of it authenticates, and telling a reader
/// their token is fine would send them back to their identity provider to look for a fault that
/// is not there. The reverse order was the first version of this function and it read
/// convincingly, which is how a wrong instruction survives a review.
async fn token_verdict(
    read: &ironauth_store::ScopedStore<'_>,
    connection: &ironauth_store::ScimConnection,
    connection_id: &ironauth_store::ScimConnectionId,
    presented: &str,
    now: i64,
) -> Result<String, ()> {
    // THE SHAPE FIRST, because a value that is not a token of this deployment at all is the
    // commonest paste error and needs no query to recognise. The id half is SCOPED, so this also
    // refuses a token minted for another tenant or environment before anything is looked up.
    let Some((handle, _)) = presented.split_once('.') else {
        return Ok(refusal_html(
            "That does not look like a provisioning token. Copy the whole value, including the \
             part before the full stop.",
        ));
    };
    // THE TOKEN NAMES ITS OWN CONNECTION, and comparing the two strings is the whole
    // cross-organization fence on this path: a token belonging to a neighbour is refused HERE,
    // before any read, so this surface cannot be used to confirm that a given connection id
    // exists somewhere else in the deployment.
    if handle != connection_id.to_string() {
        return Ok(refusal_html(
            "That token belongs to a different connection. Check you are looking at the \
             connection you configured it on.",
        ));
    }

    // THE CONNECTION'S OWN STATE, which outranks anything about the token; see the note above.
    if connection.revoked {
        return Ok(refusal_html(
            "This connection has been revoked, so nothing provisions through it whatever token \
             is presented. Ask your vendor for a new connection.",
        ));
    }
    if connection
        .expires_at_unix_micros
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Ok(refusal_html(
            "This connection has expired, so nothing provisions through it whatever token is \
             presented. It cannot be rotated: ask your vendor to replace it.",
        ));
    }

    let digest = ironauth_store::scim_token_digest(presented);
    let standing = read
        .scim_connections()
        .standing_of(connection_id, &digest)
        .await
        .map_err(|_| ())?;
    // NO ROW, AND THE ID HALF WAS RIGHT. Something was edited or lost between this connection's
    // token and the string in front of the reader, and the two ways that happens are worth
    // naming because the remedies differ: a copy that dropped characters is fixed by copying
    // again, and a token from a connection that was replaced is fixed by going to get the
    // current one.
    let Some(standing) = standing else {
        return Ok(refusal_html(
            "This is not a token of this connection. It may have been truncated when it was \
             copied, or it may be left over from a connection that has since been replaced. \
             Copy the current token and try again.",
        ));
    };

    if let Some(revoked_at) = standing.revoked_at_unix_micros {
        return Ok(refusal_html(&format!(
            "This token was revoked on {when}, which ends it immediately rather than at the end \
             of an overlap. Paste the current token into your identity provider.",
            when = escape_html(&crate::saml_start::rfc3339_utc(revoked_at / 1_000_000)),
        )));
    }
    if let Some(expires_at) = standing.expires_at_unix_micros {
        // A HORIZON ON A TOKEN ROW HAS TWO WRITERS AND THEY MEAN OPPOSITE THINGS. An earlier
        // version of this arm asserted only one of them -- "a horizon means a rotation
        // superseded it" -- and `create` copies the CONNECTION's own expiry onto the very first
        // token row. So a connection created with an expiry had its ONLY token reported as "the
        // PREVIOUS token", and its holder was told to go and copy a current one that does not
        // exist. `rotate_token` refuses a lapsed connection, so the remedy they would have asked
        // for is one this product answers with a not-found.
        //
        // WORSE, THE SAME PAGE SAID THE OPPOSITE. `connection_rows` renders that same date as
        // "Provisioning stops {when}: ask your vendor to replace this connection", with its own
        // comment explaining at length that the connection's expiry is cleared by nothing. Two
        // halves of one page, two contradictory instructions about one date.
        //
        // `superseded` IS THE DISCRIMINATOR and it is exact: something replaced this credential,
        // or nothing did.
        let when = escape_html(&crate::saml_start::rfc3339_utc(expires_at / 1_000_000));
        if !standing.superseded {
            // NOTHING REPLACED IT, so this date came from the connection it belongs to. The
            // sentence matches the status column's, because it is the same fact.
            if expires_at <= now {
                return Ok(refusal_html(&format!(
                    "This token stopped working on {when}, and nothing has replaced it. This \
                     connection cannot be rotated once that date has passed: ask your vendor to \
                     replace the connection.",
                )));
            }
            return Ok(format!(
                "<p>This token authenticates, and it stops on {when}.</p><p>Nothing has \
                 replaced it, and this date is the connection's own rather than a rotation's, \
                 so there is no newer token to copy. Ask your vendor to replace this connection \
                 before then.</p>{activity}",
                activity = activity_html(&standing),
            ));
        }
        if expires_at <= now {
            return Ok(refusal_html(&format!(
                "This token was replaced and stopped working on {when}. Copy the current token \
                 from this page into your identity provider.",
            )));
        }
        return Ok(format!(
            "<p>This is the PREVIOUS token. It still works, and it stops on {when}. Copy the \
             current token into your identity provider before then, or provisioning stops when \
             that date passes.</p>{activity}",
            activity = activity_html(&standing),
        ));
    }

    // NO HORIZON, NOT REVOKED, AND THE CONNECTION IS LIVE: this is what a provisioning client
    // presenting it would authenticate as.
    Ok(format!(
        "<p>This token authenticates against this connection.</p>{activity}",
        activity = activity_html(&standing),
    ))
}

/// What has actually happened through the token that was pasted, said only where it is knowable.
///
/// # A working token nobody has used is the finding
///
/// It is the state a half-finished rotation leaves, and the one thing that predicts an outage at
/// the end of an overlap: the credential is valid, the check says so, and the identity provider
/// is still calling with the old one. "This token authenticates" on its own would be read as
/// "provisioning is fine", which is the reading that ends when the window does.
fn activity_html(standing: &ironauth_store::ScimTokenStanding) -> String {
    if let Some(seen) = standing.last_seen_at_unix_micros {
        return format!(
            "<p>A request last arrived with it on {when}.</p>",
            when = escape_html(&crate::saml_start::rfc3339_utc(seen / 1_000_000)),
        );
    }
    // NOT OBSERVED IS NOT NOT USED, and the page must not collapse them: the legacy population
    // and every row that predates migration 0206 have no observation history at all, and saying
    // "nothing has used it" to them reports a working connection as dead. `connection_rows`
    // above draws the same distinction for the same reason.
    if standing.observed {
        "<p>No request has ever arrived with it. If you have already pasted it into your \
         identity provider, provisioning has not started: check it is in the provisioning \
         credential field rather than the SSO one.</p>"
            .to_owned()
    } else {
        "<p>Whether anything has used it is not recorded for this token.</p>".to_owned()
    }
}

/// A refusal on the token-check surface: a 200 carrying an explanation.
///
/// NOT AN ERROR STATUS, because none of these is one. The request was well formed and the reader
/// is entitled to the answer; what they pasted is the subject of the page rather than a fault in
/// it, and a 4xx would put a banner over the one sentence they came for.
fn refusal_html(reason: &str) -> String {
    format!("<p>{}</p>", escape_html(reason))
}
