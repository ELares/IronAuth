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
    // THE OTHER INTENTS STILL RENDER THEIR PLACEHOLDER: `sso`, `domain-verification` and
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
         {guides}",
        organization = escape_html(&session.organization().to_string()),
        endpoint = endpoint,
        rows = rows,
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
            "<tr><td>{name}</td><td>{email}</td><td>{receives}</td></tr>",
            name = escape_html(&contact.display_name),
            email = escape_html(&contact.email),
            receives = escape_html(describes_category(&contact.category)),
        );
    }
    body.push_str("</table>");
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
