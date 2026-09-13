//! Embeddable portal widgets: the SSO-status and SCIM-setup surfaces as org-scoped JSON
//! (issue #145 criterion 6, EXPLORATORY).
//!
//! # What a widget is, and what it is not
//!
//! The hosted portal sends a customer's IT admin AWAY, to a page that reads as the vendor's
//! product only as far as the branding system reaches. A widget is the same facts delivered to
//! the VENDOR'S OWN application, which renders them in its own layout beside its own navigation.
//! This module is the delivery half. The rendering half is the vendor's, by definition, and the
//! test suite carries a host-app fixture that does it so the claim "a widget renders inside a
//! host app" is measured rather than asserted.
//!
//! # BEARER ONLY, and the cookie is refused on purpose
//!
//! Every other portal route authenticates with `__Host-ironauth_portal_session`, which a browser
//! attaches by itself. That is exactly what a widget must not rely on: a widget is fetched by
//! code running on the vendor's origin, and a route that accepted an ambient cookie from a
//! cross-origin fetch would be spendable by any page the customer's browser happens to open.
//! The same-origin guard the mutating portal routes take is the other half of that answer, and
//! it does not apply to a GET a third party is MEANT to make.
//!
//! So these routes read the session token from `Authorization: Bearer` and nowhere else. The
//! consequences are all in the right direction: there is no ambient authority to forge, `Access-
//! Control-Allow-Origin: *` is safe to send because no credential rides along with it, and a
//! browser that holds the portal cookie cannot turn it into a bearer because the cookie is
//! `HttpOnly`.
//!
//! # Where the vendor gets a token
//!
//! From the link it already mints. `POST /portal/{link_id}` redeems a link and returns the
//! session in a `Set-Cookie`; a vendor's BACKEND can make that call itself, read the value, and
//! hand it to its own front end. Nothing new mints anything, which is deliberate: a second
//! minting path for the same credential is a second place for its TTL, its single-use rule and
//! its intent to be decided, and those are the properties the portal link exists to carry.
//!
//! # READ ONLY
//!
//! Every route here is a GET that reads rows and serialises them. A widget that could write
//! would need the CSRF answer this module just argued it does not have to give.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::portal_route::{PortalRefusal, PortalSession, resolve_session_from_bearer};
use crate::state::OidcState;
use crate::util::epoch_micros;
use crate::wellknown::parse_scope;

/// One SSO connection, as a widget sees it.
///
/// THE SAME FACTS THE HOSTED PAGE PRINTS, and no more. A widget is a second renderer of one
/// surface, not a second surface: a field here that the page does not show would be a
/// disclosure decision made in the place least likely to be reviewed for one.
#[derive(Debug, Serialize)]
pub struct SsoConnectionView {
    /// The connection's id, which the host echoes back to address it.
    pub id: String,
    /// What the customer called it.
    pub display_name: String,
    /// Whether sign-in through it is switched on.
    ///
    /// THE ONE FACT A STATUS WIDGET EXISTS FOR. A connection can be fully configured and still
    /// sign nobody in, and that is invisible from every other field.
    pub active: bool,
    /// The identity provider this connection trusts.
    pub idp_entity_id: String,
    /// What this deployment asks the provider to send as the audience.
    pub sp_entity_id: String,
    /// Where the provider posts responses.
    pub acs_url: String,
    /// How many signing certificates are pinned.
    ///
    /// A COUNT RATHER THAN THE CERTIFICATES. What a status widget answers is "has anybody
    /// finished the pinning step", and zero is the whole answer. The material itself is on the
    /// hosted certificate surface, behind its own intent.
    pub pinned_certificates: usize,
}

/// One provisioning connection, as a widget sees it.
#[derive(Debug, Serialize)]
pub struct ScimConnectionView {
    /// The connection's id.
    pub id: String,
    /// What the customer called it.
    pub display_name: String,
    /// `okta`, `entra` or `generic`.
    pub provider: String,
    /// Whether an operator switched this connection off.
    pub revoked: bool,
    /// Whether anything a customer can present will authenticate right now.
    ///
    /// THE BROKEN STATE, named as its own field for the reason `ScimConnection::live_token_count`
    /// gives: a connection with no usable credential and one that simply never expires publish
    /// the same absent deadline, and only one of them needs somebody today.
    pub provisioning_stopped: bool,
    /// The next deadline one of its credentials meets, in epoch microseconds.
    ///
    /// A DEADLINE TO ACT ON RATHER THAN AN OUTAGE TO EXPECT. During a rotation overlap this is
    /// the date the customer has to have finished pasting the new token by; the date
    /// provisioning would actually stop is usually never. The field name that got this wrong
    /// once is recorded on `ScimConnection::credential_expires_at_unix_micros`.
    pub next_deadline_unix_micros: Option<i64>,
    /// When a request last arrived with any of its credentials, or `null`.
    pub last_seen_at_unix_micros: Option<i64>,
    /// Whether an absent `last_seen_at_unix_micros` may be read as "nothing has used it".
    ///
    /// FALSE IS NOT A SMALL CAVEAT. It is every token row that predates migration 0206, which is
    /// the whole installed base on upgrade day, and a host that rendered the absent stamp as
    /// "never used" would tell those customers their working connection is dead. The flag
    /// travels beside the value so a renderer cannot read one without the other.
    pub usage_is_knowable: bool,
}

/// What a widget request answers with.
#[derive(Debug, Serialize)]
pub struct WidgetEnvelope<T> {
    /// The organization every row belongs to, echoed so a host cannot mis-file a response.
    ///
    /// IT COMES FROM THE SESSION, never from the request, and a host that asked for another one
    /// gets this one. Echoing it is what lets a host app holding two customers' widgets notice
    /// if it ever wired them up wrongly.
    pub organization_id: String,
    /// Whether more rows exist than were returned.
    ///
    /// A BOUND THAT ADMITS ITSELF. A silent truncation reads to a host as "this customer has
    /// three connections", and it renders a complete-looking list that is not one.
    pub truncated: bool,
    /// The rows.
    pub items: Vec<T>,
}

/// `GET /t/{tenant}/e/{environment}/portal/w/sso`: this organization's SSO connections.
///
/// # Errors
///
/// Answers a uniform 404 when the feature is off, when no bearer resolves a session, and when
/// the session's intent is not `sso` -- the same not-found the hosted surfaces give, for the
/// same reason: a host must not be able to tell a disabled feature from a spent token from a
/// link minted for something else.
pub async fn sso_widget(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let session = match widget_session(&state, &tenant_id, &environment_id, &headers, "sso").await {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    let read = state.store().scoped(session.scope());
    let Ok(connections) = read
        .saml_connections()
        .list_for_org(session.organization(), WIDGET_LIMIT + 1, None)
        .await
    else {
        return PortalRefusal::Unavailable.into_response();
    };
    let truncated = connections.len() > usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX);
    let mut items = Vec::new();
    for connection in connections
        .iter()
        .take(usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX))
    {
        // ONE READ PER CONNECTION, which is what a certificate COUNT costs when the listing does
        // not carry one. It is bounded by `WIDGET_LIMIT` and this is a read-only surface behind
        // an exploratory flag; if it ever matters the count belongs in the listing's projection
        // rather than here.
        let Ok(certificates) = read.saml_connections().certificates(&connection.id).await else {
            return PortalRefusal::Unavailable.into_response();
        };
        items.push(SsoConnectionView {
            id: connection.id.to_string(),
            display_name: connection.display_name.clone(),
            active: connection.active,
            idp_entity_id: connection.idp_entity_id.clone(),
            sp_entity_id: connection.sp_entity_id.clone(),
            acs_url: connection.acs_url.clone(),
            pinned_certificates: certificates.len(),
        });
    }
    widget_response(&session, truncated, items)
}

/// `GET /t/{tenant}/e/{environment}/portal/w/scim`: this organization's provisioning connections.
///
/// # Errors
///
/// As [`sso_widget`], with the `scim` intent.
pub async fn scim_widget(
    State(state): State<OidcState>,
    Path((tenant_id, environment_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let session = match widget_session(&state, &tenant_id, &environment_id, &headers, "scim").await
    {
        Ok(session) => session,
        Err(refusal) => return refusal.into_response(),
    };
    let now = epoch_micros(state.env().clock().now_utc());
    let Ok(connections) = state
        .store()
        .scoped(session.scope())
        .scim_connections()
        .list_for_organization(session.organization(), WIDGET_LIMIT + 1, None, now)
        .await
    else {
        return PortalRefusal::Unavailable.into_response();
    };
    let truncated = connections.len() > usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX);
    let items = connections
        .iter()
        .take(usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX))
        .map(|connection| ScimConnectionView {
            id: connection.id.to_string(),
            display_name: connection.display_name.clone(),
            provider: connection.provider.clone(),
            revoked: connection.revoked,
            provisioning_stopped: connection.no_live_credential(),
            next_deadline_unix_micros: connection.credential_expires_at_unix_micros,
            last_seen_at_unix_micros: connection.last_seen_at_unix_micros,
            usage_is_knowable: connection.usage_history_complete,
        })
        .collect();
    widget_response(&session, truncated, items)
}

/// The most rows a widget returns.
///
/// SMALLER THAN THE HOSTED PAGE'S, because a widget is a panel in somebody else's layout rather
/// than a page of its own, and because the bound is REPORTED: a host that needs the rest knows
/// there is a rest.
const WIDGET_LIMIT: i64 = 20;

/// Resolve the session a widget request speaks for, or the uniform refusal.
///
/// THE FOUR FENCES IN ORDER, and the order is what makes the answer uniform: the feature, the
/// scope, the bearer, then the intent. An enabled-feature check that ran after the session
/// resolution would make a spent token distinguishable from a disabled deployment by timing
/// alone.
async fn widget_session(
    state: &OidcState,
    tenant_id: &str,
    environment_id: &str,
    headers: &HeaderMap,
    intent: &str,
) -> Result<PortalSession, PortalRefusal> {
    if !state.portal_widgets_enabled() {
        return Err(PortalRefusal::NotFound);
    }
    let Some(scope) = parse_scope(tenant_id, environment_id) else {
        return Err(PortalRefusal::NotFound);
    };
    let session = resolve_session_from_bearer(state, scope, headers).await?;
    session.require_intent(intent)?;
    Ok(session)
}

/// The JSON body, with the headers a cross-origin reader needs and no others.
fn widget_response<T: Serialize>(
    session: &PortalSession,
    truncated: bool,
    items: Vec<T>,
) -> Response {
    let body = WidgetEnvelope {
        organization_id: session.organization().to_string(),
        truncated,
        items,
    };
    (
        StatusCode::OK,
        [
            // SAFE ONLY BECAUSE THERE IS NO AMBIENT CREDENTIAL. `*` and
            // `Access-Control-Allow-Credentials` are mutually exclusive by the fetch
            // specification, and this surface wants neither: the bearer is attached by the
            // host's own code, so a page that has not been given the token learns nothing by
            // being allowed to ask.
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            // THE BEARER IS THE ONLY HEADER A HOST HAS TO SEND, and naming it is what keeps a
            // browser's preflight from failing on a request this surface accepts.
            (header::ACCESS_CONTROL_ALLOW_HEADERS, "authorization"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Json(body),
    )
        .into_response()
}
