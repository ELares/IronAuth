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

/// What the SSO widget answers with: both kinds of upstream, because an organization may have
/// either or both and a host cannot tell an absent kind from an unread one.
#[derive(Debug, Serialize)]
pub struct SsoWidgetItems {
    /// The SAML connections.
    pub saml: Vec<SsoConnectionView>,
    /// The OpenID Connect upstreams.
    pub oidc: Vec<OidcUpstreamView>,
}

/// One OpenID Connect upstream, as a widget sees it.
///
/// # It exists because the hosted page reads TWO tables and the widget read one
///
/// A SAML upstream is a `saml_connections` row. An OIDC upstream is not a row of its own: it is
/// an `org_connections` binding naming a connector, which is why `sso_surface` reads both and
/// says so. The first version of this widget read only the first, so an organization whose sign
/// on is OIDC -- an ordinary configuration -- rendered as an EMPTY list with `truncated: false`,
/// which a host app cannot distinguish from "nothing is configured". A status widget that
/// reports a working configuration as absent is worse than no widget.
#[derive(Debug, Serialize)]
pub struct OidcUpstreamView {
    /// The connector this organization is bound to.
    pub connector_id: String,
    /// The connector's SLUG, or `null` when the binding names one this deployment cannot read.
    ///
    /// A SLUG RATHER THAN A DISPLAY NAME, because `ConnectorRecord` has no display name: the
    /// slug is what an operator named it and what the hosted page keys its guide on.
    ///
    /// NULL IS A REAL STATE and the hosted page has an arm for it: a binding can name a
    /// connector that has been removed. A host rendering the row can say so; a widget that
    /// dropped the row would report the organization as having one fewer upstream than it has.
    pub slug: Option<String>,
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
    ///
    /// IT IS NOT `no_live_credential` ALONE. That method answers `!revoked && live_token_count
    /// == 0` on purpose, because the hosted page renders "Revoked" in an arm above the one that
    /// calls it. A widget is one boolean with no arms, so this ORs the two -- and the version
    /// that did not reported a revoked connection as working, which the host-app fixture
    /// rendered word for word.
    pub provisioning_stopped: bool,
    /// The next deadline one of its credentials meets, in epoch microseconds.
    ///
    /// A DEADLINE TO ACT ON RATHER THAN AN OUTAGE TO EXPECT, and the field name that got this
    /// wrong once is recorded on `ScimConnection::credential_expires_at_unix_micros`.
    ///
    /// WHAT IT DOES NOT SAY IS WHICH DEADLINE IT IS, and a host must not assume. It is the
    /// LEAST of the connection's own expiry and its soonest live token's, and the two have
    /// opposite remedies: a token deadline is cleared by rotating, and the connection's own is
    /// cleared by nothing -- no path in this system writes `scim_connections.expires_at`, so on
    /// that date provisioning stops for good and the only remedy is a replacement connection.
    /// The hosted page distinguishes them by comparing this against the connection's own expiry;
    /// this payload carries only the LEAST, so a host rendering "renew before" would be wrong
    /// for one of the two populations.
    ///
    /// A host that needs to tell them apart should say what it knows -- "the next deadline" --
    /// and send the reader to the hosted page, or ask for the discriminator to be added here.
    pub next_deadline_unix_micros: Option<i64>,
    /// When a request last arrived with any of its credentials, or `null`.
    pub last_seen_at_unix_micros: Option<i64>,
    /// Whether an absent `last_seen_at_unix_micros` may be read as "nothing has used it".
    ///
    /// FALSE IS NOT A SMALL CAVEAT AND IT COVERS THREE POPULATIONS, not the one an earlier
    /// version of this sentence named: every token row that predates migration 0206, which is
    /// the whole installed base on upgrade day; a connection with no token rows at all, which
    /// authenticates through the legacy column and may be provisioning right now; and one that
    /// adopted a legacy credential by rotation, whose earlier life went unwatched. A host that
    /// rendered the absent stamp as "never used" would tell all three their working connection
    /// is dead. The flag travels beside the value so a renderer cannot read one without the
    /// other.
    ///
    /// AND TRUE IS NOT PROOF EITHER. `ScimConnection::usage_history_complete` records what it
    /// still cannot see: mid-rolling-upgrade, traffic served only by replicas that predate 0206
    /// is watched by nobody while the rows say otherwise. Read it as "no request was observed,
    /// and observation was in place".
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
    ///
    /// NOT ALWAYS A LIST. The SSO widget answers two kinds of upstream, which a single list
    /// could only express by tagging each row -- so this is whatever shape that widget's items
    /// take, and the envelope stays one type across both routes.
    pub items: T,
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

    // AND THE OTHER KIND. `sso_surface` reads both tables and its doc says why: a SAML upstream
    // is a row of its own, an OIDC upstream is an `org_connections` binding naming a connector,
    // and neither table sees the other's. A widget that read one reported an organization whose
    // sign-on is OIDC as having none.
    let Ok(bindings) = read
        .org_connections()
        .list_for_organization(session.organization(), WIDGET_LIMIT + 1)
        .await
    else {
        return PortalRefusal::Unavailable.into_response();
    };
    let truncated =
        truncated || bindings.len() > usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX);
    let mut oidc = Vec::new();
    for binding in bindings
        .iter()
        .take(usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX))
    {
        let Some(raw) = binding.connector_id.as_deref() else {
            continue;
        };
        // THE NAME IS BEST EFFORT AND THE ROW IS NOT. A binding can name a connector that has
        // since been removed, and the hosted page has an arm for exactly that; dropping the row
        // would report the organization as having one fewer upstream than it has.
        let slug = match read.connectors().parse_id(raw) {
            Ok(id) => read
                .connectors()
                .get(&id)
                .await
                .ok()
                .map(|connector| connector.slug.clone()),
            Err(_) => None,
        };
        oidc.push(OidcUpstreamView {
            connector_id: raw.to_owned(),
            slug,
        });
    }

    widget_response(&session, truncated, SsoWidgetItems { saml: items, oidc })
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
    let items: Vec<ScimConnectionView> = connections
        .iter()
        .take(usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX))
        .map(|connection| ScimConnectionView {
            id: connection.id.to_string(),
            display_name: connection.display_name.clone(),
            provider: connection.provider.clone(),
            revoked: connection.revoked,
            // REVOKED COUNTS, and `no_live_credential` deliberately does not say so:
            // it is `!revoked && live_token_count == 0`, because the hosted page renders
            // "Revoked" in its own arm BEFORE reaching that method. A widget has no such
            // arm -- this is one boolean -- so reading the method alone reported a revoked
            // connection as working, and the host-app fixture rendered exactly that.
            provisioning_stopped: connection.revoked || connection.no_live_credential(),
            next_deadline_unix_micros: connection.credential_expires_at_unix_micros,
            last_seen_at_unix_micros: connection.last_seen_at_unix_micros,
            usage_is_knowable: connection.usage_history_complete,
        })
        .collect();
    widget_response(&session, truncated, items)
}

/// `OPTIONS` on either widget path: the CORS preflight a browser sends before the real fetch.
///
/// # Without this the whole surface is unreachable from the only consumer it is for
///
/// `Authorization` is not a CORS-safelisted request header, so a cross-origin `fetch` that
/// attaches the bearer ALWAYS sends an `OPTIONS` first. A path registered with `get(...)` alone
/// answers that with 405 and no `Access-Control-Allow-*` headers at all, the browser blocks, and
/// the GET is never sent -- so "a widget is fetched by code running on the vendor's origin",
/// which is this module's entire premise, does not work in any browser.
///
/// THE 200's `Access-Control-Allow-Headers` DID NOT COVER THIS, and an earlier comment beside it
/// said it did. That header is consulted only on a preflight RESPONSE; on the GET it is inert.
///
/// `/userinfo` is the same crate's other bearer-and-CORS surface and it mounts a preflight for
/// exactly this reason. This one differs in one way, and deliberately: it answers every origin
/// rather than a registered one, because the widget surface sends `*` on the GET and the two
/// have to agree -- a preflight narrower than the response it authorises would pass for one
/// origin and fail for another that the GET would have served.
///
/// NO CREDENTIAL IS CONSULTED HERE. A preflight carries none by specification, and answering it
/// discloses only that these paths exist, which the route table already does.
pub async fn widget_preflight() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"),
            (header::ACCESS_CONTROL_ALLOW_HEADERS, "authorization"),
            // TEN MINUTES, as `/userinfo` uses. A preflight per widget fetch would double the
            // round trips on a page that renders several.
            (header::ACCESS_CONTROL_MAX_AGE, "600"),
        ],
    )
        .into_response()
}

/// The most rows a widget returns.
///
/// SMALLER THAN THE HOSTED PAGE'S, because a widget is a panel in somebody else's layout rather
/// than a page of its own, and because the bound is REPORTED: a host that needs the rest knows
/// there is a rest.
const WIDGET_LIMIT: i64 = 20;

/// Resolve the session a widget request speaks for, or the uniform refusal.
///
/// THE FOUR FENCES: the feature, the scope, the bearer, then the intent. An earlier version of
/// this paragraph claimed the ORDER was what made the answer uniform, and had the argument
/// exactly backwards: checking the feature first is what CREATES a timing difference, because a
/// disabled deployment returns without the store read an enabled one makes.
///
/// THE ORDER STAYS ANYWAY, and the reason is the opposite of the one that was written here. A
/// deployment that has not enabled this surface should not be doing token lookups for it: the
/// read is work an unauthenticated caller can compel, and the flag is the only thing standing
/// between an unflagged deployment and that work. What the ordering does NOT buy is
/// indistinguishability, and this deployment does not claim it: whether a feature is switched on
/// is an operator's configuration rather than a secret, and it is discoverable from the
/// published feature registry regardless.
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
fn widget_response<T: Serialize>(session: &PortalSession, truncated: bool, items: T) -> Response {
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
