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
//! # THE TOKEN IS THE SESSION, and a vendor has to treat it as one
//!
//! This is the cost of reusing the credential rather than minting a second, and it is stated
//! here rather than left for somebody to discover. The bearer a host holds is the same value the
//! `__Host-` cookie carries. Anything that can send an HTTP request with that value as a COOKIE
//! -- a server, a script, anything not a browser tab -- reaches every other portal route the
//! session's intent allows, INCLUDING the mutating ones: an `sso` widget token can drive the
//! SAML setup form, and a `scim` one can mint a provisioning credential.
//!
//! WHAT THAT CHANGES AND WHAT IT DOES NOT. It changes nothing about the vendor's BACKEND, which
//! redeemed the link and already held the session. It changes the vendor's FRONT END: a value
//! that was `HttpOnly` and unreadable by script is now in script, so a cross-site scripting bug
//! on the vendor's own page exfiltrates a working portal session instead of nothing.
//!
//! SO: mint a link per intent and hand a widget only the one it needs, which is what the intent
//! fence is for and which bounds this to the surface that widget shows. And know that the
//! bearer is a credential, not an identifier.
//!
//! CLOSING IT PROPERLY NEEDS A DISTINCT CREDENTIAL -- a read-only token derived from the session
//! and resolvable on its own -- which is a store change rather than a wording one, and which
//! this exploratory does not make. It is recorded here as the reason this surface is exploratory
//! rather than as an oversight.
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
    /// Whether sign-in through this connection is switched on.
    ///
    /// A FACT A STATUS WIDGET EXISTS FOR, and not the only one: a connection can be switched on
    /// and still sign nobody in, because it has no certificate pinned. The two travel together
    /// here for that reason -- `pinned_certificates: 0` beside `active: true` is a connection
    /// that will refuse every response its provider sends.
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
    /// The connector-based upstreams: OpenID Connect, OAuth 2.0, or whatever else a connector
    /// declares. Each row carries its own protocol, because they are not interchangeable.
    pub connectors: Vec<ConnectorUpstreamView>,
}

/// One CONNECTOR-BASED upstream, as a widget sees it.
///
/// # It exists because the hosted page reads TWO tables and the widget read one
///
/// A SAML upstream is a `saml_connections` row. The other kind is not a row of its own: it is an
/// `org_connections` binding naming a connector, which is why `sso_surface` reads both and says
/// so. The first version of this widget read only the first, so an organization whose sign-on is
/// federated this way -- an ordinary configuration -- rendered as an EMPTY list with
/// `truncated: false`, which a host app cannot distinguish from "nothing is configured".
///
/// # NOT "the OIDC upstream", which is what it was called and which was wrong
///
/// `OrgConnectionUpstream::Connector` is documented as "a `cnr_` OIDC or OAuth 2.0 connector",
/// and `sso_oidc_section` branches on the protocol with the reason spelled out: calling an
/// OAuth 2.0 connector OpenID Connect "sends its admin looking for an issuer URL and an
/// `openid` scope their provider does not have". The hosted page carries a regression test
/// forbidding exactly that label, and the first version of this view re-introduced it on the
/// JSON surface -- under a field name a host could not even contradict, because the protocol
/// was not in the payload.
#[derive(Debug, Serialize)]
pub struct ConnectorUpstreamView {
    /// The connector this organization is bound to.
    pub connector_id: String,
    /// The connector's SLUG, or `null` when the binding names one this deployment cannot read.
    ///
    /// A SLUG RATHER THAN A DISPLAY NAME, because `ConnectorRecord` has no display name: the
    /// slug is what an operator named it.
    ///
    /// NULL IS A REAL STATE and the hosted page has an arm for it: a binding can name a
    /// connector that has been removed. A host rendering the row can say so; a widget that
    /// dropped the row would report the organization as having one fewer upstream than it has.
    pub slug: Option<String>,
    /// What the connector's own definition declares: `oidc`, `oauth2`, or `null` when the
    /// definition does not say or the connector could not be read.
    ///
    /// THE FIELD THE MISLABEL NEEDED. The hosted page selects both its heading and its setup
    /// guide on this value, and without it a host app cannot write a true sentence about an
    /// OAuth 2.0 upstream at all.
    pub protocol: Option<String>,
    /// Whether sign-in through this upstream is switched on: BOTH switches, combined.
    ///
    /// TWO ROWS DECIDE IT and either alone is a half-truth: the BINDING carries an `enabled`,
    /// and so does the CONNECTOR, and disabling the connector stops every organization bound to
    /// it. An earlier version reported the binding's only, so an operator who switched a
    /// connector off left every widget reading it saying "sign-in is on".
    ///
    /// A CONNECTOR THIS DEPLOYMENT CANNOT READ IS FALSE TOO. A binding naming a row that is gone
    /// signs nobody in, and the row is still reported -- with `slug: null` -- because dropping
    /// it would tell the organization it has one fewer upstream than it has.
    pub enabled: bool,
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
    /// Whether NOTHING a customer can present will authenticate right now.
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
    /// cleared by nothing -- `create` is the only path that writes `scim_connections.expires_at`
    /// and nothing UPDATES it, so once a connection carries one that date is fixed, provisioning
    /// stops on it for good, and the only remedy is a replacement connection.
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

/// What the SCIM widget answers with: the connections AND the two facts a SETUP flow needs.
///
/// # Criterion 6 names a SCIM-SETUP flow, not a SCIM-status one
///
/// "Widgets render the SSO-status and SCIM-SETUP flows inside a host-app fixture." A list of
/// existing connections is a status panel; what a host renders to somebody SETTING provisioning
/// up is where their provisioning client connects, and whether this deployment serves that
/// endpoint at all. The hosted page prints both, and prints the URL only where it is served --
/// with the reason at that branch: "nothing stops a portal link with the `scim` intent being
/// minted anyway", and an admin sent to configure their provider against an endpoint that
/// answers nothing discovers it days later as "provisioning never started".
#[derive(Debug, Serialize)]
pub struct ScimWidgetItems {
    /// Where a provisioning client connects, or `null` when this deployment does not serve it.
    ///
    /// NULL RATHER THAN THE URL, for the reason the page has: a base URL printed on a
    /// deployment whose `/scim/v2` is a uniform 404 is an instruction that cannot work.
    pub base_url: Option<String>,
    /// Whether this deployment serves inbound provisioning at all.
    ///
    /// IT CANNOT DISAGREE WITH `base_url` BEING NULL, and an earlier version of this sentence
    /// claimed it could -- it named "we could not read your configuration" as a second state the
    /// pair distinguishes, and no path here produces one: a failure to read answers the uniform
    /// refusal instead, and the two fields come from the same flag.
    ///
    /// IT IS HERE ANYWAY, because a host reading a null has to know WHY without being told to
    /// infer it, and because the day this surface gains a second reason for a missing URL, the
    /// flag is where that reason goes. A host that branches on it today is correct and will stay
    /// correct; one that branches on the null alone would have to change.
    pub surface_served: bool,
    /// The connections.
    pub connections: Vec<ScimConnectionView>,
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
        Err(refusal) => return cors_refusal(refusal),
    };
    let read = state.store().scoped(session.scope());
    let Ok(connections) = read
        .saml_connections()
        .list_for_org(session.organization(), WIDGET_LIMIT + 1, None)
        .await
    else {
        return cors_refusal(PortalRefusal::Unavailable);
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
            return cors_refusal(PortalRefusal::Unavailable);
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
    // is a row of its own, a connector-based one is an `org_connections` binding, and neither
    // table sees the other's. A widget that read one reported an organization federating the
    // other way as having nothing configured.
    // THE FILTER IS IN THE STATEMENT, which is the only place it can be. An earlier version
    // asked for every binding and filtered in Rust, and called that "the filter runs before the
    // bound" -- it does not: the bound that matters is the SQL `LIMIT`, and it had already
    // chosen which rows came back. So an organization with more SAML bindings than the limit
    // still got `connectors: []`, and worse, the truncation flag was computed AFTER the discard
    // and so reported `false` about rows that had been dropped.
    let Ok(bindings) = read
        .org_connections()
        .list_connector_bindings(session.organization(), WIDGET_LIMIT + 1)
        .await
    else {
        return cors_refusal(PortalRefusal::Unavailable);
    };
    let limit = usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX);
    let truncated = truncated || bindings.len() > limit;
    let mut connectors = Vec::new();
    for binding in bindings.iter().take(limit) {
        let Some(raw) = binding.connector_id.as_deref() else {
            continue;
        };
        // THE NAME AND THE PROTOCOL ARE BEST EFFORT AND THE ROW IS NOT. A binding can name a
        // connector that has since been removed, and the hosted page has an arm for exactly
        // that; dropping the row would report the organization as having one fewer upstream
        // than it has.
        let found = match read.connectors().parse_id(raw) {
            Ok(id) => read.connectors().get(&id).await.ok(),
            Err(_) => None,
        };
        connectors.push(ConnectorUpstreamView {
            connector_id: raw.to_owned(),
            slug: found.as_ref().map(|connector| connector.slug.clone()),
            // BOTH SWITCHES, because sign-in needs both and either alone is a half-truth. An
            // earlier version reported only the BINDING's, so a connector an operator had
            // disabled -- which stops every organization bound to it -- still rendered as "sign
            // in is on". A connector this deployment cannot read at all is `false` too: a
            // binding naming a row that is gone signs nobody in either.
            enabled: binding.enabled && found.as_ref().is_some_and(|connector| connector.enabled),
            // FROM THE DEFINITION, through the same function the hosted page uses to choose its
            // heading and its guide. A second reading of that document is how a page comes to
            // call an upstream something the runtime does not.
            protocol: found.as_ref().and_then(|connector| {
                crate::portal_guides::connector_protocol(&connector.definition_json)
            }),
        });
    }

    widget_response(
        &session,
        truncated,
        SsoWidgetItems {
            saml: items,
            connectors,
        },
    )
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
        Err(refusal) => return cors_refusal(refusal),
    };
    let now = epoch_micros(state.env().clock().now_utc());
    let Ok(connections) = state
        .store()
        .scoped(session.scope())
        .scim_connections()
        .list_for_organization(session.organization(), WIDGET_LIMIT + 1, None, now)
        .await
    else {
        return cors_refusal(PortalRefusal::Unavailable);
    };
    let truncated = connections.len() > usize::try_from(WIDGET_LIMIT).unwrap_or(usize::MAX);
    let connection_views: Vec<ScimConnectionView> = connections
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
    widget_response(
        &session,
        truncated,
        ScimWidgetItems {
            // PRINTED ONLY WHERE IT IS SERVED, exactly as the hosted page prints it.
            base_url: state
                .scim_surface_enabled()
                .then(|| format!("{}/scim/v2", state.issuer_base())),
            surface_served: state.scim_surface_enabled(),
            connections: connection_views,
        },
    )
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
/// THE 200's `Access-Control-Allow-Headers` DID NOT COVER THIS. That header is consulted only on
/// a preflight RESPONSE; on the GET it is inert, which is why it is no longer sent there -- an
/// earlier version kept it on the 200 with a comment claiming it was what made preflights
/// succeed, and BOTH the header and the claim have gone.
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
/// between an unflagged deployment and that work.
///
/// WHAT THE ORDERING DOES NOT BUY IS INDISTINGUISHABILITY, and nothing here claims otherwise.
/// An earlier version claimed it, and its replacement then claimed the fact was "discoverable
/// from the published feature registry" -- also unestablished: the registry publishes what
/// features EXIST, not which a given deployment enabled. What is true is narrower and enough: a
/// timing difference between a disabled surface and a spent token reveals whether an operator
/// switched on an exploratory feature, which is not a secret this deployment undertakes to keep,
/// and the responses themselves are byte-identical, which is the property the suite pins.
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
            (header::CACHE_CONTROL, "no-store"),
        ],
        Json(body),
    )
        .into_response()
}

/// Put the cross-origin headers on a REFUSAL, which is the half that was missing.
///
/// # A preflight that succeeds and a refusal a host cannot read is worse than neither
///
/// `widget_session` answers a uniform not-found for a disabled feature, a bad scope, an absent
/// or spent bearer, and the wrong intent -- four states a host app has to distinguish from a
/// network failure in order to say anything useful to its user. Every one of them carried no
/// `Access-Control-Allow-Origin` at all, so a browser refused to expose the response and the
/// host saw an opaque error.
///
/// THE PREFLIGHT MADE THAT WORSE RATHER THAN BETTER. Before it, nothing reached these routes
/// from a browser at all; now the fetch happens, gets its answer, and the answer is unreadable.
///
/// THE HEADERS MUST MATCH THE SUCCESS PATH EXACTLY, which is why they are one function. A
/// refusal authorising a narrower set than the 200 would be a surface a host can read when it
/// works and not when it does not.
fn cors_refusal(refusal: PortalRefusal) -> Response {
    let mut response = refusal.into_response();
    let out = response.headers_mut();
    out.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        axum::http::HeaderValue::from_static("*"),
    );
    out.insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
