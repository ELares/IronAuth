//! Redeeming a portal link over the real router (issue #140).
//!
//! # What these drive that the store tests cannot
//!
//! The store suite proves the redemption is atomic and single-use. What only the router can show
//! is the property #140 actually asks for: that the GET a mail scanner performs does NOT spend
//! the link, that the POST does, and that the browser leaves with a cookie whose authority is
//! the row rather than anything it presented.
#![cfg(feature = "testing")]

mod common;

use common::Harness;
use ironauth_env::Env;
use ironauth_store::{CorrelationId, NewPortalLink, OrganizationId, PortalLinkId};

/// SHA-256 of a bearer value, which is what the row stores.
fn digest(token: &str) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(token.as_bytes()).to_vec()
}

async fn get(harness: &Harness, path: &str) -> (axum::http::StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(path)
        .body(axum::body::Body::empty())
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    (status, body)
}

/// Mint a link through the CONTROL store and return its path and id.
///
/// THE CONTROL PLANE MINTS, which is not a detail of the harness but of the product: a portal
/// link is created by a vendor's backend calling the management API, and the data plane the
/// router runs on holds `SELECT` plus a column-scoped `UPDATE` on `portal_links` and nothing
/// more. Seeding through `harness.store()` fails with a permission error, and that failure is
/// the grant working.
async fn wire(harness: &Harness, intent: &str, token: &str) -> (String, PortalLinkId) {
    let organization = seed_org(harness, "Globex").await;
    wire_in(harness, intent, token, &organization).await
}

/// One organization, created through the CONTROL plane as the product does.
async fn seed_org(harness: &Harness, name: &str) -> OrganizationId {
    let env = Env::system();
    let scope = harness.scope();
    let organization = OrganizationId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .management()
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .organizations(scope)
        .create(&env, &organization, 1_000_000, name, None)
        .await
        .expect("create organization");
    organization
}

/// A link for an organization the caller already holds, so a test can put TWO organizations in
/// one environment and check that a session for one cannot see the other.
async fn wire_in(
    harness: &Harness,
    intent: &str,
    token: &str,
    organization: &OrganizationId,
) -> (String, PortalLinkId) {
    let env = Env::system();
    let scope = harness.scope();
    let id = PortalLinkId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .portal_links()
        .mint(
            &env,
            NewPortalLink {
                id: &id,
                organization_id: organization,
                intent,
                token_digest: &digest(token),
            },
            1_000_000,
            i64::MAX / 4,
        )
        .await
        .expect("mint the link");

    let path = format!(
        "/t/{}/e/{}/portal/{id}",
        scope.tenant(),
        scope.environment()
    );
    (path, id)
}

#[tokio::test]
async fn the_confirmation_get_does_not_spend_the_link() {
    // THE REASON THE TWO ROUTES EXIST. Enterprise mail scanners follow links in mail they are
    // inspecting, and this link works once. If the GET redeemed, the admin's own click would
    // find a spent link and the vendor would be minting a second one for every customer whose
    // mail provider does its job.
    let harness = Harness::start_store_backed().await;
    let (path, _) = wire(&harness, "sso", "tok-a").await;

    let (status, body) = get(&harness, &format!("{path}?t=tok-a")).await;
    assert_eq!(status, 200, "the confirmation page: {body}");

    // AND THE LINK STILL REDEEMS AFTERWARDS, which is the assertion that matters: a 200 from a
    // handler that had also consumed the row would satisfy the status check above.
    let (status, _, body) = harness.post_form(&path, "t=tok-a", None).await;
    assert_eq!(
        status, 303,
        "the GET spent the link, so the recipient's own click fails: {body}"
    );
}

#[tokio::test]
async fn the_confirmation_page_answers_the_same_for_an_unknown_link() {
    // NO ORACLE. The GET does not look the link up at all, so a page that differed for a live
    // link would tell anybody who can see the URL -- every mail scanner between the vendor and
    // the admin among them -- whether it is still good.
    let harness = Harness::start_store_backed().await;
    let (live, _) = wire(&harness, "sso", "tok-b").await;
    let scope = harness.scope();
    let absent = format!(
        "/t/{}/e/{}/portal/{}",
        scope.tenant(),
        scope.environment(),
        PortalLinkId::generate(&Env::system(), &scope)
    );

    let (live_status, live_body) = get(&harness, &format!("{live}?t=tok-b")).await;
    let (absent_status, absent_body) = get(&harness, &format!("{absent}?t=tok-b")).await;
    assert_eq!(live_status, absent_status);
    // The bodies differ only where the id is echoed into the form action, so compare with each
    // id removed rather than asserting equality on text that legitimately carries it.
    let strip = |body: &str, path: &str| body.replace(path, "{link}");
    assert_eq!(
        strip(&live_body, &live),
        strip(&absent_body, &absent),
        "the confirmation page distinguishes a live link from an unknown one"
    );
}

#[tokio::test]
async fn redeeming_sets_a_host_prefixed_session_cookie_and_redirects() {
    // WHAT THE BROWSER LEAVES WITH. The cookie is the session's proof; its REACH is the row.
    let harness = Harness::start_store_backed().await;
    let (path, _) = wire(&harness, "scim", "tok-c").await;

    let (status, headers, body) = harness.post_form(&path, "t=tok-c", None).await;
    assert_eq!(status, 303, "redeeming: {body}");
    let cookie = headers
        .get(axum::http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("a session cookie is set")
        .to_owned();
    assert!(
        cookie.starts_with("__Host-ironauth_portal_session="),
        "the session cookie is not __Host- prefixed, so a sibling subdomain can write it: \
         {cookie}"
    );
    for attribute in ["Secure", "HttpOnly", "Path=/"] {
        assert!(
            cookie.contains(attribute),
            "the session cookie is missing {attribute}: {cookie}"
        );
    }
    // THE TOKEN FROM THE LINK IS NOT THE COOKIE. If the handler ever handed the link's own
    // bearer value back as the session credential, the URL sitting in the admin's history and in
    // every mail scanner's log would stay live for the session's whole life.
    assert!(
        !cookie.contains("tok-c"),
        "the link's token was reused as the session cookie: {cookie}"
    );
}

#[tokio::test]
async fn a_second_redemption_of_one_link_is_refused() {
    // SINGLE-USE, OVER THE ROUTER. The store proves the statement; this proves the handler
    // reports it, and reports it as the same not-found an unknown link gets.
    let harness = Harness::start_store_backed().await;
    let (path, _) = wire(&harness, "sso", "tok-d").await;

    let (first, _, _) = harness.post_form(&path, "t=tok-d", None).await;
    assert_eq!(first, 303);
    let (second, headers, body) = harness.post_form(&path, "t=tok-d", None).await;
    assert_eq!(second, 404, "a link redeemed twice: {body}");
    assert!(
        headers.get(axum::http::header::SET_COOKIE).is_none(),
        "the refused redemption still set a session cookie"
    );
}

#[tokio::test]
async fn the_wrong_token_is_refused_and_leaves_the_link_live() {
    // THE ID IS NOT SECRET -- it is in the URL, in logs, in audit rows. So holding it must buy
    // nothing, and a failed guess must not burn the link for its rightful holder, which would be
    // a denial of service anybody who saw the URL could mount.
    let harness = Harness::start_store_backed().await;
    let (path, _) = wire(&harness, "sso", "tok-e").await;

    let (status, headers, body) = harness.post_form(&path, "t=not-the-token", None).await;
    assert_eq!(status, 404, "a wrong token redeemed: {body}");
    assert!(headers.get(axum::http::header::SET_COOKIE).is_none());

    let (status, _, body) = harness.post_form(&path, "t=tok-e", None).await;
    assert_eq!(
        status, 303,
        "a wrong-token attempt burned the link for its rightful holder: {body}"
    );
}

#[tokio::test]
async fn a_redemption_with_no_token_is_refused() {
    // THE TOKEN COMES FROM THE FORM AND ONLY THE FORM. A POST carrying the token in the QUERY
    // STRING instead must not work: accepting it there would let a bare URL be turned into a
    // redeeming request by anything that can cause a navigation, which is exactly what the
    // GET/POST split exists to prevent.
    let harness = Harness::start_store_backed().await;
    let (path, _) = wire(&harness, "sso", "tok-f").await;

    let (status, _, body) = harness
        .post_form(&format!("{path}?t=tok-f"), "", None)
        .await;
    assert_eq!(
        status, 404,
        "a POST redeemed using a token from the query string: {body}"
    );

    // AND THE LINK IS UNTOUCHED, so the refusal above did not merely spend it silently.
    let (status, _, body) = harness.post_form(&path, "t=tok-f", None).await;
    assert_eq!(status, 303, "the refused attempt spent the link: {body}");
}

#[tokio::test]
async fn one_environments_link_cannot_be_redeemed_in_another() {
    // THE PARSE IS THE FENCE HERE, and saying so is the point: a `plk_` id EMBEDS its scope, so
    // `parse_in_scope` refuses it under any other environment before a statement runs. An
    // earlier version of this comment credited the store's scope predicate, which this request
    // never reaches -- and it drove a SYNTACTICALLY INVALID environment id, so it was refused by
    // `EnvironmentId::parse` and measured neither.
    //
    // The sibling below is a REAL, seeded environment, so the refusal is about the link
    // belonging elsewhere rather than about the path being unparsable.
    let harness = Harness::start_store_backed().await;
    let (_, id) = wire(&harness, "sso", "tok-g").await;
    let sibling = harness.db().seed_scope(&Env::system()).await;
    let foreign = format!(
        "/t/{}/e/{}/portal/{id}",
        sibling.tenant(),
        sibling.environment()
    );

    let (status, _, body) = harness.post_form(&foreign, "t=tok-g", None).await;
    assert_eq!(
        status, 404,
        "one environment redeemed another's portal link: {body}"
    );
}

/// Redeem a link and return the session cookie the browser would hold.
async fn open_session(harness: &Harness, intent: &str, token: &str) -> String {
    let (path, _) = wire(harness, intent, token).await;
    let (status, headers, body) = harness.post_form(&path, &format!("t={token}"), None).await;
    assert_eq!(status, 303, "opening a session: {body}");
    headers
        .get(axum::http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .expect("a session cookie is set")
        .to_owned()
}

async fn get_with_cookie(
    harness: &Harness,
    path: &str,
    cookie: Option<&str>,
) -> (axum::http::StatusCode, String) {
    let mut builder = axum::http::Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(axum::http::header::COOKIE, cookie);
    }
    let (status, _, body) = harness
        .send(
            builder
                .body(axum::body::Body::empty())
                .expect("request builds"),
        )
        .await;
    (status, body)
}

#[tokio::test]
async fn the_redirect_target_serves_the_session_that_was_just_opened() {
    // THE REDEMPTION'S 303 MUST LAND SOMEWHERE. The link is spent by the time the browser
    // follows it, so a redirect to a path nothing serves is a dead end with no way back -- the
    // failure the atomic redeem-and-open prevents at the store, reintroduced one layer up.
    let harness = Harness::start_store_backed().await;
    let cookie = open_session(&harness, "sso", "tok-h").await;
    let scope = harness.scope();
    let home = format!("/t/{}/e/{}/portal", scope.tenant(), scope.environment());

    let (status, body) = get_with_cookie(&harness, &home, Some(&cookie)).await;
    assert_eq!(status, 200, "the portal home: {body}");
    assert!(
        body.contains("sso"),
        "the home page does not name the session's intent: {body}"
    );
}

#[tokio::test]
async fn the_portal_is_unreachable_without_a_session_cookie() {
    // NO COOKIE, NO SESSION. Anonymous reach into the portal would make the link pointless.
    let harness = Harness::start_store_backed().await;
    let scope = harness.scope();
    let home = format!("/t/{}/e/{}/portal", scope.tenant(), scope.environment());

    let (status, body) = get_with_cookie(&harness, &home, None).await;
    assert_eq!(status, 404, "the portal answered without a cookie: {body}");

    // A COOKIE NAMING NOTHING is the same answer, so a holder of a stale one cannot tell
    // "expired" from "never existed".
    let (status, _) = get_with_cookie(
        &harness,
        &home,
        Some("__Host-ironauth_portal_session=not-a-real-session"),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn an_sso_session_cannot_reach_the_scim_surface() {
    // ISSUE #140, ACCEPTANCE CRITERION 2, VERBATIM: "an `sso` link cannot reach SCIM or
    // domain-verification surfaces". This is that criterion, driven.
    let harness = Harness::start_store_backed().await;
    let cookie = open_session(&harness, "sso", "tok-i").await;
    let scope = harness.scope();
    let surface = |intent: &str| {
        format!(
            "/t/{}/e/{}/portal/s/{intent}",
            scope.tenant(),
            scope.environment()
        )
    };

    // ITS OWN SURFACE WORKS, so the refusals below are the intent fence rather than the surface
    // being unreachable for this session at all.
    let (status, body) = get_with_cookie(&harness, &surface("sso"), Some(&cookie)).await;
    assert_eq!(status, 200, "the session's own surface: {body}");

    // THE WHOLE CLOSED SET BAR THIS SESSION'S OWN. Enumerated by hand and therefore a list
    // that goes stale: it had three entries when the set had four, so #141's fifth intent was
    // added with a fence nothing checked for it. `certificate-renewal` is the one that matters
    // most here, because its surface is the only one that leads to a write.
    for forbidden in [
        "scim",
        "domain-verification",
        "log-streams",
        "certificate-renewal",
        "contacts",
        "audit",
    ] {
        let (status, body) = get_with_cookie(&harness, &surface(forbidden), Some(&cookie)).await;
        assert_eq!(
            status, 404,
            "an sso session reached the {forbidden} surface: {body}"
        );
    }

    // AND AN UNKNOWN SURFACE ANSWERS THE SAME, which is what stops the fence being an oracle for
    // which surfaces this deployment serves.
    let (status, _) = get_with_cookie(&harness, &surface("invented"), Some(&cookie)).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn a_scim_session_reaches_scim_and_not_sso() {
    // THE OTHER DIRECTION, because a fence that refused everything but `sso` would pass the test
    // above for the wrong reason. Both directions or neither.
    let harness = Harness::start_store_backed().await;
    let cookie = open_session(&harness, "scim", "tok-j").await;
    let scope = harness.scope();
    let surface = |intent: &str| {
        format!(
            "/t/{}/e/{}/portal/s/{intent}",
            scope.tenant(),
            scope.environment()
        )
    };

    let (status, body) = get_with_cookie(&harness, &surface("scim"), Some(&cookie)).await;
    assert_eq!(status, 200, "a scim session's own surface: {body}");
    let (status, body) = get_with_cookie(&harness, &surface("sso"), Some(&cookie)).await;
    assert_eq!(
        status, 404,
        "a scim session reached the sso surface: {body}"
    );
}

#[tokio::test]
async fn a_session_cookie_from_another_environment_is_inert() {
    // A COOKIE MINTED IN ONE ENVIRONMENT IS INERT IN ANOTHER, and what enforces that is worth
    // stating precisely because two earlier versions of this comment got it wrong.
    //
    // It is NOT the parser: a session cookie carries no id, the digest is the lookup key, so
    // there is nothing to parse. (The first version drove a syntactically invalid environment
    // id and was refused by `EnvironmentId::parse` before any query ran, measuring nothing.)
    //
    // It is NOT the `tenant_id`/`environment_id` clause in `authenticate` ALONE, which the
    // second version called "the only thing standing between a cookie and a sibling
    // environment's rows". FORCE ROW LEVEL SECURITY on `portal_sessions` filters on the same two
    // GUCs that `begin_scoped` sets, so deleting that clause leaves this test green: the policy
    // still hides the row. The clause is defence in depth against a future read that forgets to
    // go through `begin_scoped`, not the fence.
    //
    // WHAT THIS TEST PROVES is the property that matters and the only one it can: the two
    // together refuse, and the same cookie still works in its own scope, so the refusal is the
    // scope rather than a lapsed session. Proving which of the two layers did it would mean
    // defeating RLS, which the application role cannot do -- and if it could, that would be the
    // finding.
    let harness = Harness::start_store_backed().await;
    let cookie = open_session(&harness, "sso", "tok-k").await;
    let sibling = harness.db().seed_scope(&Env::system()).await;
    let foreign = format!("/t/{}/e/{}/portal", sibling.tenant(), sibling.environment());

    let (status, body) = get_with_cookie(&harness, &foreign, Some(&cookie)).await;
    assert_eq!(
        status, 404,
        "one environment served another's portal session: {body}"
    );

    // AND THE COOKIE STILL WORKS IN ITS OWN SCOPE, so the refusal above is the scope predicate
    // rather than the session having lapsed or the cookie being malformed.
    let own = format!(
        "/t/{}/e/{}/portal",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(&harness, &own, Some(&cookie)).await;
    assert_eq!(
        status, 200,
        "the cookie stopped working in its own scope: {body}"
    );
}

/// POST with explicit fetch-metadata headers, so a test can be conclusively cross-site.
async fn post_form_from(
    harness: &Harness,
    path: &str,
    form: &str,
    site: &str,
) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header("sec-fetch-site", site)
        .body(axum::body::Body::from(form.to_owned()))
        .expect("request builds");
    harness.send(request).await
}

#[tokio::test]
async fn a_cross_site_redemption_is_refused_and_spends_nothing() {
    // LOGIN-CSRF AND SESSION FIXATION, which `SameSite=Lax` does not stop. SameSite decides
    // whether a browser SENDS an existing cookie; this request sends none, it MINTS one, and a
    // cross-site top-level POST may store a Lax cookie which the 303's navigation then carries.
    //
    // The attack it buys: anyone holding an unredeemed link -- their own, or one seen in a
    // forwarded ticket or a mail scanner log -- auto-submits it from a page the victim opens.
    // The victim's browser ends up holding a live portal session for the ATTACKER'S
    // organization, and because the cookie name is a single fixed slot, the victim's own session
    // is overwritten while their link is already spent.
    let harness = Harness::start_store_backed().await;
    let (path, _) = wire(&harness, "sso", "tok-csrf").await;

    let (status, headers, body) = post_form_from(&harness, &path, "t=tok-csrf", "cross-site").await;
    assert_eq!(
        status, 403,
        "a conclusively cross-site redemption was accepted: {body}"
    );
    assert!(
        headers.get(axum::http::header::SET_COOKIE).is_none(),
        "the cross-site redemption set a session cookie, which is the fixation half"
    );

    // AND IT SPENT NOTHING. A refusal that had already consumed the link would be a denial of
    // service anybody who saw the URL could mount against its rightful holder, which is worse
    // than the refusal is worth.
    let (status, _, body) = post_form_from(&harness, &path, "t=tok-csrf", "same-origin").await;
    assert_eq!(
        status, 303,
        "the refused cross-site attempt burned the link: {body}"
    );
}

#[tokio::test]
async fn a_same_origin_redemption_still_works() {
    // THE OTHER DIRECTION. A check that refused everything would satisfy the test above, and the
    // real confirmation page posts same-origin.
    let harness = Harness::start_store_backed().await;
    let (path, _) = wire(&harness, "sso", "tok-same").await;

    let (status, _, body) = post_form_from(&harness, &path, "t=tok-same", "same-origin").await;
    assert_eq!(status, 303, "a same-origin redemption was refused: {body}");
}

#[tokio::test]
async fn finishing_ends_the_session_immediately() {
    // THE CALLER FOR `revoke`, and the reason it needs one: without it an admin who has finished
    // leaves a live portal session in a browser -- possibly a shared machine -- for the rest of
    // the half hour, with nothing able to end it.
    let harness = Harness::start_store_backed().await;
    let cookie = open_session(&harness, "sso", "tok-fin").await;
    let scope = harness.scope();
    let home = format!("/t/{}/e/{}/portal", scope.tenant(), scope.environment());
    let finish = format!("{home}/finish");

    // IT WORKS FIRST, so the refusal below is the revocation rather than the session never
    // having authenticated.
    let (status, _) = get_with_cookie(&harness, &home, Some(&cookie)).await;
    assert_eq!(status, 200);

    let request = axum::http::Request::builder()
        .method("POST")
        .uri(&finish)
        .header(axum::http::header::COOKIE, &cookie)
        .header("sec-fetch-site", "same-origin")
        .body(axum::body::Body::empty())
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, 200, "finishing: {body}");

    // AND THE COOKIE IS INERT NOW, not in thirty minutes.
    let (status, body) = get_with_cookie(&harness, &home, Some(&cookie)).await;
    assert_eq!(
        status, 404,
        "the session still authenticates after being finished: {body}"
    );
}

#[tokio::test]
async fn a_cross_site_finish_is_refused() {
    // A FORGED LOGOUT IS A SMALLER ACT THAN A FORGED REDEMPTION, but it is still a state change
    // a third party should not be able to trigger, and the check costs nothing.
    let harness = Harness::start_store_backed().await;
    let cookie = open_session(&harness, "sso", "tok-fin2").await;
    let scope = harness.scope();
    let home = format!("/t/{}/e/{}/portal", scope.tenant(), scope.environment());

    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{home}/finish"))
        .header(axum::http::header::COOKIE, &cookie)
        .header("sec-fetch-site", "cross-site")
        .body(axum::body::Body::empty())
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, 403, "a cross-site finish was accepted: {body}");

    // AND THE SESSION SURVIVED, so the refusal is not a revocation by another name.
    let (status, _) = get_with_cookie(&harness, &home, Some(&cookie)).await;
    assert_eq!(
        status, 200,
        "the refused cross-site finish revoked the session anyway"
    );
}

/// Open a session for a link minted against `organization`.
async fn open_session_in(
    harness: &Harness,
    intent: &str,
    token: &str,
    organization: &OrganizationId,
) -> String {
    let (path, _) = wire_in(harness, intent, token, organization).await;
    let (status, headers, body) = harness.post_form(&path, &format!("t={token}"), None).await;
    assert_eq!(status, 303, "opening a session: {body}");
    headers
        .get(axum::http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .expect("a session cookie is set")
        .to_owned()
}

/// Create a SCIM connection in `organization` through the CONTROL plane, as the vendor does.
async fn connect(
    harness: &Harness,
    organization: &OrganizationId,
    display_name: &str,
    token: &str,
    expires_at_unix_micros: Option<i64>,
) -> ironauth_store::ScimConnectionId {
    connect_with_provider(
        harness,
        organization,
        display_name,
        "okta",
        token,
        expires_at_unix_micros,
    )
    .await
}

/// As [`connect`], naming the provider, which is what the setup guides are keyed on.
async fn connect_with_provider(
    harness: &Harness,
    organization: &OrganizationId,
    display_name: &str,
    provider: &str,
    token: &str,
    expires_at_unix_micros: Option<i64>,
) -> ironauth_store::ScimConnectionId {
    let env = Env::system();
    let scope = harness.scope();
    let id = ironauth_store::ScimConnectionId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .create(
            &env,
            ironauth_store::NewScimConnection {
                id: &id,
                organization_id: organization,
                display_name,
                provider,
                token_digest: &hex_digest(token),
                expires_at_unix_micros,
            },
            None,
        )
        .await
        .expect("create the connection");
    id
}

/// The harness clock in epoch microseconds, which is the unit every deadline here is in.
fn now_micros(harness: &Harness) -> i64 {
    i64::try_from(
        harness
            .env()
            .clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_micros(),
    )
    .expect("a microsecond count inside i64")
}

/// SHA-256 of a bearer value as hex, which is what the SCIM token column holds.
///
/// Written the way `ironauth-store`'s own SCIM tests write it, appending to one buffer rather
/// than collecting a `format!` per byte.
fn hex_digest(token: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(token.as_bytes()) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The provisioning page shows THIS organization's connections and no others.
///
/// # Issue #140 criterion 3, on the first surface that can express it
///
/// "A portal session for org A cannot read or mutate any org B state". Until this page existed
/// there was nothing for that to mean: the portal rendered its own intent and organization id and
/// read no organization-scoped data at all, so the criterion's ORG dimension had no surface to be
/// tested against. Its SCOPE dimension is covered elsewhere in this file, by the link that cannot
/// be redeemed in another environment and the cookie that is inert in one.
///
/// TWO ORGANIZATIONS IN ONE ENVIRONMENT, which is the arrangement that can actually fail. A
/// session confined by scope alone would pass a cross-environment test and still hand one
/// customer another customer's provisioning connections, because both live under the same tenant
/// and environment and differ only by the organization on the session row.
#[tokio::test]
async fn a_portal_session_sees_only_its_own_organizations_connections() {
    // THE SURFACE IS MOUNTED on this harness, because this test also asserts the provisioning
    // URL the page hands over, and the page prints that only where it is served.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let mine = seed_org(&harness, "Acme").await;
    let theirs = seed_org(&harness, "Globex").await;
    connect(&harness, &mine, "acme-okta", "tok-acme", None).await;
    connect(&harness, &theirs, "globex-entra", "tok-globex", None).await;

    let cookie = open_session_in(&harness, "scim", "tok-p1", &mine).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;

    assert_eq!(status, 200, "the provisioning page: {body}");
    // THE CONTROL: the page really is listing connections, so the absence below is a fence
    // rather than a page that lists nothing at all.
    assert!(
        body.contains("acme-okta"),
        "the session's own connection is missing from its provisioning page: {body}"
    );
    assert!(
        !body.contains("globex-entra"),
        "one customer's portal listed ANOTHER customer's provisioning connection: {body}"
    );

    // AND THE COPY-PASTE VALUE AN ADMIN CAME FOR: the base URL their provisioning client
    // connects to. Asserted as a DEPLOYMENT-wide absolute URL, because the SCIM surface is
    // mounted unscoped -- `mount_public(scim_router(..))` serves `/scim/v2/...` and the bearer
    // token is what carries the tenant and environment. A page that helpfully rendered the
    // per-environment issuer instead would hand the admin a URL that 404s, and it would look
    // more correct rather than less.
    assert!(
        body.contains("/scim/v2"),
        "the provisioning base URL is missing, which is the value the page exists to hand over: \
         {body}"
    );
    let advertised = body
        .split("<code>")
        .nth(1)
        .and_then(|rest| rest.split("</code>").next())
        .expect("the base URL is rendered in a code element");
    // TIED TO THIS DEPLOYMENT, not merely well-shaped. Asserting only that it is absolute and
    // unscoped is satisfied by a hardcoded literal, which is the defect that assertion was
    // written to catch and did not: the value has to be the issuer base THIS state was built
    // with, or a page serving two deployments hands both the same address.
    // DERIVED FROM THE HARNESS, not read off the state: `OidcState::issuer_base` is
    // `pub(crate)` and widening it so a test can reach it would be the test changing the shipped
    // surface to make itself easier. The per-environment issuer is that base plus the scope path,
    // so stripping the scope path recovers it.
    let scope_path = format!("/t/{}/e/{}", scope.tenant(), scope.environment());
    let deployment_base = harness
        .issuer()
        .strip_suffix(&scope_path)
        .expect("the per-environment issuer is the deployment base plus the scope path");
    assert_eq!(
        advertised,
        format!("{deployment_base}/scim/v2"),
        "the advertised provisioning URL is not this deployment's own base"
    );
    assert!(
        !advertised.contains("/t/"),
        "the advertised base is scoped to a tenant path, but the SCIM surface is mounted \
         unscoped -- pasting this into a provisioning client would 404: {advertised}"
    );
}

/// The five rows `each_connection_row_reports_which_of_the_five_states_it_is_in` asserts over.
///
/// Split out because the seeding is most of that test's length and none of its subject: what the
/// test is about is which words each row ends up with, and the reasoning for each fixture's SHAPE
/// belongs next to the fixture.
async fn seed_five_states(
    harness: &Harness,
    org: &OrganizationId,
    now: i64,
    day: i64,
) -> ironauth_store::ScimConnectionId {
    let env = Env::system();
    let writes = || {
        harness.db().control_store().scoped(harness.scope()).acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
    };
    connect(harness, org, "never-expires", "tok-a", None).await;

    // THE TOKEN-DEADLINE ROWS ARE BUILT BY ROTATION, not by a connection expiry. `create` writes
    // its `expires_at` onto the connection AND its first token, so a connection-expiry fixture
    // produces a row whose two timestamps are equal -- which is the OUTAGE case, and asserting
    // "Renew before" on such a row pinned the wrong wording for a whole review round. A rotation
    // leaves the connection no expiry of its own and gives the superseded token a horizon, which
    // is the state the renew wording is actually for.
    let soon = connect(harness, org, "renew-inside-the-lead", "tok-b", None).await;
    let later = connect(harness, org, "renew-outside-the-lead", "tok-e", None).await;
    writes()
        .scim_connections()
        .rotate_token(&env, &soon, &hex_digest("tok-b2"), 20 * 24 * 60 * 60, now)
        .await
        .expect("rotate the inside-the-lead connection");
    writes()
        .scim_connections()
        .rotate_token(&env, &later, &hex_digest("tok-e2"), 40 * 24 * 60 * 60, now)
        .await
        .expect("rotate the outside-the-lead connection");

    // AND A CONNECTION-EXPIRY ROW, whose deadline nothing can move: no path writes
    // `scim_connections.expires_at`, and rotating mints a token with no horizon while leaving
    // that column where it was. This row has to say provisioning stops rather than tell the
    // customer to renew, which is a remedy they can perform forever without moving the date.
    connect(
        harness,
        org,
        "expires-in-twenty-days",
        "tok-x",
        Some(now + 20 * day),
    )
    .await;

    let revoked = connect(harness, org, "switched-off", "tok-c", Some(now + 40 * day)).await;
    writes()
        .scim_connections()
        .revoke(&env, &revoked, now)
        .await
        .expect("revoke the connection");

    // THE BROKEN ONE, built the only way the API can build it: rotate so the original token is
    // superseded to the end of a short overlap, then revoke the fresh token outright. The
    // CONNECTION stays live -- its own expiry is forty days out -- so what the page reports is
    // the loss of its credentials rather than the connection lapsing.
    let broken = connect(
        harness,
        org,
        "credentials-gone",
        "tok-d",
        Some(now + 40 * day),
    )
    .await;
    writes()
        .scim_connections()
        .rotate_token(&env, &broken, &hex_digest("tok-d2"), 60, now)
        .await
        .expect("rotate");
    writes()
        .scim_connections()
        .revoke_token(&env, &broken, &hex_digest("tok-d2"), now)
        .await
        .expect("revoke the fresh token");
    // PAST THE OVERLAP, or the superseded token is still live and this connection reads as
    // "stops working in sixty seconds" rather than as broken. The rotation is what makes the
    // original token lapse and the revocation is what removes its replacement; neither has
    // happened yet on a clock that has not moved.
    harness.clock().advance(std::time::Duration::from_secs(120));

    broken
}

/// The five-state page, seeded and fetched, with a per-row extractor.
///
/// Returned as `(body, now, day)` so the two tests below assert over ONE page rather than seeding
/// the same five connections twice: the fixtures are a hundred lines of setup whose shape is
/// argued at its own site, and the tests are about which words each row ends up with.
async fn five_state_page(harness: &Harness) -> (String, i64, i64) {
    let org = seed_org(harness, "Acme").await;
    let now = now_micros(harness);
    let day = 24 * 60 * 60 * 1_000_000_i64;
    seed_five_states(harness, &org, now, day).await;

    let cookie = open_session_in(harness, "scim", "tok-p2", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");
    (body, now, day)
}

/// One row out of the rendered table, by connection name.
///
/// PER ROW, not per page: asserting that the page contains "Renew before" somewhere would be
/// satisfied by any one of the rows carrying it, including the wrong one.
fn row(body: &str, name: &str) -> String {
    let cell = format!("<td>{name}</td>");
    let at = body
        .find(&cell)
        .unwrap_or_else(|| panic!("no row for {name}: {body}"));
    let rest = &body[at..];
    let end = rest.find("</tr>").unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// Which deadline a row carries decides what it tells the customer to do about it.
#[tokio::test]
async fn each_deadline_row_names_the_remedy_that_fits_its_deadline() {
    let harness = Harness::start_store_backed_with_scim_warning_lead(30 * 24 * 60 * 60).await;
    let (body, now, day) = five_state_page(&harness).await;
    let row = |name: &str| row(&body, name);

    assert!(
        row("never-expires").contains("Active") && !row("never-expires").contains("until"),
        "a connection with no deadline is not plainly active: {}",
        row("never-expires")
    );
    assert!(
        row("renew-inside-the-lead").contains("Renew before"),
        "a connection lapsing twenty days out, under a THIRTY-day configured lead, is not \
         reported as stopping -- the page is reading a lead it was not given: {}",
        row("renew-inside-the-lead")
    );
    // THE DATE ITSELF, on both deadline branches. Nothing asserted it before, so the
    // microseconds-to-seconds conversion the page performs was unpinned: feeding microseconds
    // to a seconds formatter prints a year around 55,000 and every assertion stayed green.
    let rendered = |at: i64| -> String {
        // A DELIBERATE SECOND IMPLEMENTATION, which is the point rather than an oversight. The
        // page formats through `saml_start::rfc3339_utc`, and asserting its output against a call
        // to that same function would be `f(x) == f(x)` -- green whatever it computes. What this
        // catches is the conversion the page does BEFORE formatting: it divides microseconds to
        // seconds, and feeding microseconds straight in prints a year around 55,000. Written
        // independently here, from the same published algorithm, the two agree only if both are
        // right about the value being passed.
        let secs = at / 1_000_000;
        let days = secs.div_euclid(86_400);
        let rest = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day_of = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day_of:02}T{:02}:{:02}:{:02}Z",
            rest / 3600,
            (rest % 3600) / 60,
            rest % 60
        )
    };
    assert!(
        row("renew-inside-the-lead").contains(&rendered(now + 20 * day)),
        "the warned row does not carry the date it is counting down to: {}",
        row("renew-inside-the-lead")
    );
    // THE DEADLINE NOTHING CAN MOVE says so, and does NOT tell the customer to renew. Rotating
    // this connection re-supersedes the token they just pasted and leaves the printed date
    // identical, so "renew before" would be an instruction they can follow forever while the
    // outage arrives on schedule.
    assert!(
        row("expires-in-twenty-days").contains("Provisioning stops"),
        "a connection whose own expiry is the deadline does not say provisioning stops, so the \
         customer is told to renew something renewing cannot reach: {}",
        row("expires-in-twenty-days")
    );
    assert!(
        row("expires-in-twenty-days").contains("replace this connection"),
        "the row names no remedy, and the one the other rows name does not work here: {}",
        row("expires-in-twenty-days")
    );
    assert!(
        !row("expires-in-twenty-days").contains("Renew before"),
        "a connection-level expiry is rendered with the token wording: {}",
        row("expires-in-twenty-days")
    );
    assert!(
        row("expires-in-twenty-days").contains(&rendered(now + 20 * day)),
        "the outage row does not carry its date: {}",
        row("expires-in-twenty-days")
    );

    assert!(
        row("renew-outside-the-lead").contains("Next deadline")
            && row("renew-outside-the-lead").contains(&rendered(now + 40 * day)),
        "a live connection whose deadline is OUTSIDE the thirty-day lead must read its next \
         deadline and that date, which is the state an admin plans around: {}",
        row("renew-outside-the-lead")
    );
    assert!(
        !row("renew-outside-the-lead").contains("Renew before"),
        "a deadline outside the lead is reported as imminent, so the lead bounds nothing: {}",
        row("renew-outside-the-lead")
    );

    assert!(
        row("switched-off").contains("Revoked"),
        "a revoked connection is not reported as revoked: {}",
        row("switched-off")
    );
    assert!(
        !row("switched-off").contains("no working token"),
        "a REVOKED connection is reported as broken, which is noise on the one row whose state \
         the revocation already explains: {}",
        row("switched-off")
    );
    assert!(
        row("credentials-gone").contains("no working token"),
        "a connection whose credentials are all gone is not reported as stopped, so an admin \
         reads it as healthy while provisioning is down: {}",
        row("credentials-gone")
    );
    // AND THE BROKEN ROW CARRIES NO COUNTDOWN. This is NOT the outside-the-lead control -- an
    // earlier version of this comment claimed it was, and it never could be: `no_live_credential`
    // catches this row two branches before the deadline arm is reached, and the store has already
    // nulled its deadline. The lead's outside edge is held by `lapses-in-forty-days` above.
}

/// A connection that has already stopped, and one an operator switched off, are told apart.
#[tokio::test]
async fn the_stopped_and_the_revoked_rows_are_not_confused() {
    let harness = Harness::start_store_backed_with_scim_warning_lead(30 * 24 * 60 * 60).await;
    let (body, _now, _day) = five_state_page(&harness).await;
    let row = |name: &str| row(&body, name);

    // AND THE EMPTY NOTICE IS NOT HERE. It is pinned in the empty case, which cannot tell that
    // notice from one rendered beside real rows -- the shape where a customer with connections is
    // also told they have none.
    assert!(
        !body.contains("No provisioning connections yet"),
        "the empty-list notice is rendered beside real connection rows: {body}"
    );

    assert!(
        !row("credentials-gone").contains("Renew before"),
        "a connection with nothing live is counting down to a moment that has passed: {}",
        row("credentials-gone")
    );
}

/// A longer list than the page shows is REPORTED as longer, not silently cut.
///
/// # The branch this drives, and why it needed driving
///
/// The page renders at most a hundred connections and reads a hundred and one, so it can tell
/// "this is all of them" from "there are more". Without a fixture that crosses the bound, the
/// whole reporting branch is unreachable and deleting it leaves every other test green -- and
/// what ships is a page titled "your connections" that is missing some of them with no sign.
///
/// A HUNDRED AND ONE CONNECTIONS is deliberate rather than round: it is the smallest fixture
/// that crosses the bound, so the test fails loudly if the bound moves rather than quietly
/// ceasing to drive the branch.
///
/// AND THE BOUNDARY ITSELF is driven by the sibling below, at exactly a hundred. Without it the
/// comparison could be `>=` instead of `>` and nothing would notice: at a hundred and one both
/// answer "truncated", and only the exactly-full page tells them apart -- the page that is
/// complete and would be labelled as cut.
#[tokio::test]
async fn a_list_longer_than_the_page_says_so() {
    let harness = Harness::start_store_backed().await;
    let org = seed_org(&harness, "Acme").await;
    for index in 0..101 {
        connect(
            &harness,
            &org,
            &format!("conn-{index:03}"),
            &format!("tok-{index}"),
            None,
        )
        .await;
    }

    let cookie = open_session_in(&harness, "scim", "tok-many", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    assert!(
        body.contains("Showing the first"),
        "a list longer than the page renders was cut with no notice, so an admin reads a partial \
         list as a complete one"
    );
    // AND THE HUNDRED-AND-FIRST IS THE ONE MISSING, not a hundred of them: the page shows what
    // it can and says what it cannot, rather than truncating to some smaller number.
    let rendered = body.matches("<td>conn-").count();
    assert_eq!(
        rendered, 100,
        "the page rendered {rendered} connection rows rather than the hundred it bounds itself to"
    );
}

/// An organization with no connections says so, rather than rendering an empty table.
///
/// # The branch this drives
///
/// The page has an explicit empty case, and without a fixture that reaches it the whole notice
/// can be deleted with every other test still green -- leaving an IT admin who has configured
/// nothing yet staring at a table with headers and no rows, which reads like a page that failed
/// to load rather than like "you have not set this up yet".
#[tokio::test]
async fn an_organization_with_no_connections_is_told_so() {
    let harness = Harness::start_store_backed().await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "scim", "tok-empty", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );

    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");
    assert!(
        body.contains("No provisioning connections yet"),
        "an organization with nothing configured is shown an empty table with no explanation, \
         which reads as a page that failed rather than as nothing to show: {body}"
    );
    // AND THE TABLE IS OTHERWISE EMPTY, so the notice is the whole content rather than a line
    // beside rows this organization should not have. Counted on `<td` rather than `<td>`: the
    // notice cell carries a `colspan`, so the closing-angle form matches none of the cells that
    // are actually there and the assertion would be measuring nothing.
    assert_eq!(
        body.matches("<td").count(),
        1,
        "the empty notice is rendered beside connection rows: {body}"
    );
}

/// A deployment that does not serve inbound provisioning says so instead of advertising a URL.
///
/// # The pairing nothing else prevents
///
/// `scim.enabled` decides whether `/scim/v2` mounts at all, and minting a portal link with the
/// `scim` intent never consults it -- `create_portal_link` validates the intent against a closed
/// set and nothing more. So a vendor can hand a customer a provisioning link on a deployment
/// that serves no provisioning, and the page is the last thing standing between that admin and
/// an afternoon spent configuring their identity provider against an endpoint that 404s.
#[tokio::test]
async fn a_deployment_without_the_scim_surface_advertises_no_url() {
    let harness = Harness::start_store_backed_with_scim_surface(false).await;
    let org = seed_org(&harness, "Acme").await;
    connect(&harness, &org, "acme-okta", "tok-off", None).await;
    let cookie = open_session_in(&harness, "scim", "tok-off-p", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );

    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");
    assert!(
        !body.contains("/scim/v2"),
        "the page advertised a provisioning URL on a deployment that answers 404 for it: {body}"
    );
    assert!(
        body.contains("does not serve inbound provisioning"),
        "the page went silent about the endpoint instead of saying why there is none: {body}"
    );
    // AND IT STILL SHOWS THE CONNECTIONS, which an operator can still manage through the
    // management API: the missing piece is the surface, not the configuration.
    assert!(
        body.contains("acme-okta"),
        "the connections vanished along with the endpoint: {body}"
    );
}

/// A page that is exactly full is not labelled as cut.
///
/// # The boundary the sibling above cannot reach
///
/// It seeds one more than the page shows, where `>` and `>=` agree. This one seeds EXACTLY the
/// page size: the correct comparison stays quiet and the off-by-one tells a customer whose list
/// is complete that there are more connections their vendor is hiding from them. Mutating the
/// `>` to `>=` turns this red and nothing else.
#[tokio::test]
async fn a_page_that_is_exactly_full_is_not_called_truncated() {
    let harness = Harness::start_store_backed().await;
    let org = seed_org(&harness, "Acme").await;
    for index in 0..100 {
        connect(
            &harness,
            &org,
            &format!("conn-{index:03}"),
            &format!("full-{index}"),
            None,
        )
        .await;
    }

    let cookie = open_session_in(&harness, "scim", "tok-full", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    // THE CONTROL: all hundred are rendered, so the absence of the notice below is a complete
    // page rather than a page that failed to list anything.
    assert_eq!(
        body.matches("<td>conn-").count(),
        100,
        "the exactly-full page does not render every connection"
    );
    assert!(
        !body.contains("Showing the first"),
        "a complete list of exactly the page size is labelled truncated, telling a customer \
         their vendor is withholding connections that do not exist: {body}"
    );
}

/// Every provider gets ITS OWN guide, naming ITS OWN connection, carrying THIS deployment's URL.
///
/// # Issue #140 criterion 4, and the half of it that is easy to fake
///
/// "Setup guides render per IdP with correct copy-paste values for the specific connection being
/// configured." A page carrying one generic guide would satisfy a test that only looked for the
/// word "SCIM", so this asserts the discriminating parts: each provider's guide names the field
/// ITS console calls the URL (Okta's Base URL, Entra's Tenant URL), each guide is attached to the
/// connection it configures by name, and the URL in them is this deployment's own rather than a
/// literal.
#[tokio::test]
async fn each_connection_gets_its_own_providers_setup_guide() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    connect_with_provider(&harness, &org, "okta-primary", "okta", "g-a", None).await;
    connect_with_provider(&harness, &org, "entra-secondary", "entra", "g-b", None).await;
    connect_with_provider(&harness, &org, "homegrown", "generic", "g-c", None).await;

    let cookie = open_session_in(&harness, "scim", "tok-guides", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    // ONE GUIDE PER CONNECTION, each naming the connection it belongs to. An organization with
    // two providers needs to know which steps go with which row.
    for (name, provider) in [
        ("okta-primary", "Okta"),
        ("entra-secondary", "Microsoft Entra ID"),
        ("homegrown", "your identity provider"),
    ] {
        let heading = format!("Set up {name} in {provider}");
        assert!(
            body.contains(&heading),
            "no guide headed {heading:?}, so this connection's steps are missing or are filed \
             under another connection: {body}"
        );
    }

    // THE STEPS ARE THE PROVIDER'S OWN, asserted INSIDE the guide they belong to. Page-global
    // `contains` checks are satisfied by the right words appearing anywhere, so the Okta and
    // Entra step lists could be swapped wholesale and every one of them would still pass -- which
    // is the exact failure these guides exist to prevent, pasting into the wrong console's field.
    let guide = |name: &str| -> String {
        let heading = format!("Set up {name} in ");
        let at = body
            .find(&heading)
            .unwrap_or_else(|| panic!("no guide for {name}: {body}"));
        let rest = &body[at..];
        let end = rest.find("</details>").unwrap_or(rest.len());
        rest[..end].to_owned()
    };
    assert!(
        guide("okta-primary").contains("Base URL field")
            && guide("okta-primary").contains("API Token field"),
        "the Okta guide does not name the fields Okta uses: {}",
        guide("okta-primary")
    );
    assert!(
        guide("entra-secondary").contains("Tenant URL field")
            && guide("entra-secondary").contains("Secret Token field"),
        "the Entra guide does not name the fields Entra uses: {}",
        guide("entra-secondary")
    );
    // AND NEITHER CARRIES THE OTHER'S, which is what makes the pair a swap test rather than two
    // independent presence checks.
    assert!(
        !guide("okta-primary").contains("Tenant URL"),
        "the Okta guide carries Entra's field names: {}",
        guide("okta-primary")
    );
    assert!(
        !guide("entra-secondary").contains("API Token"),
        "the Entra guide carries Okta's field names: {}",
        guide("entra-secondary")
    );

    // AND THE URL IS THIS DEPLOYMENT'S, in every guide. Asserting merely that "/scim/v2" appears
    // would be satisfied by a hardcoded literal, which is what a guide copied from a vendor
    // document would contain.
    let scope_path = format!("/t/{}/e/{}", scope.tenant(), scope.environment());
    let deployment_base = harness
        .issuer()
        .strip_suffix(&scope_path)
        .expect("the per-environment issuer is the deployment base plus the scope path");
    let expected = format!("{deployment_base}/scim/v2");
    // PER GUIDE, not a page-global count. Counting occurrences cannot see WHICH guide carries the
    // URL, so four copies in one guide and none in the others would satisfy it -- the same defect
    // the field-name assertions beside this one were just reshaped to remove.
    for name in ["okta-primary", "entra-secondary", "homegrown"] {
        assert!(
            guide(name).contains(&expected),
            "the guide for {name} does not carry this deployment's SCIM URL, so the customer \
             would paste an address from somewhere else: {}",
            guide(name)
        );
    }
    assert!(
        body.contains(&format!("<code>{expected}</code>")),
        "the endpoint paragraph above the table does not carry the deployment's URL: {body}"
    );

    // NO GUIDE OFFERS THE TOKEN, because no reader can produce it: the store holds a digest and
    // the plaintext existed once, in the response that minted it. Every guide says where it
    // comes from instead.
    for name in ["okta-primary", "entra-secondary", "homegrown"] {
        assert!(
            guide(name).contains("ask your vendor to rotate it"),
            "the guide for {name} does not say where the token comes from, which is the one \
             value it cannot show and the one an admin will not otherwise have: {}",
            guide(name)
        );
    }
}

/// A revoked connection gets no guide, and a deployment serving no SCIM gets none at all.
///
/// # Both are the same mistake: instructions that cannot succeed
///
/// Configuring an identity provider against a credential an operator has switched off is wasted
/// work, and pasting a URL this deployment answers 404 for is worse -- the admin has no way to
/// tell the setup failed for a reason on the vendor's side.
#[tokio::test]
async fn no_guide_is_offered_for_work_that_cannot_succeed() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let env = Env::system();
    let org = seed_org(&harness, "Acme").await;
    let live = connect_with_provider(&harness, &org, "still-working", "okta", "g-live", None).await;
    let dead = connect_with_provider(&harness, &org, "switched-off", "entra", "g-dead", None).await;
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .revoke(&env, &dead, now_micros(&harness))
        .await
        .expect("revoke");

    let cookie = open_session_in(&harness, "scim", "tok-g2", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    // THE CONTROL: the live connection does get one, so the absence below is the revocation.
    assert!(
        body.contains("Set up still-working in Okta"),
        "the live connection has no guide, so the absence asserted next proves nothing: {body}"
    );
    assert!(
        !body.contains("Set up switched-off in"),
        "a revoked connection is offered setup steps that cannot succeed: {body}"
    );
    let _ = live;

    // AND A LAPSED CONNECTION, which is the other way a row reaches "cannot succeed" and the one
    // that arrives by itself. `authenticate` refuses it on `c.expires_at > now`, so no token the
    // admin pastes will ever work -- and the guide's closing sentence would tell them to ask for
    // a ROTATION, which `rotate_token` refuses for this same connection with a not-found. The
    // customer would do the work, watch it fail unexplained, and request a remedy the product
    // answers 404 to.
    let lapsing = connect_with_provider(
        &harness,
        &org,
        "already-expired",
        "okta",
        "g-lapsed",
        Some(now_micros(&harness) + 60 * 1_000_000),
    )
    .await;
    harness.clock().advance(std::time::Duration::from_secs(120));
    let (_, after) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert!(
        after.contains("already-expired"),
        "the lapsed connection is missing from the listing entirely: {after}"
    );
    assert!(
        !after.contains("Set up already-expired in"),
        "a connection past its own expiry is offered setup steps that cannot succeed, ending in \
         a request its vendor must refuse: {after}"
    );
    // AND ITS ROW NAMES THE REMEDY THAT WORKS, rather than blaming a token that is not the
    // problem: this connection cannot be rotated, only replaced.
    assert!(
        after.contains("this connection expired and must be replaced"),
        "the lapsed row does not say what has to happen to it: {after}"
    );
    // THE CONTROL, again after the clock moved: the live connection still has its guide, so the
    // absence above is the lapse rather than the whole section disappearing.
    assert!(
        after.contains("Set up still-working in Okta"),
        "the live connection lost its guide when a sibling lapsed: {after}"
    );
    let _ = lapsing;

    // AND WITH THE SURFACE OFF, no guide at all -- the steps would point at a 404.
    let dark = Harness::start_store_backed_with_scim_surface(false).await;
    let dark_org = seed_org(&dark, "Acme").await;
    connect_with_provider(&dark, &dark_org, "hopeful", "okta", "g-dark", None).await;
    let dark_cookie = open_session_in(&dark, "scim", "tok-g3", &dark_org).await;
    let dark_scope = dark.scope();
    let dark_path = format!(
        "/t/{}/e/{}/portal/s/scim",
        dark_scope.tenant(),
        dark_scope.environment()
    );
    let (status, dark_body) = get_with_cookie(&dark, &dark_path, Some(&dark_cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {dark_body}");
    assert!(
        !dark_body.contains("Setting up your identity provider"),
        "a deployment that serves no provisioning offers setup steps for it: {dark_body}"
    );
    assert!(
        dark_body.contains("hopeful"),
        "the connection itself vanished along with its guide: {dark_body}"
    );
}

/// Two connections of the SAME provider get two guides, one each.
///
/// # The case that separates per-connection from per-provider
///
/// An Okta-plus-Entra organization does not: those differ by provider, so per-provider rendering
/// would give them two sections too. A customer migrating between two Okta tenants, or running
/// one for staging, is the case where per-provider gives a single "Okta" section and no way to
/// tell which connection it configures -- which is exactly where a vendor's own documentation
/// already leaves them.
#[tokio::test]
async fn two_connections_of_one_provider_get_a_guide_each() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    connect_with_provider(&harness, &org, "okta-staging", "okta", "g-s", None).await;
    connect_with_provider(&harness, &org, "okta-production", "okta", "g-p", None).await;

    let cookie = open_session_in(&harness, "scim", "tok-same", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    assert!(
        body.contains("Set up okta-staging in Okta"),
        "the staging connection has no guide of its own: {body}"
    );
    assert!(
        body.contains("Set up okta-production in Okta"),
        "the production connection has no guide of its own: {body}"
    );
    assert_eq!(
        body.matches("<details>").count(),
        2,
        "two connections of one provider produced {} guides rather than two, so the admin \
         cannot tell which set of steps configures which connection: {body}",
        body.matches("<details>").count()
    );
}

/// A page that lists a hundred connections offers a hundred guides, not a hundred and one.
///
/// # The bound the guides carry separately from the table
///
/// The rows and the guides each `take` the page limit off the same over-long read. Deleting the
/// guides' `take` renders a guide for a connection the table says is not shown, so the page would
/// contradict itself -- and nothing observed that: the truncation test counts rows only.
#[tokio::test]
async fn the_guides_stop_where_the_table_stops() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    for index in 0..101 {
        connect_with_provider(
            &harness,
            &org,
            &format!("conn-{index:03}"),
            "okta",
            &format!("guide-{index}"),
            None,
        )
        .await;
    }

    let cookie = open_session_in(&harness, "scim", "tok-bound", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    // THE CONTROL: the page really is truncating, so the count below is the guides honouring the
    // same bound rather than a page that happens to be short.
    assert!(
        body.contains("Showing the first"),
        "the page is not truncating, so this fixture proves nothing about the bound: {body}"
    );
    assert_eq!(
        body.matches("<details>").count(),
        100,
        "the guides do not stop where the table stops, so the page offers setup steps for a \
         connection it says it is not showing"
    );
}

/// A connection that has lost its TOKENS still gets its guide; one past its own expiry does not.
///
/// # The positive control the filter's narrowness depends on
///
/// The filter suppresses a guide for a connection nothing can revive, keyed on the connection's
/// own expiry. Keying it on `no_live_credential()` instead would be a strict superset -- the
/// store zeroes `live_token_count` for any lapsed row before it looks at the token rows at all,
/// so lapsed always implies no live credential -- and every other test would stay green under
/// that broader condition.
///
/// What separates them is exactly one row: a connection that is live and unrevoked but whose
/// tokens are gone. Rotation works there, the admin has a fresh token to paste, and these steps
/// are what they need. Without this assertion the narrowness is unobservable and the next
/// simplification silently removes the guide from the population the feature was reshaped for.
#[tokio::test]
async fn a_connection_that_lost_its_tokens_still_gets_its_guide() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let env = Env::system();
    let org = seed_org(&harness, "Acme").await;
    let now = now_micros(&harness);
    let day = 24 * 60 * 60 * 1_000_000_i64;
    let writes = || {
        harness.db().control_store().scoped(harness.scope()).acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
    };

    // THE CONNECTION OUTLIVES ITS CREDENTIALS: ninety days out, so it is neither revoked nor
    // lapsed, while a rotation followed by revoking the fresh token leaves nothing live.
    let stranded = connect_with_provider(
        &harness,
        &org,
        "tokens-gone",
        "okta",
        "tg-1",
        Some(now + 90 * day),
    )
    .await;
    writes()
        .scim_connections()
        .rotate_token(&env, &stranded, &hex_digest("tg-2"), 60, now)
        .await
        .expect("rotate");
    writes()
        .scim_connections()
        .revoke_token(&env, &stranded, &hex_digest("tg-2"), now)
        .await
        .expect("revoke the fresh token");
    harness.clock().advance(std::time::Duration::from_secs(120));

    let cookie = open_session_in(&harness, "scim", "tok-stranded", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    // THE PREMISE: this row really has lost its credentials, so the guide below is being kept
    // for a connection that reports itself stopped rather than for an ordinary healthy one.
    assert!(
        row(&body, "tokens-gone").contains("no working token"),
        "the fixture did not reach the tokens-gone state, so the assertion below proves nothing \
         about the filter: {}",
        row(&body, "tokens-gone")
    );
    assert!(
        !row(&body, "tokens-gone").contains("must be replaced"),
        "a connection whose tokens are gone is reported as needing replacement, which is the \
         lapsed remedy and not this one: {}",
        row(&body, "tokens-gone")
    );
    assert!(
        body.contains("Set up tokens-gone in Okta"),
        "the connection that most needs setup steps -- live, rotatable, and with nothing to \
         authenticate -- was denied them: {body}"
    );
}

/// A live connection WITH a future expiry still gets its guide.
///
/// # The other half of `is_some_and`
///
/// The filter could test `expires_at_unix_micros.is_some()` -- suppressing the guide for every
/// connection that has an expiry, whether or not it has passed -- and only a fixture whose expiry
/// is in the FUTURE can tell that apart from the shipped condition. That is a large population to
/// be wrong about: an expiry is what a cautious vendor sets.
///
/// Its sibling `a_connection_that_lost_its_tokens_still_gets_its_guide` also carries a future
/// expiry and would fail the same mutation. This one keeps it as the case stated plainly, with
/// nothing else going on in the fixture to explain a failure.
#[tokio::test]
async fn a_connection_with_a_future_expiry_still_gets_its_guide() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let now = now_micros(&harness);
    connect_with_provider(
        &harness,
        &org,
        "expires-next-year",
        "okta",
        "fe-1",
        Some(now + 365 * 24 * 60 * 60 * 1_000_000),
    )
    .await;

    let cookie = open_session_in(&harness, "scim", "tok-future", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");
    assert!(
        body.contains("Set up expires-next-year in Okta"),
        "a connection with an expiry a year away is treated as already lapsed and denied its \
         setup steps: {body}"
    );
}

/// A connection that is BOTH revoked and lapsed reads as revoked.
///
/// # Which of two true things a row says
///
/// Both branches apply, and the order decides. Revocation is the one somebody did on purpose and
/// the one `revoked_at` timestamps, so it is the more informative answer -- and without a fixture
/// carrying both, the branch order is free to change with nothing noticing.
#[tokio::test]
async fn a_revoked_and_lapsed_connection_reads_as_revoked() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let env = Env::system();
    let org = seed_org(&harness, "Acme").await;
    let now = now_micros(&harness);
    let both = connect_with_provider(
        &harness,
        &org,
        "off-and-expired",
        "okta",
        "bl-1",
        Some(now + 60 * 1_000_000),
    )
    .await;
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .revoke(&env, &both, now)
        .await
        .expect("revoke");
    harness.clock().advance(std::time::Duration::from_secs(120));

    let cookie = open_session_in(&harness, "scim", "tok-both", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (_, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert!(
        row(&body, "off-and-expired").contains("Revoked"),
        "a connection that was switched off AND has since lapsed reports the lapse, hiding the \
         deliberate act that is the more useful answer: {}",
        row(&body, "off-and-expired")
    );
    assert!(
        !row(&body, "off-and-expired").contains("must be replaced"),
        "the revoked row also carries the lapsed remedy: {}",
        row(&body, "off-and-expired")
    );

    // AND NO EMPTY GUIDES SECTION. The surface is on and every connection here is filtered out,
    // which is the only state that reaches the heading's emptiness guard -- an organization that
    // has offboarded its identity provider, or has no connections yet on a SCIM-serving
    // deployment. Without this the guard can be deleted and the page ships a heading with
    // nothing underneath, which reads as a section that failed to load.
    assert!(
        !body.contains("Setting up your identity provider"),
        "a heading was rendered over no guides at all: {body}"
    );
}

/// A display name carrying markup is escaped everywhere the page prints it.
///
/// # The one value on this page that a customer's own vendor controls
///
/// Everything else in a row and a guide is a constant, a timestamp, or the deployment's own URL.
/// The display name is chosen by whoever created the connection through the management API, which
/// accepts any text the column allows -- so it is the only value here that can carry markup, and
/// it is printed twice: once in the table cell and once in the guide's summary. Dropping the
/// escape on either was invisible; the row cell had no fixture with markup in it either.
#[tokio::test]
async fn a_display_name_carrying_markup_is_escaped_in_the_row_and_the_guide() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    // A NAME THAT WOULD CLOSE THE CELL AND OPEN A SCRIPT if it reached the page unescaped. It
    // stays a legal display name: the column bounds its length and nothing else.
    let hostile = "</td><script>alert(1)</script>";
    connect_with_provider(&harness, &org, hostile, "okta", "esc-1", None).await;

    let cookie = open_session_in(&harness, "scim", "tok-esc", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    // THE PREMISE: the connection really is on the page, so the absences below are escaping
    // rather than a row that never rendered.
    assert!(
        body.contains("alert(1)"),
        "the connection is missing from the page entirely, so this proves nothing: {body}"
    );
    assert!(
        !body.contains("<script>"),
        "a display name opened a script tag on the portal page: {body}"
    );
    assert!(
        !body.contains("</td><script"),
        "a display name closed its own table cell: {body}"
    );
    // AND THE GUIDE, which prints the same name in its summary. The row and the guide escape
    // separately, so one being right says nothing about the other.
    let summary_at = body
        .find("<summary>Set up ")
        .expect("the connection's guide is missing");
    let summary = &body[summary_at..body[summary_at..].find("</summary>").unwrap() + summary_at];
    assert!(
        summary.contains("&lt;/td&gt;") || summary.contains("&lt;script&gt;"),
        "the guide summary did not escape the display name: {summary}"
    );
}

/// The page says what has actually happened, not only what is configured.
///
/// # The failure this column exists to make visible
///
/// A connection whose credentials are live and whose identity provider has never called is
/// identical, in every other column, to one provisioning happily. That is the ordinary result of
/// pasting a token into the wrong field, or into the right field of the wrong application, and
/// nothing else on this page would tell an admin so.
#[tokio::test]
async fn the_page_reports_whether_anything_has_actually_used_each_connection() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let env = Env::system();
    let org = seed_org(&harness, "Acme").await;
    let now = now_micros(&harness);

    connect_with_provider(&harness, &org, "never-called", "okta", "act-a", None).await;
    connect_with_provider(&harness, &org, "in-use", "okta", "act-b", None).await;
    // A REAL PROVISIONING REQUEST, through the store's own authentication path, because the
    // stamp is written there: seeding a timestamp directly would test the column and not the
    // thing that fills it.
    assert!(
        harness
            .db()
            .store()
            .scoped(harness.scope())
            .scim_connections()
            .authenticate(&hex_digest("act-b"), now)
            .await
            .expect("authenticate")
            .is_some(),
        "the fixture's provisioning request was refused"
    );

    // AND A CONNECTION MID-CUTOVER: rotated, with the customer still on the old token.
    let cutting = connect_with_provider(&harness, &org, "mid-cutover", "okta", "act-c", None).await;
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .rotate_token(&env, &cutting, &hex_digest("act-c2"), 3600, now)
        .await
        .expect("rotate");
    assert!(
        harness
            .db()
            .store()
            .scoped(harness.scope())
            .scim_connections()
            .authenticate(&hex_digest("act-c"), now)
            .await
            .expect("authenticate")
            .is_some(),
        "the customer's old token stopped working inside its own overlap"
    );

    let cookie = open_session_in(&harness, "scim", "tok-activity", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    assert!(
        row(&body, "never-called").contains("No requests yet"),
        "a connection nothing has ever called is indistinguishable from one in use, which is \
         what a token pasted into the wrong field looks like: {}",
        row(&body, "never-called")
    );
    assert!(
        row(&body, "in-use").contains("Last request"),
        "a connection that has served a provisioning request does not say so: {}",
        row(&body, "in-use")
    );
    assert!(
        !row(&body, "in-use").contains("No requests yet"),
        "a connection in use is reported as never called: {}",
        row(&body, "in-use")
    );

    // THE CUTOVER OUTRANKS THE TIMESTAMP. This connection is plainly in use -- on the OLD token --
    // so a last-request time would report exactly the health that ends when the overlap does.
    assert!(
        row(&body, "mid-cutover").contains("New token not used yet"),
        "a connection whose customer has not pasted the new token yet reports itself healthy, so \
         nothing warns before the overlap ends and provisioning stops: {}",
        row(&body, "mid-cutover")
    );
    assert!(
        !row(&body, "mid-cutover").contains("Last request"),
        "the mid-cutover row leads with the reassuring half: {}",
        row(&body, "mid-cutover")
    );

    the_rendered_date_is_the_stamp_and_not_its_microseconds(&body, now);
    a_revoked_connection_reports_no_activity(&harness, &org, &env, now, &path, &cookie).await;
}

/// The date half of [`the_page_reports_whether_anything_has_actually_used_each_connection`].
///
/// SPLIT OUT because that test stood at 163 lines against the hundred-line ceiling clippy
/// enforces and `cargo test` cannot see. It is a distinct claim -- how the stamp is
/// RENDERED, rather than which rows carry one -- and it is the tail of the test, so moving
/// it changes no ordering.
fn the_rendered_date_is_the_stamp_and_not_its_microseconds(body: &str, now: i64) {
    // THE DATE ITSELF, which nothing asserted: the column divides microseconds to seconds before
    // formatting, and feeding microseconds straight in puts the date tens of millions of years
    // out. (An earlier version of this comment said "around fifty-five thousand", which is the
    // figure for a MILLISECOND value; microseconds are a thousand times worse.)
    // Derived independently here, for the reason the deadline assertions above give.
    let secs = now / 1_000_000;
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day_of = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let stamped = format!(
        "{year:04}-{month:02}-{day_of:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    );
    assert!(
        row(body, "in-use").contains(&stamped),
        "the activity column does not carry the time of the request it is reporting: {}",
        row(body, "in-use")
    );
}

/// The revoked half of the same test: a revoked connection reports no activity at all, so
/// nothing invites the reader to wonder whether it still works.
async fn a_revoked_connection_reports_no_activity(
    harness: &Harness,
    org: &OrganizationId,
    env: &Env,
    now: i64,
    path: &str,
    cookie: &str,
) {
    // AND A REVOKED CONNECTION REPORTS NO ACTIVITY AT ALL. Its state is explained by the
    // revocation, and a last-used time beside it would invite the reader to wonder whether it is
    // still working. Nothing drove this arm before.
    let switched = connect_with_provider(harness, org, "switched-off", "okta", "act-d", None).await;
    assert!(
        harness
            .db()
            .store()
            .scoped(harness.scope())
            .scim_connections()
            .authenticate(&hex_digest("act-d"), now)
            .await
            .expect("authenticate")
            .is_some(),
        "the fixture's request was refused before the revocation"
    );
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .scim_connections()
        .revoke(env, &switched, now)
        .await
        .expect("revoke");
    let (_, after) = get_with_cookie(harness, path, Some(cookie)).await;
    assert!(
        row(&after, "switched-off").contains("Revoked"),
        "the premise: the row reports the revocation: {}",
        row(&after, "switched-off")
    );
    assert!(
        !row(&after, "switched-off").contains("Last request"),
        "a revoked connection reports when it was last used, which invites the reader to wonder \
         whether it still works: {}",
        row(&after, "switched-off")
    );
}

/// A connection with no token rows is not reported as unused, because nothing knows.
///
/// # The population this page must not lie about
///
/// A connection created by an un-upgraded replica after migration 0205 has no row in
/// `scim_connection_tokens`: it authenticates through the fallback on
/// `scim_connections.token_digest`, and the authentication path has nothing to stamp. Every
/// request it serves leaves no trace.
///
/// SAYING "NO REQUESTS YET" THERE REPORTS A WORKING CONNECTION AS DEAD, and the admin's remedy
/// would be to go reconfigure something already correct. The page says "Not recorded" instead --
/// which is what it actually knows.
#[tokio::test]
async fn a_connection_with_no_token_rows_reports_that_nothing_is_recorded() {
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let legacy = connect_with_provider(&harness, &org, "old-binary", "okta", "leg-1", None).await;
    // SIMULATE THE UN-UPGRADED REPLICA'S CREATE: the connection row exists and the token row does
    // not, which is the state the fallback and the adopt-on-rotate both exist for.
    sqlx::query("DELETE FROM scim_connection_tokens WHERE connection_id = $1")
        .bind(legacy.to_string())
        .execute(harness.db().owner_pool())
        .await
        .expect("remove the token rows");

    // AND IT REALLY IS PROVISIONING: the request authenticates through the fallback, which is
    // what makes "no requests yet" a lie rather than merely unhelpful.
    let now = now_micros(&harness);
    assert!(
        harness
            .db()
            .store()
            .scoped(harness.scope())
            .scim_connections()
            .authenticate(&hex_digest("leg-1"), now)
            .await
            .expect("authenticate")
            .is_some(),
        "the fallback connection stopped authenticating, so this fixture proves nothing"
    );

    let cookie = open_session_in(&harness, "scim", "tok-legacy", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    assert!(
        row(&body, "old-binary").contains("Not recorded"),
        "a connection whose requests leave no trace does not say so: {}",
        row(&body, "old-binary")
    );
    assert!(
        !row(&body, "old-binary").contains("No requests yet"),
        "a connection that just served a provisioning request is reported as never used, so an \
         admin would go reconfigure something that is already working: {}",
        row(&body, "old-binary")
    );

    // AND ROTATING IT DOES NOT CHANGE THAT ANSWER. Adoption gives the connection token rows, and
    // a page that keyed on "are there rows" flipped straight to "No requests yet" here -- the
    // same lie, one step later in the same lifecycle, at the exact moment an admin loads the page
    // to check whether their rotation landed.
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&Env::system())),
            CorrelationId::generate(&Env::system()),
        )
        .scim_connections()
        .rotate_token(
            &Env::system(),
            &legacy,
            &hex_digest("leg-2"),
            3600,
            now_micros(&harness),
        )
        .await
        .expect("rotate");

    let (_, after) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert!(
        row(&after, "old-binary").contains("Not recorded"),
        "rotating a connection whose history was never watched reports it as never used: {}",
        row(&after, "old-binary")
    );
    assert!(
        !row(&after, "old-binary").contains("No requests yet"),
        "the page asserts as fact that a months-old working connection has never been called, \
         moments after its rotation: {}",
        row(&after, "old-binary")
    );
}

/// Pin one certificate to `connection`, expiring `in_secs` from now.
async fn pin(
    harness: &Harness,
    connection: &ironauth_store::SamlConnectionId,
    seed: u8,
    in_secs: i64,
) -> ironauth_store::SamlCertificateId {
    let env = Env::system();
    let scope = harness.scope();
    let id = ironauth_store::SamlCertificateId::generate(&env, &scope);
    // THE HARNESS CLOCK, not the wall clock. The app under test runs on a deterministic clock
    // starting at the Unix epoch, so a certificate seeded from real time is decades in that
    // clock's future and every row renders as "not yet valid" -- which is what this test first
    // reported, and it was the fixture that was wrong rather than the page.
    let now = i64::try_from(
        harness
            .env()
            .clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("in range");
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(seed, 64));
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .saml_connections()
        .pin_certificate(
            &env,
            ironauth_store::NewSamlCertificate {
                id: &id,
                connection_id: connection,
                key_kind: ironauth_store::SamlKeyKind::EcdsaP256,
                public_key: &point,
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, seed],
                fingerprint_sha256: &std::iter::repeat_n(seed, 32).collect::<Vec<u8>>(),
                // AN HOUR BEFORE THE EARLIER OF now AND THE EXPIRY. Both anchors alone are
                // wrong for one of the two fixtures this helper has to build: relative to now
                // only, an already-lapsed certificate collapses the interval and the schema's
                // `not_before < not_after` refuses it; relative to the expiry only, a
                // certificate expiring in two days starts TOMORROW and the page correctly
                // reports it as not yet valid. Taking the earlier makes a live certificate's
                // window straddle now and a lapsed one's sit wholly behind it.
                not_before_unix_micros: now.min(now + in_secs * 1_000_000) - 60 * 60 * 1_000_000,
                not_after_unix_micros: now + in_secs * 1_000_000,
            },
            None,
            None,
        )
        .await
        .expect("pin the certificate");
    id
}

/// A SAML connection in `organization`.
async fn saml_connection(
    harness: &Harness,
    organization: &OrganizationId,
    display_name: &str,
) -> ironauth_store::SamlConnectionId {
    let env = Env::system();
    let scope = harness.scope();
    let id = ironauth_store::SamlConnectionId::generate(&env, &scope);
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .saml_connections()
        .create(
            &env,
            ironauth_store::NewSamlConnection {
                id: &id,
                organization_id: organization,
                display_name,
                idp_entity_id: "https://idp.example/entity",
                idp_sso_url: "https://idp.example/sso",
                sp_entity_id: "https://ironauth.example/saml/metadata",
                acs_url: "https://ironauth.example/saml/acs",
                allow_unsolicited: false,
                clock_skew_secs: 30,
                max_assertion_age_secs: 300,
                nameid_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                attribute_mapping: &serde_json::json!({}),
                require_encrypted_assertion: false,
            },
            None,
            None,
        )
        .await
        .expect("create the connection");
    id
}

/// The `<tr>` for one certificate, so a state can be asserted against the row it belongs to.
///
/// Every state assertion in this suite was a whole-body substring check, which is a sum over the
/// rows it claims to distinguish: reading each row's state off the FIRST certificate left all of
/// them green. Slicing the row by its own id is what binds the two together.
fn row_for(body: &str, id: &ironauth_store::SamlCertificateId) -> String {
    let needle = id.to_string();
    let at = body
        .find(&needle)
        .unwrap_or_else(|| panic!("no row for {needle} in {body}"));
    let start = body[..at].rfind("<tr>").expect("a row start");
    let end = at + body[at..].find("</tr>").expect("a row end");
    body[start..end].to_owned()
}

#[tokio::test]
async fn a_renewal_link_lands_on_the_connection_whose_certificate_is_expiring() {
    // #141 criterion 2, first clause: "a certificate-renewal portal link lands on the renewal
    // flow for the right connection".
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("Okta Production"),
        "the page must name the connection whose certificate is expiring: {body}"
    );
    assert!(
        body.contains("in use"),
        "and say that the pinned certificate is currently trusted: {body}"
    );
}

#[tokio::test]
async fn a_rollover_shows_both_certificates_as_trusted() {
    // OVERLAP, which is the second clause of criterion 2. It is not something this page builds:
    // `saml_acs` verifies an assertion against EVERY pinned certificate, so pinning the
    // replacement alongside the one being retired is what makes a renewal survive the switchover.
    // What the page owes is telling the holder that BOTH are trusted, so they can see the new one
    // has landed before the identity provider cuts over.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    // TWO DIFFERENT STATES on one page, which is the state a real rollover reaches when the
    // switchover runs late: the certificate being retired has lapsed and the replacement is
    // live. With both "in use" the two rows are textually identical, and every assertion about
    // them is satisfied by a page that read either row's state off the other.
    let retiring = pin(&harness, &connection, 7, -60 * 60).await;
    let replacement = pin(&harness, &connection, 9, 400 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;

    assert_eq!(status, 200, "{body}");
    // EACH STATE AGAINST ITS OWN ROW.
    let retiring_row = row_for(&body, &retiring);
    let replacement_row = row_for(&body, &replacement);
    assert!(
        retiring_row.contains("still accepted"),
        "the lapsed certificate must be shown as still trusted, so the holder does not read a \
         working rollover as an outage: {retiring_row}"
    );
    assert!(
        replacement_row.contains("in use"),
        "and the replacement must be shown as live, so they can see it landed: {replacement_row}"
    );
    assert!(
        !replacement_row.contains("still accepted"),
        "the two rows must not carry each other's state: {replacement_row}"
    );
}

#[tokio::test]
async fn a_renewal_session_sees_only_its_own_organizations_connections() {
    // The link carries ONE organization. A renewal holder is often an outside IdP administrator,
    // so a page that leaked a neighbour's connection would tell them that organization uses SSO,
    // through which provider, and when its certificate expires.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    let ours = saml_connection(&harness, &mine, "Okta Production").await;
    pin(&harness, &ours, 7, 2 * 24 * 60 * 60).await;
    let neighbour = saml_connection(&harness, &theirs, "Entra Neighbour").await;
    let neighbour_certificate = pin(&harness, &neighbour, 9, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &mine).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;

    assert_eq!(status, 200, "{body}");
    assert!(body.contains("Okta Production"), "{body}");
    assert!(
        !body.contains("Entra Neighbour"),
        "a renewal session must not see another organization's connection: {body}"
    );
    // NOR ITS CERTIFICATE. The previous version of this line asserted the absence of the
    // neighbour's CONNECTION id, which the page never prints under any input -- an assertion
    // structurally unable to fail. The certificate id IS printed, so this one can.
    assert!(
        !body.contains(&neighbour_certificate.to_string()),
        "nor its certificate: {body}"
    );
}

#[tokio::test]
async fn a_lapsed_certificate_is_shown_as_still_accepted() {
    // THE SENTENCE THIS PAGE MOST NEEDS TO GET RIGHT, and it was measured by nothing: deleting
    // the expired branch left every renewal test green.
    //
    // `saml_acs` verifies against the pinned KEY and deliberately does NOT check `notAfter`,
    // because the alternative is an enterprise-wide lockout at midnight on a date nobody was
    // watching. So a lapsed certificate is still accepted here, and the page has to say so.
    // Showing it as simply "expired" would tell the holder that sign-in is already broken and
    // that they are in an outage -- panic during a rollover that is in fact working.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    // Pinned, and already past its expiry on the clock the page reads.
    pin(&harness, &connection, 7, -60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("still accepted"),
        "a lapsed certificate must be shown as still trusted, or the holder reads a working \
         rollover as an outage: {body}"
    );
    assert!(
        !body.contains(">in use<"),
        "and must not be reported as current: {body}"
    );
}

#[tokio::test]
async fn a_switched_off_connection_is_not_reported_as_working() {
    // A CONNECTION THE VENDOR HAS TURNED OFF accepts no assertion at all, whatever is pinned to
    // it. Listing its certificates as "in use" tells the holder the opposite of the truth in the
    // way that costs them the most: they renew the certificate, the page looks right, and
    // sign-in still fails for a reason the page never mentioned.
    //
    // This behaviour was added in response to review and then measured by nothing -- disabling
    // the check left every renewal test green.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    let certificate = pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&Env::system())),
            CorrelationId::generate(&Env::system()),
        )
        .saml_connections()
        .set_active(&Env::system(), &connection, false, None)
        .await
        .expect("switch the connection off");

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;

    assert_eq!(status, 200, "{body}");
    assert!(
        body.contains("switched off"),
        "the page must say the connection is off: {body}"
    );
    assert!(
        !body.contains("in use"),
        "and must not report its certificates as accepted: {body}"
    );
    assert!(
        !body.contains(&certificate.to_string()),
        "nor list them as though renewing one would help: {body}"
    );
}

/// Percent-encode a form value.
///
/// A pasted certificate carries `+`, `/`, `=` and newlines, every one of which changes meaning
/// in an `application/x-www-form-urlencoded` body. Encoding by hand rather than pulling a
/// dependency into a test file, and conservative: everything outside the unreserved set goes.
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for byte in raw.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// A well-formed X.509 certificate carrying a P-256 key derived from `seed`, PEM-armoured the
/// way an identity provider console shows it.
fn pem_certificate(seed: u8) -> String {
    use base64::Engine as _;
    let mut point = vec![0x04];
    point.extend(std::iter::repeat_n(seed, 64));
    let der = ironauth_saml::test_util::certificate_carrying(&point);
    let body = base64::engine::general_purpose::STANDARD.encode(&der);
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}

/// Drain the pin-request queue through the CONTROL-plane consumer, as the worker does.
///
/// The portal cannot write a trust anchor -- 0197 grants that INSERT to `ironauth_control`
/// alone -- so it enqueues and this applies. A test stopping at the 303 would be measuring that
/// a row reached a queue, which is not what the customer asked for.
async fn apply_pin_requests(harness: &Harness) -> usize {
    use ironauth_store::outbox::OutboxConsumer as _;

    let scope = harness.scope();
    let env = Env::system();
    let consumer = ironauth_admin::certificate_pin_requests::CertificatePinRequestConsumer::new(
        harness.db().control_store().clone(),
    );
    let mut applied = 0;
    loop {
        let claimed = harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                ironauth_store::CERTIFICATE_PIN_REQUEST_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim");
        if claimed.is_empty() {
            return applied;
        }
        for message in &claimed {
            consumer
                .handle(&env, scope, message)
                .await
                .expect("the pin applies");
            harness
                .db()
                .store()
                .scoped(scope)
                .outbox()
                .complete(&env, message)
                .await
                .expect("complete");
            applied += 1;
        }
    }
}

/// The certificates pinned to `connection`, read as the vendor.
async fn pinned_count(harness: &Harness, connection: &ironauth_store::SamlConnectionId) -> usize {
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .saml_connections()
        .certificates(connection)
        .await
        .expect("read the certificates")
        .len()
}

#[tokio::test]
async fn pinning_a_replacement_leaves_the_old_certificate_trusted() {
    // #141 criterion 2's third clause: "uploading the new cert enables an overlap window and
    // logins succeed with both old and new certs during it".
    //
    // The overlap is not a window this code opens; it is what pinning ADDS rather than replaces.
    // `saml_acs` verifies against every pinned certificate, so from the moment this POST returns
    // the identity provider may cut over whenever it likes. Replacing in place would close the
    // window at the exact instant the customer needs it open.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;
    assert_eq!(pinned_count(&harness, &connection).await, 1);

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&connection.to_string()),
        urlencode(&pem_certificate(9))
    );
    let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;

    assert_eq!(
        status, 303,
        "the queued pin redirects back to the surface: {body}"
    );
    // NOT YET PINNED: the portal enqueued, because the data plane may not write a trust anchor.
    assert_eq!(
        pinned_count(&harness, &connection).await,
        1,
        "the portal must not have written the certificate itself"
    );
    assert_eq!(apply_pin_requests(&harness).await, 1, "one queued request");
    assert_eq!(
        pinned_count(&harness, &connection).await,
        2,
        "the replacement is pinned BESIDE the certificate being retired, not instead of it"
    );
}

#[tokio::test]
async fn a_renewal_session_cannot_pin_onto_another_organizations_connection() {
    // THE WORST THING THIS SURFACE COULD DO. A renewal link holder is frequently an outside IdP
    // administrator; pinning a key they control onto a neighbour's connection would let them
    // mint assertions that deployment accepts for that neighbour's organization. Parsing the id
    // in scope proves only the tenant and environment, so the ORGANIZATION has to be checked.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    let neighbour = saml_connection(&harness, &theirs, "Entra Neighbour").await;
    pin(&harness, &neighbour, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &mine).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&neighbour.to_string()),
        urlencode(&pem_certificate(9))
    );
    let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;

    assert_eq!(status, 400, "{body}");
    assert_eq!(
        pinned_count(&harness, &neighbour).await,
        1,
        "nothing was pinned onto the neighbour's connection"
    );
    assert_eq!(
        apply_pin_requests(&harness).await,
        0,
        "and the refusal queued nothing either: a rejection that still enqueues is a \
         rejection in name only"
    );
    // AND THE REFUSAL SAYS NOTHING. A holder must not be able to tell "that connection is not
    // yours" from "no such connection", or the link becomes a way to enumerate the environment.
    assert!(
        !body.contains(&neighbour.to_string()),
        "the refusal must not echo the identifier it refused: {body}"
    );
}

#[tokio::test]
async fn a_session_for_another_intent_cannot_pin() {
    // Mounting a write behind the same session as a read does not make it the same permission.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "scim", "k-scim", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&connection.to_string()),
        urlencode(&pem_certificate(9))
    );
    let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;

    assert_ne!(
        status, 303,
        "a scim session must not pin a certificate: {body}"
    );
    assert_eq!(
        pinned_count(&harness, &connection).await,
        1,
        "and nothing was written"
    );
    assert_eq!(
        apply_pin_requests(&harness).await,
        0,
        "and nothing was queued"
    );
}

#[tokio::test]
async fn a_certificate_that_does_not_parse_is_refused_without_writing() {
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    for pasted in [
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----",
        "not base64 at all !!!",
        "",
    ] {
        let form = format!(
            "connection={}&certificate={}",
            urlencode(&connection.to_string()),
            urlencode(pasted)
        );
        let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;
        assert_eq!(status, 400, "refusing {pasted:?}: {body}");
    }
    assert_eq!(
        pinned_count(&harness, &connection).await,
        1,
        "no refused paste left anything behind"
    );
    assert_eq!(
        apply_pin_requests(&harness).await,
        0,
        "no refused paste was queued"
    );
}

#[tokio::test]
async fn a_queued_row_the_worker_cannot_read_is_dead_lettered_not_retried() {
    // THE WORKER RE-PARSES, and until this test nothing measured that it does. The portal parses
    // the paste before queueing -- that is how a holder learns immediately their paste is not a
    // certificate -- so in every other test here the row the worker sees is already known good,
    // and deleting the worker's own parse left all of them green.
    //
    // What reaches this branch in production is a row this build did not write: an older
    // producer, a hand-inserted row, a payload shape that changed. The answer must be PERMANENT.
    // A row whose DER does not parse will not parse on the fifth attempt either, and retrying
    // burns the budget and delays the dead letter that is the only way an operator finds out.
    use ironauth_store::outbox::OutboxConsumer as _;

    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    let env = Env::system();
    let scope = harness.scope();

    harness
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .enqueue(
            &env,
            &ironauth_store::NewOutboxMessage {
                consumer: ironauth_store::CERTIFICATE_PIN_REQUEST_CONSUMER,
                idempotency_key: "a-row-this-build-did-not-write",
                ordering_key: &connection.to_string(),
                payload: serde_json::json!({
                    "saml_connection_id": connection.to_string(),
                    "portal_session_id": "pse_whatever",
                    "certificate_der_base64": "bm90IGEgY2VydGlmaWNhdGU=",
                }),
            },
        )
        .await
        .expect("enqueue");

    let consumer = ironauth_admin::certificate_pin_requests::CertificatePinRequestConsumer::new(
        harness.db().control_store().clone(),
    );
    let claimed = harness
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::CERTIFICATE_PIN_REQUEST_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);

    let outcome = consumer.handle(&env, scope, &claimed[0]).await;
    let error = outcome.expect_err("an unreadable certificate must not be reported as applied");
    assert!(
        !error.is_retryable(),
        "an unreadable certificate must be dead-lettered on the spot, not retried five times"
    );
    assert_eq!(error.label(), "pin_request_certificate_unreadable");
    assert_eq!(
        pinned_count(&harness, &connection).await,
        0,
        "and nothing was pinned"
    );
}

/// Post a form with a session cookie AND a chosen `sec-fetch-site`.
async fn post_form_from_with_cookie(
    harness: &Harness,
    path: &str,
    form: &str,
    site: &str,
    cookie: &str,
) -> (axum::http::StatusCode, String) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(axum::http::header::COOKIE, cookie)
        .header("sec-fetch-site", site)
        .body(axum::body::Body::from(form.to_owned()))
        .expect("request builds");
    let (status, _, body) = harness.send(request).await;
    (status, body)
}

#[tokio::test]
async fn a_cross_site_pin_is_refused_and_writes_nothing() {
    // THE CSRF GUARD ON THE ONE PORTAL ROUTE THAT WRITES TRUST MATERIAL, and it was measured by
    // nothing: deleting `same_origin_ok` from this handler left all 43 portal tests green, while
    // both sibling POST routes -- redemption and finish -- have had cross-site tests since they
    // landed.
    //
    // What it stops is the worst thing a portal route could do. The holder of a renewal link is
    // signed in to this deployment in their browser; an attacker's page that could post this form
    // on their behalf would pin an attacker-controlled key as a trust anchor for that
    // organization, and every assertion signed with it would be accepted from then on.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&connection.to_string()),
        urlencode(&pem_certificate(9))
    );

    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "cross-site", &cookie).await;
    assert_ne!(status, 303, "a cross-site pin was accepted: {body}");
    assert_eq!(
        apply_pin_requests(&harness).await,
        0,
        "and it must not even have been queued"
    );
    assert_eq!(
        pinned_count(&harness, &connection).await,
        1,
        "nothing was pinned"
    );

    // THE CONTROL: the same request same-origin IS accepted, so the refusal above is the guard
    // rather than the form being wrong.
    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "same-origin", &cookie).await;
    assert_eq!(status, 303, "a same-origin pin was refused: {body}");
    assert_eq!(apply_pin_requests(&harness).await, 1);
    assert_eq!(pinned_count(&harness, &connection).await, 2);
}

#[tokio::test]
async fn the_worker_pins_the_key_that_was_pasted() {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    // WHAT WAS PINNED, not just that something was. Every other test here counts rows, so a
    // worker that pinned a fixed or empty key would satisfy all of them -- and the whole point of
    // this feature is which key a future assertion is checked against.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let pasted = pem_certificate(9);
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&connection.to_string()),
        urlencode(&pasted)
    );
    let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;
    assert_eq!(status, 303, "{body}");
    assert_eq!(apply_pin_requests(&harness).await, 1);

    // The DER the page was given, and the key inside it.
    let expected_der = base64::engine::general_purpose::STANDARD
        .decode(
            pasted
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .expect("the fixture is base64");
    let expected = ironauth_saml::x509::pinned(&expected_der).expect("the fixture parses");

    let stored = harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .saml_connections()
        .certificates(&connection)
        .await
        .expect("read certificates")
        .into_iter()
        .find(|c| c.certificate_der == expected_der)
        .expect("the pasted certificate is pinned");

    let ironauth_jose::xmldsig::XmlSigKey::EcdsaP256(expected_point) = &expected.key else {
        panic!("the fixture is a P-256 certificate");
    };
    assert_eq!(
        &stored.public_key, expected_point,
        "the key pinned is not the key inside the certificate that was pasted"
    );
    assert_eq!(
        stored.not_after_unix_micros,
        expected.not_after_unix_secs * 1_000_000,
        "and its validity must be the certificate's own, not the clock's"
    );
    // THE FINGERPRINT IS OF THE WHOLE DER, which is the number an identity provider's console
    // shows. A digest of the key alone would match nothing an operator can compare against.
    assert_eq!(
        stored.fingerprint_sha256,
        Sha256::digest(&expected_der).to_vec(),
        "the fingerprint must be of the certificate, not of the key"
    );
}

#[tokio::test]
async fn the_consumer_handed_the_data_plane_store_cannot_pin() {
    // THE ONE DECISION THE WHOLE TWO-PLANE DESIGN RESTS ON: which Store the boot path gives this
    // consumer. Swapping it to the data-plane one compiles, starts, drains, and fails on every
    // insert -- and until this test, passed every test too, because every other test constructs
    // the consumer with the control store by hand.
    //
    // This pins the GRANT, which is what actually enforces the separation. If 0197 were ever
    // relaxed to let `ironauth_app` write a trust anchor, this goes red and says so.
    use ironauth_store::outbox::OutboxConsumer as _;

    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&connection.to_string()),
        urlencode(&pem_certificate(9))
    );
    let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;
    assert_eq!(status, 303, "{body}");

    // THE WRONG STORE: the data-plane one the portal itself runs on.
    let wrong = ironauth_admin::certificate_pin_requests::CertificatePinRequestConsumer::new(
        harness.db().store().clone(),
    );
    let env = Env::system();
    let scope = harness.scope();
    let claimed = harness
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::CERTIFICATE_PIN_REQUEST_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);

    let outcome = wrong.handle(&env, scope, &claimed[0]).await;
    let error = outcome.expect_err("the data plane must not be able to pin a trust anchor");
    assert!(
        error.is_retryable(),
        "a permission refusal is retryable: the row must survive until the worker is wired to \
         the plane that may write it, rather than being dead-lettered as bad input"
    );
    assert_eq!(
        pinned_count(&harness, &connection).await,
        1,
        "and nothing was pinned"
    );
}

#[tokio::test]
async fn two_organizations_pasting_the_same_certificate_are_both_pinned() {
    // THE IDEMPOTENCY KEY MUST NAME THE CONNECTION. It was the bare certificate fingerprint, and
    // the outbox's uniqueness is per (tenant, environment, consumer, key) -- so two organizations
    // in one environment federating with the same identity provider, which is ordinary, collided:
    // whichever pasted second had its renewal refused as a transient fault, for ever.
    let harness = Harness::start().await;
    let first = seed_org(&harness, "Contoso").await;
    let second = seed_org(&harness, "Initech").await;
    let their_connection = saml_connection(&harness, &first, "Shared IdP").await;
    let other_connection = saml_connection(&harness, &second, "Shared IdP").await;
    pin(&harness, &their_connection, 7, 2 * 24 * 60 * 60).await;
    pin(&harness, &other_connection, 7, 2 * 24 * 60 * 60).await;

    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    // THE SAME CERTIFICATE, pasted by each organization's own link holder.
    let shared = pem_certificate(9);
    for (organization, connection, key) in [
        (&first, &their_connection, "k-one"),
        (&second, &other_connection, "k-two"),
    ] {
        let cookie = open_session_in(&harness, "certificate-renewal", key, organization).await;
        let form = format!(
            "connection={}&certificate={}",
            urlencode(&connection.to_string()),
            urlencode(&shared)
        );
        let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;
        assert_eq!(status, 303, "paste for {connection}: {body}");
    }

    assert_eq!(
        apply_pin_requests(&harness).await,
        2,
        "both organizations' pastes must be queued, not one"
    );
    assert_eq!(pinned_count(&harness, &their_connection).await, 2);
    assert_eq!(
        pinned_count(&harness, &other_connection).await,
        2,
        "the second organization's renewal must land too"
    );
}

#[tokio::test]
async fn pasting_the_same_certificate_twice_is_answered_as_success() {
    // IDEMPOTENT TO THE HOLDER. The outbox refuses a duplicate key with a conflict, and letting
    // that reach the caller answered "This did not work just now; your link has not been used"
    // about a renewal that had in fact been accepted -- which invites them to paste again, and
    // then to call their vendor.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;
    pin(&harness, &connection, 7, 2 * 24 * 60 * 60).await;

    let cookie = open_session_in(&harness, "certificate-renewal", "k-renew", &organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/certificate-renewal/pin",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&connection.to_string()),
        urlencode(&pem_certificate(9))
    );

    for attempt in 1..=2 {
        let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;
        assert_eq!(
            status, 303,
            "attempt {attempt} was not answered as success: {body}"
        );
    }
    assert_eq!(
        apply_pin_requests(&harness).await,
        1,
        "and the certificate is queued once, not twice"
    );
    assert_eq!(pinned_count(&harness, &connection).await, 2);
}

/// Add an IT contact to `organization`, as the vendor does over the management API.
async fn add_contact(
    harness: &Harness,
    organization: &OrganizationId,
    email: &str,
    category: &str,
) -> ironauth_store::OrgContactId {
    let env = Env::system();
    let scope = harness.scope();
    let id = ironauth_store::OrgContactId::generate(&env, &scope);
    let now = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_micros(),
    )
    .expect("in range");
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .org_contacts()
        .add(
            &env,
            ironauth_store::NewOrgContact {
                id: &id,
                organization_id: organization,
                display_name: "A Person",
                email,
                category,
                created_at_micros: now,
            },
        )
        .await
        .expect("add the contact");
    id
}

async fn contacts_page(harness: &Harness, organization: &OrganizationId, key: &str) -> String {
    let cookie = open_session_in(harness, "contacts", key, organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/contacts",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "{body}");
    body
}

#[tokio::test]
async fn the_contacts_page_lists_this_organizations_contacts_and_what_each_receives() {
    // #141 criterion 3's portal half: the customer's own administrator sees who operational
    // notices reach, without going through their vendor.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    add_contact(&harness, &organization, "ops@contoso.test", "technical").await;
    add_contact(&harness, &organization, "soc@contoso.test", "security").await;

    let body = contacts_page(&harness, &organization, "k-contacts").await;

    assert!(body.contains("ops@contoso.test"), "{body}");
    assert!(body.contains("soc@contoso.test"), "{body}");
    // THE CATEGORY IN THE READER'S WORDS. Printing the stored value raw would make them guess
    // which category receives a certificate warning, and guessing wrong there is how a list ends
    // up looking complete while warning nobody.
    assert!(
        body.contains("certificate expiry"),
        "the technical row must say it receives certificate warnings: {body}"
    );
    assert!(
        body.contains("security notices"),
        "and the security row must say what it receives: {body}"
    );
}

#[tokio::test]
async fn a_list_with_no_technical_contact_says_nobody_is_warned() {
    // THE ONE ABSENCE WORTH CALLING OUT. Certificate expiry notices reach the TECHNICAL contacts
    // only, so a list of security and billing contacts looks populated and warns nobody about
    // the thing most likely to break this organization's sign-in.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    add_contact(&harness, &organization, "soc@contoso.test", "security").await;
    add_contact(&harness, &organization, "ap@contoso.test", "billing").await;

    let body = contacts_page(&harness, &organization, "k-contacts").await;

    assert!(
        body.contains("soc@contoso.test"),
        "the list is not empty: {body}"
    );
    assert!(
        body.contains("nobody here is warned"),
        "a list with no technical contact must say so: {body}"
    );
}

#[tokio::test]
async fn an_empty_contact_list_says_what_it_costs() {
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;

    let body = contacts_page(&harness, &organization, "k-contacts").await;

    assert!(
        body.contains("reach nobody"),
        "an empty list must say that notices reach nobody: {body}"
    );
    assert!(
        body.contains("certificate expires"),
        "and name the consequence a reader will care about: {body}"
    );
}

#[tokio::test]
async fn a_contacts_session_sees_only_its_own_organizations_contacts() {
    // A contact list is a list of people's names and work addresses. A holder for one
    // organization seeing a neighbour's is a disclosure of exactly the thing the portal link's
    // single-organization scope exists to prevent.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    add_contact(&harness, &mine, "ops@contoso.test", "technical").await;
    add_contact(&harness, &theirs, "ops@initech.test", "technical").await;

    let body = contacts_page(&harness, &mine, "k-contacts").await;

    assert!(body.contains("ops@contoso.test"), "{body}");
    assert!(
        !body.contains("ops@initech.test"),
        "a contacts session must not see another organization's people: {body}"
    );
}

#[tokio::test]
async fn a_technical_contact_past_the_page_bound_is_not_reported_as_nobody() {
    // THE PAGE MUST NOT CONTRADICT THE ROUTER. `CertificateNoticeConsumer` loops the contact
    // list TO EXHAUSTION and mails every technical contact wherever it sorts; this page shows a
    // bounded number. Counting technical contacts only over the RENDERED rows let an
    // organization whose hundred security contacts sort ahead of its one technical contact read
    // "nobody here is warned" while the router was warning that person.
    //
    // NO FIXTURE HERE EVER REACHED THE BOUND before this test -- the largest was two rows -- so
    // the truncation banner was unmeasured too.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    for index in 0..101 {
        add_contact(
            &harness,
            &organization,
            &format!("soc{index}@contoso.test"),
            "security",
        )
        .await;
    }
    // Added last, so it sorts last in the (created_at, id) order the listing uses.
    add_contact(&harness, &organization, "ops@contoso.test", "technical").await;

    let body = contacts_page(&harness, &organization, "k-contacts").await;

    assert!(
        body.contains("Showing the first"),
        "a truncated list must admit its bound: {body}"
    );
    assert!(
        !body.contains("so nobody here is warned"),
        "the page claimed nobody is warned while a technical contact exists: {body}"
    );
}

#[tokio::test]
async fn the_no_technical_warning_is_absent_when_a_technical_contact_is_listed() {
    // MEASURED IN ONE DIRECTION ONLY until now. The suite proved the sentence CAN appear;
    // nothing proved it does not appear when it should not. Making the technical count
    // permanently zero left all 52 tests green while every page carried a warning
    // contradicting its own table.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    add_contact(&harness, &organization, "ops@contoso.test", "technical").await;
    add_contact(&harness, &organization, "soc@contoso.test", "security").await;

    let body = contacts_page(&harness, &organization, "k-contacts").await;

    assert!(body.contains("ops@contoso.test"), "{body}");
    assert!(
        !body.contains("nobody here is warned"),
        "a list WITH a technical contact must not warn that nobody is warned: {body}"
    );
}

#[tokio::test]
async fn a_category_nothing_routes_to_says_so_rather_than_promising_mail() {
    // THE RECEIVES COLUMN IS A CLAIM. `CertificateNoticeConsumer` is the only delivery path any
    // contact category feeds and it compares against `technical` alone -- nothing in the tree
    // sends a security notice or a billing one. Under a heading saying these are the people
    // operational notices reach, a cell reading "security notices" tells a customer they are
    // covered for something no producer exists for.
    //
    // The billing arm was also unmeasured outright: replacing its text with the technical
    // sentence left every test green.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    add_contact(&harness, &organization, "ops@contoso.test", "technical").await;
    add_contact(&harness, &organization, "soc@contoso.test", "security").await;
    add_contact(&harness, &organization, "ap@contoso.test", "billing").await;

    let body = contacts_page(&harness, &organization, "k-contacts").await;

    assert!(
        body.contains("SSO and provisioning problems, including certificate expiry"),
        "the technical row must say what it actually receives: {body}"
    );
    // PER ROW, not counted over the body. A body-wide count is a sum over the things it means to
    // distinguish, and it broke the moment the page gained an add form whose dropdown carries
    // the same (correct) wording -- four occurrences where it expected two. Slicing each
    // contact's row asserts the thing the test is named for and is indifferent to what else the
    // page grows.
    for address in ["soc@contoso.test", "ap@contoso.test"] {
        let at = body
            .find(address)
            .unwrap_or_else(|| panic!("no row for {address} in {body}"));
        let start = body[..at].rfind("<tr>").expect("a row start");
        let row = &body[start..at + body[at..].find("</tr>").expect("a row end")];
        assert!(
            row.contains("none are sent yet"),
            "{address}'s row must say nothing is sent to it: {row}"
        );
    }
    // AND THE FORM AGREES WITH THE TABLE. The dropdown is where somebody CHOOSES a category, so
    // a label promising "security notices" there is the promise the table just retracted --
    // which is exactly what this page did until the options were derived from the same function
    // the rows use.
    assert!(
        !body.contains(">security notices<"),
        "no label may promise mail with no producer behind it: {body}"
    );
}

/// Create a client attributed to `organization`, returning the id its audit row targets.
async fn attributed_client(harness: &Harness, organization: &OrganizationId, name: &str) -> String {
    let env = Env::system();
    // THE DATA PLANE, because `clients` INSERT is granted to `ironauth_app` -- the opposite way
    // round from `saml_connection_certificates`, whose writes are control-plane only. Which
    // plane owns a table is per table, not a rule.
    harness
        .db()
        .store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .in_organization(*organization)
        .clients()
        .create(&env, name)
        .await
        .expect("create a client in an organization")
        .to_string()
}

async fn audit_page(
    harness: &Harness,
    organization: &OrganizationId,
    key: &str,
    query: &str,
) -> String {
    let cookie = open_session_in(harness, "audit", key, organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/audit{query}",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "{body}");
    body
}

#[tokio::test]
async fn the_audit_page_shows_this_organizations_events_and_no_others() {
    // #141 criterion 4, at the surface. The store test proves the query; this proves the PAGE
    // passes the session's organization to it, which is the only thing standing between a
    // portal holder and a neighbour's history.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    let ours = attributed_client(&harness, &mine, "ours").await;
    let neighbour = attributed_client(&harness, &theirs, "neighbour").await;

    let body = audit_page(&harness, &mine, "k-audit", "").await;

    assert!(body.contains(&ours), "our own event is missing: {body}");
    assert!(
        !body.contains(&neighbour),
        "a neighbour's event was shown: {body}"
    );
    assert!(
        body.contains("client.create"),
        "the action is named: {body}"
    );
    assert!(body.contains("service "), "and the actor's kind: {body}");
}

#[tokio::test]
async fn the_audit_page_never_shows_the_detail_or_the_correlation_id() {
    // BOTH ARE ON EVERY ROW AND NEITHER BELONGS HERE. `detail` is free text the vendor's own
    // handlers write for their own operators, so publishing it on a customer-facing page ships
    // whatever a future handler happens to put in it; the correlation id is an internal request
    // handle. Omitted deliberately, and asserted so a later "just add the columns" cannot pass.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    attributed_client(&harness, &mine, "ours").await;

    let body = audit_page(&harness, &mine, "k-audit", "").await;

    let record = harness
        .db()
        .store()
        .scoped(harness.scope())
        .audit()
        .search_for_organization(&mine, &ironauth_store::AuditSearch::default(), 10)
        .await
        .expect("search")
        .into_iter()
        .next()
        .expect("an event");
    assert!(
        !body.contains(&record.correlation_id.to_string()),
        "the correlation id reached a customer-facing page: {body}"
    );
    if let Some(detail) = &record.detail {
        assert!(
            !body.contains(detail.as_str()),
            "the operator detail reached a customer-facing page: {body}"
        );
    }
}

#[tokio::test]
async fn a_filter_narrows_the_audit_page_and_says_when_nothing_matches() {
    // CRITERION 5 at the surface. The corpus holds a row the filter must EXCLUDE, and the empty
    // message must distinguish "nothing recorded" from "nothing matching" -- one message for
    // both leaves a reader unable to tell an over-narrow filter from a quiet month.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let first = attributed_client(&harness, &mine, "first").await;
    let second = attributed_client(&harness, &mine, "second").await;

    let both = audit_page(&harness, &mine, "k-all", "").await;
    assert!(both.contains(&first) && both.contains(&second), "{both}");

    let narrowed = audit_page(&harness, &mine, "k-one", &format!("?target={first}")).await;
    assert!(narrowed.contains(&first), "{narrowed}");
    assert!(
        !narrowed.contains(&second),
        "the target filter did not narrow: {narrowed}"
    );

    let none = audit_page(&harness, &mine, "k-none", "?action=saml_certificate.pinned").await;
    assert!(
        none.contains("No events match those filters"),
        "an over-narrow filter must say so: {none}"
    );
    assert!(
        !none.contains("Nothing has been recorded"),
        "and must not read as an empty history: {none}"
    );
}

#[tokio::test]
async fn an_organization_with_no_events_says_so_rather_than_showing_an_empty_table() {
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;

    let body = audit_page(&harness, &mine, "k-empty", "").await;
    assert!(
        body.contains("Nothing has been recorded"),
        "an empty history must say so: {body}"
    );
    assert!(!body.contains("<table>"), "and render no table: {body}");
}

/// Drain the contact-change queue, as the control plane's worker does.
///
/// The portal cannot write a contact -- 0207 grants `org_contacts` INSERT and the soft-delete
/// UPDATE to `ironauth_control` alone -- so it enqueues and this applies. A test stopping at the
/// 303 would be measuring that a row reached a queue, which is not what the customer asked for.
async fn apply_contact_changes(harness: &Harness) -> usize {
    use ironauth_store::outbox::OutboxConsumer as _;

    let scope = harness.scope();
    let env = Env::system();
    let consumer = ironauth_admin::contact_changes::ContactChangeConsumer::new(
        harness.db().control_store().clone(),
    );
    let mut applied = 0;
    loop {
        let claimed = harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                ironauth_store::CONTACT_CHANGE_CONSUMER,
                std::time::Duration::from_secs(30),
                100,
            )
            .await
            .expect("claim");
        if claimed.is_empty() {
            return applied;
        }
        for message in &claimed {
            consumer
                .handle(&env, scope, message)
                .await
                .expect("the contact change applies");
            harness
                .db()
                .store()
                .scoped(scope)
                .outbox()
                .complete(&env, message)
                .await
                .expect("complete");
            applied += 1;
        }
    }
}

/// The live contacts of `organization`, read as the vendor.
async fn contacts_of(harness: &Harness, organization: &OrganizationId) -> Vec<String> {
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .org_contacts()
        .list_for_organization(organization, 50, None)
        .await
        .expect("list the contacts")
        .into_iter()
        .map(|contact| contact.email)
        .collect()
}

fn change_path(harness: &Harness) -> String {
    format!(
        "/t/{}/e/{}/portal/s/contacts/change",
        harness.scope().tenant(),
        harness.scope().environment()
    )
}

/// The customer's own administrator adds and removes a contact, end to end.
///
/// #141 criterion 3's write half. It is asserted THROUGH THE CONSUMER rather than at the 303,
/// because the portal only enqueues: a test that stopped at the redirect would pass while the
/// change never reached `org_contacts`.
#[tokio::test]
async fn a_contacts_session_adds_and_removes_a_contact_through_the_form() {
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let cookie = open_session_in(&harness, "contacts", "k-add", &organization).await;

    let form = format!(
        "action=add&display_name={}&email={}&category=technical",
        urlencode("Dana Ops"),
        urlencode("dana@contoso.test")
    );
    let (status, _, body) = harness
        .post_form(&change_path(&harness), &form, Some(&cookie))
        .await;
    assert_eq!(status, 303, "{body}");
    assert_eq!(apply_contact_changes(&harness).await, 1);
    assert!(
        contacts_of(&harness, &organization)
            .await
            .iter()
            .any(|email| email == "dana@contoso.test"),
        "the added contact never reached org_contacts"
    );

    let added = add_contact(&harness, &organization, "soc@contoso.test", "security").await;
    let form = format!("action=remove&contact={}", urlencode(&added.to_string()));
    let (status, _, body) = harness
        .post_form(&change_path(&harness), &form, Some(&cookie))
        .await;
    assert_eq!(status, 303, "{body}");
    assert_eq!(apply_contact_changes(&harness).await, 1);
    assert!(
        !contacts_of(&harness, &organization)
            .await
            .iter()
            .any(|email| email == "soc@contoso.test"),
        "the removed contact is still live"
    );
}

/// A session opened for another surface cannot change contacts.
///
/// Mounting a write behind the same session as a read does not make it the same permission, and
/// this is the fence that says so: `require_intent("contacts")`.
#[tokio::test]
async fn a_session_for_another_intent_cannot_change_contacts() {
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let cookie = open_session_in(&harness, "scim", "k-scim-contacts", &organization).await;

    let form = format!(
        "action=add&display_name={}&email={}&category=technical",
        urlencode("Mallory"),
        urlencode("mallory@evil.test")
    );
    let (status, _, body) = harness
        .post_form(&change_path(&harness), &form, Some(&cookie))
        .await;
    assert_ne!(status, 303, "a scim session changed contacts: {body}");
    assert_eq!(
        apply_contact_changes(&harness).await,
        0,
        "the refusal queued a change anyway, which is a refusal in name only"
    );
    assert!(
        contacts_of(&harness, &organization).await.is_empty(),
        "a contact was added by a session that has no business adding one"
    );
}

/// A contact in another organization is not removed, and the answer does not say which case it
/// was.
///
/// THE GROUPING IS NOT WHAT IT LOOKS LIKE, and it is worth stating exactly because the obvious
/// phrasing is wrong. A foreign-organization handle and an absent one both PARSE, are both
/// enqueued, and both get the same `303` a real removal gets -- the consumer is what checks the
/// organization, and it finds nothing to do. So the two indistinguishable answers are the
/// SUCCESS-shaped ones; a malformed field is the odd one out, and it is a `400`. That is still
/// the anti-enumeration property the surface needs, because the two a link holder could use to
/// probe are the two that match.
#[tokio::test]
async fn a_neighbours_contact_is_not_removed_and_answers_as_a_success_does() {
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    let neighbour = add_contact(&harness, &theirs, "ops@initech.test", "technical").await;
    let cookie = open_session_in(&harness, "contacts", "k-probe", &mine).await;

    let form = format!("action=remove&contact={}", urlencode(&neighbour.to_string()));
    let (foreign_status, _, body) = harness
        .post_form(&change_path(&harness), &form, Some(&cookie))
        .await;
    assert_eq!(foreign_status, 303, "{body}");
    apply_contact_changes(&harness).await;
    assert!(
        contacts_of(&harness, &theirs)
            .await
            .iter()
            .any(|email| email == "ops@initech.test"),
        "a link holder for one organization removed a neighbour's contact"
    );

    // AN ABSENT HANDLE ANSWERS IDENTICALLY. This is the pair that matters: if the two differed,
    // the form would tell a holder which handles exist in other organizations.
    let absent = ironauth_store::OrgContactId::generate(&Env::system(), &harness.scope());
    let form = format!("action=remove&contact={}", urlencode(&absent.to_string()));
    let (absent_status, _, body) = harness
        .post_form(&change_path(&harness), &form, Some(&cookie))
        .await;
    assert_eq!(
        absent_status, foreign_status,
        "an absent contact answered differently from a neighbour's, which makes the form a \
         probe for handles in other organizations: {body}"
    );

    // AND A MALFORMED FIELD IS THE ONE THAT DIFFERS, which is fine: it reveals nothing about
    // who exists, only that the request was not well formed.
    let (status, _, body) = harness
        .post_form(&change_path(&harness), "action=remove&contact=not-a-handle", Some(&cookie))
        .await;
    assert_eq!(status, 400, "{body}");
}
