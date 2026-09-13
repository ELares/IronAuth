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
use ironauth_jose::xmldsig::test_util::XmlTestKey;
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

/// As [`connect_with_provider`], with the connection id supplied by the caller.
///
/// THE CALLER NEEDS THE ID FIRST, because a real provisioning token is `{scim_id}.{secret}` and
/// the digest stored here has to be the digest of that whole string. Generating the id inside
/// would leave a fixture that can store a digest but cannot state the token it came from.
async fn connect_with_id(
    harness: &Harness,
    organization: &OrganizationId,
    display_name: &str,
    provider: &str,
    id: &ironauth_store::ScimConnectionId,
    token: &str,
    expires_at_unix_micros: Option<i64>,
) -> ironauth_store::ScimConnectionId {
    let env = Env::system();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .create(
            &env,
            ironauth_store::NewScimConnection {
                id,
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
    *id
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
    saml_connection_from(
        harness,
        organization,
        display_name,
        "https://idp.example/entity",
    )
    .await
}

/// [`saml_connection`] with the identity provider's own published entity id chosen by the test.
///
/// The SSO page keys its setup guide on that string, because `saml_connections` has no provider
/// column to key on, so a test of the guide has to be able to set it.
async fn saml_connection_from(
    harness: &Harness,
    organization: &OrganizationId,
    display_name: &str,
    idp_entity_id: &str,
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
                idp_entity_id,
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

    // THE CONTROL, in the SAME session against a connection that is ours. Every assertion
    // above is equally satisfied by a surface that refuses every pin -- the happy path lives
    // in its own test, so without this one a page broken outright would still report a working
    // organization fence here.
    let ours = saml_connection(&harness, &mine, "Okta Ours").await;
    pin(&harness, &ours, 7, 2 * 24 * 60 * 60).await;
    let form = format!(
        "connection={}&certificate={}",
        urlencode(&ours.to_string()),
        urlencode(&pem_certificate(9))
    );
    let (status, _, body) = harness.post_form(&path, &form, Some(&cookie)).await;
    assert_eq!(status, 303, "the control was refused: {body}");
    assert_eq!(
        apply_pin_requests(&harness).await,
        1,
        "the control queued nothing, so the zero asserted above is not evidence of a refusal"
    );
    assert_eq!(
        pinned_count(&harness, &ours).await,
        2,
        "the control failed: this session cannot pin onto its OWN connection either, so the \
         refusal above proves nothing about the organization fence"
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
async fn a_target_filter_naming_another_organizations_object_matches_nothing() {
    // CRITERION 3 OF #140 ON THE READ SIDE, at the one combination the other audit tests leave
    // open. `the_audit_page_shows_this_organizations_events_and_no_others` drives the
    // UNFILTERED page, and `a_filter_narrows_the_audit_page_and_says_when_nothing_matches`
    // drives a filter whose two subjects both belong to the caller. Neither asks what happens
    // when a filter names an object of ANOTHER organization -- which is the request a holder
    // probing this surface actually sends, because the filter is the only caller-supplied
    // value that reaches the query.
    //
    // The organization comes off the session and the filter is meant to narrow WITHIN it. A
    // filter that instead widened -- a second statement that forgot the organization, an OR
    // where an AND belongs -- would hand a neighbour's configuration history to anyone holding
    // a link, and every other test on this surface would still pass.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    let ours = attributed_client(&harness, &mine, "ours").await;
    let neighbour = attributed_client(&harness, &theirs, "neighbour").await;

    let probed = audit_page(&harness, &mine, "k-probe", &format!("?target={neighbour}")).await;
    assert!(
        !probed.contains(&neighbour),
        "a portal session filtered on another organization's object and was shown it: {probed}"
    );
    assert!(
        probed.contains("No events match those filters"),
        "the page has to answer the narrowed question rather than fall back to the unfiltered \
         list: {probed}"
    );

    // THE CONTROL, a second session for the SAME organization against our own object.
    // Without it the assertion above
    // is equally satisfied by a target filter that matches nothing at all, and this test would
    // pass against a surface whose filtering is broken outright.
    let own = audit_page(&harness, &mine, "k-own", &format!("?target={ours}")).await;
    assert!(
        own.contains(&ours),
        "the control failed: the target filter matches nothing even for our own object, so \
         the neighbour's absence above proves nothing: {own}"
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
    // THE ORGANIZATION FILTER SITS AT TWO SITES, which is worth knowing before reading a
    // mutation result off this test. `remove_with_event` probes for the live row and then
    // updates it, and both statements carry `organization_id`. Take it off the probe alone and
    // the update still matches nothing, which the store reports as the ordinary already-gone
    // answer, so this test passes. Only removing both lets a neighbour's row through, and then
    // this test fails. A single-site mutant surviving here is the second filter doing its job,
    // not a hole in this test.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    let neighbour = add_contact(&harness, &theirs, "ops@initech.test", "technical").await;
    let cookie = open_session_in(&harness, "contacts", "k-probe", &mine).await;

    let form = format!(
        "action=remove&contact={}",
        urlencode(&neighbour.to_string())
    );
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
        .post_form(
            &change_path(&harness),
            "action=remove&contact=not-a-handle",
            Some(&cookie),
        )
        .await;
    assert_eq!(status, 400, "{body}");

    // THE CONTROL, in the SAME session against a contact that is ours. The three answers above
    // are all "nothing happened", and a consumer that removed nothing for anybody would give
    // all three. The happy path lives in its own test, so only this line ties the neighbour's
    // survival to the organization fence rather than to a surface that does not work.
    let own = add_contact(&harness, &mine, "it@contoso.test", "technical").await;
    let form = format!("action=remove&contact={}", urlencode(&own.to_string()));
    let (status, _, body) = harness
        .post_form(&change_path(&harness), &form, Some(&cookie))
        .await;
    assert_eq!(status, 303, "the control was refused: {body}");
    apply_contact_changes(&harness).await;
    assert!(
        !contacts_of(&harness, &mine)
            .await
            .iter()
            .any(|email| email == "it@contoso.test"),
        "the control failed: this session cannot remove its OWN contact either, so the \
         neighbour's survival above proves nothing about the organization fence"
    );
}

/// Open an `sso` session for `organization` and fetch its single sign-on page.
async fn sso_page(harness: &Harness, organization: &OrganizationId, key: &str) -> String {
    let cookie = open_session_in(harness, "sso", key, organization).await;
    let path = format!(
        "/t/{}/e/{}/portal/s/sso",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let (status, body) = get_with_cookie(harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the single sign-on page: {body}");
    body
}

/// The slice of the page belonging to ONE connection, from its heading to the next.
///
/// A whole-body substring check is a sum over the sections it claims to distinguish: with two
/// connections rendered, asserting that the page contains "Okta" is satisfied by either one of
/// them, so a build that gave every connection the same guide would stay green. Slicing by the
/// heading is what binds an assertion to the connection it is about, exactly as `row_for` does
/// for certificate rows.
fn section_for(body: &str, heading: &str) -> String {
    let needle = format!("<h2>{heading}</h2>");
    let at = body
        .find(&needle)
        .unwrap_or_else(|| panic!("no section headed {heading} in {body}"));
    let rest = &body[at + needle.len()..];
    let end = rest.find("<h2>").unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// An OIDC upstream for `organization`: a connector, and the binding that points at it.
async fn oidc_upstream(harness: &Harness, organization: &OrganizationId, slug: &str) {
    upstream_with_protocol(harness, organization, slug, "oidc").await;
}

/// [`oidc_upstream`] with the protocol the connector declares chosen by the test.
///
/// `Protocol::Oauth2` upstreams (issue #74) bind through the same table, and the page's label
/// and guide key on this string, so a test of that has to be able to set it.
async fn upstream_with_protocol(
    harness: &Harness,
    organization: &OrganizationId,
    slug: &str,
    protocol: &str,
) {
    let env = Env::system();
    let scope = harness.scope();
    let control = harness.db().control_store();
    let actor = || ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env));
    let connector_id = ironauth_store::ConnectorId::generate(&env, &scope);
    let definition = format!(
        r#"{{"connector_id":"{slug}","display_name":"Upstream","protocol":"{protocol}","endpoints":{{"issuer":"https://upstream.example"}},"scopes":["openid","email"],"client_id":"upstream-client"}}"#
    );
    control
        .scoped(scope)
        .acting(actor(), CorrelationId::generate(&env))
        .connectors()
        .create(
            &env,
            &connector_id,
            1_000_000,
            ironauth_store::NewConnector {
                slug,
                definition_json: &definition,
                client_secret: b"upstream-secret",
                capabilities: ironauth_store::ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    email_verified_trust: "untrusted",
                },
                enabled: true,
            },
            None,
        )
        .await
        .expect("create the connector");

    let binding = ironauth_store::OrgConnectionId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(actor(), CorrelationId::generate(&env))
        .org_connections()
        .create(
            &env,
            &binding,
            1_000_000,
            ironauth_store::NewOrgConnection {
                organization_id: organization,
                upstream: ironauth_store::OrgConnectionUpstream::Connector(&connector_id),
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("bind the connector to the organization");
}

#[tokio::test]
async fn the_sso_page_hands_over_the_values_a_saml_console_asks_for() {
    // #140 CRITERION 4, the "correct copy-paste values for the specific connection being
    // configured" half. The three values are the entire reason an IT admin opens this page:
    // the ACS URL and the audience go into their provider's console by hand, and the metadata
    // document is the import that saves them typing either.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;

    let body = sso_page(&harness, &organization, "k-sso").await;
    let section = section_for(&body, "Okta Production");

    assert!(
        section.contains("https://ironauth.example/saml/acs"),
        "the ACS URL is missing, which is the value the page exists to hand over: {section}"
    );
    assert!(
        section.contains("https://ironauth.example/saml/metadata"),
        "the audience (SP entity id) is missing: {section}"
    );
    // TIED TO THIS DEPLOYMENT AND THIS CONNECTION, not merely present. A metadata URL naming
    // another connection, or another deployment, is pasted successfully and fails later with
    // nothing on this page to blame.
    let scope_path = format!(
        "/t/{}/e/{}",
        harness.scope().tenant(),
        harness.scope().environment()
    );
    let deployment_base = harness
        .issuer()
        .strip_suffix(&scope_path)
        .expect("the per-environment issuer is the deployment base plus the scope path")
        .to_owned();
    let expected = format!("{deployment_base}{scope_path}/saml/metadata/{connection}");
    assert!(
        section.contains(&expected),
        "the metadata URL must name this deployment and this connection, expected {expected}: \
         {section}"
    );
}

#[tokio::test]
async fn the_sso_guide_follows_the_provider_each_connection_names() {
    // #140 CRITERION 4, the "per IdP" half. `saml_connections` has no provider column, so the
    // page keys on the entity id the identity provider itself publishes. What has to be true is
    // that the keying REACHES the right section: two connections on one page, each getting its
    // own provider's steps.
    //
    // BOTH DIRECTIONS, because either alone is satisfied by a page that always renders the same
    // guide. The Okta section proves the match fires; the unrecognized section proves it does
    // not fire for everything, and that the fallback is a usable guide rather than a blank.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    saml_connection_from(
        &harness,
        &organization,
        "Okta Production",
        "http://www.okta.com/exk1fake",
    )
    .await;
    saml_connection_from(
        &harness,
        &organization,
        "In House",
        "https://sso.contoso.test/entity",
    )
    .await;

    let body = sso_page(&harness, &organization, "k-sso-guides").await;

    let okta = section_for(&body, "Okta Production");
    assert!(
        okta.contains("Okta"),
        "the Okta connection did not get Okta's guide: {okta}"
    );
    assert!(
        okta.contains("Audience URI"),
        "and it must name the field Okta's own console calls it: {okta}"
    );

    let generic = section_for(&body, "In House");
    assert!(
        !generic.contains("Audience URI"),
        "an unrecognized provider was given Okta's console wording: {generic}"
    );
    assert!(
        generic.contains("assertion consumer service URL"),
        "the fallback has to be a usable guide, not a blank section: {generic}"
    );
}

#[tokio::test]
async fn the_sso_page_hands_over_the_redirect_uri_the_oidc_console_asks_for() {
    // The OIDC half of criterion 4. One value matters upstream and this is it, and it has to be
    // the URL the callback route actually serves: a second spelling is pasted successfully and
    // fails at the first sign-in, with the portal's own page as the evidence it was right.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    oidc_upstream(&harness, &organization, "contoso-entra").await;

    let body = sso_page(&harness, &organization, "k-sso-oidc").await;
    let section = section_for(&body, "contoso-entra");

    let expected = format!(
        "{}/federation/contoso-entra/callback",
        harness.issuer().trim_end_matches('/')
    );
    assert!(
        section.contains(&expected),
        "the redirect URI must be the one the callback route serves, expected {expected}: \
         {section}"
    );
    assert!(
        section.contains("client secret"),
        "the guide has to say the application must be the confidential kind: {section}"
    );
}

#[tokio::test]
async fn an_sso_session_sees_only_its_own_organizations_connections() {
    // #140 criterion 3, for the panel this slice adds. Every other panel that lists
    // organization state has this test, and the page reads TWO tables, so it needs a
    // neighbour in each: a SAML connection and an OIDC binding that both belong elsewhere.
    let harness = Harness::start().await;
    let mine = seed_org(&harness, "Contoso").await;
    let theirs = seed_org(&harness, "Initech").await;
    saml_connection(&harness, &mine, "Contoso Okta").await;
    saml_connection(&harness, &theirs, "Initech Okta").await;
    oidc_upstream(&harness, &mine, "contoso-upstream").await;
    oidc_upstream(&harness, &theirs, "initech-upstream").await;

    let body = sso_page(&harness, &mine, "k-sso-isolation").await;

    // THE CONTROLS FIRST, one per table: "the neighbour is absent" is also true of a page that
    // lists nothing, and this page has a legitimate empty state.
    assert!(
        body.contains("Contoso Okta"),
        "our own SAML connection is missing, so the absences below prove nothing: {body}"
    );
    assert!(
        body.contains("contoso-upstream"),
        "our own OIDC upstream is missing, so the absences below prove nothing: {body}"
    );
    assert!(
        !body.contains("Initech Okta"),
        "a portal session for one organization was shown another's SAML connection: {body}"
    );
    assert!(
        !body.contains("initech-upstream"),
        "a portal session for one organization was shown another's OIDC upstream: {body}"
    );
}

#[tokio::test]
async fn an_organization_with_no_sign_on_connection_is_offered_the_form() {
    // NOT A REFUSAL. The link is fine and nothing is configured yet, and the two are different
    // things to an admin holding a link they were told would work.
    //
    // AND NOT A DEAD END. This page used to say "ask your vendor to create one", which is
    // exactly the vendor-side action #140 criterion 1 exists to remove -- and it said it to the
    // reader the whole surface is for, the one who has just arrived with nothing set up. The
    // assertion changed with the behaviour rather than being relaxed: what is measured now is
    // that they can finish, which is a stronger property than being told they cannot.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;

    let body = sso_page(&harness, &organization, "k-sso-empty").await;

    assert!(
        body.contains("Nothing is configured yet"),
        "an unconfigured organization must be told so: {body}"
    );
    assert!(
        body.contains("Add a SAML connection"),
        "and handed the form, not sent to their vendor: {body}"
    );
    assert!(
        !body.contains("Ask your vendor to create one"),
        "the dead end has to be gone: {body}"
    );
}

#[tokio::test]
async fn an_oauth2_upstream_is_not_described_as_openid_connect() {
    // `Protocol::Oauth2` (issue #74, GitHub being the example) binds through the same
    // `org_connections` table as an OIDC connector. An earlier version of this page labelled
    // every binding "OpenID Connect" and told its admin to grant an `openid` scope.
    //
    // THAT IS THE ONE FAILURE A GUIDE MUST NOT HAVE. A generic guide is a degraded answer; a
    // guide naming a field the provider does not have sends the admin hunting, and when they
    // give up they ask the vendor -- which is the support call this whole surface exists to
    // remove. The SAML classifier is allowed a substring test precisely because its misses
    // degrade instead of misdirecting, and this one has to meet the same bar.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    upstream_with_protocol(&harness, &organization, "contoso-github", "oauth2").await;

    let body = sso_page(&harness, &organization, "k-sso-oauth2").await;
    let section = section_for(&body, "contoso-github");

    // ASSERTED ON THE LABEL, not on the section. The corrected guide says "there is no
    // OpenID Connect here", which contains the phrase while meaning the opposite -- a bare
    // substring check over the whole section fails against correct output, which is how the
    // first version of this test read.
    assert!(
        !section.contains("Type: OpenID Connect"),
        "an OAuth 2.0 upstream was labelled OpenID Connect: {section}"
    );
    assert!(
        section.contains("Type: OAuth 2.0"),
        "and it has to say what it actually is: {section}"
    );
    assert!(
        !section.contains("Grant the openid"),
        "the admin must not be told to grant a scope this protocol has no concept of: \
         {section}"
    );
    // THE CONTROL: the value that IS the same for both protocols is still handed over, so
    // this is a corrected guide rather than a blank one.
    let expected = format!(
        "{}/federation/contoso-github/callback",
        harness.issuer().trim_end_matches('/')
    );
    assert!(
        section.contains(&expected),
        "the redirect URI is the same either way and must still be here: {section}"
    );
}

#[tokio::test]
async fn a_switched_off_saml_connection_says_so_and_offers_no_metadata_url() {
    // `saml_metadata::metadata_get` reads through `find_active`, and the page's own listing
    // read does not filter on `active` -- so a switched-off connection is listed here while
    // its metadata document 404s.
    //
    // PRINTING IT ANYWAY IS THE WORST OF THE THREE OPTIONS. Hiding the connection tells an
    // admin a connection they have does not exist. Printing a URL that answers nothing sends
    // them to configure an import that fails, and the failure arrives days later reading as
    // "your metadata is broken", with this page as the evidence it should have worked. Saying
    // it is off is the only answer that is both true and actionable.
    let harness = Harness::start().await;
    let organization = seed_org(&harness, "Contoso").await;
    let connection = saml_connection(&harness, &organization, "Okta Production").await;

    let env = Env::system();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .saml_connections()
        .set_active(&env, &connection, false, None)
        .await
        .expect("switch the connection off");

    let body = sso_page(&harness, &organization, "k-sso-off").await;
    let section = section_for(&body, "Okta Production");

    assert!(
        section.contains("switched off"),
        "a connection nobody can sign in through must say so: {section}"
    );
    assert!(
        !section.contains("/saml/metadata/"),
        "the metadata URL 404s while the connection is off and must not be offered: {section}"
    );
    // THE TWO STABLE VALUES STAY, so this is a warning rather than a blanked page: an admin
    // can still configure their side before the vendor switches it on.
    assert!(
        section.contains("https://ironauth.example/saml/acs"),
        "the ACS URL is a stable property and should still be handed over: {section}"
    );
}

/// Pin the REAL public point of `key`, so a response it signs actually verifies.
///
/// The `pin` helper above seeds a synthetic point, which is right for the pages that only
/// render certificate rows and wrong here: this file's other fixtures never ask a signature to
/// hold, and a diagnosis about the audience is only reachable once one does.
async fn pin_certificate_for(
    harness: &Harness,
    connection: &ironauth_store::SamlConnectionId,
    key: &XmlTestKey,
) {
    let env = Env::system();
    let scope = harness.scope();
    let id = ironauth_store::SamlCertificateId::generate(&env, &scope);
    // THE HARNESS CLOCK, and NOT for the reason `pin` gives -- that rationale was copied here
    // and does not hold on this path. `pin` seeds rows for the certificate LISTING, which reads
    // these columns and dates them; `saml_acs` never reads either of them, so the verification
    // this fixture feeds would hold with any pair at all. They are written against the harness
    // clock so the row is coherent with the rest of the fixture rather than because anything
    // under test consults it, and a reviewer should not read a dependency into them.
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
                public_key: &key.public_point(),
                rsa_exponent: None,
                certificate_der: &[0x30, 0x82, 0x01],
                fingerprint_sha256: &[0x11; 32],
                not_before_unix_micros: now - 3_600_000_000,
                not_after_unix_micros: now + 3_600_000_000,
            },
            None,
            None,
        )
        .await
        .expect("pin the signing certificate");
}

/// Base64 the document the way an identity provider's form field carries it.
fn base64_of(xml: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

/// A signed SAML response whose audience is whatever the caller names.
///
/// ONE FIELD VARIES between the fixtures below, which is the discipline `saml_acs.rs` already
/// keeps for the same reason: a negative that differs in two ways cannot say which one the
/// diagnosis is about, and a test-connection page whose message is right for the wrong reason
/// is worse than a generic error, because an operator acts on it.
fn response_with_audience(key: &XmlTestKey, audience: &str) -> String {
    let children = format!(
        "<saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Subject><saml:NameID \
         Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
         ada@globex.example</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"https://ironauth.example/saml/acs\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"1969-12-31T23:58:00Z\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\">\
         <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement><saml:Attribute Name=\"email\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    );
    ironauth_saml::test_util::signed_response_with(key, "_a1", &children)
}

/// The same signed response, with the `Recipient` in its bearer confirmation varied.
///
/// ONE FIELD APART from [`response_with_audience`]'s passing form, for the reason that function
/// states: a negative differing in two ways cannot say which one the diagnosis is about.
fn response_with_recipient(key: &XmlTestKey, recipient: &str) -> String {
    let children = format!(
        "<saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Subject><saml:NameID \
         Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
         ada@globex.example</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"{recipient}\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"1969-12-31T23:58:00Z\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\">\
         <saml:AudienceRestriction>\
         <saml:Audience>https://ironauth.example/saml/metadata</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement><saml:Attribute Name=\"email\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    );
    ironauth_saml::test_util::signed_response_with(key, "_a1", &children)
}

/// Post a pasted response to the connection test and return the page.
async fn test_connection(
    harness: &Harness,
    cookie: &str,
    connection: &ironauth_store::SamlConnectionId,
    response_b64: &str,
) -> (axum::http::StatusCode, String) {
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/test",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "connection_id={}&saml_response={}",
        urlencoding(&connection.to_string()),
        urlencoding(response_b64),
    );
    post_form_from_with_cookie(harness, &path, &form, "same-origin", cookie).await
}

/// Percent-encode a form value.
fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[tokio::test]
async fn an_unpinned_certificate_is_named_as_the_setup_step_it_is() {
    // #140 criterion 6, the first of the three failures it names by name. `saml_route`'s own
    // doc says of these variants: "THAT FLOW IS NOT BUILT ... today the variant reaches a Rust
    // caller and nothing else". This is the flow, and this is the variant that matters most to
    // an admin still setting up: they have pinned nothing, and the generic answer -- "the
    // signature did not verify" -- sends them to their identity provider, where everything is
    // fine, and leaves them there.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let cookie = open_session_in(&harness, "sso", "tok-t1", &org).await;

    // ANY BYTES, deliberately: with nothing pinned there is no key to check a signature
    // against, so `examine` answers before it reads the document. A fixture that bothered to
    // sign would be measuring the same branch while implying the signature mattered.
    let (status, body) = test_connection(&harness, &cookie, &connection, "bm90LXhtbA==").await;

    assert_eq!(status, 200, "the diagnosis page: {body}");
    assert!(
        body.contains("No signing certificate is pinned"),
        "an admin who has pinned nothing must be told that, not that a signature failed: {body}"
    );
    assert!(
        !body.contains("signature did not verify"),
        "the generic answer sends them to the wrong system: {body}"
    );
}

#[tokio::test]
async fn a_wrong_audience_names_what_was_sent_and_what_is_expected() {
    // The second failure #140 names, and the one an identity provider gets wrong by default:
    // its own field for the audience is usually pre-filled with something else entirely.
    //
    // The message has to carry BOTH values. "Wrong audience" alone leaves an admin comparing
    // two strings they cannot both see, and the whole complaint the criterion makes about
    // generic errors is that they do not say what to change.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &connection, &key).await;
    let cookie = open_session_in(&harness, "sso", "tok-t2", &org).await;

    let wrong = response_with_audience(&key, "https://someone-elses-app.example/saml");
    let (status, body) = test_connection(&harness, &cookie, &connection, &base64_of(&wrong)).await;

    assert_eq!(status, 200, "the diagnosis page: {body}");
    assert!(
        body.contains("wrong audience"),
        "the diagnosis has to name the failure: {body}"
    );
    assert!(
        body.contains("https://someone-elses-app.example/saml"),
        "it has to say what the identity provider actually sent: {body}"
    );
    assert!(
        body.contains("https://ironauth.example/saml/metadata"),
        "and what this connection expects, which is the value they go and paste: {body}"
    );
}

#[tokio::test]
async fn one_organizations_session_cannot_diagnose_anothers_connection() {
    // The confinement every portal surface keeps, on the one route that reads another
    // organization's trust material. Without it a link issued for one customer reports back
    // another's audience and how many certificates they have pinned.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let mine = seed_org(&harness, "Acme").await;
    let theirs = seed_org(&harness, "Globex").await;
    let ours =
        saml_connection_from(&harness, &mine, "acme-okta", "https://idp.example/entity").await;
    let theirs_connection = saml_connection_from(
        &harness,
        &theirs,
        "globex-entra",
        "https://other.example/entity",
    )
    .await;
    let cookie = open_session_in(&harness, "sso", "tok-t4", &mine).await;

    // THE CONTROL FIRST: this session can diagnose its OWN connection, so the refusal below is
    // the fence rather than a route that refuses everybody.
    let (status, body) = test_connection(&harness, &cookie, &ours, "bm90LXhtbA==").await;
    assert_eq!(status, 200, "the session's own connection: {body}");

    let (status, body) =
        test_connection(&harness, &cookie, &theirs_connection, "bm90LXhtbA==").await;
    assert_eq!(
        status, 400,
        "one customer's portal diagnosed ANOTHER customer's connection: {body}"
    );
    assert!(
        !body.contains("globex"),
        "and it must not name them either: {body}"
    );
}

#[tokio::test]
async fn a_cross_site_connection_test_is_refused() {
    // The CSRF guard every portal POST takes. This one reports whether an organization has
    // finished its SSO setup, which another site has no business learning.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let cookie = open_session_in(&harness, "sso", "tok-t5", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/test",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "connection_id={}&saml_response=bm90LXhtbA%3D%3D",
        urlencoding(&connection.to_string())
    );
    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "cross-site", &cookie).await;
    assert_eq!(status, 403, "a cross-site diagnosis was served: {body}");
}

/// A connection that accepts a response it did not ask for, so `examine` runs to the end.
///
/// IT DIFFERS FROM `saml_connection_from` IN ONE FIELD `examine` READS, and that is the property
/// the pair below rests on. Every value the verification consults -- the issuer, the audience,
/// the skew, the maximum age, the name ID format, the encryption requirement, and the pinned
/// certificate -- is identical; `allow_unsolicited` is the only one that is not.
///
/// IT LIVES IN ANOTHER ORGANIZATION, because `saml_connections` is unique on
/// `(tenant, environment, organization, idp_entity_id)` and keeping the issuer equal is worth
/// more than keeping the organization equal: the issuer is a value `examine` compares and the
/// organization is not one it can see. `display_name` differs too, and reaches only the sentence
/// `diagnose` prints, never a decision.
async fn unsolicited_connection_from(
    harness: &Harness,
    organization: &OrganizationId,
    display_name: &str,
    idp_entity_id: &str,
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
                idp_entity_id,
                idp_sso_url: "https://idp.example/sso",
                sp_entity_id: "https://ironauth.example/saml/metadata",
                acs_url: "https://ironauth.example/saml/acs",
                allow_unsolicited: true,
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

#[tokio::test]
async fn a_response_that_passes_every_check_says_so_and_the_unsolicited_one_does_not() {
    // TWO GOOD-NEWS SENTENCES, AND THE DIFFERENCE BETWEEN THEM IS THE FINDING.
    //
    // `examine` refuses an unsolicited response BEFORE it reaches the connection's remaining
    // controls: the encryption requirement, the name ID format, and the attribute statement are
    // all checked AFTER that point. An earlier version of this page called the unsolicited
    // refusal "the certificate, issuer, audience and validity window all check out" and then
    // named the correlation as "the one thing this test cannot check" -- which was false, and
    // false in the direction that matters: a connection configured to require encryption refuses
    // every real sign-in, and this page would have called it healthy.
    //
    // ONE FIXTURE FIELD SEPARATES THE TWO RUNS, so the difference in the answer is attributable.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let key = XmlTestKey::generate();
    let right = base64_of(&response_with_audience(
        &key,
        "https://ironauth.example/saml/metadata",
    ));

    let solicited_only =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    pin_certificate_for(&harness, &solicited_only, &key).await;
    let cookie = open_session_in(&harness, "sso", "tok-t3", &org).await;
    let (status, narrow) = test_connection(&harness, &cookie, &solicited_only, &right).await;
    assert_eq!(status, 200, "the diagnosis page: {narrow}");
    assert!(
        narrow.contains("all check out"),
        "a response that passes every check this connection reaches must be reported as \
         passing: {narrow}"
    );
    assert!(
        !narrow.contains("was refused"),
        "and it must not read as a failure: {narrow}"
    );
    // THE LIMIT IS STATED. This is the assertion that would have failed against the sentence
    // this test replaced.
    assert!(
        narrow.contains("does not vouch for what comes after"),
        "the page must say what it did NOT reach, or an operator reads it as finished: {narrow}"
    );

    // THE SAME ISSUER, in another organization, with the same key pinned: see the helper's doc
    // for why the organization is the thing that gives way rather than the issuer.
    let other_org = seed_org(&harness, "Globex").await;
    let accepts_unsolicited = unsolicited_connection_from(
        &harness,
        &other_org,
        "globex-okta",
        "https://idp.example/entity",
    )
    .await;
    pin_certificate_for(&harness, &accepts_unsolicited, &key).await;
    let other_cookie = open_session_in(&harness, "sso", "tok-t3b", &other_org).await;
    let (status, full) =
        test_connection(&harness, &other_cookie, &accepts_unsolicited, &right).await;
    assert_eq!(status, 200, "the diagnosis page: {full}");
    // THE `Ok` BRANCH, which nothing reached before: every earlier fixture stopped at the
    // correlation, so the strongest sentence on the page was unmeasured.
    assert!(
        full.contains("passes every check this deployment makes on the document itself"),
        "a response that reaches the end of `examine` must be reported as doing so: {full}"
    );
    assert!(
        !full.contains("does not vouch for what comes after"),
        "and it must not carry the narrower page's caveat: {full}"
    );
    // THE CORRELATION SENTENCE IS READ FROM THE COLUMN. This connection really does accept
    // unsolicited responses, and the page says so BECAUSE the column says so rather than because
    // reaching this branch implies it -- which it does not; see the sibling test below.
    assert!(
        full.contains("accepts a response it did not ask for"),
        "the page must report the connection's own setting: {full}"
    );
    // AND THE STATE HALF IS EXCLUDED ON BOTH BRANCHES. `examine` is stateless: a real sign-in
    // also has to spend an outstanding request, which a pasted document cannot.
    assert!(
        full.contains("NOT checked here"),
        "the page must not imply a real sign-in would succeed: {full}"
    );
}

#[tokio::test]
async fn an_unsigned_assertion_is_not_blamed_on_the_certificate() {
    // The third shape of "right for the wrong reason". `AcsError::Signature` wraps five distinct
    // `VerifyError` variants, and an earlier version of `diagnose` printed the same
    // certificate-rotation sentence for all five -- so an identity provider with assertion
    // signing switched OFF, which is one of the two commonest real misconfigurations here, sent
    // its administrator to rotate and re-pin a certificate that was perfectly correct.
    //
    // A CERTIFICATE IS PINNED, deliberately: without one the answer is `NoTrustAnchor` and this
    // would be measuring the unpinned test again.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &connection, &key).await;
    let cookie = open_session_in(&harness, "sso", "tok-t6", &org).await;

    // AN UNSIGNED DOCUMENT, and the comment that used to sit here claimed it differed from the
    // signed fixtures in one field. It does not: `signed_response_with` builds a subject, a
    // conditions block and an attribute statement that this one has none of. What the fixture
    // establishes is narrower and is all this test needs -- a document with NO signature over
    // its assertion, against a connection that HAS a certificate pinned, so the answer is a
    // signature verdict rather than `NoTrustAnchor`.
    let unsigned = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\" Version=\"2.0\" \
         IssueInstant=\"1970-01-01T00:00:00Z\">\
         <saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Assertion ID=\"_a1\" Version=\"2.0\" IssueInstant=\"1970-01-01T00:00:00Z\">\
         <saml:Issuer>https://idp.example/entity</saml:Issuer></saml:Assertion></samlp:Response>";
    let (status, body) =
        test_connection(&harness, &cookie, &connection, &base64_of(unsigned)).await;

    assert_eq!(status, 200, "the diagnosis page: {body}");
    assert!(
        body.contains("could not find exactly one signature"),
        "the page has to name what it observed: {body}"
    );
    // AND IT MUST NOT NAME A CAUSE IT CANNOT SEE. `SignatureMissing` has seven producers, so
    // "assertion signing is off" -- what this arm said before -- is one of them presented as the
    // diagnosis. A provider signing BOTH elements reaches the same variant.
    assert!(
        body.contains("not a certificate problem"),
        "and say what it is not, since that is where the wrong remedy lives: {body}"
    );
    assert!(
        !body.contains("rotated at your identity provider"),
        "and must not send an operator to re-pin a certificate that is correct: {body}"
    );
}

#[tokio::test]
async fn a_line_wrapped_response_is_read_the_way_the_acs_reads_it() {
    // WHAT AN IDENTITY PROVIDER ACTUALLY EMITS. The `SAMLResponse` field is wrapped, and the
    // first version of this route called `.trim()` and decoded -- so the normal shape came back
    // as "that does not look like a SAMLResponse" from the one page whose job is telling an
    // operator what a real sign-in would do, while the ACS beside it accepted the same bytes.
    //
    // THE TEST IS THE SAME DOCUMENT TWICE, wrapped and not, and the two answers must agree.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &connection, &key).await;
    let cookie = open_session_in(&harness, "sso", "tok-t7", &org).await;

    let packed = base64_of(&response_with_audience(
        &key,
        "https://ironauth.example/saml/metadata",
    ));
    let wrapped = packed
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n");
    assert!(wrapped.contains("\r\n"), "the fixture must actually wrap");

    let (status, from_wrapped) = test_connection(&harness, &cookie, &connection, &wrapped).await;
    assert_eq!(status, 200, "the diagnosis page: {from_wrapped}");
    let (_, from_packed) = test_connection(&harness, &cookie, &connection, &packed).await;
    assert_eq!(
        from_wrapped, from_packed,
        "wrapping the field changed the answer"
    );
    assert!(
        !from_wrapped.contains("does not look like a SAMLResponse"),
        "the shape every identity provider emits was refused: {from_wrapped}"
    );
}

#[tokio::test]
async fn a_switched_off_connection_is_diagnosed_and_told_it_is_switched_off() {
    // THE ADMIN THE FORM IS RENDERED FOR. The test form appears on every connection whether or
    // not sign-in through it is switched on, because the admin whose connection is off is
    // exactly the one still setting it up. The first version of the handler resolved with
    // `find_active`, so that admin posted the form and got "no active connection with that id"
    // -- the SAME sentence the organization fence returns, which reads as "that connection is
    // not yours" and says nothing about the one fact that would have helped.
    //
    // BOTH HALVES ARE ASSERTED: the document is still examined, so they can get their audience
    // and their certificate right before their vendor throws the switch, AND the page says
    // plainly that nobody can sign in yet, so a clean verdict is not read as "you are finished".
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &connection, &key).await;
    let env = Env::system();
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .saml_connections()
        .set_active(&env, &connection, false, None)
        .await
        .expect("switch the connection off");
    let cookie = open_session_in(&harness, "sso", "tok-t8", &org).await;

    let wrong = response_with_audience(&key, "https://someone-elses-app.example/saml");
    let (status, body) = test_connection(&harness, &cookie, &connection, &base64_of(&wrong)).await;

    assert_eq!(
        status, 200,
        "a connection being off is not a bad request: {body}"
    );
    assert!(
        body.contains("switched off"),
        "the page must say sign-in is not on yet: {body}"
    );
    assert!(
        body.contains("wrong audience"),
        "and it must still diagnose the document, which is why they are here: {body}"
    );
    assert!(
        !body.contains("no connection with that id"),
        "the refusal that reads as 'not yours' must not be what they get: {body}"
    );
}

#[tokio::test]
async fn a_wrong_reply_url_names_both_addresses() {
    // A THIRD ARM THAT WAS REACHING THE CATCH-ALL. Splitting `diagnose` made the compiler name
    // four `ConditionError` variants the old `other =>` arm was swallowing, and this is the one
    // an operator hits most: `Recipient` is the reply URL they pasted into their provider, and
    // the catch-all told them "nothing in this connection's configuration explains it" about a
    // value this very page prints two paragraphs higher.
    //
    // ONE FIELD VARIES from the passing fixture: the `Recipient` in the subject confirmation.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &connection, &key).await;
    let cookie = open_session_in(&harness, "sso", "tok-t9", &org).await;

    let misdirected = response_with_recipient(&key, "https://someone-elses-app.example/acs");
    let (status, body) =
        test_connection(&harness, &cookie, &connection, &base64_of(&misdirected)).await;

    assert_eq!(status, 200, "the diagnosis page: {body}");
    assert!(
        body.contains("wrong address"),
        "the diagnosis has to name the failure: {body}"
    );
    assert!(
        body.contains("https://someone-elses-app.example/acs"),
        "it has to say where the provider is sending it: {body}"
    );
    assert!(
        body.contains("https://ironauth.example/saml/acs"),
        "and where it should be sending it, which is the value they go and paste: {body}"
    );
    assert!(
        !body.contains("Send this page to your vendor"),
        "this is the customer's own to fix and must not be routed to support: {body}"
    );
}

/// A signed response that ANSWERS a request, so it carries an `InResponseTo`.
///
/// ONE THING VARIES from [`response_with_audience`]'s passing form: the
/// `SubjectConfirmationData` gains that attribute. Everything else -- issuer, audience,
/// recipient, window, name ID, attribute statement -- is byte for byte the same.
fn response_answering(key: &XmlTestKey, in_response_to: &str) -> String {
    let children = format!(
        "<saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Subject><saml:NameID \
         Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
         ada@globex.example</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData InResponseTo=\"{in_response_to}\" \
         Recipient=\"https://ironauth.example/saml/acs\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"1969-12-31T23:58:00Z\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\">\
         <saml:AudienceRestriction>\
         <saml:Audience>https://ironauth.example/saml/metadata</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement><saml:Attribute Name=\"email\">\
         <saml:AttributeValue>ada@globex.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>"
    );
    ironauth_saml::test_util::signed_response_with(key, "_a1", &children)
}

#[tokio::test]
async fn a_captured_response_reaches_the_end_without_being_told_the_connection_is_unsolicited() {
    // THE BRANCH NOTHING REACHED, and the false sentence it used to print.
    //
    // `examine` refuses an unsolicited response only when the document carries NO
    // `InResponseTo`. A response captured from a real sign-in -- the commonest thing an operator
    // has to paste, because it is what their own browser posted -- carries one, so it sails past
    // that guard on a connection whose `allow_unsolicited` is FALSE. The page then printed "this
    // connection accepts a response it did not ask for", which is the opposite of this
    // connection's setting, and "reaches the end of the same path a real sign-in takes", which
    // is the half `examine` does not reach at all.
    //
    // THE FIXTURE IS THE DEFAULT CONNECTION, deliberately: `allow_unsolicited` is false, as
    // migration 0196 defaults it and as every real deployment leaves it.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &connection, &key).await;
    let cookie = open_session_in(&harness, "sso", "tok-t10", &org).await;

    let answering = response_answering(&key, "_req-that-was-issued");
    let (status, body) =
        test_connection(&harness, &cookie, &connection, &base64_of(&answering)).await;

    assert_eq!(status, 200, "the diagnosis page: {body}");
    assert!(
        body.contains("passes every check this deployment makes on the document itself"),
        "a document that reaches the end of `examine` is reported as doing so: {body}"
    );
    // THE SENTENCE THAT WAS FALSE.
    assert!(
        !body.contains("accepts a response it did not ask for"),
        "a connection that accepts ONLY solicited responses was told it accepts any: {body}"
    );
    assert!(
        body.contains("accepts only responses to its own requests"),
        "the page has to report this connection's actual setting: {body}"
    );
    // AND THE SECOND FALSE SENTENCE: a real sign-in with these bytes would additionally have to
    // spend an outstanding request, and this document names one that is long gone.
    assert!(
        body.contains("NOT checked here"),
        "the page must not imply a real sign-in would succeed: {body}"
    );
}

/// Post a pasted provisioning token to the token check and return the page.
async fn check_token(
    harness: &Harness,
    cookie: &str,
    connection: &ironauth_store::ScimConnectionId,
    token: &str,
) -> (axum::http::StatusCode, String) {
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim/test",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "connection_id={}&token={}",
        urlencoding(&connection.to_string()),
        urlencoding(token),
    );
    post_form_from_with_cookie(harness, &path, &form, "same-origin", cookie).await
}

/// The token a real mint would hand the customer for this connection: `{scim_id}.{secret}`.
///
/// THE ID HALF IS NOT DECORATION. `ironauth-scim`'s `authenticate` reads the scope out of it
/// before any query runs, and the portal check compares it to the connection the form names
/// before any read at all. A fixture that invented an unshaped token would exercise neither.
fn token_for(connection: &ironauth_store::ScimConnectionId, secret: &str) -> String {
    format!("{connection}.{secret}")
}

#[tokio::test]
async fn the_current_token_is_reported_as_working_and_as_unused() {
    // #140 criterion 6's third named failure, the bad token, and the state that makes it worth
    // having: a token that authenticates and that nothing has ever presented.
    //
    // THE ACTIVITY LINE IS THE POINT. "This token authenticates" on its own reads as
    // "provisioning is fine", and during a rotation that reading is what ends when the overlap
    // does. The connection was created by this binary, so an absent stamp genuinely means
    // nothing has used it -- see `observed_since`.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let id = ironauth_store::ScimConnectionId::generate(&Env::system(), &harness.scope());
    let token = token_for(&id, "s3cr3t");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &token, None).await;
    let cookie = open_session_in(&harness, "scim", "tok-s1", &org).await;

    let (status, body) = check_token(&harness, &cookie, &connection, &token).await;

    assert_eq!(status, 200, "the check page: {body}");
    assert!(
        body.contains("authenticates against this connection"),
        "a working token has to be reported as working: {body}"
    );
    assert!(
        body.contains("No request has ever arrived"),
        "and a working token nobody has used is the finding, not a detail: {body}"
    );
    // THE PASTED SECRET IS A LIVE CREDENTIAL. A page that quoted it back would put it in a
    // browser history, a screenshot, and every proxy in between.
    assert!(
        !body.contains("s3cr3t"),
        "the pasted token was echoed into the page: {body}"
    );
}

#[tokio::test]
async fn a_missing_bound_names_which_bound_is_missing() {
    // THE VARIANT CARRIES THE ATTRIBUTE and the arm used to throw it away, printing one sentence
    // for four producers. Here `Conditions/@NotBefore` is absent while `NotOnOrAfter` is
    // present, and the sentence that got discarded sent the operator to switch on a condition
    // their document already had.
    //
    // ONE ATTRIBUTE VARIES from the passing fixture.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &connection, &key).await;
    let cookie = open_session_in(&harness, "sso", "tok-t11", &org).await;

    let children = "<saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Subject><saml:NameID \
         Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
         ada@globex.example</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"https://ironauth.example/saml/acs\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotOnOrAfter=\"1970-01-01T00:02:00Z\">\
         <saml:AudienceRestriction>\
         <saml:Audience>https://ironauth.example/saml/metadata</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>";
    let missing = ironauth_saml::test_util::signed_response_with(&key, "_a1", children);
    let (status, body) =
        test_connection(&harness, &cookie, &connection, &base64_of(&missing)).await;

    assert_eq!(status, 200, "the diagnosis page: {body}");
    assert!(
        body.contains("Conditions/@NotBefore"),
        "the page has to name the bound that is actually absent: {body}"
    );
    // THE SENTENCE THAT WAS WRONG: `NotOnOrAfter` IS in this document.
    assert!(
        !body.contains("switch on the assertion lifetime"),
        "it must not send an operator to enable something already there: {body}"
    );
}

#[tokio::test]
async fn the_previous_token_is_named_as_the_previous_one() {
    // THE ROTATION'S OWN FAILURE MODE, and the one the status column beside this cannot see. An
    // admin who has not finished their cutover is presenting the old token, which still works --
    // so every other signal on the page says healthy right up to the end of the overlap.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let old = token_for(&id, "old-one");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &old, None).await;
    let new = token_for(&id, "new-one");
    let now = now_micros(&harness);
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .rotate_token(&env, &connection, &hex_digest(&new), 3600, now)
        .await
        .expect("rotate")
        .expect("the connection exists");
    let cookie = open_session_in(&harness, "scim", "tok-s2", &org).await;

    let (status, body) = check_token(&harness, &cookie, &connection, &old).await;
    assert_eq!(status, 200, "the check page: {body}");
    assert!(
        body.contains("PREVIOUS token"),
        "the superseded token has to be named as superseded: {body}"
    );
    assert!(
        body.contains("still works"),
        "and it does still work, which is what an overlap is for: {body}"
    );

    // THE CONTROL: the token that replaced it is reported as the live one, so the sentence above
    // is about WHICH token and not about this connection being in a rotated state.
    let (_, fresh) = check_token(&harness, &cookie, &connection, &new).await;
    assert!(
        fresh.contains("authenticates against this connection"),
        "the new token is the live one: {fresh}"
    );
    assert!(
        !fresh.contains("PREVIOUS token"),
        "and must not be reported as the old one: {fresh}"
    );
}

#[tokio::test]
async fn a_lapsed_token_says_when_it_stopped_rather_than_that_it_is_unknown() {
    // AFTER THE OVERLAP the old token is refused by `authenticate` and the customer's
    // provisioning has stopped. "This is not a token of this connection" would be true of a
    // truncated paste and is the wrong instruction here: what they need is the date, because it
    // tells them the cutover they started is the thing that is finished.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let old = token_for(&id, "old-one");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &old, None).await;
    let new = token_for(&id, "new-one");
    let now = now_micros(&harness);
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        // A WINDOW THAT HAS ALREADY CLOSED, which the harness clock makes expressible: the
        // overlap is one second and the page is read after it.
        .rotate_token(&env, &connection, &hex_digest(&new), 0, now - 2_000_000)
        .await
        .expect("rotate")
        .expect("the connection exists");
    let cookie = open_session_in(&harness, "scim", "tok-s3", &org).await;

    let (status, body) = check_token(&harness, &cookie, &connection, &old).await;
    assert_eq!(status, 200, "the check page: {body}");
    assert!(
        body.contains("stopped working on"),
        "a lapsed token has to say when it lapsed: {body}"
    );
    assert!(
        !body.contains("not a token of this connection"),
        "and must not be confused with a value that was never one: {body}"
    );
}

#[tokio::test]
async fn a_token_of_another_connection_is_refused_without_a_lookup() {
    // THE CROSS-CONNECTION FENCE, which is a string comparison rather than a query: the token
    // names its own connection in its id half, so a value minted for a neighbour is refused here
    // BEFORE anything is read. That is what stops this surface confirming that a given
    // connection id exists somewhere else in the deployment.
    //
    // BOTH CONNECTIONS ARE THIS ORGANIZATION'S, so what is measured is the token-to-connection
    // binding and not the organization fence, which has its own test below.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let mine = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let other = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let my_token = token_for(&mine, "s3cr3t");
    let other_token = token_for(&other, "s3cr3t");
    let mine = connect_with_id(
        &harness,
        &org,
        "Okta Production",
        "okta",
        &mine,
        &my_token,
        None,
    )
    .await;
    let _other = connect_with_id(
        &harness,
        &org,
        "Entra Staging",
        "entra",
        &other,
        &other_token,
        None,
    )
    .await;
    let cookie = open_session_in(&harness, "scim", "tok-s4", &org).await;

    // THE CONTROL FIRST: this connection recognises its own token, so the refusal below is the
    // binding rather than a page that refuses everything.
    let (_, own) = check_token(&harness, &cookie, &mine, &my_token).await;
    assert!(
        own.contains("authenticates against this connection"),
        "the control: {own}"
    );

    let (status, body) = check_token(&harness, &cookie, &mine, &other_token).await;
    assert_eq!(status, 200, "the check page: {body}");
    assert!(
        body.contains("belongs to a different connection"),
        "a token minted for another connection has to be named as one: {body}"
    );
    assert!(
        !body.contains("authenticates"),
        "and must not be reported as working here: {body}"
    );
}

#[tokio::test]
async fn a_truncated_token_is_not_confused_with_a_revoked_one() {
    // THE COMMONEST PASTE ERROR, and the one the page has to keep separate from every lifecycle
    // answer: a value that was never a token of this connection is fixed by copying again, and a
    // revoked one is fixed by going to get the current one.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let token = token_for(&id, "s3cr3tttt");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &token, None).await;
    let cookie = open_session_in(&harness, "scim", "tok-s5", &org).await;

    // THE RIGHT CONNECTION, THE WRONG SECRET: the id half still names this connection, so this
    // reaches the store read rather than the string comparison in front of it.
    let truncated = token_for(&id, "s3cr3t");
    let (status, body) = check_token(&harness, &cookie, &connection, &truncated).await;
    assert_eq!(status, 200, "the check page: {body}");
    assert!(
        body.contains("not a token of this connection"),
        "an unrecognised value has to be named as one: {body}"
    );
    assert!(
        body.contains("truncated"),
        "and the commonest cause is worth naming: {body}"
    );
}

#[tokio::test]
async fn a_revoked_connection_outranks_anything_about_the_token() {
    // ORDER, WHICH IS THE ORDER THE REMEDIES COME IN. A revoked connection authenticates nothing
    // whatever token is presented, so reporting the token as fine would send the reader back to
    // their identity provider to look for a fault that is not there.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let token = token_for(&id, "s3cr3t");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &token, None).await;
    let cookie = open_session_in(&harness, "scim", "tok-s6", &org).await;

    // THE CONTROL FIRST, on the same token: before the revocation it reads as working, so the
    // sentence below is the revocation and not the token.
    let (_, before) = check_token(&harness, &cookie, &connection, &token).await;
    assert!(
        before.contains("authenticates against this connection"),
        "the control: {before}"
    );

    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .revoke(&env, &connection, now_micros(&harness))
        .await
        .expect("revoke the connection");

    let (status, body) = check_token(&harness, &cookie, &connection, &token).await;
    assert_eq!(status, 200, "the check page: {body}");
    assert!(
        body.contains("has been revoked"),
        "the connection's own state has to be reported first: {body}"
    );
    assert!(
        !body.contains("authenticates against this connection"),
        "and a token of a revoked connection must not read as working: {body}"
    );
}

#[tokio::test]
async fn one_organizations_session_cannot_check_a_token_against_anothers_connection() {
    // #140 criterion 3 on this route. Without the organization predicate a link issued for one
    // customer would confirm the existence of a neighbour's connection, and -- with a token they
    // happened to hold -- its lifecycle dates as well.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let mine = seed_org(&harness, "Acme").await;
    let theirs = seed_org(&harness, "Globex").await;
    let env = Env::system();
    let my_id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let their_id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let my_token = token_for(&my_id, "mine");
    let their_token = token_for(&their_id, "theirs");
    let my_connection = connect_with_id(
        &harness,
        &mine,
        "Okta Production",
        "okta",
        &my_id,
        &my_token,
        None,
    )
    .await;
    let their_connection = connect_with_id(
        &harness,
        &theirs,
        "Entra Staging",
        "entra",
        &their_id,
        &their_token,
        None,
    )
    .await;
    let cookie = open_session_in(&harness, "scim", "tok-s7", &mine).await;

    // THE CONTROL: this session checks its OWN connection, so the refusal below is the fence.
    let (status, own) = check_token(&harness, &cookie, &my_connection, &my_token).await;
    assert_eq!(status, 200, "the session's own connection: {own}");

    let (status, body) = check_token(&harness, &cookie, &their_connection, &their_token).await;
    assert_eq!(
        status, 400,
        "one customer's portal checked a token against ANOTHER customer's connection: {body}"
    );
    assert!(
        !body.contains("Entra Staging"),
        "and it must not name them either: {body}"
    );
}

#[tokio::test]
async fn a_cross_site_token_check_is_refused() {
    // The CSRF guard every portal POST takes. A cross-origin post here would let another site
    // test tokens it holds against this customer's connection and read the answer.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let token = token_for(&id, "s3cr3t");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &token, None).await;
    let cookie = open_session_in(&harness, "scim", "tok-s8", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim/test",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "connection_id={}&token={}",
        urlencoding(&connection.to_string()),
        urlencoding(&token),
    );
    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "cross-site", &cookie).await;
    assert_eq!(status, 403, "a cross-site token check was served: {body}");
}

#[tokio::test]
async fn an_sso_session_cannot_reach_the_token_check() {
    // THE INTENT FENCE, which every portal surface keeps and which a new POST is exactly the
    // place to forget. A link minted for `sso` reaches a connection's trust material; it has no
    // business reading provisioning credentials' lifecycle.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let token = token_for(&id, "s3cr3t");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &token, None).await;

    // THE CONTROL: a `scim` session checks the same token on the same connection and is served.
    let scim_cookie = open_session_in(&harness, "scim", "tok-s9", &org).await;
    let (status, served) = check_token(&harness, &scim_cookie, &connection, &token).await;
    assert_eq!(status, 200, "the control: {served}");

    let sso_cookie = open_session_in(&harness, "sso", "tok-s10", &org).await;
    let (status, body) = check_token(&harness, &sso_cookie, &connection, &token).await;
    assert_eq!(
        status, 404,
        "an sso session reached the token check: {body}"
    );
}

#[tokio::test]
async fn a_first_token_bounded_by_its_connection_is_not_called_the_previous_one() {
    // ROUND 3's HIGH FINDING. `create` copies the CONNECTION's expiry onto the very first token
    // row, so a horizon on a token row is not evidence of a rotation -- and the arm that assumed
    // it was told the holder of a connection's ONLY token that it was "the PREVIOUS token" and
    // to go and copy a current one that does not exist. `rotate_token` refuses a lapsed
    // connection, so the remedy they would then ask for is one this product answers with a
    // not-found.
    //
    // THE STATUS COLUMN ON THE SAME PAGE said the opposite about the same date, which is how a
    // page comes to give two contradictory instructions.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let token = token_for(&id, "s3cr3t");
    // A FUTURE EXPIRY, which is the only kind the management API will store, so this is the
    // reachable state rather than a contrived one.
    let expires = now_micros(&harness) + 30 * 24 * 60 * 60 * 1_000_000;
    let connection = connect_with_id(
        &harness,
        &org,
        "Okta Production",
        "okta",
        &id,
        &token,
        Some(expires),
    )
    .await;
    let cookie = open_session_in(&harness, "scim", "tok-s11", &org).await;

    let (status, body) = check_token(&harness, &cookie, &connection, &token).await;
    assert_eq!(status, 200, "the check page: {body}");
    assert!(
        !body.contains("PREVIOUS token"),
        "a connection's only token was called the previous one: {body}"
    );
    assert!(
        !body.contains("Copy the current token"),
        "and its holder was sent to copy a token that does not exist: {body}"
    );
    assert!(
        body.contains("Nothing has replaced it"),
        "the page has to say the date is the connection's own: {body}"
    );
    assert!(
        body.contains("replace this connection"),
        "and name the remedy that exists, which is the one the status column names: {body}"
    );

    // THE CONTROL, on the same connection: rotate, and the OLD token is now genuinely the
    // previous one. One fact changes -- a newer token exists -- and the sentence changes with
    // it, which is what makes the assertion above about supersession rather than about expiry.
    let new = token_for(&id, "new-one");
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .rotate_token(
            &env,
            &connection,
            &hex_digest(&new),
            3600,
            now_micros(&harness),
        )
        .await
        .expect("rotate")
        .expect("the connection exists");

    let (_, after) = check_token(&harness, &cookie, &connection, &token).await;
    assert!(
        after.contains("PREVIOUS token"),
        "once something HAS replaced it, that is what it is: {after}"
    );
}

#[tokio::test]
async fn the_token_check_is_absent_where_nothing_can_authenticate() {
    // A DEPLOYMENT THAT DOES NOT SERVE `/scim/v2` answers every provisioning request with a
    // uniform 404, so no token authenticates anything however healthy its row is. The check
    // would have said "this token authenticates against this connection" -- a sentence about a
    // credential table, true of the row and false of everything the reader came to find out.
    // They would go away satisfied and nothing would ever call.
    //
    // BOTH HALVES: the form is not offered, AND the route refuses, because a form not being
    // rendered is not a fence.
    let harness = Harness::start_store_backed_with_scim_surface(false).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let token = token_for(&id, "s3cr3t");
    let connection =
        connect_with_id(&harness, &org, "Okta Production", "okta", &id, &token, None).await;
    let cookie = open_session_in(&harness, "scim", "tok-s12", &org).await;

    let scope = harness.scope();
    let surface = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, _, page) = harness.get_with_cookie(&surface, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {page}");
    assert!(
        !page.contains("Check a token"),
        "a check that cannot mean anything was offered: {page}"
    );

    let (status, body) = check_token(&harness, &cookie, &connection, &token).await;
    assert_eq!(
        status, 404,
        "the route answered on a deployment serving no SCIM: {body}"
    );

    // THE CONTROL: the same fixture with the surface on serves both.
    let live = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&live, "Acme").await;
    let id = ironauth_store::ScimConnectionId::generate(&env, &live.scope());
    let token = token_for(&id, "s3cr3t");
    let connection =
        connect_with_id(&live, &org, "Okta Production", "okta", &id, &token, None).await;
    let cookie = open_session_in(&live, "scim", "tok-s13", &org).await;
    let scope = live.scope();
    let surface = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (_, _, page) = live.get_with_cookie(&surface, Some(&cookie)).await;
    assert!(page.contains("Check a token"), "the control: {page}");
    let (status, body) = check_token(&live, &cookie, &connection, &token).await;
    assert_eq!(status, 200, "the control: {body}");
}
// ---------------------------------------------------------------------------------------------
// THE WIDGET SURFACE (issue #145 criterion 6), and the host app that renders it.
// ---------------------------------------------------------------------------------------------

/// A SAML connection bound through `org_connections`, which is a binding that names NO
/// connector.
///
/// THE POPULATION THAT CROWDED THE OTHER ONE OUT. `list_for_organization` returns every binding
/// of either kind, and the widget drops the ones with no connector -- so these are what a bound
/// applied before the filter spends itself on.
async fn saml_binding_for(harness: &Harness, organization: &OrganizationId, index: usize) {
    // A DISTINCT `created_at` PER ROW. Every binding fixture here used the same literal, so
    // `ORDER BY created_at, id` fell entirely to `id` -- which is random -- and any test whose
    // result depended on which rows a `LIMIT` returned was a coin flip. The index makes the
    // order total and the test deterministic.
    let env = Env::system();
    let scope = harness.scope();
    let connection = saml_connection_from(
        harness,
        organization,
        &format!("bound-saml-{index}"),
        &format!("https://idp-{index}.example/entity"),
    )
    .await;
    harness
        .db()
        .control_store()
        .scoped(scope)
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .org_connections()
        .create(
            &env,
            &ironauth_store::OrgConnectionId::generate(&env, &scope),
            1_000_000 + i64::try_from(index).unwrap_or(0),
            ironauth_store::NewOrgConnection {
                organization_id: organization,
                upstream: ironauth_store::OrgConnectionUpstream::Saml(&connection),
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled: true,
            },
        )
        .await
        .expect("bind the SAML connection to the organization");
}

/// As [`upstream_with_protocol`], choosing whether the BINDING is switched on.
///
/// ONE FIELD APART, which is what lets the pair below attribute a rendering difference to the
/// switch rather than to anything else about the upstream.
async fn upstream_enabled(
    harness: &Harness,
    organization: &OrganizationId,
    slug: &str,
    enabled: bool,
) {
    let env = Env::system();
    let scope = harness.scope();
    let control = harness.db().control_store();
    let actor = || ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env));
    let connector_id = ironauth_store::ConnectorId::generate(&env, &scope);
    let definition = format!(
        r#"{{"connector_id":"{slug}","display_name":"Upstream","protocol":"oidc","endpoints":{{"issuer":"https://upstream.example"}},"scopes":["openid","email"],"client_id":"upstream-client"}}"#
    );
    control
        .scoped(scope)
        .acting(actor(), CorrelationId::generate(&env))
        .connectors()
        .create(
            &env,
            &connector_id,
            1_000_000,
            ironauth_store::NewConnector {
                slug,
                definition_json: &definition,
                client_secret: b"upstream-secret",
                capabilities: ironauth_store::ConnectorCapabilities {
                    refresh: false,
                    groups: false,
                    logout_propagation: false,
                    email_verified_trust: "untrusted",
                },
                enabled: true,
            },
            None,
        )
        .await
        .expect("create the connector");
    control
        .scoped(scope)
        .acting(actor(), CorrelationId::generate(&env))
        .org_connections()
        .create(
            &env,
            &ironauth_store::OrgConnectionId::generate(&env, &scope),
            1_000_000,
            ironauth_store::NewOrgConnection {
                organization_id: organization,
                upstream: ironauth_store::OrgConnectionUpstream::Connector(&connector_id),
                overlay_min_acr: None,
                max_age_secs: None,
                overlay_min_class: None,
                capture_upstream_tokens: false,
                enabled,
            },
        )
        .await
        .expect("bind the connector to the organization");
}

/// The vendor's backend, doing what a vendor's backend does to get a widget token.
///
/// It mints a portal link through the control plane and REDEEMS IT ITSELF, reading the session
/// value out of the `Set-Cookie` rather than handing the link to a browser. That is the whole
/// mechanism, and it is why the widget surface needs no second minting path: the TTL, the
/// single-use rule and the intent all still come from the link.
async fn widget_token(
    harness: &Harness,
    intent: &str,
    token: &str,
    organization: &OrganizationId,
) -> String {
    let cookie = open_session_in(harness, intent, token, organization).await;
    cookie
        .split_once('=')
        .expect("the cookie carries a value")
        .1
        .to_owned()
}

/// `GET` a widget with a bearer, the way the host's own code does.
async fn widget_get(
    harness: &Harness,
    surface: &str,
    bearer: Option<&str>,
) -> (axum::http::StatusCode, axum::http::HeaderMap, String) {
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/w/{surface}",
        scope.tenant(),
        scope.environment()
    );
    let mut builder = axum::http::Request::builder().method("GET").uri(&path);
    if let Some(bearer) = bearer {
        builder = builder.header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {bearer}"),
        );
    }
    harness
        .send(
            builder
                .body(axum::body::Body::empty())
                .expect("request builds"),
        )
        .await
}

/// THE HOST APP. A vendor's page, rendering the widget payload into its own markup.
///
/// IT IS HERE BECAUSE THE CRITERION IS ABOUT RENDERING. "Widgets render the SSO-status and
/// SCIM-setup flows inside a host-app fixture" is a claim about what a consumer can build out of
/// this surface, and a test that only asserted JSON field names would leave it unmeasured: a
/// payload can carry every field and still not answer the question a status panel asks.
///
/// IT IS DELIBERATELY DUMB. It does no lookup of its own and holds no notion of which customer
/// it is showing; everything on the page comes out of the response, including the organization
/// it labels itself with. That is what makes the cross-organization assertions below meaningful
/// -- if the surface leaked a neighbour's row, this would render it.
fn host_app_render(payload: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    let mut page = String::new();
    page.push_str("<section class=\"ironauth-widget\">");
    let _ = write!(
        page,
        "<h3>Organization {}</h3>",
        payload["organization_id"].as_str().unwrap_or("?")
    );
    // THE ITEMS ARE NOT ALWAYS A LIST. The SSO widget answers two kinds of upstream, so the
    // host flattens whatever shape it is handed -- which is what a real host does, and what
    // makes the OIDC rows below observable at all.
    let rows: Vec<serde_json::Value> = match &payload["items"] {
        serde_json::Value::Array(rows) => rows.clone(),
        serde_json::Value::Object(map) => map
            .values()
            .filter_map(|value| value.as_array())
            .flatten()
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    // THE SETUP FACTS, which a status list cannot express and which criterion 6 names: where the
    // provisioning client connects, and whether this deployment serves that endpoint at all.
    match (
        payload["items"]["surface_served"].as_bool(),
        payload["items"]["base_url"].as_str(),
    ) {
        (Some(true), Some(base)) => {
            let _ = write!(page, "<p class=\"base\">Connect to {base}</p>");
        }
        (Some(false), _) => page.push_str(
            "<p class=\"base\">This deployment does not serve provisioning. Ask your vendor.</p>",
        ),
        _ => {}
    }
    for item in rows {
        page.push_str("<div class=\"row\">");
        let _ = write!(
            page,
            "<span class=\"name\">{}</span>",
            // AN OIDC UPSTREAM HAS NO DISPLAY NAME, only the slug an operator gave the
            // connector, so a host renders whichever the row carries.
            item["display_name"]
                .as_str()
                .or_else(|| item["slug"].as_str())
                .or_else(|| item["connector_id"].as_str())
                .unwrap_or("?")
        );
        // A CONNECTOR-BASED UPSTREAM, which is not necessarily OpenID Connect: the host says
        // what the row says, because "OIDC" printed over an OAuth 2.0 connector sends an admin
        // looking for an issuer URL their provider does not have.
        if let Some(protocol) = item["protocol"].as_str() {
            let _ = write!(page, "<span class=\"protocol\">{protocol}</span>");
        }
        if item["connector_id"].as_str().is_some() {
            page.push_str(match item["enabled"].as_bool() {
                Some(true) => "<span class=\"state\">Sign-in is on</span>",
                Some(false) => "<span class=\"state\">Sign-in is off</span>",
                None => "",
            });
        }
        if let Some(active) = item["active"].as_bool() {
            page.push_str(if active {
                "<span class=\"state\">Sign-in is on</span>"
            } else {
                "<span class=\"state\">Sign-in is off</span>"
            });
            let _ = write!(
                page,
                "<span class=\"certs\">{} certificate(s) pinned</span>",
                item["pinned_certificates"].as_u64().unwrap_or(0)
            );
        }
        if let Some(stopped) = item["provisioning_stopped"].as_bool() {
            page.push_str(if stopped {
                "<span class=\"state\">Provisioning has stopped</span>"
            } else {
                "<span class=\"state\">Provisioning is working</span>"
            });
            // THE FLAG IS READ BESIDE THE VALUE, which is the contract the field carries. A host
            // that rendered an absent stamp as "never used" would say that to every customer of
            // a freshly upgraded deployment.
            page.push_str(
                match (
                    item["last_seen_at_unix_micros"].as_i64(),
                    item["usage_is_knowable"].as_bool(),
                ) {
                    (Some(_), _) => "<span class=\"seen\">Recently used</span>",
                    (None, Some(true)) => "<span class=\"seen\">Never used</span>",
                    (None, _) => "<span class=\"seen\">Usage not recorded</span>",
                },
            );
        }
        page.push_str("</div>");
    }
    page.push_str("</section>");
    page
}

#[tokio::test]
async fn a_host_app_renders_this_organizations_sso_status_and_no_others() {
    // #145 criterion 6. TWO ORGANIZATIONS EXIST and the widget is fetched with ONE's token, so
    // "no cross-org leakage" is measured against a deployment that actually has something to
    // leak. An assertion made in a single-tenant fixture proves nothing: every list is correct
    // when there is only one customer.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let mine = seed_org(&harness, "Acme").await;
    let theirs = seed_org(&harness, "Globex").await;
    let ours =
        saml_connection_from(&harness, &mine, "acme-okta", "https://idp.example/entity").await;
    let _theirs = saml_connection_from(
        &harness,
        &theirs,
        "globex-entra",
        "https://other.example/entity",
    )
    .await;
    let key = XmlTestKey::generate();
    pin_certificate_for(&harness, &ours, &key).await;
    let bearer = widget_token(&harness, "sso", "w-1", &mine).await;

    let (status, headers, body) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(status, 200, "the widget: {body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    let page = host_app_render(&payload);

    assert!(
        page.contains("acme-okta"),
        "the host app has to be able to render this organization's connection: {page}"
    );
    assert!(
        page.contains("1 certificate(s) pinned"),
        "and the one fact a status panel exists for -- whether setup is finished: {page}"
    );
    assert!(
        page.contains("Sign-in is on"),
        "and whether anyone can actually use it: {page}"
    );
    assert!(
        !page.contains("globex-entra"),
        "another customer's connection reached this host app: {page}"
    );
    assert!(
        page.contains(&mine.to_string()),
        "the payload labels itself with the session's organization: {page}"
    );
    // THE HEADERS A CROSS-ORIGIN READER NEEDS, and no credentialed variant of them.
    assert_eq!(
        headers
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok()),
        Some("*"),
        "a widget is fetched from the vendor's origin"
    );
    assert!(
        headers
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .is_none(),
        "credentials must never be allowed: the whole design is that none ride along"
    );
}

#[tokio::test]
async fn a_host_app_renders_this_organizations_provisioning_state() {
    // The SCIM half of the criterion, and the state a status panel is for: a connection whose
    // credentials are gone provisions nothing, and that is invisible from every other field.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let mine = seed_org(&harness, "Acme").await;
    let theirs = seed_org(&harness, "Globex").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let token = token_for(&id, "s3cr3t");
    let working = connect_with_id(
        &harness,
        &mine,
        "Okta Production",
        "okta",
        &id,
        &token,
        None,
    )
    .await;
    let _ = working;
    let their_id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let _theirs = connect_with_id(
        &harness,
        &theirs,
        "Globex Entra",
        "entra",
        &their_id,
        &token_for(&their_id, "other"),
        None,
    )
    .await;
    let bearer = widget_token(&harness, "scim", "w-2", &mine).await;

    let (status, _, body) = widget_get(&harness, "scim", Some(&bearer)).await;
    assert_eq!(status, 200, "the widget: {body}");
    let page = host_app_render(&serde_json::from_str(&body).expect("json"));

    assert!(
        page.contains("Okta Production"),
        "this organization's provisioning connection: {page}"
    );
    assert!(
        page.contains("Provisioning is working"),
        "a live connection reads as live: {page}"
    );
    // A CONNECTION CREATED BY THIS BINARY IS WATCHED, so the absent stamp is knowable and the
    // host may say so. The other branch is the installed base, and this is the assertion that
    // keeps the flag load-bearing rather than decorative.
    assert!(
        page.contains("Never used"),
        "a watched connection nobody has called reads as unused: {page}"
    );
    assert!(
        !page.contains("Globex Entra"),
        "another customer's provisioning reached this host app: {page}"
    );
}

#[tokio::test]
async fn a_widget_refuses_the_cookie_that_every_hosted_page_accepts() {
    // THE DESIGN, MEASURED. Every other portal route authenticates with the `__Host-` cookie,
    // which a browser attaches by itself -- and a widget is fetched by code on somebody else's
    // origin, so a route that took the ambient cookie would be spendable by any page the
    // customer happens to have open. The refusal is the control that says the bearer is doing
    // the work.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    let _connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let cookie = open_session_in(&harness, "sso", "w-3", &org).await;
    let bearer = cookie
        .split_once('=')
        .expect("the cookie carries a value")
        .1
        .to_owned();

    // THE CONTROL: the same session, presented as a bearer, is served.
    let (status, _, served) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(status, 200, "the control: {served}");

    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/w/sso",
        scope.tenant(),
        scope.environment()
    );
    let (status, _, body) = harness.get_with_cookie(&path, Some(&cookie)).await;
    assert_eq!(status, 404, "the widget accepted an ambient cookie: {body}");
}

#[tokio::test]
async fn an_sso_token_cannot_read_the_provisioning_widget() {
    // The intent fence, on a surface that is new and therefore exactly where it gets forgotten.
    // A link minted to show an admin their SSO status has no business listing provisioning
    // credentials' health.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let _connection = connect_with_id(
        &harness,
        &org,
        "Okta Production",
        "okta",
        &id,
        &token_for(&id, "s3cr3t"),
        None,
    )
    .await;

    // THE CONTROL: a `scim` token reads the same widget.
    let scim = widget_token(&harness, "scim", "w-4", &org).await;
    let (status, _, served) = widget_get(&harness, "scim", Some(&scim)).await;
    assert_eq!(status, 200, "the control: {served}");

    let sso = widget_token(&harness, "sso", "w-5", &org).await;
    let (status, _, body) = widget_get(&harness, "scim", Some(&sso)).await;
    assert_eq!(
        status, 404,
        "an sso token read the provisioning widget: {body}"
    );
}

#[tokio::test]
async fn the_widgets_are_absent_until_an_operator_enables_them() {
    // EXPLORATORY MEANS OFF. A surface whose JSON shape is expected to move must not appear on a
    // deployment that never asked for it, and the answer has to be the SAME not-found a spent
    // token gets -- otherwise a caller learns which deployments have it switched on.
    let harness = Harness::start_store_backed_with_widgets(false).await;
    let org = seed_org(&harness, "Acme").await;
    let _connection =
        saml_connection_from(&harness, &org, "acme-okta", "https://idp.example/entity").await;
    let bearer = widget_token(&harness, "sso", "w-6", &org).await;

    let (status, _, body) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(
        status, 404,
        "an unflagged deployment served a widget: {body}"
    );

    // THE SAME ANSWER a live deployment gives an invented token, so the pair is uniform -- and
    // the BODY as well as the status, because an earlier version compared only the code and
    // would have passed for a router that never mounted the route at all.
    let live = Harness::start_store_backed_with_widgets(true).await;
    let (live_status, _, live_body) = widget_get(&live, "sso", Some("not-a-token")).await;
    assert_eq!(
        live_status, status,
        "the refusals have to be the same status"
    );
    assert_eq!(
        live_body, body,
        "and the same body, or the pair is an oracle for which deployments serve widgets"
    );
    // AND THE ROUTE IS MOUNTED EITHER WAY, which is what makes the comparison meaningful: an
    // unmounted path would answer the same 404 and prove nothing about the flag.
    let request = axum::http::Request::builder()
        .method("OPTIONS")
        .uri(format!(
            "/t/{}/e/{}/portal/w/sso",
            harness.scope().tenant(),
            harness.scope().environment()
        ))
        .body(axum::body::Body::empty())
        .expect("request builds");
    let (status, _, _) = harness.send(request).await;
    assert_eq!(
        status, 204,
        "the route is mounted on an unflagged deployment; only its GET refuses"
    );
}

#[tokio::test]
async fn a_widget_bound_reports_itself_rather_than_truncating_quietly() {
    // A LIST THAT STOPS WITHOUT SAYING SO renders, in a host app, as a complete list. The host
    // has no way to know otherwise: it holds no count of its own and asks for no page. So the
    // envelope carries the fact.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    for index in 0..21 {
        saml_connection_from(
            &harness,
            &org,
            &format!("connection-{index}"),
            &format!("https://idp-{index}.example/entity"),
        )
        .await;
    }
    let bearer = widget_token(&harness, "sso", "w-7", &org).await;

    let (status, _, body) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(status, 200, "the widget: {body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        payload["items"]["saml"].as_array().map(Vec::len),
        Some(20),
        "the bound is what it says it is"
    );
    assert_eq!(
        payload["truncated"].as_bool(),
        Some(true),
        "and a bounded response has to admit it: {body}"
    );

    // THE NEGATIVE CONTROL, without which a constant `true` -- or an off-by-one bound -- passes
    // everything above. A second organization holding ONE connection must report `false`, so
    // the flag is measuring the list rather than being decoration.
    let small = seed_org(&harness, "Initech").await;
    saml_connection_from(&harness, &small, "just-one", "https://one.example/entity").await;
    let bearer = widget_token(&harness, "sso", "w-7b", &small).await;
    let (_, _, body) = widget_get(&harness, "sso", Some(&bearer)).await;
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        payload["items"]["saml"].as_array().map(Vec::len),
        Some(1),
        "the control organization has one connection: {body}"
    );
    assert_eq!(
        payload["truncated"].as_bool(),
        Some(false),
        "and a response that dropped nothing must not claim it did: {body}"
    );
}

#[tokio::test]
async fn a_browser_preflight_is_answered_so_the_fetch_can_happen_at_all() {
    // THE FINDING THAT MADE THE WHOLE SURFACE UNREACHABLE. `Authorization` is not a
    // CORS-safelisted request header, so a cross-origin `fetch` sends `OPTIONS` first. Both
    // routes were registered with `get(...)` alone, which answers that with 405 and no
    // `Access-Control-Allow-*` headers -- so the browser blocks and the GET is never sent. The
    // module's entire premise is "a widget is fetched by code running on the vendor's origin",
    // and no browser could do it.
    //
    // THE HOST-APP FIXTURE COULD NOT SEE IT, which is why this test exists separately: it drives
    // the router in process, where no preflight happens.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let scope = harness.scope();
    for surface in ["sso", "scim"] {
        let path = format!(
            "/t/{}/e/{}/portal/w/{surface}",
            scope.tenant(),
            scope.environment()
        );
        let request = axum::http::Request::builder()
            .method("OPTIONS")
            .uri(&path)
            .header(axum::http::header::ORIGIN, "https://vendor.example")
            .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .header(
                axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS,
                "authorization",
            )
            .body(axum::body::Body::empty())
            .expect("request builds");
        let (status, headers, body) = harness.send(request).await;
        assert_eq!(status, 204, "the preflight for {surface}: {body}");
        assert_eq!(
            headers
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("*"),
            "the preflight has to authorise the origin the GET answers"
        );
        // THE HEADER THE PREFLIGHT EXISTS FOR. Without it the browser refuses to send
        // `Authorization`, which is the only way this surface authenticates anything.
        let allowed = headers
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            allowed.contains("authorization"),
            "the preflight must allow the bearer header: {allowed}"
        );
        assert!(
            headers
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "credentials must never be allowed, on the preflight either"
        );
    }
}

#[tokio::test]
async fn a_revoked_connection_is_not_rendered_as_working() {
    // `ScimConnection::no_live_credential` answers `!revoked && live_token_count == 0` ON
    // PURPOSE, because the hosted page renders "Revoked" in an arm ABOVE the one that calls it.
    // A widget is one boolean with no arms, and reading that method alone reported a revoked
    // connection as working -- which the host-app fixture rendered word for word.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    let env = Env::system();
    let id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let connection = connect_with_id(
        &harness,
        &org,
        "Okta Production",
        "okta",
        &id,
        &token_for(&id, "s3cr3t"),
        None,
    )
    .await;
    let bearer = widget_token(&harness, "scim", "w-8", &org).await;

    // THE CONTROL FIRST, on the same connection: before the revocation the host renders it as
    // working, so the assertion below is the revocation and not a page that says nothing works.
    let (_, _, before) = widget_get(&harness, "scim", Some(&bearer)).await;
    let page = host_app_render(&serde_json::from_str(&before).expect("json"));
    assert!(
        page.contains("Provisioning is working"),
        "the control: {page}"
    );

    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ironauth_store::ActorRef::service(ironauth_store::ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .scim_connections()
        .revoke(&env, &connection, now_micros(&harness))
        .await
        .expect("revoke the connection");

    let (_, _, after) = widget_get(&harness, "scim", Some(&bearer)).await;
    let page = host_app_render(&serde_json::from_str(&after).expect("json"));
    assert!(
        page.contains("Provisioning has stopped"),
        "a revoked connection must not read as working: {page}"
    );
    assert!(
        !page.contains("Provisioning is working"),
        "and it must not read as working anywhere on the page: {page}"
    );

    // THE OTHER HALF OF THE EXPRESSION. `revoked || no_live_credential()` has two disjuncts and
    // the revocation above exercises one; deleting the other left this test green. A connection
    // whose TOKENS are gone while the connection itself is live is the second broken state, and
    // it is the one `no_live_credential` was written for.
    let other = seed_org(&harness, "Initech").await;
    let lapsed_id = ironauth_store::ScimConnectionId::generate(&env, &harness.scope());
    let lapsed = connect_with_id(
        &harness,
        &other,
        "Initech Okta",
        "okta",
        &lapsed_id,
        &token_for(&lapsed_id, "s3cr3t"),
        // AN EXPIRY ALREADY PASSED, which is what leaves a live connection with no usable
        // credential: `authenticate` refuses on the token's horizon and the row stays unrevoked.
        Some(now_micros(&harness) - 1_000_000),
    )
    .await;
    let _ = lapsed;
    let other_bearer = widget_token(&harness, "scim", "w-8b", &other).await;
    let (_, _, body) = widget_get(&harness, "scim", Some(&other_bearer)).await;
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        payload["items"]["connections"][0]["revoked"].as_bool(),
        Some(false),
        "this one is NOT revoked, which is what makes it the other disjunct: {body}"
    );
    let page = host_app_render(&payload);
    assert!(
        page.contains("Provisioning has stopped"),
        "a live connection with no usable credential has stopped too: {page}"
    );
}

#[tokio::test]
async fn an_organization_whose_sign_on_is_oidc_is_not_reported_as_having_none() {
    // A SAML UPSTREAM IS A ROW; AN OIDC UPSTREAM IS A BINDING naming a connector, and
    // `sso_surface` reads both tables and says so. The widget read one, so an organization
    // configured entirely through OIDC -- an ordinary configuration -- rendered as an EMPTY list
    // with `truncated: false`, which a host app cannot tell from "nothing is configured".
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    upstream_with_protocol(&harness, &org, "acme-entra", "oidc").await;
    let bearer = widget_token(&harness, "sso", "w-9", &org).await;

    let (status, _, body) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(status, 200, "the widget: {body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        payload["items"]["saml"].as_array().map(Vec::len),
        Some(0),
        "this organization has no SAML connection: {body}"
    );
    assert_eq!(
        payload["items"]["connectors"].as_array().map(Vec::len),
        Some(1),
        "and exactly one OIDC upstream, which the widget has to report: {body}"
    );
    let page = host_app_render(&payload);
    assert!(
        page.contains("acme-entra"),
        "the host app has to be able to render it: {page}"
    );
}

#[tokio::test]
async fn an_oauth2_upstream_is_not_published_as_openid_connect() {
    // `OrgConnectionUpstream::Connector` is documented as "a `cnr_` OIDC OR OAUTH 2.0
    // connector", and `sso_oidc_section` branches on the protocol with the reason spelled out:
    // calling an OAuth 2.0 connector OpenID Connect "sends its admin looking for an issuer URL
    // and an `openid` scope their provider does not have". The hosted page carries a regression
    // test forbidding exactly that label; the widget re-introduced it on the JSON surface, under
    // a field name a host could not even contradict because the protocol was not in the payload.
    //
    // ONE STRING VARIES between this and the OIDC test beside it.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    upstream_with_protocol(&harness, &org, "acme-github", "oauth2").await;
    let bearer = widget_token(&harness, "sso", "w-10", &org).await;

    let (status, _, body) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(status, 200, "the widget: {body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    let rows = payload["items"]["connectors"]
        .as_array()
        .expect("the connector upstreams are a list");
    assert_eq!(rows.len(), 1, "the upstream is reported: {body}");
    assert_eq!(
        rows[0]["protocol"].as_str(),
        Some("oauth2"),
        "the row has to carry what its connector actually declares: {body}"
    );
    // AND THE HOST CAN SAY SO, which is the property the payload exists for.
    let page = host_app_render(&payload);
    assert!(
        page.contains("oauth2"),
        "a host app has to be able to name the protocol: {page}"
    );
    assert!(
        !page.contains("OpenID Connect"),
        "and must not be forced into the wrong one: {page}"
    );
}

#[tokio::test]
async fn a_switched_off_upstream_does_not_render_as_a_working_one() {
    // THE ONE FACT A STATUS WIDGET EXISTS FOR. The SAML view has carried `active` all along; the
    // connector view carried nothing, so a binding an operator had switched off rendered exactly
    // like one signing people in.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    // THE CONTROL, in its own organization: an upstream that IS on renders as on, so the
    // assertion below is the switch rather than a host that says "off" about everything.
    upstream_enabled(&harness, &org, "acme-on", true).await;
    let bearer = widget_token(&harness, "sso", "w-11", &org).await;
    let (_, _, before) = widget_get(&harness, "sso", Some(&bearer)).await;
    let page = host_app_render(&serde_json::from_str(&before).expect("json"));
    assert!(page.contains("Sign-in is on"), "the control: {page}");

    let off_org = seed_org(&harness, "Initech").await;
    upstream_enabled(&harness, &off_org, "initech-off", false).await;
    let off_bearer = widget_token(&harness, "sso", "w-11b", &off_org).await;
    let (_, _, after) = widget_get(&harness, "sso", Some(&off_bearer)).await;
    let page = host_app_render(&serde_json::from_str(&after).expect("json"));
    assert!(
        page.contains("Sign-in is off"),
        "a switched-off upstream must not read as working: {page}"
    );
    assert!(
        !page.contains("Sign-in is on"),
        "and must not read as working anywhere on the page: {page}"
    );
}

#[tokio::test]
async fn a_connector_upstream_is_not_crowded_out_by_saml_bindings() {
    // THE BOUND WAS APPLIED BEFORE THE FILTER. `list_for_organization` returns every binding,
    // including the SAML ones, which name no connector and are dropped -- so an organization
    // with twenty SAML bindings and one connector filled the page with rows that were then
    // discarded and answered `connectors: []`, reporting a configured upstream as absent. That
    // is the defect the whole second read was added to fix, reintroduced by the ordering.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    // MORE SAML BINDINGS THAN THE BOUND, and the connector binding created LAST so it is the
    // one an over-early limit discards. Both halves matter: with twenty or fewer the whole set
    // fits inside `LIMIT 21` and any ordering passes, which is why the first version of this
    // test proved nothing and passed against the unfixed code.
    for index in 0..25 {
        saml_binding_for(&harness, &org, index).await;
    }
    upstream_with_protocol(&harness, &org, "acme-entra", "oidc").await;
    let bearer = widget_token(&harness, "sso", "w-12", &org).await;

    let (status, _, body) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(status, 200, "the widget: {body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        payload["items"]["connectors"].as_array().map(Vec::len),
        Some(1),
        "the connector upstream has to survive the SAML bindings in front of it: {body}"
    );
    // AND THE SAML HALF REPORTS ITS OWN TRUNCATION, which is the other thing this fixture has
    // enough rows to express: twenty-five connections, twenty shown.
    assert_eq!(
        payload["truncated"].as_bool(),
        Some(true),
        "twenty-five SAML connections have to report as cut: {body}"
    );
}

#[tokio::test]
async fn the_provisioning_widget_carries_what_a_setup_flow_renders() {
    // CRITERION 6 NAMES A SCIM-SETUP FLOW, not a SCIM-status one. A list of existing connections
    // is a status panel; what a host renders to somebody SETTING provisioning up is where their
    // provisioning client connects -- and whether this deployment serves that endpoint at all.
    //
    // THE URL IS PRINTED ONLY WHERE IT IS SERVED, exactly as the hosted page prints it: an admin
    // sent to configure their provider against an endpoint answering a uniform 404 discovers it
    // days later as "provisioning never started", with this page as the evidence it should have.
    let harness = Harness::start_store_backed_with_widgets(true).await;
    let org = seed_org(&harness, "Acme").await;
    let bearer = widget_token(&harness, "scim", "w-13", &org).await;

    let (status, _, body) = widget_get(&harness, "scim", Some(&bearer)).await;
    assert_eq!(status, 200, "the widget: {body}");
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(payload["items"]["surface_served"].as_bool(), Some(true));
    assert!(
        payload["items"]["base_url"]
            .as_str()
            .is_some_and(|base| base.ends_with("/scim/v2")),
        "a setup flow needs the base URL: {body}"
    );
    let page = host_app_render(&payload);
    assert!(
        page.contains("Connect to"),
        "and a host app has to be able to render it: {page}"
    );

    // THE OTHER DEPLOYMENT, where the endpoint is not served. One fact varies.
    let off = Harness::start_store_backed_with_widgets_and_scim(true, false).await;
    let org = seed_org(&off, "Acme").await;
    let bearer = widget_token(&off, "scim", "w-14", &org).await;
    let (_, _, body) = widget_get(&off, "scim", Some(&bearer)).await;
    let payload: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(payload["items"]["surface_served"].as_bool(), Some(false));
    assert!(
        payload["items"]["base_url"].is_null(),
        "a URL that answers nothing must not be printed: {body}"
    );
    let page = host_app_render(&payload);
    assert!(
        page.contains("does not serve provisioning"),
        "and the host has to be able to say WHICH: {page}"
    );
}

#[tokio::test]
async fn a_widget_refusal_is_readable_from_the_host_origin() {
    // A PREFLIGHT THAT SUCCEEDS AND A REFUSAL A HOST CANNOT READ is worse than neither. Before
    // the preflight nothing reached these routes from a browser at all; with it, the fetch
    // happens, gets its answer, and the answer had no `Access-Control-Allow-Origin` -- so the
    // browser refused to expose it and the host saw an opaque error indistinguishable from the
    // network being down.
    let harness = Harness::start_store_backed_with_widgets(true).await;

    // THE CONTROL: the success path carries the header.
    let org = seed_org(&harness, "Acme").await;
    let bearer = widget_token(&harness, "sso", "w-15", &org).await;
    let (status, ok_headers, _) = widget_get(&harness, "sso", Some(&bearer)).await;
    assert_eq!(status, 200);
    let allowed = |headers: &axum::http::HeaderMap| {
        headers
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(allowed(&ok_headers).as_deref(), Some("*"), "the control");

    // THREE OF THE FOUR STATES `widget_session` REFUSES ON -- an absent bearer, an unknown one,
    // and the wrong intent below. The fourth is a malformed SCOPE in the path, which is driven
    // separately because it needs a different URL rather than a different token.
    for (label, token) in [("no bearer", None), ("an invented bearer", Some("nope"))] {
        let (status, headers, body) = widget_get(&harness, "sso", token).await;
        assert_eq!(status, 404, "{label}: {body}");
        assert_eq!(
            allowed(&headers).as_deref(),
            Some("*"),
            "a host cannot read the refusal for {label}"
        );
    }

    // AND THE WRONG INTENT, which is the refusal a host is likeliest to hit in normal use.
    let scim = widget_token(&harness, "scim", "w-16", &org).await;
    let (status, headers, body) = widget_get(&harness, "sso", Some(&scim)).await;
    assert_eq!(status, 404, "the intent fence: {body}");
    assert_eq!(
        allowed(&headers).as_deref(),
        Some("*"),
        "a host cannot read the intent refusal"
    );

    // AND THE FOURTH: a path whose scope does not parse, which `widget_session` refuses before
    // it looks at the bearer at all. A host app that builds its URL from a stale tenant id sees
    // this one, so it has to be readable too.
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/t/not-a-tenant/e/not-an-environment/portal/w/sso")
        .header(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {bearer}"),
        )
        .body(axum::body::Body::empty())
        .expect("request builds");
    let (status, headers, body) = harness.send(request).await;
    assert_eq!(status, 404, "a malformed scope: {body}");
    assert_eq!(
        allowed(&headers).as_deref(),
        Some("*"),
        "a host cannot read the malformed-scope refusal"
    );
}

// ---------------------------------------------------------------------------------------------
// THE CREATE PATH (issue #140 criterion 1), and the journey it completes.
// ---------------------------------------------------------------------------------------------

/// Drain the SAML setup queue through the CONTROL-plane consumer, as the worker does.
///
/// The portal cannot create a connection -- 0196 grants that INSERT to `ironauth_control` alone
/// -- so it enqueues and this applies. A test stopping at the 303 would be measuring that a row
/// reached a queue, which is not what the customer asked for.
async fn apply_saml_setups(harness: &Harness) -> usize {
    use ironauth_store::outbox::OutboxConsumer as _;

    let scope = harness.scope();
    let env = Env::system();
    let consumer = ironauth_admin::saml_connection_setup::SamlConnectionSetupConsumer::new(
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
                ironauth_store::SAML_CONNECTION_SETUP_CONSUMER,
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
                .expect("the setup applies");
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

/// Submit the SAML setup form the way the page renders it.
async fn submit_saml_setup(
    harness: &Harness,
    cookie: &str,
    display_name: &str,
    idp_entity_id: &str,
    idp_sso_url: &str,
    certificate: &str,
) -> (axum::http::StatusCode, String) {
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/saml",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "display_name={}&idp_entity_id={}&idp_sso_url={}&certificate={}",
        urlencode(display_name),
        urlencode(idp_entity_id),
        urlencode(idp_sso_url),
        urlencode(certificate),
    );
    post_form_from_with_cookie(harness, &path, &form, "same-origin", cookie).await
}

/// A signed response addressed to a connection, using that connection's OWN stored values.
///
/// READ OFF THE ROW rather than written into the fixture, which is the point on the create path:
/// the audience and the recipient a provider must send are the ones the portal DERIVED, and a
/// fixture that spelled them out again would pass while the two disagreed.
fn response_for(key: &XmlTestKey, connection: &ironauth_store::SamlConnection) -> String {
    let children = format!(
        "<saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Subject><saml:NameID \
         Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
         ada@acme.example</saml:NameID>\
         <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\
         <saml:SubjectConfirmationData Recipient=\"{acs}\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\"/></saml:SubjectConfirmation></saml:Subject>\
         <saml:Conditions NotBefore=\"1969-12-31T23:58:00Z\" \
         NotOnOrAfter=\"1970-01-01T00:02:00Z\">\
         <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>\
         </saml:AudienceRestriction></saml:Conditions>\
         <saml:AttributeStatement><saml:Attribute Name=\"email\">\
         <saml:AttributeValue>ada@acme.example</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement>",
        acs = connection.acs_url,
        audience = connection.sp_entity_id,
    );
    ironauth_saml::test_util::signed_response_with(key, "_a1", &children)
}

/// The portal's SSO surface path for this harness.
fn sso_surface_path(harness: &Harness) -> String {
    let scope = harness.scope();
    format!(
        "/t/{}/e/{}/portal/s/sso",
        scope.tenant(),
        scope.environment()
    )
}

/// The SSO surface as a session holder sees it, asserting only that it was served.
async fn sso_surface_page(harness: &Harness, cookie: &str) -> String {
    let path = sso_surface_path(harness);
    let (status, _, page) = harness.get_with_cookie(&path, Some(cookie)).await;
    assert_eq!(status, 200, "the sso surface: {page}");
    page
}

#[tokio::test]
async fn an_admin_sets_up_saml_from_the_portal_and_a_response_then_verifies() {
    // #140 CRITERION 1, THE SAML HALF, AS A SCRIPTED JOURNEY. NOTHING the vendor does appears
    // between the link being minted and sign-in working, which is what "zero vendor-side
    // actions" means.
    //
    // THE LAST STEP IS THE ONE THAT MATTERS. Asserting a row exists would measure that a form
    // wrote a database. What a customer asked for is that a response their identity provider
    // signs is ACCEPTED, so the journey ends by signing one with the key they pasted and
    // running it through the connection test -- the same `examine` a real sign-in runs.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "setup-1", &org).await;

    // THE PAGE OFFERS THE FORM before anything exists, which is the state an admin arrives in.
    let scope = harness.scope();
    let surface = sso_surface_path(&harness);
    let page = sso_surface_page(&harness, &cookie).await;
    assert!(
        page.contains("Add a SAML connection"),
        "an admin with nothing configured needs a form, not an empty page: {page}"
    );

    // THE ADMIN'S OWN KEY, so the response signed at the end is signed by what they pasted.
    let key = XmlTestKey::generate();
    let der = ironauth_saml::test_util::certificate_carrying(&key.public_point());
    let pem = {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(&der);
        format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    };

    let (status, body) = submit_saml_setup(
        &harness,
        &cookie,
        "Acme Okta",
        "https://idp.example/entity",
        "https://idp.example/sso",
        &pem,
    )
    .await;
    assert_eq!(status, 303, "the setup was refused: {body}");

    // NOTHING EXISTS YET, and that is the design rather than a lag to paper over: the data
    // plane may not write this table at all.
    let before = harness
        .db()
        .store()
        .scoped(scope)
        .saml_connections()
        .list_for_org(&org, 10, None)
        .await
        .expect("list");
    assert!(
        before.is_empty(),
        "the portal wrote a connection it has no grant for"
    );

    assert_eq!(apply_saml_setups(&harness).await, 1, "one setup to apply");

    let created = harness
        .db()
        .store()
        .scoped(scope)
        .saml_connections()
        .list_for_org(&org, 10, None)
        .await
        .expect("list");
    assert_eq!(created.len(), 1, "the connection was created");
    let connection = &created[0];
    assert_eq!(connection.display_name, "Acme Okta");
    assert_eq!(connection.idp_entity_id, "https://idp.example/entity");
    // THE TWO VALUES THIS DEPLOYMENT OWNS, derived from the id and NOT from the form. Both paths
    // name the connection, which is why the page cannot print them until it exists.
    assert!(
        connection
            .acs_url
            .ends_with(&format!("/saml/acs/{}", connection.id)),
        "the reply URL has to name this connection: {}",
        connection.acs_url
    );
    assert!(
        connection
            .sp_entity_id
            .ends_with(&format!("/saml/metadata/{}", connection.id)),
        "and so does the audience: {}",
        connection.sp_entity_id
    );
    // THE SAFE DEFAULTS ARE NOT THE ADMIN'S TO CHOOSE, and the form offers no field for them.
    assert!(
        !connection.allow_unsolicited,
        "a link holder must not be able to create a connection that accepts any response"
    );
    // SWITCHED ON, and this is the criterion rather than an oversight. "Zero vendor-side
    // actions" means zero: a connection created switched off would need somebody at the vendor
    // to enable it, which is the action the criterion exists to remove. An earlier version of
    // this work asserted the opposite and called it a commercial decision -- a reasonable
    // product argument, and one that contradicts the thing being built.
    //
    // WHAT BOUNDS IT IS THE LINK, not the switch. A portal link is minted by the vendor, is
    // single-use, expires in minutes, and is scoped to one organization and one intent. The
    // decision "this customer may configure SSO" is made when that link is issued.
    assert!(
        connection.active,
        "an admin who completes the form has to end up with a connection that works"
    );

    // AND THE PAGE NOW HANDS OVER THE TWO VALUES, which is what the admin came back for.
    let (_, _, page) = harness.get_with_cookie(&surface, Some(&cookie)).await;
    assert!(
        page.contains(&connection.acs_url),
        "the page has to print the reply URL now that it exists: {page}"
    );

    // THE CERTIFICATE CAME WITH IT, so the connection is not the half-applied kind that looks
    // finished and refuses everything.
    let certificates = harness
        .db()
        .store()
        .scoped(scope)
        .saml_connections()
        .certificates(&connection.id)
        .await
        .expect("certificates");
    assert_eq!(certificates.len(), 1, "the pasted certificate was pinned");

    // THE JOURNEY'S END. A response signed by the admin's own key, addressed to the connection
    // the portal created, run through the same `examine` a real sign-in runs.
    let response = response_for(&key, connection);
    let (status, verdict) =
        test_connection(&harness, &cookie, &connection.id, &base64_of(&response)).await;
    assert_eq!(status, 200, "the connection test: {verdict}");
    assert!(
        verdict.contains("all check out"),
        "a response signed by the certificate the admin pasted has to verify against the \
         connection the admin created: {verdict}"
    );
}

#[tokio::test]
async fn a_setup_form_cannot_choose_what_this_deployment_expects() {
    // THE FORM HAS NO FIELD for the audience, the reply URL, the name ID format, or
    // `allow_unsolicited` -- and a form field is not the fence, because a POST can carry
    // anything. What refuses them is that the handler reads none of them: it derives the two
    // URLs from the id it minted and hard-codes the rest.
    //
    // THIS POSTS THEM ANYWAY, which is what an attacker holding a link would do.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "setup-2", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/saml",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "display_name=Acme&idp_entity_id={}&idp_sso_url={}&certificate={}\
         &sp_entity_id={}&acs_url={}&allow_unsolicited=true&nameid_format={}",
        urlencode("https://idp.example/entity"),
        urlencode("https://idp.example/sso"),
        urlencode(&pem_certificate(7)),
        urlencode("https://attacker.example/audience"),
        urlencode("https://attacker.example/acs"),
        urlencode("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
    );
    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "same-origin", &cookie).await;
    assert_eq!(status, 303, "the setup was refused: {body}");
    apply_saml_setups(&harness).await;

    let created = harness
        .db()
        .store()
        .scoped(scope)
        .saml_connections()
        .list_for_org(&org, 10, None)
        .await
        .expect("list");
    assert_eq!(created.len(), 1);
    let connection = &created[0];
    assert!(
        !connection.acs_url.contains("attacker.example"),
        "a link holder chose where responses are sent: {}",
        connection.acs_url
    );
    assert!(
        !connection.sp_entity_id.contains("attacker.example"),
        "a link holder chose what audience this deployment expects: {}",
        connection.sp_entity_id
    );
    assert!(
        !connection.allow_unsolicited,
        "a link holder switched off the correlation check"
    );
    assert!(
        connection.nameid_format.ends_with("emailAddress"),
        "a link holder chose a transient identifier: {}",
        connection.nameid_format
    );
}

#[tokio::test]
async fn a_setup_names_the_field_that_is_wrong() {
    // EVERY REFUSAL HERE IS ABOUT THE FORM THEY JUST TYPED, so unlike the renewal surface's
    // uniform page it says which. A setup form that answered "no" without saying what is
    // wrong is the generic error #140 criterion 6 complains about, one surface over.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "setup-3", &org).await;

    // AN http SIGN-ON URL. This deployment sends a browser there, so a link holder choosing an
    // unprotected address is a downgrade they do not get to make.
    let (status, body) = submit_saml_setup(
        &harness,
        &cookie,
        "Acme",
        "https://idp.example/entity",
        "http://idp.example/sso",
        &pem_certificate(3),
    )
    .await;
    assert_eq!(status, 400, "an http sign-on URL was accepted: {body}");
    assert!(body.contains("https://"), "and it has to say why: {body}");

    // A CERTIFICATE THAT IS NOT ONE, told NOW rather than in a worker where nobody is looking.
    let (status, body) = submit_saml_setup(
        &harness,
        &cookie,
        "Acme",
        "https://idp.example/entity",
        "https://idp.example/sso",
        "-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n",
    )
    .await;
    assert_eq!(
        status, 400,
        "an unparseable certificate was accepted: {body}"
    );
    assert!(
        body.contains("X.509"),
        "and it has to name what failed: {body}"
    );

    // NOTHING WAS QUEUED BY EITHER, which is the property that matters: a queue is not a place
    // to defer validation to.
    assert_eq!(
        apply_saml_setups(&harness).await,
        0,
        "a refused form still queued a job"
    );
}

#[tokio::test]
async fn a_scim_session_cannot_create_an_sso_connection() {
    // THE INTENT FENCE on the newest mutating route, which is exactly where it gets forgotten.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;

    // THE CONTROL: an `sso` session creates one.
    let sso = open_session_in(&harness, "sso", "setup-4", &org).await;
    let (status, body) = submit_saml_setup(
        &harness,
        &sso,
        "Acme",
        "https://idp.example/entity",
        "https://idp.example/sso",
        &pem_certificate(4),
    )
    .await;
    assert_eq!(status, 303, "the control: {body}");

    let scim = open_session_in(&harness, "scim", "setup-5", &org).await;
    let (status, body) = submit_saml_setup(
        &harness,
        &scim,
        "Acme",
        "https://idp.example/entity",
        "https://idp.example/sso",
        &pem_certificate(5),
    )
    .await;
    assert_eq!(
        status, 404,
        "a scim session created an SSO connection: {body}"
    );
    assert_eq!(
        apply_saml_setups(&harness).await,
        1,
        "only the control's setup should have been queued"
    );
}

#[tokio::test]
async fn a_cross_site_setup_is_refused() {
    // The CSRF guard every mutating portal route takes. This one creates the object every
    // sign-in through that organization is checked against.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "setup-6", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/saml",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "display_name=Acme&idp_entity_id={}&idp_sso_url={}&certificate={}",
        urlencode("https://idp.example/entity"),
        urlencode("https://idp.example/sso"),
        urlencode(&pem_certificate(6)),
    );
    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "cross-site", &cookie).await;
    assert_eq!(status, 403, "a cross-site setup was served: {body}");
    assert_eq!(apply_saml_setups(&harness).await, 0, "and queued nothing");
}

/// Drain the provisioning setup queue through the CONTROL-plane consumer, as the worker does.
async fn apply_scim_setups(harness: &Harness) -> usize {
    use ironauth_store::outbox::OutboxConsumer as _;

    let scope = harness.scope();
    let env = Env::system();
    let consumer = ironauth_admin::scim_connection_setup::ScimConnectionSetupConsumer::new(
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
                ironauth_store::SCIM_CONNECTION_SETUP_CONSUMER,
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
                .expect("the setup applies");
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

/// Submit the provisioning setup form the way the page renders it.
async fn submit_scim_setup(
    harness: &Harness,
    cookie: &str,
    display_name: &str,
    provider: &str,
) -> (axum::http::StatusCode, String) {
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim/connections",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "display_name={}&provider={}",
        urlencode(display_name),
        urlencode(provider),
    );
    post_form_from_with_cookie(harness, &path, &form, "same-origin", cookie).await
}

/// The token out of the one page that ever shows it.
fn token_from(page: &str) -> String {
    let at = page
        .find("Token: <code>")
        .unwrap_or_else(|| panic!("no token on the page: {page}"));
    let rest = &page[at + "Token: <code>".len()..];
    let end = rest.find("</code>").expect("the token is closed");
    rest[..end].to_owned()
}

#[tokio::test]
async fn an_admin_sets_up_provisioning_and_the_token_they_were_shown_authenticates() {
    // #140 CRITERION 1, THE PROVISIONING HALF, AS A SCRIPTED JOURNEY.
    //
    // THE LAST STEP IS THE ONE THAT MATTERS, exactly as on the SAML side: asserting a row exists
    // would measure that a form wrote a database. What the customer asked for is that the token
    // they were handed WORKS, so the journey ends by presenting it to the same
    // `ScimConnectionRepo::authenticate` every provisioning request goes through.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "scim", "scimsetup-1", &org).await;

    let scope = harness.scope();
    let surface = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, _, page) = harness.get_with_cookie(&surface, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning surface: {page}");
    assert!(
        page.contains("Add a provisioning connection"),
        "an admin with nothing configured needs a form: {page}"
    );

    let (status, shown) = submit_scim_setup(&harness, &cookie, "Acme Okta", "okta").await;
    assert_eq!(status, 200, "the setup was refused: {shown}");
    let token = token_from(&shown);
    assert!(
        shown.contains("shown once"),
        "an admin has to be told there is no second chance: {shown}"
    );
    assert!(
        shown.contains("/scim/v2"),
        "and given the base URL they need beside it: {shown}"
    );

    // THE PLAINTEXT IS NOWHERE BUT THAT RESPONSE, which is the claim the whole minting design
    // rests on. The queue row is durable, replicated and backed up; if the token were on it,
    // every replica would hold a live provisioning credential.
    let queued = harness
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::SCIM_CONNECTION_SETUP_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(queued.len(), 1, "one setup queued");
    let payload = queued[0].payload.to_string();
    assert!(
        !payload.contains(&token),
        "the plaintext token reached a durable queue row: {payload}"
    );
    assert!(
        payload.contains(&ironauth_store::scim_token_digest(&token)),
        "and its digest has to be what travels instead: {payload}"
    );
    // APPLIED FROM THE MESSAGE ALREADY IN HAND, because claiming it above took it: the drain
    // helper would find nothing and report zero, which would read as "no setup was queued".
    {
        use ironauth_store::outbox::OutboxConsumer as _;
        let consumer = ironauth_admin::scim_connection_setup::ScimConnectionSetupConsumer::new(
            harness.db().control_store().clone(),
        );
        consumer
            .handle(&Env::system(), scope, &queued[0])
            .await
            .expect("the setup applies");
        harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .complete(&Env::system(), &queued[0])
            .await
            .expect("complete");
    }

    // THE JOURNEY'S END. The token the admin was shown, through the read every provisioning
    // request makes.
    let resolved = harness
        .db()
        .store()
        .scoped(scope)
        .scim_connections()
        .authenticate(
            &ironauth_store::scim_token_digest(&token),
            now_micros(&harness),
        )
        .await
        .expect("authenticate");
    let resolved = resolved.expect("the token the admin was shown has to authenticate");
    assert_eq!(resolved.display_name, "Acme Okta");
    assert_eq!(&resolved.organization_id, &org, "and as their organization");
    // AND THE TOKEN NAMES THE CONNECTION IT AUTHENTICATES AS, which is what lets
    // `ironauth-scim` read a scope out of it before any query runs.
    assert!(
        token.starts_with(&format!("{}.", resolved.id)),
        "the token has to name its own connection: {token}"
    );

    // NO HORIZON, which is the one decision this form makes for the admin and the one worth
    // asserting: a connection created with an expiry cannot be rotated once it passes, so a
    // portal form setting one would hand over a credential with a one-way date and no remedy.
    assert!(
        resolved.expires_at_unix_micros.is_none(),
        "a portal-created connection must not carry a one-way expiry"
    );
}

#[tokio::test]
async fn provisioning_setup_is_absent_where_the_surface_is_not_served() {
    // A CREDENTIAL FOR AN ENDPOINT THAT ANSWERS NOTHING. With `scim.enabled` off this deployment
    // answers `/scim/v2` with a uniform 404, so a token minted here could never be used -- and
    // the page would have handed it over with instructions saying it could.
    let harness = Harness::start_store_backed_with_scim_surface(false).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "scim", "scimsetup-2", &org).await;

    let scope = harness.scope();
    let surface = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (_, _, page) = harness.get_with_cookie(&surface, Some(&cookie)).await;
    assert!(
        !page.contains("Add a provisioning connection"),
        "a form minting a credential that cannot work was offered: {page}"
    );

    let (status, body) = submit_scim_setup(&harness, &cookie, "Acme", "okta").await;
    assert_eq!(status, 404, "the route minted a token anyway: {body}");
    assert_eq!(apply_scim_setups(&harness).await, 0, "and queued nothing");
}

#[tokio::test]
async fn a_provisioning_setup_names_what_is_wrong() {
    // THE PROVIDER IS A CLOSED SET and the column's CHECK constraint would refuse an unknown one
    // -- in the WORKER, where the admin is not looking and the only trace is a dead letter. It
    // is also what the setup guides key on, so a value outside the set is a connection with no
    // guide.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "scim", "scimsetup-3", &org).await;

    let (status, body) = submit_scim_setup(&harness, &cookie, "Acme", "pied-piper").await;
    assert_eq!(status, 400, "an unknown provider was accepted: {body}");
    assert!(
        body.contains("Okta"),
        "and it has to say what is allowed: {body}"
    );

    let (status, body) = submit_scim_setup(&harness, &cookie, "   ", "okta").await;
    assert_eq!(status, 400, "a blank name was accepted: {body}");

    assert_eq!(
        apply_scim_setups(&harness).await,
        0,
        "a refused form still queued a job"
    );
}

#[tokio::test]
async fn an_sso_session_cannot_mint_a_provisioning_token() {
    // THE INTENT FENCE on a route that mints a bearer credential, which is the strongest reason
    // any portal route has to keep one.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;

    // THE CONTROL: a `scim` session mints one.
    let scim = open_session_in(&harness, "scim", "scimsetup-4", &org).await;
    let (status, body) = submit_scim_setup(&harness, &scim, "Acme", "okta").await;
    assert_eq!(status, 200, "the control: {body}");

    let sso = open_session_in(&harness, "sso", "scimsetup-5", &org).await;
    let (status, body) = submit_scim_setup(&harness, &sso, "Acme", "okta").await;
    assert_eq!(
        status, 404,
        "an sso session minted a provisioning token: {body}"
    );
    assert_eq!(
        apply_scim_setups(&harness).await,
        1,
        "only the control's setup should have been queued"
    );
}

#[tokio::test]
async fn a_cross_site_provisioning_setup_is_refused() {
    // The CSRF guard, on the route with the most to lose: a cross-origin post would mint a
    // provisioning credential and render it into a page another site asked for.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "scim", "scimsetup-6", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim/connections",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = post_form_from_with_cookie(
        &harness,
        &path,
        "display_name=Acme&provider=okta",
        "cross-site",
        &cookie,
    )
    .await;
    assert_eq!(status, 403, "a cross-site setup was served: {body}");
    assert_eq!(apply_scim_setups(&harness).await, 0, "and queued nothing");
}

/// Drain the OIDC upstream setup queue through the CONTROL-plane consumer.
async fn apply_oidc_setups(harness: &Harness) -> usize {
    use ironauth_store::outbox::OutboxConsumer as _;

    let scope = harness.scope();
    let env = Env::system();
    let consumer = ironauth_admin::oidc_upstream_setup::OidcUpstreamSetupConsumer::new(
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
                ironauth_store::OIDC_UPSTREAM_SETUP_CONSUMER,
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
                .expect("the setup applies");
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

/// Submit the OIDC setup form the way the page renders it.
async fn submit_oidc_setup(
    harness: &Harness,
    cookie: &str,
    display_name: &str,
    issuer: &str,
    client_id: &str,
    client_secret: &str,
) -> (axum::http::StatusCode, String) {
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/oidc",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "display_name={}&issuer={}&client_id={}&client_secret={}",
        urlencode(display_name),
        urlencode(issuer),
        urlencode(client_id),
        urlencode(client_secret),
    );
    post_form_from_with_cookie(harness, &path, &form, "same-origin", cookie).await
}

/// The connector an organization's single OIDC binding names, and the secret it holds.
///
/// THE READ THE FEDERATION FLOW MAKES, which is the point of asserting on it: a ciphertext
/// nothing can open is the failure a portal-side seal could ship silently, and it is invisible
/// from the row.
async fn bound_connector_secret(harness: &Harness, org: &OrganizationId) -> Vec<u8> {
    let scope = harness.scope();
    let bindings = harness
        .db()
        .store()
        .scoped(scope)
        .org_connections()
        .list_for_organization(org, 10)
        .await
        .expect("list the bindings");
    assert_eq!(bindings.len(), 1, "one OIDC upstream is bound");
    let connector = harness
        .db()
        .store()
        .scoped(scope)
        .connectors()
        .parse_id(
            bindings[0]
                .connector_id
                .as_deref()
                .expect("the binding names a connector"),
        )
        .expect("the connector id parses");
    harness
        .db()
        .store()
        .scoped(scope)
        .connectors()
        .open_client_secret(&connector)
        .await
        .expect("the sealed secret has to open")
}

#[tokio::test]
async fn an_admin_sets_up_an_oidc_upstream_and_the_secret_survives_the_queue() {
    // #140 CRITERION 1, THE OIDC HALF. The journey ends where it has to: the secret the admin
    // typed comes back OUT of the connector through `open_client_secret`, which is the read the
    // federation flow itself makes. Asserting a row exists would leave the one thing that can
    // silently break -- a ciphertext nothing can open -- unmeasured.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "oidcsetup-1", &org).await;

    let page = sso_surface_page(&harness, &cookie).await;
    assert!(
        page.contains("Add an OpenID Connect connection"),
        "an admin with an OIDC provider needs the form for the one they have: {page}"
    );

    let (status, body) = submit_oidc_setup(
        &harness,
        &cookie,
        "Acme Entra",
        "https://login.example/acme",
        "client-abc",
        "super-secret-value",
    )
    .await;
    assert_eq!(status, 303, "the setup was refused: {body}");

    // THE PLAINTEXT IS NOT ON THE QUEUE, which is the claim the whole sealing design rests on.
    let scope = harness.scope();
    let queued = harness
        .db()
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &Env::system(),
            ironauth_store::OIDC_UPSTREAM_SETUP_CONSUMER,
            std::time::Duration::from_secs(30),
            10,
        )
        .await
        .expect("claim");
    assert_eq!(queued.len(), 1, "one setup queued");
    let payload = queued[0].payload.to_string();
    assert!(
        !payload.contains("super-secret-value"),
        "the upstream client secret reached a durable queue row: {payload}"
    );
    assert!(
        payload.contains("client_secret_sealed_base64"),
        "and the sealed form has to be what travels instead: {payload}"
    );

    {
        use ironauth_store::outbox::OutboxConsumer as _;
        let consumer = ironauth_admin::oidc_upstream_setup::OidcUpstreamSetupConsumer::new(
            harness.db().control_store().clone(),
        );
        consumer
            .handle(&Env::system(), scope, &queued[0])
            .await
            .expect("the setup applies");
        harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .complete(&Env::system(), &queued[0])
            .await
            .expect("complete");
    }

    // THE BINDING EXISTS, and THE SECRET OPENS. The AAD binds the ciphertext to this scope
    // and this connector id, so a seal performed on the data plane before the row existed has
    // to authenticate here.
    assert_eq!(
        bound_connector_secret(&harness, &org).await,
        b"super-secret-value".to_vec(),
        "the secret the admin typed has to be the one the federation flow reads"
    );

    // AND THE PAGE NOW LISTS IT, which is what the admin came back for.
    let page = sso_surface_page(&harness, &cookie).await;
    assert!(
        page.contains("acme-entra"),
        "the page has to show the upstream once it exists: {page}"
    );
}

#[tokio::test]
async fn an_oidc_setup_form_cannot_declare_what_this_deployment_believes() {
    // THE CAPABILITIES ARE NOT THE ADMIN'S TO DECLARE. Each one widens what this deployment does
    // with an upstream's answers -- trust its `email_verified`, act on its group claims, honour
    // its logout propagation -- so a link holder asserting them would be configuring how much we
    // believe their identity provider. The form has no field for any of them, and a form field
    // is not the fence: this posts them anyway.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "oidcsetup-2", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/oidc",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "display_name=Acme&issuer={}&client_id=abc&client_secret=s\
         &capabilities.groups=true&capabilities.email_verified_trust=trusted\
         &enabled=true&protocol=oauth2",
        urlencode("https://login.example/acme"),
    );
    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "same-origin", &cookie).await;
    assert_eq!(status, 303, "the setup was refused: {body}");
    apply_oidc_setups(&harness).await;

    let bindings = harness
        .db()
        .store()
        .scoped(scope)
        .org_connections()
        .list_for_organization(&org, 10)
        .await
        .expect("list");
    let connector_id = bindings[0]
        .connector_id
        .as_deref()
        .expect("the binding names a connector");
    let parsed = harness
        .db()
        .store()
        .scoped(scope)
        .connectors()
        .parse_id(connector_id)
        .expect("parses");
    let connector = harness
        .db()
        .store()
        .scoped(scope)
        .connectors()
        .get(&parsed)
        .await
        .expect("the connector exists");
    assert!(
        !connector.capabilities.groups,
        "a link holder switched on group claims from their own provider"
    );
    assert!(
        !connector.capabilities.logout_propagation,
        "a link holder switched on logout propagation"
    );
    assert_eq!(
        connector.capabilities.email_verified_trust, "untrusted",
        "a link holder made us believe their provider's email_verified"
    );
}

#[tokio::test]
async fn an_oidc_setup_names_what_is_wrong() {
    // AS THE SAML FORM DOES, and for the same reason: everything refused here is about the form
    // the reader just typed.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "oidcsetup-3", &org).await;

    let (status, body) = submit_oidc_setup(
        &harness,
        &cookie,
        "Acme",
        "http://login.example/acme",
        "abc",
        "s",
    )
    .await;
    assert_eq!(status, 400, "an http issuer was accepted: {body}");
    assert!(body.contains("https://"), "and it has to say why: {body}");

    // A NAME WITH NOTHING TO MAKE AN IDENTIFIER FROM. The slug goes in operator tooling and in
    // URLs, so it is derived rather than taken raw -- and a name that derives to nothing is a
    // refusal rather than a connector nobody can address.
    let (status, body) = submit_oidc_setup(
        &harness,
        &cookie,
        "!!!",
        "https://login.example/a",
        "abc",
        "s",
    )
    .await;
    assert_eq!(status, 400, "a nameless connector was created: {body}");

    assert_eq!(
        apply_oidc_setups(&harness).await,
        0,
        "a refused form still queued a job"
    );
}

#[tokio::test]
async fn a_cross_site_oidc_setup_is_refused() {
    // The CSRF guard. This one creates an upstream this deployment will believe about identity.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "oidcsetup-4", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/sso/oidc",
        scope.tenant(),
        scope.environment()
    );
    let form = format!(
        "display_name=Acme&issuer={}&client_id=abc&client_secret=s",
        urlencode("https://login.example/acme"),
    );
    let (status, body) =
        post_form_from_with_cookie(&harness, &path, &form, "cross-site", &cookie).await;
    assert_eq!(status, 403, "a cross-site setup was served: {body}");
    assert_eq!(apply_oidc_setups(&harness).await, 0, "and queued nothing");
}

#[tokio::test]
async fn one_it_admin_configures_sso_and_provisioning_end_to_end_with_no_vendor_action() {
    // #140 CRITERION 1, AS THE ONE SCRIPTED SCENARIO IT ASKS FOR.
    //
    // The three journeys beside this each prove one protocol in isolation, which is what makes
    // a failure attributable. This one is the criterion's own sentence, run as written: an IT
    // admin completes SSO -- SAML AND OIDC -- plus SCIM setup, through portal links, and nothing
    // at the vendor happens in between.
    //
    // TWO LINKS, NOT ONE, and that is the intent fence rather than a gap: a link is scoped to
    // one intent on purpose, so the person configuring provisioning need not be handed the
    // ability to change sign-on. The vendor mints them; that is the act the link IS.
    //
    // EACH STEP ENDS IN THE THING THAT WORKS, never in a row: a response the admin's own key
    // signed is accepted, the secret they typed opens back out, and the token they were shown
    // authenticates.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let scope = harness.scope();
    let env = Env::system();

    // ---- 1. SSO, the SAML half ---------------------------------------------------------
    let sso = open_session_in(&harness, "sso", "e2e-sso", &org).await;
    let key = XmlTestKey::generate();
    let der = ironauth_saml::test_util::certificate_carrying(&key.public_point());
    let pem = {
        use base64::Engine as _;
        let body = base64::engine::general_purpose::STANDARD.encode(&der);
        format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
    };
    let (status, body) = submit_saml_setup(
        &harness,
        &sso,
        "Acme Okta",
        "https://idp.example/entity",
        "https://idp.example/sso",
        &pem,
    )
    .await;
    assert_eq!(status, 303, "the SAML setup: {body}");

    // ---- 2. SSO, the OIDC half, through the SAME link ------------------------------------
    let (status, body) = submit_oidc_setup(
        &harness,
        &sso,
        "Acme Entra",
        "https://login.example/acme",
        "client-abc",
        "super-secret-value",
    )
    .await;
    assert_eq!(status, 303, "the OIDC setup: {body}");

    // ---- 3. Provisioning, through a link for that intent ---------------------------------
    let scim = open_session_in(&harness, "scim", "e2e-scim", &org).await;
    let (status, shown) = submit_scim_setup(&harness, &scim, "Acme Okta SCIM", "okta").await;
    assert_eq!(status, 200, "the provisioning setup: {shown}");
    let token = token_from(&shown);

    // ---- the workers run, which is the only thing that happens between ---------------------
    assert_eq!(apply_saml_setups(&harness).await, 1, "one SAML setup");
    assert_eq!(apply_oidc_setups(&harness).await, 1, "one OIDC setup");
    assert_eq!(
        apply_scim_setups(&harness).await,
        1,
        "one provisioning setup"
    );

    // ---- and every one of the three now WORKS ---------------------------------------------

    // SAML: a response the admin's own key signed, addressed with the connection's own stored
    // values, through the same `examine` a real sign-in runs.
    let saml = harness
        .db()
        .store()
        .scoped(scope)
        .saml_connections()
        .list_for_org(&org, 10, None)
        .await
        .expect("list");
    assert_eq!(saml.len(), 1, "the SAML connection exists");
    let response = response_for(&key, &saml[0]);
    let (status, verdict) =
        test_connection(&harness, &sso, &saml[0].id, &base64_of(&response)).await;
    assert_eq!(status, 200, "the connection test: {verdict}");
    assert!(
        verdict.contains("all check out"),
        "the SAML connection has to accept its own provider's response: {verdict}"
    );

    // OIDC: the secret the admin typed, back out through the read the federation flow makes.
    assert_eq!(
        bound_connector_secret(&harness, &org).await,
        b"super-secret-value".to_vec()
    );

    // SCIM: the token the admin was shown, through the read every provisioning request makes.
    let resolved = harness
        .db()
        .store()
        .scoped(scope)
        .scim_connections()
        .authenticate(
            &ironauth_store::scim_token_digest(&token),
            now_micros(&harness),
        )
        .await
        .expect("authenticate")
        .expect("the token the admin was shown has to authenticate");
    assert_eq!(resolved.display_name, "Acme Okta SCIM");
    assert_eq!(&resolved.organization_id, &org);

    // ---- and the pages hand over what the admin needs next ---------------------------------
    let page = sso_surface_page(&harness, &sso).await;
    assert!(
        page.contains(&saml[0].acs_url),
        "the reply URL the provider needs: {page}"
    );
    assert!(
        page.contains("acme-entra"),
        "and the OIDC upstream, listed: {page}"
    );
    let _ = env;
}

#[tokio::test]
async fn the_token_page_names_the_provider_and_the_wait() {
    // TWO SENTENCES A CUSTOMER READS, both of which were wrong in their own way.
    //
    // THE SLUG IS NOT A NAME. "Paste these two values into generic" is not a sentence, and the
    // page is read by somebody looking at their provider's console.
    //
    // AND THE CONNECTION DOES NOT EXIST YET. The token is minted and shown before the consumer
    // runs, so an admin who pastes it immediately gets a 401 -- and if the job dead-letters they
    // hold a credential for a connection that never appears, with nothing anywhere to say so.
    // The page has to name the wait and what it means if it does not end.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "scim", "label-1", &org).await;

    let (status, page) = submit_scim_setup(&harness, &cookie, "Acme Okta", "okta").await;
    assert_eq!(status, 200, "the setup: {page}");
    assert!(
        page.contains("into Okta"),
        "a provider with a name is called by it: {page}"
    );
    assert!(
        page.contains("being created"),
        "and the wait has to be named: {page}"
    );

    // THE THIRD SLUG IS NOT A PRODUCT, so the sentence has to work without one.
    let (_, page) = submit_scim_setup(&harness, &cookie, "Acme Other", "generic").await;
    assert!(
        !page.contains("into generic"),
        "the stored slug reached a customer's page: {page}"
    );
    assert!(
        page.contains("your identity provider"),
        "and the sentence still has to read: {page}"
    );
}

#[tokio::test]
async fn the_stored_definition_is_one_the_runtime_can_read() {
    // A HAND-BUILT DOCUMENT IS A SHAPE NOTHING CHECKS. The federation flow parses
    // `ConnectorDefinition` out of `definition_json` at every sign-in, so a connector stored
    // with an object that type cannot read exists, looks configured on every page, and fails at
    // sign-in with nothing able to say why. The management API composes what it stores through
    // `validate` and `secret_free_json`; so does this.
    //
    // AND THE SECRET IS NOT IN IT, which is the other half: the portal seals the real value
    // separately, and the placeholder the type requires to parse must not survive into storage.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "def-1", &org).await;

    let (status, body) = submit_oidc_setup(
        &harness,
        &cookie,
        "Acme Entra",
        "https://login.example/acme",
        "client-abc",
        "super-secret-value",
    )
    .await;
    assert_eq!(status, 303, "the setup: {body}");
    apply_oidc_setups(&harness).await;

    let scope = harness.scope();
    let bindings = harness
        .db()
        .store()
        .scoped(scope)
        .org_connections()
        .list_for_organization(&org, 10)
        .await
        .expect("list");
    let connector = harness
        .db()
        .store()
        .scoped(scope)
        .connectors()
        .parse_id(
            bindings[0]
                .connector_id
                .as_deref()
                .expect("the binding names a connector"),
        )
        .expect("parses");
    let record = harness
        .db()
        .store()
        .scoped(scope)
        .connectors()
        .get(&connector)
        .await
        .expect("the connector exists");

    // THE READ THE FEDERATION FLOW ACTUALLY MAKES, which is `ConnectorRuntimeConfig` and not
    // `ConnectorDefinition`. The two are different types on purpose: the stored document is
    // SECRET-FREE, so it cannot satisfy a type that requires `client_secret` -- and asserting
    // against that type would have been asserting a contract nothing has.
    let parsed: ironauth_connector::ConnectorRuntimeConfig =
        serde_json::from_str(&record.definition_json)
            .expect("the stored definition has to parse as the type the sign-in path reads");
    assert_eq!(parsed.client_id, "client-abc");
    // THE ISSUER LANDED IN THE DISCOVERY VARIANT, which is what an `endpoints: { issuer }`
    // document means to this type -- and the variant is what decides whether the flow fetches
    // a discovery document at all, so getting it wrong would produce a connector that parses
    // and then does not sign anybody in.
    assert!(
        matches!(
            &parsed.endpoints,
            ironauth_connector::Endpoints::Discovery(endpoints)
                if endpoints.issuer == "https://login.example/acme"
        ),
        "the issuer the admin typed has to reach the runtime's discovery endpoints: {:?}",
        parsed.endpoints
    );

    // THE PLACEHOLDER MUST NOT HAVE SURVIVED. `secret_free_json` strips the field, and the real
    // value lives sealed on the row rather than in this document.
    assert!(
        !record.definition_json.contains("placeholder"),
        "the parse placeholder reached storage: {}",
        record.definition_json
    );
    assert!(
        !record.definition_json.contains("super-secret-value"),
        "the admin's secret reached the stored definition: {}",
        record.definition_json
    );
}

#[tokio::test]
async fn every_provider_the_form_offers_is_one_the_handler_accepts() {
    // ONE LIST, MEASURED. The slug was validated in one place, labelled in another, and rendered
    // as `<option>`s in a third -- so a provider added to the picker and not to the validation
    // would be a page whose own control produces a 400, and one added to the validation and not
    // to the labels would print "Paste these two values into" and then the wrong thing.
    //
    // THIS DRIVES THE PAGE'S OWN OPTIONS, so it cannot drift from what a customer can choose:
    // the test reads the values out of the rendered form rather than spelling them again.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "scim", "prov-1", &org).await;
    let scope = harness.scope();
    let surface = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (_, _, page) = harness.get_with_cookie(&surface, Some(&cookie)).await;

    let mut offered = Vec::new();
    let mut rest = page.as_str();
    while let Some(at) = rest.find("<option value=\"") {
        rest = &rest[at + "<option value=\"".len()..];
        let end = rest.find('"').expect("the value is closed");
        offered.push(rest[..end].to_owned());
    }
    assert!(
        offered.len() >= 3,
        "the picker has to offer the providers this deployment supports: {page}"
    );

    for slug in offered {
        let (status, body) = submit_scim_setup(&harness, &cookie, "Acme", &slug).await;
        assert_eq!(
            status, 200,
            "the form offers `{slug}` and the handler refuses it: {body}"
        );
        // AND THE PAGE THAT COMES BACK SAYS SOMETHING, rather than printing the slug at a
        // customer: every choice has a label, which is the other half of the one list.
        assert!(
            !body.contains(&format!("into {slug}")),
            "the stored slug reached a customer's page for `{slug}`: {body}"
        );
    }
}

#[tokio::test]
async fn the_guide_and_the_created_connection_agree_about_the_name_id() {
    // A CORRESPONDENCE NOTHING ENFORCED. The setup guide tells an admin "Set Name ID format to
    // EmailAddress", and the create path writes the format the connection will EXPECT. Those are
    // two sentences in two files, and if they ever disagree the admin configures exactly what
    // they were told and every sign-in is refused with `WrongNameIdFormat` -- a failure the
    // connection test would then diagnose correctly and blame on their provider.
    //
    // THE TEST READS BOTH off the same connection, so it pins the pair rather than either.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "nameid-1", &org).await;

    let (status, body) = submit_saml_setup(
        &harness,
        &cookie,
        "Acme Okta",
        "https://idp.example/entity",
        "https://idp.example/sso",
        &pem_certificate(9),
    )
    .await;
    assert_eq!(status, 303, "the setup: {body}");
    apply_saml_setups(&harness).await;

    let created = harness
        .db()
        .store()
        .scoped(harness.scope())
        .saml_connections()
        .list_for_org(&org, 10, None)
        .await
        .expect("list");
    assert_eq!(created.len(), 1);
    // WHAT THE CONNECTION EXPECTS.
    assert!(
        created[0].nameid_format.ends_with("emailAddress"),
        "the created connection expects: {}",
        created[0].nameid_format
    );

    // AND WHAT THE PAGE TELLS THE ADMIN TO CONFIGURE, for that same connection.
    let page = sso_surface_page(&harness, &cookie).await;
    assert!(
        page.contains("EmailAddress"),
        "the guide has to name the format the connection expects: {page}"
    );
    // AND IT MUST NOT SEND THEM TO THE VENDOR FOR THE CERTIFICATE, which is the step this
    // create path removed: the guides told an admin to hand it over, and the form now takes it.
    assert!(
        !page.contains("give it to your vendor"),
        "the guide still names the vendor-side action the criterion removes: {page}"
    );
}

#[tokio::test]
async fn a_second_connection_to_the_same_provider_is_not_silently_discarded() {
    // `saml_connections_one_per_idp` is `UNIQUE (tenant, environment, organization,
    // idp_entity_id)`, and the consumer's Conflict arm assumed the conflict was always on the
    // connection ID -- a redelivery. It is not: an admin who submits the form twice for one
    // identity provider raises it on the IdP key, where the connection this row names was never
    // written. Treating that as done pinned their certificate onto nothing, answered them 303,
    // and raised no dead letter.
    //
    // THE TEST IS THE SECOND SUBMISSION, and what it asserts is that the WORKER refuses it --
    // because the admin has already been told 303 and the only way anybody learns is the queue.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "conflict-1", &org).await;

    for label in ["first", "second"] {
        let (status, body) = submit_saml_setup(
            &harness,
            &cookie,
            &format!("Acme Okta {label}"),
            "https://idp.example/entity",
            "https://idp.example/sso",
            &pem_certificate(11),
        )
        .await;
        assert_eq!(
            status, 303,
            "the {label} setup was refused at the form: {body}"
        );
    }

    // THE FIRST APPLIES, THE SECOND DOES NOT, and the second is an ERROR rather than a no-op.
    use ironauth_store::outbox::OutboxConsumer as _;
    let env = Env::system();
    let scope = harness.scope();
    let consumer = ironauth_admin::saml_connection_setup::SamlConnectionSetupConsumer::new(
        harness.db().control_store().clone(),
    );
    // ONE AT A TIME, because both rows share an ordering key -- the organization -- and the
    // outbox hands out one per key so setups for one customer apply in the order they were
    // made. Claiming ten returns one.
    let mut outcomes = Vec::new();
    for _ in 0..2 {
        let claimed = harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .claim(
                &env,
                ironauth_store::SAML_CONNECTION_SETUP_CONSUMER,
                std::time::Duration::from_secs(30),
                10,
            )
            .await
            .expect("claim");
        assert_eq!(claimed.len(), 1, "one row per ordering key at a time");
        let applied = consumer.handle(&env, scope, &claimed[0]).await.is_ok();
        outcomes.push(applied);
        // COMPLETED EITHER WAY, so the second row is reachable. A real worker would dead-letter
        // the failure instead; what this test needs is to see both verdicts.
        harness
            .db()
            .store()
            .scoped(scope)
            .outbox()
            .complete(&env, &claimed[0])
            .await
            .expect("complete");
    }
    assert_eq!(
        outcomes.iter().filter(|ok| **ok).count(),
        1,
        "exactly one of the two has to apply"
    );
    assert!(
        outcomes.contains(&false),
        "and the other has to FAIL, so an operator is told rather than the setup vanishing"
    );

    // AND ONE CONNECTION EXISTS, not two and not zero.
    let created = harness
        .db()
        .store()
        .scoped(scope)
        .saml_connections()
        .list_for_org(&org, 10, None)
        .await
        .expect("list");
    assert_eq!(created.len(), 1, "one connection per identity provider");
}

#[tokio::test]
async fn two_organizations_naming_their_upstream_the_same_both_get_one() {
    // `connectors_slug_idx` is UNIQUE on (tenant, environment, connector_slug) -- SCOPE-wide,
    // not per-organization -- so a slug derived from the display name alone collides the moment
    // two of a deployment's customers both call their upstream "Okta". The loser's create was
    // then swallowed as "already exists" and the consumer went on to write an `org_connections`
    // row pointing at a connector that was never inserted: nothing backs that column with a
    // foreign key, so the insert SUCCEEDED and the admin's sign-in was never going to work,
    // with no dead letter and no page able to say why.
    //
    // TWO ORGANIZATIONS, THE SAME NAME, and both must end up with a working upstream.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let first = seed_org(&harness, "Acme").await;
    let second = seed_org(&harness, "Initech").await;

    for (label, org) in [("one", &first), ("two", &second)] {
        let cookie = open_session_in(&harness, "sso", &format!("slug-{label}"), org).await;
        let (status, body) = submit_oidc_setup(
            &harness,
            &cookie,
            // THE SAME DISPLAY NAME. One field, identical, which is the whole fixture.
            "Okta",
            "https://login.example/acme",
            "client-abc",
            "s3cr3t",
        )
        .await;
        assert_eq!(status, 303, "organization {label}: {body}");
    }
    assert_eq!(apply_oidc_setups(&harness).await, 2, "both setups apply");

    // BOTH BINDINGS NAME A CONNECTOR THAT EXISTS, which is the property the dangling write broke.
    let scope = harness.scope();
    for (label, org) in [("one", &first), ("two", &second)] {
        let bindings = harness
            .db()
            .store()
            .scoped(scope)
            .org_connections()
            .list_for_organization(org, 10)
            .await
            .expect("list");
        assert_eq!(bindings.len(), 1, "organization {label} has one binding");
        let raw = bindings[0]
            .connector_id
            .as_deref()
            .expect("the binding names a connector");
        let id = harness
            .db()
            .store()
            .scoped(scope)
            .connectors()
            .parse_id(raw)
            .expect("parses");
        harness
            .db()
            .store()
            .scoped(scope)
            .connectors()
            .get(&id)
            .await
            .unwrap_or_else(|error| {
                panic!("organization {label} is bound to a connector that does not exist: {error}")
            });
    }
}

#[tokio::test]
async fn a_name_the_column_refuses_is_refused_at_the_form() {
    // THE BOUND HAS TO BE THE COLUMN'S. `saml_connections_display_name_bounded` is
    // `octet_length(display_name) <= 252`, and this surface checked 512 -- so a name between the
    // two was accepted, answered 303, and then refused by the storage engine in a WORKER, where
    // the only trace is a dead letter and the admin is told nothing.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "bound-1", &org).await;

    let too_long = "x".repeat(253);
    let (status, body) = submit_saml_setup(
        &harness,
        &cookie,
        &too_long,
        "https://idp.example/entity",
        "https://idp.example/sso",
        &pem_certificate(12),
    )
    .await;
    assert_eq!(
        status, 400,
        "a name the column refuses was accepted: {body}"
    );
    assert_eq!(
        apply_saml_setups(&harness).await,
        0,
        "and nothing reached the queue to dead-letter"
    );

    // THE CONTROL, one octet shorter: the bound is the column's rather than a refusal of
    // everything long.
    let (status, body) = submit_saml_setup(
        &harness,
        &cookie,
        &"x".repeat(252),
        "https://idp.example/entity",
        "https://idp.example/sso",
        &pem_certificate(12),
    )
    .await;
    assert_eq!(status, 303, "the longest name the column takes: {body}");
    assert_eq!(apply_saml_setups(&harness).await, 1, "and it applies");
}

#[tokio::test]
async fn an_issuer_the_definition_refuses_names_the_field() {
    // THE HANDLER CHECKS `starts_with("https://")` and `ConnectorDefinition::validate` refuses a
    // great deal more -- a query string, a fragment, an empty authority. Those failures were
    // answered with the unavailable page, which blames this deployment for a value the reader
    // typed and can fix, on the surface whose whole purpose is naming which field is wrong.
    let harness = Harness::start_store_backed_with_scim_surface(true).await;
    let org = seed_org(&harness, "Acme").await;
    let cookie = open_session_in(&harness, "sso", "issuer-1", &org).await;

    for issuer in [
        "https://login.example/acme?tenant=1",
        "https://login.example/acme#fragment",
        "https://",
    ] {
        let (status, body) =
            submit_oidc_setup(&harness, &cookie, "Acme", issuer, "client-abc", "s").await;
        assert_eq!(status, 400, "`{issuer}` was accepted: {body}");
        assert!(
            body.contains("issuer"),
            "and the refusal has to name the field: {body}"
        );
    }
    assert_eq!(apply_oidc_setups(&harness).await, 0, "nothing was queued");
}
