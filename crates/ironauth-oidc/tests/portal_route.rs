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
        .create(&env, &organization, 1_000_000, "Globex", None)
        .await
        .expect("create organization");

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
                organization_id: &organization,
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

    for forbidden in ["scim", "domain-verification", "log-streams"] {
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
