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
                provider: "okta",
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

/// Each connection's row says which of the five things it is.
///
/// # The five states, and why the page has to keep them apart
///
/// An absent deadline is published by a healthy connection whose token never expires AND by one
/// that has already stopped working, so a page that rendered only deadlines would show those two
/// identically while only one of them needs the admin today. A revoked connection also has no
/// usable credential, but somebody made it that way and its row says so instead.
///
/// # The lead is the configured one, and the fixture is what proves it
///
/// The harness installs THIRTY days. A connection lapsing in twenty is inside that and OUTSIDE
/// the shipped fourteen-day default, so it warns only if the page read the lead off the state.
/// A page that hardcoded the default renders it "Active until" and turns this red. That is the
/// whole reason the harness has the knob: at the default, every fixture would pass against a
/// hardcoded page.
#[tokio::test]
async fn each_connection_row_reports_which_of_the_five_states_it_is_in() {
    let harness = Harness::start_store_backed_with_scim_warning_lead(30 * 24 * 60 * 60).await;
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

    connect(&harness, &org, "never-expires", "tok-a", None).await;
    connect(&harness, &org, "lapses-in-twenty-days", "tok-b", Some(now + 20 * day)).await;
    // THE STATE NOTHING RENDERED BEFORE: a live credential with a deadline OUTSIDE the lead.
    // Every other row here is caught by an earlier branch -- revoked, or no live credential, or
    // inside the lead -- so without this one the "Active until" arm was unreachable in the whole
    // suite and could be deleted, or made to print the wrong word or the wrong date, in silence.
    connect(&harness, &org, "lapses-in-forty-days", "tok-e", Some(now + 40 * day)).await;

    let revoked = connect(&harness, &org, "switched-off", "tok-c", Some(now + 40 * day)).await;
    writes()
        .scim_connections()
        .revoke(&env, &revoked, now)
        .await
        .expect("revoke the connection");

    // THE BROKEN ONE, built the only way the API can build it: rotate so the original token is
    // superseded to the end of a short overlap, then revoke the fresh token outright. The
    // CONNECTION stays live -- its own expiry is forty days out -- so what the page reports is
    // the loss of its credentials rather than the connection lapsing.
    let broken = connect(&harness, &org, "credentials-gone", "tok-d", Some(now + 40 * day)).await;
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
    harness
        .clock()
        .advance(std::time::Duration::from_secs(120));

    let cookie = open_session_in(&harness, "scim", "tok-p2", &org).await;
    let scope = harness.scope();
    let path = format!(
        "/t/{}/e/{}/portal/s/scim",
        scope.tenant(),
        scope.environment()
    );
    let (status, body) = get_with_cookie(&harness, &path, Some(&cookie)).await;
    assert_eq!(status, 200, "the provisioning page: {body}");

    // PER ROW, not per page: asserting that the page contains "Stops working" somewhere would be
    // satisfied by any one of the four rows carrying it, including the wrong one.
    let row = |name: &str| -> String {
        let cell = format!("<td>{name}</td>");
        let at = body
            .find(&cell)
            .unwrap_or_else(|| panic!("no row for {name}: {body}"));
        let rest = &body[at..];
        let end = rest.find("</tr>").unwrap_or(rest.len());
        rest[..end].to_owned()
    };

    assert!(
        row("never-expires").contains("Active") && !row("never-expires").contains("until"),
        "a connection with no deadline is not plainly active: {}",
        row("never-expires")
    );
    assert!(
        row("lapses-in-twenty-days").contains("Stops working"),
        "a connection lapsing twenty days out, under a THIRTY-day configured lead, is not \
         reported as stopping -- the page is reading a lead it was not given: {}",
        row("lapses-in-twenty-days")
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
        row("lapses-in-twenty-days").contains(&rendered(now + 20 * day)),
        "the warned row does not carry the date it is counting down to: {}",
        row("lapses-in-twenty-days")
    );
    assert!(
        row("lapses-in-forty-days").contains("Active until")
            && row("lapses-in-forty-days").contains(&rendered(now + 40 * day)),
        "a live connection whose deadline is OUTSIDE the thirty-day lead must read Active until \
         that date, which is the state an admin plans around: {}",
        row("lapses-in-forty-days")
    );
    assert!(
        !row("lapses-in-forty-days").contains("Stops working"),
        "a deadline outside the lead is reported as imminent, so the lead bounds nothing: {}",
        row("lapses-in-forty-days")
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
    assert!(
        !row("credentials-gone").contains("Stops working"),
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
#[tokio::test]
async fn a_list_longer_than_the_page_says_so() {
    let harness = Harness::start_store_backed().await;
    let org = seed_org(&harness, "Acme").await;
    for index in 0..101 {
        connect(&harness, &org, &format!("conn-{index:03}"), &format!("tok-{index}"), None).await;
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
