// SPDX-License-Identifier: MIT OR Apache-2.0

//! An organization-owned client issues tokens with the organization's lifetime, behind the
//! experimental flag (issue #103, bet 1, criterion 1), against a real Postgres.
//!
//! Three things have to hold together for the criterion to mean anything, and each is
//! measured here rather than argued:
//!
//!   1. With the flag OFF nothing changes, for a client that already carries an owner and
//!      whose owner already states a lifetime. That is criterion 2, and it is only worth
//!      believing when the same fixture is measured in both flag states.
//!   2. With the flag ON the organization's lifetime NARROWS the token. Never lengthens
//!      it: an organization stating a day gets the environment's five minutes.
//!   3. The lifetime the response ADVERTISES is the lifetime the token actually has. The
//!      narrowing lives in `resolve_access_token_target` for exactly this reason; applied
//!      at the mint instead, `expires_in` would be computed from the un-narrowed target
//!      and the client would be told a number that is not true.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use ironauth_store::{
    ActorRef, AuthPolicy, CorrelationId, NewResourceServer, OrganizationId, ResourceServerId,
    ServiceId, TokenFormat,
};

/// The environment's own access-token lifetime under the default config, in seconds. Every
/// expectation below is stated against this so a config change surfaces as a failure here
/// rather than as a test that quietly measures nothing.
const ENVIRONMENT_TTL_SECS: u64 = 300;

/// Seed an organization stating `access_token_ttl_secs` and hand the harness client to it.
async fn own_the_client(harness: &Harness, ttl_secs: Option<u32>) -> OrganizationId {
    let org = harness
        .seed_unjoined_org(AuthPolicy {
            access_token_ttl_secs: ttl_secs,
            ..AuthPolicy::default()
        })
        .await;
    harness
        .db()
        .control_store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(harness.env())),
            CorrelationId::generate(harness.env()),
        )
        .clients()
        .set_owning_organization(harness.env(), harness.client_id(), Some(&org))
        .await
        .expect("hand the client to the organization");
    org
}

/// The resolved access-token lifetime for the harness client with no resource targeted.
async fn resolved_ttl(harness: &Harness) -> Duration {
    harness
        .state()
        .resolve_access_token_target(&harness.scope(), &[], &harness.client_id().to_string())
        .await
        .expect("the target resolves")
        .ttl
}

/// Criterion 1, and criterion 2's control: the SAME owned client, the SAME organization
/// policy, measured with the flag off and then on.
#[tokio::test]
async fn the_organizations_lifetime_applies_only_once_the_flag_is_armed() {
    let mut harness = Harness::start().await;
    own_the_client(&harness, Some(60)).await;

    assert_eq!(
        resolved_ttl(&harness).await,
        Duration::from_secs(ENVIRONMENT_TTL_SECS),
        "with the flag off an owned client keeps the environment lifetime, so migration \
         0121 and a stated organization policy together change nothing"
    );

    harness.enable_org_scoped_clients();
    assert_eq!(
        resolved_ttl(&harness).await,
        Duration::from_secs(60),
        "with the flag armed the organization's lifetime applies"
    );
}

/// An organization can only SHORTEN. Stating a longer lifetime than the environment's
/// leaves the environment's in place.
///
/// This is the direction that matters: if the innermost opinion simply won, an
/// organization could hand itself day-long tokens in an environment that deliberately
/// issues five-minute ones, which inverts the control.
#[tokio::test]
async fn an_organization_can_shorten_a_token_and_can_never_lengthen_one() {
    let mut harness = Harness::start().await;
    own_the_client(&harness, Some(86_400)).await;
    harness.enable_org_scoped_clients();

    assert_eq!(
        resolved_ttl(&harness).await,
        Duration::from_secs(ENVIRONMENT_TTL_SECS),
        "an organization stating a DAY must not lengthen a five-minute environment token"
    );
}

/// The organization's lifetime folds with the resource server's by the same rule, so the
/// shortest of the three wins whichever one it is.
#[tokio::test]
async fn the_shortest_of_environment_resource_server_and_organization_wins() {
    let mut harness = Harness::start().await;
    own_the_client(&harness, Some(120)).await;
    harness.enable_org_scoped_clients();

    // A resource server SHORTER than the organization: the resource server wins.
    register_resource_server(&harness, "https://api.example/short", 30).await;
    let short = harness
        .state()
        .resolve_access_token_target(
            &harness.scope(),
            &["https://api.example/short".to_owned()],
            &harness.client_id().to_string(),
        )
        .await
        .expect("the target resolves");
    assert_eq!(short.ttl, Duration::from_secs(30));

    // A resource server LONGER than the organization: the organization wins. Without this
    // case the fold could be dropped entirely from the resource branch and the test above
    // would still pass, because the resource server was already the shortest.
    register_resource_server(&harness, "https://api.example/long", 600).await;
    let long = harness
        .state()
        .resolve_access_token_target(
            &harness.scope(),
            &["https://api.example/long".to_owned()],
            &harness.client_id().to_string(),
        )
        .await
        .expect("the target resolves");
    assert_eq!(
        long.ttl,
        Duration::from_secs(120),
        "the organization narrows a resource server that asked for longer"
    );
}

/// An environment-owned client is untouched with the flag ARMED.
///
/// The control for the whole feature: arming it must not change the lifetime of a client
/// that never acquired an owner, which is every client in every existing deployment.
#[tokio::test]
async fn an_environment_owned_client_is_untouched_by_the_armed_flag() {
    let mut harness = Harness::start().await;
    // An organization exists and states a short lifetime; the client is simply not its.
    harness
        .seed_unjoined_org(AuthPolicy {
            access_token_ttl_secs: Some(15),
            ..AuthPolicy::default()
        })
        .await;
    harness.enable_org_scoped_clients();

    assert_eq!(
        resolved_ttl(&harness).await,
        Duration::from_secs(ENVIRONMENT_TTL_SECS),
        "an unowned client must not pick up some other organization's lifetime"
    );
}

/// An owner that states NO lifetime narrows nothing.
///
/// The `None` case is separate from the unowned case and can fail on its own: a fold that
/// treated an absent value as zero, or that read the policy row's presence rather than its
/// field, would issue an immediately-expired token here.
#[tokio::test]
async fn an_owner_stating_no_lifetime_leaves_the_environments_in_place() {
    let mut harness = Harness::start().await;
    own_the_client(&harness, None).await;
    harness.enable_org_scoped_clients();

    assert_eq!(
        resolved_ttl(&harness).await,
        Duration::from_secs(ENVIRONMENT_TTL_SECS),
        "an organization that states no token lifetime states nothing"
    );
}

/// The advertised `expires_in` is the narrowed lifetime, over a real code exchange.
///
/// This is the test that pins WHERE the fold lives. `expires_in` and the token's own `exp`
/// are both computed from `target.ttl`; narrowing at the mint alone would leave this
/// reading 300 while the token expired after 60.
#[tokio::test]
async fn the_advertised_lifetime_is_the_narrowed_one() {
    let mut harness = Harness::start().await;
    own_the_client(&harness, Some(60)).await;
    harness.enable_org_scoped_clients();

    let client_id = harness.client_id().to_string();
    let cookie = harness.authenticated_cookie().await;
    let (status, headers, body) = harness
        .authorize_with_cookie(
            &format!(
                "response_type=code&client_id={client_id}&redirect_uri={}&state=xyz&\
                 nonce=n-103&scope={}&code_challenge={PKCE_CHALLENGE}&\
                 code_challenge_method=S256",
                enc(REDIRECT_URI),
                enc("openid profile"),
            ),
            &cookie,
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    let (status, _, body) = harness
        .token(&form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", PKCE_VERIFIER),
        ]))
        .await;
    assert_eq!(status, StatusCode::OK, "token exchange: {body}");
    assert_eq!(
        json(&body)["expires_in"],
        60,
        "the response must advertise the lifetime the token actually has"
    );
}

/// Register a resource server with its own access-token lifetime.
async fn register_resource_server(harness: &Harness, audience: &str, ttl_secs: i64) {
    let env = harness.env();
    let id = ResourceServerId::generate(env, &harness.scope());
    harness
        .store()
        .scoped(harness.scope())
        .acting(
            ActorRef::service(ServiceId::generate(env)),
            CorrelationId::generate(env),
        )
        .resource_servers()
        .register(
            env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: TokenFormat::AtJwt,
                access_token_ttl_secs: Some(ttl_secs),
            },
        )
        .await
        .expect("register resource server");
}

/// A soft-deleted owner goes on narrowing.
///
/// Pinned because it is a DECISION rather than an accident. `document_for_org` filters on
/// the policy row's `deleted_at` and not the organization's, so removing an organization
/// while its clients still point at it leaves the shortening in place. The alternative,
/// falling back to the environment lifetime, would let an ordinary administrative act
/// silently LENGTHEN live credentials.
#[tokio::test]
async fn removing_the_owning_organization_never_lengthens_its_clients_tokens() {
    let mut harness = Harness::start().await;
    let org = own_the_client(&harness, Some(60)).await;
    harness.enable_org_scoped_clients();
    assert_eq!(resolved_ttl(&harness).await, Duration::from_secs(60));

    harness
        .db()
        .control_store()
        .management()
        .acting(
            ActorRef::service(ServiceId::generate(harness.env())),
            CorrelationId::generate(harness.env()),
        )
        .organizations(harness.scope())
        .delete(harness.env(), &org)
        .await
        .expect("soft delete the organization");

    assert_eq!(
        resolved_ttl(&harness).await,
        Duration::from_secs(60),
        "deleting the owner must not hand its clients longer-lived tokens"
    );
}
