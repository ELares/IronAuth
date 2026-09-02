// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM surface's authentication and discovery, over the real router (issue #135).
//!
//! # What this file is for
//!
//! `tests/scim_connections.rs` in `ironauth-store` proves the credential resolves its own
//! organization. This file proves the SURFACE uses it: that no route answers without a token,
//! that a token from one scope cannot be repointed at another by editing the part of it that
//! names a scope, and that the discovery documents say what the server actually enforces.
//!
//! Needs a database.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ironauth_env::Env;
use ironauth_scim::ScimLimits;
use ironauth_scim::server::{ScimState, digest_of, mint_token, scim_router};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, NewScimConnection, OrganizationId, ScimConnectionId, Scope};
use tower::ServiceExt as _;

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Seed an organization and a connection, returning the token a caller would present.
async fn seed(db: &TestDatabase, env: &Env, scope: Scope) -> String {
    let org = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &org, now_micros(env), "Globex", None)
        .await
        .expect("create organization");

    let id = ScimConnectionId::generate(env, &scope);
    let token = mint_token(&id, "s3cret-provisioning-material");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_connections()
        .create(
            env,
            NewScimConnection {
                id: &id,
                organization_id: &org,
                display_name: "Okta production",
                provider: "okta",
                token_digest: &digest_of(&token),
                expires_at_unix_micros: None,
            },
        )
        .await
        .expect("create connection");
    token
}

/// Drive one request against the router.
async fn get(
    db: &TestDatabase,
    env: &Env,
    path: &str,
    token: Option<&str>,
) -> (StatusCode, String) {
    let state = ScimState::new(
        db.store().clone(),
        env.clone(),
        ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = scim_router(state)
        .oneshot(builder.body(Body::empty()).expect("request builds"))
        .await
        .expect("router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

const DISCOVERY: [&str; 3] = [
    "/scim/v2/ServiceProviderConfig",
    "/scim/v2/ResourceTypes",
    "/scim/v2/Schemas",
];

#[tokio::test]
async fn no_discovery_route_answers_without_a_credential() {
    // RFC 7644 permits open discovery. This surface does not take that permission: an open
    // endpoint echoing a deployment's configured limits is a free fingerprint of it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed(&db, &env, scope).await;

    for path in DISCOVERY {
        let (status, body) = get(&db, &env, path, None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{path} without a token: {body}"
        );
        // A SCIM error document, not axum's default, so a client parses the refusal.
        assert!(
            body.contains("urn:ietf:params:scim:api:messages:2.0:Error"),
            "{body}"
        );

        // And a token nobody issued answers IDENTICALLY, so a caller cannot tell "no such
        // token" from "no token": the first would confirm that a leaked credential was once
        // real.
        let (unknown_status, unknown_body) =
            get(&db, &env, path, Some("scim_notarealhandle.whatever")).await;
        assert_eq!(unknown_status, status);
        assert_eq!(unknown_body, body, "the two refusals are byte identical");

        // The real token opens it, so the refusals above are the credential check rather than
        // a route that never worked.
        let (ok, ok_body) = get(&db, &env, path, Some(&token)).await;
        assert_eq!(ok, StatusCode::OK, "{path} with a token: {ok_body}");
    }
}

#[tokio::test]
async fn a_token_cannot_be_repointed_at_another_scope() {
    // THE ATTACK THE SELF-SCOPING TOKEN INVITES. The token declares its own scope in its `scim_`
    // half, so the obvious move is to keep the secret and edit the handle to name another
    // tenant. The digest covers the WHOLE token, so editing any part of it changes what is
    // searched for -- and the search runs inside the scope the edited handle names, where that
    // digest does not exist.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let token_a = seed(&db, &env, scope_a).await;
    let _token_b = seed(&db, &env, scope_b).await;

    let (handle_a, secret_a) = token_a.split_once('.').expect("a two-part token");
    // A handle minted in scope B, carrying scope A's secret.
    let foreign_handle = ScimConnectionId::generate(&env, &scope_b).to_string();
    let forged = format!("{foreign_handle}.{secret_a}");
    assert_ne!(forged, token_a);

    let (status, body) = get(&db, &env, DISCOVERY[0], Some(&forged)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a secret repointed at another scope opens nothing: {body}"
    );

    // The unmodified token still works, so the refusal is the edit rather than the secret.
    let (ok, _) = get(&db, &env, DISCOVERY[0], Some(&token_a)).await;
    assert_eq!(ok, StatusCode::OK);
    assert!(
        handle_a.starts_with("scim_"),
        "the handle half is a scoped id"
    );
}

#[tokio::test]
async fn a_revoked_token_stops_opening_the_surface() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed(&db, &env, scope).await;
    let (handle, _) = token.split_once('.').expect("a two-part token");
    let id = ScimConnectionId::parse_in_scope(handle, &scope).expect("the handle parses");

    let (ok, _) = get(&db, &env, DISCOVERY[0], Some(&token)).await;
    assert_eq!(ok, StatusCode::OK, "live before revocation");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_connections()
        .revoke(&env, &id, now_micros(&env))
        .await
        .expect("revoke");

    let (status, _) = get(&db, &env, DISCOVERY[0], Some(&token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked opens nothing");
}

#[tokio::test]
async fn the_discovery_documents_report_what_the_server_enforces() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed(&db, &env, scope).await;

    let (_, config) = get(&db, &env, DISCOVERY[0], Some(&token)).await;
    let config: serde_json::Value = serde_json::from_str(&config).expect("json");
    let limits = ScimLimits::default();
    // The ADVERTISED bulk maximum is the one the validator enforces, read from the same value
    // rather than a literal beside it. A document promising a maximum the server did not
    // honour would be worse than no document.
    assert_eq!(
        config["bulk"]["maxOperations"].as_u64(),
        Some(limits.bulk.max_operations as u64),
        "the advertised bulk maximum is the enforced one: {config}"
    );
    assert_eq!(config["patch"]["supported"], serde_json::json!(true));

    let (_, types) = get(&db, &env, DISCOVERY[1], Some(&token)).await;
    let types: serde_json::Value = serde_json::from_str(&types).expect("json");
    let ids: Vec<&str> = types["Resources"]
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|r| r["id"].as_str())
        .collect();
    assert_eq!(ids, vec!["User", "Group"]);

    let (_, schemas) = get(&db, &env, DISCOVERY[2], Some(&token)).await;
    let schemas: serde_json::Value = serde_json::from_str(&schemas).expect("json");
    let published: Vec<&str> = schemas["Resources"]
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert!(
        published.contains(&"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"),
        "the Enterprise User extension is published, since criterion 2 requires it: {published:?}"
    );

    // Every response carries the SCIM content type, which is what makes a strict client parse
    // them at all.
    for path in DISCOVERY {
        let state = ScimState::new(
            db.store().clone(),
            env.clone(),
            ScimLimits::default(),
            ironauth_store::identifier::UniquenessMode::EnvironmentWide,
        );
        let response = scim_router(state)
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router answers");
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/scim+json"),
            "{path} answers with the SCIM content type"
        );
    }
}

/// Whether a mounted handler answered, for the reachability sweep.
///
/// The discriminator is the CONTENT TYPE, not the status. This surface answers `404` for an
/// absent resource on purpose -- that is the uniform not-found the whole IDOR design rests on
/// -- so "not 404" cannot mean "mounted": a mounted route and an unmounted one would look
/// identical for an id nobody holds. Every handler here answers `application/scim+json`,
/// including on its errors, and axum's own no-route 404 answers no content type at all. That
/// is the only signal that separates them.
async fn answered_by_a_handler(
    db: &TestDatabase,
    env: &Env,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> bool {
    let state = ScimState::new(
        db.store().clone(),
        env.clone(),
        ScimLimits::default(),
        ironauth_store::identifier::UniquenessMode::EnvironmentWide,
    );
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/scim+json");
    let request = match body {
        Some(body) => builder.body(Body::from(body.to_owned())),
        None => builder.body(Body::empty()),
    }
    .expect("request builds");
    let response = scim_router(state)
        .oneshot(request)
        .await
        .expect("router answers");
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/scim+json"))
}

#[tokio::test]
async fn every_advertised_capability_is_reachable_and_every_unadvertised_one_is_not() {
    // THE ASSERTION THE UNIT GUARD CANNOT MAKE. `nothing_is_advertised_that_this_crate_cannot_
    // enforce` compares the document against the names of functions in this crate, which is a
    // fact about the crate rather than about what a caller can reach -- and an audit found it
    // asserting `bulk: supported` justified by `validate_bulk` while `scim_router` mounts no
    // `/Bulk` at all. A client reading that document would batch its provisioning run and get
    // axum's bare 404, not even a SCIM error.
    //
    // So this drives each capability through the REAL router and asks only "did a handler run":
    // anything that is not `404 Not Found` means the route exists, whatever it then decides
    // about the request. That is the weakest question that distinguishes a mounted route from
    // an absent one, and it is deliberately weak -- the behaviour of each route is asserted by
    // its own suite, not here.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let token = seed(&db, &env, scope).await;

    let (status, body) = get(&db, &env, "/scim/v2/ServiceProviderConfig", Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let document: serde_json::Value = serde_json::from_str(&body).expect("the config document");

    // (advertised flag, method, path, body) for every capability the document names.
    let patch_body = r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations":[{"op":"replace","path":"active","value":false}]}"#;
    let probes: Vec<(&str, &str, String, Option<&str>)> = vec![
        (
            "patch",
            "PATCH",
            "/scim/v2/Users/usr_nobody".to_owned(),
            Some(patch_body),
        ),
        (
            "filter",
            "GET",
            "/scim/v2/Users?filter=userName%20eq%20%22a%22".to_owned(),
            None,
        ),
        (
            "bulk",
            "POST",
            "/scim/v2/Bulk".to_owned(),
            Some(
                r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[]}"#,
            ),
        ),
    ];
    for (capability, method, path, request_body) in probes {
        let advertised = document[capability]["supported"]
            .as_bool()
            .unwrap_or_else(|| panic!("{capability} carries a supported flag"));
        let mounted = answered_by_a_handler(&db, &env, method, &path, &token, request_body).await;
        assert_eq!(
            advertised,
            mounted,
            "{capability}: the document says supported={advertised} and the router \
             {} it",
            if mounted { "serves" } else { "does not serve" }
        );
    }

    // BOTH CONTROLS, because the discriminator is the thing most likely to be wrong here.
    //
    // A path nothing mounts must read as unmounted:
    assert!(
        !answered_by_a_handler(&db, &env, "GET", "/scim/v2/Nothing", &token, None).await,
        "an unmounted path must not look like a handler answered"
    );
    // And a MOUNTED route must read as mounted even when it answers 404, which is exactly the
    // case that defeats a status-based discriminator: this id belongs to nobody.
    assert!(
        answered_by_a_handler(&db, &env, "GET", "/scim/v2/Users/usr_nobody", &token, None).await,
        "a mounted route answering its uniform 404 must still read as mounted"
    );
}
