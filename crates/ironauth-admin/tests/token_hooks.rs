// SPDX-License-Identifier: MIT OR Apache-2.0

//! WASM token hook management over HTTP (issue #114, criterion 5).
//!
//! # Why this file exists
//!
//! Review found that nothing observed the deploy PERSISTING anything: the unit tests exercise
//! `validate_component` below HTTP, and the sweeps only ask whether the environment is fenced,
//! so deleting the store write from the handler left the whole suite green. A management
//! surface whose write nothing checks is the same defect this surface was built to close --
//! `token_hooks` having no production writer -- moved one level up.
//!
//! So these drive the real router, and then read the real table.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use sqlx::Row as _;

/// The eight-byte preamble of a WebAssembly component: `\0asm` then the layer word.
const COMPONENT: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

/// What `token_hooks.component_bounded` permits, and what the handler's own constant says.
const MAX_COMPONENT_BYTES: usize = 8 * 1024 * 1024;

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn hook_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/applications/{client}/token-hook")
}

/// The stored component's length and payload version, read from the table itself.
async fn stored(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    client: &str,
) -> Option<(i32, i32)> {
    sqlx::query(
        "SELECT octet_length(component) AS n, payload_version FROM token_hooks \
         WHERE tenant_id = $1 AND environment_id = $2 AND client_id = $3",
    )
    .bind(tenant)
    .bind(environment)
    .bind(client)
    .fetch_optional(harness.db().owner_pool())
    .await
    .expect("read token_hooks")
    .map(|row| (row.get("n"), row.get("payload_version")))
}

/// The deploy WRITES, the read reports what was written, and the delete REMOVES.
///
/// Every assertion here reads the table or the handler's own response rather than trusting a
/// status code: deleting the store write from the handler must fail this, which is precisely
/// what it did not do before this file existed.
#[tokio::test]
async fn deploy_read_delete_lifecycle_actually_persists() {
    let harness = Harness::start(215).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = hook_path(&tenant, &env, &client);

    let (status, _, body) = harness
        .put_bytes(&format!("{path}?payload_version=1"), COMPONENT)
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    // THE TABLE, not the response. A handler that returned its own view without writing would
    // satisfy the status and the body and fail here.
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(COMPONENT.len()).expect("fits"), 1)),
        "the deploy must store the component it was given"
    );

    // THE SECOND durable write. `set_with_event` takes `Option<&DomainEvent>` and silently
    // does nothing when the builder returns `None` -- which it does for any type the catalog
    // does not know -- so a deploy that announces nothing is indistinguishable from one that
    // announces correctly unless the outbox is read.
    let announced = events_of(&harness, &tenant, &env, "token_hook.deployed").await;
    assert_eq!(
        announced.len(),
        1,
        "the deploy announces itself once: {announced:?}"
    );
    assert_eq!(
        announced[0]["payload"]["client_id"], client,
        "the event names the client whose tokens are now shaped by code"
    );
    assert_eq!(announced[0]["payload"]["component_bytes"], 8);
    // THE POLICY IS ON THE EVENT, so a redeploy that changes only it is distinguishable from
    // the deploy before. Flipping a client to fail-open is the change on this surface a
    // consumer most needs to see, and without this the two events are byte-identical.
    assert_eq!(announced[0]["payload"]["failure_policy"], "fail_closed");
    assert!(
        announced[0]["payload"].get("component").is_none(),
        "the component must never ride on the event: {announced:?}"
    );

    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get: {body}");
    assert!(
        body.contains("\"component_bytes\":8") && body.contains("\"payload_version\":1"),
        "the read reports the stored length and version: {body}"
    );

    let (status, _, _) = harness.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete");
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        None,
        "the delete must remove the row, not just answer 204"
    );
    let (status, _, _) = harness.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "the hook is gone");

    let removed = events_of(&harness, &tenant, &env, "token_hook.deleted").await;
    assert_eq!(
        removed.len(),
        1,
        "the removal announces itself too: {removed:?}"
    );
    assert_eq!(removed[0]["payload"]["client_id"], client);

    // THE THIRD durable write, and the one nothing looked at. Swapping
    // `Action::TokenHookDelete` for `TokenHookSet` in the store leaves the entire suite green,
    // because the action reaches only the `audit_log` row and no test read it -- so an auditor
    // asking "whose tokens STOPPED being shaped by code" would get the wrong answer and
    // nothing would say so.
    assert_eq!(
        audit_targets(&harness, &tenant, &env, "token_hook.set").await,
        vec![client.clone()],
        "the deploy writes one audit row naming the client"
    );
    assert_eq!(
        audit_targets(&harness, &tenant, &env, "token_hook.delete").await,
        vec![client.clone()],
        "and the removal writes its OWN action, not the deploy's"
    );
}

/// The DATA plane can read a hook and cannot write or remove one.
///
/// Migration 0163 widens `ironauth_control` and argues at length for the split it preserves,
/// and nothing tested it: `token_hooks` is named in zero store tests, so the grant that keeps
/// the token-minting plane from installing the code that shapes its own tokens rested entirely
/// on the migration being read correctly. A grant is exactly the kind of thing a later
/// migration widens by accident.
#[tokio::test]
async fn the_data_plane_reads_a_hook_and_cannot_change_one() {
    let harness = Harness::start(221).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));
    let (status, _, _) = harness.put_bytes(&path, COMPONENT).await;
    assert_eq!(status, StatusCode::OK);

    // READS, through the data plane's own store -- the path the issuance dispatch takes. It
    // goes through `begin_scoped`, which sets the scope GUCs the row-level-security policy
    // reads; a raw pool query returns nothing for want of them, which would look like a
    // refused grant and is a different fact entirely.
    let readable = harness
        .store()
        .scoped(scope)
        .token_hooks()
        .get(&client)
        .await
        .expect("the data plane may read a hook");
    assert!(
        readable.is_some(),
        "the issuance path must be able to read the hook it is going to run"
    );

    // And CANNOT change one. Raw statements on the data plane's pool, because the point is the
    // GRANT: privileges are checked before row-level security, so a missing grant is an ERROR
    // rather than an empty result, and only the error proves the split.
    //
    // ALL THREE WRITE VERBS. The doc above says "installing", which is INSERT, and the first
    // version of this loop drove only DELETE and UPDATE -- so the one verb the prose named was
    // the one verb nothing checked. The sibling grant test on `claims_mappings` records
    // exactly that partial-verb gap as its own prior defect.
    //
    // Matched on SQLSTATE 42501 rather than on the message, because a widened INSERT grant
    // would then be refused by row-level security instead ("new row violates row-level
    // security policy"), and a substring match on "permission denied" would report the wrong
    // reason for a real regression.
    for (what, sql) in [
        ("delete", "DELETE FROM token_hooks WHERE client_id = $1"),
        (
            "update",
            "UPDATE token_hooks SET payload_version = 99 WHERE client_id = $1",
        ),
        (
            "insert",
            "INSERT INTO token_hooks (tenant_id, environment_id, client_id, component, \
             payload_version) VALUES ('t', 'e', $1, '\\x0061736d0d000100'::bytea, 1)",
        ),
    ] {
        let error = sqlx::query(sql)
            .bind(&client)
            .execute(harness.db().app_pool())
            .await
            .expect_err("the data plane must not change a hook");
        let code = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default();
        assert_eq!(
            code, "42501",
            "the {what} must be refused by the GRANT (SQLSTATE 42501), not by row-level \
             security: a plane that could change the code shaping its own tokens could strip \
             a security-relevant claim from every token it issues. Got: {error}"
        );
    }
}

/// Every event this surface emits, newest last, as parsed envelopes.
async fn events_of(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    event_type: &str,
) -> Vec<serde_json::Value> {
    sqlx::query(
        "SELECT payload FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = $3 \
         ORDER BY sequence",
    )
    .bind(tenant)
    .bind(environment)
    .bind(event_type)
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read the outbox")
    .iter()
    .map(|row| row.get::<serde_json::Value, _>("payload"))
    .collect()
}

/// A REDEPLOY replaces in place rather than accumulating rows.
#[tokio::test]
async fn a_redeploy_replaces_the_component() {
    let harness = Harness::start(216).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));

    let (status, _, _) = harness.put_bytes(&path, COMPONENT).await;
    assert_eq!(status, StatusCode::OK);

    let mut longer = COMPONENT.to_vec();
    longer.extend_from_slice(b"more of a component");
    let (status, _, body) = harness.put_bytes(&path, &longer).await;
    assert_eq!(status, StatusCode::OK, "redeploy: {body}");

    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(longer.len()).expect("fits"), 1)),
        "one row per client, replaced in place"
    );
}

/// A component AT the documented bound is stored, which is what crosses the handler's constant
/// with the table's CHECK.
///
/// The unit test beside `MAX_COMPONENT_BYTES` reads that constant and never reads the
/// migration, so it would pass with both numbers wrong in the same direction. This one puts
/// exactly that many bytes through the real handler into the real table: if the two disagree,
/// the insert fails.
///
/// It also proves the route's body limit was lifted. axum's default is 2 MiB, so without the
/// `DefaultBodyLimit` layer this is a framework 413 long before the handler or the database
/// sees it.
#[tokio::test]
async fn a_component_at_the_documented_bound_is_stored() {
    let harness = Harness::start(217).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));

    let mut at_bound = COMPONENT.to_vec();
    at_bound.resize(MAX_COMPONENT_BYTES, 0);
    let (status, _, body) = harness.put_bytes(&path, &at_bound).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the handler's bound and the table's CHECK must admit the same size: {body}"
    );
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(MAX_COMPONENT_BYTES).expect("fits"), 1))
    );

    let mut over = at_bound;
    over.push(0);
    let (status, _, body) = harness.put_bytes(&path, &over).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "one byte over is this API's 400, not a framework 413: {body}"
    );
    assert!(
        body.contains("component_too_large"),
        "named refusal: {body}"
    );
}

/// An ABSENT `payload_version` is this API's refusal too, not the framework's.
///
/// This is the half a bare `String` left behind. A malformed value was parsed in the handler
/// and refused properly, but an absent one still failed inside `Query<T>` -- axum's plain-text
/// 400, no `ErrorBody`, raised before `require_permission`, `require_fresh_privilege` and
/// `require_live_environment`, so a request with no query string answered that instead of the
/// uniform not-found this surface owes at an absent environment. The field is an `Option` now.
///
/// It lives here rather than in `absent_environment.rs` because that sweep permits exactly one
/// case per documented operation, and the shape of the refusal is what matters anyway.
#[tokio::test]
async fn an_absent_payload_version_is_this_apis_refusal() {
    let harness = Harness::start(220).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);

    let (status, _, body) = harness
        .put_bytes(&hook_path(&tenant, &env, &client), COMPONENT)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "no query string: {body}");
    assert!(
        body.contains("unknown_payload_version"),
        "an absent version must be this API's named refusal with an ErrorBody, not axum's \
         plain-text extractor rejection: {body}"
    );

    // And at an ABSENT environment the same request is the uniform not-found, which is the
    // contract the extractor rejection was breaking.
    //
    // GENERATED, not a hand-written literal. The first version used
    // `env_00000000000000000000000000`, whose body is 26 characters and therefore not a
    // 16-byte id at all: it died in `parse_id` one line before `exists_in_any_state`, so the
    // branch this comment names was never driven. A well-formed id that names nothing is what
    // reaches the existence check.
    let absent_environment =
        ironauth_store::EnvironmentId::generate(&ironauth_env::Env::system()).to_string();
    let (status, _, body) = harness
        .put_bytes(&hook_path(&tenant, &absent_environment, &client), COMPONENT)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an absent environment answers the uniform not-found even with no query string: {body}"
    );
}

/// A core MODULE is refused over HTTP, with the named reason, and nothing is stored.
#[tokio::test]
async fn a_core_module_is_refused_over_http_and_stores_nothing() {
    let harness = Harness::start(218).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));

    let module: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let (status, _, body) = harness.put_bytes(&path, module).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "core module: {body}");
    assert!(
        body.contains("core_module_not_component"),
        "the refusal names WHICH mistake it is, so an operator checks their build command \
         rather than their bytes: {body}"
    );
    assert_eq!(stored(&harness, &tenant, &env, &client).await, None);
}

/// An unknown payload version is refused with this API's error shape, not the framework's.
///
/// Both spellings: a value this build cannot honour, and a value that is not a number at all.
/// The second is why the query parameter is a `String` -- typed `u32` it would be an axum
/// extractor rejection, which is plain text, carries no `ErrorBody`, and happens before the
/// permission check.
#[tokio::test]
async fn a_bad_payload_version_is_this_apis_refusal() {
    let harness = Harness::start(219).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    for version in ["99", "banana"] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version={version}"), COMPONENT)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "version {version}: {body}");
        assert!(
            body.contains("unknown_payload_version"),
            "version {version} must be this API's named refusal: {body}"
        );
        assert_eq!(stored(&harness, &tenant, &env, &client).await, None);
    }
}

/// The audit targets this scope holds for `action`, oldest first.
async fn audit_targets(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    action: &str,
) -> Vec<String> {
    sqlx::query(
        "SELECT target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = $3 ORDER BY id",
    )
    .bind(tenant)
    .bind(environment)
    .bind(action)
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read the audit log")
    .iter()
    .map(|row| row.get::<String, _>("target_id"))
    .collect()
}

/// The FAILURE POLICY round-trips, defaults to fail-closed, and refuses an unknown spelling.
///
/// The default is the load-bearing half. Fail-open means minting a token the operator's own
/// hook did not shape -- and because a hook's answer REPLACES the claim set, a hook deployed to
/// STRIP a claim that fails open issues a token still carrying it. So the dangerous setting has
/// to be the one an operator types, and a deploy that says nothing must get the safe one.
#[tokio::test]
async fn the_failure_policy_round_trips_and_defaults_to_fail_closed() {
    let harness = Harness::start(223).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // Says nothing -> fail-closed.
    let (status, _, body) = harness
        .put_bytes(&format!("{base}?payload_version=1"), COMPONENT)
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");
    assert!(
        body.contains("\"failure_policy\":\"fail_closed\""),
        "a deploy that names no policy reads back as the safe one: {body}"
    );

    // Asks for fail-open -> stored and read back.
    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&failure_policy=fail_open"),
            COMPONENT,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "redeploy: {body}");
    let (status, _, body) = harness.get(&base).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("\"failure_policy\":\"fail_open\""),
        "the read reports the stored policy: {body}"
    );

    // A TYPO IS REFUSED rather than read as the default. Silently selecting the safe answer
    // would be indistinguishable from asking for it, and an operator whose `fail-open` did
    // nothing would never learn.
    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&failure_policy=fail-open"),
            COMPONENT,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a typo is refused: {body}");
    assert!(
        body.contains("unknown_failure_policy"),
        "named refusal: {body}"
    );
}

/// A REAL component, built by a compiler, is accepted -- and its first eight bytes are the
/// preamble this crate hard-codes.
///
/// Everything else about that constant is self-referential: `COMPONENT_PREAMBLE` is checked
/// against test inputs written by copying it, so a wrong constant would be a feature that
/// rejects every genuine deploy while the whole suite stayed green. This is the only assertion
/// in the tree that crosses it with an artifact a compiler actually produced --
/// `ironauth_hooks::fixtures::GOOD` comes out of that crate's `build.rs`.
#[tokio::test]
async fn a_real_compiled_component_is_accepted() {
    let component = ironauth_hooks::fixtures::GOOD;
    assert!(
        component.len() > 8,
        "the fixture must be a real artifact, not a stub"
    );

    let harness = Harness::start(222).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let path = format!("{}?payload_version=1", hook_path(&tenant, &env, &client));

    let (status, _, body) = harness.put_bytes(&path, component).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a component this project's own build produced must deploy; a 400 here means the \
         hard-coded preamble is wrong and every real deploy is refused: {body}"
    );
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(component.len()).expect("fits"), 1))
    );
}
