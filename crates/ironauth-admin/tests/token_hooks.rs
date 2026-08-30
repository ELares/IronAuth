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
use ironauth_env::Env;
use ironauth_store::{EnvironmentId, Scope, TenantId};
use sqlx::Row as _;

/// The eight-byte preamble of a WebAssembly component: `\0asm` then the layer word.
const COMPONENT: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];

/// Epoch MICROSECONDS at 2020-01-01 and 2100-01-01.
///
/// A window, not a floor, and in the unit the field is documented in. `created_at_unix_micros`
/// was asserted only as `> 0`, which every wrong unit satisfies: seconds since the epoch is
/// about 1.7e9 and milliseconds about 1.7e12, three and six orders of magnitude below a
/// microsecond value. Bounding both sides in micros is what makes the unit observable.
const MICROS_2020: i64 = 1_577_836_800_000_000;
const MICROS_2100: i64 = 4_102_444_800_000_000;

/// What `token_hooks.component_bounded` permits, and what the handler's own constant says.
///
/// A THIRD, INDEPENDENT COPY, and it must stay one: importing the handler's constant would
/// make `a_component_at_the_documented_bound_is_stored` agree with the source by construction,
/// and that test's whole job is to write exactly this many bytes through the real handler into
/// the real table so a source/schema disagreement is a failed insert. Three copies that a test
/// crosses beat one copy that nothing checks against the database.
const MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;

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

    // THE HISTORY TABLE IS INVISIBLE TO IT ENTIRELY -- not even SELECT.
    //
    // 0165 grants `token_hook_versions` to the control plane alone and says so, and nothing
    // tested it: the table was named in zero tests, so a later `GRANT SELECT ... TO
    // ironauth_app` would leave every test passing while handing the data plane the component
    // bytes of up to twenty historical hooks per client -- including ones deliberately
    // withdrawn. Nothing on the issuance path reads history, so the honest grant is none.
    let history = sqlx::query("SELECT 1 FROM token_hook_versions WHERE client_id = $1")
        .bind(&client)
        .fetch_optional(harness.db().app_pool())
        .await
        .expect_err("the data plane must not read hook history");
    assert_eq!(
        history
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default(),
        "42501",
        "refused by the GRANT, not by row-level security: {history}"
    );

    // And CANNOT change the ACTIVE hook either. Raw statements on the data plane's pool,
    // because the point is the GRANT: privileges are checked before row-level security, so a
    // missing grant is an ERROR rather than an empty result, and only the error proves it.
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
    // THE RESPONSE IS AN ECHO of the handler's own local, so it proves nothing about what was
    // STORED. The GET reads the row back, which is the assertion that would fail if the write
    // dropped the policy on the floor.
    let (status, _, stored_body) = harness.get(&base).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        stored_body.contains("\"failure_policy\":\"fail_closed\""),
        "and the STORED row says so too, not just the response: {stored_body}"
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

/// Every deploy appends a VERSION, and a rollback makes an earlier one active again.
///
/// Issue #114 criterion 5's versioned-deploy and rollback halves. `token_hooks` holds one row
/// and a redeploy overwrites it, so before the history table there was nothing to roll back TO
/// -- the previous component was gone the moment the next one landed.
#[tokio::test]
async fn deploys_are_versioned_and_a_rollback_restores_an_earlier_one() {
    let harness = Harness::start(226).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // v1: the bare preamble. v2: something longer, so the two are distinguishable by LENGTH
    // rather than by a number this test also supplies.
    let mut second = COMPONENT.to_vec();
    second.extend_from_slice(b"the second deploy");
    let mut third = COMPONENT.to_vec();
    third.extend_from_slice(b"the third deploy, which is longer still");
    let (status, _, body) = harness
        .put_bytes(&format!("{base}?payload_version=1"), COMPONENT)
        .await;
    assert_eq!(status, StatusCode::OK, "v1: {body}");
    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&failure_policy=fail_open"),
            &second,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "v2: {body}");
    let (status, _, body) = harness
        .put_bytes(&format!("{base}?payload_version=1"), &third)
        .await;
    assert_eq!(status, StatusCode::OK, "v3: {body}");

    // TWO VERSIONS, newest first, and each remembers what it was deployed WITH -- the policy
    // included, which is what makes a rollback restore a configuration rather than just bytes.
    let (status, _, body) = harness.get(&format!("{base}/versions")).await;
    assert_eq!(status, StatusCode::OK, "versions: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("versions parse");
    let listed = listed.as_array().expect("an array");
    assert_eq!(listed.len(), 3, "one version per deploy: {body}");
    assert_eq!(listed[0]["version"], 3, "newest first");
    assert_eq!(listed[0]["component_bytes"], third.len());
    assert_eq!(listed[1]["version"], 2);
    assert_eq!(listed[1]["component_bytes"], second.len());
    assert_eq!(
        listed[1]["failure_policy"], "fail_open",
        "each version remembers the policy it was deployed WITH, which is what makes a \
         rollback restore a configuration rather than just bytes: {body}"
    );
    assert_eq!(listed[2]["version"], 1);
    assert_eq!(listed[2]["component_bytes"], COMPONENT.len());
    assert_eq!(listed[2]["failure_policy"], "fail_closed");
    // A version records WHEN, because "what did it look like before" is a question about time.
    //
    // BOUNDED ON BOTH SIDES AND IN THE RIGHT UNIT. `> 0` was the assertion here, and every
    // wrong unit satisfies it: seconds since the epoch is about 1.7e9, milliseconds about
    // 1.7e12, and the field is documented as MICROSECONDS, about 1.7e15. The floor is
    // 2020-01-01 in micros and the ceiling is 2100-01-01, so a seconds or millisecond value
    // lands three orders of magnitude below the floor and fails.
    let recorded = listed[0]["created_at_unix_micros"]
        .as_i64()
        .expect("an integer timestamp");
    assert!(
        (MICROS_2020..MICROS_2100).contains(&recorded),
        "created_at_unix_micros must be epoch MICROSECONDS, and {recorded} is not in \
         [{MICROS_2020}, {MICROS_2100}): {body}"
    );
    assert!(
        listed.iter().all(|v| v.get("component").is_none()),
        "the list must not carry components; five versions would be a forty-megabyte answer"
    );

    // ROLL BACK to v2 -- the MIDDLE version. The active row becomes v2's component AND v2's
    // policy, which is `fail_open`: a rollback restores the configuration, not just the bytes.
    //
    // Targeting the middle one is what makes this able to fail. Mutation hardcoded the lookup
    // to version 1 and the test stayed green, because it only ever rolled back to v1.
    let (status, _, body) = harness
        .post(
            &format!("{base}/rollback"),
            "k-rollback-2",
            r#"{"version":2}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "rollback: {body}");
    assert!(
        body.contains(&format!("\"component_bytes\":{}", second.len()))
            && body.contains("\"failure_policy\":\"fail_open\""),
        "the response reports what is NOW RUNNING, read back from the row rather than echoed \
         from the request -- which carried neither of these numbers: {body}"
    );
    assert_eq!(
        stored(&harness, &tenant, &env, &client).await,
        Some((i32::try_from(second.len()).expect("fits"), 1)),
        "the ACTIVE row is v2's component"
    );

    // AND THE HISTORY GREW. A rollback is a deploy of an older component, so it appends rather
    // than rewinding: three deploys then a rollback to v2 leaves FOUR versions, where v4
    // carries v2's bytes. Rewinding a pointer instead would make "version 2" mean two
    // different components depending on when you asked.
    //
    // (This comment said "v1, v2, v3 -- where v3 is v1's bytes", which contradicted both
    // assertions immediately below it: the count is four and the newest carries v2's bytes,
    // not v1's.)
    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("versions parse");
    let listed = listed.as_array().expect("an array");
    assert_eq!(listed.len(), 4, "the rollback appended: {body}");
    assert_eq!(listed[0]["version"], 4);
    assert_eq!(
        listed[0]["component_bytes"],
        second.len(),
        "v4 is v2's bytes, recorded as its own deploy rather than rewinding v2 -- so a version \
         number never means two different components: {body}"
    );
}

/// THE PUBLISHED CAP IS THE REAL CAP.
///
/// `listTokenHookVersions`'s 200 description says "At most 20", because an API consumer cannot
/// resolve a Rust constant name and the previous wording ("the history is capped") told them
/// nothing they could plan against. A number written into a doc attribute is a number that
/// will disagree with the constant beside it, so this reads BOTH: the constant that the prune
/// actually binds, and the description in the committed OpenAPI document that clients read.
///
/// It fails if either moves without the other. Changing `TOKEN_HOOK_VERSION_RETENTION` and
/// regenerating leaves the description saying 20; changing the description alone leaves it
/// disagreeing with the prune.
#[test]
fn the_published_version_cap_matches_the_retention_the_prune_enforces() {
    let document = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/openapi/management.json"
    ))
    .expect("the committed OpenAPI document");
    let document: serde_json::Value = serde_json::from_str(&document).expect("parse");

    // Located by OPERATION ID rather than by path, so a route move does not silently turn this
    // into a test of nothing.
    let description = document["paths"]
        .as_object()
        .expect("paths")
        .values()
        .filter_map(|item| item.get("get"))
        .find(|op| op["operationId"] == "listTokenHookVersions")
        .map(|op| op["responses"]["200"]["description"].to_string())
        .expect("listTokenHookVersions must be in the published document");

    let retention = ironauth_store::TOKEN_HOOK_VERSION_RETENTION;
    // THE NUMBER MUST END WHERE THE RETENTION ENDS. `contains("At most 20")` was the first
    // version of this and it is satisfied by "At most 200" and "At most 2000" -- so the
    // document could drift an order of magnitude upward while the test reported agreement,
    // which is the exact direction the doc comment above claims to catch.
    let phrase = format!("At most {retention}");
    let Some((_, after)) = description.split_once(&phrase) else {
        panic!(
            "the published cap and the retention the prune enforces disagree. The prune \
             keeps {retention}; the document says: {description}"
        )
    };
    assert!(
        !after.starts_with(|c: char| c.is_ascii_digit()),
        "the document says a LONGER number than the retention: the prune keeps {retention} \
         and the description reads: {description}"
    );
}

/// A ROLLBACK THAT CHANGES NOTHING WRITES NOTHING, which is what makes retrying one safe.
///
/// This endpoint takes no `Idempotency-Key`, unlike the create-shaped POSTs on this surface.
/// The justification is that a rollback names an existing version rather than minting an
/// identity, so replaying it is inert -- and that is only true if a rollback to what is
/// already running appends no version. Without this the history is SPENDABLE: a client
/// retrying a rollback it already completed (a timeout, a lost response, a doubled click)
/// writes a fresh identical version each time, and `RETENTION` retries delete every real one.
///
/// The retry here is byte-identical, which is what a retry is. The FIRST rollback must still
/// append, or this test would pass against a rollback that never wrote anything at all.
#[tokio::test]
async fn a_repeated_rollback_writes_no_second_version() {
    let harness = Harness::start(231).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    let mut second = COMPONENT.to_vec();
    second.extend_from_slice(b"the second deploy");
    for component in [COMPONENT, second.as_slice()] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1"), component)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy: {body}");
    }

    // Back to v1. This one DOES change the active row, so it appends: two deploys plus one
    // rollback is three versions.
    let (status, _, body) = harness
        .post(&format!("{base}/rollback"), "k-rb-1", r#"{"version":1}"#)
        .await;
    assert_eq!(status, StatusCode::OK, "the first rollback: {body}");
    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed.as_array().expect("array").len(),
        3,
        "a rollback that changes the active row appends, or the retry below proves nothing: \
         {body}"
    );

    // THE RETRY. Same version, same bytes, and v1 is still in the history -- so this is a
    // successful 200 that must nevertheless write nothing.
    let (status, _, body) = harness
        .post(&format!("{base}/rollback"), "k-rb-2", r#"{"version":1}"#)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a retry reports the state it found, not an error: {body}"
    );
    assert!(
        body.contains(&format!("\"component_bytes\":{}", COMPONENT.len())),
        "and it reports what is running, which is still v1's component: {body}"
    );

    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let listed = listed.as_array().expect("array");
    assert_eq!(
        listed.len(),
        3,
        "the retry appended nothing: a rollback to what is already running is inert, which is \
         the entire reason this endpoint needs no Idempotency-Key: {body}"
    );
    assert_eq!(
        listed[0]["version"], 3,
        "and it did not renumber anything either: {body}"
    );
}

/// 0165'S BACKFILL COPIES A LIVE HOOK INTO THE HISTORY, WITH ITS POLICY.
///
/// The migration creates `token_hook_versions` and every test database applies it to an EMPTY
/// schema, so the backfill runs against no rows in every other test in this file. On a real
/// upgrade it runs against every hook already in service, and getting it wrong is invisible
/// here: an empty `INSERT ... SELECT` succeeds whatever its column list says.
///
/// So this drives the real statement, read out of the migration file rather than retyped, over
/// a real deployed hook. The setup deletes the history the deploy wrote, which is exactly the
/// state an upgraded install is in: a live `token_hooks` row and no history beside it.
#[tokio::test]
async fn the_migration_backfill_copies_a_live_hook_into_the_history() {
    let harness = Harness::start(233).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // A hook deployed with a NON-DEFAULT policy, because the backfill copies every column and
    // a version that lost the policy would restore bytes without the configuration.
    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&failure_policy=fail_open"),
            COMPONENT,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "deploy: {body}");

    // Now make it look pre-migration: the active row stays, its history goes.
    sqlx::query("DELETE FROM token_hook_versions WHERE client_id = $1")
        .bind(client.clone())
        .execute(harness.db().owner_pool())
        .await
        .expect("clear the history");
    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body)
            .expect("parse")
            .as_array()
            .expect("array")
            .len(),
        0,
        "the fixture must start with no history, or the backfill below proves nothing: {body}"
    );

    // THE REAL STATEMENT, taken from the migration. Retyping it here would let the two drift
    // and this test would then pass against a backfill that no longer exists.
    let migration = include_str!("../../ironauth-store/migrations/0165_token_hook_versions.sql");
    let backfill = migration
        .split_once("INSERT INTO token_hook_versions")
        .map(|(_, rest)| format!("INSERT INTO token_hook_versions{rest}"))
        .expect("0165 must carry a backfill INSERT");
    sqlx::raw_sql(&backfill)
        .execute(harness.db().owner_pool())
        .await
        .expect("run the backfill");

    let (status, _, body) = harness.get(&format!("{base}/versions")).await;
    assert_eq!(status, StatusCode::OK);
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let listed = listed.as_array().expect("array");
    assert_eq!(
        listed.len(),
        1,
        "the live hook must appear in the history exactly once: {body}"
    );
    assert_eq!(
        listed[0]["version"], 1,
        "the backfilled row is version 1, so the first post-upgrade deploy is 2: {body}"
    );
    assert_eq!(
        listed[0]["component_bytes"],
        COMPONENT.len(),
        "with the live component's bytes: {body}"
    );
    assert_eq!(
        listed[0]["failure_policy"], "fail_open",
        "and the policy it was running WITH, or a rollback restores bytes without the \
         configuration: {body}"
    );

    // AND IT IS ROLLABLE-BACK, which is the point of backfilling at all.
    let (status, _, body) = harness
        .post(
            &format!("{base}/rollback"),
            "k-backfill",
            r#"{"version":1}"#,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the backfilled version must be a valid rollback target: {body}"
    );
}

/// THE NO-OP COMPARES THE COMPONENT, NOT ITS LENGTH, AND IT COMPARES THE POLICY TOO.
///
/// `a_repeated_rollback_writes_no_second_version` pins that an identical rollback is inert,
/// which is the bytes-versus-nothing axis. It cannot see the other two clauses of the guard:
/// every other rollback fixture in this file targets a version differing from the active row
/// in BOTH bytes and length, so a guard comparing only `component.len()` would pass all of
/// them, and so would one that ignored `failure_policy` entirely.
///
/// Two rollbacks here, each varying ONE dimension:
///
/// - EQUAL LENGTH, different bytes. A length comparison calls these the same and skips the
///   write, so the rollback silently does nothing and the operator's hook never changes.
/// - IDENTICAL bytes, different policy. A guard that compared only the component calls these
///   the same, so rolling back to recover a `fail_closed` setting leaves `fail_open` running --
///   which is the configuration half this file already claims a rollback restores.
#[tokio::test]
async fn the_rollback_no_op_compares_the_component_and_the_policy_not_the_length() {
    let harness = Harness::start(232).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);

    // EQUAL LENGTH, DIFFERENT BYTES.
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);
    let mut first = COMPONENT.to_vec();
    first.extend_from_slice(b"AAAA");
    let mut second = COMPONENT.to_vec();
    second.extend_from_slice(b"BBBB");
    assert_eq!(
        first.len(),
        second.len(),
        "the fixture must vary ONE dimension"
    );
    for component in [first.as_slice(), second.as_slice()] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1"), component)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy: {body}");
    }
    let (status, _, body) = harness
        .post(&format!("{base}/rollback"), "k-len", r#"{"version":1}"#)
        .await;
    assert_eq!(status, StatusCode::OK, "rollback: {body}");
    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed.as_array().expect("array").len(),
        3,
        "the rollback must WRITE: v1 and v2 are the same length and different components, so \
         a no-op comparing lengths would skip it and leave v2 running: {body}"
    );

    // IDENTICAL BYTES, DIFFERENT POLICY.
    let policy_client = Harness::fresh_client_id(scope);
    let policy_base = hook_path(&tenant, &env, &policy_client);
    for policy in ["fail_closed", "fail_open"] {
        let (status, _, body) = harness
            .put_bytes(
                &format!("{policy_base}?payload_version=1&failure_policy={policy}"),
                COMPONENT,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "deploy {policy}: {body}");
    }
    let (status, _, body) = harness
        .post(
            &format!("{policy_base}/rollback"),
            "k-pol",
            r#"{"version":1}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "rollback: {body}");
    assert!(
        body.contains("\"failure_policy\":\"fail_closed\""),
        "rolling back must restore the POLICY, and the two versions have identical bytes -- so \
         a no-op comparing only the component would skip the write and leave fail_open: {body}"
    );
    let (_, _, body) = harness.get(&format!("{policy_base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed.as_array().expect("array").len(),
        3,
        "and it must have appended a version: {body}"
    );
}

/// Rolling back to a version this client never had is the uniform not-found, and changes
/// nothing.
#[tokio::test]
async fn a_rollback_to_an_unknown_version_is_not_found_and_changes_nothing() {
    let harness = Harness::start(227).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);
    let (status, _, _) = harness
        .put_bytes(&format!("{base}?payload_version=1"), COMPONENT)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = harness
        .post(
            &format!("{base}/rollback"),
            "k-rollback-99",
            r#"{"version":99}"#,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no such version: {body}");

    // NOT a silent success: reporting one would tell an operator their rollback took effect
    // and turn the endpoint into a probe for how many versions exist.
    let (_, _, body) = harness.get(&format!("{base}/versions")).await;
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed.as_array().expect("array").len(),
        1,
        "a refused rollback appends nothing: {body}"
    );
}

/// A client with no hook lists an EMPTY history rather than a not-found.
///
/// Deliberately unlike `getTokenHook`, where "no hook" and "an empty hook" would be opposite
/// tokens. "Nothing deployed yet" is a complete and common answer to "what have I deployed".
#[tokio::test]
async fn a_client_with_no_hook_lists_no_versions() {
    let harness = Harness::start(228).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);

    let (status, _, body) = harness
        .get(&format!("{}/versions", hook_path(&tenant, &env, &client)))
        .await;
    assert_eq!(status, StatusCode::OK, "an empty history is a 200: {body}");
    assert_eq!(body.trim(), "[]");
}

/// The history is PRUNED to the newest few, and the pruning keeps the newest.
///
/// Without it the history is unbounded: a component may be sixteen megabytes and nothing else
/// deletes these rows, so a client redeployed a thousand times would hold sixteen gigabytes of
/// versions nobody will roll back to. The migration used to claim a retention that did not
/// exist, which is how this got written.
#[tokio::test]
async fn the_version_history_is_pruned_to_the_retention_bound() {
    let harness = Harness::start(229).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // A SECOND CLIENT IN THE SAME ENVIRONMENT, deployed once BEFORE the loop below.
    //
    // Row-level security on `token_hook_versions` scopes tenant and environment and NOT client,
    // so the only thing holding two clients' histories apart is a hand-written
    // `AND client_id = $3` in three statements: the version numbering, the prune, and the list.
    // Every test in this file used exactly one client per environment, and all three predicates
    // could be deleted with the whole file still green -- measured, one mutant each. Without
    // the numbering predicate this client's first deploy is numbered 2; without the list
    // predicate the listing below returns the neighbour's row too; without the prune predicate
    // the loop deletes the neighbour's only version.
    let neighbour = Harness::fresh_client_id(scope);
    let neighbour_base = hook_path(&tenant, &env, &neighbour);
    let mut neighbour_component = COMPONENT.to_vec();
    neighbour_component.extend_from_slice(b"the neighbour");
    let (status, _, body) = harness
        .put_bytes(
            &format!("{neighbour_base}?payload_version=1"),
            &neighbour_component,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the neighbour's only deploy: {body}"
    );

    // Two past the bound, so the assertion is about the BOUND and not about "some pruning
    // happened": exactly `RETENTION` must survive and exactly the newest ones.
    let deploys = usize::try_from(ironauth_store::TOKEN_HOOK_VERSION_RETENTION).expect("fits") + 2;
    for index in 0..deploys {
        let mut component = COMPONENT.to_vec();
        component.extend_from_slice(format!("deploy {index}").as_bytes());
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1"), &component)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy {index}: {body}");
    }

    let (status, _, body) = harness.get(&format!("{base}/versions")).await;
    assert_eq!(status, StatusCode::OK);
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let listed = listed.as_array().expect("array");
    assert_eq!(
        i32::try_from(listed.len()).expect("fits"),
        ironauth_store::TOKEN_HOOK_VERSION_RETENTION,
        "exactly the retention survives, not merely fewer than everything: {body}"
    );

    // THE NEWEST ONES, which is the half that matters. Pruning that kept the OLDEST would also
    // satisfy a count assertion and would throw away every version anyone would roll back to.
    assert_eq!(
        listed[0]["version"],
        i32::try_from(deploys).expect("fits"),
        "the most recent deploy is still there: {body}"
    );
    let oldest_kept =
        deploys - usize::try_from(ironauth_store::TOKEN_HOOK_VERSION_RETENTION).expect("fits") + 1;
    assert_eq!(
        listed[listed.len() - 1]["version"],
        i32::try_from(oldest_kept).expect("fits"),
        "and the window is the newest N, so the oldest survivor is deploys - N + 1: {body}"
    );

    // A SECOND NEIGHBOUR DEPLOY, now that the environment holds twenty-two other versions.
    //
    // This is what makes the neighbour's version number able to fail. The first neighbour
    // deploy went into an EMPTY environment, where `COALESCE(MAX(version), 0) + 1` is 1 with
    // or without the client predicate -- so asserting it is 1 pinned nothing about numbering,
    // and an earlier version of this comment credited it with doing so. This one lands after
    // the loop, so environment-wide numbering would give it 23 rather than 2.
    let mut neighbour_second = COMPONENT.to_vec();
    neighbour_second.extend_from_slice(b"the neighbour again");
    let (status, _, body) = harness
        .put_bytes(
            &format!("{neighbour_base}?payload_version=1"),
            &neighbour_second,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the neighbour's second deploy: {body}"
    );

    // THE NEIGHBOUR IS UNTOUCHED, and each assertion pins a different predicate.
    //
    // `len() == 2` fails without the PRUNE's client predicate -- this client's twenty-two
    // deploys would have taken the neighbour's first row -- and without the LIST's, which
    // would return this client's rows as well. `version == 2` fails without the NUMBERING's,
    // because the deploy above lands into an environment holding twenty-two other versions.
    // The byte counts fail if the list crossed clients.
    let (status, _, body) = harness.get(&format!("{neighbour_base}/versions")).await;
    assert_eq!(status, StatusCode::OK);
    let neighbour_listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let neighbour_listed = neighbour_listed.as_array().expect("array");
    assert_eq!(
        neighbour_listed.len(),
        2,
        "the neighbour deployed twice and this client's twenty-two deploys must not have \
         numbered, listed or pruned across the client boundary: {body}"
    );
    assert_eq!(
        neighbour_listed[0]["version"], 2,
        "version numbering is per CLIENT, not per environment: this deploy followed \
         twenty-two of another client's, and it is the neighbour's second: {body}"
    );
    assert_eq!(
        neighbour_listed[0]["component_bytes"],
        neighbour_second.len(),
        "and the rows listed are the neighbour's own: {body}"
    );
    assert_eq!(
        neighbour_listed[1]["version"], 1,
        "its first deploy survived the other client's pruning: {body}"
    );
    assert_eq!(
        neighbour_listed[1]["component_bytes"],
        neighbour_component.len()
    );
}

/// SEVERAL NAMED HOOKS, READ BACK IN ORDER, AND REARRANGED THROUGH THE API.
///
/// Issue #114 criterion 5 asks that ordering "work through the admin surface", which is three
/// separate things: a deploy has to be able to ADDRESS a hook other than the default, a read has
/// to report the arrangement, and a caller has to be able to CHANGE it without redeploying.
///
/// # What each assertion rules out
///
/// The default position is LAST, and asserting the ordinals rather than only the sequence is
/// what catches an "append" that actually inserts: a chain read back as `[a, b, c]` is the same
/// whether the positions are 0,1,2 or 0,0,0, and the second is a schema violation the unique
/// constraint would have refused -- so seeing the numbers is what says the API and the database
/// agree about what "last" means.
///
/// The REDEPLOY assertion is the one that protects rollback: redeploying `second` with an
/// explicit ordinal of zero must leave it where it is, because a redeploy replaces code and a
/// rollback is a redeploy. Without this a rollback of the hook that runs last would silently
/// make it run first, changing what every other hook is handed.
///
/// The REORDER asserts both halves of what the route returns: the new sequence, and the new
/// ordinals. A response that echoed the request would show the sequence and not the positions.
#[tokio::test]
async fn hooks_are_named_ordered_and_rearranged_through_the_admin_surface() {
    let harness = Harness::start(60).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // THREE HOOKS, none of them naming a position: each must land after the last.
    for name in ["first", "second", "third"] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1&name={name}"), COMPONENT)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy {name}: {body}");
    }

    let (status, _, body) = harness.get(&format!("{base}/chain")).await;
    assert_eq!(status, StatusCode::OK, "read the chain: {body}");
    let chain: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let names: Vec<&str> = chain["hooks"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|hook| hook["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        vec!["first", "second", "third"],
        "absent means LAST, so three deploys run in the order they were made: {body}"
    );
    let ordinals: Vec<i64> = chain["hooks"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|hook| hook["ordinal"].as_i64().expect("an ordinal"))
        .collect();
    assert_eq!(
        ordinals,
        vec![0, 1, 2],
        "and the POSITIONS are distinct and ascending -- a sequence alone cannot tell 0,1,2 \
         from three hooks piled at one position: {body}"
    );

    // A REDEPLOY MUST NOT MOVE A HOOK, which is what a rollback depends on.
    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&name=second&ordinal=0"),
            COMPONENT,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "redeploy second: {body}");
    let (_, _, body) = harness.get(&format!("{base}/chain")).await;
    let chain: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let names: Vec<&str> = chain["hooks"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|hook| hook["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        vec!["first", "second", "third"],
        "a redeploy replaces CODE and must not move a hook, even when it names a position -- \
         a rollback is a redeploy, and one that reordered would change what every later hook \
         is handed: {body}"
    );

    // AND THE REORDER MOVES IT, which is the route that exists for exactly that.
    let (status, _, body) = harness
        .post(
            &format!("{base}/order"),
            "k-order",
            r#"{"order":["third","first","second"]}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "reorder: {body}");
    let chain: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let names: Vec<&str> = chain["hooks"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|hook| hook["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        vec!["third", "first", "second"],
        "the route READS BACK what the chain is, not what was asked for: {body}"
    );
    let ordinals: Vec<i64> = chain["hooks"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|hook| hook["ordinal"].as_i64().expect("an ordinal"))
        .collect();
    assert_eq!(
        ordinals,
        vec![0, 1, 2],
        "and the positions are rewritten, not just the sequence reported: {body}"
    );
}

/// A REORDER MUST NAME THE WHOLE ARRANGEMENT, and a partial one is refused.
///
/// The contract is that the request IS the order. A partial reorder has to say what happens to
/// what it did not name, and every answer surprises someone: shifting the others silently
/// renumbers hooks the caller never mentioned, and leaving them makes a collision the caller
/// cannot see. So a list that is not exactly this client's hook names is refused, and BOTH
/// directions are asserted -- a short list and a list naming a hook that is not deployed --
/// because a check that only counted would pass the second.
#[tokio::test]
async fn a_reorder_that_is_not_the_whole_arrangement_is_refused() {
    let harness = Harness::start(61).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    for name in ["alpha", "beta"] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1&name={name}"), COMPONENT)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy {name}: {body}");
    }

    let (status, _, body) = harness
        .post(
            &format!("{base}/order"),
            "k-short",
            r#"{"order":["alpha"]}"#,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a SHORT list would leave `beta` at a position the caller never chose while they \
         believed they had arranged everything: {body}"
    );

    let (status, _, body) = harness
        .post(
            &format!("{base}/order"),
            "k-unknown",
            r#"{"order":["alpha","gamma"]}"#,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "and a list the right LENGTH naming a hook that is not deployed is refused too, or a \
         count would be the whole check: {body}"
    );

    // THE ARRANGEMENT IS UNCHANGED. A refusal that had already written half the order would be
    // worse than the partial reorder it refuses.
    let (_, _, body) = harness.get(&format!("{base}/chain")).await;
    let chain: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let names: Vec<&str> = chain["hooks"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|hook| hook["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        vec!["alpha", "beta"],
        "a refused reorder writes nothing: {body}"
    );
}

/// THE NAME BOUND AT THE DOOR IS THE COLUMN'S BOUND, IN THE COLUMN'S UNIT.
///
/// `MAX_HOOK_NAME_CHARS` and the CHECK on `token_hooks.name` are two copies of one number, and
/// two copies is how they stop agreeing. The API's copy exists because a database CHECK cannot
/// produce an `ErrorBody`: a constraint violation is a 500 with `23514` in a log, where a
/// refusal at the door is a message the operator reads.
///
/// # The unit is the point
///
/// Postgres `length()` counts CHARACTERS. An earlier version of the handler counted BYTES while
/// its comment claimed to match the column, so the two disagreed on every non-ASCII name -- a
/// forty-character name of three-byte characters is a hundred and twenty bytes, which the
/// column admits and a byte count refuses. This drives a name of exactly the limit in
/// MULTI-BYTE characters, which is the only input that can tell the two units apart: 64
/// characters and 192 bytes. Under a byte bound it is refused; under the column's bound it is
/// deployed.
///
/// One over the limit is refused with this API's 400, which is the other half: a bound nothing
/// exceeds is not observably a bound.
#[tokio::test]
async fn a_hook_name_at_the_column_bound_is_accepted_and_one_past_it_is_refused() {
    let harness = Harness::start(62).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // 64 CHARACTERS, 192 BYTES. The only shape that distinguishes the two units.
    let at_limit: String = std::iter::repeat_n('\u{4e16}', 64).collect();
    assert_eq!(at_limit.chars().count(), 64);
    assert_eq!(at_limit.len(), 192);

    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&name={at_limit}"),
            COMPONENT,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a name at exactly the column's bound must deploy, or the door is stricter than the \
         column it says it matches: {body}"
    );

    let past_limit: String = std::iter::repeat_n('\u{4e16}', 65).collect();
    let (status, _, body) = harness
        .put_bytes(
            &format!("{base}?payload_version=1&name={past_limit}"),
            COMPONENT,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "and one past it is this API's 400 rather than a constraint violation surfacing as a \
         500: {body}"
    );
}

/// EVERY VERB REACHES A NAMED HOOK, not only the one a client had before ordering existed.
///
/// Criterion 5 asks that "versioned deploy, fixture-based draft testing, ordering, per-hook
/// secrets, and rollback all work through the admin surface". Adding names made ordering work
/// and left the other verbs addressing `default` only -- so a client with a second hook could
/// deploy it and arrange it, and then could not list its versions, roll it back, or draft-test
/// it. The criterion would have read as met while being met for one hook per client.
///
/// # Why the versions assertion is the sharp one
///
/// The version SEQUENCE is per hook. Deploying `beta` twice while `alpha` has one deploy must
/// give beta versions 1 and 2 and leave alpha at 1 -- if the numbering were per CLIENT, beta's
/// second deploy would be version 3, and rolling alpha back to "version 1" could restore beta's
/// bytes. Asserting the COUNT and the NUMBERS is what separates those.
#[tokio::test]
async fn versions_rollback_and_draft_runs_all_address_the_named_hook() {
    let harness = Harness::start(63).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    // `alpha` once, `beta` twice.
    for name in ["alpha", "beta", "beta"] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1&name={name}"), COMPONENT)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy {name}: {body}");
    }

    let (status, _, body) = harness.get(&format!("{base}/versions?name=beta")).await;
    assert_eq!(status, StatusCode::OK, "list beta's versions: {body}");
    // A BARE LIST, not an envelope: the route returns `Vec<TokenHookVersionView>`.
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let numbers: Vec<i64> = listed
        .as_array()
        .expect("a list")
        .iter()
        .map(|v| v["version"].as_i64().expect("a version"))
        .collect();
    assert_eq!(
        numbers,
        vec![2, 1],
        "beta has TWO versions, numbered from one: a per-CLIENT sequence would have made its \
         second deploy version 3, and rolling `alpha` back to version 1 could then restore \
         beta's bytes: {body}"
    );

    let (status, _, body) = harness.get(&format!("{base}/versions?name=alpha")).await;
    assert_eq!(status, StatusCode::OK, "list alpha's versions: {body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        listed.as_array().expect("a list").len(),
        1,
        "and alpha's history is its own -- beta's two deploys did not advance it: {body}"
    );

    // A ROLLBACK ADDRESSES THE NAMED HOOK, and does not move it.
    let (status, _, body) = harness
        .post(
            &format!("{base}/rollback?name=beta"),
            "k-roll-beta",
            r#"{"version":1}"#,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "roll beta back: {body}");
    let (_, _, body) = harness.get(&format!("{base}/chain")).await;
    let chain: serde_json::Value = serde_json::from_str(&body).expect("parse");
    let names: Vec<&str> = chain["hooks"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|hook| hook["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        vec!["alpha", "beta"],
        "a rollback restores CODE and must not move a hook: {body}"
    );

    // AND A DRAFT RUN NAMES ONE TOO. The component here is a bare preamble rather than a
    // loadable guest, so the run ABORTS -- which is still the answer to "what would this hook
    // do", and it proves the route resolved the named hook rather than 404ing on it.
    let (status, _, body) = harness
        .post(
            &format!("{base}/test?name=beta"),
            "k-draft-beta",
            &serde_json::json!({ "grant_type": "authorization_code" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a draft run of a NAMED hook must resolve it: a 404 here is the route addressing \
         `default` and not finding this client's beta: {body}"
    );
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["outcome"], "aborted",
        "and it reports what that component does, which for a bare preamble is an abort: {body}"
    );
}

/// A HOOK'S SECRET GRANTS ARE SET, READ AND WITHDRAWN THROUGH THE ADMIN SURFACE.
///
/// Issue #114 criterion 5's per-hook secrets, through the routes an operator uses. The issuance
/// suite proves a granted secret reaches a hook; this proves an operator can arrange that
/// without touching the database.
///
/// # The read returns NAMES, and that is a security property rather than a shape
///
/// A grant records a REFERENCE. The value lives sealed in the environment secret store behind a
/// different repository and the platform key, so this route could not return one if it tried --
/// which is what stops "what may this hook read" ever being one keystroke from disclosing it.
/// The assertion checks the value is absent from the whole body, not just from the field, so a
/// future handler that added it anywhere fails here.
///
/// # Grants are per hook, and the read shows it
///
/// Two hooks, one grant each, and each read returns only its own. A store that keyed grants on
/// the client would return both to both -- which is the arrangement that would let a hook read
/// a key deployed for its neighbour.
#[tokio::test]
async fn hook_secret_grants_are_set_read_and_withdrawn_through_the_admin_surface() {
    const VALUE: &str = "sk_live_do_not_disclose";

    let harness = Harness::start(64).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env);
    let client = Harness::fresh_client_id(scope);
    let base = hook_path(&tenant, &env, &client);

    for name in ["signer", "auditor"] {
        let (status, _, body) = harness
            .put_bytes(&format!("{base}?payload_version=1&name={name}"), COMPONENT)
            .await;
        assert_eq!(status, StatusCode::OK, "deploy {name}: {body}");
    }

    // NOTHING GRANTED to start, which is the deny-by-default this whole capability rests on.
    let (status, _, body) = harness.get(&format!("{base}/secrets?name=signer")).await;
    assert_eq!(status, StatusCode::OK, "read the grants: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["secrets"].as_array().expect("a list").len(),
        0,
        "a freshly deployed hook may read nothing: {body}"
    );

    // A REAL VALUE, so the assertion below is about a secret that EXISTS rather than one
    // nothing could have disclosed. Written through the store rather than the API because this
    // harness has no data-plane connection, and `setSecret` refuses without one -- the
    // management role is deliberately not permitted to write an ordinary secret.
    {
        let store_env = Env::system();
        harness
            .store()
            .scoped(scope)
            .acting(
                harness.test_actor(&store_env),
                ironauth_store::CorrelationId::generate(&store_env),
            )
            .environment_secrets()
            .put_under_platform_key(&store_env, "stripe", VALUE.as_bytes(), None)
            .await
            .expect("provision the secret");
    }

    let (status, _, body) = harness
        .put(&format!("{base}/secrets?name=signer&secret=stripe"), "")
        .await;
    assert_eq!(status, StatusCode::OK, "grant: {body}");
    // AND THE VALUE IS NOWHERE IN THE BODY. Not merely absent from the `secrets` field: a
    // handler that returned it under some other key, or an error path that echoed it, would
    // pass a field-shaped assertion. This is the check that the route reports references.
    assert!(
        !body.contains(VALUE),
        "the response must not carry the secret's VALUE anywhere: {body}"
    );
    let (status, _, body) = harness
        .put(&format!("{base}/secrets?name=auditor&secret=siem"), "")
        .await;
    assert_eq!(status, StatusCode::OK, "grant the other: {body}");

    // EACH HOOK READS ONLY ITS OWN. A store keyed on the client would return both to both.
    for (hook, expected) in [("signer", "stripe"), ("auditor", "siem")] {
        let (_, _, body) = harness.get(&format!("{base}/secrets?name={hook}")).await;
        assert!(
            !body.contains(VALUE),
            "nor may the LISTING carry it: {body}"
        );
        let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
        let names: Vec<&str> = view["secrets"]
            .as_array()
            .expect("a list")
            .iter()
            .map(|v| v.as_str().expect("a name"))
            .collect();
        assert_eq!(
            names,
            vec![expected],
            "{hook} may read its OWN grant and not its neighbour's: {body}"
        );
    }

    // A GRANT TO A HOOK THAT IS NOT DEPLOYED is a 404 an operator can act on, not a constraint
    // violation surfacing as a 500.
    let (status, _, body) = harness
        .put(&format!("{base}/secrets?name=absent&secret=stripe"), "")
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "granting to a hook that does not exist names the missing thing: {body}"
    );

    // AND THE REVOKE, which reads back what is left rather than echoing the request.
    let (status, _, body) = harness
        .delete(&format!("{base}/secrets?name=signer&secret=stripe"))
        .await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");
    let view: serde_json::Value = serde_json::from_str(&body).expect("parse");
    assert_eq!(
        view["secrets"].as_array().expect("a list").len(),
        0,
        "the response says what the hook may read NOW, not what was asked for: {body}"
    );

    // REVOKING WHAT WAS NEVER GRANTED SUCCEEDS. The caller's intent -- this hook must not read
    // that secret -- holds either way, and refusing would make the safe direction the one an
    // operator has to retry.
    let (status, _, body) = harness
        .delete(&format!("{base}/secrets?name=signer&secret=stripe"))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a repeat revoke is not an error: {body}"
    );

    // AND A SECRET NAME IS REQUIRED. An omitted one would have to mean `all of them`, which is
    // not something an operator should be able to say by leaving a parameter out.
    let (status, _, body) = harness.delete(&format!("{base}/secrets?name=signer")).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a revoke with no secret named is refused rather than read as `everything`: {body}"
    );
}
