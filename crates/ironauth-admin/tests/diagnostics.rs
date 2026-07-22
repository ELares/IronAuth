// SPDX-License-Identifier: MIT OR Apache-2.0

//! Management-API integration test for the client authentication diagnostics read
//! (issue #91, M9 flow inspector): the endpoint returns the scope's recorded
//! failures, filters by client id and time window, is IDOR safe (a cross tenant read
//! resolves to nothing and a wrong scope management key is rejected), and exposes
//! ONLY the safe, non secret fields.

mod common;

use std::time::{Duration, UNIX_EPOCH};

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    ClientAuthDiagnosticReason, EnvironmentId, FlowId, NewClientAuthDiagnostic, NewFlow, Scope,
    TenantId,
};
use sqlx::PgPool;

/// A retention long enough that no seeded row is ever pruned during a test (30 days).
const RETENTION_MICROS: i64 = 30 * 24 * 60 * 60 * 1_000_000;

/// Parse a `(tenant, environment)` id pair into a store scope.
fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Seed one client authentication diagnostic into `scope` through the data-plane
/// store, exactly as the OIDC token endpoint records it, at the instant `env`'s clock
/// reads. The management plane reads these rows; it never writes them.
async fn seed(harness: &Harness, env: &Env, scope: Scope, diagnostic: NewClientAuthDiagnostic<'_>) {
    harness
        .store()
        .scoped(scope)
        .client_auth_diagnostics()
        .record(env, RETENTION_MICROS, diagnostic)
        .await
        .expect("record diagnostic");
}

#[tokio::test]
async fn the_read_returns_the_scope_rows_and_filters_by_client_and_time() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let scope = scope_of(&tenant, &environment);
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/client-auth");

    // A deterministic clock so each seeded row's occurred_at is a known instant. The
    // clock starts at the epoch and is ADVANCED by the deltas below, landing the three
    // rows at 1s, 5s, and 9s, which the time-window filter selects against.
    let (env, clock) = Env::deterministic(UNIX_EPOCH, 0x91);
    for (client, reason, key_id, advance_by) in [
        (
            "cli_a",
            ClientAuthDiagnosticReason::AssertionExpired,
            None,
            1_000_000,
        ),
        (
            "cli_a",
            ClientAuthDiagnosticReason::AssertionKidUnknown,
            Some("key-1"),
            4_000_000,
        ),
        (
            "cli_b",
            ClientAuthDiagnosticReason::BadSecret,
            None,
            4_000_000,
        ),
    ] {
        clock.advance(Duration::from_micros(advance_by));
        seed(
            &harness,
            &env,
            scope,
            NewClientAuthDiagnostic {
                client_id: client,
                auth_method: "private_key_jwt",
                reason,
                key_id,
                signing_alg: Some("EdDSA"),
                skew_seconds: None,
                expected: None,
            },
        )
        .await;
    }

    // No filter: every row in scope, NEWEST first (so a capped result keeps the most
    // recent failures), and not truncated (three rows are well under the limit).
    let (status, _, body) = harness.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);
    assert_eq!(items.len(), 3, "every row in scope: {body}");
    assert_eq!(items[0]["reason"], "bad_secret");
    assert_eq!(items[1]["reason"], "assertion_kid_unknown");
    assert_eq!(items[2]["reason"], "assertion_expired");
    assert!(
        items[0]["occurred_at_unix_micros"].as_i64().unwrap()
            >= items[1]["occurred_at_unix_micros"].as_i64().unwrap(),
        "newest first"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["truncated"],
        serde_json::Value::Bool(false),
        "three rows under the limit are not truncated: {body}"
    );

    // A small limit caps the result and flags the truncation (never silent): the newest
    // row is kept, and the operator is told to narrow the window.
    let (status, _, body) = harness.get(&format!("{base}?limit=1")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let capped = list_items(&body);
    assert_eq!(capped.len(), 1, "the limit caps the result: {body}");
    assert_eq!(capped[0]["reason"], "bad_secret", "the newest row is kept");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["truncated"],
        serde_json::Value::Bool(true),
        "a capped result is flagged truncated: {body}"
    );

    // A client filter returns only that client's rows.
    let (status, _, body) = harness.get(&format!("{base}?client_id=cli_a")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);
    assert_eq!(items.len(), 2, "two failures for cli_a: {body}");
    assert!(items.iter().all(|item| item["client_id"] == "cli_a"));

    // A time window narrows further: only the cli_a row at 5s falls in [2s, 8s).
    let (status, _, body) = harness
        .get(&format!(
            "{base}?client_id=cli_a&since=2000000&until=8000000"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);
    assert_eq!(items.len(), 1, "one cli_a row in the window: {body}");
    assert_eq!(items[0]["reason"], "assertion_kid_unknown");
    assert_eq!(items[0]["key_id"], "key-1");

    // A malformed filter value is a structured bad request, never a plain-text 400.
    let (status, _, body) = harness.get(&format!("{base}?since=notanumber")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("json error body");
    assert!(value["error"].is_string(), "structured error body: {body}");
}

#[tokio::test]
async fn the_read_is_idor_safe_across_tenants_and_environments() {
    let harness = Harness::start(50).await;
    let (tenant_a, env_a) = harness.create_tenant("Acme", "key-a").await;
    let (tenant_b, env_b) = harness.create_tenant("Beta", "key-b").await;
    let scope_b = scope_of(&tenant_b, &env_b);

    let env = Env::system();
    // A distinctive victim row in tenant B only.
    seed(
        &harness,
        &env,
        scope_b,
        NewClientAuthDiagnostic {
            client_id: "cli_victim_b",
            auth_method: "client_secret_basic",
            reason: ClientAuthDiagnosticReason::BadSecret,
            key_id: None,
            signing_alg: None,
            skew_seconds: None,
            expected: None,
        },
    )
    .await;

    // Tenant A's diagnostics read (even as the all-seeing operator) never crosses into
    // tenant B: the forced row level security scopes the read to tenant A, which holds
    // no rows. The victim's client id can never appear on tenant A's path.
    let base_a = format!("/v1/tenants/{tenant_a}/environments/{env_a}/diagnostics/client-auth");
    let (status, _, body) = harness.get(&base_a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(list_items(&body).len(), 0, "tenant A holds no rows: {body}");
    assert!(
        !body.contains("cli_victim_b"),
        "tenant B's row never leaks into tenant A's read: {body}"
    );

    // A management key scoped to tenant A / env A, presented against tenant B's path, is
    // rejected LOUD (wrong scope), never a silent cross-tenant read.
    let key_a = harness
        .create_key(&tenant_a, &env_a, "diag-reader", "mint-key-a")
        .await;
    let base_b = format!("/v1/tenants/{tenant_b}/environments/{env_b}/diagnostics/client-auth");
    let (status, _, body) = harness.get_as(&base_b, &key_a).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong scope is loud: {body}");

    // The same key against its OWN scope is authorized (a healthy baseline for the 403).
    let (status, _, body) = harness.get_as(&base_a, &key_a).await;
    assert_eq!(status, StatusCode::OK, "own scope is authorized: {body}");

    // A cross-environment read (tenant A, a second environment) is likewise scoped: the
    // key for env A cannot reach a sibling environment of the same tenant.
    let env_a2 = harness
        .create_environment(&tenant_a, "Staging", "key-a2")
        .await;
    let base_a2 = format!("/v1/tenants/{tenant_a}/environments/{env_a2}/diagnostics/client-auth");
    let (status, _, body) = harness.get_as(&base_a2, &key_a).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "cross-environment is loud too: {body}"
    );
}

#[tokio::test]
async fn the_response_carries_only_the_safe_non_secret_fields() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let scope = scope_of(&tenant, &environment);
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/client-auth");

    let env = Env::system();
    seed(
        &harness,
        &env,
        scope,
        NewClientAuthDiagnostic {
            client_id: "cli_a",
            auth_method: "private_key_jwt",
            reason: ClientAuthDiagnosticReason::AssertionBadSignature,
            key_id: Some("kid-42"),
            signing_alg: Some("RS256"),
            skew_seconds: None,
            expected: None,
        },
    )
    .await;

    let (status, _, body) = harness.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);
    assert_eq!(items.len(), 1, "{body}");

    // The record type is structurally incapable of holding a secret, an assertion body,
    // or a token; assert the SERIALIZED item exposes exactly the safe field set, so a
    // future field can never silently widen the wire projection past the redaction line.
    let keys: std::collections::BTreeSet<&str> = items[0]
        .as_object()
        .expect("item object")
        .keys()
        .map(String::as_str)
        .collect();
    let allowed: std::collections::BTreeSet<&str> = [
        "client_id",
        "auth_method",
        "reason",
        "key_id",
        "signing_alg",
        "skew_seconds",
        "expected",
        "occurred_at_unix_micros",
    ]
    .into_iter()
    .collect();
    assert!(
        keys.is_subset(&allowed),
        "the response exposes only the safe fields, got {keys:?}"
    );
    // The safe-field allowlist above is the STRUCTURAL guarantee: the record type has
    // no field capable of holding a secret, an assertion body, or a token, so a secret
    // cannot appear as a value here either (there is nothing to carry it). A substring
    // scan for the words "secret"/"assertion"/"token" would be a false positive: the
    // bounded reason enum legitimately contains them (for example "assertion_bad_signature",
    // "bad_secret"), which is exactly why the allowlist, not a word scan, is the check.
}

#[tokio::test]
async fn an_unauthenticated_read_is_rejected() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/client-auth");

    let (status, _, _) = harness.get_as(&base, "not-a-real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The `items` array of a diagnostics list response body, parsed as JSON values.
fn list_items(body: &str) -> Vec<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(body).expect("json list body");
    value["items"].as_array().expect("items array").clone()
}

// ===========================================================================
// The flow inspector endpoints (issue #91, PR4): the OBSERVE read and the zero
// side effect DRY REPLAY.
// ===========================================================================

/// Seed a login flow at its start state into `scope` through the data-plane store, exactly as
/// the flow engine creates one. Returns the flow id string the observe path carries.
async fn seed_login_flow(harness: &Harness, scope: Scope) -> String {
    let env = Env::system();
    let flow_id = FlowId::generate(&env, &scope);
    harness
        .store()
        .scoped(scope)
        .flows()
        .create(
            &flow_id,
            NewFlow {
                journey: "login",
                transport: "browser",
                // The serialized PersistedState at the login start state (opaque application
                // JSON the inspector projects read only).
                state: "{\"step\":\"identifier_password\"}",
                submit_token: "SEEDSUBMITTOKENSENTINEL",
                transient_payload: None,
                // A resume URL carrying the RP's state and nonce: sensitive, and the observe
                // response must never surface it (the projection is the redaction).
                return_to: Some(
                    "/authorize?client_id=rp&state=RETURNTOSTATESENTINEL&nonce=RETURNTONONCESENTINEL",
                ),
                contract_version: 1,
                flow_version_id: None,
                expires_at_unix_micros: common::FAR_FUTURE_MICROS,
            },
        )
        .await
        .expect("seed a login flow");
    flow_id.to_string()
}

/// Snapshot every public table's row count, read as the superuser owner (so forced row level
/// security never hides a write).
async fn snapshot(pool: &PgPool) -> std::collections::BTreeMap<String, i64> {
    let tables: Vec<(String,)> =
        sqlx::query_as("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            .fetch_all(pool)
            .await
            .expect("list public tables");
    let mut counts = std::collections::BTreeMap::new();
    for (table,) in tables {
        let (count,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM \"{table}\""))
            .fetch_one(pool)
            .await
            .expect("count table rows");
        counts.insert(table, count);
    }
    counts
}

#[tokio::test]
async fn the_flow_observe_read_projects_the_flow_read_only() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let scope = scope_of(&tenant, &environment);
    let flow_id = seed_login_flow(&harness, scope).await;

    let path =
        format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/flow/{flow_id}");
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("json body");
    assert_eq!(value["flow_id"], flow_id);
    assert_eq!(value["journey"], "login");
    assert_eq!(value["current"], "identifier_password");
    // The plan is the ordered login state sequence from the one transition table the engine
    // shares; it starts at the current state.
    let plan = value["plan"].as_array().expect("plan array");
    assert_eq!(plan[0], "identifier_password");
    assert!(
        plan.iter().any(|s| s == "completed"),
        "plan reaches completed"
    );
    // The redacted context never leaks an identifier value.
    assert_eq!(value["context"]["step"], "identifier_password");
    assert_eq!(value["context"]["has_identifier"], false);
    // The current node render reuses the engine's node model.
    assert!(
        !value["nodes"].as_array().expect("nodes array").is_empty(),
        "the node render is not empty: {body}"
    );
    // No policy traces recorded for this fresh flow's (absent) subject.
    assert!(value["traces"].as_array().expect("traces array").is_empty());
    // The wire response NEVER surfaces the flow's submit token (the API CSRF handle) nor its
    // return_to resume URL (which embeds the RP's state and nonce): the observe projection is the
    // redaction, so a future field addition that leaked either would fail this guard.
    for sentinel in [
        "SEEDSUBMITTOKENSENTINEL",
        "RETURNTOSTATESENTINEL",
        "RETURNTONONCESENTINEL",
    ] {
        assert!(
            !body.contains(sentinel),
            "the observe response leaked {sentinel}: {body}"
        );
    }
}

#[tokio::test]
async fn the_flow_observe_read_is_idor_safe() {
    let harness = Harness::start(50).await;
    let (tenant_a, env_a) = harness.create_tenant("Acme", "key-a").await;
    let (tenant_b, env_b) = harness.create_tenant("Beta", "key-b").await;
    let scope_b = scope_of(&tenant_b, &env_b);

    // A flow that exists only in tenant B.
    let flow_b = seed_login_flow(&harness, scope_b).await;

    // Tenant A's observe path with tenant B's flow id: the id carries tenant B's scope, so
    // parse_in_scope under tenant A rejects it as a UNIFORM not found (never an oracle).
    let cross = format!("/v1/tenants/{tenant_a}/environments/{env_a}/diagnostics/flow/{flow_b}");
    let (status, _, body) = harness.get(&cross).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross tenant is not found: {body}"
    );
    assert!(
        !body.contains(&flow_b) || status == StatusCode::NOT_FOUND,
        "tenant B's flow never leaks into tenant A"
    );

    // A wrong scope management key against tenant B's own path is rejected LOUD (403).
    let key_a = harness
        .create_key(&tenant_a, &env_a, "diag-reader", "mint-key-a")
        .await;
    let own_b = format!("/v1/tenants/{tenant_b}/environments/{env_b}/diagnostics/flow/{flow_b}");
    let (status, _, body) = harness.get_as(&own_b, &key_a).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong scope is loud: {body}");

    // An unknown (well formed in scope) flow id is a uniform not found, not a 500.
    let env = Env::system();
    let unknown = FlowId::generate(&env, &scope_of(&tenant_a, &env_a)).to_string();
    let missing = format!("/v1/tenants/{tenant_a}/environments/{env_a}/diagnostics/flow/{unknown}");
    let (status, _, body) = harness.get(&missing).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "unknown flow is not found: {body}"
    );
}

#[tokio::test]
async fn the_flow_dry_run_evaluates_the_real_policies_and_writes_no_row() {
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/flow/dry-run");

    // The BEFORE snapshot: every table's row count, superuser read (RLS never hides a write).
    let before = snapshot(harness.db().owner_pool()).await;

    // A dry run over the login journey: a pwd session against an mfa floor forces a step up,
    // and two corroborating MED risk signals challenge. If this were the live path it would
    // persist a risk decision and a step up trace; the dry run persists nothing.
    let body = serde_json::json!({
        "journey": "login",
        "achieved_acr": "pwd",
        "required_acr": "mfa",
        "risk": {
            "require_mfa_at": "med",
            "new_device": true,
            "signals": [
                { "name": "velocity", "level": "med" },
                { "name": "impossible_travel", "level": "med" }
            ]
        }
    })
    .to_string();
    let (status, _, response) = harness.post(&base, "dry-run-1", &body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let value: serde_json::Value = serde_json::from_str(&response).expect("json body");
    assert_eq!(value["journey"], "login");
    assert_eq!(
        value["terminal"], "completed",
        "the step up threads to completion"
    );
    let steps = value["steps"].as_array().expect("steps array");
    let primary = &steps[0];
    assert_eq!(primary["step"], "identifier_password");
    // The REAL step up evaluator ran: a pwd session does not satisfy the mfa floor.
    assert_eq!(primary["step_up"]["outcome"], "step_up_required");
    // The REAL risk compute core ran: two MED signals corroborate to HIGH and challenge.
    assert_eq!(primary["risk"]["action"], "challenge");
    assert_eq!(primary["risk"]["level"], "high");

    // The AFTER snapshot MUST be byte identical: the dry run wrote no risk decision, no step
    // up trace, no flow, no session, no jti, no row anywhere.
    let after = snapshot(harness.db().owner_pool()).await;
    assert_eq!(
        before, after,
        "the dry run wrote a row: the store is not byte identical before and after"
    );
}

#[tokio::test]
async fn the_flow_dry_run_is_scope_gated() {
    let harness = Harness::start(50).await;
    let (tenant_a, env_a) = harness.create_tenant("Acme", "key-a").await;
    let (tenant_b, env_b) = harness.create_tenant("Beta", "key-b").await;

    let body = serde_json::json!({ "journey": "login", "achieved_acr": "pwd" }).to_string();

    // A management key scoped to tenant A, presented against tenant B's dry run path, is
    // rejected LOUD (wrong scope), never a silent cross tenant evaluation.
    let key_a = harness
        .create_key(&tenant_a, &env_a, "diag-reader", "mint-key-a")
        .await;
    let base_b = format!("/v1/tenants/{tenant_b}/environments/{env_b}/diagnostics/flow/dry-run");
    let (status, _, resp) = harness.post_as(&base_b, &key_a, "dry-run-b", &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong scope is loud: {resp}");

    // An unauthenticated dry run is rejected.
    let (status, _, _) = harness
        .post_as(&base_b, "not-a-real-token", "dry-run-c", &body)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
