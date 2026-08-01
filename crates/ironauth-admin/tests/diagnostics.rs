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
    ClientAuthDiagnosticReason, EnvironmentId, FlowId, NewClientAuthDiagnostic, NewFlow,
    NewTokenSizeEvent, Scope, TenantId, TokenSizeKind, TokenSizeReason,
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

    // The record type has no field for a secret, an assertion body, or a token, which is
    // where the structural half of the guarantee stops: its four free-form strings would
    // carry one (issue #423). What this assertion adds is the part that IS enforceable
    // here: the SERIALIZED item exposes exactly the safe field set, so a future field can
    // never silently widen the wire projection past the redaction line.
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

// ===========================================================================
// The operational warnings read (issue #91), and the two PERMISSION BUDGET kinds
// issue #98 adds to it out of the same event sink.
// ===========================================================================

/// Seed one token size event into `scope` through the data-plane store, exactly as the
/// OIDC mint path records it. The management plane reads these rows; it never writes them.
async fn seed_size_event(harness: &Harness, env: &Env, scope: Scope, event: NewTokenSizeEvent<'_>) {
    harness
        .store()
        .scoped(scope)
        .token_size_events()
        .record(env, RETENTION_MICROS, event)
        .await
        .expect("record token size event");
}

/// The audience one organization hits the budget on.
const ORDERS: &str = "https://api.example.com/orders";

/// A SECOND audience for the same organization, so the (organization, audience) subject can
/// be shown to separate two warnings a client-id subject would have merged.
const REPORTS: &str = "https://api.example.com/reports";

/// Seed the corpus the warnings assertions below read: three withholdings on one
/// (organization, audience) pair, one approach on a second audience of the same
/// organization, and one ID-token bloat event from the same client.
async fn seed_budget_corpus(harness: &Harness, env: &Env, scope: Scope) {
    // Two withholdings and one still-oversize fallback on ONE pair, so the aggregate is
    // three events with the worst case of each dimension surfaced.
    for (reason, byte_size, permission_count) in [
        (TokenSizeReason::BudgetOverflowCount, 7000_i64, 900_i64),
        (TokenSizeReason::BudgetOverflowBytes, 9001, 412),
        (TokenSizeReason::RolesOnlyStillOversize, 9500, 412),
    ] {
        seed_size_event(
            harness,
            env,
            scope,
            NewTokenSizeEvent {
                token_type: TokenSizeKind::AccessToken,
                byte_size,
                claim_count: None,
                client_id: "cli_budget",
                reason: Some(reason),
                audience: Some(ORDERS),
                organization_id: Some("org_acme"),
                permission_count: Some(permission_count),
                permission_status: Some("budget_exceeded"),
            },
        )
        .await;
    }

    // One APPROACHING event on the same organization but a DIFFERENT audience: a separate
    // warning, which is the whole reason the subject is the pair.
    seed_size_event(
        harness,
        env,
        scope,
        NewTokenSizeEvent {
            token_type: TokenSizeKind::AccessToken,
            byte_size: 6000,
            claim_count: None,
            client_id: "cli_budget",
            reason: Some(TokenSizeReason::BudgetApproaching),
            audience: Some(REPORTS),
            organization_id: Some("org_acme"),
            permission_count: Some(300),
            permission_status: None,
        },
    )
    .await;

    // And one ID-token bloat event from the SAME client, which must stay its own kind.
    seed_size_event(
        harness,
        env,
        scope,
        NewTokenSizeEvent {
            token_type: TokenSizeKind::IdToken,
            byte_size: 4096,
            claim_count: Some(37),
            client_id: "cli_budget",
            reason: None,
            audience: None,
            organization_id: None,
            permission_count: None,
            permission_status: None,
        },
    )
    .await;
}

/// The one warning item of `kind` whose `subject` is `subject`.
fn warning<'a>(items: &'a [serde_json::Value], kind: &str, subject: &str) -> &'a serde_json::Value {
    let matching: Vec<&serde_json::Value> = items
        .iter()
        .filter(|item| item["kind"] == kind && item["subject"] == subject)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "exactly one {kind} warning for {subject}, got {matching:?}"
    );
    matching[0]
}

#[tokio::test]
async fn the_warnings_read_surfaces_the_two_permission_budget_kinds() {
    // Issue #98: the permission budget's operator-visible half. Four properties, each of
    // which a plausible refactor would break:
    //
    //   * The two new `kind` values appear, from the SAME sink the token_size kind reads,
    //     with no schema change (`kind` is a string and the console groups on it).
    //   * They are addressed by the (organization, audience) PAIR, not by the client id. A
    //     client id cannot tell an operator which organization on which audience to act on.
    //   * They AGGREGATE per pair, the way token_size aggregates per client, so a flood of
    //     mints for one pair is one legible item rather than hundreds.
    //   * An access-token budget event is NOT counted as ID token claim bloat. The
    //     token_size detail claims to count ID tokens, and it has to keep being true.
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();
    seed_budget_corpus(&harness, &env, scope).await;

    let path = format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/warnings");
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);

    // The overflow warning: one item for the pair, counting all THREE withholding events,
    // carrying the largest set and the largest token, and naming the still-oversize case.
    let overflow = warning(
        &items,
        "permission_budget_overflow",
        "org_acme https://api.example.com/orders",
    );
    let detail = overflow["detail"].as_str().expect("a detail string");
    assert!(
        detail.starts_with("3 recent access token(s) did NOT carry the permission claim"),
        "the three withholdings aggregate into one item: {detail}"
    );
    assert!(
        detail.contains("largest set 900 permissions")
            && detail.contains("largest token 9500 bytes"),
        "the aggregate carries the worst case of each dimension: {detail}"
    );
    // WHICH bound was crossed, because the remediations differ (a smaller permission set
    // or a larger permission_claim_max_count, against a larger access_token_max_bytes).
    // This aggregate holds one of each, so it must name both rather than say "the budget".
    assert!(
        detail.contains(
            "the permission count budget on some mints and the token byte \
                         budget on others"
        ),
        "the detail must say WHICH bound was crossed: {detail}"
    );
    assert!(
        detail.contains("STILL over the byte budget"),
        "the roles-only-still-oversize case is named, not folded away silently: {detail}"
    );

    // The approaching warning: the SAME organization on a different audience is a separate
    // item, and it says plainly that nothing was withheld.
    let approaching = warning(
        &items,
        "permission_budget_approaching",
        "org_acme https://api.example.com/reports",
    );
    let detail = approaching["detail"].as_str().expect("a detail string");
    assert!(
        detail.starts_with("1 recent access token(s) carried a permission claim at or past a warn"),
        "an approach is reported as emitted, not withheld: {detail}"
    );
    assert!(
        detail.contains("nothing was withheld"),
        "the approach warning must not read as a withholding: {detail}"
    );
    // The still-oversize sentence belongs to the OVERFLOW half and to nothing else.
    // Latched onto an approach it produces a self contradicting operator message
    // ("nothing was withheld ... STILL over the byte budget with the permission claim
    // withheld"), so its ABSENCE here is asserted rather than assumed.
    assert!(
        !detail.contains("STILL over the byte budget"),
        "the still-oversize sentence must never attach to an approach, which withheld \
         nothing: {detail}"
    );

    // The ID-token bloat warning counts ONE token, not five: the four access-token budget
    // events share this sink and this client id, and counting them here would report them
    // as oversized ID tokens, which they are not.
    let bloat = warning(&items, "token_size", "cli_budget");
    let detail = bloat["detail"].as_str().expect("a detail string");
    assert!(
        detail.starts_with("1 recent ID token(s) exceeded the claim bloat threshold"),
        "an access-token budget event is not ID token claim bloat: {detail}"
    );

    // Nothing else: five seeded rows produce exactly these three aggregated warnings.
    assert_eq!(items.len(), 3, "no other warning is produced: {body}");

    // The ORDER is promised in the response schema, in the OpenAPI description, and in the
    // changelog, so it is pinned here rather than left to whatever the code happens to do:
    // connector warnings first (none seeded), then token size, then permission budget.
    let kinds: Vec<&str> = items
        .iter()
        .map(|item| item["kind"].as_str().expect("a kind string"))
        .collect();
    assert_eq!(
        kinds,
        vec![
            "token_size",
            "permission_budget_approaching",
            "permission_budget_overflow",
        ],
        "the documented item order must hold: token size warnings before permission \
         budget warnings, and the budget kinds in their own stable order"
    );
}

#[tokio::test]
async fn the_warnings_read_is_scope_confined_for_permission_budget_events() {
    // The same IDOR property the other diagnostics reads hold, driven over the new kinds:
    // tenant B's budget event is invisible to tenant A even to the all-seeing operator,
    // because the read runs under forced row level security in the path's scope.
    let harness = Harness::start(50).await;
    let (tenant_a, env_a) = harness.create_tenant("Acme", "key-a").await;
    let (tenant_b, env_b) = harness.create_tenant("Beta", "key-b").await;
    let env = Env::system();

    seed_size_event(
        &harness,
        &env,
        scope_of(&tenant_b, &env_b),
        NewTokenSizeEvent {
            token_type: TokenSizeKind::AccessToken,
            byte_size: 9001,
            claim_count: None,
            client_id: "cli_victim_b",
            reason: Some(TokenSizeReason::BudgetOverflowBytes),
            audience: Some("https://api.beta.example.com"),
            organization_id: Some("org_victim_b"),
            permission_count: Some(412),
            permission_status: Some("budget_exceeded"),
        },
    )
    .await;

    let path_a = format!("/v1/tenants/{tenant_a}/environments/{env_a}/diagnostics/warnings");
    let (status, _, body) = harness.get(&path_a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body.contains("org_victim_b") && !body.contains("api.beta.example.com"),
        "tenant B's permission budget event must not appear in tenant A's warnings: {body}"
    );

    // And it IS visible in its own scope, so the absence above is the fence and not a
    // seeding failure.
    let path_b = format!("/v1/tenants/{tenant_b}/environments/{env_b}/diagnostics/warnings");
    let (status, _, body) = harness.get(&path_b).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("org_victim_b"),
        "the event is visible in its own scope: {body}"
    );
}

/// Bulk-seed `count` permission-budget withholdings for one (organization, audience) pair
/// directly, as OWNER SQL, all NEWER than anything the repository has written so far.
///
/// Through the repository this would be `count` separate transactions each running the
/// retention prune first, which for a flood past the 200-row read clamp is slow enough to
/// matter and buys nothing: the property under test is what the READ does with a saturated
/// window, not what the write path does. Owner SQL also fixes the ordering exactly, which
/// is the whole point of a starvation test.
async fn seed_budget_flood(harness: &Harness, scope: Scope, count: i64) {
    harness
        .db()
        .execute_owner_sql(&format!(
            "INSERT INTO token_size_events \
             (id, tenant_id, environment_id, token_type, byte_size, claim_count, client_id, \
              reason, audience, organization_id, permission_count, permission_status, \
              occurred_at, expires_at) \
             SELECT 'evt_flood_{environment}_' || i, '{tenant}', '{environment}', \
                    'access_token', 9001, \
                    NULL, 'cli_noisy', 'budget_overflow_bytes', \
                    'https://api.example.com/noisy', 'org_noisy', 412, 'budget_exceeded', \
                    now() + (i || ' seconds')::interval, \
                    now() + '30 days'::interval \
             FROM generate_series(1, {count}) AS i",
            tenant = scope.tenant(),
            environment = scope.environment(),
        ))
        .await;
}

/// Seed the pair of quiet rows the starvation assertions look for in `scope`: one quiet
/// organization's withholding, and one ID-token bloat event from a different client.
async fn seed_quiet_pair(harness: &Harness, env: &Env, scope: Scope) {
    seed_size_event(
        harness,
        env,
        scope,
        NewTokenSizeEvent {
            token_type: TokenSizeKind::AccessToken,
            byte_size: 7000,
            claim_count: None,
            client_id: "cli_quiet",
            reason: Some(TokenSizeReason::BudgetOverflowCount),
            audience: Some(ORDERS),
            organization_id: Some("org_quiet"),
            permission_count: Some(900),
            permission_status: Some("budget_exceeded"),
        },
    )
    .await;
    seed_size_event(
        harness,
        env,
        scope,
        NewTokenSizeEvent {
            token_type: TokenSizeKind::IdToken,
            byte_size: 4096,
            claim_count: Some(37),
            client_id: "cli_bloat",
            reason: None,
            audience: None,
            organization_id: None,
            permission_count: None,
            permission_status: None,
        },
    )
    .await;
}

#[tokio::test]
async fn a_noisy_pair_cannot_starve_the_other_warning_families() {
    // Issue #98, the read-clamp starvation seam, and the honest boundary of the fix.
    //
    // The permission budget shares the issue #91 event sink, and both families used to be
    // read through ONE `recent(200)` window. A flood of budget events therefore evicted,
    // from a SHIPPED response, the entire `token_size` family, which is a regression to a
    // shipped feature, along with every quieter budget pair.
    //
    // Each family now gets its own clamped window. That removes the CROSS family eviction
    // outright and the WITHIN family eviction below the clamp. It does NOT remove within
    // family eviction above the clamp, and nothing could without an unbounded read, which
    // is exactly why a saturated window is rendered as a lower bound rather than a count.
    // Both regimes are measured here, on two tenants of one harness.
    let harness = Harness::start(50).await;
    let env = Env::system();

    // REGIME ONE, below the clamp: nothing is lost and every count is exact.
    let (calm_tenant, calm_environment) = harness.create_tenant("Acme", "tenant-key").await;
    let calm = scope_of(&calm_tenant, &calm_environment);
    seed_quiet_pair(&harness, &env, calm).await;
    seed_budget_flood(&harness, calm, 50).await;

    let path =
        format!("/v1/tenants/{calm_tenant}/environments/{calm_environment}/diagnostics/warnings");
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);

    let quiet = warning(
        &items,
        "permission_budget_overflow",
        "org_quiet https://api.example.com/orders",
    );
    assert!(
        quiet["detail"]
            .as_str()
            .expect("a detail")
            .starts_with("1 recent access token(s)"),
        "a quiet pair survives a noisy pair below the clamp, with an EXACT count: {quiet}"
    );
    let bloat = warning(&items, "token_size", "cli_bloat");
    assert!(
        bloat["detail"]
            .as_str()
            .expect("a detail")
            .starts_with("1 recent ID token(s)"),
        "and so does the other family: {bloat}"
    );
    let noisy = warning(
        &items,
        "permission_budget_overflow",
        "org_noisy https://api.example.com/noisy",
    );
    assert!(
        noisy["detail"]
            .as_str()
            .expect("a detail")
            .starts_with("50 recent access token(s)"),
        "an unsaturated window reports an exact count and does not hedge: {noisy}"
    );

    // REGIME TWO, past the clamp: the OTHER family still survives, which is the shipped
    // regression this fix is about, and the saturated family's counts become lower bounds.
    let (loud_tenant, loud_environment) = harness.create_tenant("Beta", "tenant-key-2").await;
    let loud = scope_of(&loud_tenant, &loud_environment);
    seed_quiet_pair(&harness, &env, loud).await;
    seed_budget_flood(&harness, loud, 220).await;

    let path =
        format!("/v1/tenants/{loud_tenant}/environments/{loud_environment}/diagnostics/warnings");
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);

    // THE REGRESSION THAT IS FIXED: a shipped warning family is not evicted by a newer one.
    let bloat = warning(&items, "token_size", "cli_bloat");
    assert!(
        bloat["detail"]
            .as_str()
            .expect("a detail")
            .starts_with("1 recent ID token(s)"),
        "the issue #91 family must survive 220 access-token events, which a shared window \
         deleted outright: {bloat}"
    );

    // THE RESIDUAL, asserted rather than glossed: the quiet budget pair IS beyond a
    // saturated same-family window. That is a bound of the clamp, not of the split, and it
    // is precisely why the next assertion exists.
    assert!(
        !body.contains("org_quiet"),
        "a quiet pair 220 events deep in its OWN family is outside the clamped window, \
         which the response must therefore not present as a complete picture: {body}"
    );

    // So a saturated window reports a LOWER BOUND. Rendering the clamp as an exact figure
    // ("200 recent access token(s)") would be an under report presented as precision.
    let noisy = warning(
        &items,
        "permission_budget_overflow",
        "org_noisy https://api.example.com/noisy",
    );
    let detail = noisy["detail"].as_str().expect("a detail");
    assert!(
        detail.starts_with("at least 200 recent access token(s) did NOT carry"),
        "a full window is reported as a lower bound, never as a count: {detail}"
    );
}

#[tokio::test]
async fn an_unparseable_reason_produces_no_warning_item() {
    // The rolling-upgrade skip, at the READ rather than only at `TokenSizeReason::from_wire`
    // (issue #98). A row written by a NEWER build carries a reason this build has never
    // heard of, and an advisory read that mapped it to some kind anyway would be inventing
    // an operator message out of a value it cannot interpret.
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();

    seed_size_event(
        &harness,
        &env,
        scope,
        NewTokenSizeEvent {
            token_type: TokenSizeKind::AccessToken,
            byte_size: 9001,
            claim_count: None,
            client_id: "cli_future",
            reason: Some(TokenSizeReason::BudgetOverflowBytes),
            audience: Some(ORDERS),
            organization_id: Some("org_future"),
            permission_count: Some(412),
            permission_status: Some("budget_exceeded"),
        },
    )
    .await;

    // Rewrite the recorded reason to one only a newer build could have written. Raw SQL,
    // because no Rust API can express a value outside the closed enum, which is the point.
    harness
        .db()
        .execute_owner_sql(
            "UPDATE token_size_events SET reason = 'reason_from_a_newer_build' \
             WHERE client_id = 'cli_future'",
        )
        .await;

    let path = format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/warnings");
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);
    assert!(
        items.is_empty(),
        "a reason this build cannot parse produces NO warning item, rather than being \\
         mapped to a kind the row never claimed: {body}"
    );
    assert!(
        !body.contains("org_future"),
        "and the row's subject does not surface through some other item: {body}"
    );
}

#[tokio::test]
async fn a_multi_audience_verdict_is_addressed_by_its_organization_alone() {
    // Issue #98: the budget produces ONE verdict per TOKEN, and a token may target several
    // resource servers, so a verdict is attributable to one audience only when the token
    // targets exactly one. The recorder writes no audience for the multi-audience case, and
    // the subject is then the organization alone rather than a fabricated "unknown" half.
    //
    // The organizationless row beside it pins UNKNOWN_SUBJECT_PART and the
    // `permission_count.unwrap_or(0)` fallback, both of which are reachable from the public
    // store API and neither of which any recorder produces. They keep the warning VISIBLE
    // instead of dropping it for an incomplete address, and that is asserted, not claimed.
    let harness = Harness::start(50).await;
    let (tenant, environment) = harness.create_tenant("Acme", "tenant-key").await;
    let scope = scope_of(&tenant, &environment);
    let env = Env::system();

    seed_size_event(
        &harness,
        &env,
        scope,
        NewTokenSizeEvent {
            token_type: TokenSizeKind::AccessToken,
            byte_size: 9001,
            claim_count: None,
            client_id: "cli_multi",
            reason: Some(TokenSizeReason::BudgetOverflowBytes),
            audience: None,
            organization_id: Some("org_multi"),
            permission_count: Some(412),
            permission_status: Some("pdp_required"),
        },
    )
    .await;
    seed_size_event(
        &harness,
        &env,
        scope,
        NewTokenSizeEvent {
            token_type: TokenSizeKind::AccessToken,
            byte_size: 8000,
            claim_count: None,
            client_id: "cli_headless",
            reason: Some(TokenSizeReason::BudgetOverflowCount),
            audience: Some(REPORTS),
            organization_id: None,
            permission_count: None,
            permission_status: Some("budget_exceeded"),
        },
    )
    .await;

    let path = format!("/v1/tenants/{tenant}/environments/{environment}/diagnostics/warnings");
    let (status, _, body) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = list_items(&body);

    let multi = warning(&items, "permission_budget_overflow", "org_multi");
    let multi_detail = multi["detail"].as_str().expect("a detail");
    assert!(
        multi_detail.contains("exceeded the token byte budget"),
        "the organization alone is a complete subject for a multi-audience verdict, and \
         the detail names the BYTE bound this row crossed: {multi_detail}"
    );
    assert!(
        !multi_detail.contains("the permission count budget"),
        "and does not also claim the count bound: {multi_detail}"
    );

    // The organizationless row: still visible, addressed by the stand-in, and its missing
    // permission count reported as zero rather than dropping the item.
    let headless = warning(
        &items,
        "permission_budget_overflow",
        "unknown https://api.example.com/reports",
    );
    let headless_detail = headless["detail"].as_str().expect("a detail");
    assert!(
        headless_detail.contains("largest set 0 permissions"),
        "a row with no permission count still produces a visible warning: {headless_detail}"
    );
    // The SINGLE bound cases, one per row, so a detail that collapsed either back into a
    // generic "the budget" fails: this one crossed the element bound and the one above
    // crossed the byte bound, and the two have different remediations.
    assert!(
        headless_detail.contains("exceeded the permission count budget"),
        "a count overflow names the count bound: {headless_detail}"
    );
    assert!(
        !headless_detail.contains("the token byte budget"),
        "and does not also claim the byte bound: {headless_detail}"
    );
}
