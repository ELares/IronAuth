// SPDX-License-Identifier: MIT OR Apache-2.0

//! The resource-server management surface over HTTP (issue #98, PR 11), driven
//! through the management router against a real database.
//!
//! There is no CREATE endpoint (issue #98 adds none), so every fixture is registered
//! through the store, which is exactly how a resource server comes into existence
//! today. That makes the seeding here production-shaped rather than a shortcut.
//!
//! Each of the following gets its own test because each is the kind of thing this
//! surface would be wrong about silently:
//!
//!   * ANTI-ORACLE uniformity. Every addressing failure must be ONE answer, byte for
//!     byte, in status AND body, on the read and on the mutation. The audience of a
//!     resource server is the URI of a protected API, so an endpoint that answered
//!     differently for "belongs to another environment" than for "never registered"
//!     would let a caller enumerate a sibling environment's APIs one id at a time.
//!   * The OPAQUE refusal and its ORDERING. The 422 must be reachable only AFTER the
//!     row has resolved in this scope, or it becomes a token-format oracle over a
//!     sibling environment.
//!   * The CREDENTIAL scope check. A test driving the operator proves containment of
//!     IDS and nothing about the credential, because the operator passes every scope
//!     check by design.
//!   * The PROJECTION, on a resource server that is not the one every other test
//!     reads. A view that hard-coded the format, the audience, or a null lifetime
//!     would otherwise pass, because a single fixture shape cannot tell a projection
//!     from a constant.
//!   * The READ-ONLY fields. Naming one must be a typed 400 that says which, because
//!     this endpoint's whole subject is the interaction between `token_format` and
//!     the opt-in and a silent ignore is the one answer that misleads.
//!   * The CURSOR WALK, including the sibling environment the list must never
//!     include. Every pagination defect is invisible to a single-page test.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    ActorRef, CorrelationId, EnvironmentId, NewResourceServer, ResourceServerId, Scope, ServiceId,
    TenantId, TokenFormat,
};
use serde_json::Value;

/// Create a tenant with an environment.
async fn tenant_env(h: &Harness) -> (String, String) {
    h.create_tenant("acme", "k-tenant").await
}

/// The `.../environments/{environment}/resource-servers` base path.
fn servers_base(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/resource-servers")
}

/// The `(tenant, environment)` scope parsed from two id path segments.
fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Register a resource server through the store (there is no create endpoint) and
/// return its `rsv_` id. No custom lifetime; see [`register_with_ttl`].
async fn register(
    h: &Harness,
    tenant: &str,
    environment: &str,
    audience: &str,
    format: TokenFormat,
) -> String {
    register_with_ttl(h, tenant, environment, audience, format, None).await
}

/// Register a resource server with an explicit per-resource-server access-token
/// lifetime.
///
/// A separate helper because every fixture in this file used to register with a NULL
/// lifetime, which left `access_token_ttl_secs` on the view reported as `null` in
/// every assertion: a projection that always answered `None` would have passed the
/// whole suite.
async fn register_with_ttl(
    h: &Harness,
    tenant: &str,
    environment: &str,
    audience: &str,
    format: TokenFormat,
    ttl: Option<i64>,
) -> String {
    let env = Env::system();
    let scope = scope_of(tenant, environment);
    let id = ResourceServerId::generate(&env, &scope);
    h.control_store()
        .scoped(scope)
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .resource_servers()
        .register(
            &env,
            NewResourceServer {
                id: &id,
                audience,
                token_format: format,
                access_token_ttl_secs: ttl,
            },
        )
        .await
        .expect("register resource server");
    id.to_string()
}

/// A well-formed resource-server id in the given scope that was never registered.
fn fresh_in_scope_server(tenant: &str, environment: &str) -> String {
    ResourceServerId::generate(&Env::system(), &scope_of(tenant, environment)).to_string()
}

/// A well-formed PERMISSION id in the given scope: right scope, WRONG kind.
fn fresh_in_scope_permission(tenant: &str, environment: &str) -> String {
    ironauth_store::PermissionId::generate(&Env::system(), &scope_of(tenant, environment))
        .to_string()
}

/// A PATCH body setting the opt-in.
fn opt_in_body(enabled: bool) -> String {
    serde_json::json!({ "permission_claims_enabled": enabled }).to_string()
}

/// One field of a JSON body.
fn field(response: &str, name: &str) -> Value {
    serde_json::from_str::<Value>(response).expect("json")[name].clone()
}

/// The `(target_kind, target_id)` of every `resource_server.permission_claims.set`
/// audit row in one scope, sorted.
///
/// The action alone says a write happened; the target says WHICH resource server it
/// happened to, which is the dimension an operator reads the audit log for.
async fn server_audit_targets(
    h: &Harness,
    tenant: &str,
    environment: &str,
) -> Vec<(String, String)> {
    let mut targets: Vec<(String, String)> = h
        .control_store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .filter(|row| row.action == "resource_server.permission_claims.set")
        .map(|row| (row.target_kind, row.target_id))
        .collect();
    targets.sort();
    targets
}

/// Every `resource_server.*` audit action recorded in one scope, sorted: the audit
/// MULTISET, compared whole so an extra row is as visible as a missing one.
async fn server_audit(h: &Harness, tenant: &str, environment: &str) -> Vec<String> {
    let mut actions: Vec<String> = h
        .control_store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .map(|row| row.action)
        .filter(|action| action.starts_with("resource_server."))
        .collect();
    actions.sort();
    actions
}

#[tokio::test]
async fn the_registry_lists_reads_and_toggles_the_permission_claim_opt_in() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = servers_base(&tenant, &environment);

    let jwt_id = register(
        &h,
        &tenant,
        &environment,
        "https://api.example.test/billing",
        TokenFormat::AtJwt,
    )
    .await;
    let opaque_id = register(
        &h,
        &tenant,
        &environment,
        "https://api.example.test/legacy",
        TokenFormat::Opaque,
    )
    .await;

    // LIST: the whole set, so a missing entry is as visible as an extra one, and the
    // ids the item endpoints take are what a console finds here.
    let (status, _, response) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "list: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    let mut ids: Vec<String> = value["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect();
    ids.sort();
    let mut expected = vec![jwt_id.clone(), opaque_id.clone()];
    expected.sort();
    assert_eq!(ids, expected, "the list is the whole registry: {response}");

    // GET: the audience and the format ride back, and the opt-in starts OFF for a
    // freshly registered resource server (migration 0094's DEFAULT).
    let (status, _, response) = h.get(&format!("{base}/{jwt_id}")).await;
    assert_eq!(status, StatusCode::OK, "get: {response}");
    assert_eq!(
        field(&response, "audience"),
        "https://api.example.test/billing"
    );
    assert_eq!(field(&response, "token_format"), "at_jwt");
    assert_eq!(
        field(&response, "permission_claims_enabled"),
        Value::Bool(false),
        "a registration is opted OUT until an operator says otherwise"
    );

    // PATCH ON, and the response describes the NEW state rather than echoing the
    // request.
    let (status, _, response) = h
        .patch(&format!("{base}/{jwt_id}"), &opt_in_body(true))
        .await;
    assert_eq!(status, StatusCode::OK, "patch on: {response}");
    assert_eq!(
        field(&response, "permission_claims_enabled"),
        Value::Bool(true)
    );
    // And it PERSISTED: a re-read through the same address, not the write's own body.
    let (_, _, reread) = h.get(&format!("{base}/{jwt_id}")).await;
    assert_eq!(
        field(&reread, "permission_claims_enabled"),
        Value::Bool(true),
        "the opt-in is stored, not merely reported"
    );

    // The PATCH touches ONE column: the format and the audience are unchanged.
    assert_eq!(field(&reread, "token_format"), "at_jwt");
    assert_eq!(
        field(&reread, "audience"),
        "https://api.example.test/billing"
    );

    // The sibling resource server is untouched: this is a per-row toggle, not an
    // environment-wide switch.
    let (_, _, other) = h.get(&format!("{base}/{opaque_id}")).await;
    assert_eq!(
        field(&other, "permission_claims_enabled"),
        Value::Bool(false),
        "toggling one audience must not toggle another"
    );

    // PATCH OFF again, and re-applying the SAME value is accepted (a PATCH addressed
    // by an existing id is naturally idempotent, which is why it takes no
    // Idempotency-Key).
    let (status, _, _) = h
        .patch(&format!("{base}/{jwt_id}"), &opt_in_body(false))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, response) = h
        .patch(&format!("{base}/{jwt_id}"), &opt_in_body(false))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        field(&response, "permission_claims_enabled"),
        Value::Bool(false)
    );

    // A body omitting the one field is a 400 that names it, never a silent no-op:
    // a caller who sent `{}` would otherwise get a 200 describing a state they did
    // not ask for and could not distinguish from one they did.
    let (status, _, response) = h.patch(&format!("{base}/{jwt_id}"), "{}").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "empty body: {response}");

    assert_two_registrations_and_three_opt_in_writes(&h, &tenant, &environment, &jwt_id).await;
}

/// The audit tail of [`the_registry_lists_reads_and_toggles_the_permission_claim_opt_in`]:
/// two registrations, exactly three opt-in writes, and every one of the three naming
/// the resource server that was actually written.
///
/// A separate function only because the round trip it closes is already at the
/// line budget; it is not independently meaningful, and it asserts a multiset that
/// only means anything after that exact sequence of requests.
async fn assert_two_registrations_and_three_opt_in_writes(
    h: &Harness,
    tenant: &str,
    environment: &str,
    written: &str,
) {
    // Two registrations and exactly three opt-in writes (on, off, off), each its own
    // row. The multiset is compared whole, so an extra row is as visible as a
    // missing one.
    assert_eq!(
        server_audit(h, tenant, environment).await,
        vec![
            "resource_server.permission_claims.set",
            "resource_server.permission_claims.set",
            "resource_server.permission_claims.set",
            "resource_server.register",
            "resource_server.register",
        ],
        "every opt-in write is audited, and nothing else is"
    );

    // And every opt-in row names the RIGHT TARGET. The action alone would be
    // satisfied by an audit row pointing at the sibling resource server, which is
    // exactly the row an operator would go looking for after a surprising change:
    // all three writes addressed `written`, and none addressed its sibling.
    assert_eq!(
        server_audit_targets(h, tenant, environment).await,
        vec![
            ("rsv".to_owned(), written.to_owned()),
            ("rsv".to_owned(), written.to_owned()),
            ("rsv".to_owned(), written.to_owned()),
        ],
        "every opt-in audit row names the resource server that was written"
    );
}

/// The WHOLE view, for a resource server that is not the at+jwt one every other test
/// reads and not the one audience every other test expects.
///
/// Every assertion elsewhere in this file reads a single `at_jwt` resource server
/// registered at `https://api.example.test/billing` with no custom lifetime, so
/// `ResourceServerView::from_record` could have hard-coded `token_format` to
/// `"at_jwt"`, hard-coded `audience` to that one string, and hard-coded
/// `access_token_ttl_secs` to `None`, and the suite would not have noticed. The
/// asymmetry is the tell: hard-coding `"opaque"` was already caught, and
/// hard-coding `"at_jwt"` was not, which means the format was never actually read
/// back from a stored row.
///
/// The timestamp is asserted for SCALE rather than value. `created_at_unix_ms` is
/// `created_at_unix_micros / 1000`, and dropping that division reports microseconds
/// under a field named milliseconds: a console would render a registration made
/// today as a date fifty thousand years out. The bound below is loose enough never
/// to age out and tight enough that a microsecond value cannot satisfy it.
#[tokio::test]
async fn the_view_reports_the_stored_format_audience_lifetime_and_timestamp() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = servers_base(&tenant, &environment);

    // An OPAQUE resource server, at a DIFFERENT audience, with a NON-NULL lifetime:
    // three fields that no other fixture in this file exercises.
    let opaque_id = register_with_ttl(
        &h,
        &tenant,
        &environment,
        "https://api.example.test/reports",
        TokenFormat::Opaque,
        Some(900),
    )
    .await;

    let (status, _, response) = h.get(&format!("{base}/{opaque_id}")).await;
    assert_eq!(status, StatusCode::OK, "get: {response}");
    let view: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(view["id"], opaque_id.as_str());
    assert_eq!(view["audience"], "https://api.example.test/reports");
    assert_eq!(
        view["token_format"], "opaque",
        "the view must report the STORED format: {response}"
    );
    assert_eq!(
        view["access_token_ttl_secs"], 900,
        "a registered non-null lifetime must ride back: {response}"
    );
    assert_eq!(view["permission_claims_enabled"], Value::Bool(false));

    let created = view["created_at_unix_ms"]
        .as_i64()
        .expect("created_at_unix_ms");
    assert!(
        (1_700_000_000_000..10_000_000_000_000).contains(&created),
        "created_at_unix_ms must be MILLISECONDS since the epoch (a microsecond \
         value is roughly a thousand times larger and lands outside this window): \
         {created}"
    );

    // A SECOND audience with the other format, read through the LIST, so the
    // projection is exercised on both endpoints rather than only on the item GET.
    let jwt_id = register(
        &h,
        &tenant,
        &environment,
        "https://api.example.test/orders",
        TokenFormat::AtJwt,
    )
    .await;
    let (status, _, response) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "list: {response}");
    let listed: Value = serde_json::from_str(&response).expect("json");
    let mut pairs: Vec<(String, String, String)> = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| {
            (
                item["id"].as_str().expect("id").to_owned(),
                item["token_format"].as_str().expect("format").to_owned(),
                item["audience"].as_str().expect("audience").to_owned(),
            )
        })
        .collect();
    pairs.sort();
    let mut expected = vec![
        (
            opaque_id.clone(),
            "opaque".to_owned(),
            "https://api.example.test/reports".to_owned(),
        ),
        (
            jwt_id.clone(),
            "at_jwt".to_owned(),
            "https://api.example.test/orders".to_owned(),
        ),
    ];
    expected.sort();
    assert_eq!(
        pairs, expected,
        "the list reports each resource server's OWN format and audience: {response}"
    );

    // The lifetime is OMITTED rather than reported as null when it was never set,
    // which is what `skip_serializing_if` on the field means and the only way to
    // tell "no custom lifetime" from "a lifetime of zero" on the wire.
    let jwt_item = listed["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|item| item["id"] == jwt_id.as_str())
        .expect("the at_jwt resource server is listed");
    assert!(
        jwt_item.get("access_token_ttl_secs").is_none(),
        "a NULL lifetime is omitted from the view: {response}"
    );
}

/// A body that NAMES a field this surface cannot write is a typed 400 that says
/// which, never a 200 that dropped it (issue #98).
///
/// The endpoint's entire subject is the interaction between `token_format` and the
/// opt-in, so `{"permission_claims_enabled": true, "token_format": "at_jwt"}` is
/// exactly the request a caller sends when they believe they are changing the format
/// to make the opt-in legal. Answering 200 with the format unchanged is the worst
/// available answer, and it is what a plain `#[derive(Deserialize)]` gives.
///
/// The test is PRESENCE and never value, so `null` is refused like a value: a caller
/// who wrote the key said something about the field.
#[tokio::test]
async fn a_body_naming_a_read_only_field_is_a_typed_400() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = servers_base(&tenant, &environment);

    let id = register_with_ttl(
        &h,
        &tenant,
        &environment,
        "https://api.example.test/billing",
        TokenFormat::AtJwt,
        Some(600),
    )
    .await;
    let path = format!("{base}/{id}");

    for (label, body) in [
        (
            "token_format",
            serde_json::json!({ "permission_claims_enabled": true, "token_format": "at_jwt" }),
        ),
        (
            "token_format null",
            serde_json::json!({ "permission_claims_enabled": true, "token_format": null }),
        ),
        (
            "audience",
            serde_json::json!({
                "permission_claims_enabled": true,
                "audience": "https://api.example.test/other"
            }),
        ),
        (
            "access_token_ttl_secs",
            serde_json::json!({ "permission_claims_enabled": true, "access_token_ttl_secs": 30 }),
        ),
    ] {
        let (status, _, response) = h.patch(&path, &body.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "naming {label} must be refused: {response}"
        );
        let error: Value = serde_json::from_str(&response).expect("json");
        assert_eq!(error["error"], "bad_request", "{label}: {response}");
        let message = error["message"].as_str().expect("message");
        let named = label.split(' ').next().expect("field name");
        assert!(
            message.contains(named),
            "the refusal must NAME the field the caller wrote ({named}): {response}"
        );
    }

    // Nothing landed: the opt-in every one of those bodies also carried is still
    // off, the format and the lifetime are unchanged, and no write was audited.
    let (_, _, stored) = h.get(&path).await;
    assert_eq!(
        field(&stored, "permission_claims_enabled"),
        Value::Bool(false),
        "a refused body must not apply the field it DID name legally: {stored}"
    );
    assert_eq!(field(&stored, "token_format"), "at_jwt");
    assert_eq!(field(&stored, "access_token_ttl_secs"), 600);
    assert_eq!(
        field(&stored, "audience"),
        "https://api.example.test/billing"
    );
    assert_eq!(
        server_audit(&h, &tenant, &environment).await,
        vec!["resource_server.register"],
        "a refused body writes no audit row"
    );

    // An unknown key that names NOTHING on this resource is still tolerated and
    // ignored, exactly as on every other management body in this crate. The rule is
    // "refuse the fields of THIS resource that this surface cannot write", not
    // "refuse anything unrecognized".
    let (status, _, response) = h
        .patch(
            &path,
            &serde_json::json!({ "permission_claims_enabled": true, "colour": "blue" }).to_string(),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an unrelated unknown key is ignored: {response}"
    );
    assert_eq!(
        field(&response, "permission_claims_enabled"),
        Value::Bool(true)
    );
}

/// The LIST pages by cursor: every row appears exactly ONCE, in the endpoint's
/// order, with no repeat at a page boundary and no page longer than the requested
/// limit (issue #98).
///
/// Five separate defects live in this one walk and none of them was reachable
/// before, because no test requested a second page or looked at `next_cursor`: a
/// cursor comparison of `>=` instead of `>` repeats the boundary row on the next
/// page; a cursor predicate replaced by `TRUE` makes every page page one; a
/// `fetch_limit` that stops asking for one row beyond the page never reports a next
/// cursor, so the walk ends after page one and loses three rows; a `finish` key built
/// from the wrong columns points the next page somewhere else entirely; and a
/// reversed `ORDER BY` walks the registry backwards while the cursor still compares
/// forwards. Each was run against this test and each turns it red.
///
/// One near-miss is worth recording rather than claiming. Making the STORE ignore the
/// requested limit (a hard-coded large `LIMIT`) leaves this test green, measured, and
/// correctly so: `Pagination::finish` truncates the page to the requested size
/// afterwards, so the caller-visible limit is honoured either way and only the rows
/// fetched change. The limit assertion here binds the response, which is the contract.
///
/// The foreign environment is here for a different reason: the whole file ran in ONE
/// environment, so an over-inclusive list had nothing to over-include.
///
/// Be precise about what that half proves. Deleting the list statement's `tenant_id`
/// / `environment_id` predicates leaves this test GREEN, measured, because forced
/// row-level security hides the sibling row anyway; the sibling appears only once the
/// policy is ALSO neutered. That is the same redundancy `ResourceServerRepo::get`
/// records, and it is the reason to have the case at all: this is the only test in
/// the file that can observe an over-inclusive list under any mutation.
#[tokio::test]
async fn the_list_walks_pages_by_cursor_without_repeating_or_skipping_a_row() {
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let base = servers_base(&tenant, &env_one);

    // Registered one at a time, so `created_at` (the first cursor column) increases
    // with registration order and the expected page order below is exactly this
    // vector.
    let mut expected = Vec::new();
    for index in 0..5 {
        expected.push(
            register(
                &h,
                &tenant,
                &env_one,
                &format!("https://api.example.test/svc-{index}"),
                TokenFormat::AtJwt,
            )
            .await,
        );
    }

    // A resource server of a SIBLING ENVIRONMENT of the same tenant. It must never
    // appear on any page: with the list's scope predicates gone it would.
    let foreign = register(
        &h,
        &tenant,
        &env_two,
        "https://api.example.test/foreign",
        TokenFormat::AtJwt,
    )
    .await;

    // Walk with a limit of 2 over 5 rows: three pages, and the last one short.
    let limit = 2;
    let mut walked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(value) => format!("{base}?limit={limit}&cursor={value}"),
            None => format!("{base}?limit={limit}"),
        };
        let (status, _, response) = h.get(&path).await;
        assert_eq!(status, StatusCode::OK, "page {pages}: {response}");
        let page: Value = serde_json::from_str(&response).expect("json");
        let items = page["items"].as_array().expect("items");
        assert!(
            items.len() <= limit,
            "page {pages} exceeded the requested limit of {limit}: {response}"
        );
        for item in items {
            walked.push(item["id"].as_str().expect("id").to_owned());
        }
        pages += 1;
        assert!(pages <= 10, "the cursor walk did not terminate: {response}");
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }

    assert_eq!(
        pages, 3,
        "five rows at two per page is three pages, so the limit was honoured: {walked:?}"
    );
    assert_eq!(
        walked, expected,
        "the walk must yield every row exactly once, in registration order, with no \
         repeat at a page boundary"
    );
    assert!(
        !walked.contains(&foreign),
        "a sibling environment's resource server must never appear on any page"
    );

    // And the sibling environment sees exactly its OWN row through the same
    // endpoint, so the absence above is isolation rather than the row missing.
    let (status, _, response) = h.get(&servers_base(&tenant, &env_two)).await;
    assert_eq!(status, StatusCode::OK, "foreign list: {response}");
    let foreign_ids: Vec<String> = serde_json::from_str::<Value>(&response).expect("json")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(foreign_ids, vec![foreign]);
}

#[tokio::test]
async fn enabling_the_opt_in_on_an_opaque_resource_server_is_a_typed_422() {
    let h = Harness::start(50).await;
    let (tenant, environment) = tenant_env(&h).await;
    let base = servers_base(&tenant, &environment);

    let opaque_id = register(
        &h,
        &tenant,
        &environment,
        "https://api.example.test/legacy",
        TokenFormat::Opaque,
    )
    .await;

    // ENABLING is refused, with a 422 (the value is well formed and names a real
    // field; what is wrong is the combination) that NAMES the reason.
    let (status, _, response) = h
        .patch(&format!("{base}/{opaque_id}"), &opt_in_body(true))
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "opaque opt-in: {response}"
    );
    let body: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        body["error"], "unprocessable_entity",
        "the refusal carries the typed error code: {response}"
    );
    let message = body["message"].as_str().expect("message");
    assert!(
        message.contains("opaque") && message.contains("at_jwt"),
        "the refusal must name the format that is required and the one that is set: {response}"
    );

    // And NOTHING was written: a refused enable leaves the row opted out.
    let (_, _, reread) = h.get(&format!("{base}/{opaque_id}")).await;
    assert_eq!(
        field(&reread, "permission_claims_enabled"),
        Value::Bool(false)
    );
    assert!(
        server_audit(&h, &tenant, &environment)
            .await
            .iter()
            .all(|action| action == "resource_server.register"),
        "a refused enable must write no opt-in audit row"
    );

    // DISABLING an opaque resource server is ALLOWED. This is the way out of the
    // state a config promotion can produce (see the module docs on resource_servers.rs
    // and migration 0094 section 4): the promotion apply writes token_format and the
    // opt-in from one snapshot with no handler in the path, so a row CAN reach
    // `opaque` plus opted-in, and a refusal here would trap it there forever.
    let (status, _, response) = h
        .patch(&format!("{base}/{opaque_id}"), &opt_in_body(false))
        .await;
    assert_eq!(status, StatusCode::OK, "opaque opt-OUT: {response}");
}

#[tokio::test]
async fn the_opaque_refusal_is_never_reachable_for_an_id_the_caller_cannot_address() {
    // The ORDERING assertion, and the reason the 422 is not an oracle. A caller who
    // cannot address the row must not be able to separate "that resource server is
    // not yours" from "that resource server does not exist" by observing a
    // format-specific refusal. Every probe below carries the body that WOULD be
    // refused with a 422 in its own environment.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    // The foreign scope differs in the ENVIRONMENT alone, under one tenant. A second
    // tenant would also be refused by the tenant predicate, so it would prove nothing
    // about the environment half of the fence.
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let base_one = servers_base(&tenant, &env_one);

    // A foreign OPAQUE resource server: the one shape that would produce a 422 if the
    // format were inspected before the address resolved.
    let foreign_opaque = register(
        &h,
        &tenant,
        &env_two,
        "https://api.example.test/foreign",
        TokenFormat::Opaque,
    )
    .await;
    // And an OWN opaque one, so the test proves the 422 is genuinely produced in this
    // environment for exactly the request that must be a 404 in the other.
    let own_opaque = register(
        &h,
        &tenant,
        &env_one,
        "https://api.example.test/own-legacy",
        TokenFormat::Opaque,
    )
    .await;
    let (status, _, _) = h
        .patch(&format!("{base_one}/{own_opaque}"), &opt_in_body(true))
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the 422 IS produced for an addressable opaque resource server, so a 404 \
         below is the address refusing and not the rule being absent"
    );

    let absent = fresh_in_scope_server(&tenant, &env_one);
    let probes = [
        ("foreign environment", foreign_opaque.clone()),
        ("malformed", "rsv_not-a-real-id".to_owned()),
        // Well formed and of THIS scope, but the wrong KIND of id.
        ("wrong prefix", fresh_in_scope_permission(&tenant, &env_one)),
        // A segment present but carrying nothing addressable. Percent encoded so it
        // REACHES the handler as a one-character id.
        ("blank", "%20".to_owned()),
    ];

    // --- The READ. ---
    let (absent_status, _, absent_body) = h.get(&format!("{base_one}/{absent}")).await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_str::<Value>(&absent_body).expect("json")["error"],
        "not_found"
    );
    for (label, probe) in &probes {
        let (status, _, body) = h.get(&format!("{base_one}/{probe}")).await;
        assert_eq!(status, absent_status, "get probe {label}: {body}");
        assert_eq!(body, absent_body, "get probe {label} body");
    }

    // --- The PATCH, with a body every layer accepts. ---
    let (absent_status, _, absent_body) = h
        .patch(&format!("{base_one}/{absent}"), &opt_in_body(false))
        .await;
    assert_eq!(absent_status, StatusCode::NOT_FOUND);
    for (label, probe) in &probes {
        let (status, _, body) = h
            .patch(&format!("{base_one}/{probe}"), &opt_in_body(false))
            .await;
        assert_eq!(status, absent_status, "patch probe {label}: {body}");
        assert_eq!(body, absent_body, "patch probe {label} body");
    }

    // --- The PATCH with a body that WOULD be refused on its own merits. This is the
    //     ordering assertion. The enable body is a 422 for an opaque resource server
    //     and an unparseable body is a 400, and each becomes a distinguishing signal
    //     the moment either runs before the address resolves. ---
    for (label, probe) in probes
        .iter()
        .chain(std::iter::once(&("never registered", absent.clone())))
    {
        for (shape, request) in [
            ("opaque-refused enable", opt_in_body(true)),
            ("unparseable", "not json at all".to_owned()),
            ("missing the required field", "{}".to_owned()),
        ] {
            let (status, _, body) = h.patch(&format!("{base_one}/{probe}"), &request).await;
            assert_eq!(
                status, absent_status,
                "patch probe {label} with a {shape} body must answer on the ADDRESS: {body}"
            );
            assert_eq!(
                body, absent_body,
                "patch probe {label} with a {shape} body must be byte-identical to the \
                 not-found reference"
            );
        }
    }

    // The foreign resource server is untouched by every probe above.
    let (_, _, foreign_read) = h
        .get(&format!(
            "{}/{foreign_opaque}",
            servers_base(&tenant, &env_two)
        ))
        .await;
    assert_eq!(
        field(&foreign_read, "permission_claims_enabled"),
        Value::Bool(false),
        "no cross-environment patch may land"
    );
}

/// The LOUD wrong-scope refusal: a management key used outside the environment it
/// was minted for is a 403 naming the mismatch, never the uniform not-found. That
/// posture is deliberate and shared with every other management surface: an
/// addressing failure is hidden, while a credential used in the wrong place is an
/// operator error worth reporting.
fn assert_wrong_scope(label: &str, status: StatusCode, body: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{label}: {body}");
    assert_eq!(
        serde_json::from_str::<Value>(body).expect("json")["error"],
        "wrong_scope",
        "{label} must be the LOUD wrong-scope refusal: {body}"
    );
}

#[tokio::test]
async fn an_environment_scoped_key_reaches_only_its_own_environments_registry() {
    // The CREDENTIAL half of the fence. Every test above drives the bootstrap
    // operator, which passes every scope check by design, so none of them says
    // anything about a management key. This one drives a real `mak_` key on all
    // three endpoints.
    let h = Harness::start(50).await;
    let (tenant, env_one) = tenant_env(&h).await;
    let env_two = h.create_environment(&tenant, "second", "k-env-2").await;
    let base_one = servers_base(&tenant, &env_one);
    let base_two = servers_base(&tenant, &env_two);

    // Environment two is seeded so every id-addressed probe below names a row that
    // genuinely EXISTS there: with the scope check gone the read answers 200 and the
    // mutation executes, rather than collapsing to a 404 that could be mistaken for
    // containment.
    let own = register(
        &h,
        &tenant,
        &env_one,
        "https://api.example.test/own",
        TokenFormat::AtJwt,
    )
    .await;
    let foreign = register(
        &h,
        &tenant,
        &env_two,
        "https://api.example.test/foreign",
        TokenFormat::AtJwt,
    )
    .await;
    let own_path = format!("{base_one}/{own}");
    let foreign_path = format!("{base_two}/{foreign}");

    // A key minted for env_one and nothing else.
    let key = h.create_key(&tenant, &env_one, "ci", "k-key").await;

    // --- Authorized on all three endpoints INSIDE environment one. ---
    let (status, _, body) = h.get_as(&base_one, &key).await;
    assert_eq!(status, StatusCode::OK, "own-environment list: {body}");
    let (status, _, body) = h.get_as(&own_path, &key).await;
    assert_eq!(status, StatusCode::OK, "own-environment get: {body}");
    let (status, _, body) = h.patch_as(&own_path, &key, &opt_in_body(true)).await;
    assert_eq!(status, StatusCode::OK, "own-environment patch: {body}");

    // --- The SAME key against environment two: the LOUD 403 on every one. ---
    let (status, _, body) = h.get_as(&base_two, &key).await;
    assert_wrong_scope("cross-environment list", status, &body);
    let (status, _, body) = h.get_as(&foreign_path, &key).await;
    assert_wrong_scope("cross-environment get", status, &body);
    let (status, _, body) = h.patch_as(&foreign_path, &key, &opt_in_body(true)).await;
    assert_wrong_scope("cross-environment patch", status, &body);

    // Environment two is exactly as it was: the refused patch moved nothing, and it
    // wrote no audit row either.
    let (_, _, foreign_read) = h.get(&foreign_path).await;
    assert_eq!(
        field(&foreign_read, "permission_claims_enabled"),
        Value::Bool(false),
        "no refused request touched environment two"
    );
    assert_eq!(
        server_audit(&h, &tenant, &env_two).await,
        vec!["resource_server.register"],
        "the only audited write in environment two is the seed registration"
    );
}
