// SPDX-License-Identifier: MIT OR Apache-2.0

//! The LDAP/AD connector management surface, and per-connector sync health (issue #142).
//!
//! # What each test is here for
//!
//! THE BIND SECRET NAMESPACE is the only rule in this module that is a security boundary. A
//! connector names an `environment_secrets` row and the sweep sends that value to `host` as a
//! bind password; no endpoint on this plane returns a secret, so a connector free to name any
//! secret turns the store into a read oracle -- point one at the database password, at a
//! directory you control, and the next tick delivers it. The refusal is asserted, and so is the
//! acceptance, because a prefix check that refused everything would pass the first alone.
//!
//! THE HEALTH LISTING IS ORGANIZATION SCOPED, which the health table cannot do by itself: it is
//! keyed by connector and carries no organization column. An operator delegated one organization
//! must not read another's directory hosts and failure states.
//!
//! THE REST IS REFUSING AT CONFIGURATION TIME what the sweep could never use, and refusing it as
//! a 400 rather than as the 500 a CHECK violation becomes.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    CorrelationId, EnvironmentId, LdapConnectorId, LdapRunOutcome, NewLdapRun, Scope, TenantId,
};
use serde_json::Value;

/// Create an organization through the management API and return its id.
async fn create_org(h: &Harness, tenant: &str, environment: &str, key: &str) -> String {
    let base = format!("/v1/tenants/{tenant}/environments/{environment}/organizations");
    let body = serde_json::json!({ "display_name": "Globex" }).to_string();
    let (status, _, response) = h.post(&base, key, &body).await;
    assert_eq!(status, StatusCode::CREATED, "create org: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

fn path(tenant: &str, environment: &str, org: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/organizations/{org}/ldap-connectors")
}

/// A well formed create.
fn create_body() -> Value {
    serde_json::json!({
        "display_name": "Contoso AD",
        "host": "ad.contoso.test",
        "port": 636,
        "bind_dn": "cn=svc,dc=contoso,dc=test",
        "bind_secret_name": "ldap_bind_contoso",
        "user_base_dn": "ou=people,dc=contoso,dc=test",
        "user_filter": "(objectClass=user)",
        "attribute_mapping": { "username": "sAMAccountName" }
    })
}

/// Configure one connector and return its id.
async fn configure(
    h: &Harness,
    tenant: &str,
    environment: &str,
    org: &str,
    key: &str,
    secret: &str,
) -> String {
    let mut body = create_body();
    body["bind_secret_name"] = Value::String(secret.to_owned());
    let (status, _, response) = h
        .post(&path(tenant, environment, org), key, &body.to_string())
        .await;
    assert_eq!(status, StatusCode::CREATED, "configure: {response}");
    serde_json::from_str::<Value>(&response).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned()
}

/// Record how a pass went for one connector, the way the sweep does.
async fn record_health(
    h: &Harness,
    tenant: &str,
    environment: &str,
    connector: &str,
    outcome: LdapRunOutcome,
    error: Option<&str>,
    apply_failures: i32,
) {
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    );
    let id = LdapConnectorId::parse_in_scope(connector, &scope).expect("connector id");
    h.db()
        .control_store()
        .scoped(scope)
        .acting(h.db().test_actor(&env), CorrelationId::generate(&env))
        .ldap_sync_runs()
        .record(&NewLdapRun {
            connector_id: &id,
            started_at_unix_micros: 1_767_323_045_678_901,
            duration_ms: 12,
            outcome,
            error,
            provisioned: 7,
            already_present: 3,
            deactivated: 2,
            deleted: 1,
            already_absent: 0,
            already_removed: 0,
            apply_failures,
        })
        .await
        .expect("record health");
}

/// THE SECURITY BOUNDARY. A connector that could name any secret makes the write-only secret
/// store readable by anybody who can configure one, because the sweep sends the value to a host
/// the same principal chose.
#[tokio::test]
async fn a_bind_secret_outside_the_connector_namespace_is_refused() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);

    for stolen in [
        "database_password",
        "ironauth.outbound_verification_token",
        "scim_push_downstream",
    ] {
        let mut body = create_body();
        body["bind_secret_name"] = Value::String(stolen.to_owned());
        let (status, _, response) = h
            .post(&base, &format!("k-{stolen}"), &body.to_string())
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "naming {stolen} was accepted: {response}"
        );
        assert!(
            response.contains("invalid_bind_secret_name"),
            "the refusal must name the field: {response}"
        );
    }
}

/// AND THE NAMESPACE IS REACHABLE. A prefix check that refused everything would satisfy the test
/// above and make the surface unusable.
#[tokio::test]
async fn a_bind_secret_inside_the_namespace_is_accepted() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);

    let (status, _, response) = h.post(&base, "k-create", &create_body().to_string()).await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let created: Value = serde_json::from_str(&response).expect("json");
    assert!(
        created["id"].as_str().expect("id").starts_with("ldc_"),
        "{response}"
    );
}

/// NOTHING IN A RESPONSE IS A SECRET, and there is nothing that could be: the row holds a NAME.
/// Here because "there is nothing to leak" stops being true the moment somebody adds a
/// convenience field that resolves it.
#[tokio::test]
async fn no_response_carries_a_secret_value() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);
    h.post(&base, "k-create", &create_body().to_string()).await;

    let (status, _, listing) = h.get(&base).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(
        listing.contains("ldap_bind_contoso"),
        "the NAME is the point of naming one: {listing}"
    );

    // EVERY FIELD THE VIEW RENDERS, against the values the create supplied. Without this, `host`
    // could publish the bind DN and `created_at_unix_ms` could publish raw microseconds -- a
    // 1000x error every console renders as a date tens of thousands of years out -- with the
    // suite green.
    let item = &serde_json::from_str::<Value>(&listing).expect("json")["items"][0];
    assert_eq!(item["host"], "ad.contoso.test", "{listing}");
    assert_eq!(item["port"], 636, "{listing}");
    assert_eq!(item["bind_dn"], "cn=svc,dc=contoso,dc=test", "{listing}");
    assert_eq!(
        item["user_base_dn"], "ou=people,dc=contoso,dc=test",
        "{listing}"
    );
    assert_eq!(item["user_filter"], "(objectClass=user)", "{listing}");
    assert_eq!(item["group_base_dn"], "", "{listing}");
    assert_eq!(item["group_filter"], "", "{listing}");
    assert_eq!(item["display_name"], "Contoso AD", "{listing}");
    assert_eq!(item["max_group_depth"], 10, "{listing}");
    assert_eq!(
        item["attribute_mapping"]["username"], "sAMAccountName",
        "{listing}"
    );
    // MILLISECONDS, as the field name and its doc both say. A recent create is within a decade
    // of now in millis and nowhere near it in micros.
    let created = item["created_at_unix_ms"].as_i64().expect("created_at");
    assert!(
        (1_600_000_000_000..4_000_000_000_000).contains(&created),
        "created_at_unix_ms is not milliseconds: {created}"
    );
    for field in ["bind_password", "password", "secret_value", "plaintext"] {
        assert!(
            !listing.contains(field),
            "the listing carries a {field} field: {listing}"
        );
    }
}

/// EVERY SHAPE RULE IS A 400, not the 500 a CHECK violation becomes. Each case here is a value
/// migration 0212 or 0213 refuses at the column.
#[tokio::test]
async fn misconfiguration_is_refused_as_a_bad_request() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);

    let cases: Vec<(&str, Value, &str)> = vec![
        ("empty host", serde_json::json!(""), "invalid_host"),
        (
            "long host",
            serde_json::json!("h".repeat(300)),
            "invalid_host",
        ),
    ];
    for (what, host, expected) in cases {
        let mut body = create_body();
        body["host"] = host;
        let (status, _, response) = h.post(&base, &format!("k-{what}"), &body.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {response}");
        assert!(response.contains(expected), "{what}: {response}");
    }

    // A GROUP BASE WITH NO FILTER: half a configuration, and 0213's CHECK refuses it.
    let mut body = create_body();
    body["group_base_dn"] = serde_json::json!("ou=groups,dc=contoso,dc=test");
    let (status, _, response) = h.post(&base, "k-halfgroup", &body.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("invalid_group_filter"), "{response}");

    // A DEPTH OUTSIDE 0212's RANGE.
    let mut body = create_body();
    body["max_group_depth"] = serde_json::json!(500);
    let (status, _, response) = h.post(&base, "k-depth", &body.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("invalid_max_group_depth"), "{response}");

    // AN UNKNOWN TLS MODE, rather than silently falling back to the insecure one.
    let mut body = create_body();
    body["tls_mode"] = serde_json::json!("whatever");
    let (status, _, response) = h.post(&base, "k-tls", &body.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("invalid_tls_mode"), "{response}");

    // A MAPPING THAT IS NOT AN OBJECT, which the mapper could not read.
    let mut body = create_body();
    body["attribute_mapping"] = serde_json::json!(["username"]);
    let (status, _, response) = h.post(&base, "k-map", &body.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert!(response.contains("invalid_attribute_mapping"), "{response}");
}

/// THE DEFAULTS ARE THE SAFE ONES. `ldaps` and `deactivate`, so the insecure and the
/// irreversible choice each have to be a value somebody typed.
#[tokio::test]
async fn the_defaults_are_ldaps_and_deactivate() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);
    h.post(&base, "k-create", &create_body().to_string()).await;

    let (_, _, listing) = h.get(&base).await;
    let items = serde_json::from_str::<Value>(&listing).expect("json");
    let first = &items["items"][0];
    assert_eq!(first["tls_mode"], "ldaps", "{listing}");
    assert_eq!(first["absence_policy"], "deactivate", "{listing}");
    assert_eq!(first["active"], true, "{listing}");
}

/// THE LISTING PAGINATES. Publishing a `cursor` that does nothing makes an organization's
/// connectors past the first page unreachable -- the defect the outbound SCIM listing next door
/// was corrected for, and the reason `created_at` is on the row at all.
#[tokio::test]
async fn the_listing_pages_through_every_connector() {
    let h = Harness::start(2).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);

    for n in 0..5 {
        let mut body = create_body();
        body["display_name"] = serde_json::json!(format!("Directory {n}"));
        body["bind_secret_name"] = serde_json::json!(format!("ldap_bind_{n}"));
        let (status, _, response) = h.post(&base, &format!("k-{n}"), &body.to_string()).await;
        assert_eq!(status, StatusCode::CREATED, "{response}");
    }

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let url = match &cursor {
            None => base.clone(),
            Some(c) => format!("{base}?cursor={c}"),
        };
        let (status, _, page) = h.get(&url).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let value: Value = serde_json::from_str(&page).expect("json");
        for item in value["items"].as_array().expect("items") {
            seen.push(item["id"].as_str().expect("id").to_owned());
        }
        match value["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    // COUNTED BEFORE ANY DEDUP. The keyset promise is that a row is never skipped OR RETURNED
    // TWICE, and deduping first erases the second half: a non-strict tie-break (`id >= $6`
    // rather than `id > $6`) returns the boundary row on every page and, at `limit=1`, never
    // advances at all -- an unbounded loop driven by server data. Deduping would have called
    // that a pass.
    let total = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        5,
        "paging did not reach every connector, so the cursor does nothing"
    );
    assert_eq!(
        total, 5,
        "a connector came back on more than one page, so the cursor's tie-break is not strict"
    );
}

/// AND AT A PAGE SIZE OF ONE, where a repeated boundary row consumes the whole page and the walk
/// never advances. The page size above is two, so a duplicate still leaves room for progress and
/// the loop terminates; here it does not, which is what makes the bound observable.
#[tokio::test]
async fn paging_one_at_a_time_terminates() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);
    for n in 0..4 {
        configure(
            &h,
            &tenant,
            &environment,
            &org,
            &format!("k-{n}"),
            &format!("ldap_bind_{n}"),
        )
        .await;
    }

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    // A HARD STOP well above the four pages a correct cursor needs, so a stuck walk fails the
    // count below rather than hanging the suite.
    for _ in 0..12 {
        let url = match &cursor {
            None => format!("{base}?limit=1"),
            Some(c) => format!("{base}?limit=1&cursor={c}"),
        };
        let (status, _, page) = h.get(&url).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let value: Value = serde_json::from_str(&page).expect("json");
        for item in value["items"].as_array().expect("items") {
            seen.push(item["id"].as_str().expect("id").to_owned());
        }
        match value["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    let distinct: std::collections::BTreeSet<&String> = seen.iter().collect();
    assert_eq!(
        (seen.len(), distinct.len()),
        (4, 4),
        "the one-at-a-time walk repeated or missed a connector: {seen:?}"
    );
}

/// HEALTH IS ORGANIZATION SCOPED. The table is keyed by connector and has no organization
/// column, so without the filter an operator delegated one organization reads every directory in
/// the environment -- host names and failure states included.
///
/// BOTH ORGANIZATIONS HAVE A HEALTH ROW, which is what makes this able to fail: with none, an
/// unfiltered listing and a filtered one are both empty.
#[tokio::test]
async fn health_shows_only_this_organizations_connectors() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "k1").await;
    let theirs = create_org(&h, &tenant, &environment, "k2").await;

    let my_id = configure(&h, &tenant, &environment, &mine, "k-mine", "ldap_bind_mine").await;
    let their_id = configure(
        &h,
        &tenant,
        &environment,
        &theirs,
        "k-theirs",
        "ldap_bind_theirs",
    )
    .await;

    // A pass reached both directories: mine succeeded, theirs could not be opened.
    record_health(
        &h,
        &tenant,
        &environment,
        &my_id,
        LdapRunOutcome::Planned,
        None,
        0,
    )
    .await;
    record_health(
        &h,
        &tenant,
        &environment,
        &their_id,
        LdapRunOutcome::Unreachable,
        Some("the directory could not be opened; see the log"),
        0,
    )
    .await;

    let (status, _, body) = h
        .get(&format!("{}/health", path(&tenant, &environment, &mine)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let value: Value = serde_json::from_str(&body).expect("json");
    let items = value["items"].as_array().expect("items");
    assert_eq!(
        items.len(),
        1,
        "the listing must hold exactly this organization's connector: {body}"
    );
    assert_eq!(items[0]["connector_id"], my_id, "{body}");
    assert_eq!(items[0]["healthy"], true, "{body}");
    // THE COUNTS THE VIEW PUBLISHES, each a distinct number so any two crossed in `health_view`
    // are visible. The fixture stamps a fixed instant, so the millisecond conversion is checked
    // against a known value rather than a range.
    assert_eq!(items[0]["provisioned"], 7, "{body}");
    assert_eq!(items[0]["already_present"], 3, "{body}");
    assert_eq!(items[0]["deactivated"], 2, "{body}");
    assert_eq!(items[0]["deleted"], 1, "{body}");
    assert_eq!(items[0]["apply_failures"], 0, "{body}");
    assert_eq!(items[0]["duration_ms"], 12, "{body}");
    assert_eq!(
        items[0]["last_run_at_unix_ms"], 1_767_323_045_678_i64,
        "last_run_at_unix_ms is not the fixture's instant in milliseconds: {body}"
    );
    assert_eq!(
        value["unhealthy"], 0,
        "another organization's broken directory was counted here: {body}"
    );
    assert!(
        !body.contains(&their_id),
        "the other organization's connector leaked into this listing: {body}"
    );

    // A CONNECTOR THAT BOUND FINE AND FAILED EVERY PRINCIPAL IS NOT HEALTHY. It reports
    // `planned`, so a `healthy` keyed on the outcome -- or on the failure counter alone -- calls
    // it fine. This is the case #142's isolation criterion exists to make visible, and without
    // it `healthy` and `outcome` move together in this fixture and nothing separates them.
    record_health(
        &h,
        &tenant,
        &environment,
        &my_id,
        LdapRunOutcome::Planned,
        None,
        9,
    )
    .await;
    let (_, _, body) = h
        .get(&format!("{}/health", path(&tenant, &environment, &mine)))
        .await;
    let value: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        value["items"][0]["outcome"], "planned",
        "it did bind: {body}"
    );
    assert_eq!(value["items"][0]["apply_failures"], 9, "{body}");
    assert_eq!(
        value["items"][0]["healthy"], false,
        "a connector that failed every principal reads as healthy: {body}"
    );
    assert_eq!(
        value["unhealthy"], 1,
        "the alert count an operator reads missed it: {body}"
    );

    // AND THEIRS SEES THEIRS, so the filter is a filter rather than a wall.
    let (_, _, body) = h
        .get(&format!("{}/health", path(&tenant, &environment, &theirs)))
        .await;
    let value: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["unhealthy"], 1, "{body}");
    assert_eq!(value["items"][0]["connector_id"], their_id, "{body}");
    assert_eq!(value["items"][0]["outcome"], "unreachable", "{body}");
}

/// PAUSE AND RESUME WITHOUT DELETING. An operator who suspects a directory wants it out of the
/// sweep, not out of the configuration.
#[tokio::test]
async fn a_connector_can_be_paused_and_resumed() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);
    let (_, _, created) = h.post(&base, "k-create", &create_body().to_string()).await;
    let id = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, _, body) = h
        .put(
            &format!("{base}/{id}/active"),
            &serde_json::json!({ "active": false }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, _, listing) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listing).expect("json")["items"][0]["active"],
        false,
        "{listing}"
    );

    let (status, _, body) = h
        .put(
            &format!("{base}/{id}/active"),
            &serde_json::json!({ "active": true }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (_, _, listing) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listing).expect("json")["items"][0]["active"],
        true,
        "{listing}"
    );
}

/// A CONNECTOR FROM ANOTHER ORGANIZATION IS A 404, not a refusal admitting it exists.
#[tokio::test]
async fn another_organizations_connector_is_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let mine = create_org(&h, &tenant, &environment, "k1").await;
    let theirs = create_org(&h, &tenant, &environment, "k2").await;
    let (_, _, created) = h
        .post(
            &path(&tenant, &environment, &theirs),
            "k-theirs",
            &create_body().to_string(),
        )
        .await;
    let id = serde_json::from_str::<Value>(&created).expect("json")["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let (status, _, body) = h
        .delete(&format!("{}/{id}", path(&tenant, &environment, &mine)))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "one organization deleted another's connector: {body}"
    );
    // AND IT SURVIVED. A 404 that deleted the row anyway would satisfy the assertion above.
    let (_, _, listing) = h.get(&path(&tenant, &environment, &theirs)).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listing).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        1,
        "{listing}"
    );
}

/// THE CREATE REPLAYS UNDER ITS KEY, rather than configuring a second directory.
#[tokio::test]
async fn a_repeated_create_replays_instead_of_configuring_twice() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let org = create_org(&h, &tenant, &environment, "k1").await;
    let base = path(&tenant, &environment, &org);

    let (first_status, _, first) = h.post(&base, "k-same", &create_body().to_string()).await;
    let (second_status, _, second) = h.post(&base, "k-same", &create_body().to_string()).await;

    assert_eq!(first_status, StatusCode::CREATED, "{first}");
    assert_eq!(second_status, StatusCode::CREATED, "{second}");
    assert_eq!(first, second, "the replay returned different bytes");
    let (_, _, listing) = h.get(&base).await;
    assert_eq!(
        serde_json::from_str::<Value>(&listing).expect("json")["items"]
            .as_array()
            .expect("items")
            .len(),
        1,
        "the retry configured a second directory: {listing}"
    );
}
