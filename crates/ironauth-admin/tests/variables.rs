// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment variable management over HTTP (issue #235, follow-up to #45), driven through
//! the management router against a real database.
//!
//! The substrate has been live since #45: promotion writes variables and the reference
//! resolver reads them. What had never existed was a per-key surface, so the properties worth
//! proving here are the ones a wrapper can still get wrong.
//!
//! * The ROUND TRIP. A value written through `PUT` must be the value `GET` returns, and a
//!   second `PUT` must replace rather than duplicate. The store keys on `(scope, name)`, so a
//!   surface that generated a fresh row per write would look correct until the second write.
//! * The REFERENCE FENCE. Deleting a variable that another variable still points at would turn
//!   the next promotion plan into an unresolvable reference, failing far from the delete that
//!   caused it. The delete asks `referents` first and refuses with a conflict that NAMES the
//!   holder, which is the one behaviour here that is a decision rather than plumbing.
//! * SCOPE CONTAINMENT. Variables are `(tenant, environment)` scoped and row-level security is
//!   the fence, so a variable written in one environment must be invisible to its sibling. The
//!   fixtures below differ in the ENVIRONMENT alone, under one tenant: a second tenant would
//!   also be refused by the tenant predicate and so would prove nothing about the environment
//!   half.
//! * IDEMPOTENCY. `PUT` takes a required key and the record rides into the store write, so a
//!   replay must return the original response rather than re-running the write.

mod common;

use axum::http::StatusCode;
use common::Harness;
use serde_json::Value;

/// The `.../environments/{environment}/variables` base path.
fn base(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/variables")
}

fn body(value: &str) -> String {
    serde_json::json!({ "value": value }).to_string()
}

#[tokio::test]
async fn a_variable_round_trips_and_a_second_write_replaces_rather_than_duplicates() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = base(&tenant, &environment);

    let (status, _, response) = h
        .put_with_key(
            &format!("{root}/API_BASE"),
            "k-1",
            &body("https://one.test"),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "first write: {response}");

    let (status, _, response) = h.get(&format!("{root}/API_BASE")).await;
    assert_eq!(status, StatusCode::OK, "read back: {response}");
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["value"], "https://one.test");
    assert_eq!(value["name"], "API_BASE");
    let first_version = value["version"].as_i64().expect("version");

    // A second write REPLACES. The store keys on (scope, name), so a surface that minted a new
    // row per write would leave two and the list below would show it.
    let (status, _, response) = h
        .put_with_key(
            &format!("{root}/API_BASE"),
            "k-2",
            &body("https://two.test"),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "second write: {response}");

    let (_, _, response) = h.get(&format!("{root}/API_BASE")).await;
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["value"], "https://two.test", "the write replaced");
    assert!(
        value["version"].as_i64().expect("version") > first_version,
        "a replace advances the revision counter"
    );

    let (status, _, response) = h.get(&root).await;
    assert_eq!(status, StatusCode::OK, "list: {response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "one name is one row, not two: {response}");
}

#[tokio::test]
async fn deleting_a_variable_another_one_references_is_refused_and_names_the_holder() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = base(&tenant, &environment);

    let (status, _, _) = h
        .put_with_key(&format!("{root}/HOST"), "k-host", &body("api.test"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // A second variable whose VALUE is a reference to the first.
    let (status, _, _) = h
        .put_with_key(&format!("{root}/ENDPOINT"), "k-ep", &body("${var:HOST}"))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, response) = h.delete(&format!("{root}/HOST")).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "deleting a referenced variable must be refused, not silently break the next plan: \
         {response}"
    );
    assert!(
        response.contains("ENDPOINT"),
        "the refusal must NAME what still points at it, or an operator cannot act on it: \
         {response}"
    );

    // The referenced variable is still there: a refused delete removed nothing.
    let (status, _, _) = h.get(&format!("{root}/HOST")).await;
    assert_eq!(status, StatusCode::OK, "the refusal left the value intact");

    // Removing the holder first makes the delete legal.
    let (status, _, _) = h.delete(&format!("{root}/ENDPOINT")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, response) = h.delete(&format!("{root}/HOST")).await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "now unreferenced: {response}"
    );
    let (status, _, _) = h.get(&format!("{root}/HOST")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted is gone");
}

#[tokio::test]
async fn a_variable_is_invisible_to_a_sibling_environment() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let sibling = h.create_environment(&tenant, "sibling", "k-sibling").await;

    let (status, _, _) = h
        .put_with_key(
            &format!("{}/ONLY_HERE", base(&tenant, &environment)),
            "k-scope",
            &body("secret-ish"),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The fixtures differ in the ENVIRONMENT alone, under one tenant, so this proves the
    // environment half of the fence rather than the tenant predicate.
    let (status, _, response) = h
        .get(&format!("{}/ONLY_HERE", base(&tenant, &sibling)))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a sibling environment must not see it: {response}"
    );
    let (_, _, response) = h.get(&base(&tenant, &sibling)).await;
    let list: Value = serde_json::from_str(&response).expect("json");
    assert!(
        list["items"].as_array().expect("items").is_empty(),
        "nor list it: {response}"
    );
}

#[tokio::test]
async fn replaying_the_write_key_returns_the_original_response_and_writes_once() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = base(&tenant, &environment);

    let (first, _, _) = h
        .put_with_key(&format!("{root}/REPLAYED"), "k-same", &body("original"))
        .await;
    assert_eq!(first, StatusCode::NO_CONTENT);

    // The SAME key with the SAME body replays the stored response rather than re-running the
    // write. The value must therefore still be the original.
    let (again, _, response) = h
        .put_with_key(&format!("{root}/REPLAYED"), "k-same", &body("original"))
        .await;
    assert_eq!(again, StatusCode::NO_CONTENT, "replay: {response}");

    let (_, _, response) = h.get(&format!("{root}/REPLAYED")).await;
    let value: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(value["value"], "original");
    assert_eq!(
        value["version"].as_i64().expect("version"),
        1,
        "a replay must not advance the revision counter: {response}"
    );
}

#[tokio::test]
async fn an_invalid_name_is_refused_by_the_store_grammar_rather_than_a_500() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let root = base(&tenant, &environment);

    // The grammar lives in the store (`esv::name_is_valid`: alphanumeric, underscore, dot and
    // hyphen only) and is deliberately not re-implemented at the edge. What matters is that it
    // surfaces as a 400 rather than an opaque 500, which is the shape an unmapped StoreError
    // produces.
    //
    // `~` is chosen deliberately: it is UNRESERVED in RFC 3986, so it forms a legal URI and
    // reaches the handler, while failing the store grammar. A name with a space would be
    // rejected by the request builder instead and the test would prove nothing about the
    // handler.
    let (status, _, response) = h
        .put_with_key(&format!("{root}/BAD~NAME"), "k-bad", &body("x"))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an invalid name is the caller's error, not a server fault: {response}"
    );
}
