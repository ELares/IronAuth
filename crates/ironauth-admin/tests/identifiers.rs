// SPDX-License-Identifier: MIT OR Apache-2.0

//! Login identifier management over HTTP (issue #54, epic #514), driven through the
//! management router against a real database.
//!
//! The store half has been complete since #54. What had never existed was a production
//! WRITER: `ActingUserIdentifierRepo::add` had zero callers outside tests, so
//! `user_identifiers` was empty in every real deployment and the shipped readers in
//! federation, recovery and account resolution ran against an empty table. The
//! properties worth proving here are therefore the ones a wrapper can still get wrong.
//!
//! * CANONICALIZATION reaches the uniqueness check. Two raw values that differ only in
//!   case (or by an invisible character) are ONE identifier, so the second must be
//!   refused. A surface that compared raw values would pass a naive round-trip test and
//!   fail this one.
//! * The CONFIGURED MODE is read rather than assumed. This is the property the whole
//!   config seam exists for and the one that would have caught issue #459: a handler
//!   that passes a hardcoded `EnvironmentWide` behaves identically to a correct one
//!   under the default, and differs only when a non-default mode is installed. So the
//!   same collision is driven twice, under two modes, and must answer differently.
//! * SCOPE CONTAINMENT, since identifiers are `(tenant, environment)` scoped and row
//!   level security is the fence.
//! * IDEMPOTENCY, because the `Idempotency-Key` record rides into the same transaction
//!   as the row, so a replay must return the original response and write nothing.
//! * The EDGE GRAMMAR: an unknown kind and a value that canonicalizes to nothing are
//!   the caller's errors, not opaque 500s.
//! * REMOVAL FREES THE UNIQUENESS SLOT. This is the property that makes the remove a
//!   hard delete rather than a tombstone, and it is the one a soft-deleting
//!   implementation would fail while passing every other test here: the row IS the claim
//!   on the slot, so a tombstoned row would hold it forever and the identifier could
//!   never be re-added by anyone.
//! * REMOVAL IS FENCED BY THE OWNING USER, not just by scope, so an identifier cannot be
//!   removed through another user's path.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_config::{IdentifierUniqueness, IdentifiersConfig};
use serde_json::Value;

/// The identifiers collection path for a user.
fn base(tenant: &str, environment: &str, user: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/users/{user}/identifiers")
}

fn body(kind: &str, value: &str) -> String {
    serde_json::json!({ "type": kind, "value": value }).to_string()
}

/// Create a user in `(tenant, environment)` and return its `usr_` id.
async fn user(h: &Harness, tenant: &str, environment: &str, identifier: &str, key: &str) -> String {
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/users");
    let request = serde_json::json!({ "identifier": identifier }).to_string();
    let (status, _, response) = h.post(&path, key, &request).await;
    assert_eq!(status, StatusCode::CREATED, "seed user: {response}");
    let created: Value = serde_json::from_str(&response).expect("json");
    created["id"].as_str().expect("id").to_owned()
}

#[tokio::test]
async fn an_identifier_round_trips_and_canonicalization_decides_the_uniqueness_check() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let ada = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let grace = user(&h, &tenant, &environment, "grace@example.test", "k-grace").await;

    let (status, _, response) = h
        .post(
            &base(&tenant, &environment, &ada),
            "k-add",
            &body("email", "Ada@Example.TEST"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "add: {response}");
    let created: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(created["type"], "email");
    assert_eq!(
        created["value"], "Ada@Example.TEST",
        "the RAW submitted value is what is returned and sealed for display, not the \
         canonical form, which is the blind-index input: {response}"
    );
    assert_eq!(
        created["verified"], false,
        "an operator-added identifier is unverified until an M7 ceremony says otherwise"
    );
    let identifier_id = created["id"].as_str().expect("id").to_owned();

    let (status, _, response) = h.get(&base(&tenant, &environment, &ada)).await;
    assert_eq!(status, StatusCode::OK, "list: {response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "one identifier: {response}");
    assert_eq!(items[0]["id"], identifier_id.as_str());
    assert_eq!(items[0]["value"], "Ada@Example.TEST");

    // The SAME identifier in a different case, on a DIFFERENT user. Under the default
    // environment-wide mode this must be refused, and it is refused only because the
    // canonical form (not the raw string) is what the uniqueness key is computed over.
    let (status, _, response) = h
        .post(
            &base(&tenant, &environment, &grace),
            "k-dupe",
            &body("email", "ADA@example.test"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a case variant is the SAME identifier after canonicalization, so the second \
         claim must be refused rather than silently creating two login handles that \
         resolve to different users: {response}"
    );

    // The refusal wrote nothing: the audited add rolls back as a whole.
    let (_, _, response) = h.get(&base(&tenant, &environment, &grace)).await;
    let list: Value = serde_json::from_str(&response).expect("json");
    assert!(
        list["items"].as_array().expect("items").is_empty(),
        "a refused add leaves no row: {response}"
    );
}

#[tokio::test]
async fn the_configured_uniqueness_mode_is_read_rather_than_assumed() {
    // The SAME collision the test above drives to a 409, under a NON-DEFAULT mode. This
    // is the pair that measures the config seam: a handler passing a hardcoded
    // `EnvironmentWide` is indistinguishable from a correct one under the default and
    // differs only here. Before this surface existed the section had no reader at all
    // and every write took the default no matter what the operator wrote (issue #459).
    let h = Harness::start_with_identifiers(
        50,
        &IdentifiersConfig {
            uniqueness: IdentifierUniqueness::NonUnique,
        },
    )
    .await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let ada = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let grace = user(&h, &tenant, &environment, "grace@example.test", "k-grace").await;

    let (status, _, response) = h
        .post(
            &base(&tenant, &environment, &ada),
            "k-first",
            &body("email", "shared@example.test"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "first: {response}");

    let (status, _, response) = h
        .post(
            &base(&tenant, &environment, &grace),
            "k-second",
            &body("email", "shared@example.test"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "under `non_unique` the second claim of one canonical identifier must be \
         ACCEPTED. A 409 here means the handler ignored the installed mode and passed a \
         constant, which is exactly the inert-knob defect this surface exists to close: \
         {response}"
    );
}

#[tokio::test]
async fn an_identifier_is_invisible_to_a_sibling_environment() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let sibling = h.create_environment(&tenant, "sibling", "k-sibling").await;
    let here = user(&h, &tenant, &environment, "ada@example.test", "k-here").await;
    let there = user(&h, &tenant, &sibling, "ada@example.test", "k-there").await;

    let (status, _, _) = h
        .post(
            &base(&tenant, &environment, &here),
            "k-scoped",
            &body("email", "only@example.test"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // The fixtures differ in the ENVIRONMENT alone, under one tenant, so this measures
    // the environment half of the fence rather than the tenant predicate.
    let (status, _, response) = h.get(&base(&tenant, &sibling, &there)).await;
    assert_eq!(status, StatusCode::OK, "sibling list: {response}");
    let list: Value = serde_json::from_str(&response).expect("json");
    assert!(
        list["items"].as_array().expect("items").is_empty(),
        "the sibling environment must not see it: {response}"
    );

    // Nor does the uniqueness scope reach across: the same canonical identifier is free
    // in the sibling environment, because the key is per (tenant, environment).
    let (status, _, response) = h
        .post(
            &base(&tenant, &sibling, &there),
            "k-sibling-add",
            &body("email", "only@example.test"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "environment-wide uniqueness is bounded by the environment: {response}"
    );
}

#[tokio::test]
async fn replaying_the_write_key_returns_the_original_response_and_writes_once() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let ada = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let path = base(&tenant, &environment, &ada);

    let (first, _, first_body) = h
        .post(&path, "k-same", &body("email", "replay@example.test"))
        .await;
    assert_eq!(first, StatusCode::CREATED);

    // The SAME key with the SAME body replays the stored response rather than re-running
    // the write. Re-running it would hit the partial unique index and answer 409, so a
    // surface that recorded no key would be observably different here.
    let (again, _, again_body) = h
        .post(&path, "k-same", &body("email", "replay@example.test"))
        .await;
    assert_eq!(again, StatusCode::CREATED, "replay: {again_body}");
    assert_eq!(
        again_body, first_body,
        "a replay returns the ORIGINAL response, id included"
    );

    let (_, _, response) = h.get(&path).await;
    let list: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        list["items"].as_array().expect("items").len(),
        1,
        "the replay wrote nothing: {response}"
    );
}

#[tokio::test]
async fn an_unknown_kind_and_a_degenerate_value_are_the_callers_errors() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let ada = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let path = base(&tenant, &environment, &ada);

    // An unknown kind is refused at the edge through the store's own parser, so this
    // surface holds no second copy of the closed set that could drift from migration
    // 0041's CHECK constraint.
    let (status, _, response) = h
        .post(&path, "k-kind", &body("passport", "ada@example.test"))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown kind must not reach the CHECK constraint as a 500: {response}"
    );

    // A value made only of characters canonicalization strips reduces to the empty
    // canonical form. The store refuses it deterministically rather than letting it
    // squat the "empty" slot, and that refusal must surface as a 400.
    let (status, _, response) = h
        .post(&path, "k-empty", &body("username", "\u{200b} \u{feff}"))
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an identifier that canonicalizes to nothing is a caller error, not a 500: \
         {response}"
    );
}

#[tokio::test]
async fn an_absent_user_is_the_uniform_not_found_on_both_operations() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let absent = format!("usr_{}", "0".repeat(26));
    let path = base(&tenant, &environment, &absent);

    let (status, _, response) = h.get(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "list: {response}");

    let (status, _, response) = h
        .post(&path, "k-absent", &body("email", "ghost@example.test"))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "add: {response}");
}

/// Add one identifier to `user` and return its row id.
async fn add(
    h: &Harness,
    tenant: &str,
    environment: &str,
    user: &str,
    value: &str,
    key: &str,
) -> String {
    let (status, _, response) = h
        .post(&base(tenant, environment, user), key, &body("email", value))
        .await;
    assert_eq!(status, StatusCode::CREATED, "add {value}: {response}");
    let created: Value = serde_json::from_str(&response).expect("json");
    created["id"].as_str().expect("id").to_owned()
}

#[tokio::test]
async fn an_identifier_is_removed_and_removing_it_again_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let ada = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let id = add(&h, &tenant, &environment, &ada, "old@example.test", "k-add").await;
    let path = format!("{}/{id}", base(&tenant, &environment, &ada));

    let (status, _, response) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "remove: {response}");

    let (_, _, response) = h.get(&base(&tenant, &environment, &ada)).await;
    let list: Value = serde_json::from_str(&response).expect("json");
    assert!(
        list["items"].as_array().expect("items").is_empty(),
        "the removed identifier is gone from the list: {response}"
    );

    // Removing it again is the uniform not-found, never a silent 204: a caller that got
    // a success for a row that is not there learns the wrong thing about what exists.
    let (status, _, response) = h.delete(&path).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "second remove: {response}");
}

#[tokio::test]
async fn removing_an_identifier_frees_the_uniqueness_slot() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let ada = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let grace = user(&h, &tenant, &environment, "grace@example.test", "k-grace").await;

    let id = add(
        &h,
        &tenant,
        &environment,
        &ada,
        "shared@example.test",
        "k-1",
    )
    .await;
    // While it is held, the canonical identifier is taken environment-wide.
    let (status, _, response) = h
        .post(
            &base(&tenant, &environment, &grace),
            "k-blocked",
            &body("email", "shared@example.test"),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "still held: {response}");

    let (status, _, _) = h
        .delete(&format!("{}/{id}", base(&tenant, &environment, &ada)))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The slot is now FREE. A tombstoning implementation would keep the partial unique
    // index populated and answer 409 here forever, with nothing to show the caller why,
    // which is the whole reason 0104 grants a real DELETE.
    let (status, _, response) = h
        .post(
            &base(&tenant, &environment, &grace),
            "k-freed",
            &body("email", "shared@example.test"),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "removal must FREE the uniqueness slot, or an identifier could never be \
         re-homed after it is given up: {response}"
    );
}

#[tokio::test]
async fn an_identifier_cannot_be_removed_through_another_users_path() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let ada = user(&h, &tenant, &environment, "ada@example.test", "k-ada").await;
    let grace = user(&h, &tenant, &environment, "grace@example.test", "k-grace").await;
    let id = add(
        &h,
        &tenant,
        &environment,
        &ada,
        "ada-only@example.test",
        "k-add",
    )
    .await;

    // Same tenant, same environment, same well-formed row id, WRONG owning user. The
    // DELETE is keyed on the user too, so this is the uniform not-found rather than a
    // successful removal of someone else's login handle.
    let (status, _, response) = h
        .delete(&format!("{}/{id}", base(&tenant, &environment, &grace)))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an identifier must not be removable through another user's path: {response}"
    );

    // And it is genuinely still there: the refusal removed nothing.
    let (_, _, response) = h.get(&base(&tenant, &environment, &ada)).await;
    let list: Value = serde_json::from_str(&response).expect("json");
    assert_eq!(
        list["items"].as_array().expect("items").len(),
        1,
        "the refused remove left the row intact: {response}"
    );
}
