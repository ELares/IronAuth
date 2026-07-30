// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-client scope-allowlist management surface over HTTP (issue #98, PR 15),
//! driven through the management router against a real database.
//!
//! There is no client CREATE endpoint on the management API (the contract documents
//! none, and issue #98 adds none), so every fixture is created through the store,
//! which is how a client comes into existence today.
//!
//! Each of the following gets its own test because each is the kind of thing this
//! surface would be wrong about silently:
//!
//!   * The THREE STATES, round-tripped over HTTP. `null`, a populated array, and `[]`
//!     mean three different things, and the empty array is the one a naive
//!     implementation collapses into the clear.
//!   * ANTI-ORACLE uniformity. Every addressing failure must be ONE answer, byte for
//!     byte, in status AND body, on the read and on the write, or a caller can
//!     enumerate a sibling environment's clients one id at a time.
//!   * ORDERING of the body refusal against the address resolution. A 400 visible for
//!     a client the caller cannot address would be exactly that oracle.
//!   * The CREDENTIAL scope check. A test driving the operator proves containment of
//!     IDS and nothing about the credential, because the operator passes every scope
//!     check by design.
//!   * The FAIL-SAFE read. A corrupted stored value must surface to the console as
//!     `[]`, which is what the mint will enforce, and never as `null`.
//!   * The unmatchable-entry refusal, which is the one well-formedness rule this
//!     endpoint has and is deliberately NOT charset validation.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{
    ActorRef, ClientId, CorrelationId, EnvironmentId, Scope, ServiceId, TenantId,
};
use serde_json::Value;

/// The `.../clients/{client}/allowed-scopes` path.
fn allowed_scopes_path(tenant: &str, environment: &str, client: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/clients/{client}/allowed-scopes")
}

/// The `(tenant, environment)` scope parsed from two id path segments.
fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

/// Create a client through the store (there is no create endpoint) and return its
/// `cli_` id. A fresh client has NO allowlist, which is the state migration 0096
/// leaves every existing client in.
async fn create_client(h: &Harness, tenant: &str, environment: &str, name: &str) -> String {
    let env = Env::system();
    let scope = scope_of(tenant, environment);
    h.store()
        .scoped(scope)
        .acting(
            ActorRef::service(ServiceId::generate(&env)),
            CorrelationId::generate(&env),
        )
        .clients()
        .create(&env, name)
        .await
        .expect("create client")
        .to_string()
}

/// A well-formed client id in the given scope that names no client.
fn fresh_in_scope_client(tenant: &str, environment: &str) -> String {
    ClientId::generate(&Env::system(), &scope_of(tenant, environment)).to_string()
}

/// A PUT body naming an allowlist.
fn set_body(scopes: &[&str]) -> String {
    serde_json::json!({ "allowed_scopes": scopes }).to_string()
}

/// The `allowed_scopes` field of a response body.
fn allowed_scopes(response: &str) -> Value {
    serde_json::from_str::<Value>(response).expect("json")["allowed_scopes"].clone()
}

/// Every `client.allowed_scopes.set` audit row's target in one scope, sorted.
async fn audit_targets(h: &Harness, tenant: &str, environment: &str) -> Vec<String> {
    let mut targets: Vec<String> = h
        .control_store()
        .scoped(scope_of(tenant, environment))
        .audit()
        .list()
        .await
        .expect("audit list")
        .into_iter()
        .filter(|row| row.action == "client.allowed_scopes.set")
        .map(|row| row.target_id)
        .collect();
    targets.sort();
    targets
}

/// The three states round-trip over HTTP, and the response describes the NEW state
/// rather than echoing the request.
///
/// The empty array is the case worth its own assertion: it is a real, maximally
/// restrictive value, and an implementation that collapsed it into the NULL clear
/// would turn "this client may request no scope at all" into "this client may request
/// anything", which is the widening direction.
#[tokio::test]
async fn the_allowlist_round_trips_null_a_set_and_the_empty_array() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let client = create_client(&h, &tenant, &environment, "acme worker").await;
    let path = allowed_scopes_path(&tenant, &environment, &client);

    // A fresh client has NO allowlist.
    let (status, _, response) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get: {response}");
    assert_eq!(allowed_scopes(&response), Value::Null);
    assert_eq!(
        serde_json::from_str::<Value>(&response).expect("json")["client_id"],
        Value::String(client.clone()),
        "the view names the client it describes"
    );

    // SET a populated allowlist. Order is preserved, so the console can render what
    // the operator wrote.
    let (status, _, response) = h
        .put(&path, &set_body(&["read:orders", "write:orders"]))
        .await;
    assert_eq!(status, StatusCode::OK, "put: {response}");
    assert_eq!(
        allowed_scopes(&response),
        serde_json::json!(["read:orders", "write:orders"])
    );
    let (_, _, response) = h.get(&path).await;
    assert_eq!(
        allowed_scopes(&response),
        serde_json::json!(["read:orders", "write:orders"]),
        "the read agrees with the write"
    );

    // SET the EMPTY allowlist: a real value, NOT the clear.
    let (status, _, response) = h.put(&path, &set_body(&[])).await;
    assert_eq!(status, StatusCode::OK, "put empty: {response}");
    assert_eq!(
        allowed_scopes(&response),
        serde_json::json!([]),
        "the empty allowlist must NOT read back as null: they mean opposite things"
    );

    // CLEAR with an explicit null.
    let body = serde_json::json!({ "allowed_scopes": Value::Null }).to_string();
    let (status, _, response) = h.put(&path, &body).await;
    assert_eq!(status, StatusCode::OK, "put null: {response}");
    assert_eq!(allowed_scopes(&response), Value::Null);

    // Three writes, three audit rows, each naming the client.
    assert_eq!(
        audit_targets(&h, &tenant, &environment).await,
        vec![client.clone(), client.clone(), client],
        "every write is audited against the client it changed"
    );
}

/// An ABSENT `allowed_scopes` key is a 400 that names it, and it is NOT the same as
/// an explicit `null`.
///
/// Without this the empty object would be a legal request that does nothing, and a
/// caller who sent one would have no way to tell it apart from a request that was
/// applied.
#[tokio::test]
async fn an_absent_allowed_scopes_key_is_a_400_and_is_not_the_explicit_null() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let client = create_client(&h, &tenant, &environment, "acme worker").await;
    let path = allowed_scopes_path(&tenant, &environment, &client);

    // Seed a real allowlist, so a request that silently did nothing would be
    // distinguishable from one that cleared.
    let (status, _, response) = h.put(&path, &set_body(&["read:orders"])).await;
    assert_eq!(status, StatusCode::OK, "seed: {response}");

    let (status, _, response) = h.put(&path, "{}").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "empty object: {response}");
    assert!(
        response.contains("allowed_scopes is required"),
        "the refusal names the field: {response}"
    );

    // The stored allowlist is untouched: the refusal wrote nothing.
    let (_, _, response) = h.get(&path).await;
    assert_eq!(
        allowed_scopes(&response),
        serde_json::json!(["read:orders"]),
        "a refused request must not clear the allowlist"
    );
    assert_eq!(
        audit_targets(&h, &tenant, &environment).await.len(),
        1,
        "only the seed write is audited"
    );
}

/// An entry that could never MATCH a requested scope is refused with a typed 400
/// naming it, and this is NOT charset validation.
///
/// `validate_m2m_scope` splits a REQUEST on whitespace, so an entry that is empty or
/// carries whitespace can never equal a token that split produces. Accepting one with
/// a 200 would leave the operator believing they had allowlisted something while the
/// client's request was refused.
///
/// The second half of this test is the load-bearing half: `read:orders`, `urn:x:y`,
/// and `*` are all accepted unchanged, so a reader can see that no character class is
/// being policed. That asymmetry is deliberate and documented: `read:orders` is a
/// legal scope token while being an illegal PERMISSION slug under issue #98's
/// grammar.
#[tokio::test]
async fn an_unmatchable_entry_is_refused_but_no_charset_is_policed() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let client = create_client(&h, &tenant, &environment, "acme worker").await;
    let path = allowed_scopes_path(&tenant, &environment, &client);

    for entry in ["", "read:orders write:orders", "read\torders", " lead"] {
        let (status, _, response) = h.put(&path, &set_body(&[entry])).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the entry `{entry}` must be refused: {response}"
        );
        assert!(
            response.contains("allowed_scopes"),
            "the refusal names the field: {response}"
        );
    }
    let (_, _, response) = h.get(&path).await;
    assert_eq!(
        allowed_scopes(&response),
        Value::Null,
        "no refused entry was stored"
    );

    // NOT charset validation: punctuation, colons, dots, slashes, and a wildcard all
    // pass, because nothing here validates the scope alphabet.
    let permissive = [
        "read:orders",
        "urn:x:y",
        "https://api.example/scope",
        "a.b_c-d",
        "*",
        "SCOPE",
        "\u{e9}t\u{e9}",
    ];
    let (status, _, response) = h.put(&path, &set_body(&permissive)).await;
    assert_eq!(status, StatusCode::OK, "permissive entries: {response}");
    assert_eq!(allowed_scopes(&response), serde_json::json!(permissive));
}

/// Every addressing failure is ONE answer, byte for byte, on BOTH the read and the
/// write, and the body refusal is unreachable for a client the caller cannot address.
///
/// The last assertion is the ordering one: a malformed body sent to a FOREIGN client
/// must answer 404 and not 400. A 400 there would say "that client exists and is
/// yours to talk to", which is the oracle this uniformity exists to close.
#[tokio::test]
async fn every_addressing_failure_is_the_same_answer_on_both_verbs() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    // A SECOND environment of the same tenant, with a real client in it.
    let sibling = h.create_environment(&tenant, "sibling", "k-env-2").await;
    let foreign = create_client(&h, &tenant, &sibling, "sibling worker").await;

    let absent = fresh_in_scope_client(&tenant, &environment);
    let malformed = "not-a-client-id";
    let wrong_kind =
        ironauth_store::PermissionId::generate(&Env::system(), &scope_of(&tenant, &environment))
            .to_string();

    let mut read_answers = Vec::new();
    let mut write_answers = Vec::new();
    for candidate in [&foreign, &absent, &malformed.to_owned(), &wrong_kind] {
        let path = allowed_scopes_path(&tenant, &environment, candidate);
        let (status, _, response) = h.get(&path).await;
        read_answers.push((status, response));
        let (status, _, response) = h.put(&path, &set_body(&["read:orders"])).await;
        write_answers.push((status, response));
    }
    let first_read = read_answers[0].clone();
    for answer in &read_answers {
        assert_eq!(answer.0, StatusCode::NOT_FOUND, "read: {}", answer.1);
        assert_eq!(
            answer, &first_read,
            "every addressing failure must be the SAME answer on the read"
        );
    }
    let first_write = write_answers[0].clone();
    for answer in &write_answers {
        assert_eq!(answer.0, StatusCode::NOT_FOUND, "write: {}", answer.1);
        assert_eq!(
            answer, &first_write,
            "every addressing failure must be the SAME answer on the write"
        );
    }

    // ORDERING: EVERY body that would be a 400 for an addressable client is still the
    // uniform 404 for one the caller cannot address. All three refusal shapes are
    // driven, because they are refused at three different points in the handler and
    // each could independently be hoisted above the address resolve:
    //
    //   * unparseable JSON, refused by `parse_json`;
    //   * a parseable body OMITTING the required key, refused by the `let else`;
    //   * a parseable body whose ENTRY is unmatchable, refused by the entry check.
    //
    // A single `{}` probe covers only the middle one, which is how an earlier version
    // of this test let a hoisted `parse_json` survive.
    let foreign_path = allowed_scopes_path(&tenant, &environment, &foreign);
    for body in [
        "not json at all",
        "{",
        "{\"allowed_scopes\": 7}",
        "{}",
        &set_body(&["read orders"]),
        &set_body(&[""]),
    ] {
        let (status, _, response) = h.put(&foreign_path, body).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "the body refusal must not be reachable for a foreign client: {response}"
        );
        assert_eq!(
            (status, response),
            first_write,
            "the body `{body}` must answer on the ADDRESS, byte for byte"
        );
    }

    // And each of those bodies IS a 400 for a client the caller CAN address, so the
    // 404s above are the address refusing rather than the refusals being absent.
    let own = create_client(&h, &tenant, &environment, "own worker").await;
    let own_path = allowed_scopes_path(&tenant, &environment, &own);
    for body in [
        "not json at all",
        "{",
        "{\"allowed_scopes\": 7}",
        "{}",
        &set_body(&["read orders"]),
        &set_body(&[""]),
    ] {
        let (status, _, response) = h.put(&own_path, body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the body `{body}` must be a 400 for an addressable client: {response}"
        );
    }

    // The sibling environment's client is untouched by every one of those attempts.
    let sibling_path = allowed_scopes_path(&tenant, &sibling, &foreign);
    let (status, _, response) = h.get(&sibling_path).await;
    assert_eq!(status, StatusCode::OK, "sibling read: {response}");
    assert_eq!(
        allowed_scopes(&response),
        Value::Null,
        "no cross-environment write landed"
    );
}

/// A management key minted for ONE environment cannot read or write the allowlist of
/// a client in a SIBLING environment of the same tenant.
///
/// The test above drives the OPERATOR, which passes every scope check by design, so
/// it proves the containment of IDS and nothing about the credential. This one proves
/// the credential check, which is a different layer
/// (`Principal::require_environment` inside `resolve_scope`).
#[tokio::test]
async fn a_key_scoped_to_one_environment_cannot_reach_a_sibling() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let sibling = h.create_environment(&tenant, "sibling", "k-env-2").await;
    let victim = create_client(&h, &tenant, &sibling, "sibling worker").await;
    let key = h
        .create_key(&tenant, &environment, "scoped key", "k-key-1")
        .await;

    let path = allowed_scopes_path(&tenant, &sibling, &victim);
    let (status, _, response) = h.get_as(&path, &key).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key must not read a sibling environment's client: {response}"
    );
    let (status, _, response) = h.put_as(&path, &key, &set_body(&["read:orders"])).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a key must not write a sibling environment's client: {response}"
    );

    // Nothing landed.
    let (_, _, response) = h.get(&path).await;
    assert_eq!(allowed_scopes(&response), Value::Null);
}

/// A MALFORMED stored value surfaces to the console as `[]`, never as `null`.
///
/// The store's fail-safe parse reads an unparsable value as the EMPTY allowlist, and
/// this endpoint reports it verbatim rather than repairing it, because `[]` is
/// exactly what the mint will enforce. Reporting `null` would tell an operator their
/// client is unrestricted while every one of its machine-token requests is refused,
/// which is the most misleading answer available.
#[tokio::test]
async fn a_corrupted_stored_value_reads_as_the_empty_allowlist_over_http() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-tenant").await;
    let client = create_client(&h, &tenant, &environment, "acme worker").await;
    let path = allowed_scopes_path(&tenant, &environment, &client);

    // No setter can produce this, so it is planted through the owner pool: it stands
    // in for a hand-edited row or a restore from another format.
    sqlx::query("UPDATE clients SET allowed_scopes = $1::jsonb WHERE id = $2")
        .bind(r#"{"scopes": ["read:orders"]}"#)
        .bind(&client)
        .execute(h.db().owner_pool())
        .await
        .expect("plant the malformed value");

    let (status, _, response) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "get: {response}");
    assert_eq!(
        allowed_scopes(&response),
        serde_json::json!([]),
        "a corrupted allowlist must read as [] (deny everything), never as null"
    );
}
