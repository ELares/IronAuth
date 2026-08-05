// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity trait schemas over HTTP (issue #53, PR 1): the registry management surface, the
//! validation wired into the user create and PATCH, the admin-only visibility split, and the
//! arrays-and-nested-objects round trip.
//!
//! The four decisive properties, one test each:
//!
//! - **A violating payload is refused with the right pointer PER FIELD** and creates nothing.
//!   The refusal is the structured `trait_errors` list, not a flattened sentence.
//! - **A valid payload PERSISTS the version it validated against**, and a later activation of
//!   a new version does not retroactively restamp it (that is what makes a migration job able
//!   to select the identities still on the old one).
//! - **Admin-only metadata is invisible AND immutable through self service.** Both halves:
//!   a self-service write cannot SET one, and a self-service write that omits one (which every
//!   self-service write does, because the self-service READ redacts it) cannot CLEAR it.
//! - **A trait document containing BOTH an array and a nested object survives create, PATCH
//!   and export byte for byte.** This is the named Kratos regression; a flat object would not
//!   exercise it.
//!
//!   What is new here is the ARRAY AND NESTING half, not export coverage as such:
//!   `tests/export.rs` already seeds a traits-carrying identity and pins its
//!   `traits_schema_version` through a round trip. That test's document is a FLAT object, so
//!   it cannot see an implementation that reorders, dedupes, or flattens; this one carries a
//!   three-element array of objects and a nested object, and its PATCH removes an element,
//!   reverses the survivors, and adds a nested member.
//!
//! Plus the registry's own management contract: create is idempotent on the key and appends,
//! a malformed schema is a precise 400 that stores nothing, activation is CUTOVER GATED
//! (refused while an identity fails the target schema), and every read is scope fenced.

mod common;

use common::Harness;

use axum::http::StatusCode;
use ironauth_env::Env;
use ironauth_store::{
    CorrelationId, EnvironmentId, Scope, StoreError, TenantId, TraitWriteVisibility, UserId,
};
use serde_json::{Value, json};

/// A schema with a user-visible string, a NESTED OBJECT, an ARRAY OF OBJECTS, and an
/// ADMIN-ONLY integer. One schema exercises every property this file pins.
fn schema_document() -> Value {
    json!({
        "type": "object",
        "properties": {
            "nickname": {"type": "string", "minLength": 2, "maxLength": 20},
            "address": {
                "type": "object",
                "properties": {
                    "city": {"type": "string"},
                    "zip": {"type": "string", "maxLength": 10},
                    "country": {"type": "string"}
                },
                "required": ["city"]
            },
            "phones": {
                "type": "array",
                "maxItems": 4,
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["mobile", "home"]},
                        "number": {"type": "string"}
                    },
                    "required": ["number"]
                }
            },
            "risk_score": {"type": "integer", "x-ironauth": {"visibility": "admin"}}
        },
        "required": ["nickname"]
    })
}

/// The genuinely nested, genuinely array-valued trait document. NOT a flat object: the whole
/// point of the named regression is that a competitor breaks on exactly this shape.
fn nested_traits() -> Value {
    json!({
        "nickname": "ada",
        "address": {"city": "London", "zip": "NW1"},
        "phones": [
            {"kind": "mobile", "number": "+44 700 900001"},
            {"kind": "home", "number": "+44 20 7946 0000"},
            {"kind": "mobile", "number": "+44 700 900002"}
        ]
    })
}

fn schemas_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/trait-schemas")
}

fn users_path(tenant: &str, environment: &str) -> String {
    format!("/v1/tenants/{tenant}/environments/{environment}/users")
}

fn scope_of(tenant: &str, environment: &str) -> Scope {
    Scope::new(
        TenantId::parse(tenant).expect("tenant id"),
        EnvironmentId::parse(environment).expect("environment id"),
    )
}

fn parse(body: &str) -> Value {
    serde_json::from_str(body).expect("json body")
}

/// Register `document` as a new version and ACTIVATE it, returning the version number.
async fn register_active_schema(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    document: &Value,
    key: &str,
) -> i64 {
    let path = schemas_path(tenant, environment);
    let body = json!({"schema": document}).to_string();
    let (status, _, created) = harness.post(&path, &format!("{key}-create"), &body).await;
    assert_eq!(status, StatusCode::OK, "create schema: {created}");
    let version = parse(&created)["version"].as_i64().expect("version");
    let (status, _, activated) = harness
        .post(
            &format!("{path}/{version}/activate"),
            &format!("{key}-activate"),
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "activate schema: {activated}");
    assert_eq!(parse(&activated)["active"], json!(true));
    version
}

/// Create a user carrying `traits`, returning the raw `(status, body)`.
async fn create_user_with_traits(
    harness: &Harness,
    tenant: &str,
    environment: &str,
    identifier: &str,
    traits: &Value,
    key: &str,
) -> (StatusCode, String) {
    let body = json!({"identifier": identifier, "traits": traits}).to_string();
    let (status, _, response) = harness
        .post(&users_path(tenant, environment), key, &body)
        .await;
    (status, response)
}

#[tokio::test]
async fn a_violating_payload_is_refused_with_a_json_pointer_per_field_and_creates_nothing() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    register_active_schema(&harness, &tenant, &env, &schema_document(), "s1").await;

    // THREE independent violations, at three different DEPTHS: a top-level scalar of the wrong
    // type, a missing property inside a NESTED OBJECT, and a wrong type inside an ARRAY ELEMENT.
    // A validator that only reported the first, or only reported top-level fields, passes a
    // flat-object test and fails this one.
    let bad = json!({
        "nickname": 7,
        "address": {"zip": "NW1 000000000000000"},
        "phones": [{"kind": "mobile", "number": "ok"}, {"kind": "mobile", "number": 12345}]
    });
    let (status, response) =
        create_user_with_traits(&harness, &tenant, &env, "bad@example.test", &bad, "u1").await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a violating traits document is refused: {response}"
    );
    let body = parse(&response);
    assert_eq!(body["error"], json!("traits_invalid"), "{response}");

    // The refusal is STRUCTURED: one entry per failing field, each with its RFC 6901 pointer.
    let errors = body["trait_errors"]
        .as_array()
        .expect("trait_errors is a list, not a flattened string");
    let pointers: Vec<&str> = errors
        .iter()
        .map(|entry| entry["pointer"].as_str().expect("pointer"))
        .collect();
    assert!(
        pointers.contains(&"/nickname"),
        "the top-level type failure points at /nickname: {pointers:?}"
    );
    assert!(
        pointers.contains(&"/address/city"),
        "the nested missing-required failure points at the MISSING MEMBER, not merely at the \
         object holding it: {pointers:?}"
    );
    assert!(
        pointers.contains(&"/phones/1/number"),
        "the array-element failure points at the INDEXED element and its field: {pointers:?}"
    );
    // A FOURTH failure, and the one that makes the no-echo check below mean something: the
    // nested `zip` violates `maxLength`, so a failure for that field EXISTS and its message
    // is a message that had the offending value in hand and chose not to carry it. The
    // earlier cut submitted a `zip` that PASSED the schema, so half the no-echo assertion
    // was ranging over failures that could not have mentioned it (MEASURED: no entry named
    // `/address/zip` at all).
    assert!(
        pointers.contains(&"/address/zip"),
        "the nested length failure points at the offending member: {pointers:?}"
    );
    // No entry echoes a submitted VALUE, so a refusal carries no trait PII. Both needles
    // are values this very payload submitted at a location that FAILED.
    for entry in errors {
        let message = entry["message"].as_str().expect("message");
        assert!(
            !message.contains("NW1") && !message.contains("12345"),
            "a failure reason must name a dimension, never the offending value: {message}"
        );
    }

    // NOTHING was created: the user list is empty.
    let (status, _, list) = harness.get(&users_path(&tenant, &env)).await;
    assert_eq!(status, StatusCode::OK, "list: {list}");
    assert_eq!(
        parse(&list)["items"].as_array().expect("items").len(),
        0,
        "a refused create writes no user: {list}"
    );
}

#[tokio::test]
async fn a_valid_payload_persists_the_schema_version_it_validated_against() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let v1 = register_active_schema(&harness, &tenant, &env, &schema_document(), "s1").await;
    assert_eq!(v1, 1, "the first version is 1");

    let (status, response) = create_user_with_traits(
        &harness,
        &tenant,
        &env,
        "ada@example.test",
        &nested_traits(),
        "u1",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {response}");
    let user_id = parse(&response)["id"].as_str().expect("id").to_owned();

    let traits_path = format!("{}/{user_id}/traits", users_path(&tenant, &env));
    let (status, _, read) = harness.get(&traits_path).await;
    assert_eq!(status, StatusCode::OK, "read traits: {read}");
    assert_eq!(
        parse(&read)["schema_version"],
        json!(v1),
        "the identity records the version it validated against: {read}"
    );

    // Register and activate a SECOND version. The identity's stamp must NOT move: it records
    // what it was validated against, not what the environment currently serves. This is the
    // property that lets a migration job select the identities still on the old version, so a
    // stamp that tracked the active pointer would make the whole migration surface inert.
    let mut widened = schema_document();
    widened["properties"]["motto"] = json!({"type": "string"});
    let v2 = register_active_schema(&harness, &tenant, &env, &widened, "s2").await;
    assert_eq!(v2, 2);
    let (status, _, after) = harness.get(&traits_path).await;
    assert_eq!(status, StatusCode::OK, "re-read traits: {after}");
    assert_eq!(
        parse(&after)["schema_version"],
        json!(v1),
        "activating a new version does not restamp existing identities: {after}"
    );

    // A user created NOW, while v2 is the active default, must stamp 2. This is the case
    // that separates "the create records the ACTIVE version" from "the create records 1":
    // every other assertion in this test is taken while v1 is active or on a user created
    // then, so a constant would satisfy all of them. MEASURED: mutating the create's stamp
    // to the literal 1 SURVIVED the rest of this file.
    let (status, later) = create_user_with_traits(
        &harness,
        &tenant,
        &env,
        "grace@example.test",
        &nested_traits(),
        "u2",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "later create: {later}");
    let later_id = parse(&later)["id"].as_str().expect("id").to_owned();
    let (status, _, later_traits) = harness
        .get(&format!("{}/{later_id}/traits", users_path(&tenant, &env)))
        .await;
    assert_eq!(status, StatusCode::OK, "{later_traits}");
    assert_eq!(
        parse(&later_traits)["schema_version"],
        json!(v2),
        "a create under a NEWER active version stamps that version, not a constant: \
         {later_traits}"
    );

    // A PATCH re-validates against the NOW-active version and restamps to it.
    let patch = json!({"traits": nested_traits()}).to_string();
    let (status, _, patched) = harness
        .patch(&format!("{}/{user_id}", users_path(&tenant, &env)), &patch)
        .await;
    assert_eq!(status, StatusCode::OK, "patch: {patched}");
    let (status, _, restamped) = harness.get(&traits_path).await;
    assert_eq!(status, StatusCode::OK, "read after patch: {restamped}");
    assert_eq!(
        parse(&restamped)["schema_version"],
        json!(v2),
        "a re-validated write stamps the version it validated against: {restamped}"
    );
}

#[tokio::test]
async fn admin_only_metadata_is_invisible_and_immutable_through_self_service() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    register_active_schema(&harness, &tenant, &env, &schema_document(), "s1").await;

    // An ADMIN write sets both a user-visible field and the admin-only one. This is the plane
    // where admin-only metadata is written, so it must SUCCEED here.
    let mut with_admin_field = nested_traits();
    with_admin_field["risk_score"] = json!(90);
    let (status, response) = create_user_with_traits(
        &harness,
        &tenant,
        &env,
        "ada@example.test",
        &with_admin_field,
        "u1",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "admin create: {response}");
    let user_id = parse(&response)["id"].as_str().expect("id").to_owned();
    let scope = scope_of(&tenant, &env);
    let id = UserId::parse_in_scope(&user_id, &scope).expect("user id");
    let system = Env::system();

    // INVISIBLE: the self-service projection strips it; the management read still shows it.
    let visible = harness
        .store()
        .scoped(scope)
        .users()
        .traits_user_visible(&id)
        .await
        .expect("read")
        .expect("traits");
    assert_eq!(
        visible.get("risk_score"),
        None,
        "the self-service read must not carry admin-only metadata: {visible}"
    );
    assert_eq!(
        visible.get("nickname"),
        Some(&json!("ada")),
        "user-visible fields survive the redaction: {visible}"
    );
    let (status, _, admin_read) = harness
        .get(&format!("{}/{user_id}/traits", users_path(&tenant, &env)))
        .await;
    assert_eq!(status, StatusCode::OK, "{admin_read}");
    assert_eq!(
        parse(&admin_read)["traits"]["risk_score"],
        json!(90),
        "the MANAGEMENT read is the full document: {admin_read}"
    );

    // IMMUTABLE, half one: a self-service write cannot SET it.
    let acting = harness.store().scoped(scope).acting(
        harness.test_actor(&system),
        CorrelationId::generate(&system),
    );
    let mut hostile = nested_traits();
    hostile["risk_score"] = json!(0);
    let refused = acting
        .users()
        .set_traits_with_visibility(
            &system,
            &id,
            &hostile.to_string(),
            TraitWriteVisibility::SelfService,
        )
        .await
        .expect_err("a self-service write naming an admin-only field must be refused");
    let StoreError::TraitsInvalid(failures) = refused else {
        panic!("expected a per-field refusal, got {refused:?}");
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].pointer, "/risk_score");

    // IMMUTABLE, half two, and the half that is easy to miss: a self-service write that OMITS
    // the admin-only field cannot CLEAR it. This is the shape EVERY well-behaved self-service
    // write has, because the self-service read redacted the field out of the document the
    // caller round-trips. Without preservation, the ordinary path silently deletes admin
    // metadata; the refusal above would still pass and the property would still be broken.
    let mut renamed = nested_traits();
    renamed["nickname"] = json!("ada-2");
    acting
        .users()
        .set_traits_with_visibility(
            &system,
            &id,
            &renamed.to_string(),
            TraitWriteVisibility::SelfService,
        )
        .await
        .expect("a self-service write of only user-visible fields is allowed");
    let (_, full) = harness
        .store()
        .scoped(scope)
        .users()
        .traits(&id)
        .await
        .expect("read")
        .expect("traits");
    assert_eq!(
        full["risk_score"],
        json!(90),
        "the admin-only field survived a self-service write that omitted it: {full}"
    );
    assert_eq!(
        full["nickname"],
        json!("ada-2"),
        "the user-visible field the write DID carry was updated: {full}"
    );
}

#[tokio::test]
async fn arrays_and_nested_objects_round_trip_through_create_patch_and_export() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    register_active_schema(&harness, &tenant, &env, &schema_document(), "s1").await;

    // CREATE with a document carrying BOTH an array of objects and a nested object.
    let created_traits = nested_traits();
    let (status, response) = create_user_with_traits(
        &harness,
        &tenant,
        &env,
        "ada@example.test",
        &created_traits,
        "u1",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {response}");
    let user_id = parse(&response)["id"].as_str().expect("id").to_owned();
    let traits_path = format!("{}/{user_id}/traits", users_path(&tenant, &env));

    let (status, _, read) = harness.get(&traits_path).await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(
        parse(&read)["traits"],
        created_traits,
        "the created document round-trips byte for byte, arrays and nesting included: {read}"
    );

    // PATCH with a DIFFERENT nested/array shape, and it has to DIFFER in three independent
    // ways or it is not testing what the comment says. The fixture carries THREE phones, so
    // this payload REMOVES one (a stale-element bug shows), REVERSES the order of the two
    // survivors (an implementation that sorts or dedupes shows), and ADDS a nested member
    // (`address.country`, absent from the created document) rather than only changing the
    // values of members that were already there.
    let patched_traits = json!({
        "nickname": "ada",
        "address": {"city": "Paris", "zip": "75001", "country": "FR"},
        "phones": [
            {"kind": "mobile", "number": "+44 700 900002"},
            {"kind": "home", "number": "+44 20 7946 0000"}
        ]
    });
    // The three differences, asserted against the CREATED document rather than assumed, so
    // the payload cannot silently drift back to a trivial one.
    assert_eq!(
        created_traits["phones"].as_array().expect("phones").len(),
        patched_traits["phones"].as_array().expect("phones").len() + 1,
        "the patch REMOVES an array element"
    );
    assert_eq!(
        patched_traits["phones"][0], created_traits["phones"][2],
        "the surviving elements are REVERSED relative to the created order"
    );
    assert_eq!(
        created_traits["address"].get("country"),
        None,
        "the patch ADDS a nested member that was absent"
    );
    let patch = json!({"traits": patched_traits}).to_string();
    let (status, _, patched) = harness
        .patch(&format!("{}/{user_id}", users_path(&tenant, &env)), &patch)
        .await;
    assert_eq!(status, StatusCode::OK, "patch: {patched}");
    let (status, _, after) = harness.get(&traits_path).await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(
        parse(&after)["traits"],
        patched_traits,
        "the PATCHed document round-trips byte for byte, and REPLACES rather than merging \
         (the removed phone is gone, the survivors keep the submitted order, the added \
         nested member is there): {after}"
    );

    // Move the environment to a SECOND active version and re-write the identity under it,
    // so the exported stamp below is 2 and not the only number this fixture ever produces.
    // Without this the version assertion is a constant against a constant: MEASURED,
    // mutating the export's `traits_schema_version` to the literal 1 SURVIVED this test
    // (it was killed only by the pre-existing `tests/export.rs` round trip, which is a
    // different file and a different regression).
    let mut widened = schema_document();
    widened["properties"]["motto"] = json!({"type": "string"});
    let v2 = register_active_schema(&harness, &tenant, &env, &widened, "s2").await;
    assert_eq!(v2, 2);
    let (status, _, restamped) = harness
        .patch(&format!("{}/{user_id}", users_path(&tenant, &env)), &patch)
        .await;
    assert_eq!(status, StatusCode::OK, "re-patch under v2: {restamped}");

    // EXPORT. The line-delimited export record must carry the SAME document and the schema
    // version it validated against, so an exit and a re-import are lossless for traits.
    let export_path = format!("/v1/tenants/{tenant}/environments/{env}/export");
    let (status, _, exported) = harness.get(&export_path).await;
    assert_eq!(status, StatusCode::OK, "export: {exported}");
    let line = exported
        .lines()
        .find(|line| line.contains("ada@example.test"))
        .unwrap_or_else(|| panic!("the exported user is on a line: {exported}"));
    let record = parse(line);
    assert_eq!(
        record["traits"], patched_traits,
        "the export carries the nested/array document verbatim: {line}"
    );
    assert_eq!(
        record["traits_schema_version"],
        json!(v2),
        "the export carries the schema version the traits validated against, which is the \
         SECOND one here, so a constant cannot satisfy it: {line}"
    );
}

#[tokio::test]
async fn the_registry_appends_idempotently_and_refuses_a_malformed_schema() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = schemas_path(&tenant, &env);
    let body = json!({"schema": schema_document()}).to_string();

    let (status, _, first) = harness.post(&path, "v1", &body).await;
    assert_eq!(status, StatusCode::OK, "create: {first}");
    assert_eq!(parse(&first)["version"], json!(1));
    assert_eq!(
        parse(&first)["active"],
        json!(false),
        "a new version is a CANDIDATE, never the active default: {first}"
    );
    // The introspection payload rides the version: the served schema plus its annotations.
    assert_eq!(
        parse(&first)["annotations"]["admin_only"],
        json!(["risk_score"]),
        "the behavior annotations are served with the version: {first}"
    );

    // A RETRY under the same key REPLAYS: the same version, no duplicate appended.
    let (status, _, replay) = harness.post(&path, "v1", &body).await;
    assert_eq!(status, StatusCode::OK, "replay: {replay}");
    assert_eq!(first, replay, "the replay is byte-identical");

    // The same key with a DIFFERENT body is a 422.
    let other = json!({"schema": {"type": "object"}}).to_string();
    let (status, _, conflict) = harness.post(&path, "v1", &other).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{conflict}");

    // A NEW key APPENDS the next version.
    let (status, _, second) = harness.post(&path, "v2", &other).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(parse(&second)["version"], json!(2));

    // A MALFORMED schema is a precise 400 and stores nothing.
    let malformed = json!({"schema": {"type": "widget"}}).to_string();
    let (status, _, rejected) = harness.post(&path, "v3", &malformed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "malformed: {rejected}");
    let (status, _, list) = harness.get(&path).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(
        parse(&list).as_array().expect("array").len(),
        2,
        "the malformed create stored nothing: {list}"
    );

    // No active version yet, so the introspection read is the uniform not-found.
    let (status, _, absent) = harness.get(&format!("{path}/active")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{absent}");

    // `/active` is a STATIC sibling of `/{version}` and resolves to the active read, not to a
    // version lookup, once a version is activated.
    let (status, _, activated) = harness.post(&format!("{path}/1/activate"), "a1", "").await;
    assert_eq!(status, StatusCode::OK, "activate: {activated}");
    let (status, _, active) = harness.get(&format!("{path}/active")).await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(parse(&active)["version"], json!(1));
    assert_eq!(parse(&active)["active"], json!(true));
    // The demoted sibling is honest about no longer being active.
    let (status, _, demoted) = harness.get(&format!("{path}/2")).await;
    assert_eq!(status, StatusCode::OK, "{demoted}");
    assert_eq!(parse(&demoted)["active"], json!(false));
    // A version that does not exist is the uniform not-found.
    let (status, _, missing) = harness.get(&format!("{path}/99")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{missing}");
}

// One test rather than three: the refusal, the count FOLLOWING the population down, and the
// unblocked activation only mean anything against the same seeded identities.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn activation_is_cutover_gated_while_an_identity_fails_the_target_schema() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;
    let path = schemas_path(&tenant, &env);
    register_active_schema(&harness, &tenant, &env, &schema_document(), "s1").await;

    // TWO identities valid under v1, neither with a `motto`. Two rather than one on
    // purpose: the refusal below reports HOW MANY block the cutover, and with a single
    // blocking identity that number is indistinguishable from a hardcoded 1. MEASURED,
    // mutating the store's `invalid_identities` to the constant 1 SURVIVED this test
    // (killed only by the pre-existing `ironauth-store` traits test, a different crate).
    let (status, response) = create_user_with_traits(
        &harness,
        &tenant,
        &env,
        "ada@example.test",
        &nested_traits(),
        "u1",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let (status, second) = create_user_with_traits(
        &harness,
        &tenant,
        &env,
        "grace@example.test",
        &nested_traits(),
        "u1b",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");

    // v2 REQUIRES `motto`, which the existing identity does not have.
    let mut tightened = schema_document();
    tightened["properties"]["motto"] = json!({"type": "string"});
    tightened["required"] = json!(["nickname", "motto"]);
    let (status, _, created) = harness
        .post(&path, "v2", &json!({"schema": tightened}).to_string())
        .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let v2 = parse(&created)["version"].as_i64().expect("version");

    // The cutover is REFUSED, and the message names how many identities block it.
    let (status, _, blocked) = harness
        .post(&format!("{path}/{v2}/activate"), "a2", "")
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "activation must be refused while an identity fails the target schema: {blocked}"
    );
    assert!(
        parse(&blocked)["message"]
            .as_str()
            .expect("message")
            .contains('2'),
        "the refusal names the blocking count, which is 2 here: {blocked}"
    );

    // NOTHING moved: v1 is still the active default and v2 is still a candidate.
    let (status, _, active) = harness.get(&format!("{path}/active")).await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(parse(&active)["version"], json!(1), "{active}");
    let (status, _, candidate) = harness.get(&format!("{path}/{v2}")).await;
    assert_eq!(status, StatusCode::OK, "{candidate}");
    assert_eq!(parse(&candidate)["active"], json!(false), "{candidate}");

    // Resolve the blocking identity, and the SAME activation now succeeds. The gate is a live
    // scan, so it reflects the fix immediately with no job to re-run.
    let users = users_path(&tenant, &env);
    let (status, _, list) = harness.get(&users).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let ids: Vec<String> = parse(&list)["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["id"].as_str().expect("user id").to_owned())
        .collect();
    assert_eq!(ids.len(), 2, "both blocking identities are present: {list}");
    let mut fixed = nested_traits();
    fixed["motto"] = json!("per aspera");
    // Fix ONE, and the cutover is STILL refused, now naming 1. That is the assertion that
    // makes the count a live measurement rather than a fixed string: the same request
    // reports a DIFFERENT number as the population changes under it.
    let (status, _, patched) = harness
        .patch(
            &format!("{users}/{}", ids[0]),
            &json!({"traits": fixed}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "patch: {patched}");
    let (status, _, still_blocked) = harness
        .post(&format!("{path}/{v2}/activate"), "a2b", "")
        .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "one identity still blocks: {still_blocked}"
    );
    assert!(
        parse(&still_blocked)["message"]
            .as_str()
            .expect("message")
            .contains('1'),
        "the count FOLLOWED the population down to 1: {still_blocked}"
    );
    let (status, _, patched) = harness
        .patch(
            &format!("{users}/{}", ids[1]),
            &json!({"traits": fixed}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "patch: {patched}");
    let (status, _, unblocked) = harness
        .post(&format!("{path}/{v2}/activate"), "a3", "")
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "activation after the fix: {unblocked}"
    );
    let (status, _, active) = harness.get(&format!("{path}/active")).await;
    assert_eq!(status, StatusCode::OK, "{active}");
    assert_eq!(parse(&active)["version"], json!(v2), "{active}");
}

#[tokio::test]
async fn traits_cannot_be_written_where_no_schema_is_active_and_reads_are_scope_fenced() {
    let harness = Harness::start(50).await;
    let (tenant, env) = harness.create_tenant("Acme", "k1").await;

    // No active schema: a create carrying traits is a legible 422, never an UNVALIDATED write.
    // A silent accept here would be the worst outcome: the rule would read as enforced while
    // the first environment to skip the registry wrote whatever it liked.
    let (status, response) = create_user_with_traits(
        &harness,
        &tenant,
        &env,
        "ada@example.test",
        &nested_traits(),
        "u1",
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "traits with no active schema must be refused: {response}"
    );
    let (status, _, list) = harness.get(&users_path(&tenant, &env)).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(parse(&list)["items"].as_array().expect("items").len(), 0);

    // A user created WITHOUT traits is fine, and its traits read is an honest empty.
    let body = json!({"identifier": "ada@example.test"}).to_string();
    let (status, _, created) = harness.post(&users_path(&tenant, &env), "u2", &body).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let user_id = parse(&created)["id"].as_str().expect("id").to_owned();
    let (status, _, traits) = harness
        .get(&format!("{}/{user_id}/traits", users_path(&tenant, &env)))
        .await;
    assert_eq!(status, StatusCode::OK, "{traits}");
    assert_eq!(parse(&traits)["traits"], Value::Null, "{traits}");
    assert_eq!(parse(&traits)["schema_version"], Value::Null, "{traits}");

    // Scope fence: another tenant's environment sees NONE of this, on every route, as the
    // uniform not-found rather than an empty success or a loud error.
    let (other_tenant, other_env) = harness.create_tenant("Other", "k2").await;
    let (status, _, foreign) = harness
        .get(&format!(
            "{}/{user_id}/traits",
            users_path(&other_tenant, &other_env)
        ))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a cross-scope traits read is the uniform not-found: {foreign}"
    );
    let (status, _, foreign_list) = harness.get(&schemas_path(&other_tenant, &other_env)).await;
    assert_eq!(status, StatusCode::OK, "{foreign_list}");
    assert_eq!(
        parse(&foreign_list).as_array().expect("array").len(),
        0,
        "another environment's registry is empty, not the first one's: {foreign_list}"
    );
}

/// Drive a migration job to completion the way the worker pool does: handle one batch,
/// complete its message, then claim whatever the worker queued next. Returns how many
/// batches ran, which is what proves the worker queued its own follow-ups.
async fn drain_migration_batches(
    store: &ironauth_store::Store,
    env: &Env,
    scope: Scope,
    first: ironauth_store::OutboxMessage,
) -> usize {
    use ironauth_admin::trait_migration_worker::TraitMigrationConsumer;
    use ironauth_store::TRAIT_MIGRATION_CONSUMER;
    use ironauth_store::outbox::OutboxConsumer;
    use std::time::Duration;

    let consumer = TraitMigrationConsumer::new(store.clone(), 1);
    let mut message = first;
    let mut batches = 0;
    loop {
        consumer
            .handle(env, scope, &message)
            .await
            .expect("the batch advances");
        batches += 1;
        assert!(batches < 20, "the job should finish long before this");
        store
            .scoped(scope)
            .outbox()
            .complete(env, &message)
            .await
            .expect("complete the batch");
        let next = store
            .scoped(scope)
            .outbox()
            .claim(env, TRAIT_MIGRATION_CONSUMER, Duration::from_secs(30), 10)
            .await
            .expect("claim");
        match next.into_iter().next() {
            Some(m) => message = m,
            None => return batches,
        }
    }
}

#[tokio::test]
async fn a_migration_job_runs_to_completion_through_the_worker_it_queues_itself() {
    // The store shipped `create`, `get` and `advance` and NOTHING called them (issue #53).
    // This is the test that makes that layer live, so the property it pins is not that the
    // repository works, which it already did, but that an operator can start a job over
    // HTTP and it FINISHES without anything polling for it.
    //
    // The chain has three links and each one has failed silently in this codebase before:
    // the create must enqueue a batch in its own transaction, the worker must be registered
    // under the name the producer wrote, and the worker must queue the NEXT batch or the
    // job stalls after the first.
    use ironauth_store::{TRAIT_MIGRATION_CONSUMER, WEBHOOK_DELIVERY_CONSUMER};
    use std::time::Duration;

    let harness = Harness::start(50).await;
    let (tenant, env_name) = harness.create_tenant("Acme", "k1").await;
    let scope = scope_of(&tenant, &env_name);
    let env = Env::system();
    let store = harness.store().clone();

    // A schema everything satisfies, then identities on it. THREE, with a batch size of
    // one, so the job cannot finish in a single batch and the self-queuing link is
    // exercised rather than assumed.
    let v1 = register_active_schema(
        &harness,
        &tenant,
        &env_name,
        &json!({"type": "object", "properties": {"nickname": {"type": "string"}}}),
        "s1",
    )
    .await;
    for n in 0..3 {
        let (status, body) = create_user_with_traits(
            &harness,
            &tenant,
            &env_name,
            &format!("u{n}@example.test"),
            &json!({"nickname": format!("n{n}")}),
            &format!("u{n}"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    // START one, over the real management surface.
    let migrations = format!("{}/migrations", schemas_path(&tenant, &env_name));
    let (status, _, created) = harness
        .post(
            &migrations,
            "k-job",
            &json!({ "kind": "dry_run", "from_version": v1, "to_version": v1 }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{created}");
    let job_id = parse(&created)["id"].as_str().expect("id").to_owned();
    assert_eq!(parse(&created)["status"], json!("pending"), "{created}");

    // The create queued its first batch IN ITS OWN TRANSACTION. Without that the job would
    // exist at `pending` forever, since nothing polls for new jobs, which is the dormant
    // shape this whole change exists to remove.
    let claimed = store
        .scoped(scope)
        .outbox()
        .claim(&env, TRAIT_MIGRATION_CONSUMER, Duration::from_secs(30), 10)
        .await
        .expect("claim");
    assert_eq!(
        claimed.len(),
        1,
        "creating a job queues exactly one first batch"
    );
    // And it is on the migration queue alone: a producer writing the wrong discriminator
    // would leave this drained by nothing at all, silently.
    assert!(
        store
            .scoped(scope)
            .outbox()
            .claim(&env, WEBHOOK_DELIVERY_CONSUMER, Duration::from_secs(30), 10)
            .await
            .expect("claim")
            .is_empty(),
        "the batch is not on another consumer's queue"
    );

    // Drive the worker to completion, one batch per message, exactly as the pool would.
    let batches = drain_migration_batches(
        &store,
        &env,
        scope,
        claimed.into_iter().next().expect("first batch"),
    )
    .await;
    assert!(
        batches >= 3,
        "three identities at a batch size of one takes at least three batches, so the \
         worker queued its own follow-ups rather than stopping after the first: {batches}"
    );

    // The job reports itself finished through the real GET.
    let (status, _, body) = harness.get(&format!("{migrations}/{job_id}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let job = parse(&body);
    assert_eq!(job["status"], json!("completed"), "{body}");
    assert_eq!(job["total_count"], json!(3), "{body}");
    assert_eq!(job["processed_count"], json!(3), "{body}");
    assert_eq!(
        job["failure_count"],
        json!(0),
        "every identity satisfies the target schema: {body}"
    );
    assert_eq!(
        job["migrated_count"],
        json!(0),
        "a dry run writes nothing: {body}"
    );
}
