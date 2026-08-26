// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client declarative claim mappings over a real database (issue #113).
//!
//! Before this file, NOTHING in the tree named `claims_mappings`: its isolation, its policy
//! predicate, its grant split, its export and its import arm were all unmeasured, and seven
//! separate mutations of the export and the import validator survived the whole suite. A table
//! with a promotable classification and no test is a claim about coverage rather than coverage.
//!
//! What is proved here:
//!
//! - **Control-plane write, data-plane read.** A mapping is written on the role that owns the
//!   lifecycle and read back on the role the issuance path uses; the data-plane role can read and
//!   never write, which is the grant split the migration draws.
//! - **The promotable round trip.** A config-snapshot export carries the rules, and
//!   `validate_document` accepts the exported bytes -- the binding between the export and the
//!   import arm, which nothing exercised.
//! - **Cross-scope isolation.** A mapping written in scope A never appears in scope B's read or
//!   its export, which is the RLS policy doing its job rather than a filter in a query.
//! - **The scope foreign key.** A write into a scope that does not exist is a uniform not-found
//!   rather than an orphan row.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{ClientId, CorrelationId, export_snapshot, validate_document};

/// A rule set as the admin path would store it after validation: a rename and a static claim.
const RULES: &str = r#"[{"kind":"rename","from":"dept","to":"department"},{"kind":"static","name":"tier","value":"gold"}]"#;

#[tokio::test]
async fn a_mapping_written_on_the_control_plane_reads_back_on_the_data_plane() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let app = db.store();
    let client = ClientId::generate(&env, &scope);

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &client, RULES)
        .await
        .expect("write the mapping");

    let record = app
        .scoped(scope)
        .claims_mappings()
        .get(&client.to_string())
        .await
        .expect("read the mapping")
        .expect("a mapping exists");
    assert_eq!(record.client_id, client.to_string());
    assert!(
        record.rules_json.contains("department"),
        "the rules round-trip verbatim: {}",
        record.rules_json
    );

    // An overwrite is idempotent on the client: one row per (scope, client).
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(
            &env,
            &client,
            r#"[{"kind":"static","name":"tier","value":"silver"}]"#,
        )
        .await
        .expect("overwrite");
    let all = app
        .scoped(scope)
        .claims_mappings()
        .list_all()
        .await
        .expect("list");
    assert_eq!(all.len(), 1, "an overwrite must not create a second row");
    assert!(all[0].rules_json.contains("silver"));
}

#[tokio::test]
async fn a_mapping_travels_in_a_config_snapshot_and_the_export_validates() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let client = ClientId::generate(&env, &scope);

    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &client, RULES)
        .await
        .expect("write the mapping");

    let snapshot = export_snapshot(&control.scoped(scope))
        .await
        .expect("export");
    assert_eq!(
        snapshot.resources.claims_mapping.len(),
        1,
        "the export must carry the mapping, or the resource type claims a coverage it lacks"
    );
    assert_eq!(
        snapshot.resources.claims_mapping[0].client_id,
        client.to_string()
    );
    assert!(
        snapshot.resources.claims_mapping[0]
            .rules
            .as_array()
            .is_some_and(|rules| rules.len() == 2),
        "the rules travel as parsed JSON, not as opaque text"
    );

    // The binding between the export and the import arm. Nothing exercised this, and seven
    // mutations of the import validator survived because of it.
    let bytes = snapshot.to_canonical_bytes().expect("canonical bytes");
    validate_document(&bytes).expect("the exported mapping must validate on import");

    let again = export_snapshot(&control.scoped(scope))
        .await
        .expect("re-export")
        .to_canonical_bytes()
        .expect("canonical bytes");
    assert_eq!(bytes, again, "a re-export is byte-identical");
}

#[tokio::test]
async fn a_mapping_in_one_scope_is_invisible_in_another() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let one = db.seed_scope(&env).await;
    let two = db.seed_scope(&env).await;
    let control = db.control_store();
    let client = ClientId::generate(&env, &one);

    control
        .scoped(one)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &client, RULES)
        .await
        .expect("write in scope one");

    let other = db
        .store()
        .scoped(two)
        .claims_mappings()
        .get(&client.to_string())
        .await
        .expect("read in scope two");
    assert!(
        other.is_none(),
        "a mapping of another scope must be a uniform not-found"
    );
    assert!(
        db.store()
            .scoped(two)
            .claims_mappings()
            .list_all()
            .await
            .expect("list scope two")
            .is_empty(),
        "another scope's list must not carry it either"
    );
    let snapshot = export_snapshot(&control.scoped(two)).await.expect("export");
    assert!(
        snapshot.resources.claims_mapping.is_empty(),
        "another scope's export must not carry it"
    );
}

#[tokio::test]
async fn a_write_into_a_scope_that_does_not_exist_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let real = db.seed_scope(&env).await;
    let absent = ironauth_store::Scope::new(
        ironauth_store::TenantId::generate(&env),
        ironauth_store::EnvironmentId::generate(&env),
    );
    let client = ClientId::generate(&env, &absent);

    // Without the scope foreign key this INSERT succeeds and parks an orphan row in an
    // environment that does not exist; `is_absent_scope` converts the 23503 the key raises into
    // a uniform not-found, and with no key there is no 23503 to convert.
    let refused = db
        .control_store()
        .scoped(absent)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &client, RULES)
        .await;
    assert!(
        refused.is_err(),
        "a write into an absent scope must be refused, not parked as an orphan"
    );

    // And the real scope is untouched by the attempt.
    assert!(
        db.store()
            .scoped(real)
            .claims_mappings()
            .list_all()
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
async fn the_export_is_ordered_by_client_id_whatever_order_the_writes_arrived_in() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    // Two clients, written in the order that is NOT their sorted order. With one mapping the
    // sort is unobservable: deleting it entirely left the export tests green.
    let mut clients: Vec<String> = (0..2)
        .map(|_| ClientId::generate(&env, &scope).to_string())
        .collect();
    clients.sort();
    let (first, second) = (clients[0].clone(), clients[1].clone());
    for client_id in [&second, &first] {
        let client = ironauth_store::ClientId::parse_in_scope(client_id, &scope).expect("client");
        control
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .claims_mappings()
            .set(&env, &client, RULES)
            .await
            .expect("write");
    }

    let snapshot = export_snapshot(&control.scoped(scope))
        .await
        .expect("export");
    let exported: Vec<String> = snapshot
        .resources
        .claims_mapping
        .iter()
        .map(|mapping| mapping.client_id.clone())
        .collect();
    assert_eq!(
        exported,
        vec![first, second],
        "the export must be ordered by client id, so two environments with the same mappings \
         produce the same bytes regardless of write order"
    );
}

/// A malformed `claims_mapping` document is REFUSED on import.
///
/// The positive round-trip cannot see this: a well-formed document validates whether or not the
/// import arm does anything, and neutering the arm to a no-op left every other test green.
#[test]
fn a_malformed_claims_mapping_document_is_refused_on_import() {
    let document = |resource: &str| {
        format!(
            r#"{{"schema_version":"ironauth.config-snapshot/v1","resources":{{"claims_mapping":[{resource}]}}}}"#
        )
    };
    let cases: &[(&str, &str)] = &[
        (
            r#"{"client_id":"cli_x","rules":{"kind":"static"}}"#,
            "rules that are not an array",
        ),
        (r#"{"client_id":"","rules":[]}"#, "an empty client id"),
        (
            r#"{"client_id":"cli_x","rules":[1,2,3]}"#,
            "rules that are not objects",
        ),
        (r#"{"client_id":"cli_x"}"#, "no rules field at all"),
        (
            r#"{"client_id":"cli_x","rules":[],"surprise":true}"#,
            "a key nobody registered",
        ),
    ];
    for (resource, why) in cases {
        let bytes = document(resource).into_bytes();
        assert!(
            validate_document(&bytes).is_err(),
            "a document with {why} must be refused on import"
        );
    }

    // And one that is well-formed is accepted, so the assertions above are not passing because
    // everything is refused.
    let ok = document(r#"{"client_id":"cli_x","rules":[{"kind":"static","name":"tier"}]}"#);
    validate_document(ok.as_bytes()).expect("a well-formed mapping must be accepted");
}
