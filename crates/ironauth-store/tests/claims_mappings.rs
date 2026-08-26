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
use sqlx::Row as _;

/// A rule set as the admin path would store it after validation: a rename and a static claim.
const RULES: &str = r#"[{"kind":"rename","from":"dept","to":"department"},{"kind":"static","name":"tier","value":"gold"}]"#;

#[tokio::test]
async fn a_mapping_written_on_the_control_plane_reads_back_on_the_data_plane() {
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

    let record = control
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
    let all = control
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
        .control_store()
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
        db.control_store()
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

    // What this pins is the CONVERSION: an absent scope answers with the uniform not-found
    // rather than a raw database error, so a caller cannot distinguish "no such environment"
    // from "nothing there".
    //
    // It does NOT pin that the FOREIGN KEY is what refuses it -- measured: removing both keys
    // leaves this test green, because the write is refused earlier for another reason. The key's
    // existence is pinned by `every_scoped_table_declares_a_scope_foreign_key` in
    // tests/absent_scope.rs, which enumerates every RLS-forcing table and fails when one has no
    // scope key. Two tests, two properties; saying so here stops this one being read as proof
    // of the other.
    let refused = db
        .control_store()
        .scoped(absent)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &client, RULES)
        .await;
    assert!(
        matches!(refused, Err(ironauth_store::StoreError::NotFound)),
        "an absent scope must convert to the UNIFORM not-found, which is the whole point of the \
         foreign key: `is_absent_scope` matches SQLSTATE 23503 on a `_tenant_id_fkey` \
         constraint, and with no key there is no 23503 to convert. Got: {refused:?}"
    );

    // And NOTHING was written anywhere. Counted as the cluster OWNER, not through a scoped
    // read: a scoped read of the absent scope is empty whether the row landed or not, so it
    // could not tell an orphan from a refusal.
    let row = sqlx::query("SELECT COUNT(*) AS n FROM claims_mappings")
        .fetch_one(db.owner_pool())
        .await
        .expect("count as owner");
    let total: i64 = row.get("n");
    assert_eq!(
        total, 0,
        "a refused write must leave no orphan row anywhere"
    );
    let _ = real;
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

/// The ROW-LEVEL SECURITY policy is what isolates a mapping, not the query's WHERE clause.
///
/// The cross-scope test above reads through `ClaimsMappingRepo`, whose SQL already filters by
/// scope -- so it passes with the policy replaced by `USING (true)`, and it did. This one
/// subverts the application filter the way `tests/rls.rs` does: a raw `SELECT` with NO scope
/// predicate, on a connection pinned to another scope. Only the policy can refuse it.
#[tokio::test]
async fn the_row_level_policy_refuses_a_raw_read_from_another_scope() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let one = db.seed_scope(&env).await;
    let two = db.seed_scope(&env).await;
    let client = ClientId::generate(&env, &one);

    db.control_store()
        .scoped(one)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &client, RULES)
        .await
        .expect("write in scope one");

    let mut conn = db.control_pool().acquire().await.expect("acquire");
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, false)")
        .bind(two.tenant().to_string())
        .execute(&mut *conn)
        .await
        .expect("pin tenant to scope two");
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, false)")
        .bind(two.environment().to_string())
        .execute(&mut *conn)
        .await
        .expect("pin environment to scope two");

    // No WHERE clause at all: whatever comes back is what the POLICY allowed.
    let rows = sqlx::query("SELECT client_id FROM claims_mappings")
        .fetch_all(&mut *conn)
        .await
        .expect("raw read");
    assert!(
        rows.is_empty(),
        "a raw read pinned to another scope must see nothing; the isolation is the policy, not \
         the repository's WHERE clause"
    );
}

/// The DATA plane cannot write a mapping, and the control plane cannot delete one.
///
/// Both are stated in the migration and neither was attempted by any test: widening the
/// data-plane grant to INSERT and UPDATE -- letting the plane that mints tokens rewrite the
/// shape of the tokens it mints -- left the whole suite green.
#[tokio::test]
async fn the_grant_split_is_what_the_migration_says_it_is() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let mut app = db.app_pool().acquire().await.expect("acquire app");
    let refused = sqlx::query(
        "INSERT INTO claims_mappings (tenant_id, environment_id, client_id, rules) \
         VALUES ($1, $2, 'cli_x', '[]'::jsonb)",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .execute(&mut *app)
    .await;
    let message = refused
        .expect_err("the data plane must not write")
        .to_string();
    assert!(
        message.contains("permission denied"),
        "the data plane must be refused by a GRANT, not by a policy or a filter: {message}"
    );

    // The control plane may write, and may NOT delete.
    let mut control = db.control_pool().acquire().await.expect("acquire control");
    for setting in ["ironauth.tenant_id", "ironauth.environment_id"] {
        let value = if setting.ends_with("tenant_id") {
            scope.tenant().to_string()
        } else {
            scope.environment().to_string()
        };
        sqlx::query("SELECT set_config($1, $2, false)")
            .bind(setting)
            .bind(value)
            .execute(&mut *control)
            .await
            .expect("pin scope");
    }
    let deleted = sqlx::query("DELETE FROM claims_mappings")
        .execute(&mut *control)
        .await;
    let message = deleted
        .expect_err("no DELETE grant exists yet, by design")
        .to_string();
    assert!(
        message.contains("permission denied"),
        "removing a mapping is an operation that has no caller yet, so the privilege must not \
         be held: {message}"
    );
}

/// A write is AUDITED, and the audit names the client whose tokens changed shape.
///
/// Replacing the audited write with a plain transaction and the same INSERT left every test
/// green: the mapping landed and nothing recorded who changed it.
#[tokio::test]
async fn a_write_records_an_audit_row_naming_the_client() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let client = ClientId::generate(&env, &scope);

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &client, RULES)
        .await
        .expect("write");

    let row = sqlx::query(
        "SELECT action, target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'claims_mapping.set'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("an audit row must exist for the write");
    let target: String = row.get("target_id");
    assert_eq!(
        target,
        client.to_string(),
        "the audit target is the CLIENT: this table has no id of its own, and the client is the \
         thing whose tokens changed shape"
    );
}

/// A write for a client of ANOTHER scope is a uniform not-found.
#[tokio::test]
async fn a_write_for_a_client_of_another_scope_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let here = db.seed_scope(&env).await;
    let elsewhere = db.seed_scope(&env).await;
    let foreign = ClientId::generate(&env, &elsewhere);

    let refused = db
        .control_store()
        .scoped(here)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .claims_mappings()
        .set(&env, &foreign, RULES)
        .await;
    assert!(
        matches!(refused, Err(ironauth_store::StoreError::NotFound)),
        "a client id carries its scope, so one from elsewhere must not address this one: \
         {refused:?}"
    );
}
