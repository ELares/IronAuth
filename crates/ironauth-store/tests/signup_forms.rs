// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-environment, per-client signup forms over a real database (`DATABASE_URL`) (issue #87).
//!
//! Proves the load-bearing properties of the signup-form data plane against a live database:
//!
//! - **Control-plane set, data-plane read.** A form is set on the control-plane role that owns
//!   the lifecycle and read back on the data-plane role the flow-creation path uses; the
//!   data-plane role can read (get, list) but never write (the grant split).
//! - **Overwrite idempotent on the client id.** A repeat write to the same client overwrites in
//!   place, so a scope holds exactly one form per client.
//! - **Promotable round-trip.** A config-snapshot export carries the form (its field list as
//!   embedded JSON), and `validate_document` accepts the exported bytes BYTE-IDENTICALLY on a
//!   re-export (the snapshot both-sides binding).
//! - **Delete and cross-scope isolation.** A delete removes the form; a form set in scope A never
//!   appears in scope B's get or export.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ClientId, CorrelationId, NewSignupForm, SignupFormId, export_snapshot, validate_document,
};

/// A validated field list (as the admin signup-forms path stores it after validation): one
/// required email field with a narrowing minLength rule.
const FIELDS: &str = r#"[{"trait_pointer":"/email","required":true,"order":0,"step":"signup","rules":{"minLength":5},"label_message_id":1070}]"#;

#[tokio::test]
async fn signup_form_set_reads_back_on_the_data_plane_and_round_trips_through_a_snapshot() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();
    let app = db.store();

    let client = ClientId::generate(&env, &scope).to_string();

    // SET on the control role (which owns the signup form lifecycle).
    let id = SignupFormId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .signup_forms()
        .set(
            &env,
            &id,
            1_000_000,
            NewSignupForm {
                client_id: &client,
                fields_json: FIELDS,
            },
        )
        .await
        .expect("set signup form");

    // READ back on the DATA-plane role (the flow-creation path's role).
    let record = app
        .scoped(scope)
        .signup_forms()
        .get(&client)
        .await
        .expect("read form")
        .expect("a form exists");
    assert_eq!(record.client_id, client);
    assert!(record.fields_json.contains("/email"), "fields round-trip");

    // The form appears in the config-snapshot export, and the exported bytes validate
    // (the snapshot both-sides binding).
    let snapshot = export_snapshot(&control.scoped(scope))
        .await
        .expect("export snapshot");
    assert_eq!(snapshot.resources.signup_form.len(), 1, "one form exported");
    assert_eq!(snapshot.resources.signup_form[0].client_id, client);
    let bytes = snapshot.to_canonical_bytes().expect("canonical bytes");
    validate_document(&bytes).expect("the exported form must validate");
    // The export is deterministic (byte-identical on a re-export).
    let again = export_snapshot(&control.scoped(scope))
        .await
        .expect("re-export")
        .to_canonical_bytes()
        .expect("canonical bytes");
    assert_eq!(bytes, again, "a re-export is byte-identical");
}

#[tokio::test]
async fn an_overwrite_is_idempotent_on_the_client_and_delete_removes_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let control = db.control_store();

    let client = ClientId::generate(&env, &scope).to_string();

    let id = SignupFormId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .signup_forms()
        .set(
            &env,
            &id,
            1_000_000,
            NewSignupForm {
                client_id: &client,
                fields_json: "[]",
            },
        )
        .await
        .expect("first set");

    // A repeat write to the same client (a fresh id) overwrites in place: still one row.
    let id2 = SignupFormId::generate(&env, &scope);
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .signup_forms()
        .set(
            &env,
            &id2,
            2_000_000,
            NewSignupForm {
                client_id: &client,
                fields_json: FIELDS,
            },
        )
        .await
        .expect("overwrite");

    let all = control
        .scoped(scope)
        .signup_forms()
        .list_all()
        .await
        .expect("list");
    assert_eq!(all.len(), 1, "an overwrite keeps a single row per client");
    assert!(all[0].fields_json.contains("/email"));

    // Delete by the stored id (reused across the overwrite): the form is gone.
    let stored_id = SignupFormId::parse_in_scope(&all[0].id, &scope).expect("parse stored id");
    control
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .signup_forms()
        .delete(&env, &stored_id)
        .await
        .expect("delete");
    assert!(
        control
            .scoped(scope)
            .signup_forms()
            .get(&client)
            .await
            .expect("get after delete")
            .is_none(),
        "the form is deleted"
    );
}

#[tokio::test]
async fn a_signup_form_is_scoped_and_never_leaks_across_environments() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope_a = db.seed_scope(&env).await;
    let scope_b = db.seed_scope(&env).await;
    let control = db.control_store();

    let client = ClientId::generate(&env, &scope_a).to_string();
    let id = SignupFormId::generate(&env, &scope_a);
    control
        .scoped(scope_a)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .signup_forms()
        .set(
            &env,
            &id,
            1_000_000,
            NewSignupForm {
                client_id: &client,
                fields_json: FIELDS,
            },
        )
        .await
        .expect("set form in scope A");

    // Scope B sees no form and an empty export.
    assert!(
        control
            .scoped(scope_b)
            .signup_forms()
            .get(&client)
            .await
            .expect("get in B")
            .is_none(),
        "scope B has no form"
    );
    let snapshot_b = export_snapshot(&control.scoped(scope_b))
        .await
        .expect("export B");
    assert!(
        snapshot_b.resources.signup_form.is_empty(),
        "scope B export carries no form"
    );
}
