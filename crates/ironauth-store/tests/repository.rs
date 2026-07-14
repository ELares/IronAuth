// SPDX-License-Identifier: MIT OR Apache-2.0

//! Repository round-trip and non-recycling, against a real database.

use std::collections::HashSet;

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, StoreError};

#[tokio::test]
async fn create_get_list_delete_round_trip() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Reads need no actor; writes go through an acting context.
    let reader = db.store().scoped(scope).clients();
    let actor = db.test_actor(&env);
    let writer = db
        .store()
        .scoped(scope)
        .acting(actor, CorrelationId::generate(&env))
        .clients();

    // Create returns a typed identifier that round-trips through the scoped
    // parser (the request-layer boundary).
    let id = writer.create(&env, "acme web").await.expect("create");
    let parsed = reader.parse_id(&id.to_string()).expect("parse in scope");
    assert_eq!(parsed, id);
    assert_eq!(id.scope(), scope, "the identifier embeds its scope");

    // Get.
    let record = reader.get(&id).await.expect("get");
    assert_eq!(record.id, id);
    assert_eq!(record.display_name, "acme web");

    // List.
    let all = reader.list().await.expect("list");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, id);

    // Delete, then the row is gone and the outcome is the uniform not-found.
    writer.delete(&env, &id).await.expect("delete");
    assert!(matches!(reader.get(&id).await, Err(StoreError::NotFound)));
    assert!(matches!(
        writer.delete(&env, &id).await,
        Err(StoreError::NotFound)
    ));
    assert!(reader.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn identifiers_are_never_recycled_after_deletion() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let writer = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .clients();

    // Create then delete many; remember every identifier ever issued.
    let mut ever_issued = HashSet::new();
    for _ in 0..200 {
        let id = writer.create(&env, "ephemeral").await.expect("create");
        writer.delete(&env, &id).await.expect("delete");
        assert!(
            ever_issued.insert(id.to_string()),
            "an identifier was issued twice"
        );
    }

    // A fresh batch never collides with any deleted identifier: no serial
    // reuse, no recycled-identifier leakage.
    for _ in 0..200 {
        let id = writer.create(&env, "fresh").await.expect("create");
        assert!(
            !ever_issued.contains(&id.to_string()),
            "a deleted identifier was recycled"
        );
    }
}

/// A management list at the hard cap keeps its has-next sentinel: with
/// `HARD_CAP + 1` rows present, a fetch of `HARD_CAP + 1` (the page size at the
/// cap, plus one for the sentinel) returns all `HARD_CAP + 1`. Before the store
/// clamped the fetch to `HARD_CAP + 1` (rather than `HARD_CAP`), the sentinel was
/// dropped and the final page hidden.
#[tokio::test]
async fn management_list_at_the_hard_cap_keeps_the_has_next_sentinel() {
    use ironauth_store::{MANAGEMENT_LIST_HARD_CAP, ManagementKeyId};

    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // Insert HARD_CAP + 1 credentials as the owner (a superuser, so it bypasses
    // row-level security), in one bulk statement via UNNEST.
    let n = usize::try_from(MANAGEMENT_LIST_HARD_CAP).expect("cap fits usize") + 1;
    let ids: Vec<String> = (0..n)
        .map(|_| ManagementKeyId::generate(&env, &scope).to_string())
        .collect();
    let tenants = vec![scope.tenant().to_string(); n];
    let environments = vec![scope.environment().to_string(); n];
    let hashes: Vec<String> = (0..n).map(|i| format!("hash-{i}")).collect();
    let names: Vec<String> = (0..n).map(|i| format!("key-{i}")).collect();
    sqlx::query(
        "INSERT INTO management_credentials \
         (id, tenant_id, environment_id, key_hash, display_name) \
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[])",
    )
    .bind(ids)
    .bind(tenants)
    .bind(environments)
    .bind(hashes)
    .bind(names)
    .execute(db.owner_pool())
    .await
    .expect("bulk insert credentials");

    // The admin layer fetches page_size + 1; at a page size of HARD_CAP that is
    // HARD_CAP + 1. The store must return all of them (the extra row is the
    // sentinel that tells the admin layer a further page exists).
    let rows = db
        .control_store()
        .management()
        .credentials(scope)
        .list(MANAGEMENT_LIST_HARD_CAP + 1, None)
        .await
        .expect("list at the hard cap");
    assert_eq!(
        rows.len(),
        n,
        "the has-next sentinel survives at a page size equal to the hard cap"
    );
}

/// Scope-aware consent (issue #196): `granted_ref` returns the granted scope, and a
/// re-consent to a BROADER scope UPSERTs the scope in place, keeping the row's
/// ORIGINAL id rather than inserting a second row or dropping the broadened scope.
#[tokio::test]
async fn consent_grant_upserts_the_scope_and_keeps_the_original_id() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // The consents table keys on (subject, client_id) text with no FK to users or
    // clients, so literal ids exercise the grant/read contract directly.
    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // A first consent for a NARROW scope records the granted scope and returns its id.
    let first = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("first grant");
    let recorded = db
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(recorded.id, first.to_string(), "granted_ref returns the id");
    assert_eq!(
        recorded.granted_scope.as_deref(),
        Some("openid"),
        "granted_ref returns the granted scope"
    );

    // Re-consent to a BROADER scope UPDATEs granted_scope in place and returns the
    // ORIGINAL row id (the upsert keeps it), not a fresh id or a second row.
    let second = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile email"))
        .await
        .expect("re-grant");
    assert_eq!(
        second, first,
        "the upsert returns the original consent id on re-consent"
    );
    let updated = db
        .store()
        .scoped(scope)
        .consents()
        .granted_ref(subject, client_id)
        .await
        .expect("granted_ref read")
        .expect("a consent is recorded");
    assert_eq!(
        updated.id,
        first.to_string(),
        "the row keeps its original id"
    );
    assert_eq!(
        updated.granted_scope.as_deref(),
        Some("openid profile email"),
        "the broadened scope is persisted rather than dropped"
    );
}

/// Re-consent audit attribution (issue #196): the `consent.grant` audit row's
/// `target_id` joins to the ACTUAL `consents` row on BOTH a first insert and a
/// scope-broadening re-consent. The upsert's UPDATE branch keeps the row's ORIGINAL
/// id, so a freshly generated (never-persisted) audit target would be a phantom an
/// investigator could not pivot from; this proves the audit target is the real id.
#[tokio::test]
async fn consent_grant_audit_target_joins_the_persisted_consent_row() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let subject = "usr_example-subject";
    let client_id = "cli_example-client";

    // A first consent (narrow), then a scope-BROADENING re-consent (the
    // security-relevant event): the second takes the upsert's UPDATE branch and keeps
    // the original id, which is exactly where a phantom audit target would show up.
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid"))
        .await
        .expect("first grant");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .consents()
        .grant(&env, subject, client_id, Some("openid profile email"))
        .await
        .expect("re-grant");

    // Exactly two consent.grant audit rows, and EACH one's target_id must join to a
    // real consents row (the broaden's target is NOT a phantom fresh id).
    let audit = db
        .store()
        .scoped(scope)
        .audit()
        .list()
        .await
        .expect("audit");
    let grants: Vec<_> = audit
        .iter()
        .filter(|row| row.action == "consent.grant")
        .collect();
    assert_eq!(
        grants.len(),
        2,
        "each grant writes exactly one consent.grant audit row"
    );
    for row in grants {
        assert_eq!(row.target_kind, "con", "the audit target is a consent id");
        let joined: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM consents \
             WHERE id = $1 AND tenant_id = $2 AND environment_id = $3",
        )
        .bind(&row.target_id)
        .bind(scope.tenant().to_string())
        .bind(scope.environment().to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count consents by audit target id");
        assert_eq!(
            joined, 1,
            "the consent.grant audit target_id ({}) joins to exactly one consents row",
            row.target_id
        );
    }

    // And the upsert updated in place: exactly ONE consents row exists, so the
    // broaden's audit target is the same row the first grant's target named.
    let consent_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM consents")
        .fetch_one(db.owner_pool())
        .await
        .expect("count consents");
    assert_eq!(
        consent_rows, 1,
        "the re-consent updated in place rather than inserting a second row"
    );
}
