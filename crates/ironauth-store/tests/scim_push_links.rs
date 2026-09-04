// SPDX-License-Identifier: MIT OR Apache-2.0

//! The outbound identity map: which downstream resource is which IronAuth subject (issue #137).
//!
//! # What this file is about
//!
//! Criterion 3 of issue #137 says that killing the downstream mid-sync and restoring it converges
//! with NO DUPLICATES. Nothing in the client can deliver that on its own. A client that has just
//! `POST`ed a user and lost the response has no way to know, on the next run, whether the
//! resource exists downstream: it can look the subject up by filter, but a downstream serving
//! reads from a
//! replica answers that query with nothing, and the client creates a second resource.
//!
//! What makes the criterion reachable is a durable record, written by the same transaction that
//! learned the downstream id, saying THIS subject is THAT resource. That is this table. The tests
//! below are about the properties the convergence argument actually rests on:
//!
//! * a re-push of a subject already linked UPDATES rather than duplicating,
//! * one downstream resource cannot be claimed by two subjects,
//! * a link cannot outlive the connection it belongs to,
//! * and a failure recorded against a subject does not disturb the downstream id, because the
//!   resource is still there and the next run must find it rather than create another.

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewScimPushConnection, NewScimPushLink, OrganizationId, ScimDeletionPolicy,
    ScimPushConnectionId, ScimPushLinkId, ScimPushResourceType, ScimWriteMode, Scope, StoreError,
};

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

async fn seed_org(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, now_micros(env), name, None)
        .await
        .expect("create organization");
    id
}

async fn seed_connection(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    label: &str,
) -> ScimPushConnectionId {
    let id = ScimPushConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_push_connections()
        .create(
            env,
            NewScimPushConnection {
                id: &id,
                organization_id: organization,
                display_name: label,
                base_url: "https://downstream.example.com/scim/v2",
                credential_secret_name: "downstream_token",
                attribute_mapping: &serde_json::json!({}),
                user_scope_filter: None,
                group_scope_filter: None,
                write_mode: ScimWriteMode::Patch,
                deletion_policy: ScimDeletionPolicy::Deactivate,
            },
            None,
            None,
        )
        .await
        .expect("create the push connection");
    id
}

/// Links a subject, returning the id so a caller can tell an UPDATE from an INSERT.
async fn link(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    connection: &ScimPushConnectionId,
    subject: &str,
    downstream: &str,
    external: &str,
) -> Result<ScimPushLinkId, StoreError> {
    let id = ScimPushLinkId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .scim_push_links()
        .upsert(NewScimPushLink {
            id: &id,
            connection_id: connection,
            resource_type: ScimPushResourceType::User,
            subject_id: subject,
            downstream_id: downstream,
            external_id: external,
        })
        .await?;
    Ok(id)
}

// Each insert gets its OWN transaction: a statement Postgres refuses aborts the whole
// transaction (25P02), so a control sharing one with the rogue would fail for that reason
// rather than on its own merits and prove nothing.
async fn raw_insert(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    connection: &ScimPushConnectionId,
    resource_type: &str,
    subject: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = db.app_pool().begin().await.expect("begin");
    // The scope has to be on the SESSION or row-level security refuses the insert with 42501
    // before the CHECK is ever consulted, and this test would pass against a table with no
    // CHECK at all. `begin_scoped` sets exactly these two.
    for (name, value) in [
        ("ironauth.tenant_id", scope.tenant().to_string()),
        ("ironauth.environment_id", scope.environment().to_string()),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("set the scope");
    }
    sqlx::query(
        "INSERT INTO scim_push_links \
         (id, tenant_id, environment_id, connection_id, resource_type, subject_id, \
          downstream_id, external_id) \
         VALUES ($1, $2, $3, $4, $5, $6, 'dsid-raw', 'ext-raw')",
    )
    .bind(ScimPushLinkId::generate(env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(connection.to_string())
    .bind(resource_type)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .map(|_| ())
}

#[tokio::test]
async fn a_repush_updates_the_link_rather_than_adding_a_second_one() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;

    let first = link(&db, &env, scope, &connection, "usr_ada", "dsid-1", "ext-1")
        .await
        .expect("first link");

    // THE RE-PUSH. The client looks the subject up before every write, so it reaches here again
    // on every convergence: this is the normal path, not an error. The downstream id changes
    // because the resource was recreated downstream, which is exactly the case a link that
    // refused to move would strand.
    link(&db, &env, scope, &connection, "usr_ada", "dsid-9", "ext-1")
        .await
        .expect("re-push");

    let found = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .find(&connection, ScimPushResourceType::User, "usr_ada")
        .await
        .expect("find")
        .expect("a link");
    assert_eq!(found.downstream_id, "dsid-9");
    // The ROW is the same row: an upsert that inserted a second one would leave the first
    // reachable and the next convergence would pick whichever the index happened to return.
    assert_eq!(found.id, first);
    let all = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .list_for_connection(&connection, 50, None)
        .await
        .expect("list");
    assert_eq!(all.len(), 1, "a second link was inserted: {all:?}");
}

#[tokio::test]
async fn one_downstream_resource_cannot_be_claimed_by_two_subjects() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;

    link(&db, &env, scope, &connection, "usr_ada", "dsid-1", "ext-1")
        .await
        .expect("first link");

    // THE DEFECT THIS EXCLUDES. Two IronAuth subjects pointing at one downstream resource is a
    // silent cross-account write: provisioning either one overwrites the other's attributes
    // downstream, and no error is raised at the time. A convergence that mapped two subjects onto
    // one resource has not converged, it has merged two identities.
    let clash = link(
        &db,
        &env,
        scope,
        &connection,
        "usr_grace",
        "dsid-1",
        "ext-2",
    )
    .await;
    assert!(
        matches!(clash, Err(StoreError::Conflict)),
        "a second subject claimed the same downstream resource: {clash:?}"
    );

    // CONTROL: a different downstream id under the same connection is fine, so the refusal above
    // is the downstream id doing the refusing and not the second subject.
    link(
        &db,
        &env,
        scope,
        &connection,
        "usr_grace",
        "dsid-2",
        "ext-2",
    )
    .await
    .expect("a distinct resource links");

    // AND ACROSS CONNECTIONS the same downstream id is fine: two downstreams number their
    // resources independently, and a uniqueness rule that spanned connections would make the
    // second connection unusable the moment its ids collided with the first's.
    let other = seed_connection(&db, &env, scope, &org, "Workday").await;
    link(&db, &env, scope, &other, "usr_ada", "dsid-1", "ext-1")
        .await
        .expect("the same downstream id under another connection");
}

#[tokio::test]
async fn deleting_the_connection_takes_its_links_with_it() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    link(&db, &env, scope, &connection, "usr_ada", "dsid-1", "ext-1")
        .await
        .expect("link");

    // WHY THIS IS A CASCADE AND NOT A GUARD. 0189's delete is a hard DELETE, so without the
    // cascade this call fails with a foreign key violation and an operator cannot remove a
    // connection that ever pushed anything. The alternative -- leaving the links -- is worse: the
    // rows would name a connection that no longer exists, and a later connection reusing the
    // subject would meet a link pointing into a downstream nobody can reach.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .scim_push_connections()
        .delete(&env, &org, &connection, None)
        .await
        .expect("delete the connection");

    let left = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .list_for_connection(&connection, 50, None)
        .await
        .expect("list");
    assert!(left.is_empty(), "links outlived their connection: {left:?}");
}

#[tokio::test]
async fn a_recorded_failure_keeps_the_downstream_id_and_a_success_clears_the_failure() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;
    link(&db, &env, scope, &connection, "usr_ada", "dsid-1", "ext-1")
        .await
        .expect("link");

    db.store()
        .scoped(scope)
        .scim_push_links()
        .record_failure(
            &connection,
            ScimPushResourceType::User,
            "usr_ada",
            "503 from the downstream",
        )
        .await
        .expect("record the failure");

    let failing = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .find(&connection, ScimPushResourceType::User, "usr_ada")
        .await
        .expect("find")
        .expect("a link");
    // THE POINT. A failed push does not mean the resource is gone. Clearing the downstream id
    // here would make the next run look the subject up, miss, and CREATE A SECOND RESOURCE,
    // which is precisely the duplicate criterion 3 forbids.
    assert_eq!(failing.downstream_id, "dsid-1");
    assert_eq!(
        failing.last_error.as_deref(),
        Some("503 from the downstream")
    );
    assert!(failing.last_error_at_unix_micros.is_some());

    // A SUCCESS CLEARS IT, because recording a success and clearing the failure are the same
    // event. A stale error would make the per-connection health surface answer a question about
    // the past.
    link(&db, &env, scope, &connection, "usr_ada", "dsid-1", "ext-1")
        .await
        .expect("re-push");
    let healthy = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .find(&connection, ScimPushResourceType::User, "usr_ada")
        .await
        .expect("find")
        .expect("a link");
    assert_eq!(healthy.last_error, None);
    assert_eq!(healthy.last_error_at_unix_micros, None);
    assert!(healthy.last_synced_at_unix_micros.is_some());
}

#[tokio::test]
async fn a_failure_for_a_subject_that_was_never_linked_is_not_found() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;

    // A failure BEFORE a subject was ever provisioned has no downstream id to attach to, and a
    // row invented to hold it would carry an empty one, which the column's CHECK refuses. The
    // caller has to record that against the connection instead, and this is what tells it so.
    let outcome = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .record_failure(
            &connection,
            ScimPushResourceType::User,
            "usr_nobody",
            "connection refused",
        )
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a failure invented a link: {outcome:?}"
    );

    // AND THE USER TYPE IS PART OF THE KEY. A link exists for usr_ada as a USER; the same
    // subject id as a GROUP is a different row and must not be found.
    link(&db, &env, scope, &connection, "usr_ada", "dsid-1", "ext-1")
        .await
        .expect("link");
    let as_group = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .find(&connection, ScimPushResourceType::Group, "usr_ada")
        .await
        .expect("find");
    assert!(
        as_group.is_none(),
        "the resource type is not part of the key: {as_group:?}"
    );
}

#[tokio::test]
async fn every_resource_type_round_trips_and_an_unknown_one_does_not() {
    // WHY THIS EXISTS. `resource_type` is a string in Postgres with a CHECK, and an enum in Rust.
    // Two vocabularies that must agree, and nothing makes them agree except this test. Adding a
    // variant to the enum without extending the CHECK gives a 23514 at the first write; extending
    // the CHECK without teaching `from_str` gives a NotFound on every READ of that row, which is
    // worse because it looks like a missing link and the client CREATES A DUPLICATE.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Globex").await;
    let connection = seed_connection(&db, &env, scope, &org, "Okta production").await;

    for (index, resource_type) in ScimPushResourceType::ALL.iter().copied().enumerate() {
        let subject = format!("subject-{index}");
        let id = ScimPushLinkId::generate(&env, &scope);
        db.store()
            .scoped(scope)
            .scim_push_links()
            .upsert(NewScimPushLink {
                id: &id,
                connection_id: &connection,
                resource_type,
                subject_id: &subject,
                downstream_id: &format!("dsid-{index}"),
                external_id: &format!("ext-{index}"),
            })
            .await
            .unwrap_or_else(|error| {
                panic!("{} is not writable: {error:?}", resource_type.as_str())
            });

        let read = db
            .store()
            .scoped(scope)
            .scim_push_links()
            .find(&connection, resource_type, &subject)
            .await
            .unwrap_or_else(|error| panic!("{} is not readable: {error:?}", resource_type.as_str()))
            .unwrap_or_else(|| panic!("{} round trip lost the row", resource_type.as_str()));
        assert_eq!(read.resource_type, resource_type);
    }

    let listed = db
        .store()
        .scoped(scope)
        .scim_push_links()
        .list_for_connection(&connection, 50, None)
        .await
        .expect("list");
    assert_eq!(listed.len(), ScimPushResourceType::ALL.len());

    // THE NEGATIVE ARM, which is what makes the loop above mean something. Counting the rows
    // back does NOT do it: a CHECK that accepted anything would still return two rows here. So
    // this reaches past the repository and asks Postgres directly, which is the only place the
    // vocabulary is actually enforced.
    // CONTROL FIRST: a vocabulary value inserts through this path, so a refusal below is the
    // resource_type doing the refusing and not the raw path being unusable.
    raw_insert(&db, &env, scope, &connection, "user", "usr_control")
        .await
        .expect("a vocabulary value inserts through the same path");

    let code = raw_insert(&db, &env, scope, &connection, "device", "usr_rogue")
        .await
        .expect_err("a resource type outside the vocabulary was accepted")
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .map(std::borrow::Cow::into_owned);
    // 23514 is check_violation. Asserting the CODE and not merely that it failed matters: an
    // insert refused by row-level security or by a missing grant also fails, and would let this
    // pass while the CHECK itself was absent. It did exactly that on the first run of this test.
    assert_eq!(
        code.as_deref(),
        Some("23514"),
        "refused, but not by the resource_type CHECK"
    );
}
