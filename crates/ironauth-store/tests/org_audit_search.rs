// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-organization audit search (issue #141 criteria 4 and 5).
//!
//! # What this owes
//!
//! Criterion 4 says org admins "see only their own org's events; cross-org queries return
//! nothing". Criterion 5 says the filters "return correct results over a seeded fixture corpus".
//!
//! Every test here seeds a corpus in which the thing being excluded EXISTS. A filter test whose
//! corpus contains only matching rows passes whether the filter runs or not, and that is the
//! shape most filter tests take.

#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{AuditSearch, CorrelationId, OrganizationId, Scope};

/// Create a client attributed to `organization`, returning the client id the audit row targets.
async fn attributed_client(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: OrganizationId,
    name: &str,
) -> String {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .in_organization(organization)
        .clients()
        .create(env, name)
        .await
        .expect("create a client in an organization")
        .to_string()
}

/// Create a client with no organization: the ordinary path, which stays NULL.
async fn unattributed_client(db: &TestDatabase, env: &Env, scope: Scope, name: &str) -> String {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .clients()
        .create(env, name)
        .await
        .expect("create a client")
        .to_string()
}

async fn search(
    db: &TestDatabase,
    scope: Scope,
    organization: &OrganizationId,
    search: &AuditSearch<'_>,
) -> Vec<String> {
    db.store()
        .scoped(scope)
        .audit()
        .search_for_organization(organization, search, 100)
        .await
        .expect("the search runs")
        .into_iter()
        .map(|record| record.target_id)
        .collect()
}

#[tokio::test]
async fn a_search_returns_this_organizations_events_and_no_others() {
    // CRITERION 4. The corpus holds all three kinds a real deployment has: this organization's
    // events, a NEIGHBOUR's, and the vendor's own unattributed operations. A query that returned
    // the neighbour's is a disclosure; one that returned the unattributed rows shows a customer
    // the vendor's internal activity, which 0138 calls out as the failure the NULL is for.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = OrganizationId::generate(&env, &scope);
    let theirs = OrganizationId::generate(&env, &scope);

    let ours = attributed_client(&db, &env, scope, mine, "ours").await;
    let neighbour = attributed_client(&db, &env, scope, theirs, "neighbour").await;
    let vendor = unattributed_client(&db, &env, scope, "vendor-internal").await;

    let found = search(&db, scope, &mine, &AuditSearch::default()).await;

    assert!(found.contains(&ours), "our own event is missing: {found:?}");
    assert!(
        !found.contains(&neighbour),
        "a neighbour's event was returned: {found:?}"
    );
    assert!(
        !found.contains(&vendor),
        "an unattributed event was returned; NULL must match nobody: {found:?}"
    );
}

#[tokio::test]
async fn an_organization_from_another_scope_selects_nothing() {
    // A handle minted in another environment must not reach across. Answered as empty rather
    // than as an error, matching every other cross-scope read: a different answer would tell the
    // caller the organization exists somewhere.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other_scope = db.seed_scope(&env).await;

    let mine = OrganizationId::generate(&env, &scope);
    attributed_client(&db, &env, scope, mine, "ours").await;
    let elsewhere = OrganizationId::generate(&env, &other_scope);

    let found = search(&db, scope, &elsewhere, &AuditSearch::default()).await;
    assert!(
        found.is_empty(),
        "a cross-scope handle returned rows: {found:?}"
    );
}

#[tokio::test]
async fn each_filter_excludes_something_the_corpus_actually_contains() {
    // CRITERION 5, and the fixture is the point: for every filter there is a row that would be
    // returned without it. A corpus of only-matching rows passes whether the filter runs or not.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = OrganizationId::generate(&env, &scope);

    let first = attributed_client(&db, &env, scope, mine, "first").await;
    let second = attributed_client(&db, &env, scope, mine, "second").await;

    let all = search(&db, scope, &mine, &AuditSearch::default()).await;
    assert!(all.contains(&first) && all.contains(&second), "{all:?}");

    // TARGET: selects one of two rows that are otherwise identical in every filtered column.
    let by_target = search(
        &db,
        scope,
        &mine,
        &AuditSearch {
            target_id: Some(&first),
            ..AuditSearch::default()
        },
    )
    .await;
    assert_eq!(
        by_target,
        vec![first.clone()],
        "target filter: {by_target:?}"
    );

    // ACTION: an action the corpus does NOT hold returns nothing, and the one it does holds both.
    let absent = search(
        &db,
        scope,
        &mine,
        &AuditSearch {
            action: Some("saml_certificate.pinned"),
            ..AuditSearch::default()
        },
    )
    .await;
    assert!(absent.is_empty(), "an unrelated action matched: {absent:?}");

    let present = search(
        &db,
        scope,
        &mine,
        &AuditSearch {
            action: Some("client.create"),
            ..AuditSearch::default()
        },
    )
    .await;
    assert_eq!(present.len(), 2, "the action the corpus holds: {present:?}");

    // ACTOR: a different actor matches nothing, and the corpus's own actor matches both.
    let other_actor = search(
        &db,
        scope,
        &mine,
        &AuditSearch {
            actor_id: Some("svc_nobody"),
            ..AuditSearch::default()
        },
    )
    .await;
    assert!(
        other_actor.is_empty(),
        "a stranger's actor matched: {other_actor:?}"
    );
}

/// When the audit row targeting `target` occurred, read back through the same search.
///
/// Read back rather than stamped by the test, because the store writes `occurred_at` itself:
/// a bound compared against a clock the test took would be testing the test's clock.
async fn stamp_of(
    db: &TestDatabase,
    scope: Scope,
    organization: &OrganizationId,
    target: &str,
) -> i64 {
    db.store()
        .scoped(scope)
        .audit()
        .search_for_organization(
            organization,
            &AuditSearch {
                target_id: Some(target),
                ..AuditSearch::default()
            },
            10,
        )
        .await
        .expect("search")
        .first()
        .expect("the row exists")
        .occurred_at_unix_micros
}

#[tokio::test]
async fn the_time_bounds_are_inclusive_and_each_one_excludes_the_other_end() {
    // A window with only one end tested cannot tell a bound that is ignored from one that is
    // applied to the wrong column, and an exclusive bound that should be inclusive drops exactly
    // the row somebody searched for by copying its timestamp off the page.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = OrganizationId::generate(&env, &scope);

    let older = attributed_client(&db, &env, scope, mine, "older").await;
    // Two rows with distinct instants: the store stamps `occurred_at` per write.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let newer = attributed_client(&db, &env, scope, mine, "newer").await;

    let older_at = stamp_of(&db, scope, &mine, &older).await;
    let newer_at = stamp_of(&db, scope, &mine, &newer).await;
    assert!(newer_at > older_at, "the fixture must span two instants");

    // SINCE excludes the older row, and INCLUDES the newer one at its exact instant.
    let since_newer = search(
        &db,
        scope,
        &mine,
        &AuditSearch {
            since_unix_micros: Some(newer_at),
            ..AuditSearch::default()
        },
    )
    .await;
    assert_eq!(since_newer, vec![newer.clone()], "since: {since_newer:?}");

    // UNTIL excludes the newer row, and INCLUDES the older one at its exact instant.
    let until_older = search(
        &db,
        scope,
        &mine,
        &AuditSearch {
            until_unix_micros: Some(older_at),
            ..AuditSearch::default()
        },
    )
    .await;
    assert_eq!(until_older, vec![older.clone()], "until: {until_older:?}");
}

#[tokio::test]
async fn results_are_newest_first() {
    // A person reading their own history wants the most recent thing first. `AuditRepo::list` is
    // oldest-first because export and replay need the order to BE the content; this is the other
    // reader, and the two must not be confused.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = OrganizationId::generate(&env, &scope);

    let older = attributed_client(&db, &env, scope, mine, "older").await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let newer = attributed_client(&db, &env, scope, mine, "newer").await;

    let found = search(&db, scope, &mine, &AuditSearch::default()).await;
    assert_eq!(found, vec![newer, older], "not newest first: {found:?}");
}

#[tokio::test]
async fn a_row_attributed_to_a_foreign_organization_is_not_returned() {
    // THE CROSS-SCOPE GUARD, and the corpus that can actually see it.
    //
    // `an_organization_from_another_scope_selects_nothing` names this boundary and cannot check
    // it: deleting the guard leaves it green, because tenant_id, environment_id and the RLS
    // policy already exclude rows LIVING in another scope, and an OrganizationId's wire form
    // embeds its own scope so it never textually matches one of ours.
    //
    // What the guard actually catches is the row that lives HERE and is attributed THERE.
    // `ActingContext::in_organization` takes the handle by value and compares nothing -- its doc
    // claimed otherwise until this test was written -- so a caller holding a foreign handle
    // produces exactly that row. Without the guard, searching this scope for that foreign
    // organization returns it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other_scope = db.seed_scope(&env).await;
    let foreign = OrganizationId::generate(&env, &other_scope);

    // A row in THIS scope, attributed to an organization from the other one.
    let misattributed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .in_organization(foreign)
        .clients()
        .create(&env, "misattributed")
        .await
        .expect("create a client")
        .to_string();

    let found = search(&db, scope, &foreign, &AuditSearch::default()).await;
    assert!(
        !found.contains(&misattributed),
        "a row attributed to an organization outside this scope was returned: {found:?}"
    );
    assert!(
        found.is_empty(),
        "and nothing else came back either: {found:?}"
    );
}

#[tokio::test]
async fn the_actor_filter_returns_that_actors_rows_and_not_only_an_empty_set() {
    // THE POSITIVE DIRECTION, which nothing asserted. The suite checked only that a STRANGER's
    // actor matches nothing, so an actor filter that matches nothing AT ALL -- a `||` typo, a
    // comparison against actor_kind, $7 bound where $8 was meant -- shipped green.
    //
    // That is the failure mode worth guarding on an audit surface: an org admin asking "what did
    // this person do" is answered "nothing", which reads as innocent rather than broken.
    //
    // ONE ACTOR FOR BOTH ROWS, built by hand: `db.test_actor` generates a FRESH random principal
    // per call, so the obvious fixture gives two rows two different actors and the assertion
    // this test needs cannot be written against it.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = OrganizationId::generate(&env, &scope);

    let actor = db.test_actor(&env);
    let actor_id = match &actor {
        ironauth_store::ActorRef::Human(id) => id.to_string(),
        other => panic!("the harness actor is a human: {other:?}"),
    };
    let mut theirs = Vec::new();
    for name in ["first", "second"] {
        theirs.push(
            db.store()
                .scoped(scope)
                .acting(actor, CorrelationId::generate(&env))
                .in_organization(mine)
                .clients()
                .create(&env, name)
                .await
                .expect("create a client")
                .to_string(),
        );
    }
    // A DIFFERENT actor in the same organization, so the filter has something to exclude.
    let other = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .in_organization(mine)
        .clients()
        .create(&env, "somebody-else")
        .await
        .expect("create a client")
        .to_string();

    let found = search(
        &db,
        scope,
        &mine,
        &AuditSearch {
            actor_id: Some(&actor_id),
            ..AuditSearch::default()
        },
    )
    .await;

    for target in &theirs {
        assert!(
            found.contains(target),
            "the actor's own rows must come back: {found:?}"
        );
    }
    assert!(
        !found.contains(&other),
        "and another actor's must not: {found:?}"
    );
}
