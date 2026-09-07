// SPDX-License-Identifier: MIT OR Apache-2.0

//! An organization's operational contacts (issue #141).
//!
//! # What these pin
//!
//! The contact list is a routing destination, so the properties that matter are the boundary (one
//! organization's contacts are not another's), the duplicate rule (one address per category, or
//! the same person is notified twice about the same outage), and the removal semantics (the row
//! survives, because "who was told about the certificate that then expired" is answerable only
//! while it does).
#![cfg(feature = "testing")]

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewOrgContact, OrgContactId, OrganizationId, Scope, StoreError,
};

/// The scope's clock in epoch microseconds.
fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("a clock after the epoch")
            .as_micros(),
    )
    .expect("a microsecond count inside i64")
}

/// One organization, created through the control plane as the product does.
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

/// Add one contact and return its handle.
async fn add(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
    display_name: &str,
    email: &str,
    category: &str,
) -> Result<OrgContactId, StoreError> {
    let id = OrgContactId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .org_contacts()
        .add(
            env,
            NewOrgContact {
                id: &id,
                organization_id: organization,
                display_name,
                email,
                category,
            },
        )
        .await?;
    Ok(id)
}

#[tokio::test]
async fn a_contact_is_listed_for_its_own_organization_and_no_other() {
    // THE BOUNDARY. A contact receives notifications about one organization's outages, and the
    // list is what a sender reads to decide where they go -- so a listing that leaked across
    // organizations would deliver one customer's operational detail to another's staff.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = seed_org(&db, &env, scope, "Acme").await;
    let theirs = seed_org(&db, &env, scope, "Globex").await;

    add(
        &db,
        &env,
        scope,
        &mine,
        "Ada",
        "ada@acme.example",
        "technical",
    )
    .await
    .expect("add mine");
    add(
        &db,
        &env,
        scope,
        &theirs,
        "Grace",
        "grace@globex.example",
        "technical",
    )
    .await
    .expect("add theirs");

    let listed = db
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&mine, 50)
        .await
        .expect("list");
    let addresses: Vec<&str> = listed.iter().map(|c| c.email.as_str()).collect();
    assert_eq!(
        addresses,
        vec!["ada@acme.example"],
        "one organization's contact list carried another's staff"
    );
}

#[tokio::test]
async fn the_same_address_cannot_be_listed_twice_on_one_category() {
    // TWO ROWS FOR ONE PERSON IS TWO NOTIFICATIONS about one outage, and an operator reading the
    // list cannot tell which to remove. The index refuses it; this is what turns that into a
    // conflict a handler can report rather than a raw database error.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;

    add(
        &db,
        &env,
        scope,
        &org,
        "Ada",
        "ada@acme.example",
        "technical",
    )
    .await
    .expect("the first add");
    let again = add(
        &db,
        &env,
        scope,
        &org,
        "Ada again",
        "ada@acme.example",
        "technical",
    )
    .await;
    assert!(
        matches!(again, Err(StoreError::Conflict)),
        "a duplicate address on one category was accepted: {again:?}"
    );

    // ANOTHER CATEGORY IS A DIFFERENT SUBSCRIPTION, not a duplicate: the same person may want
    // security notices as well as technical ones, and refusing that would force an organization
    // to invent a second address for one human being.
    add(
        &db,
        &env,
        scope,
        &org,
        "Ada",
        "ada@acme.example",
        "security",
    )
    .await
    .expect("the same person on another category");
    let listed = db
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&org, 50)
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        2,
        "the second category was refused as a duplicate"
    );
}

#[tokio::test]
async fn removing_a_contact_stops_notifying_them_and_keeps_the_row() {
    // THE ROW SURVIVES REMOVAL, which is what makes the audit trail answerable: "who was told
    // about the certificate that then expired" needs the contact that was told, not a gap.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;
    let id = add(
        &db,
        &env,
        scope,
        &org,
        "Ada",
        "ada@acme.example",
        "technical",
    )
    .await
    .expect("add");

    let at = now_micros(&env);
    let writes = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env));
    assert!(
        writes
            .org_contacts()
            .remove(&env, &id, at)
            .await
            .expect("remove"),
        "the first removal must report that it removed something"
    );
    assert!(
        !writes
            .org_contacts()
            .remove(&env, &id, at + 1)
            .await
            .expect("remove again"),
        "a repeated removal reported a second removal, so a caller cannot tell one from a retry"
    );

    let listed = db
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&org, 50)
        .await
        .expect("list");
    assert!(
        listed.is_empty(),
        "a removed contact is still on the list a sender reads: {}",
        listed.len()
    );

    // AND THE ROW IS STILL THERE, which the listing cannot show. Read it directly.
    let surviving: i64 = sqlx::query_scalar("SELECT count(*) FROM org_contacts WHERE id = $1")
        .bind(id.to_string())
        .fetch_one(db.owner_pool())
        .await
        .expect("count");
    assert_eq!(
        surviving, 1,
        "removal deleted the row, taking the audit trail's referent with it"
    );

    // AND THE ADDRESS CAN BE ADDED AGAIN, which is the ordinary case when somebody rejoins a
    // team. A total unique index would refuse it forever.
    add(
        &db,
        &env,
        scope,
        &org,
        "Ada",
        "ada@acme.example",
        "technical",
    )
    .await
    .expect("re-adding a removed address");
}

#[tokio::test]
async fn a_foreign_organization_or_id_is_refused_before_any_write() {
    // THE SCOPE GUARD, asked of both identifiers this call takes. A handler that resolved either
    // from caller input would otherwise write into another tenant's environment.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let other = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;
    let foreign_org = seed_org(&db, &env, other, "Elsewhere").await;

    let outcome = add(
        &db,
        &env,
        scope,
        &foreign_org,
        "Ada",
        "ada@acme.example",
        "technical",
    )
    .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a contact was added to an organization outside the caller's scope: {outcome:?}"
    );

    let foreign_id = OrgContactId::generate(&env, &other);
    let outcome = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_contacts()
        .add(
            &env,
            NewOrgContact {
                id: &foreign_id,
                organization_id: &org,
                display_name: "Ada",
                email: "ada@acme.example",
                category: "technical",
            },
        )
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a contact was written under an identifier from another scope: {outcome:?}"
    );

    // AND THE LISTING REFUSES A FOREIGN ORGANIZATION rather than returning an empty page, which
    // a caller would read as "that organization has no contacts".
    let outcome = db
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&foreign_org, 50)
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a foreign organization's contact list answered instead of refusing: {outcome:?}"
    );
}

#[tokio::test]
async fn the_column_checks_refuse_a_malformed_address_and_an_unknown_category() {
    // THE CLOSED SET AND THE SHALLOW ADDRESS CHECK, asserted at the database rather than trusted
    // from the handler: a category nothing routes is a promise the product cannot keep, and an
    // address with no domain is one the send path can only fail on.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;

    for (email, category) in [
        ("not-an-address", "technical"),
        ("ada@example", "technical"),
        ("ada@acme.example", "marketing"),
    ] {
        let outcome = add(&db, &env, scope, &org, "Ada", email, category).await;
        assert!(
            matches!(outcome, Err(StoreError::Database(_))),
            "the column checks accepted email={email:?} category={category:?}: {outcome:?}"
        );
    }

    // THE CONTROL: a well-formed pair is accepted, so the refusals above are the constraints and
    // not a table that refuses everything.
    add(&db, &env, scope, &org, "Ada", "ada@acme.example", "billing")
        .await
        .expect("a well-formed contact");
}
