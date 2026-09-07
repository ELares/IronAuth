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
            .remove(&env, &org, &id, at)
            .await
            .expect("remove"),
        "the first removal must report that it removed something"
    );
    assert!(
        !writes
            .org_contacts()
            .remove(&env, &org, &id, at + 1)
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
async fn a_malformed_address_or_an_unknown_category_is_refused() {
    // THE CLOSED SET AND THE SHALLOW ADDRESS CHECK. They are enforced in the REPOSITORY rather
    // than by a CHECK constraint, and not by preference: the address is sealed, and a constraint
    // cannot see through a seal. A category nothing routes is a promise the product cannot keep,
    // and an address with no domain is one the send path can only fail on.
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
            matches!(outcome, Err(StoreError::Invalid)),
            "the shape rules accepted email={email:?} category={category:?}: {outcome:?}"
        );
    }

    // THE CONTROL: a well-formed pair is accepted, so the refusals above are the constraints and
    // not a table that refuses everything.
    add(&db, &env, scope, &org, "Ada", "ada@acme.example", "billing")
        .await
        .expect("a well-formed contact");
}

#[tokio::test]
async fn one_organizations_caller_cannot_remove_anothers_contact() {
    // THE ORGANIZATION IS A PREDICATE, NOT CONTEXT. Both identifiers are caller-supplied and the
    // two are related only by the row, so a removal keyed on the contact alone would let a
    // handler holding one organization's handle silence any other organization's notifications
    // in the same environment -- and nothing in the statement would notice.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let mine = seed_org(&db, &env, scope, "Acme").await;
    let theirs = seed_org(&db, &env, scope, "Globex").await;
    let target = add(
        &db,
        &env,
        scope,
        &theirs,
        "Grace",
        "grace@globex.example",
        "security",
    )
    .await
    .expect("add theirs");

    let at = now_micros(&env);
    let outcome = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_contacts()
        .remove(&env, &mine, &target, at)
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a caller removed a contact belonging to another organization: {outcome:?}"
    );

    // AND THE CONTACT IS STILL BEING NOTIFIED, which is the consequence that matters: the
    // refusal above would be worthless if the row had been removed anyway.
    let still = db
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&theirs, 50)
        .await
        .expect("list");
    assert_eq!(
        still.len(),
        1,
        "the foreign removal took effect despite refusing"
    );
}

#[tokio::test]
async fn removal_tells_a_first_removal_a_repeat_and_a_stranger_apart() {
    // THREE ANSWERS, because a caller acts differently on each: it removed something, it was
    // already gone, or the handle names nothing here at all. An earlier version collapsed the
    // last two into `Ok(false)`, so a handler could not tell a repeat from a typo.
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
            .remove(&env, &org, &id, at)
            .await
            .expect("first")
    );
    assert!(
        !writes
            .org_contacts()
            .remove(&env, &org, &id, at + 1)
            .await
            .expect("repeat"),
        "a repeated removal reported a second removal"
    );

    let stranger = OrgContactId::generate(&env, &scope);
    let outcome = writes
        .org_contacts()
        .remove(&env, &org, &stranger, at + 2)
        .await;
    assert!(
        matches!(outcome, Err(StoreError::NotFound)),
        "a handle that names no contact reported a repeat rather than a miss: {outcome:?}"
    );
}

#[tokio::test]
async fn the_duplicate_rule_folds_case_and_is_per_organization() {
    // TWO DIMENSIONS OF THE INDEX, each unmeasured by the plain duplicate test.
    //
    // CASE: `Ada@acme.example` and `ada@acme.example` reach the same person, and listing both
    // sends them one outage notice twice. Both probes in the plain test used byte-identical
    // strings, so dropping the folding changed nothing.
    //
    // ORGANIZATION: two customers may employ the same consultant. Refusing the second would let
    // one organization's contact list decide another's.
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
    .expect("the first");
    let folded = add(
        &db,
        &env,
        scope,
        &mine,
        "Ada",
        "Ada@ACME.example",
        "technical",
    )
    .await;
    assert!(
        matches!(folded, Err(StoreError::Conflict)),
        "the same address in another case was accepted, so one person receives every notice \
         twice: {folded:?}"
    );

    add(
        &db,
        &env,
        scope,
        &theirs,
        "Ada",
        "ada@acme.example",
        "technical",
    )
    .await
    .expect("the same consultant for another customer");
    let listed = db
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&theirs, 50)
        .await
        .expect("list");
    assert_eq!(
        listed.len(),
        1,
        "one organization's contact list refused an address because another organization uses it"
    );
}

#[tokio::test]
async fn the_stored_address_is_sealed_and_the_listing_opens_it() {
    // THE PII GUARANTEE, asked of the bytes on disk rather than of the migration's prose. A
    // database dump must not carry a customer's staff addresses, and the listing must still
    // return one a sender can deliver to -- both halves, because either alone is satisfiable by
    // a mistake (a sealed column nothing can open, or a readable one).
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
    .expect("add");

    let sealed: Vec<u8> = sqlx::query_scalar("SELECT email_sealed FROM org_contacts")
        .fetch_one(db.owner_pool())
        .await
        .expect("read the sealed column");
    assert!(
        !String::from_utf8_lossy(&sealed).contains("ada@acme.example"),
        "the address is readable in the stored bytes, so a database dump carries every \
         customer's staff in the clear"
    );

    let listed = db
        .store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&org, 50)
        .await
        .expect("list");
    assert_eq!(
        listed[0].email, "ada@acme.example",
        "the listing cannot recover the address, so nothing can be delivered"
    );
}

#[tokio::test]
async fn both_writes_are_audited() {
    // THE TRAIL THE SOFT DELETE EXISTS FOR. The migration keeps a removed row so an audit entry
    // has a referent; a removal that wrote no entry would leave the tombstone pointing at
    // nothing, and an unaudited add is a change to who a vendor notifies with no actor on it.
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
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_contacts()
        .remove(&env, &org, &id, now_micros(&env))
        .await
        .expect("remove");

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE target_id = $1 ORDER BY occurred_at",
    )
    .bind(id.to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the audit log");
    assert_eq!(
        actions,
        vec![
            "org_contact.add".to_owned(),
            "org_contact.remove".to_owned()
        ],
        "the contact writes left no attributable trail"
    );
}
