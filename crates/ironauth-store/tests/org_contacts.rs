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

/// Run one statement as `ironauth_control` with this scope's RLS settings bound.
async fn as_control(db: &TestDatabase, scope: Scope, sql: &str) -> Result<u64, sqlx::Error> {
    run_as(db.control_pool(), scope, sql).await
}

/// Run one statement as `ironauth_app` -- the DATA plane role -- with this scope's settings.
async fn as_app(db: &TestDatabase, scope: Scope, sql: &str) -> Result<u64, sqlx::Error> {
    run_as(db.app_pool(), scope, sql).await
}

/// The shared body of [`as_control`] and [`as_app`].
///
/// THE GRANTS AND THE POLICY ARE ENFORCED BY POSTGRES, and a suite that only ever reaches the
/// table through the repository cannot tell a control from its absence: every repository
/// statement carries explicit scope predicates, so it would pass against a table with no policy
/// and every grant wide open.
async fn run_as(pool: &sqlx::PgPool, scope: Scope, sql: &str) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
    let affected = sqlx::query(sql).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    Ok(affected)
}

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

    // EVERY TERM THE DOC ON `plausible_email` NAMES, each case chosen so that DELETING THAT
    // TERM is what turns it red. Nine cases over seven terms: term 3 (exactly one `@`) gets one
    // case per failure shape, and term 5 (a domain with no dot) gets the no-dot and the
    // empty-domain shapes it covers together.
    //
    // A doc listing refusals the test does not drive is a doc nothing holds to the code -- but
    // so is a case some OTHER term refuses first: `a@b@c.example` looks like it drives the
    // multi-@ term and does not, because with that term gone the domain is `b`, which the
    // no-dot term refuses anyway.
    let long_local = format!("{}@acme.example", "a".repeat(320));
    for (email, why) in [
        ("ada @acme.example", "whitespace inside the address"),
        (long_local.as_str(), "longer than the 320-octet ceiling"),
        ("not-an-address", "no @ at all"),
        (
            "ada@acme.example@evil.example",
            "two @: the apparent domain is not the deliverable one",
        ),
        ("@acme.example", "an empty local part"),
        ("ada@", "an empty domain, which the no-dot rule refuses"),
        ("ada@example", "a domain with no dot"),
        ("ada@.example", "a domain whose dot leads"),
        ("ada@example.", "a domain whose dot trails"),
    ] {
        let outcome = add(&db, &env, scope, &org, "Ada", email, "technical").await;
        assert!(
            matches!(outcome, Err(StoreError::Invalid)),
            "the address rule accepted {email:?} ({why}): {outcome:?}"
        );
    }

    // THE CATEGORY, whose `CHECK` exists but which the repository refuses FIRST so a caller's
    // typo is a bad request rather than an opaque database failure.
    let outcome = add(
        &db,
        &env,
        scope,
        &org,
        "Ada",
        "ada@acme.example",
        "marketing",
    )
    .await;
    assert!(
        matches!(outcome, Err(StoreError::Invalid)),
        "an unknown category was accepted: {outcome:?}"
    );

    // AND THE NAME'S CEILING, which moved out of the schema when 0207 sealed the column: a
    // `CHECK` cannot measure what it cannot read, so nothing but this rule holds it.
    let too_long = "n".repeat(257);
    for (name, why) in [
        ("", "an empty name"),
        (too_long.as_str(), "one octet past the ceiling"),
    ] {
        let outcome = add(
            &db,
            &env,
            scope,
            &org,
            name,
            "ada@acme.example",
            "technical",
        )
        .await;
        assert!(
            matches!(outcome, Err(StoreError::Invalid)),
            "the name rule accepted {why}: {outcome:?}"
        );
    }

    // THE BOUNDARY IS WHERE IT SAYS IT IS: exactly at the ceiling is accepted.
    add(
        &db,
        &env,
        scope,
        &org,
        &"n".repeat(256),
        "at-the-ceiling@acme.example",
        "technical",
    )
    .await
    .expect("a name exactly at the ceiling");

    // THE CONTROL: a well-formed pair is accepted, so the refusals above are the constraints and
    // not a table that refuses everything.
    add(&db, &env, scope, &org, "Ada", "ada@acme.example", "billing")
        .await
        .expect("a well-formed contact");
}

#[tokio::test]
async fn neither_the_name_nor_the_address_is_readable_from_the_table() {
    // 0207 CLAIMS "whoever can read this table cannot thereby learn who a customer's staff are".
    // A sealed address next to a PLAINTEXT NAME does not have that property -- the name alone
    // tells a reader who a customer's security lead is -- so the claim is only true while BOTH
    // columns are ciphertext, and this is what says so.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;
    let id = add(
        &db,
        &env,
        scope,
        &org,
        "Grace Okonjo",
        "grace@acme.example",
        "security",
    )
    .await
    .expect("add");

    // READ AS THE TABLE OWNER, which is strictly more than any deployed role can do: if the
    // plaintext is absent from what the owner sees, it is absent from a dump and from every role
    // below. Cast to text so the comparison is over the stored bytes rather than a decoded value.
    let row: (String, String) = sqlx::query_as(
        "SELECT encode(display_name_sealed, 'escape'), encode(email_sealed, 'escape') \
         FROM org_contacts WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("the row is readable as bytes");
    for (column, stored) in [("display_name_sealed", &row.0), ("email_sealed", &row.1)] {
        for secret in ["Grace Okonjo", "Grace", "Okonjo", "grace@acme.example"] {
            assert!(
                !stored.contains(secret),
                "{column} carries {secret:?} in the clear, so reading this table names a \
                 customer's staff"
            );
        }
    }

    // AND THE LISTING STILL ANSWERS, so the seal is a seal rather than a column nothing can use.
    let listed = db
        .control_store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&org, 10)
        .await
        .expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].display_name, "Grace Okonjo");
    assert_eq!(listed[0].email, "grace@acme.example");
}

#[tokio::test]
async fn the_name_and_the_address_do_not_open_under_each_others_context() {
    // THE TWO SEALS SHARE ONE DEK, so what keeps them from being interchangeable is the AAD
    // LABEL and nothing else. Both docs claim that separation; this is the only thing that
    // measures it. Give the labels the same value and this test is the one that goes red --
    // without it, a shared label is invisible, because every row seals and opens on the same
    // side of the swap.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;
    let id = add(
        &db,
        &env,
        scope,
        &org,
        "Grace Okonjo",
        "grace@acme.example",
        "security",
    )
    .await
    .expect("add");

    // SWAP THE TWO CIPHERTEXTS. Both were sealed by the same key under the same scope and DEK
    // version, so every input to the open agrees EXCEPT the label.
    sqlx::query(
        "UPDATE org_contacts \
         SET display_name_sealed = email_sealed, email_sealed = display_name_sealed \
         WHERE id = $1",
    )
    .bind(id.to_string())
    .execute(db.owner_pool())
    .await
    .expect("the swap is writable as the owner");

    let outcome = db
        .control_store()
        .scoped(scope)
        .org_contacts()
        .list_for_organization(&org, 10)
        .await;
    assert!(
        matches!(outcome, Err(StoreError::Encryption)),
        "a name ciphertext opened as an address, so the delivery path would send to a person's \
         name: {outcome:?}"
    );
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

    // AND A REPEAT ADDS NOTHING. This is the property the pre-probe exists for and the only
    // thing that measures it: `write_audited` commits its audit row on ANY `Ok` the closure
    // returns, so a repeat answered as `Ok(false)` from INSIDE the audited write would land a
    // second `org_contact.remove` for a removal that did not happen -- the trail would say the
    // contact was taken off the list twice, and an operator reading it could not tell which
    // entry was the real one. The answer therefore has to be decided before the write opens.
    let repeated = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_contacts()
        .remove(&env, &org, &id, now_micros(&env))
        .await
        .expect("a repeat is not an error");
    assert!(!repeated, "a repeat reported that it removed something");

    let after: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE target_id = $1 ORDER BY occurred_at",
    )
    .bind(id.to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the audit log");
    assert_eq!(
        after, actions,
        "the repeat wrote an audit row for a removal that never happened"
    );
}

#[tokio::test]
async fn the_grants_and_the_one_way_policy_are_enforced() {
    // THE ROLE CLAIMS 0207 MAKES, driven as the ROLES rather than read from the migration's
    // prose -- a grant nothing drives is a grant somebody widens without noticing, and a
    // migration is checksum-frozen once shipped, so a policy that ships wrong cannot be
    // corrected in place.
    //
    // WHAT IT DRIVES AND WHAT IT DOES NOT. This issues statements and reads the ERRORS; it does
    // not read `information_schema`, so it cannot enumerate the grant set and cannot notice a
    // column added later that nobody listed here. It probes the five columns the control role
    // must not write -- every column of this table except `updated_at` and `deleted_at`, which
    // are the two the grant names -- plus the policy in both directions and both halves of the
    // data plane. The catalog-wide sweep that no per-table test can do lives in
    // `migration.rs::the_data_plane_holds_no_table_wide_update_on_any_table`.
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = seed_org(&db, &env, scope, "Acme").await;
    let other = seed_org(&db, &env, scope, "Globex").await;
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

    // THE COLUMN SCOPE. Each of these decides what the row IS -- whose list it is on, who it
    // reaches, and which notices it receives -- and the control role may write none of them.
    for (column, value) in [
        ("organization_id", format!("'{other}'")),
        ("email_sealed", "'\\x00'::bytea".to_owned()),
        ("email_bidx", "'\\x00'::bytea".to_owned()),
        ("category", "'billing'".to_owned()),
        ("display_name_sealed", "'\\x00'::bytea".to_owned()),
    ] {
        let outcome = as_control(
            &db,
            scope,
            &format!("UPDATE org_contacts SET {column} = {value} WHERE id = '{id}'"),
        )
        .await;
        let error = outcome.expect_err(&format!("{column} must not be updatable"));
        assert!(
            error.to_string().contains("permission denied"),
            "{column} is refused by something other than the grant: {error}"
        );
    }

    // THE WITH CHECK HALF: an update that TOUCHES a live row without removing it is refused by
    // the policy, not by the grant -- `updated_at` is a column the role may write.
    let outcome = as_control(
        &db,
        scope,
        &format!("UPDATE org_contacts SET updated_at = now() WHERE id = '{id}'"),
    )
    .await;
    let error = outcome.expect_err("a live row may not be touched without being removed");
    assert!(
        error.to_string().contains("row-level security"),
        "refused by the policy's WITH CHECK half, not by something else: {error}"
    );

    // AND REMOVAL IS ONE WAY. The grant cannot express this, because `deleted_at` is exactly the
    // column a removal writes; `USING (deleted_at IS NULL)` hides the removed row, so the
    // un-removal is FILTERED rather than errored and touches nothing.
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .org_contacts()
        .remove(&env, &org, &id, now_micros(&env))
        .await
        .expect("remove");
    let affected = as_control(
        &db,
        scope,
        &format!("UPDATE org_contacts SET deleted_at = NULL WHERE id = '{id}'"),
    )
    .await
    .expect("an un-removal is filtered, not errored");
    assert_eq!(
        affected, 0,
        "a removed contact was resurrected, so the sender starts notifying somebody an operator \
         took off the list"
    );

    // THE DATA PLANE READS AND ONLY READS. Its INSERT is the half no catalog-wide sweep covers:
    // the table-wide UPDATE and the DELETE set are both asserted elsewhere in the migration
    // suite, and an INSERT grant here would let the delivery path invent its own destinations.
    let outcome = as_app(
        &db,
        scope,
        "INSERT INTO org_contacts \
         (id, tenant_id, environment_id, organization_id, display_name_sealed, email_sealed, \
          email_bidx, pii_dek_version, category) \
         VALUES ('oct_x', 'ten_x', 'env_x', 'org_x', '\\x01'::bytea, '\\x00'::bytea, \
                 '\\x00'::bytea, 1, \
                 'technical')",
    )
    .await;
    let error = outcome.expect_err("the data plane must not insert contacts");
    assert!(
        error.to_string().contains("permission denied"),
        "the app role is refused by the grant rather than by something else: {error}"
    );

    // AND ITS READ WORKS, so the INSERT refusal just above is a narrowing of this role rather
    // than a role with no access to the table at all. It speaks only for the data plane: the six
    // refusals before it are the CONTROL role's, and its own read says nothing about those.
    as_app(&db, scope, "SELECT 1 FROM org_contacts")
        .await
        .expect("the data plane must be able to read the list it delivers to");
}
