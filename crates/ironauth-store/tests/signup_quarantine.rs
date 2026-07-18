// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signup fraud review queue (issue #82, PR 2) against a real Postgres: a risky signup
//! is created ACTIVE-but-quarantined with an open review case, an admin review action
//! (release / reject / extend) is the ONLY thing that moves the case and it names the
//! deciding actor in the audit log, and every read and write is scope-bound (cross-tenant
//! isolation across two seeded scopes).

use ironauth_env::Env;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    ActorRef, CorrelationId, HumanId, Scope, SignupQuarantineReason, SignupQuarantineState,
    StoreError, UserId, UserState,
};

/// The admin actor a review action is attributed to (a human operator), distinct from the
/// data-plane actor that opened the case at signup.
fn admin_actor(env: &Env) -> ActorRef {
    ActorRef::human(HumanId::generate(env))
}

/// Register a risky signup as ACTIVE-but-quarantined, returning its subject.
async fn quarantine_signup(db: &TestDatabase, env: &Env, scope: Scope, identifier: &str) -> UserId {
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_quarantined(
            env,
            identifier,
            "$argon2id$dummy",
            SignupQuarantineReason::RiskOutput,
        )
        .await
        .expect("register a quarantined signup")
}

/// The user's lifecycle state and quarantine flag, read straight from the row.
async fn user_row(db: &TestDatabase, scope: Scope, subject: &UserId) -> (String, bool) {
    sqlx::query_as::<_, (String, bool)>(
        "SELECT state, quarantined FROM users WHERE id = $1 AND tenant_id = $2 \
         AND environment_id = $3",
    )
    .bind(subject.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the user row")
}

/// How many audit rows for `action` name `actor_id`.
async fn audited_by(db: &TestDatabase, scope: Scope, action: &str, actor_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE tenant_id = $1 AND environment_id = $2 \
         AND action = $3 AND actor_id = $4",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(action)
    .bind(actor_id)
    .fetch_one(db.owner_pool())
    .await
    .expect("count audit rows")
}

#[tokio::test]
async fn a_quarantined_signup_opens_a_case_that_only_an_admin_release_clears() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // A risky signup lands ACTIVE (so it can authenticate) but quarantined, with one open
    // review case.
    let subject = quarantine_signup(&db, &env, scope, "risky@example.test").await;
    let (state, quarantined) = user_row(&db, scope, &subject).await;
    assert_eq!(state, "active", "a quarantined signup stays Active");
    assert!(quarantined, "the account is created quarantined");
    assert!(
        db.store()
            .scoped(scope)
            .users()
            .is_quarantined(&subject)
            .await
            .expect("read quarantine flag"),
        "is_quarantined reports the flag"
    );

    // The open case is on the review queue, bound to this subject.
    let open = db
        .store()
        .scoped(scope)
        .signup_quarantines()
        .list_open(100, None)
        .await
        .expect("list open cases");
    assert_eq!(open.len(), 1, "one open case");
    assert_eq!(open[0].subject, subject, "the case is bound to the subject");
    assert_eq!(open[0].reason, SignupQuarantineReason::RiskOutput);
    assert_eq!(open[0].state, SignupQuarantineState::Pending);

    // An admin RELEASE clears the quarantine and closes the case, naming the admin actor.
    let admin = admin_actor(&env);
    let admin_id = admin.id_string();
    db.control_store()
        .scoped(scope)
        .acting(admin, CorrelationId::generate(&env))
        .signup_quarantines()
        .approve(&env, &subject, None)
        .await
        .expect("release the account");
    let (_, quarantined) = user_row(&db, scope, &subject).await;
    assert!(!quarantined, "release cleared the quarantine flag");
    assert_eq!(
        audited_by(&db, scope, "signup_quarantine.approved", &admin_id).await,
        1,
        "the release audits the deciding admin actor"
    );
    // The case is closed: no longer open, and a second release is a uniform not-found.
    assert!(
        db.store()
            .scoped(scope)
            .signup_quarantines()
            .list_open(100, None)
            .await
            .expect("list open")
            .is_empty(),
        "the released case is off the open queue"
    );
    assert!(matches!(
        db.control_store()
            .scoped(scope)
            .acting(admin_actor(&env), CorrelationId::generate(&env))
            .signup_quarantines()
            .approve(&env, &subject, None)
            .await,
        Err(StoreError::NotFound)
    ));
}

#[tokio::test]
async fn reject_disables_the_account_and_extend_bumps_the_window() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    // REJECT disables the account (it can no longer authenticate) and closes the case.
    let rejected = quarantine_signup(&db, &env, scope, "fraud@example.test").await;
    let admin = admin_actor(&env);
    let admin_id = admin.id_string();
    db.control_store()
        .scoped(scope)
        .acting(admin, CorrelationId::generate(&env))
        .signup_quarantines()
        .reject(&env, &rejected, None)
        .await
        .expect("reject the signup");
    let (state, _) = user_row(&db, scope, &rejected).await;
    assert_eq!(state, "disabled", "reject disables the account");
    assert!(
        !UserState::from_wire(&state)
            .expect("known state")
            .can_authenticate(),
        "a disabled account cannot authenticate"
    );
    assert_eq!(
        audited_by(&db, scope, "signup_quarantine.rejected", &admin_id).await,
        1,
        "the reject audits the deciding admin actor"
    );

    // EXTEND bumps the window and keeps the case OPEN (the account stays quarantined).
    let extended = quarantine_signup(&db, &env, scope, "maybe@example.test").await;
    let reviewer = admin_actor(&env);
    let reviewer_id = reviewer.id_string();
    let horizon = 2_000_000_000_i64 * 1_000_000;
    db.control_store()
        .scoped(scope)
        .acting(reviewer, CorrelationId::generate(&env))
        .signup_quarantines()
        .extend(&env, &extended, horizon, None)
        .await
        .expect("extend the window");
    assert_eq!(
        audited_by(&db, scope, "signup_quarantine.extended", &reviewer_id).await,
        1,
        "the extend audits the deciding admin actor"
    );
    let (_, quarantined) = user_row(&db, scope, &extended).await;
    assert!(quarantined, "extend keeps the account quarantined");
    let open = db
        .store()
        .scoped(scope)
        .signup_quarantines()
        .list_open(100, None)
        .await
        .expect("list open");
    let case = open
        .iter()
        .find(|c| c.subject == extended)
        .expect("the extended case stays open");
    assert_eq!(case.state, SignupQuarantineState::Extended);
    assert_eq!(
        case.quarantined_until_unix_micros,
        Some(horizon),
        "the window horizon was bumped"
    );
}

#[tokio::test]
async fn a_case_is_invisible_and_unreachable_from_another_tenant() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let victim = db.seed_scope(&env).await;
    let attacker = db.seed_scope(&env).await;

    // Open a case in the victim scope.
    let subject = quarantine_signup(&db, &env, victim, "victim@example.test").await;

    // The attacker scope sees NO open cases (RLS + scope-bound read).
    assert!(
        db.store()
            .scoped(attacker)
            .signup_quarantines()
            .list_open(100, None)
            .await
            .expect("attacker list")
            .is_empty(),
        "the victim's case is invisible from the attacker tenant"
    );

    // The victim subject id does not parse under the attacker scope (a scope-embedded id),
    // so an attacker-scoped release is a uniform not-found and never touches the victim row.
    assert!(
        UserId::parse_in_scope(&subject.to_string(), &attacker).is_err(),
        "the victim subject id does not parse under the attacker scope"
    );
    // Even a subject that DID parse in the attacker scope finds no open case there.
    let attacker_subject = UserId::generate(&env, &attacker);
    assert!(matches!(
        db.control_store()
            .scoped(attacker)
            .acting(admin_actor(&env), CorrelationId::generate(&env))
            .signup_quarantines()
            .approve(&env, &attacker_subject, None)
            .await,
        Err(StoreError::NotFound)
    ));
}
