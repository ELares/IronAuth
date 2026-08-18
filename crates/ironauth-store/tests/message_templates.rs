// SPDX-License-Identifier: MIT OR Apache-2.0

//! The stored message template overrides (issue #111 criterion 3), over a real database.
//!
//! The RESOLVER is pure and tested without a database in `message_template.rs`. What could not
//! be tested until now is the half that feeds it: that the store returns every candidate for a
//! (scope, kind), in precedence order, with the level and organization each row claims.
//!
//! The uniqueness rules are the sharp part. `organization_id` is nullable, and NULLs are
//! DISTINCT in a unique index -- so a single index over the nullable column would let a
//! tenant-level override be created twice and neither row would be wrong, they would simply
//! resolve in whichever order the read returned. Migration 0144 uses two partial indexes for
//! exactly that reason, and both halves are measured here.

use ironauth_env::Env;
use ironauth_store::message_template::TemplateLevel;
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, OrganizationId, Scope};

/// Insert a template row directly. There is no authoring surface yet -- that is the admin half
/// of criterion 3 -- so this exercises the STORE contract the resolver depends on.
#[allow(clippy::too_many_arguments)]
async fn insert_template(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    level: &str,
    organization: Option<&OrganizationId>,
    kind: &str,
    locale: &str,
    subject: &str,
    locked: bool,
) -> Result<(), sqlx::Error> {
    let id = ironauth_store::MessageTemplateId::generate(env, &scope).to_string();
    let statement = sqlx::query(
        "INSERT INTO message_templates \
         (id, tenant_id, environment_id, level, organization_id, kind, locale, subject, \
          body_text, locked, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'body', $9, now(), now())",
    )
    .bind(&id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(level)
    .bind(organization.map(ToString::to_string))
    .bind(kind)
    .bind(locale)
    .bind(subject)
    .bind(locked);

    // In a TRANSACTION with the scope settings, because `message_templates` is FORCE RLS with
    // a WITH CHECK: an insert that does not run under the row's own (tenant, environment) is
    // REFUSED, not silently mis-scoped. A pooled `execute` would set the settings on one
    // connection and insert on another, which is the shape that makes this look flaky.
    let mut tx = db.control_pool().begin().await?;
    sqlx::query("SELECT set_config('ironauth.tenant_id', $1, true)")
        .bind(scope.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('ironauth.environment_id', $1, true)")
        .bind(scope.environment().to_string())
        .execute(&mut *tx)
        .await?;
    statement.execute(&mut *tx).await?;
    tx.commit().await
}

async fn create_org(db: &TestDatabase, env: &Env, scope: Scope) -> OrganizationId {
    let id = OrganizationId::generate(env, &scope);
    db.control_store()
        .management()
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .organizations(scope)
        .create(env, &id, 1_000_000, "templates org", None)
        .await
        .expect("create organization");
    id
}

/// The store returns every candidate for one kind, strongest level FIRST.
///
/// The order is `TemplateLevel::PRECEDENCE`, applied in SQL rather than left to the caller: a
/// caller that re-derived it would be a second copy of the precedence rule, which is the exact
/// duplication issue #619 exists to prevent for the policy engine.
#[tokio::test]
async fn candidates_come_back_in_precedence_order() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;

    // Inserted in the WRONG order deliberately, so passing cannot be an artifact of insertion.
    insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "invitation",
        "en",
        "tenant subject",
        false,
    )
    .await
    .expect("tenant override");
    insert_template(
        &db,
        &env,
        scope,
        "organization",
        Some(&org),
        "invitation",
        "en",
        "org subject",
        false,
    )
    .await
    .expect("organization override");
    insert_template(
        &db,
        &env,
        scope,
        "environment",
        None,
        "invitation",
        "en",
        "env subject",
        false,
    )
    .await
    .expect("environment override");

    let candidates = db
        .store()
        .scoped(scope)
        .message_templates()
        .candidates_for("invitation")
        .await
        .expect("read candidates");

    let levels: Vec<TemplateLevel> = candidates.iter().map(|c| c.level).collect();
    assert_eq!(
        levels,
        vec![
            TemplateLevel::Organization,
            TemplateLevel::Environment,
            TemplateLevel::Tenant
        ],
        "strongest level first, matching TemplateLevel::PRECEDENCE"
    );
    assert_eq!(
        candidates[0].organization_id.as_ref(),
        Some(&org),
        "the organization-level row names its organization"
    );
    assert!(
        candidates[1].organization_id.is_none() && candidates[2].organization_id.is_none(),
        "the tenant and environment rows name none"
    );
}

/// A template for a DIFFERENT kind is not a candidate.
///
/// Worth its own test because the filter is the only thing separating an invitation template
/// from a password-reset one, and a resolver handed both would pick by locale and level alone
/// -- sending a recipient the wrong message entirely, which no assertion about ordering catches.
#[tokio::test]
async fn another_kinds_template_is_not_a_candidate() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "invitation",
        "en",
        "invite",
        false,
    )
    .await
    .expect("invitation template");
    insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "password_reset",
        "en",
        "reset",
        false,
    )
    .await
    .expect("reset template");

    let candidates = db
        .store()
        .scoped(scope)
        .message_templates()
        .candidates_for("invitation")
        .await
        .expect("read candidates");
    assert_eq!(
        candidates.len(),
        1,
        "only the invitation kind: {candidates:?}"
    );
    assert_eq!(candidates[0].subject, "invite");
}

/// A second override at the SAME level, kind and locale is refused.
///
/// This is the nullable-column trap the migration's two partial indexes exist for. A single
/// unique index over `organization_id` would NOT catch this: NULLs are distinct in a unique
/// index, so both tenant rows would be accepted and the resolver would pick whichever the read
/// returned first -- an override that "sometimes" applies, which is the worst kind to debug.
#[tokio::test]
async fn a_duplicate_tenant_level_override_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "invitation",
        "en",
        "first",
        false,
    )
    .await
    .expect("the first tenant override");
    let second = insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "invitation",
        "en",
        "second",
        false,
    )
    .await;
    assert!(
        second.is_err(),
        "a second tenant-level override for the same kind and locale must be refused; NULL \
         organization_id makes this the case a single unique index would silently allow"
    );
}

/// The level and the organization must agree.
///
/// A row claiming to be organization-level without naming one, or a tenant-level row carrying
/// an organization, would resolve in a way nobody wrote. The CHECK constraint refuses both
/// rather than leaving resolution to interpret a contradiction.
#[tokio::test]
async fn a_level_that_disagrees_with_its_organization_is_refused() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;

    let orphan_org_level = insert_template(
        &db,
        &env,
        scope,
        "organization",
        None,
        "invitation",
        "en",
        "no org",
        false,
    )
    .await;
    assert!(
        orphan_org_level.is_err(),
        "an organization-level row must name an organization"
    );

    let tenant_with_org = insert_template(
        &db,
        &env,
        scope,
        "tenant",
        Some(&org),
        "invitation",
        "en",
        "stray",
        false,
    )
    .await;
    assert!(
        tenant_with_org.is_err(),
        "a tenant-level row must not carry an organization"
    );
}

/// The per-field lock (issue #619) survives the round trip.
///
/// Stored now, unused by resolution yet: #619 owns the combinator that reads it. It is in the
/// table from the start because a per-field lock is cheap to include in a new table and
/// expensive to add to one already carrying data -- and #619 cannot choose "outermost pins
/// only when it opts in" at all without a column to opt in with.
#[tokio::test]
async fn the_lock_flag_round_trips() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "invitation",
        "en",
        "pinned",
        true,
    )
    .await
    .expect("locked tenant override");

    let candidates = db
        .store()
        .scoped(scope)
        .message_templates()
        .candidates_for("invitation")
        .await
        .expect("read candidates");
    assert!(
        candidates[0].locked,
        "a locked override must read back locked, or #619's combinator has nothing to act on"
    );
}

/// The store resolves end to end: an ORGANIZATION override beats the environment and tenant
/// ones for the same kind and locale (issue #111 criterion 3).
///
/// This is the assertion the resolver could never make on its own. `resolve_template` has
/// always been correct about candidates it was handed; what nothing measured was that the
/// store hands it the right ones, in the right order, with the right levels attached.
#[tokio::test]
async fn the_organization_override_wins_end_to_end() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;
    let org = create_org(&db, &env, scope).await;

    insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "invitation",
        "en",
        "tenant",
        false,
    )
    .await
    .expect("tenant override");
    insert_template(
        &db,
        &env,
        scope,
        "environment",
        None,
        "invitation",
        "en",
        "env",
        false,
    )
    .await
    .expect("environment override");
    insert_template(
        &db,
        &env,
        scope,
        "organization",
        Some(&org),
        "invitation",
        "en",
        "org",
        false,
    )
    .await
    .expect("organization override");

    let en = ironauth_store::message_template::Locale::new("en");
    let resolved = db
        .store()
        .scoped(scope)
        .message_templates()
        .resolve("invitation", &en, &en)
        .await
        .expect("resolve")
        .expect("an override exists at three levels, so one must be chosen");

    assert_eq!(
        resolved.level,
        TemplateLevel::Organization,
        "the narrowest level wins; if this ever reports Environment the store handed the \
         resolver its candidates in an order that lost the organization row"
    );
}

/// With NO override authored, resolution answers `None` -- which means "use the shipped
/// template", not "something went wrong".
///
/// Worth asserting because it is the overwhelmingly common case: almost every tenant never
/// authors an override, and a caller that treated `None` as an error would refuse to send mail
/// for all of them. It is also what makes resolution total, since the default level is code
/// rather than a row.
#[tokio::test]
async fn no_override_resolves_to_none_rather_than_an_error() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    let en = ironauth_store::message_template::Locale::new("en");
    let resolved = db
        .store()
        .scoped(scope)
        .message_templates()
        .resolve("invitation", &en, &en)
        .await
        .expect("resolution must not fail when nothing is authored");
    assert!(
        resolved.is_none(),
        "no override means fall back to the shipped template: {resolved:?}"
    );
}

/// Locale fallback runs through the store: a request for a locale nobody authored falls back
/// to the default locale at the same level.
///
/// The fallback rules are the resolver's and are tested exhaustively there. What this measures
/// is that the store preserves the locale each row was authored in -- a store that returned a
/// normalized or defaulted locale would make every fallback decision on data the operator did
/// not write.
#[tokio::test]
async fn a_locale_nobody_authored_falls_back_through_the_store() {
    let db = TestDatabase::start().await;
    let env = Env::system();
    let scope = db.seed_scope(&env).await;

    insert_template(
        &db,
        &env,
        scope,
        "tenant",
        None,
        "invitation",
        "en",
        "english",
        false,
    )
    .await
    .expect("english override");

    let resolved = db
        .store()
        .scoped(scope)
        .message_templates()
        .resolve(
            "invitation",
            &ironauth_store::message_template::Locale::new("fr"),
            &ironauth_store::message_template::Locale::new("en"),
        )
        .await
        .expect("resolve")
        .expect("the english override is reachable by fallback");
    assert_eq!(
        resolved.locale.as_str(),
        "en",
        "the resolution reports the locale it actually landed on, which is what answers \
         'why did this recipient get English?'"
    );
}
