// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the schema refuses about an impersonation session (issue #101), the constraint half.
//!
//! Two of this issue's criteria are stated as things that must not happen: starting without a
//! typed justification is rejected, and extension past the sixty-minute cap fails. Both are
//! written here as CHECKs rather than as handler code, so this file drives the ENGINE
//! deliberately. A test that went through a repository would prove the handler refuses, which
//! is a different and weaker claim than the row being unrepresentable.

use ironauth_store::test_support::TestDatabase;
use ironauth_store::{CorrelationId, Scope};

const MINUTE_MICROS: i64 = 60 * 1_000_000;

fn now_micros(env: &ironauth_env::Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

/// Insert a session directly, with whatever impersonation columns the case is probing.
///
/// Returns the raw result so a case can assert on the refusal rather than unwrapping it.
#[allow(clippy::too_many_arguments)]
async fn insert(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    impersonator: Option<&str>,
    reason_code: Option<&str>,
    reason_text: Option<&str>,
    started_offset_micros: Option<i64>,
    expires_offset_micros: Option<i64>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let now = now_micros(env);
    let id = ironauth_store::SessionId::generate(env, &scope);
    sqlx::query(
        "INSERT INTO sessions \
         (id, tenant_id, environment_id, subject, auth_methods, auth_time, expires_at, \
          impersonator, impersonation_reason_code, impersonation_reason_text, \
          impersonation_started_at, impersonation_expires_at) \
         VALUES ($1, $2, $3, 'usr_probe', 'pwd', \
                 TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval, \
                 TIMESTAMPTZ 'epoch' + ($4::text || ' microseconds')::interval, \
                 $5, $6, $7, \
                 CASE WHEN $8::bigint IS NULL THEN NULL ELSE \
                      TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval END, \
                 CASE WHEN $9::bigint IS NULL THEN NULL ELSE \
                      TIMESTAMPTZ 'epoch' + ($9::text || ' microseconds')::interval END)",
    )
    .bind(id.to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(now)
    .bind(impersonator)
    .bind(reason_code)
    .bind(reason_text)
    .bind(started_offset_micros.map(|delta| now + delta))
    .bind(expires_offset_micros.map(|delta| now + delta))
    .execute(db.owner_pool())
    .await
}

/// An ordinary session carries none of the impersonation columns and is unaffected.
///
/// The EXPAND claim: five nullable columns were added and a session that names no impersonator
/// still stores exactly as it did, so no existing row and no existing writer is disturbed.
#[tokio::test]
async fn an_ordinary_session_is_untouched_by_the_impersonation_columns() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let inserted = insert(&db, &env, scope, None, None, None, None, None).await;
    assert!(
        inserted.is_ok(),
        "an ordinary session must still insert: {inserted:?}"
    );
}

/// A well-formed impersonation session, inside the cap, is admitted.
///
/// The floor for everything below. Without it a constraint that refused EVERY impersonation
/// session would pass every refusal test in this file.
#[tokio::test]
async fn a_justified_impersonation_session_inside_the_cap_is_admitted() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let admitted = insert(
        &db,
        &env,
        scope,
        Some("adm_support_engineer"),
        Some("support_ticket"),
        Some("Ticket 4417: cannot complete checkout, reproducing as the user."),
        Some(0),
        Some(30 * MINUTE_MICROS),
    )
    .await;
    assert!(
        admitted.is_ok(),
        "a justified impersonation session within the cap must be admitted: {admitted:?}"
    );
}

/// The arc refuses every partial impersonation session.
///
/// Each case is a row a writer could produce by filling in some of the columns and forgetting
/// the rest, which is exactly what a handler that validates its input in pieces produces.
#[tokio::test]
async fn the_arc_refuses_every_partial_impersonation_session() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let cap = Some(30 * MINUTE_MICROS);

    for (label, impersonator, code, text, started, expires) in [
        (
            "an impersonator with no justification at all",
            Some("adm_x"),
            None,
            None,
            Some(0),
            cap,
        ),
        (
            "a typed code but no free text",
            Some("adm_x"),
            Some("support_ticket"),
            None,
            Some(0),
            cap,
        ),
        (
            "free text but no typed code",
            Some("adm_x"),
            None,
            Some("because I said so"),
            Some(0),
            cap,
        ),
        (
            "a justification with no expiry, which is impersonation without a cap",
            Some("adm_x"),
            Some("support_ticket"),
            Some("Ticket 4417"),
            Some(0),
            None,
        ),
        (
            "a justification with no start, so the cap has nothing to measure from",
            Some("adm_x"),
            Some("support_ticket"),
            Some("Ticket 4417"),
            None,
            cap,
        ),
        (
            "a justification attached to no impersonator",
            None,
            Some("support_ticket"),
            Some("Ticket 4417"),
            Some(0),
            cap,
        ),
    ] {
        let result = insert(&db, &env, scope, impersonator, code, text, started, expires).await;
        assert!(result.is_err(), "the arc admitted {label}");
    }
}

/// A blank justification is not a justification.
///
/// The arc is satisfied by an empty string, which is why this is a separate constraint. A
/// handler that trims its input and stores the result would otherwise write a row that
/// satisfies every schema rule and tells an auditor nothing.
#[tokio::test]
async fn a_blank_justification_is_refused() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    for (label, code, text) in [
        ("an empty code", "", "Ticket 4417"),
        ("an empty text", "support_ticket", ""),
        ("whitespace passing for a code", "   ", "Ticket 4417"),
        ("whitespace passing for text", "support_ticket", "\t\n "),
    ] {
        let result = insert(
            &db,
            &env,
            scope,
            Some("adm_x"),
            Some(code),
            Some(text),
            Some(0),
            Some(30 * MINUTE_MICROS),
        )
        .await;
        assert!(
            result.is_err(),
            "a blank justification was admitted: {label}"
        );
    }
}

/// The sixty-minute cap is unrepresentable, on INSERT and on UPDATE alike.
///
/// The UPDATE half is the one that matters. "Refresh or extension past the cap fails" is a
/// statement about a writer that does not exist yet, and a CHECK is re-evaluated on every
/// UPDATE, so it holds for that writer too. Anchoring on `impersonation_started_at` rather
/// than on `now()` is what makes an extension measured from when the impersonation BEGAN;
/// against `now()` a session could be extended sixty minutes at a time, forever.
#[tokio::test]
async fn the_sixty_minute_cap_cannot_be_stored_or_extended_past() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    let over = insert(
        &db,
        &env,
        scope,
        Some("adm_x"),
        Some("support_ticket"),
        Some("Ticket 4417"),
        Some(0),
        Some(61 * MINUTE_MICROS),
    )
    .await;
    assert!(
        over.is_err(),
        "a 61 minute impersonation session was stored"
    );

    let backwards = insert(
        &db,
        &env,
        scope,
        Some("adm_x"),
        Some("support_ticket"),
        Some("Ticket 4417"),
        Some(0),
        Some(-MINUTE_MICROS),
    )
    .await;
    assert!(
        backwards.is_err(),
        "an impersonation session expiring before it started was stored"
    );

    // Exactly at the cap is admitted: the bound is inclusive, and a test that only probed
    // over-cap could not tell an inclusive bound from an exclusive one.
    let boundary = insert(
        &db,
        &env,
        scope,
        Some("adm_x"),
        Some("support_ticket"),
        Some("Ticket 4417"),
        Some(0),
        Some(60 * MINUTE_MICROS),
    )
    .await;
    assert!(
        boundary.is_ok(),
        "a session expiring exactly at the cap must be admitted: {boundary:?}"
    );

    // The extension. Push the expiry of the row just stored past the cap.
    let extended = sqlx::query(
        "UPDATE sessions SET impersonation_expires_at = \
             impersonation_started_at + INTERVAL '90 minutes' \
         WHERE impersonator IS NOT NULL",
    )
    .execute(db.owner_pool())
    .await;
    assert!(
        extended.is_err(),
        "an impersonation session was EXTENDED past the cap, which is the bypass the \
         constraint exists to make unrepresentable"
    );

    // And an extension WITHIN the cap still works, so the constraint bounds refreshes rather
    // than forbidding them.
    let refreshed = sqlx::query(
        "UPDATE sessions SET impersonation_expires_at = \
             impersonation_started_at + INTERVAL '45 minutes' \
         WHERE impersonator IS NOT NULL",
    )
    .execute(db.owner_pool())
    .await;
    assert!(
        refreshed.is_ok(),
        "a refresh inside the cap must still be allowed: {refreshed:?}"
    );

    let _ = CorrelationId::generate(&env);
}

/// The cap is measured from the START, not from the moment of the extension.
///
/// This is the case that tells the two anchors apart, and the previous test cannot: there the
/// session begins now, so `started_at + 60m` and `now() + 60m` are the same instant and an
/// `now()` anchored constraint refuses the same rows the correct one does.
///
/// A session that has already been running fifty minutes is where they diverge. Extending it
/// to thirty minutes from NOW is eighty minutes from where it started. The correct constraint
/// refuses that; anchored on `now()` it is admitted, and admitted again ten minutes later, and
/// again, which is impersonation with no cap at all reached one refresh at a time.
#[tokio::test]
async fn an_old_impersonation_session_cannot_be_extended_a_refresh_at_a_time() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    // Started fifty minutes ago and expiring five minutes from now: fifty-five minutes of
    // impersonation, comfortably inside the cap.
    let seeded = insert(
        &db,
        &env,
        scope,
        Some("adm_x"),
        Some("support_ticket"),
        Some("Ticket 4417"),
        Some(-50 * MINUTE_MICROS),
        Some(5 * MINUTE_MICROS),
    )
    .await;
    assert!(
        seeded.is_ok(),
        "a fifty-five minute impersonation session is inside the cap: {seeded:?}"
    );

    // Thirty minutes from NOW is eighty minutes from the start.
    let extended = sqlx::query(
        "UPDATE sessions SET impersonation_expires_at =              TIMESTAMPTZ 'epoch' + ($1::text || ' microseconds')::interval          WHERE impersonator IS NOT NULL",
    )
    .bind(now_micros(&env) + 30 * MINUTE_MICROS)
    .execute(db.owner_pool())
    .await;
    assert!(
        extended.is_err(),
        "a session fifty minutes old was extended to eighty minutes from its start, which is          the refresh-at-a-time bypass the cap exists to prevent"
    );

    // Ten more minutes from now is sixty from the start: the boundary, still allowed.
    let inside = sqlx::query(
        "UPDATE sessions SET impersonation_expires_at =              impersonation_started_at + INTERVAL '60 minutes'          WHERE impersonator IS NOT NULL",
    )
    .execute(db.owner_pool())
    .await;
    assert!(
        inside.is_ok(),
        "an extension to exactly the cap must still be allowed: {inside:?}"
    );
}
