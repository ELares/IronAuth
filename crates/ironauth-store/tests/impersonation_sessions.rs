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

/// The impersonation columns as read straight back from the row: impersonator, reason code,
/// reason text, start and expiry. Named because the tuple is past the complexity lint, and
/// because a reader of the assertion below should not have to count `Option<String>`s.
type StoredImpersonation = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
);

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

/// The repository writes all five impersonation columns, and an ordinary rotate writes none.
///
/// The pairing is the point. A test that only asserted the impersonated row would pass against
/// a writer that stamped every session with the same impersonator, which is the failure mode
/// that matters here: an ordinary session wrongly flagged is an audit record accusing somebody.
#[tokio::test]
async fn the_repository_writes_the_impersonation_columns_and_only_when_asked() {
    use ironauth_store::impersonation::Impersonation;

    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let now = now_micros(&env);
    let far = now + 24 * 60 * MINUTE_MICROS;

    let plain = ironauth_store::SessionId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &plain,
            None,
            ironauth_store::NewSession {
                impersonation: None,
                subject: "usr_ordinary",
                auth_methods: "pwd",
                auth_time_micros: now,
                idle_expires_micros: far,
                absolute_expires_micros: far,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate an ordinary session");

    let impersonated = ironauth_store::SessionId::generate(&env, &scope);
    let act = Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        "Ticket 4417: cannot complete checkout, reproducing as the user.",
        now,
        30 * MINUTE_MICROS,
    )
    .expect("a justified request inside the cap");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &impersonated,
            None,
            ironauth_store::NewSession {
                impersonation: Some(act),
                subject: "usr_target",
                auth_methods: "pwd",
                auth_time_micros: now,
                idle_expires_micros: far,
                absolute_expires_micros: far,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("rotate an impersonation session");

    let (impersonator, code, text, started, expires): StoredImpersonation = sqlx::query_as(
        "SELECT impersonator, impersonation_reason_code, impersonation_reason_text, \
                (EXTRACT(EPOCH FROM impersonation_started_at) * 1000000)::bigint, \
                (EXTRACT(EPOCH FROM impersonation_expires_at) * 1000000)::bigint \
         FROM sessions WHERE id = $1",
    )
    .bind(impersonated.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the impersonation session back");
    assert_eq!(impersonator.as_deref(), Some("adm_support_engineer"));
    assert_eq!(code.as_deref(), Some("support_ticket"));
    assert_eq!(
        text.as_deref(),
        Some("Ticket 4417: cannot complete checkout, reproducing as the user.")
    );
    assert_eq!(started, Some(now));
    assert_eq!(
        expires,
        Some(now + 30 * MINUTE_MICROS),
        "the stored expiry must be the start plus the requested duration"
    );

    let ordinary: (Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT impersonator, \
                (EXTRACT(EPOCH FROM impersonation_expires_at) * 1000000)::bigint \
         FROM sessions WHERE id = $1",
    )
    .bind(plain.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the ordinary session back");
    assert_eq!(
        ordinary,
        (None, None),
        "an ordinary session must carry no impersonation at all"
    );
}

/// A live impersonation session reports its impersonation; an ordinary one reports none.
///
/// This is what makes the `act` claim reachable from a real session rather than only from a
/// test that hands the minter an actor directly.
#[tokio::test]
async fn a_live_session_reports_the_impersonation_it_was_started_under() {
    use ironauth_store::impersonation::Impersonation;

    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let now = now_micros(&env);
    let far = now + 24 * 60 * MINUTE_MICROS;

    let id = ironauth_store::SessionId::generate(&env, &scope);
    let act = Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        "Ticket 4417: reproducing the checkout failure as the user.",
        now,
        30 * MINUTE_MICROS,
    )
    .expect("a justified request inside the cap");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &id,
            None,
            ironauth_store::NewSession {
                impersonation: Some(act),
                subject: "usr_target",
                auth_methods: "pwd",
                auth_time_micros: now,
                idle_expires_micros: far,
                absolute_expires_micros: far,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("start the impersonation session");

    let record = db
        .store()
        .scoped(scope)
        .sessions()
        .get(&id, now, 0)
        .await
        .expect("read")
        .expect("a live impersonation session resolves");
    let carried = record
        .impersonation
        .expect("the session reports its impersonation");
    assert_eq!(carried.impersonator, "adm_support_engineer");
    assert_eq!(carried.reason_code, "support_ticket");
    assert_eq!(
        carried.reason_text,
        "Ticket 4417: reproducing the checkout failure as the user."
    );
    assert_eq!(carried.expires_at_unix_micros, now + 30 * MINUTE_MICROS);
}

/// A session whose IMPERSONATION has lapsed stops resolving, even though the SESSION has not.
///
/// The criterion says an impersonation session expires at or before the cap. The schema bounds
/// what can be stored; this bounds what can be USED, and the two are different claims. Here
/// the session's own absolute expiry is a day out, so nothing but the impersonation expiry can
/// refuse it: without that clause the impersonator would keep acting as the user long past the
/// window they justified, on a session that every other check calls live.
#[tokio::test]
async fn a_lapsed_impersonation_stops_the_session_even_while_the_session_lives() {
    use ironauth_store::impersonation::Impersonation;

    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let now = now_micros(&env);
    let far = now + 24 * 60 * MINUTE_MICROS;

    let id = ironauth_store::SessionId::generate(&env, &scope);
    let act = Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        "Ticket 4417",
        now,
        10 * MINUTE_MICROS,
    )
    .expect("justified");
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &id,
            None,
            ironauth_store::NewSession {
                impersonation: Some(act),
                subject: "usr_target",
                auth_methods: "pwd",
                auth_time_micros: now,
                idle_expires_micros: far,
                absolute_expires_micros: far,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("start");

    let sessions = db.store().scoped(scope).sessions();
    assert!(
        sessions
            .get(&id, now + 5 * MINUTE_MICROS, 0)
            .await
            .expect("read")
            .is_some(),
        "five minutes in, the impersonation is still within its window"
    );
    assert!(
        sessions
            .get(&id, now + 11 * MINUTE_MICROS, 0)
            .await
            .expect("read")
            .is_none(),
        "eleven minutes in the impersonation has lapsed, and the session must stop resolving \
         even though its own expiry is a day away"
    );

    // And an ORDINARY session at the same instant is untouched, so the clause above bounds
    // impersonation rather than shortening every session.
    let ordinary = ironauth_store::SessionId::generate(&env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .sessions()
        .rotate(
            &env,
            &ordinary,
            None,
            ironauth_store::NewSession {
                impersonation: None,
                subject: "usr_ordinary",
                auth_methods: "pwd",
                auth_time_micros: now,
                idle_expires_micros: far,
                absolute_expires_micros: far,
                user_agent: None,
                peer_ip: None,
            },
        )
        .await
        .expect("start an ordinary session");
    assert!(
        sessions
            .get(&ordinary, now + 11 * MINUTE_MICROS, 0)
            .await
            .expect("read")
            .is_some(),
        "an ordinary session is unaffected by the impersonation bound"
    );
}

/// The fleet surface flags an impersonation session and reports it even once lapsed.
///
/// Criterion 2 asks for impersonation sessions to be distinguishable everywhere sessions are
/// displayed. The fleet surface deliberately reports revoked and ended sessions, so it must
/// keep reporting a LAPSED impersonation too: an operator reviewing an incident needs to see
/// that a session WAS somebody acting as this user, and the auth read path is the one that
/// refuses to let them keep doing it.
///
/// An ordinary session is listed beside it, so "flagged" is a difference rather than a label
/// the surface applies to everything.
#[tokio::test]
async fn the_fleet_surface_flags_an_impersonation_session_and_keeps_reporting_it() {
    use ironauth_store::impersonation::Impersonation;

    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let now = now_micros(&env);
    let far = now + 24 * 60 * MINUTE_MICROS;

    let ordinary = ironauth_store::SessionId::generate(&env, &scope);
    let impersonated = ironauth_store::SessionId::generate(&env, &scope);
    let act = Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        "Ticket 4417",
        now,
        10 * MINUTE_MICROS,
    )
    .expect("justified");
    for (id, subject, impersonation) in [
        (&ordinary, "usr_ordinary", None),
        (&impersonated, "usr_target", Some(act)),
    ] {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(&env), CorrelationId::generate(&env))
            .sessions()
            .rotate(
                &env,
                id,
                None,
                ironauth_store::NewSession {
                    impersonation,
                    subject,
                    auth_methods: "pwd",
                    auth_time_micros: now,
                    idle_expires_micros: far,
                    absolute_expires_micros: far,
                    user_agent: None,
                    peer_ip: None,
                },
            )
            .await
            .expect("start a session");
    }

    let fleet = db.store().scoped(scope).session_fleet();
    let plain = fleet
        .get(&ordinary)
        .await
        .expect("read")
        .expect("the ordinary session is listed");
    assert!(
        plain.impersonation.is_none(),
        "an ordinary session must carry no flag"
    );

    let flagged = fleet
        .get(&impersonated)
        .await
        .expect("read")
        .expect("the impersonation session is listed");
    let carried = flagged.impersonation.expect("the flag is present");
    assert_eq!(carried.impersonator, "adm_support_engineer");
    assert_eq!(carried.reason_code, "support_ticket");
    assert_eq!(carried.reason_text, "Ticket 4417");
    assert_eq!(carried.expires_at_unix_micros, now + 10 * MINUTE_MICROS);

    // Past the cap the AUTH path refuses it, and the FLEET surface still reports it. That
    // difference is the point: one decides whether the impersonation may continue, the other
    // is the record that it happened.
    assert!(
        db.store()
            .scoped(scope)
            .sessions()
            .get(&impersonated, now + 11 * MINUTE_MICROS, 0)
            .await
            .expect("read")
            .is_none(),
        "the auth path refuses a lapsed impersonation"
    );
    assert!(
        fleet
            .get(&impersonated)
            .await
            .expect("read")
            .expect("still listed")
            .impersonation
            .is_some(),
        "the fleet surface still reports it, so the incident stays legible"
    );
}
