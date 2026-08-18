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

/// The justification is retrievable from the AUDIT STREAM, linked to session, actor and
/// target, and the end event brackets it (issue #101, criterion 4).
///
/// The written justification is carried in no token by design, so the audit row is the only
/// durable place it exists. That makes this test the whole of criterion 4 rather than a
/// convenience check: if the detail is wrong or absent, the justification a support engineer
/// typed is gone.
///
/// An ordinary session is revoked alongside, because "an end event is emitted" and "an end
/// event is emitted for impersonations" are different claims and only the second is wanted.
#[tokio::test]
async fn the_justification_is_retrievable_from_the_audit_stream_and_bracketed_by_its_end() {
    use ironauth_store::impersonation::Impersonation;

    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let now = now_micros(&env);
    let far = now + 24 * 60 * MINUTE_MICROS;
    let justification = "Ticket 4417: cannot complete checkout, reproducing as the user.";

    let impersonated = ironauth_store::SessionId::generate(&env, &scope);
    let ordinary = ironauth_store::SessionId::generate(&env, &scope);
    let act = Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        justification,
        now,
        30 * MINUTE_MICROS,
    )
    .expect("justified");
    for (id, subject, impersonation) in [
        (&impersonated, "usr_target", Some(act)),
        (&ordinary, "usr_ordinary", None),
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

    let (target, detail): (String, String) = sqlx::query_as(
        "SELECT target_id, detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'impersonation.started'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("exactly one start row exists, so the ordinary session produced none");
    assert_eq!(
        target,
        impersonated.to_string(),
        "the row targets the SESSION, which is what links the justification to everything the \
         impersonator subsequently did"
    );
    let detail: serde_json::Value = serde_json::from_str(&detail).expect("detail is JSON");
    assert_eq!(detail["impersonator"], "adm_support_engineer");
    assert_eq!(detail["reason_code"], "support_ticket");
    assert_eq!(
        detail["reason_text"], justification,
        "the WRITTEN justification is here and nowhere else: {detail}"
    );
    assert_eq!(detail["session_id"], impersonated.to_string());
    assert_eq!(detail["expires_at_unix_micros"], now + 30 * MINUTE_MICROS);

    assert_one_end_event_brackets_it(&db, &env, scope, &impersonated, &ordinary).await;
}

/// The end half, split out because the fixture above and these probes together exceed the
/// function-length lint, and the probes are the part worth reading.
async fn assert_one_end_event_brackets_it(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    impersonated: &ironauth_store::SessionId,
    ordinary: &ironauth_store::SessionId,
) {
    // Ending both sessions must produce exactly ONE end event, for the impersonation.
    for id in [impersonated, ordinary] {
        db.store()
            .scoped(scope)
            .acting(db.test_actor(env), CorrelationId::generate(env))
            .sessions()
            .revoke(
                env,
                id,
                ironauth_store::SessionEndCause::Revoked,
                false,
                None,
            )
            .await
            .expect("revoke");
    }
    let ends: Vec<(String, String)> = sqlx::query_as(
        "SELECT target_id, detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'impersonation.ended'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_all(db.owner_pool())
    .await
    .expect("read the end rows");
    assert_eq!(
        ends.len(),
        1,
        "an ordinary logout emits no impersonation end event"
    );
    assert_eq!(
        ends[0].0,
        impersonated.to_string(),
        "the end row targets the same session the start did, so the pair brackets the window"
    );
    let end_detail: serde_json::Value = serde_json::from_str(&ends[0].1).expect("detail is JSON");
    assert_eq!(end_detail["impersonator"], "adm_support_engineer");
    assert_eq!(end_detail["cause"], "revoked");
}

/// Insert an impersonation authorization directly, for the constraint probes below.
#[allow(clippy::too_many_arguments)]
async fn insert_authorization(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    impersonator: &str,
    reason_code: &str,
    reason_text: &str,
    started_offset: i64,
    expires_offset: i64,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let now = now_micros(env);
    sqlx::query(
        "INSERT INTO impersonation_authorizations \
         (id, tenant_id, environment_id, user_id, impersonator, reason_code, reason_text, \
          started_at, expires_at) \
         VALUES ($1, $2, $3, 'usr_target', $4, $5, $6, \
                 TIMESTAMPTZ 'epoch' + ($7::text || ' microseconds')::interval, \
                 TIMESTAMPTZ 'epoch' + ($8::text || ' microseconds')::interval)",
    )
    .bind(ironauth_store::ImpersonationAuthorizationId::generate(env, &scope).to_string())
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(impersonator)
    .bind(reason_code)
    .bind(reason_text)
    .bind(now + started_offset)
    .bind(now + expires_offset)
    .execute(db.owner_pool())
    .await
}

/// The authorization refuses the same things the session does, one table earlier.
///
/// It has to. The session it redeems into inherits this expiry and this justification, so an
/// authorization that could hold a blank reason or outlast the cap would move the problem
/// rather than solve it, and the session-level CHECKs would then be refusing rows the product
/// had already told an operator were accepted.
#[tokio::test]
async fn an_authorization_refuses_a_blank_justification_and_a_duration_past_the_cap() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;

    let ok = insert_authorization(
        &db,
        &env,
        scope,
        "adm_support",
        "support_ticket",
        "Ticket 4417",
        0,
        30 * MINUTE_MICROS,
    )
    .await;
    assert!(
        ok.is_ok(),
        "a justified authorization inside the cap: {ok:?}"
    );

    for (label, impersonator, code, text) in [
        (
            "a blank impersonator",
            "   ",
            "support_ticket",
            "Ticket 4417",
        ),
        ("a blank code", "adm_support", "", "Ticket 4417"),
        (
            "whitespace passing for text",
            "adm_support",
            "support_ticket",
            "\t\n ",
        ),
    ] {
        let refused = insert_authorization(
            &db,
            &env,
            scope,
            impersonator,
            code,
            text,
            0,
            30 * MINUTE_MICROS,
        )
        .await;
        assert!(refused.is_err(), "admitted {label}");
    }

    for (label, started, expires) in [
        ("sixty-one minutes", 0, 61 * MINUTE_MICROS),
        ("expiring before it starts", 0, -MINUTE_MICROS),
        ("a zero window", 0, 0),
        // Eighty minutes from a start fifty minutes ago, which is the shape a `now()`-anchored
        // cap would admit and this one must not.
        (
            "eighty minutes from an old start",
            -50 * MINUTE_MICROS,
            30 * MINUTE_MICROS,
        ),
    ] {
        let refused = insert_authorization(
            &db,
            &env,
            scope,
            "adm_support",
            "support_ticket",
            "Ticket 4417",
            started,
            expires,
        )
        .await;
        assert!(refused.is_err(), "admitted {label}");
    }
}

/// Redemption is all or nothing: a spent authorization names the session it bought.
///
/// A redemption stamp with no session would make the authorization spent with nothing to show
/// for it, which reads in an audit as an impersonation that happened and left no trace.
#[tokio::test]
async fn a_redeemed_authorization_must_name_the_session_it_bought() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    insert_authorization(
        &db,
        &env,
        scope,
        "adm_support",
        "support_ticket",
        "Ticket 4417",
        0,
        30 * MINUTE_MICROS,
    )
    .await
    .expect("issue");

    let half = sqlx::query("UPDATE impersonation_authorizations SET redeemed_at = now()")
        .execute(db.owner_pool())
        .await;
    assert!(
        half.is_err(),
        "a redemption stamp with no session was stored"
    );

    let other_half =
        sqlx::query("UPDATE impersonation_authorizations SET redeemed_session_id = 'ses_x'")
            .execute(db.owner_pool())
            .await;
    assert!(
        other_half.is_err(),
        "a session with no redemption stamp was stored"
    );

    let both = sqlx::query(
        "UPDATE impersonation_authorizations \
         SET redeemed_at = now(), redeemed_session_id = 'ses_x'",
    )
    .execute(db.owner_pool())
    .await;
    assert!(both.is_ok(), "the pair together is admitted: {both:?}");
}

/// Each plane holds exactly the authorization privileges its role in the flow needs.
///
/// The split is the whole reason this table exists, so it is asserted rather than described.
/// The control plane ISSUES and READS and may not stamp a redemption: a plane that could burn
/// an authorization without creating a session could spend an operator's justification on
/// nothing. The app plane REDEEMS and may not issue: issuing is the authorized, audited act
/// and belongs to the plane that checked the permission.
///
/// Read from the privilege catalogue rather than by attempting writes, because the tests above
/// use the owner pool and would not notice a widened grant at all.
#[tokio::test]
async fn each_plane_holds_exactly_its_authorization_privileges() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let _ = db.seed_scope(&env).await;

    assert_eq!(
        table_wide_privileges(&db, "ironauth_control").await,
        vec!["INSERT".to_owned(), "SELECT".to_owned()],
        "the control plane issues and reads, and must NOT be able to stamp a redemption: \
         burning an authorization without creating a session spends a justification on nothing"
    );
    assert_eq!(
        table_wide_privileges(&db, "ironauth_app").await,
        vec!["SELECT".to_owned()],
        "the app plane reads to redeem and must NOT be able to issue; its UPDATE is column \
         scoped and so does not appear as a table-wide privilege"
    );

    let app_updates: Vec<String> = sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.column_privileges \
         WHERE grantee = 'ironauth_app' AND privilege_type = 'UPDATE' \
           AND table_schema = 'public' AND table_name = 'impersonation_authorizations' \
         ORDER BY column_name",
    )
    .fetch_all(db.owner_pool())
    .await
    .expect("read the column privilege catalogue");
    assert_eq!(
        app_updates,
        vec!["redeemed_at".to_owned(), "redeemed_session_id".to_owned()],
        "the app plane may stamp the redemption and nothing else: it must not be able to \
         rewrite the justification or push out the bound of an authorization it is redeeming"
    );
}

/// The table-wide privileges one role holds on the authorization table, sorted.
///
/// A plain function rather than a closure: two calls need it and a closure capturing `db` by
/// move cannot be called twice.
async fn table_wide_privileges(db: &TestDatabase, grantee: &str) -> Vec<String> {
    let mut held: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT privilege_type::text FROM information_schema.table_privileges \
         WHERE grantee = $1 AND table_schema = 'public' \
           AND table_name = 'impersonation_authorizations'",
    )
    .bind(grantee)
    .fetch_all(db.owner_pool())
    .await
    .expect("read the privilege catalogue");
    held.sort();
    held
}

/// Issue an authorization through the control plane, for the redemption tests below.
async fn issue_authorization(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    user: &ironauth_store::UserId,
    window_micros: i64,
) -> ironauth_store::ImpersonationAuthorizationId {
    use ironauth_store::impersonation::Impersonation;
    let id = ironauth_store::ImpersonationAuthorizationId::generate(env, &scope);
    let act = Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        "Ticket 4417: reproducing the checkout failure as the user.",
        now_micros(env),
        window_micros,
    )
    .expect("justified");
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .impersonation_authorizations()
        .issue(
            env,
            ironauth_store::NewImpersonationAuthorization {
                id: &id,
                user_id: user,
                impersonation: act,
            },
        )
        .await
        .expect("issue the authorization");
    id
}

/// Redemption turns an authorization into a flagged session, exactly once.
///
/// The single-use guard lives in the UPDATE's own `redeemed_at IS NULL` clause rather than in
/// a read-then-write, so this also covers the case two concurrent redemptions would hit: the
/// second finds no unspent row and is the uniform not-found.
#[tokio::test]
async fn an_authorization_redeems_into_a_flagged_session_exactly_once() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "target@example.test").await;
    let id = issue_authorization(&db, &env, scope, &user, 30 * MINUTE_MICROS).await;
    let now = now_micros(&env);

    let redeemed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .redeem(&env, &id, now)
        .await
        .expect("the first redemption succeeds");
    assert_eq!(redeemed.user_id, user);

    // The session it produced is a real, flagged, capped one.
    let record = db
        .store()
        .scoped(scope)
        .sessions()
        .get(&redeemed.session_id, now, 0)
        .await
        .expect("read")
        .expect("the redeemed session is live");
    let carried = record.impersonation.expect("it is flagged");
    assert_eq!(carried.impersonator, "adm_support_engineer");
    assert_eq!(carried.reason_code, "support_ticket");
    assert_eq!(
        record.subject,
        user.to_string(),
        "the session belongs to the TARGET, not the operator"
    );
    assert_eq!(
        carried.expires_at_unix_micros,
        redeemed.expires_at_unix_micros
    );

    // The session's OWN expiry is the impersonation's, not merely longer than it. A longer one
    // would be inert, because the read refuses past the bound either way, but it would read to
    // anyone inspecting the row as though the impersonation had longer to run than it does.
    let (idle_us, abs_us): (Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT (EXTRACT(EPOCH FROM idle_expires_at) * 1000000)::bigint, \
                (EXTRACT(EPOCH FROM absolute_expires_at) * 1000000)::bigint \
         FROM sessions WHERE id = $1",
    )
    .bind(redeemed.session_id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read the session row");
    assert_eq!(
        (idle_us, abs_us),
        (
            Some(redeemed.expires_at_unix_micros),
            Some(redeemed.expires_at_unix_micros)
        ),
        "the session must not claim to outlive the impersonation that created it"
    );

    // Spent. A second redemption finds no unspent row.
    let again = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .redeem(&env, &id, now)
        .await;
    assert!(
        matches!(again, Err(ironauth_store::StoreError::NotFound)),
        "an authorization is single use: {again:?}"
    );
}

/// An authorization that lapsed before anyone redeemed it is refused.
///
/// The cap bounds how long an impersonation may LAST; this bounds redeeming one that expired
/// while nobody was looking. Without it an operator could hold an authorization issued this
/// morning and spend it tonight, with a session capped from the ORIGINAL start and therefore
/// already dead, which is a confusing failure instead of a clear refusal.
#[tokio::test]
async fn an_expired_authorization_cannot_be_redeemed() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "target@example.test").await;
    let id = issue_authorization(&db, &env, scope, &user, 10 * MINUTE_MICROS).await;

    let refused = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .redeem(&env, &id, now_micros(&env) + 11 * MINUTE_MICROS)
        .await;
    assert!(
        matches!(refused, Err(ironauth_store::StoreError::NotFound)),
        "a lapsed authorization must not redeem: {refused:?}"
    );

    // And it is still unspent, so the refusal did not burn it.
    let redeemed_at: Option<i64> = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM redeemed_at) * 1000000)::bigint \
         FROM impersonation_authorizations WHERE id = $1",
    )
    .bind(id.to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("read it back");
    assert_eq!(
        redeemed_at, None,
        "a refused redemption must leave the authorization unspent"
    );
}

/// Issuing is the control plane's, redeeming is the app plane's, and the DATABASE says so.
///
/// The grants are asserted elsewhere from the catalogue; this drives the actual calls, because
/// a grant that is correct and a code path that uses the wrong pool are different failures and
/// only one of them shows up in `information_schema`.
#[tokio::test]
async fn the_wrong_plane_cannot_issue_or_redeem() {
    use ironauth_store::impersonation::Impersonation;

    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "target@example.test").await;
    let id = ironauth_store::ImpersonationAuthorizationId::generate(&env, &scope);
    let act = Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        "Ticket 4417",
        now_micros(&env),
        30 * MINUTE_MICROS,
    )
    .expect("justified");

    // The APP plane may not issue: it holds SELECT and the two redemption columns, no INSERT.
    let issued_by_app = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .issue(
            &env,
            ironauth_store::NewImpersonationAuthorization {
                id: &id,
                user_id: &user,
                impersonation: act,
            },
        )
        .await;
    assert!(
        issued_by_app.is_err(),
        "the app plane must not be able to issue an authorization: {issued_by_app:?}"
    );

    // The CONTROL plane may not redeem: redeeming creates a session, which is the app
    // plane's alone, and it holds no UPDATE here to stamp one spent either.
    let real = issue_authorization(&db, &env, scope, &user, 30 * MINUTE_MICROS).await;
    let redeemed_by_control = db
        .control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .redeem(&env, &real, now_micros(&env))
        .await;
    assert!(
        redeemed_by_control.is_err(),
        "the control plane must not be able to redeem: {redeemed_by_control:?}"
    );
}

/// Register a user, so an authorization names a real target.
async fn seed_user(
    db: &TestDatabase,
    env: &ironauth_env::Env,
    scope: Scope,
    handle: &str,
) -> ironauth_store::UserId {
    let id = ironauth_store::UserId::generate(env, &scope);
    db.store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .users()
        .register_passwordless(env, &id, handle)
        .await
        .expect("register user");
    id
}

/// The AUTHORIZED event carries the justification, and is distinct from the STARTED one.
///
/// This exists because the first version of `issue` built the detail and dropped it:
/// `write_audited` has no way to pass one, so the row was written with an empty detail and
/// nothing failed. An authorization event with no justification records that somebody was
/// allowed to impersonate and not why, which is the half an auditor actually needs.
///
/// The two events are asserted as a pair because their separation is deliberate. An
/// authorization may be issued and never redeemed; collapsing them would log an impersonation
/// that never happened.
#[tokio::test]
async fn authorizing_audits_the_justification_and_starting_is_a_separate_event() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "target@example.test").await;
    let id = issue_authorization(&db, &env, scope, &user, 30 * MINUTE_MICROS).await;

    let (target, detail): (String, String) = sqlx::query_as(
        "SELECT target_id, detail FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'impersonation.authorized'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("exactly one authorization event");
    assert_eq!(target, id.to_string(), "it targets the authorization");
    let detail: serde_json::Value = serde_json::from_str(&detail).expect("detail is JSON");
    assert_eq!(detail["impersonator"], "adm_support_engineer");
    assert_eq!(detail["reason_code"], "support_ticket");
    assert_eq!(
        detail["reason_text"], "Ticket 4417: reproducing the checkout failure as the user.",
        "the written justification is recorded at AUTHORIZATION time, not only at start"
    );
    assert_eq!(detail["user_id"], user.to_string());

    // Issuing alone starts nothing.
    let started: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'impersonation.started'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("count");
    assert_eq!(
        started, 0,
        "an authorization that was never redeemed must not log an impersonation that never \
         happened"
    );

    // Redeeming produces the start event, targeting the SESSION rather than the authorization.
    let redeemed = db
        .store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .redeem(&env, &id, now_micros(&env))
        .await
        .expect("redeem");
    let start_target: String = sqlx::query_scalar(
        "SELECT target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'impersonation.started'",
    )
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .fetch_one(db.owner_pool())
    .await
    .expect("exactly one start event");
    assert_eq!(start_target, redeemed.session_id.to_string());
}

/// Authorizing an impersonation announces it, carrying the code and the expiry but never the
/// operator's prose.
///
/// This is the widest authority the management surface hands out: it reaches everything the
/// target user can reach. A consumer running detection or oversight needs it, needs the
/// EXPIRY (the authorization is time-boxed, and a receiver that cannot see the box has to
/// treat it as permanent), and needs the registered reason CODE.
///
/// It does not get the reason TEXT. That is prose an operator wrote about a person's account,
/// and it belongs in the audit trail -- a narrower audience than a webhook. The test asserts
/// the absence, because a leak here is worse than no event at all.
#[tokio::test]
async fn authorizing_an_impersonation_announces_it_without_the_operator_prose() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "watched@example.test").await;
    let id = ironauth_store::ImpersonationAuthorizationId::generate(&env, &scope);
    let act = ironauth_store::impersonation::Impersonation::start(
        "adm_support_engineer",
        "support_ticket",
        "Ticket 4417: reproducing the checkout failure as the user.",
        now_micros(&env),
        30 * MINUTE_MICROS,
    )
    .expect("justified");
    let expires_at = act.expires_at_unix_micros();

    let envelope = ironauth_store::event_catalog::envelope(
        "evt_impersonation_authorized",
        "impersonation.authorized",
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1,
        &serde_json::json!({
            "authorization_id": id.to_string(),
            "user_id": user.to_string(),
            "reason_code": "support_ticket",
            "expires_at_unix_ms": expires_at / 1000,
        }),
    )
    .expect("impersonation.authorized is registered");

    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .issue_with_event(
            &env,
            ironauth_store::NewImpersonationAuthorization {
                id: &id,
                user_id: &user,
                impersonation: act,
            },
            Some(&ironauth_store::DomainEvent {
                id: "evt_impersonation_authorized",
                subject: &user.to_string(),
                envelope: &envelope,
            }),
        )
        .await
        .expect("issue the authorization");

    let claimed = db
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(30),
            100,
        )
        .await
        .expect("claim webhook events");
    assert_eq!(claimed.len(), 1, "the authorization announced {claimed:?}");
    let payload = &claimed[0].payload;
    assert_eq!(payload["type"], "impersonation.authorized");
    assert_eq!(payload["payload"]["user_id"], user.to_string());
    assert_eq!(payload["payload"]["reason_code"], "support_ticket");
    assert_eq!(payload["payload"]["expires_at_unix_ms"], expires_at / 1000);
    let rendered = serde_json::to_string(payload).expect("json");
    assert!(
        !rendered.contains("Ticket 4417") && !rendered.contains("checkout"),
        "the operator's justification PROSE reached the wire: {rendered}"
    );
    ironauth_store::event_catalog::validate_event(payload)
        .expect("the envelope validates against the registry the fan-out enforces");
}

/// A REAL sign-in is metered (issue #107 criterion 4).
///
/// The existing metering test seeds the feed with `append_envelope`, which writes envelopes
/// straight to the outbox. That measures the fold's arithmetic and cannot measure whether the
/// events it folds ever exist -- and they did not: `user.signed_in` was named by a constant in
/// `UsageTally`, registered nowhere, and emitted by nothing, so metering reported zero for
/// every tenant on every deployment. The criterion says metering matches seeded ACTIVITY; the
/// old fixture seeded envelopes.
///
/// So this drives a real session through the real path and folds what the feed actually
/// contains. It is the only test that can fail if the producer is removed.
#[tokio::test]
async fn a_real_sign_in_is_metered_as_an_active_user() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "metered@example.test").await;
    let id = issue_authorization(&db, &env, scope, &user, 30 * MINUTE_MICROS).await;

    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .redeem(&env, &id, now_micros(&env))
        .await
        .expect("redeem into a session");

    // POLLED, not read once. The feed's visibility lags the commit -- `events_cursor_ordering`
    // waits the same way for the same reason -- so a single read passes on an idle machine and
    // returns an empty page under concurrent load. Reading once here made this test fail only
    // when other suites ran beside it, which is the worst way to learn about a race.
    let mut events = Vec::new();
    for _ in 0..100 {
        match db
            .store()
            .scoped(scope)
            .outbox()
            .events_page_after(ironauth_store::EventCursor::beginning(), 100)
            .await
            .expect("read the feed")
        {
            ironauth_store::EventPage::Page(page)
                if page.iter().any(|m| m.payload["type"] == "user.signed_in") =>
            {
                events = page;
                break;
            }
            ironauth_store::EventPage::Page(_) => {}
            ironauth_store::EventPage::Gone { .. } => panic!("nothing was pruned"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let signed_in: Vec<_> = events
        .iter()
        .filter(|m| m.payload["type"] == "user.signed_in")
        .collect();
    assert_eq!(
        signed_in.len(),
        1,
        "a real session creation must put exactly one sign-in on the feed, or metering \
         counts nothing: {events:?}"
    );
    assert_eq!(
        signed_in[0].payload["payload"]["subject"],
        user.to_string(),
        "the subject is what makes an active user active, and it is the only field the fold \
         reads"
    );
    ironauth_store::event_catalog::validate_event(&signed_in[0].payload)
        .expect("the sign-in validates against the registry the fan-out enforces");

    let mut tally = ironauth_store::UsageTally::new();
    tally.absorb(&events);
    assert_eq!(
        tally.monthly_active_users(),
        1,
        "one real sign-in is one active user; this is the assertion that was structurally \
         unreachable while nothing emitted the type"
    );
}

/// Neither a sign-in nor a token issuance reads the event feed (issue #107 criterion 5).
///
/// The criterion is that metering adds no work to the hot paths. Metering is a READ of the
/// feed folded into a `UsageTally`, so the assertion is that those paths never perform that
/// read -- and a number is the only way to say it. A source scan would pass the moment
/// somebody reached the fold through a helper, and a `pg_stat_*` proxy cannot separate the
/// fold's SELECT from the enqueue's own INSERT touching the same table and its unique index.
///
/// Note what this does NOT claim. Both paths now WRITE one outbox row each, because the feed
/// is the substrate metering is computed from and it only exists if activity writes to it.
/// #107 puts the fold off the hot path, not the event; this pins the fold.
///
/// The counter is process-wide, so this reads it before and after rather than expecting zero:
/// other tests in this binary fold the feed, and an absolute assertion would couple this test
/// to their scheduling.
#[tokio::test]
async fn a_sign_in_reads_the_event_feed_zero_times() {
    let db = TestDatabase::start().await;
    let env = ironauth_env::Env::system();
    let scope = db.seed_scope(&env).await;
    let user = seed_user(&db, &env, scope, "hotpath@example.test").await;
    let id = issue_authorization(&db, &env, scope, &user, 30 * MINUTE_MICROS).await;

    let before = ironauth_store::feed_reads();
    db.store()
        .scoped(scope)
        .acting(db.test_actor(&env), CorrelationId::generate(&env))
        .impersonation_authorizations()
        .redeem(&env, &id, now_micros(&env))
        .await
        .expect("redeem into a session");
    let after = ironauth_store::feed_reads();

    assert_eq!(
        after - before,
        0,
        "the sign-in path read the event feed {} time(s); metering must be folded on request, \
         never inline, or every login pays for somebody's billing report",
        after - before
    );

    // And the counter is not simply dead: folding the feed moves it, which is what makes the
    // zero above evidence rather than an assertion about a number nothing increments.
    let probe_before = ironauth_store::feed_reads();
    let _ = db
        .store()
        .scoped(scope)
        .outbox()
        .events_page_after(ironauth_store::EventCursor::beginning(), 10)
        .await
        .expect("read the feed");
    assert_eq!(
        ironauth_store::feed_reads() - probe_before,
        1,
        "a deliberate fold must move the counter, or the zero above measures nothing"
    );
}
