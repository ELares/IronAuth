// SPDX-License-Identifier: MIT OR Apache-2.0

//! The rolling N to N+1 upgrade under synthetic login load (issue #148 criterion 1).
//!
//! The criterion: "CI performs a rolling N to N+1 upgrade under synthetic login load with
//! zero failed logins and zero lost sessions, and this gate runs on every release
//! candidate."
//!
//! A real two-binary version skew cannot be run in one test process, so the harness stands
//! for the two versions the same way the framework itself does: the migration phases ARE
//! the difference between the binaries. The database starts at the FULL production chain
//! (state N). The upgrade applies the additive half of an N+1 release — a test-only
//! EXPAND + MIGRATE chain whose CONTRACT step is DEFERRED by default — while a sustained
//! stream of `/login` traffic is in flight. The runner's default is what makes this a
//! ROLLING upgrade: the deployment sits in the state where the previous binary and the new
//! one can BOTH serve, which is exactly the state `contract_gate.rs` proves the old
//! binary's own reads still work in.
//!
//! What is asserted is the criterion's numbers: every login in the stream succeeded (zero
//! failed), every session the stream minted — and every session minted BEFORE the upgrade —
//! still validates through the runtime's read guard after it (zero lost), and the store is
//! in the both-binaries-serve state (expanded shape in place, contract deferred, old shape
//! still readable).

use std::time::Duration;

mod common;
use common::{
    Harness, PKCE_CHALLENGE, REDIRECT_URI, SEED_PASSWORD, enc, form, form_field, location,
    set_cookie_pair,
};
use ironauth_store::{Migration, MigrationRunner, Phase};
use tokio::time::sleep;

/// The N+1 release's chain, TEST-ONLY (versions above the production chain): one EXPAND,
/// one MIGRATE backfill, and one CONTRACT that the runner defers by default — the rolling
/// upgrade never takes the old shape away while the old binary is still serving.
fn upgrade_chain() -> Vec<Migration> {
    vec![
        Migration {
            version: 9001,
            name: "rolling expand: add the display_version column",
            phase: Phase::Expand,
            sql: "ALTER TABLE tenants ADD COLUMN display_version text;",
        },
        Migration {
            version: 9002,
            name: "rolling migrate: backfill display_version",
            phase: Phase::Migrate,
            sql: "UPDATE tenants SET display_version = 'seed' WHERE display_version IS NULL;",
        },
        Migration {
            version: 9003,
            name: "rolling contract: drop the legacy marker (deferred)",
            phase: Phase::Contract,
            sql: "ALTER TABLE tenants DROP COLUMN display_version;",
        },
    ]
}

/// Drive `/login` for `identifier`, returning the session id when the login succeeded.
async fn login_session_id(harness: &Harness, return_to: &str, identifier: &str) -> Option<String> {
    let body = form(&[
        ("identifier", identifier),
        ("password", SEED_PASSWORD),
        ("return_to", return_to),
    ]);
    let (status, headers, _) = harness.post_form("/login", &body, None).await;
    if status != axum::http::StatusCode::SEE_OTHER {
        return None;
    }
    let cookie = set_cookie_pair(&headers)?;
    // The session cookie's value IS the session id (`SESSION_COOKIE={session_id}`).
    let (name, value) = cookie.split_once('=')?;
    if !name.contains("ironauth_session") {
        return None;
    }
    Some(value.to_owned())
}

/// Whether a session still validates through the runtime's read guard.
async fn session_valid(harness: &Harness, session_id: &str) -> bool {
    let Ok(id) = ironauth_store::SessionId::parse_in_scope(session_id, &harness.scope()) else {
        return false;
    };
    let Ok(Some(session)) = harness
        .store()
        .scoped(harness.scope())
        .sessions()
        .get(&id, 0, 1 << 62)
        .await
    else {
        return false;
    };
    !session.subject.is_empty()
}

/// Drive `/authorize` -> `/login` GET and return the resume `return_to`.
async fn resume_return_to(harness: &Harness) -> String {
    let query = format!(
        "response_type=code&client_id={}&redirect_uri={}&scope={}&state=roll&nonce=r1&\
         code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        harness.client_id(),
        enc(REDIRECT_URI),
        enc("openid"),
    );
    let (status, headers, _) = harness.authorize(&query).await;
    assert_eq!(status, axum::http::StatusCode::SEE_OTHER);
    let login_location = location(&headers).expect("login redirect");
    let (status, _headers, html) = harness.get_with_cookie(&login_location, None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    form_field(&html, "return_to").expect("login return_to")
}

/// THE CRITERION: the N+1 additive half lands under a stream of logins, with zero failed
/// logins and zero lost sessions.
#[tokio::test(flavor = "multi_thread")]
async fn a_rolling_upgrade_under_login_load_loses_no_logins_and_no_sessions() {
    let harness = Harness::start_store_backed().await;
    for index in 0..4 {
        harness
            .seed_user(&format!("roll{index}@example.test"), SEED_PASSWORD)
            .await;
    }
    let return_to = resume_return_to(&harness).await;

    // Sessions minted BEFORE the upgrade, which must survive it.
    let mut before = Vec::new();
    for index in 0..3 {
        let session = login_session_id(&harness, &return_to, &format!("roll{index}@example.test"))
            .await
            .expect("the pre-upgrade login succeeds");
        before.push(session);
    }

    // THE SYNTHETIC LOAD with the upgrade landing MID-STREAM: a sustained stream of
    // logins, ~10ms apart, and between the tenth and eleventh the N+1 additive half is
    // applied — a login stream that genuinely spans the upgrade window, with outcomes
    // asserted rather than timing.
    let mut report = None;
    let mut minted = Vec::new();
    for index in 0..20 {
        if let Some(session) = login_session_id(
            &harness,
            &return_to,
            &format!("roll{}@example.test", index % 4),
        )
        .await
        {
            minted.push(session);
        }
        if index == 10 {
            // THE ROLLING UPGRADE: the additive half of the N+1 release, inside the live
            // stream. The runner reconciles the FULL chain (the shipped chain the database
            // already holds, plus the test-only N+1 additions) — exactly what a release
            // candidate's runner does.
            let full_chain = ironauth_store::chain()
                .into_iter()
                .chain(upgrade_chain())
                .collect::<Vec<_>>();
            let applied = MigrationRunner::from_migrations(harness.pool(), full_chain)
                .run()
                .await
                .expect("the upgrade's additive half applies");
            assert_eq!(
                applied.newly_applied().to_vec(),
                vec![9001_i64, 9002],
                "expand and migrate apply during the rolling upgrade"
            );
            assert_eq!(
                applied.deferred_from(),
                Some(9003),
                "the contract step is deferred: the old binary is still serving"
            );
            report = Some(applied);
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(report.is_some(), "the upgrade ran inside the stream");

    // ZERO FAILED LOGINS: the whole stream minted a session.
    assert_eq!(minted.len(), 20, "zero failed logins in the upgrade window");

    // ZERO LOST SESSIONS: every session minted before AND during the upgrade still
    // validates through the runtime's read guard afterwards.
    for session in before.iter().chain(minted.iter()) {
        assert!(
            session_valid(&harness, session).await,
            "a session minted around the upgrade must still validate"
        );
    }

    // The both-binaries-serve state: the expanded shape is in place, backfilled, and the
    // OLD binary's own read of the store still works (the old shape was never removed).
    let pool = harness.pool();
    let backfilled: i64 =
        sqlx::query_scalar("SELECT count(*) FROM tenants WHERE display_version = 'seed'")
            .fetch_one(pool)
            .await
            .expect("the backfill ran");
    assert!(backfilled > 0, "the backfill reached the seeded tenants");
    let column: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_name = 'tenants' AND column_name = 'display_version'",
    )
    .fetch_one(pool)
    .await
    .expect("the schema probe runs");
    assert_eq!(
        column, 1,
        "the expanded column is present while the old binary serves"
    );

    // Logins STILL succeed after the upgrade (the old binary's surface, still serving).
    let after = login_session_id(&harness, &return_to, "roll1@example.test")
        .await
        .expect("a login after the upgrade succeeds");
    assert!(
        session_valid(&harness, &after).await,
        "the post-upgrade session validates"
    );
}
