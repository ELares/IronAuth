// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-tenant usage export (issue #107 criterion 4).
//!
//! The store-side fold has its own seeded fixture. What this proves is the EXPORT: that the
//! endpoint folds the same feed, reports the same numbers, and is honest when it stops
//! early. An export that quietly truncated would be the one number a customer never thinks
//! to question, which is why `truncated` is a field rather than a log line.

mod common;

use axum::http::StatusCode;
use common::Harness;
use ironauth_env::Env;
use ironauth_store::{EnvironmentId, NewOutboxMessage, Scope, TenantId};
use serde_json::Value;

/// Append one metering event envelope through the commit-ordered appender.
///
/// On `WEBHOOK_EVENT_CONSUMER`, which is what the real producers use and therefore what the
/// fold's budget counts. An earlier version used a made-up consumer string, which made no
/// difference while the budget counted every row and made this whole fixture unrepresentative
/// the moment it stopped.
///
/// Each type carries the payload its registered schema requires, so these envelopes pass the
/// emit-time validation every event-feed row now goes through. `user.signed_in` needs
/// `subject`, `token.issued` needs `grant_id` and `token_kind`, `connection.opened` needs
/// `connection_id`.
async fn append(h: &Harness, env: &Env, scope: Scope, key: &str, event_type: &str, subject: &str) {
    let payload = match event_type {
        "token.issued" => serde_json::json!({ "grant_id": key, "token_kind": "access" }),
        "connection.opened" => serde_json::json!({ "connection_id": key }),
        _ => serde_json::json!({ "subject": subject }),
    };
    h.store()
        .scoped(scope)
        .outbox()
        .append_event(
            env,
            &NewOutboxMessage {
                consumer: ironauth_store::WEBHOOK_EVENT_CONSUMER,
                idempotency_key: key,
                ordering_key: "k",
                payload: serde_json::json!({
                    "id": key,
                    "type": event_type,
                    "payload_schema_version": 1,
                    "occurred_at_unix_ms": 0,
                    "tenant_id": scope.tenant().to_string(),
                    "environment_id": scope.environment().to_string(),
                    "payload": payload,
                }),
            },
        )
        .await
        .expect("append");
}

#[tokio::test]
async fn the_export_reports_distinct_actives_and_raw_issuance() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage").await;
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    // Not uniform, deliberately: alice three times and bob once. A fixture with one event
    // per user cannot tell distinct users from activity events apart.
    for (i, subject) in ["alice", "bob", "alice", "alice"].iter().enumerate() {
        append(
            &h,
            &env,
            scope,
            &format!("u_act_{i}"),
            "user.signed_in",
            subject,
        )
        .await;
    }
    for i in 0..3 {
        append(&h, &env, scope, &format!("u_tok_{i}"), "token.issued", "-").await;
    }

    let path = format!("/v1/tenants/{tenant}/environments/{environment}/usage");

    // The feed is watermarked cluster-wide, so a bounded poll is what "the events have
    // landed" honestly means here. Same reason as the store-side tests.
    let mut body = Value::Null;
    for _ in 0..100 {
        let (status, _, response) = h.get(&path).await;
        assert_eq!(status, StatusCode::OK, "usage: {response}");
        body = serde_json::from_str(&response).expect("json");
        if body["tokens_issued"] == 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(
        body["monthly_active_users"], 2,
        "alice three times and bob once is TWO active users: {body}"
    );
    assert_eq!(body["tokens_issued"], 3, "issuance counts events: {body}");
    assert_eq!(
        body["truncated"], false,
        "a short feed must not report truncation: {body}"
    );
}

#[tokio::test]
async fn an_unknown_tenant_is_not_a_zero_usage_report() {
    // A 404 rather than a plausible-looking export of zeros. An operator scripting against
    // this would read zeros as "no activity" and never learn they typed the wrong tenant,
    // which is the same silent-wrong-answer class the feed's 410 exists to avoid.
    let h = Harness::start(50).await;
    let (_tenant, environment) = h.create_tenant("acme", "k-usage-404").await;

    // A WELL-FORMED tenant id that does not exist, generated the same way a real one is.
    // A fabricated string fails at PARSING, which is a different branch: the first version
    // of this test used one, and a mutation to the existence check survived because the
    // request never reached it. The test was passing for a reason it did not control.
    let absent = TenantId::generate(&Env::system()).to_string();
    let (status, _, body) = h
        .get(&format!(
            "/v1/tenants/{absent}/environments/{environment}/usage"
        ))
        .await;

    // NOT_FOUND specifically, not merely "not OK". The spec documents 404 for this, and a
    // 500 would satisfy a not-OK assertion while telling an operator their deployment is
    // broken rather than their tenant id is wrong. A mutation swapping one for the other
    // survived until this was tightened.
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown tenant is a 404, not a fault and not a zero report: {body}"
    );
}

#[tokio::test]
async fn a_fold_that_stops_early_says_so() {
    // The `truncated` flag, exercised. A mutation that never set it SURVIVED until this
    // existed, because the fixture was seven events against a ten-thousand limit, and the
    // one field whose whole job is to admit the number is a lower bound was unverified.
    //
    // Driving `fold_usage` directly with a tiny limit reaches the path without seeding ten
    // thousand events, which is why the limit is a parameter rather than a constant.
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-trunc").await;
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    for i in 0..3 {
        append(&h, &env, scope, &format!("u_tr_{i}"), "token.issued", "-").await;
    }

    // Wait for the cluster-wide watermark to release them, then fold with a limit BELOW
    // the number of events.
    let mut truncated = false;
    let mut counted = 0;
    for _ in 0..100 {
        let scoped = h.store().scoped(scope);
        let (tally, stopped_early) = ironauth_admin::usage::fold_usage(&scoped.outbox(), 2)
            .await
            .expect("fold");
        counted = tally.tokens_issued();
        truncated = stopped_early;
        // ALL THREE, not "any". Exiting on `counted > 0` is the subset-exit shape: the
        // assertion below needs the fold to have hit its limit of 2, and it passes today
        // only because the harness's own provisioning contributes one more meterable row.
        // With a fixture that contributed none, one visible token would satisfy the exit and
        // fail the truncation assertion below.
        if counted == 3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert_eq!(
        counted, 3,
        "the three seeded events must have landed for this to mean anything"
    );
    assert!(
        truncated,
        "a fold limited to 2 over 3 events must report that it stopped early"
    );

    // And the same feed folded WITHOUT a binding limit must not claim truncation, or the
    // flag would just be always-on and equally useless.
    let scoped = h.store().scoped(scope);
    let (_, not_truncated) = ironauth_admin::usage::fold_usage(&scoped.outbox(), 10_000)
        .await
        .expect("fold");
    assert!(
        !not_truncated,
        "a fold that reached the end of the feed must not report truncation"
    );
}

/// Publishing emits a `usage.reported` event carrying the same numbers the API returns
/// (issue #107 criterion 4: metering "exports via API and webhook").
///
/// Both halves asserted together, because the value of the webhook export is that a billing
/// pipeline gets the SAME aggregate the API would have given it. If the two could disagree,
/// a customer could be invoiced from one and audited against the other.
///
/// The payload carries counts and never a list of users: metering distinguishes people, it
/// does not identify them, and a billing pipeline is the last system that should hold a
/// directory of its customer's users.
#[tokio::test]
// One linear walk: seed the feed, publish, then check EVERY link the publish claims
// (the four numbers, the millisecond timestamp, the exact payload key set, the ordering
// key). Splitting it would re-seed the same fixture several times to assert on one
// artifact, and the reason each half of this PR's review found an unmeasured field is
// that the assertions were too few, not that they were in one place.
#[allow(clippy::too_many_lines)]
async fn publishing_usage_emits_the_same_numbers_the_api_returns() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-pub").await;
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    for (i, subject) in ["alice", "bob", "alice"].iter().enumerate() {
        append(
            &h,
            &env,
            scope,
            &format!("p_act_{i}"),
            "user.signed_in",
            subject,
        )
        .await;
    }
    // FIVE, not two, and the difference is the whole power of this fixture. With two token
    // events `tokens_issued` equalled `monthly_active_users`, so SWAPPING the two fields in
    // the handler left every assertion below green -- measured, on both the response and the
    // envelope. A billing pipeline invoiced on seats would have been invoiced on issuance.
    // The rule was already written down three lines further on and broken here.
    for i in 0..5 {
        append(&h, &env, scope, &format!("p_tok_{i}"), "token.issued", "-").await;
    }
    // Connections seeded too, and seeded at a count that is neither zero nor equal to any
    // other field. Every field needs a distinct expected value: with connections left at
    // its default, a mutant that hardcoded ANY number would be caught only if the number
    // it chose happened to differ, and one that hardcoded zero would not be caught at all.
    for i in 0..3 {
        append(
            &h,
            &env,
            scope,
            &format!("p_conn_{i}"),
            "connection.opened",
            "-",
        )
        .await;
    }

    let path = format!("/v1/tenants/{tenant}/environments/{environment}/usage");
    let publish = format!("{path}/publish");

    // A DISTINCT KEY PER ITERATION, and that is the whole correctness of this loop.
    //
    // With a constant key every iteration after the first was an idempotent REPLAY of the
    // first response, so the exit condition was decided entirely by the first call: on a
    // lagging watermark the loop slept five seconds and then failed on a frozen number. It
    // was measured doing exactly that (first fold 1, replay 1, while the GET saw 4). The
    // sibling test asserts that replay behaviour deliberately, so the two tests were in
    // direct contradiction about what a second POST does.
    let mut body = Value::Null;
    for attempt in 0..100 {
        let (status, _, response) = h
            .post(&publish, &format!("k-usage-publish-{attempt}"), "")
            .await;
        assert_eq!(status, StatusCode::OK, "publish: {response}");
        body = serde_json::from_str(&response).expect("json");
        // EVERY seeded count, not the first interesting one. The fixture seeds sign-ins,
        // then tokens, then connections, and the feed is watermarked, so they become visible
        // in that order. Keying the exit on `tokens_issued` alone let the loop stop while
        // `connections` was still 0, and the assertion twenty lines below then failed on
        // connections instead: 3 failures in 10 runs at `--test-threads=4`, reporting
        // `left: 0, right: 3`. A poll loop's exit condition has to be the whole state it is
        // waiting for.
        if body["monthly_active_users"] == 2
            && body["tokens_issued"] == 5
            && body["connections"] == 3
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        body["monthly_active_users"], 2,
        "alice twice and bob once: {body}"
    );
    assert_eq!(
        body["tokens_issued"], 5,
        "five token events were seeded, and five is distinct from the other three \
         expectations: {body}"
    );
    // Pinned against the SEEDED count, not against the event that echoes it. Comparing the
    // event's `connections` to the response's `connections` alone is a guard computing its
    // own expectation: a mutant returning 999 makes both sides 999 and passes. Three is
    // what the fixture appended, and nothing in the handler can move it.
    assert_eq!(
        body["connections"], 3,
        "three connections were seeded: {body}"
    );

    // The API returns the same aggregate.
    let (status, _, api) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "export: {api}");
    let api: Value = serde_json::from_str(&api).expect("json");
    assert_eq!(api["monthly_active_users"], body["monthly_active_users"]);
    assert_eq!(api["tokens_issued"], body["tokens_issued"]);

    // And a `usage.reported` event is on the feed for a webhook subscriber to receive.
    let mut seen: Vec<Value> = Vec::new();
    for _ in 0..100 {
        let claimed = h
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
            .expect("claim");
        for m in &claimed {
            if m.payload["type"] == "usage.reported" {
                seen.push(m.payload.clone());
            }
        }
        for m in claimed {
            h.store()
                .scoped(scope)
                .outbox()
                .complete(&env, &m)
                .await
                .expect("complete");
        }
        // Wait for the event the LAST response named, not merely for any event: with a
        // distinct key per attempt there may be several on the feed, and the earliest is
        // not the one whose numbers `body` carries.
        if seen.iter().any(|event| event["id"] == body["event_id"]) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // SELECTED BY ID, not by position, and that is not a detail.
    //
    // The loop above uses a distinct key per attempt (a constant key made every attempt
    // after the first an idempotent REPLAY, which is the defect the distinct key fixed), so
    // every attempt that runs appends ANOTHER `usage.reported` event. `seen.first()` is the
    // EARLIEST of them and `body` is the LAST response, so on any run that took more than
    // one attempt the two came from different publishes and the field comparisons below
    // compared different snapshots. Measured: 3 failures in 10 runs at `--test-threads=4`,
    // reporting `left: 1, right: 2` on `tokens_issued`.
    //
    // The fix that introduced this fixed a real bug and created a smaller one, which is
    // exactly why the selector has to be the id the response already carries.
    let event_id = body["event_id"].as_str().expect("event_id");
    let reported = seen
        .iter()
        .find(|event| event["id"] == event_id)
        .unwrap_or_else(|| {
            panic!("the event named by the response must be on the feed: {seen:#?}")
        });

    // ALL FOUR fields, not the two that happened to be interesting. An earlier version of
    // this test pinned `tokens_issued` alone, and mutants that returned 999 connections or
    // fed the timestamp microseconds instead of milliseconds both survived it. "The event
    // carries the same numbers the API returns" is a claim about every number.
    assert_eq!(
        reported["payload"]["monthly_active_users"],
        body["monthly_active_users"]
    );
    assert_eq!(reported["payload"]["tokens_issued"], body["tokens_issued"]);
    assert_eq!(reported["payload"]["connections"], body["connections"]);
    assert_eq!(reported["payload"]["truncated"], body["truncated"]);
    assert_eq!(reported["payload"]["truncated"], false);

    // The ENVELOPE's scope, which is the routing key a per-scope billing feed reads and is
    // not covered by anything above: the emit-time catalog guard validates the payload
    // against its schema and says nothing about whether the envelope names the scope the
    // row was written into. Writing a constant there survived the whole suite.
    assert_eq!(
        reported["tenant_id"], tenant,
        "the envelope must name the tenant it was published for: {reported}"
    );
    assert_eq!(
        reported["environment_id"], environment,
        "and the environment, or a consumer bills the wrong one: {reported}"
    );
    assert_eq!(
        reported["id"], body["event_id"],
        "the id the caller was handed must be the id on the feed, or the two halves of one \
         publish cannot be correlated at all"
    );

    // THE AUDIT ROW. `publish_snapshot` rides `write_audited` precisely so the append and
    // its audit row commit together, and until this assertion existed the action could be
    // any variant in the enum and every suite stayed green. `usage.publish` is the string
    // an operator greps for after a disputed invoice.
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE tenant_id = $1 AND environment_id = $2 \
         AND action = 'usage.publish'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_all(h.db().owner_pool())
    .await
    .expect("read the audit rows");
    assert!(
        !actions.is_empty(),
        "a successful publish must write a usage.publish audit row"
    );

    // The TARGET too, not only the action. Round 3 asserted the action and stopped there,
    // and pointing the row at another target survived every suite: an audit row that names
    // the right verb against the wrong object is not evidence of anything.
    let targets: Vec<(String, String)> = sqlx::query_as(
        "SELECT target_kind, target_id FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'usage.publish'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_all(h.db().owner_pool())
    .await
    .expect("read the audit targets");
    assert!(
        targets
            .iter()
            .all(|(kind, id)| kind == "usage" && id == "usage"),
        "a usage.publish row must target the scope-level usage handle: {targets:?}"
    );

    // The envelope timestamp is MILLISECONDS. Feeding it microseconds is a thousandfold
    // error that every equality assertion above would still pass, and it would land in a
    // billing record as a date roughly fifty thousand years out.
    let occurred = reported["occurred_at_unix_ms"]
        .as_i64()
        .expect("occurred_at_unix_ms is a number");
    // Read through the env clock seam rather than the process clock: the seam exists so a
    // test reads the same clock the code under test writes from, and `invariant-lints`
    // enforces that it is the only source.
    let now_ms = i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("fits");
    assert!(
        (now_ms - occurred).abs() < 600_000,
        "occurred_at_unix_ms must be milliseconds and roughly now: got {occurred}, now {now_ms}"
    );

    // The payload carries EXACTLY the four registered keys. The previous form of this
    // assertion named two keys the producer could never emit (`users`, `subjects`), so it
    // had no power at all: adding `active_subject_ids` to the payload left it green. An
    // exact key set is the only shape that catches a field nobody thought to forbid.
    let keys: std::collections::BTreeSet<&str> = reported["payload"]
        .as_object()
        .expect("payload is an object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: std::collections::BTreeSet<&str> = [
        "connections",
        "monthly_active_users",
        "tokens_issued",
        "truncated",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        keys, expected,
        "the snapshot must carry counts and nothing else, never a directory of users: \
         {reported}"
    );

    // The ordering key is the SCOPE. Two snapshots of one environment have to reach a
    // billing consumer in the order they were taken; keying on the event id instead would
    // put every snapshot in its own ordering group, where nothing orders them at all.
    let claimed_key = h
        .store()
        .scoped(scope)
        .outbox()
        .claim(
            &env,
            ironauth_store::WEBHOOK_EVENT_CONSUMER,
            std::time::Duration::from_secs(1),
            100,
        )
        .await
        .expect("claim");
    let _ = claimed_key;
    let ordering: Option<String> = sqlx::query_scalar(
        "SELECT ordering_key FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = 'usage.reported' \
         LIMIT 1",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_optional(h.db().owner_pool())
    .await
    .expect("read the ordering key");
    assert_eq!(
        ordering.as_deref(),
        Some(format!("{tenant}/{environment}").as_str()),
        "the ordering key must be the scope, so two snapshots stay in the order taken"
    );
}

/// One credential's Idempotency-Key does not replay for ANOTHER credential (issue #107).
///
/// The stored key is scoped by `credential_ref`, and replacing that with a per-scope
/// constant survived the suite: the fingerprint still binds the method and path, so
/// cross-TENANT replay stayed blocked and nothing noticed that two credentials inside one
/// environment had been merged into one replay namespace.
///
/// What that costs is a publish that silently does not happen. A scheduler and an operator
/// both publishing under a fixed key such as `daily` would have the second call replay the
/// first's response: a 200 carrying the FIRST snapshot's numbers, with no second event on
/// the feed and nothing to indicate the snapshot was never taken.
#[tokio::test]
async fn one_credentials_idempotency_key_does_not_replay_for_another() {
    // Same key, same path, same (empty) body for both credentials, so the request
    // fingerprint is identical and the credential is the only thing separating them.
    const SHARED_KEY: &str = "daily";

    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-cred").await;
    let publish = format!("/v1/tenants/{tenant}/environments/{environment}/usage/publish");

    // Two credentials in ONE environment.
    let (_, first_secret) = mint_key(&h, &tenant, &environment, "k-cred-a").await;
    let (_, second_secret) = mint_key(&h, &tenant, &environment, "k-cred-b").await;

    let (status, _, first) = h.post_as(&publish, &first_secret, SHARED_KEY, "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the first credential publishes: {first}"
    );
    let first: Value = serde_json::from_str(&first).expect("json");

    // The same credential replaying is the CONTROL: without it, a second distinct response
    // below could mean the endpoint simply never replays anything.
    let (status, _, replay) = h.post_as(&publish, &first_secret, SHARED_KEY, "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the same credential replays: {replay}"
    );
    let replay: Value = serde_json::from_str(&replay).expect("json");
    assert_eq!(
        replay["event_id"], first["event_id"],
        "the same credential under the same key must replay the SAME event"
    );

    let (status, _, second) = h.post_as(&publish, &second_secret, SHARED_KEY, "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the other credential must publish rather than replay: {second}"
    );
    let second: Value = serde_json::from_str(&second).expect("json");
    assert_ne!(
        second["event_id"], first["event_id"],
        "a second credential's publish under the same key must be its OWN snapshot, or one \
         caller's key silently suppresses another's publish"
    );

    // And BOTH events are on the feed, which is the fact a billing pipeline depends on.
    let published: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = 'usage.reported'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count");
    assert_eq!(
        published, 2,
        "two credentials, two publishes, two events; the replay in between adds none"
    );
}

/// A TRUNCATED publish says so, in the 200 body AND in the event on the feed (issue #107).
///
/// # Why this test had to be built rather than asserted
///
/// `truncated` is the field this endpoint's own doc calls "the one number a customer would
/// never think to question", and on the publish path it was unmeasured in the strictest
/// sense: hardcoding it to `false` in the published event left every suite green. The two
/// assertions that existed were `event.truncated == body.truncated` and `== false`, which is
/// a guard comparing two copies of one value plus a pin to what the mutant already produces.
///
/// The reason was structural, not an oversight anyone could see: reaching the shipped bound
/// means ten thousand meterable events, so the truncation path was not reachable from a
/// fixture at all. `AdminState::with_usage_fold_limit` lowers the bound instead, which
/// reaches the same branch on the same code the shipped bound reaches.
///
/// The control is a SECOND harness on the shipped bound, not a second assertion on this one:
/// with both states publishing the same fixture, the flag is the only thing that differs, so
/// a constant on either side fails here whichever constant it is.
#[tokio::test]
async fn a_truncated_publish_says_so_in_the_response_and_in_the_event() {
    let env = Env::system();

    // The bounded state: any feed carrying a single meterable event crosses the bound.
    let truncating = Harness::start_with_usage_fold_limit(50, 1).await;
    // And the control, on the shipped bound, seeded identically.
    let exact = Harness::start(50).await;

    let mut outcomes = Vec::new();
    for (h, label) in [(&truncating, "bounded at 1"), (&exact, "the shipped bound")] {
        let (tenant, environment) = h.create_tenant("acme", &format!("k-trunc-{label}")).await;
        let scope = Scope::new(
            TenantId::parse(&tenant).expect("tenant id"),
            EnvironmentId::parse(&environment).expect("environment id"),
        );
        for i in 0..3 {
            append(h, &env, scope, &format!("t_tok_{i}"), "token.issued", "-").await;
        }

        // WAIT FOR THE FEED before publishing, or the bound has nothing to stop at.
        //
        // The feed is watermarked, so a publish taken immediately after seeding folds an
        // EMPTY first page and returns `truncated: false` however low the bound is. That is
        // not a flaky assertion, it is the assertion measuring a feed that is not there yet,
        // and it failed 3 times in 10 at `--test-threads=4`. Polled directly with generous
        // bounds, so the wait is independent of the bound under test.
        let outbox = h.store().scoped(scope);
        let outbox = outbox.outbox();
        let mut caught_up = false;
        for _ in 0..100 {
            let (tally, _) =
                ironauth_admin::usage::fold_usage_bounded(&outbox, 1_000_000, 1_000_000)
                    .await
                    .expect("fold");
            if tally.tokens_issued() == 3 {
                caught_up = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            caught_up,
            "{label}: the fold's view never caught up with the three seeded events, so the \
             bound below would be measured against a feed the fold cannot see"
        );

        let publish = format!("/v1/tenants/{tenant}/environments/{environment}/usage/publish");
        let (status, _, response) = h.post(&publish, "k-trunc-publish", "").await;
        assert_eq!(status, StatusCode::OK, "{label}: {response}");
        let body: Value = serde_json::from_str(&response).expect("json");

        // The flag as the FEED carries it, which is the copy a billing pipeline reads. The
        // response is what the caller sees; only one of the two reaches the subscriber.
        let mut published = None;
        for _ in 0..100 {
            let claimed = h
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
                .expect("claim");
            for m in &claimed {
                if m.payload["type"] == "usage.reported" {
                    published = Some(m.payload.clone());
                }
            }
            for m in claimed {
                h.store()
                    .scoped(scope)
                    .outbox()
                    .complete(&env, &m)
                    .await
                    .expect("complete");
            }
            if published.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let published = published.expect("a usage.reported event reaches the feed");
        assert_eq!(
            published["payload"]["truncated"], body["truncated"],
            "{label}: the event and the response must agree: {published}"
        );

        // AND THE GET, which had the seam and none of the measurement. `export_usage` reads
        // the same `usage_fold_limit()` override, and hardcoding `truncated: false` in the
        // response it returns survived every suite: the only assertion on it pinned `false`,
        // which is what that mutant already produces. The publish path was measured last
        // round and the export path one function above it was not.
        let (status, _, exported) = h
            .get(&format!(
                "/v1/tenants/{tenant}/environments/{environment}/usage"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{label}: {exported}");
        let exported: Value = serde_json::from_str(&exported).expect("json");
        assert_eq!(
            exported["truncated"], body["truncated"],
            "{label}: the GET and the POST fold the same feed under the same bound, so they \
             must report the same truncation: {exported}"
        );

        outcomes.push((label, body["truncated"].clone()));
    }

    assert_eq!(
        outcomes[0].1,
        Value::Bool(true),
        "a fold that stopped at its bound must publish truncated: true, or a billing \
         pipeline books a lower bound as an exact figure: {outcomes:?}"
    );
    assert_eq!(
        outcomes[1].1,
        Value::Bool(false),
        "and the same fixture under the shipped bound must publish truncated: false, or \
         the assertion above is satisfied by a constant: {outcomes:?}"
    );
}

/// Restrict a management credential to exactly `slugs`.
async fn restrict(h: &Harness, tenant: &str, environment: &str, key_id: &str, slugs: &[&str]) {
    sqlx::query(
        "UPDATE management_credentials SET permissions = $1 \
         WHERE id = $2 AND tenant_id = $3 AND environment_id = $4",
    )
    .bind(
        slugs
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<String>>(),
    )
    .bind(key_id)
    .bind(tenant)
    .bind(environment)
    .execute(h.db().owner_pool())
    .await
    .expect("write the grant");
}

/// Mint a management key and return `(id, secret)`.
async fn mint_key(h: &Harness, tenant: &str, environment: &str, idem: &str) -> (String, String) {
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/keys"),
            idem,
            &serde_json::json!({ "display_name": "metering" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "mint management key: {body}");
    let created: Value = serde_json::from_str(&body).expect("json");
    (
        created["id"].as_str().expect("id").to_owned(),
        created["secret"].as_str().expect("secret").to_owned(),
    )
}

/// Publishing is `management.write_config`, PROVEN rather than declared (issue #107).
///
/// Both halves, because each alone is worthless: asserting only the refusal would also pass
/// against an endpoint that refused everyone, and asserting only the allow would pass
/// against one that refused no one. Deleting the `require_permission` line left the suite
/// green before this test existed, which is exactly what it means for an authorization
/// argument to be unmeasured.
///
/// `management.read` is the DIFFERENT permission deliberately: it is the one the export
/// half of this same file needs, so it is the permission a caller would most plausibly
/// already hold, and the one whose leaking into the write half would matter most.
#[tokio::test]
async fn write_config_is_required_and_sufficient_for_publishing() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-perm").await;
    let (key_id, secret) = mint_key(&h, &tenant, &environment, "ak-usage").await;
    let publish = format!("/v1/tenants/{tenant}/environments/{environment}/usage/publish");

    restrict(&h, &tenant, &environment, &key_id, &["management.read"]).await;
    let (status, _, body) = h.post_as(&publish, &secret, "k-perm-read", "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a read credential must not be able to make every subscriber receive a billing \
         record: {body}"
    );

    restrict(
        &h,
        &tenant,
        &environment,
        &key_id,
        &["management.write_config"],
    )
    .await;
    let (status, _, body) = h.post_as(&publish, &secret, "k-perm-write", "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a write_config credential must be allowed to publish: {body}"
    );
}

/// A soft-deleted environment accepts no publish (issues #411, #443, #451).
///
/// The READ half of this file must keep working for a deleted environment, because usage is
/// exactly what an operator needs during offboarding. So `resolve_scope` resolves a
/// soft-deleted environment on purpose, and the WRITE half needs its own refusal on top.
/// Without it, a deleted environment could still make every webhook subscriber receive a
/// billing record, which is the sweep `live_surface.rs` exists to prevent.
#[tokio::test]
async fn publishing_into_a_soft_deleted_environment_is_refused() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-del").await;
    let publish = format!("/v1/tenants/{tenant}/environments/{environment}/usage/publish");

    // The control. Without it a later refusal proves nothing: the route could be refusing
    // for a reason that has nothing to do with the deletion.
    let (status, _, body) = h.post(&publish, "k-del-before", "").await;
    assert_eq!(status, StatusCode::OK, "publish before deletion: {body}");

    let (status, _, body) = h
        .delete(&format!("/v1/tenants/{tenant}/environments/{environment}"))
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "soft-delete the environment: {body}"
    );

    let (status, _, body) = h.post(&publish, "k-del-after", "").await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a soft-deleted environment must not publish a billing record: {body}"
    );

    // And nothing was appended by the refused call. A refusal that still wrote the event
    // would be the worst of both.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = 'usage.reported'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count");
    // Nor an audit row. `publish_snapshot` writes the append and the audit row in ONE
    // transaction, so a refusal that reached the store at all would leave both; a refusal
    // that never reaches it leaves neither. One row, from the control publish above.
    let audited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log \
         WHERE tenant_id = $1 AND environment_id = $2 AND action = 'usage.publish'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count audit rows");
    assert_eq!(
        audited, 1,
        "the refused publish must write no audit row: only the control's remains"
    );
    assert_eq!(
        count, 1,
        "only the pre-deletion publish may have appended an event"
    );
}

/// A publish is idempotent, so a retry does not bill twice (issue #105's discipline
/// applied to #107).
///
/// The three properties that make the claim mean something, each of which failed before:
///
/// 1. the header is REQUIRED, so a caller cannot opt out of the protection by omission;
/// 2. the SAME key replays the first response and appends nothing further;
/// 3. the same key against a DIFFERENT path is a conflict, not a replay of another
///    environment's figures.
///
/// The event's own `idempotency_key` is a freshly minted id per call, so it collides with
/// nothing and dedupes nothing. It is the queue's uniqueness, not the caller's. The retry
/// that actually happens is an HTTP one, and only this header stops it.
#[tokio::test]
async fn a_retried_publish_replays_instead_of_billing_twice() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-idem").await;
    let (other_tenant, other_environment) = h.create_tenant("beta", "k-usage-idem2").await;
    let publish = format!("/v1/tenants/{tenant}/environments/{environment}/usage/publish");

    // 1. REQUIRED. `post_empty` sends no Idempotency-Key at all.
    let (status, _, body) = h.post_empty(&publish).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a publish with no Idempotency-Key must be refused, not silently accepted: {body}"
    );

    // 2. The same key twice: one event, and the second response is the first one.
    let (status, _, first) = h.post(&publish, "k-idem-same", "").await;
    assert_eq!(status, StatusCode::OK, "first publish: {first}");
    let (status, _, second) = h.post(&publish, "k-idem-same", "").await;
    assert_eq!(status, StatusCode::OK, "replayed publish: {second}");
    assert_eq!(first, second, "the retry must replay the stored response");

    let first_json: Value = serde_json::from_str(&first).expect("json");
    assert!(
        first_json["event_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("evt_")),
        "the response names the event it caused, so a caller can correlate its POST with \
         the delivery: {first}"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = 'usage.reported'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count");
    assert_eq!(
        count, 1,
        "two POSTs under one key must append ONE event, not two invoice lines"
    );

    // A DIFFERENT key does publish again: without this the test would also pass against an
    // endpoint that had simply stopped appending after the first call.
    let (status, _, body) = h.post(&publish, "k-idem-other", "").await;
    assert_eq!(status, StatusCode::OK, "a fresh key publishes: {body}");
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = 'usage.reported'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count");
    assert_eq!(count, 2, "a distinct key is a distinct snapshot");

    // 3. The same key against a different PATH is a conflict. The fingerprint binds the key
    // to the route, so a key reused across environments cannot replay the wrong figures.
    let elsewhere =
        format!("/v1/tenants/{other_tenant}/environments/{other_environment}/usage/publish");
    let (status, _, body) = h.post(&elsewhere, "k-idem-same", "").await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a key reused for a different request must conflict, never replay: {body}"
    );
}

/// Publishing does not meter itself into truncation (issue #107).
///
/// `publish_usage` appends to the SAME per-scope feed the export folds, and
/// `events_page_after` filters on scope and sequence only, so those rows come back to the
/// fold. Counting them would close a loop with the wrong sign: every publish would bring the
/// next export one row closer to its limit, and passing the limit sets `truncated`, which
/// means the numbers are a LOWER BOUND. An operator who reported diligently would under-bill
/// BECAUSE they reported.
///
/// Measured at the boundary rather than described: with the limit set to the number of
/// meterable events, adding self-published rows on top must not flip the flag.
#[tokio::test]
async fn a_published_snapshot_does_not_consume_the_export_budget() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-budget").await;
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    // A REGISTERED SUBSCRIBER, which is the whole point of the fixture and was missing.
    //
    // Without one, a publish appends a single `usage.reported` event and nothing else, so a
    // type-keyed exclusion looked sufficient and this test passed while the loop it is named
    // for was still open. With a subscriber, each published event ALSO produces a delivery
    // row per endpoint once the fan-out runs, and a delivery row is not an envelope: it has
    // no top-level `type` for an exclusion to match. Registering an endpoint is registering
    // the only configuration in which the feature does anything.
    let (status, _, body) = h
        .post(
            &format!("/v1/tenants/{tenant}/environments/{environment}/webhook-endpoints"),
            "k-budget-endpoint",
            &serde_json::json!({ "url": "https://example.test/hook" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "register a subscriber: {body}");

    for i in 0..4 {
        append(&h, &env, scope, &format!("b_tok_{i}"), "token.issued", "-").await;
    }

    let publish = format!("/v1/tenants/{tenant}/environments/{environment}/usage/publish");
    for i in 0..3 {
        let (status, _, body) = h.post(&publish, &format!("k-budget-{i}"), "").await;
        assert_eq!(status, StatusCode::OK, "publish {i}: {body}");
    }

    // Run the REAL fan-out over every queued event, so the delivery rows this test exists to
    // account for actually exist. Claiming and completing rather than peeking: a claimed but
    // open message blocks its ordering key, and the fold has to see a settled feed.
    {
        use ironauth_admin::events::WebhookFanoutConsumer;
        use ironauth_store::outbox::OutboxConsumer;
        let store = h.store().clone();
        let fanout = WebhookFanoutConsumer::new(store.clone());
        loop {
            let claimed = store
                .scoped(scope)
                .outbox()
                .claim(
                    &env,
                    ironauth_store::WEBHOOK_EVENT_CONSUMER,
                    std::time::Duration::from_secs(30),
                    100,
                )
                .await
                .expect("claim the queued events");
            if claimed.is_empty() {
                break;
            }
            for message in claimed {
                fanout
                    .handle(&env, scope, &message)
                    .await
                    .expect("the fan-out runs");
                store
                    .scoped(scope)
                    .outbox()
                    .complete(&env, &message)
                    .await
                    .expect("complete");
            }
        }
    }

    // The limit is DERIVED, not written down. The fixture's own provisioning puts events
    // on this feed too, so a hardcoded number would silently stop discriminating the day
    // that count changed. Read both totals and pick the one limit that separates the two
    // counting rules.
    // WAIT FOR THE FOLD'S VIEW TO CATCH UP before deriving anything from a direct count.
    //
    // `feed_counts` reads `outbox_messages` straight, while `fold_usage` reads through
    // `events_page_after`, which applies the cluster-wide watermark. Under concurrent load
    // from the other tests in this binary the two disagree for a moment, and a limit derived
    // from the direct count is then above what the fold can reach. That is how this test
    // came to pass alone and fail in the suite, which is the worst way to learn about a race.
    let mut caught_up = false;
    for _ in 0..100 {
        let (tally, _) =
            ironauth_admin::usage::fold_usage(&h.store().scoped(scope).outbox(), 1_000)
                .await
                .expect("fold");
        if tally.tokens_issued() == 4 {
            caught_up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // The loop's OWN exit condition, asserted where it is decided. Its two siblings in this
    // file assert theirs; this one did not, so when the watermark stayed behind for the full
    // five seconds the failure surfaced twenty lines below as "the numbers are unaffected:
    // left 0, right 4", which names the wrong thing and sends a reader to the wrong code.
    assert!(
        caught_up,
        "the fold's view never caught up with the seeded events; everything derived below \
         would be derived from a feed the fold cannot see yet"
    );

    let (total, meterable) = feed_counts(&h, &tenant, &environment).await;
    assert!(
        total > meterable + 3,
        "the publishes and their deliveries must be on the feed and OUTSIDE the meterable \
         set: total {total}, meterable {meterable}"
    );
    let limit = meterable + 1;

    // At this limit the two rules disagree BY CONSTRUCTION: counting every row the fold
    // READS reaches `total`, which is >= limit, and truncates; counting only the meterable
    // ones reaches `meterable`, which is < limit, and does not. Any limit outside this seam
    // would pass whichever rule were in force, which is what made the first version of this
    // test measure nothing -- and the second version's seam was still wrong, because it
    // subtracted only the `usage.reported` rows and left the delivery rows inside.
    let (tally, truncated) =
        ironauth_admin::usage::fold_usage(&h.store().scoped(scope).outbox(), limit)
            .await
            .expect("fold");
    assert_eq!(tally.tokens_issued(), 4, "the numbers are unaffected");
    assert!(
        !truncated,
        "publishing must not push a {meterable}-event feed into truncation at limit \
         {limit} (the feed holds {total} rows in total, the rest being the publishes and \
         their deliveries)"
    );

    // The positive control: a limit BELOW the meterable count truncates as it always did.
    // Without it, a `truncated` hardwired to false would pass the assertion above and this
    // whole test would measure nothing.
    let (_, truncated) =
        ironauth_admin::usage::fold_usage(&h.store().scoped(scope).outbox(), meterable - 1)
            .await
            .expect("fold");
    assert!(
        truncated,
        "a limit below the meterable count must still truncate"
    );
}

/// `(every row the fold READS, the meterable ones among them)`.
///
/// The first number is every `outbox_messages` row in the scope, because `events_after`
/// filters on tenant, environment and sequence only and so reads all of them. The second is
/// the subset the BUDGET counts: event-feed rows that are not this endpoint's own output.
/// The gap between the two is exactly what a publish adds -- one event AND one delivery row
/// per subscriber -- and the test's derived limit sits inside that gap.
async fn feed_counts(h: &Harness, tenant: &str, environment: &str) -> (i64, i64) {
    let row: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), \
                COUNT(*) FILTER ( \
                    WHERE consumer = $3 \
                      AND payload->>'type' IS DISTINCT FROM 'usage.reported') \
         FROM outbox_messages WHERE tenant_id = $1 AND environment_id = $2",
    )
    .bind(tenant)
    .bind(environment)
    .bind(ironauth_store::WEBHOOK_EVENT_CONSUMER)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count the feed");
    row
}

/// A CONCURRENT retry replays rather than failing (issue #105's discipline applied to #107).
///
/// The sequential retry is covered above. This is the case the conflict arm exists for, and
/// that arm was dead code: it matched `StoreError::Conflict`, the DOMAIN uniqueness error,
/// while `insert_idempotency` raises `StoreError::IdempotencyConflict`. So the replay could
/// never happen and the loser of the race fell through to a 500 -- measured five times out
/// of five -- for a request whose twin had succeeded, with no way to tell whether the
/// snapshot was published. A scheduler retrying on 500 would then publish again under a new
/// key and bill twice, which is the exact outcome the header exists to prevent.
///
/// Both halves are asserted. Two 200s with IDENTICAL bodies, because a race that returned
/// two different snapshots would be two readings presented as one; and exactly ONE event,
/// because that is what "replayed rather than repeated" means.
#[tokio::test]
async fn two_publishes_racing_under_one_key_both_replay_the_same_response() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-race").await;
    let publish = format!("/v1/tenants/{tenant}/environments/{environment}/usage/publish");

    let (first, second) = tokio::join!(
        h.post(&publish, "k-race", ""),
        h.post(&publish, "k-race", "")
    );

    assert_eq!(
        (first.0, second.0),
        (StatusCode::OK, StatusCode::OK),
        "neither racer may see a 500: {} / {}",
        first.2,
        second.2
    );
    assert_eq!(
        first.2, second.2,
        "the loser must replay the winner's response, byte for byte"
    );

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM outbox_messages \
         WHERE tenant_id = $1 AND environment_id = $2 AND payload->>'type' = 'usage.reported'",
    )
    .bind(&tenant)
    .bind(&environment)
    .fetch_one(h.db().owner_pool())
    .await
    .expect("count");
    assert_eq!(count, 1, "one key, one event, however many racers");
}

/// The SCAN bound stops a fold whose feed is mostly unmeterable (issue #107).
///
/// `EXPORT_FOLD_LIMIT` bounds meterable events; without a second bound, excluding rows from
/// that count would turn "stop after 10,000" into "keep reading until 10,000 meterable ones
/// turn up", which on a feed dominated by delivery rows is not a bound at all.
///
/// Driven through the parameterised entry point for the same reason `limit` is: reaching the
/// shipped 100,000 from a test would mean seeding a hundred thousand rows, so the bound went
/// untested and deleting it entirely survived the suite.
#[tokio::test]
async fn a_fold_whose_feed_is_mostly_unmeterable_stops_at_the_scan_bound() {
    let h = Harness::start(50).await;
    let (tenant, environment) = h.create_tenant("acme", "k-usage-scan").await;
    let env = Env::system();
    let scope = Scope::new(
        TenantId::parse(&tenant).expect("tenant id"),
        EnvironmentId::parse(&environment).expect("environment id"),
    );

    for i in 0..4 {
        append(&h, &env, scope, &format!("s_tok_{i}"), "token.issued", "-").await;
    }

    let outbox = h.store().scoped(scope);
    let outbox = outbox.outbox();

    // WAIT FOR THE FOLD'S VIEW, and assert that it caught up.
    //
    // The feed is gated on `pg_snapshot_xmin`, so a concurrent test's open transaction holds
    // rows back and the first page comes back EMPTY. `fold_usage_bounded` then returns at
    // the `events.is_empty()` arm with `truncated: false`, and this test failed 4 times in
    // 10 under `--test-threads=4` for exactly that reason. Its sibling
    // `a_published_snapshot_does_not_consume_the_export_budget` has this loop; this one had
    // no loop at all.
    let mut caught_up = false;
    for _ in 0..100 {
        let (tally, _) = ironauth_admin::usage::fold_usage_bounded(&outbox, 1_000, 1_000)
            .await
            .expect("fold");
        if tally.tokens_issued() == 4 {
            caught_up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        caught_up,
        "the fold's view never caught up with the four seeded events, so the scan bound \
         below would be measured against a feed the fold cannot see"
    );

    // A meterable limit far above what the feed holds, so ONLY the scan bound can fire.
    let (tally, truncated) = ironauth_admin::usage::fold_usage_bounded(&outbox, 1_000, 2)
        .await
        .expect("fold");
    assert!(
        truncated,
        "a scan bound below the row count must report a lower bound"
    );
    // ...and the numbers are still whatever it managed to read, never zero: a bound that
    // discarded the partial tally would turn a large tenant's invoice into nothing.
    assert!(
        tally.tokens_issued() > 0,
        "the partial tally survives the bound"
    );

    // The control: with both bounds above the feed, nothing truncates.
    let (_, truncated) = ironauth_admin::usage::fold_usage_bounded(&outbox, 1_000, 1_000)
        .await
        .expect("fold");
    assert!(
        !truncated,
        "with both bounds above the feed, the fold reaches the end"
    );
}
