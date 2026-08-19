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
        if counted > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(
        counted > 0,
        "the events must have landed for this to mean anything"
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
    for i in 0..2 {
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
        if body["tokens_issued"] == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        body["monthly_active_users"], 2,
        "alice twice and bob once: {body}"
    );
    assert_eq!(body["tokens_issued"], 2, "{body}");
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
        if !seen.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let reported = seen
        .first()
        .expect("a usage.reported event reaches the feed");

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
    for _ in 0..100 {
        let (tally, _) =
            ironauth_admin::usage::fold_usage(&h.store().scoped(scope).outbox(), 1_000)
                .await
                .expect("fold");
        if tally.tokens_issued() == 4 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

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
