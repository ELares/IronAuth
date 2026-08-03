// SPDX-License-Identifier: MIT OR Apache-2.0

//! The streaming bulk-import JOB surface, end to end over HTTP (issue #55).
//!
//! Pins the acceptance criterion M6 actually failed on: an import runs as a RESUMABLE
//! JOB with API-VISIBLE PROGRESS, and killing and resuming one mid-import neither
//! duplicates nor loses records.
//!
//! # Why the interruption here is a truncated UPLOAD
//!
//! The engine-level companion (`crates/ironauth-import/tests/engine.rs`,
//! `a_killed_import_resumes_without_duplicating_or_losing_records`) cancels the import
//! FUTURE at a point the line source chooses: `select!` drops it mid-await and nothing
//! unwinds. That is the strongest available statement of "killed", and it is made where
//! the future is reachable.
//!
//! Over HTTP the honest model of the same event is a body that STOPS: a client killed
//! part way through an upload delivers a prefix of its records and no more, and the
//! server sees exactly that. So the first pass here posts a prefix, and the assertions
//! prove it really stopped (a population strictly inside the source set, and a run that
//! CANNOT complete) before the resume is driven at all. A resume of a job that had
//! finished would prove nothing, so the test refuses to be that.

mod common;

use common::{Harness, OPERATOR_TOKEN, bearer};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::Value;

/// POST a newline-delimited record body, with an optional `Idempotency-Key`.
async fn post_ndjson(
    h: &Harness,
    path: &str,
    key: Option<&str>,
    body: &str,
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
        .header(header::CONTENT_TYPE, "application/x-ndjson");
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key);
    }
    h.send(
        builder
            .body(Body::from(body.to_owned()))
            .expect("request builds"),
    )
    .await
}

/// One import record line.
fn record(identifier: &str) -> String {
    format!("{{\"identifier\":\"{identifier}\"}}\n")
}

/// `n` records, `first..first + n`.
fn records(first: usize, count: usize) -> String {
    (first..first + count)
        .map(|n| record(&format!("import-{n}@x.test")))
        .collect()
}

/// A fresh tenant and environment.
async fn scope(h: &Harness, key: &str) -> (String, String) {
    h.create_tenant("imports", key).await
}

/// The run's LIVE progress, read from the surface the handle names.
async fn progress(h: &Harness, progress_path: &str) -> Value {
    let (status, _, body) = h.get(progress_path).await;
    assert_eq!(status, StatusCode::OK, "progress read: {body}");
    serde_json::from_str(&body).expect("progress is json")
}

/// How many users the environment holds, through the management list.
async fn user_count(h: &Harness, tenant: &str, environment: &str) -> usize {
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/users?limit=200");
    let (status, _, body) = h.get(&path).await;
    assert_eq!(status, StatusCode::OK, "list users: {body}");
    let value: Value = serde_json::from_str(&body).expect("json");
    let items = value["items"].as_array().expect("items").len();
    assert!(
        value["next_cursor"].is_null(),
        "the fixtures in this file fit one page; widen the page before trusting this count"
    );
    items
}

#[tokio::test]
async fn an_import_creates_users_and_publishes_progress_on_the_migration_run_view() {
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-basic").await;
    let path = format!("/v1/tenants/{tenant}/environments/{environment}/imports?source_total=3");

    let (status, _, body) = post_ndjson(&h, &path, Some("k-import-1"), &records(0, 3)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "the job is accepted: {body}");
    let handle: Value = serde_json::from_str(&body).expect("json");
    let run_id = handle["run_id"].as_str().expect("run id").to_owned();
    assert_eq!(handle["source_total"], 3);
    // The handle carries NO counters: progress is the migration-run view, and the handle
    // is how a caller finds it.
    assert!(
        handle.get("processed").is_none() && handle.get("succeeded").is_none(),
        "the job handle publishes no counters of its own: {body}"
    );
    let progress_path = handle["progress_path"].as_str().expect("progress path");
    assert_eq!(
        progress_path,
        format!("/v1/tenants/{tenant}/environments/{environment}/migration-runs/{run_id}")
    );

    // The identities landed.
    assert_eq!(user_count(&h, &tenant, &environment).await, 3);

    // And progress is API VISIBLE, on the surface that already existed.
    let view = progress(&h, progress_path).await;
    assert_eq!(view["kind"], "bulk_import");
    assert_eq!(view["counts"]["imported"], 3);
    assert_eq!(view["counts"]["failed"], 0);
    assert_eq!(view["counts"]["accounted"], 3);
    assert_eq!(view["source_total"], 3);
    assert_eq!(
        view["blocking"].as_array().expect("blocking").len(),
        0,
        "every declared record is accounted, so nothing blocks: {view}"
    );
    assert_eq!(
        view["state"], "complete",
        "a job whose declared source is fully accounted COMPLETES through the gated \
         transition: {view}"
    );
}

#[tokio::test]
async fn an_interrupted_import_resumes_without_duplicating_or_losing_records() {
    const TOTAL: usize = 40;
    const DELIVERED: usize = 17;

    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-resume").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let create = format!("{base}/imports?source_total={TOTAL}");

    // ---- pass 1: the upload STOPS after DELIVERED records -------------------------
    let (status, _, body) =
        post_ndjson(&h, &create, Some("k-resume-1"), &records(0, DELIVERED)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let handle: Value = serde_json::from_str(&body).expect("json");
    let run_id = handle["run_id"].as_str().expect("run id").to_owned();
    let progress_path = handle["progress_path"].as_str().expect("path").to_owned();

    // It really stopped: strictly inside the source set, in both the population and the
    // ledger, and the run cannot complete.
    let delivered_users = user_count(&h, &tenant, &environment).await;
    assert!(
        delivered_users > 0 && delivered_users < TOTAL,
        "the interruption must land strictly inside the import: {delivered_users} of {TOTAL}"
    );
    assert_eq!(delivered_users, DELIVERED);
    let mid = progress(&h, &progress_path).await;
    assert_eq!(
        mid["counts"]["accounted"],
        i64::try_from(DELIVERED).expect("fits")
    );
    assert_eq!(
        mid["state"], "running",
        "an unfinished job stays running, which is what makes it resumable: {mid}"
    );
    assert!(
        mid["blocking"]
            .as_array()
            .expect("blocking")
            .iter()
            .any(|name| name == "count"),
        "the COUNT invariant blocks while records are missing: {mid}"
    );

    // ---- pass 2: resume by re-presenting the WHOLE source -------------------------
    // The honest worst case: a resumed caller generally cannot know where the kill
    // landed, so it repeats everything.
    let resume = format!("{base}/imports/{run_id}");
    let (status, _, body) = post_ndjson(&h, &resume, None, &records(0, TOTAL)).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "the resume needs no Idempotency-Key: {body}"
    );
    let resumed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        resumed["run_id"], run_id,
        "the resume feeds the SAME run, never a new one"
    );

    // NO LOSS and NO DUPLICATE: the population is exactly the source set.
    assert_eq!(
        user_count(&h, &tenant, &environment).await,
        TOTAL,
        "every source record exists exactly once after the resume"
    );

    // And the LEDGER accounts each source record exactly once. Keying a created record
    // on the minted `usr_` id instead of its stable record key makes this TOTAL +
    // DELIVERED, because the resume reports the already-imported records as skips under
    // a different blind index; the run then over-counts and can never complete.
    let done = progress(&h, &progress_path).await;
    assert_eq!(
        done["counts"]["accounted"],
        i64::try_from(TOTAL).expect("fits"),
        "the resumed ledger accounts each source record exactly once: {done}"
    );
    assert_eq!(done["counts"]["failed"], 0, "{done}");
    assert_eq!(
        done["state"], "complete",
        "a killed-then-resumed job completes exactly like an uninterrupted one: {done}"
    );
}

#[tokio::test]
async fn replaying_the_create_key_returns_the_original_run_and_creates_no_second_one() {
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-replay").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");
    let create = format!("{base}/imports?source_total=2");

    let (status, _, first) = post_ndjson(&h, &create, Some("k-replay-1"), &records(0, 2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let (status, _, second) = post_ndjson(&h, &create, Some("k-replay-1"), &records(0, 2)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{second}");
    assert_eq!(
        first, second,
        "a replay returns the ORIGINAL response byte for byte"
    );

    // One run, not two: the Idempotency-Key record committed in the SAME transaction as
    // the run creation, which is the one write a replay must not repeat.
    let (status, _, body) = h.get(&format!("{base}/migration-runs")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let list: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        list["items"].as_array().expect("items").len(),
        1,
        "the replay created no second run: {body}"
    );

    // A key reused for a DIFFERENT request (a different declared source total) is
    // refused rather than served the wrong run.
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=9"),
        Some("k-replay-1"),
        &records(0, 2),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "the key is bound to the declared source total: {body}"
    );
}

#[tokio::test]
async fn an_import_validates_against_the_active_trait_schema_and_fails_only_the_offender() {
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-schema").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    // Register and ACTIVATE a schema, through the real management surface.
    let schema = serde_json::json!({
        "schema": {
            "type": "object",
            "properties": { "age": { "type": "integer" } },
            "additionalProperties": false
        }
    });
    let (status, _, body) = h
        .post(
            &format!("{base}/trait-schemas"),
            "k-schema-1",
            &schema.to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "create schema: {body}");
    let version = serde_json::from_str::<Value>(&body).expect("json")["version"]
        .as_i64()
        .expect("version");
    let (status, _, body) = h
        .post(
            &format!("{base}/trait-schemas/{version}/activate"),
            "k-schema-2",
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "activate schema: {body}");

    // Two records: one whose traits satisfy the active schema and one whose do not.
    let lines = concat!(
        r#"{"identifier":"good@x.test","traits":{"age":41}}"#,
        "\n",
        r#"{"identifier":"bad@x.test","traits":{"age":"forty-one"}}"#,
        "\n"
    );
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=2"),
        Some("k-schema-3"),
        lines,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let handle: Value = serde_json::from_str(&body).expect("json");
    let run_id = handle["run_id"].as_str().expect("run id").to_owned();
    let progress_path = handle["progress_path"].as_str().expect("path").to_owned();

    // The job surface did NOT reintroduce a validation bypass: the violating record fails
    // and the valid one still lands.
    assert_eq!(
        user_count(&h, &tenant, &environment).await,
        1,
        "only the record that satisfied the active schema was created"
    );
    let view = progress(&h, &progress_path).await;
    assert_eq!(view["counts"]["imported"], 1, "{view}");
    assert_eq!(view["counts"]["failed"], 1, "{view}");

    // Nothing was silently dropped: BOTH records are accounted, so the COUNT invariant is
    // satisfied and the run holds a recorded failure rather than a hole.
    assert_eq!(view["counts"]["accounted"], 2, "{view}");

    // The failure is READABLE, and it failed for the reason this test is named after.
    // Asserting only `failed == 1` would pass for a record that failed for any other
    // reason at all, under a test name promising the schema.
    let (status, _, body) = h
        .get(&format!(
            "{base}/migration-runs/{run_id}/violations?invariant=consistency"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let violations: Value = serde_json::from_str(&body).expect("json");
    let items = violations["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "the failed record pages here: {body}");
    assert_eq!(items[0]["subject"], "bad@x.test", "{body}");
    let detail = items[0]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("active schema"),
        "the violation says the ACTIVE SCHEMA refused it: {detail}"
    );
    assert!(
        detail.contains("/age"),
        "and names the offending field by RFC 6901 pointer: {detail}"
    );

    // A failed record is accounted INCONSISTENT, so the run is blocked on CONSISTENCY and
    // does not complete. Marking it consistent (which the first cut did) made this whole
    // surface vacuous: the run reported `failed = 1` while this page returned `[]`.
    assert_eq!(view["counts"]["inconsistent"], 1, "{view}");
    let blocking: Vec<&str> = view["blocking"]
        .as_array()
        .expect("blocking")
        .iter()
        .map(|name| name.as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        blocking,
        vec!["consistency"],
        "the count reconciles; consistency does not: {view}"
    );
    assert_ne!(view["state"], "complete", "{view}");
}

#[tokio::test]
async fn a_terminal_run_cannot_be_resumed_and_a_foreign_run_id_is_the_uniform_not_found() {
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-terminal").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=1"),
        Some("k-terminal-1"),
        &records(0, 1),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let handle: Value = serde_json::from_str(&body).expect("json");
    let run_id = handle["run_id"].as_str().expect("run id").to_owned();
    let view = progress(&h, handle["progress_path"].as_str().expect("path")).await;
    assert_eq!(
        view["state"], "complete",
        "the one-record job finished: {view}"
    );

    // A COMPLETE run is terminal, and the state machine refuses to re-open it. The
    // POPULATION is what this asserts, not only the status line: the refusal used to come
    // from the ledger ingest at the first batch flush, so five presented records answered
    // 409 with the environment holding SIX users, every one of them accounted in no ledger
    // anywhere. A test reading the status code alone passed throughout.
    let before = user_count(&h, &tenant, &environment).await;
    assert_eq!(before, 1, "the one-record job created one user");
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports/{run_id}"),
        None,
        &records(1, 5),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a terminal run cannot be resumed: {body}"
    );
    assert_eq!(
        user_count(&h, &tenant, &environment).await,
        before,
        "and the refusal happens BEFORE any identity is created: a 409 that creates five \
         unaccounted users is worse than no refusal at all"
    );

    // A well-formed run id that names no run in this scope is the uniform not-found, and
    // so is a malformed one: the resume route is no existence oracle.
    let absent = format!("{}0", &run_id[..run_id.len() - 1]);
    for candidate in [absent.as_str(), "mgr_not_a_real_id", "../../etc"] {
        let (status, _, _) = post_ndjson(
            &h,
            &format!("{base}/imports/{candidate}"),
            None,
            &records(9, 1),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{candidate} must be the uniform not-found"
        );
    }
    assert_eq!(
        user_count(&h, &tenant, &environment).await,
        before,
        "and none of the not-found refusals created anything either"
    );
}

#[tokio::test]
async fn the_create_requires_an_idempotency_key_and_a_well_formed_source_total() {
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-input").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    // No Idempotency-Key.
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=1"),
        None,
        &records(0, 1),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("Idempotency-Key"), "{body}");

    // A malformed or out-of-range source total.
    for bad in ["nope", "-1", "10000001"] {
        let (status, _, body) = post_ndjson(
            &h,
            &format!("{base}/imports?source_total={bad}"),
            Some("k-input-bad"),
            &records(0, 1),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "source_total={bad}: {body}"
        );
    }

    // Nothing was created by any of the refusals.
    assert_eq!(user_count(&h, &tenant, &environment).await, 0);
}

#[tokio::test]
async fn a_body_the_server_could_not_read_is_refused_rather_than_answered_202() {
    // A single line over the 1 MiB cap in the MIDDLE of a record set. The reader stops
    // there, so four later records are never seen. Answering 202 to that tells the caller
    // its upload is durable when five of its six records were dropped on the floor:
    // MEASURED at `202, users=1, accounted=1, remainder=5`, with no signal anywhere.
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-truncate").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    // Six source lines: one good record, then a line of MAX_LINE_BYTES + 1 where the
    // second record should have been, then the remaining four. The reader stops at the
    // oversized line, so records two through six are never seen.
    let body = format!(
        "{}{}\n{}",
        records(0, 1),
        "x".repeat((1 << 20) + 1),
        records(2, 4)
    );
    let (status, _, message) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=6"),
        Some("k-truncate-1"),
        &body,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a truncated upload is not an accepted job: {message}"
    );
    assert!(
        message.contains("exceeded"),
        "the refusal names the cause: {message}"
    );

    // The records delivered BEFORE the fault are durable, and the error says which run to
    // resume, so the refusal costs the caller nothing it had already achieved.
    assert_eq!(user_count(&h, &tenant, &environment).await, 1);
    let (status, _, listing) = h.get(&format!("{base}/migration-runs")).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    let list: Value = serde_json::from_str(&listing).expect("json");
    let run_id = list["items"][0]["id"].as_str().expect("the run exists");
    assert!(
        message.contains(run_id),
        "the refusal names the run to resume: {message}"
    );

    // And resuming it with a clean body finishes the job, which is what makes the 400 a
    // report rather than a loss.
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports/{run_id}"),
        None,
        &records(0, 6),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(user_count(&h, &tenant, &environment).await, 6);
    let view = progress(&h, &format!("{base}/migration-runs/{run_id}")).await;
    assert_eq!(view["counts"]["accounted"], 6, "{view}");
    assert_eq!(view["state"], "complete", "{view}");
}

#[tokio::test]
async fn an_undecodable_line_fails_its_record_rather_than_creating_an_unreachable_user() {
    // A Latin-1 byte in a login handle. Decoded lossily (which the transport used to do)
    // it created a user whose identifier carries U+FFFD, counted as imported, who can
    // never log in, with no error anywhere.
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-utf8").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    let mut body = b"{\"identifier\":\"caf\xe9@x.test\"}\n".to_vec();
    body.extend_from_slice(b"{\"identifier\":\"clean@x.test\"}\n");
    let request = Request::builder()
        .method("POST")
        .uri(format!("{base}/imports?source_total=2"))
        .header(header::AUTHORIZATION, bearer(OPERATOR_TOKEN))
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .header("idempotency-key", "k-utf8-1")
        .body(Body::from(body))
        .expect("request builds");
    let (status, _, handle) = h.send(request).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{handle}");
    let handle: Value = serde_json::from_str(&handle).expect("json");
    let run_id = handle["run_id"].as_str().expect("run id").to_owned();

    // Exactly ONE user, and it is the clean one.
    assert_eq!(user_count(&h, &tenant, &environment).await, 1);
    let (status, _, listing) = h.get(&format!("{base}/users?limit=10")).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert!(
        !listing.contains('\u{fffd}'),
        "no identity carries a replacement character: {listing}"
    );

    // And the undecodable line is an ACCOUNTED, READABLE failure rather than a success.
    let view = progress(&h, &format!("{base}/migration-runs/{run_id}")).await;
    assert_eq!(view["counts"]["imported"], 1, "{view}");
    assert_eq!(view["counts"]["failed"], 1, "{view}");
    assert_eq!(view["counts"]["accounted"], 2, "{view}");
    let (status, _, body) = h
        .get(&format!(
            "{base}/migration-runs/{run_id}/violations?invariant=consistency"
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let violations: Value = serde_json::from_str(&body).expect("json");
    let detail = violations["items"][0]["detail"]
        .as_str()
        .unwrap_or_default();
    assert!(
        detail.contains("not valid UTF-8"),
        "the reason says what happened: {body}"
    );
}

#[tokio::test]
async fn the_import_applies_the_same_input_validation_as_the_live_user_create() {
    // Two writers of the same column must agree about what a login handle is. MEASURED
    // before this: `identifier: ""` was a 400 on `POST .../users` and an IMPORT here, and
    // `" a@x.test "` was stored verbatim here and trimmed there.
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-validate").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    // The live edge refuses a blank identifier.
    let (status, _, body) = h
        .post(
            &format!("{base}/users"),
            "k-validate-1",
            &serde_json::json!({ "identifier": "" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // And so does the import, as a per-RECORD failure: a blank handle creates nothing.
    let lines = concat!(
        r#"{"identifier":""}"#,
        "\n",
        r#"{"identifier":"  padded@x.test  "}"#,
        "\n"
    );
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=2"),
        Some("k-validate-2"),
        lines,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let run_id = serde_json::from_str::<Value>(&body).expect("json")["run_id"]
        .as_str()
        .expect("run id")
        .to_owned();
    let view = progress(&h, &format!("{base}/migration-runs/{run_id}")).await;
    assert_eq!(view["counts"]["imported"], 1, "{view}");
    assert_eq!(view["counts"]["failed"], 1, "{view}");

    // The padded handle is stored TRIMMED, which is what the live edge stores, so the
    // same login handle written by either writer is one row and not two.
    let (status, _, listing) = h.get(&format!("{base}/users?limit=10")).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    let users: Value = serde_json::from_str(&listing).expect("json");
    let items = users["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{listing}");
    assert_eq!(items[0]["identifier"], "padded@x.test", "{listing}");

    // Re-presenting it UNPADDED is an idempotent skip rather than a second identity,
    // which is the property the trim buys.
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports/{run_id}"),
        None,
        "{\"identifier\":\"padded@x.test\"}\n",
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(user_count(&h, &tenant, &environment).await, 1);
}

#[tokio::test]
async fn a_run_that_can_never_reconcile_is_closed_by_the_abandon_route() {
    // A source carrying TWO records under one login handle is ONE ledger subject, so it
    // accounts one row against a declared two and the count invariant is unsatisfiable
    // forever. Nothing on this plane may rewrite `source_total` or delete a ledger row
    // (migration 0101 withholds both on purpose), so without the abandon route the run
    // would be immortal and the operator would have no audited way to say so.
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-abandon").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    let lines = concat!(
        r#"{"identifier":"twin@x.test","external_id":"crm-1"}"#,
        "\n",
        r#"{"identifier":"twin@x.test","external_id":"crm-2"}"#,
        "\n"
    );
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=2"),
        Some("k-abandon-1"),
        lines,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let run_id = serde_json::from_str::<Value>(&body).expect("json")["run_id"]
        .as_str()
        .expect("run id")
        .to_owned();

    // Wedged: one accounted against a declared two, blocked on COUNT, and re-presenting
    // the source changes nothing.
    let view = progress(&h, &format!("{base}/migration-runs/{run_id}")).await;
    assert_eq!(view["counts"]["accounted"], 1, "{view}");
    assert!(
        view["blocking"]
            .as_array()
            .expect("blocking")
            .iter()
            .any(|name| name == "count"),
        "{view}"
    );
    let (status, _, _) = post_ndjson(&h, &format!("{base}/imports/{run_id}"), None, lines).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let view = progress(&h, &format!("{base}/migration-runs/{run_id}")).await;
    assert_eq!(view["counts"]["accounted"], 1, "still one: {view}");

    // A blank reason is refused: an abandonment with no stated reason is the silent
    // forgetting the state machine exists to prevent.
    let (status, _, body) = h
        .post(
            &format!("{base}/migration-runs/{run_id}/abandon"),
            "k-abandon-2",
            &serde_json::json!({ "reason": "   " }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // The abandonment closes it, terminally, with the reason readable on the run.
    let reason = "source carried two records for twin@x.test; re-running from a corrected export";
    let (status, _, body) = h
        .post(
            &format!("{base}/migration-runs/{run_id}/abandon"),
            "k-abandon-3",
            &serde_json::json!({ "reason": reason }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let closed: Value = serde_json::from_str(&body).expect("json");
    assert_eq!(closed["state"], "abandoned", "{body}");
    assert_eq!(closed["abandoned_reason"], reason, "{body}");

    // Idempotent, and it does not rewrite history: a second abandonment keeps the FIRST
    // reason.
    let (status, _, body) = h
        .post(
            &format!("{base}/migration-runs/{run_id}/abandon"),
            "k-abandon-4",
            &serde_json::json!({ "reason": "a different reason" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).expect("json")["abandoned_reason"],
        reason,
        "the first reason stands: {body}"
    );

    // And the run is terminal: a resume is refused, before anything is created.
    let before = user_count(&h, &tenant, &environment).await;
    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports/{run_id}"),
        None,
        &records(50, 3),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(user_count(&h, &tenant, &environment).await, before);
}

#[tokio::test]
async fn a_completed_run_cannot_be_abandoned() {
    // The other direction of the same fence: `complete` is a statement that every
    // invariant re-evaluated satisfied, and nothing may quietly take it back.
    let h = Harness::start(50).await;
    let (tenant, environment) = scope(&h, "k-abandon-complete").await;
    let base = format!("/v1/tenants/{tenant}/environments/{environment}");

    let (status, _, body) = post_ndjson(
        &h,
        &format!("{base}/imports?source_total=1"),
        Some("k-ac-1"),
        &records(0, 1),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let run_id = serde_json::from_str::<Value>(&body).expect("json")["run_id"]
        .as_str()
        .expect("run id")
        .to_owned();
    let view = progress(&h, &format!("{base}/migration-runs/{run_id}")).await;
    assert_eq!(view["state"], "complete", "{view}");

    let (status, _, body) = h
        .post(
            &format!("{base}/migration-runs/{run_id}/abandon"),
            "k-ac-2",
            &serde_json::json!({ "reason": "second thoughts" }).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let view = progress(&h, &format!("{base}/migration-runs/{run_id}")).await;
    assert_eq!(view["state"], "complete", "unchanged: {view}");
    assert!(view["abandoned_reason"].is_null(), "{view}");
}
