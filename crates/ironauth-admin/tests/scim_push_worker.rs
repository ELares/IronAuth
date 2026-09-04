// SPDX-License-Identifier: MIT OR Apache-2.0

//! One pass of the outbound sync, end to end (issue #137).
//!
//! # What makes this measurement worth anything
//!
//! Everything here is real except the subject directory: a real Postgres, the real event feed,
//! the real link and sync-state tables, and the reference downstream SCIM server that was written
//! from RFC 7644 before the client existed. The only seam is [`SubjectSource`], because whether a
//! person is in scope and what their SCIM body looks like are the connection's business, not the
//! worker's.
//!
//! # The criteria this file is about
//!
//! Criterion 3 (kill the downstream mid-sync, restore it, converge with NO duplicates) is the one
//! the ordering inside a pass exists for, so the outage test drives it through the real switch
//! rather than asserting the ordering by reading the source. Criterion 4 (out-of-scope users are
//! never pushed, and a user leaving scope is deactivated) is the other.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::Request;
use ironauth_admin::scim_push_client::{DeletionPolicy, ScimPushClient, WriteMode};
use ironauth_admin::scim_push_events::Collection;
use ironauth_admin::scim_push_transport::{
    ScimRequest, ScimResponse, ScimTransport, ScimTransportError,
};
use ironauth_admin::scim_push_worker::{
    Pass, Progress, SubjectSource, WorkerError, run_backfill_pass, run_due_connections,
    run_tail_pass,
};
use ironauth_env::Env;
use ironauth_scim::downstream::{Downstream, Health};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, NewScimPushConnection, OrganizationId, ScimBackfillState, ScimDeletionPolicy,
    ScimPushConnectionId, ScimPushResourceType, ScimWriteMode, Scope,
};
use serde_json::{Value, json};
use sqlx::Row;
use tower::ServiceExt;

const TOKEN: &str = "downstream-bearer-token";
const BASE: &str = "https://downstream.example/scim/v2";

/// Carries a request into the fixture's router, as the client suite's transport does.
#[derive(Clone)]
struct FixtureTransport {
    downstream: Downstream,
}

impl ScimTransport for FixtureTransport {
    fn send(
        &self,
        base_url: &str,
        bearer: &str,
        request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send {
        let downstream = self.downstream.clone();
        let base_path = base_url
            .strip_prefix("https://")
            .and_then(|rest| rest.find('/').map(|i| rest[i..].to_owned()))
            .unwrap_or_default();
        let mut uri = format!("{}{}", base_path.trim_end_matches('/'), request.path);
        if let Some(filter) = &request.filter {
            uri.push_str("?filter=");
            for byte in filter.as_bytes() {
                match byte {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                        uri.push(*byte as char);
                    }
                    _ => {
                        use std::fmt::Write as _;
                        let _ = write!(uri, "%{byte:02X}");
                    }
                }
            }
        }
        let authorization = format!("Bearer {bearer}");
        async move {
            let builder = Request::builder()
                .method(request.method)
                .uri(uri)
                .header("authorization", authorization);
            let http_request = match request.body {
                Some(body) => builder
                    .header("content-type", "application/scim+json")
                    .body(Body::from(body.to_string())),
                None => builder.body(Body::empty()),
            }
            .map_err(|_| ScimTransportError::Transport)?;
            let response = downstream
                .router()
                .oneshot(http_request)
                .await
                .map_err(|_| ScimTransportError::Transport)?;
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .map_err(|_| ScimTransportError::Transport)?;
            let body = serde_json::from_slice::<Value>(&bytes).ok();
            Ok(ScimResponse { status, body })
        }
    }
}

/// A transport that lets a SECOND writer move the connection's health state mid-pass.
///
/// The interleaving a checkpoint guard exists to refuse cannot be produced any other way from a
/// test: the pass reads its state, does its work, and checkpoints, all inside one call. This runs
/// `during` on the first request the pass sends, which is exactly the window between the read and
/// the checkpoint.
#[derive(Clone)]
struct RacingTransport {
    inner: FixtureTransport,
    pool: sqlx::PgPool,
    connection: String,
    fired: Arc<Mutex<bool>>,
}

impl ScimTransport for RacingTransport {
    fn send(
        &self,
        base_url: &str,
        bearer: &str,
        request: ScimRequest,
    ) -> impl Future<Output = Result<ScimResponse, ScimTransportError>> + Send {
        let first = {
            let mut fired = self.fired.lock().expect("the flag is not poisoned");
            let first = !*fired;
            *fired = true;
            first
        };
        let pool = self.pool.clone();
        let connection = self.connection.clone();
        let delegated = self.inner.send(base_url, bearer, request);
        async move {
            if first {
                // ANOTHER WORKER'S PASS FAILS AGAINST THE SAME CONNECTION. Written straight to the
                // table rather than through the repository, because what is being reproduced is a
                // concurrent writer, not a call this pass makes.
                sqlx::query(
                    "UPDATE scim_push_connections \
                     SET consecutive_failures = consecutive_failures + 1, \
                         last_error = 'downstream answered 503', last_error_at = now(), \
                         paused_until = now() + interval '60 seconds' \
                     WHERE id = $1",
                )
                .bind(&connection)
                .execute(&pool)
                .await
                .expect("the racing writer lands");
            }
            delegated.await
        }
    }
}

/// A directory the test controls: who exists, and who is in scope.
#[derive(Clone, Default)]
struct Directory {
    people: Arc<Mutex<BTreeMap<String, Value>>>,
    out_of_scope: Arc<Mutex<Vec<String>>>,
}

impl Directory {
    fn with(subject: &str, user_name: &str) -> Self {
        let d = Self::default();
        d.people.lock().expect("lock").insert(
            subject.to_owned(),
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": user_name,
                "externalId": subject,
                "active": true,
            }),
        );
        d
    }

    fn put_out_of_scope(&self, subject: &str) {
        self.out_of_scope
            .lock()
            .expect("lock")
            .push(subject.to_owned());
    }
}

impl Directory {
    fn add(&self, subject: &str, user_name: &str) {
        self.people.lock().expect("lock").insert(
            subject.to_owned(),
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": user_name,
                "externalId": subject,
                "active": true,
            }),
        );
    }
}

impl SubjectSource for Directory {
    fn resource(
        &self,
        _collection: Collection,
        subject_id: &str,
    ) -> impl Future<Output = Result<Option<Value>, String>> + Send {
        let found = self.people.lock().expect("lock").get(subject_id).cloned();
        async move { Ok(found) }
    }

    fn in_scope(
        &self,
        _collection: Collection,
        subject_id: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send {
        let out = self
            .out_of_scope
            .lock()
            .expect("lock")
            .iter()
            .any(|s| s == subject_id);
        async move { Ok(!out) }
    }

    fn enumerate(
        &self,
        collection: Collection,
        after: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        // This directory holds people. A GROUP enumeration is empty, and saying so honestly is
        // what lets the users-to-groups handover be observed: a source that returned its users
        // again for the group pass would re-push every one of them under the wrong resource type.
        if collection == Collection::Group {
            return std::future::ready(Ok(Vec::new()));
        }
        // A BTreeMap, so the order is total and stable across passes. That is what makes `after`
        // mean anything: an enumeration whose order changed between passes would let a resumed
        // backfill skip people, and nothing would ever come back for them.
        let out_of_scope = self.out_of_scope.lock().expect("lock").clone();
        let page: Vec<String> = self
            .people
            .lock()
            .expect("lock")
            .keys()
            .filter(|id| after.is_none_or(|a| id.as_str() > a))
            .filter(|id| !out_of_scope.iter().any(|o| o == *id))
            .take(limit)
            .cloned()
            .collect();
        std::future::ready(Ok(page))
    }
}

fn now_micros(env: &Env) -> i64 {
    i64::try_from(
        env.clock()
            .now_utc()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("after epoch")
            .as_micros(),
    )
    .expect("fits i64")
}

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

async fn seed_connection(
    db: &TestDatabase,
    env: &Env,
    scope: Scope,
    organization: &OrganizationId,
) -> ScimPushConnectionId {
    let id = ScimPushConnectionId::generate(env, &scope);
    db.control_store()
        .scoped(scope)
        .acting(db.test_actor(env), CorrelationId::generate(env))
        .scim_push_connections()
        .create(
            env,
            NewScimPushConnection {
                id: &id,
                organization_id: organization,
                display_name: "Okta production",
                base_url: BASE,
                credential_secret_name: "downstream_token",
                attribute_mapping: &json!({}),
                user_scope_filter: None,
                group_scope_filter: None,
                write_mode: ScimWriteMode::Patch,
                deletion_policy: ScimDeletionPolicy::Deactivate,
            },
            None,
            None,
        )
        .await
        .expect("create the push connection");
    id
}

/// Puts one catalogued event on the feed and returns its sequence.
///
/// # The envelope is BUILT BY THE REGISTRY, not written here
///
/// The first version of this helper hand-wrote `{"type": ..., "payload": ...}` and inserted it.
/// That is two words of the envelope a producer actually emits: the real one also carries `id`,
/// `payload_schema_version`, `occurred_at_unix_ms`, `tenant_id` and `environment_id`, and the
/// catalog's own envelope schema makes all five REQUIRED.
///
/// So the whole worker suite was measuring the worker against envelopes this file invented and
/// nothing in the system produces. Every test passed on a shape that would not have survived
/// `validate_event`, and the question the suite exists to answer -- does the worker read the
/// events IronAuth emits -- was never asked. `event_catalog::envelope` is the same constructor
/// `enqueue_domain_event` feeds, so building through it makes the fixture and production one
/// source; `validate_event` then holds the fixture to the registry, which is what turns a
/// registry change that the worker cannot read into a failing test rather than a silent one.
async fn enqueue(
    db: &TestDatabase,
    scope: Scope,
    id: &str,
    event_type: &str,
    payload: Value,
) -> i64 {
    let payload = ironauth_store::test_support::registry_payload(event_type, &payload);
    let envelope = ironauth_store::event_catalog::envelope(
        id,
        event_type,
        &scope.tenant().to_string(),
        &scope.environment().to_string(),
        1_700_000_000_000,
        &payload,
    )
    .unwrap_or_else(|| {
        panic!("{event_type} is not an environment-scoped registered type, so no producer emits it")
    });
    ironauth_store::event_catalog::validate_event(&envelope).unwrap_or_else(|error| {
        panic!(
            "the fixture built an envelope the registry refuses, so the worker would never see \
             it in production: {error:?}\n\n{envelope}"
        )
    });
    let row = sqlx::query(
        "INSERT INTO outbox_messages \
         (id, tenant_id, environment_id, consumer, idempotency_key, ordering_key, payload, \
          next_attempt_at, enqueued_at) \
         VALUES ($1, $2, $3, 'scim-push-test', $1, 'k', $4, now(), now()) \
         RETURNING sequence",
    )
    .bind(id)
    .bind(scope.tenant().to_string())
    .bind(scope.environment().to_string())
    .bind(envelope)
    .fetch_one(db.owner_pool())
    .await
    .expect("enqueue");
    row.get::<i64, _>("sequence")
}

/// Everything a pass needs, wired to a real database and the reference downstream.
struct Harness {
    db: TestDatabase,
    env: Env,
    scope: Scope,
    connection: ScimPushConnectionId,
    /// The organization this connection pushes, as the worker compares it against events.
    org: String,
    downstream: Downstream,
}

impl Harness {
    /// A moment safely after `now_micros`, so a second pass in one test is not racing the first.
    fn scope_now(&self, env: &Env) -> i64 {
        now_micros(env) + 1_000
    }

    async fn start() -> Self {
        let db = TestDatabase::start().await;
        let env = Env::system();
        let scope = db.seed_scope(&env).await;
        let org = seed_org(&db, &env, scope, "Globex").await;
        let connection = seed_connection(&db, &env, scope, &org).await;
        Self {
            db,
            env,
            scope,
            connection,
            org: org.to_string(),
            downstream: Downstream::new(TOKEN),
        }
    }

    /// Marks the backfill done and puts the cursor at the feed's current head.
    async fn start_tailing_from(&self, sequence: i64) {
        let store = self.db.store().scoped(self.scope);
        store
            .scim_push_sync_state()
            .begin_backfill(&self.connection, Some(sequence))
            .await
            .expect("begin");
        // THE WHOLE STATE MACHINE, because reaching `done` now requires passing through both
        // collections. A helper that jumped straight from `users` to `done` would let every test
        // above it start tailing without groups ever having been enumerated, which is precisely
        // the defect the transition was added to close.
        store
            .scim_push_sync_state()
            .begin_group_backfill(&self.connection)
            .await
            .expect("users done, on to groups");
        store
            .scim_push_sync_state()
            .complete_backfill(&self.connection)
            .await
            .expect("complete");
    }

    fn client(&self) -> ScimPushClient<FixtureTransport> {
        ScimPushClient::new(
            FixtureTransport {
                downstream: self.downstream.clone(),
            },
            BASE,
            TOKEN,
            WriteMode::Patch,
        )
    }
}

#[tokio::test]
async fn a_backfill_resumes_from_where_it_stopped_and_only_then_starts_tailing() {
    // #137 requires the backfill to be RESUMABLE. The test kills it between pages and asserts
    // that the second run continues rather than restarting: for a large org, restarting means
    // re-pushing tens of thousands of people, and the interesting failure is the other one, where
    // a resumed enumeration SKIPS somebody and nothing ever comes back for them.
    let h = Harness::start().await;
    let directory = Directory::default();
    for (subject, name) in [
        ("usr_a", "ada"),
        ("usr_b", "bea"),
        ("usr_c", "cyd"),
        ("usr_d", "dee"),
    ] {
        directory.add(subject, name);
    }
    let store = h.db.store().scoped(h.scope);
    store
        .scim_push_sync_state()
        .begin_backfill(&h.connection, Some(0))
        .await
        .expect("begin");

    // THE FEED POSITION IS READ BEFORE ANY ENUMERATION, and the same value is carried through
    // every page. A backfill that finished and THEN read the head would lose every event that
    // happened while it ran.
    // Sequence 0: the position before the first event, which is where a connection with no
    // history starts.
    let feed_head = 0_i64;
    let client = h.client();
    let page = |limit: i64| Pass {
        connection_id: &h.connection,
        client: &client,
        subjects: &directory,
        deletion_policy: DeletionPolicy::Deactivate,
        limit,
        scope: h.scope,
        now_unix_micros: now_micros(&h.env),
        organization_id: h.org.clone(),
    };

    // Two at a time, then a simulated restart: the second call starts from the recorded position.
    let first = run_backfill_pass(&store, page(2))
        .await
        .expect("first page");
    assert_eq!(first.converged, 2, "{first:?}");
    let mid = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state");
    assert_eq!(
        mid.backfill_after_id.as_deref(),
        Some("usr_b"),
        "the backfill did not record where it stopped"
    );
    assert_eq!(
        mid.cursor_sequence, None,
        "a running backfill must not be tailing"
    );

    let second = run_backfill_pass(&store, page(2))
        .await
        .expect("second page");
    assert_eq!(second.converged, 2, "{second:?}");
    // FOUR PEOPLE, ONCE EACH. A restart that rewound would push a and b again, and one that
    // skipped would leave c or d unprovisioned for ever.
    assert_eq!(
        h.downstream.users().len(),
        4,
        "the resumed backfill did not provision each person exactly once: {:?}",
        h.downstream.users()
    );

    // AN EMPTY USER PAGE HANDS OVER TO GROUPS rather than finishing. A backfill that completed
    // here would leave every group unprovisioned while reporting itself done, which is what the
    // first version did whatever collection it had been handed.
    let handover = run_backfill_pass(&store, page(2))
        .await
        .expect("the empty user page hands over");
    assert!(
        !handover.checkpointed,
        "the backfill completed before groups were enumerated: {handover:?}"
    );
    let mid = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state");
    assert_eq!(mid.backfill_state, ScimBackfillState::Groups);
    assert_eq!(
        mid.cursor_sequence, None,
        "a connection still enumerating groups must not be tailing"
    );

    // AND THE EMPTY GROUP PAGE COMPLETES IT, and only then does the cursor appear.
    let done = run_backfill_pass(&store, page(2))
        .await
        .expect("the empty group page completes the backfill");
    assert!(done.checkpointed);
    let complete = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state");
    assert_eq!(complete.cursor_sequence, Some(feed_head));
    assert_eq!(complete.backfill_after_id, None);

    // AND A LINK EXISTS FOR EVERY PERSON, so the tail can address them by downstream id.
    for subject in ["usr_a", "usr_b", "usr_c", "usr_d"] {
        assert!(
            store
                .scim_push_links()
                .find(&h.connection, ScimPushResourceType::User, subject)
                .await
                .expect("find")
                .is_some(),
            "{subject} was provisioned without a link"
        );
    }
}

#[tokio::test]
async fn a_backfill_never_pushes_a_subject_outside_the_connections_scope() {
    // Criterion 4's first half, on the enumeration path rather than the event path. An
    // out-of-scope person must not be provisioned by the initial sweep either, and this is the
    // sweep that touches everybody.
    let h = Harness::start().await;
    let directory = Directory::default();
    directory.add("usr_in", "ada");
    directory.add("usr_out", "eve");
    directory.put_out_of_scope("usr_out");

    let store = h.db.store().scoped(h.scope);
    store
        .scim_push_sync_state()
        .begin_backfill(&h.connection, Some(0))
        .await
        .expect("begin");
    let client = h.client();
    run_backfill_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await
    .expect("backfill");

    let stored = h.downstream.users();
    assert_eq!(
        stored.len(),
        1,
        "an out-of-scope person was provisioned: {stored:?}"
    );
    let only = stored.values().next().expect("one");
    assert_eq!(only["externalId"], json!("usr_in"));
}

#[tokio::test]
async fn a_connection_that_is_not_enumerating_cannot_run_a_backfill_pass() {
    // The mirror of the tail pass's guard. Running an enumeration against a connection that is
    // already tailing would re-push everybody and, worse, the completing pass would then move a
    // live cursor.
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");
    h.start_tailing_from(0).await;

    let store = h.db.store().scoped(h.scope);
    let client = h.client();
    let outcome = run_backfill_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await;
    assert!(
        matches!(outcome, Err(WorkerError::Permanent(_))),
        "a tailing connection ran a backfill pass: {outcome:?}"
    );
    assert!(
        h.downstream.users().is_empty(),
        "it pushed anyway: {:?}",
        h.downstream.users()
    );
}

#[tokio::test]
async fn losing_the_checkpoint_race_is_not_recorded_as_a_connection_failure() {
    // WHY THIS EXISTS. Losing the compare-and-set answers `StoreError::NotFound`, and the driver
    // recorded EVERY error as a connection failure: the loser wrote a failure count, an error
    // string naming an internal condition, and a doubling pause. Nothing had failed. Two healthy
    // workers on a healthy connection produced a paused connection whose downstream had returned
    // nothing but success, and the three comments saying a lost race "is not a fault" were
    // enforced nowhere.
    //
    // It compounds, which is why it is worth a test rather than a comment. The checkpoint now
    // compares the failure count, so a spurious failure record invalidates the checkpoint of
    // every other pass still in flight against that connection, and each of those records another.
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");
    h.start_tailing_from(0).await;
    enqueue(
        &h.db,
        h.scope,
        "evt_1",
        "user.created",
        json!({ "user_id": "usr_ada", "state": "active" }),
    )
    .await;

    let store = h.db.store().scoped(h.scope);
    let racer = RacingTransport {
        inner: FixtureTransport {
            downstream: h.downstream.clone(),
        },
        pool: h.db.owner_pool().clone(),
        connection: h.connection.to_string(),
        fired: Arc::new(Mutex::new(false)),
    };

    let outcomes = run_due_connections(&store, h.scope, now_micros(&h.env), 50, |connection| {
        Some((
            ScimPushClient::new(racer.clone(), BASE, TOKEN, WriteMode::Patch),
            directory.clone(),
            connection.organization_id.to_string(),
        ))
    })
    .await
    .expect("the due listing reads");

    // The pass DID its work: the downstream has the user. Only the checkpoint lost.
    assert_eq!(
        h.downstream.users().len(),
        1,
        "the pass never reached the downstream, so this proves nothing about the checkpoint"
    );
    assert!(
        matches!(outcomes[0].1, Err(WorkerError::Contended)),
        "a lost checkpoint race must be reported as contention: {:?}",
        outcomes[0].1
    );

    let after = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state");
    // EXACTLY ONE failure, the racer's. A second means the driver recorded the lost race.
    assert_eq!(
        after.consecutive_failures, 1,
        "losing the checkpoint race was counted as a connection failure: {after:?}"
    );
    assert_eq!(
        after.last_error.as_deref(),
        Some("downstream answered 503"),
        "the lost race overwrote the real reason with an internal one"
    );
}

#[tokio::test]
async fn the_driver_runs_due_connections_and_writes_the_backoff_a_failure_earns() {
    // WHY THIS TEST EXISTS. `run_tail_pass` and `run_backfill_pass` had no caller outside the
    // suite, so criteria 1, 3 and 4 were satisfied by code nothing ran: the tests called those
    // functions directly, which is exactly why they passed and exactly why they proved less than
    // they appeared to. This drives the seam a deployment uses.
    //
    // It also reaches two things that were unreachable. `record_failure` was called by nothing in
    // `src`, so `consecutive_failures` stayed zero and `paused_until` stayed NULL: criterion 2's
    // health surface reported a healthy connection through an outage of any length. And 0192's
    // due index was shipped for a query nothing issued.
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");
    h.start_tailing_from(0).await;
    enqueue(
        &h.db,
        h.scope,
        "evt_1",
        "user.created",
        json!({ "user_id": "usr_ada", "state": "active" }),
    )
    .await;

    let store = h.db.store().scoped(h.scope);
    let now = now_micros(&h.env);

    // A DUE CONNECTION IS FOUND AND RUN. Nothing here names the connection: the driver reads the
    // due listing, which is the query 0192 indexed.
    let outcomes = run_due_connections(&store, h.scope, now, 50, |connection| {
        Some((
            ScimPushClient::new(
                FixtureTransport {
                    downstream: h.downstream.clone(),
                },
                BASE,
                TOKEN,
                WriteMode::Patch,
            ),
            directory.clone(),
            connection.organization_id.to_string(),
        ))
    })
    .await
    .expect("the due listing reads");
    assert_eq!(outcomes.len(), 1, "the due connection was not picked up");
    let progress = outcomes[0].1.as_ref().expect("the pass ran");
    assert_eq!(progress.converged, 1, "{progress:?}");
    assert_eq!(h.downstream.users().len(), 1);

    // NOW AN OUTAGE. The failure must be recorded and the connection paused, which is the
    // mechanism behind "an outage pauses the cursor rather than dropping events".
    h.downstream.set_health(Health::Down);
    enqueue(
        &h.db,
        h.scope,
        "evt_2",
        "user.updated",
        json!({ "user_id": "usr_ada" }),
    )
    .await;
    let outcomes = run_due_connections(&store, h.scope, h.scope_now(&h.env), 50, |connection| {
        Some((
            ScimPushClient::new(
                FixtureTransport {
                    downstream: h.downstream.clone(),
                },
                BASE,
                TOKEN,
                WriteMode::Patch,
            ),
            directory.clone(),
            connection.organization_id.to_string(),
        ))
    })
    .await
    .expect("the due listing reads");
    assert!(outcomes[0].1.is_err(), "the outage was not reported");

    let after = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state");
    assert_eq!(
        after.consecutive_failures, 1,
        "the failure was not counted, so a health surface would report this connection healthy"
    );
    assert!(
        after.last_error.is_some(),
        "the failure recorded no reason: {after:?}"
    );
    assert!(
        after.paused_until_unix_micros.is_some(),
        "a retryable failure set no backoff, so the worker would hammer a downstream that is down"
    );

    // AND THE PAUSE TAKES THE CONNECTION OUT OF THE DUE LISTING, which is what makes the backoff
    // a backoff rather than a number in a column.
    let still_due = store
        .scim_push_connections()
        .due_for_sync(h.scope_now(&h.env), 50)
        .await
        .expect("due listing");
    assert!(
        still_due.is_empty(),
        "a paused connection is still due, so the backoff does nothing: {still_due:?}"
    );
}

#[tokio::test]
async fn a_pass_pushes_each_event_then_checkpoints_once() {
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");
    h.start_tailing_from(0).await;

    enqueue(
        &h.db,
        h.scope,
        "evt_1",
        "user.created",
        json!({ "user_id": "usr_ada", "state": "active" }),
    )
    .await;
    let last = enqueue(
        &h.db,
        h.scope,
        "evt_2",
        "user.updated",
        json!({ "user_id": "usr_ada" }),
    )
    .await;

    let store = h.db.store().scoped(h.scope);
    let client = h.client();
    let progress = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await
    .expect("the pass runs");

    assert_eq!(progress.read, 2);
    assert_eq!(progress.converged, 2, "{progress:?}");
    assert!(progress.checkpointed);

    // ONE resource downstream, not two: the second event converged onto the first.
    assert_eq!(h.downstream.users().len(), 1, "{:?}", h.downstream.users());

    // THE LINK IS RECORDED, which is what a later deprovision addresses by.
    let link = store
        .scim_push_links()
        .find(&h.connection, ScimPushResourceType::User, "usr_ada")
        .await
        .expect("find")
        .expect("a link");
    assert_eq!(link.external_id, "usr_ada");

    // AND THE CHECKPOINT IS AT THE LAST EVENT, so a second pass reads nothing.
    let state = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state");
    assert_eq!(state.cursor_sequence, Some(last));
    let second = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await
    .expect("the second pass runs");
    assert_eq!(second.read, 0, "the checkpoint did not stick");
}

#[tokio::test]
async fn an_outage_leaves_the_cursor_where_it_was_and_the_replay_does_not_duplicate() {
    // CRITERION 3, driven rather than argued. The downstream is killed mid-sync and restored, and
    // the assertion is on the END STATE: one resource, not two.
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");
    h.start_tailing_from(0).await;
    enqueue(
        &h.db,
        h.scope,
        "evt_1",
        "user.created",
        json!({ "user_id": "usr_ada", "state": "active" }),
    )
    .await;

    let store = h.db.store().scoped(h.scope);
    let client = h.client();
    let before = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state")
        .cursor_sequence;

    h.downstream.set_health(Health::Down);
    let outcome = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await;
    assert!(
        matches!(outcome, Err(WorkerError::Retryable(_))),
        "an outage must be retryable: {outcome:?}"
    );

    // THE CURSOR DID NOT MOVE. This is the property the whole ordering exists for: the event is
    // still ahead of the checkpoint, so the replay re-reads it.
    let during = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state")
        .cursor_sequence;
    assert_eq!(during, before, "the outage advanced the cursor");

    // RESTORED, AND REPLAYED.
    h.downstream.set_health(Health::Up);
    let recovered = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await
    .expect("the replay converges");
    assert_eq!(recovered.converged, 1);
    assert_eq!(
        h.downstream.users().len(),
        1,
        "the replay duplicated the person: {:?}",
        h.downstream.users()
    );
}

#[tokio::test]
async fn an_out_of_scope_subject_is_never_pushed_and_one_that_leaves_is_withdrawn() {
    // CRITERION 4, both halves, from one rule: whether a link exists says whether this connection
    // ever provisioned the subject.
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");
    h.start_tailing_from(0).await;
    let store = h.db.store().scoped(h.scope);
    let client = h.client();
    let pass = || Pass {
        connection_id: &h.connection,
        client: &client,
        subjects: &directory,
        deletion_policy: DeletionPolicy::Deactivate,
        limit: 50,
        scope: h.scope,
        now_unix_micros: now_micros(&h.env),
        organization_id: h.org.clone(),
    };

    // NEVER IN SCOPE: nothing is sent at all.
    directory.put_out_of_scope("usr_ada");
    enqueue(
        &h.db,
        h.scope,
        "evt_1",
        "user.created",
        json!({ "user_id": "usr_ada", "state": "active" }),
    )
    .await;
    let first = run_tail_pass(&store, pass()).await.expect("pass");
    assert_eq!(first.out_of_scope, 1, "{first:?}");
    assert_eq!(first.converged, 0);
    assert!(
        h.downstream.users().is_empty(),
        "an out-of-scope subject was pushed: {:?}",
        h.downstream.users()
    );

    // NOW IN SCOPE, so it provisions.
    directory.out_of_scope.lock().expect("lock").clear();
    enqueue(
        &h.db,
        h.scope,
        "evt_2",
        "user.updated",
        json!({ "user_id": "usr_ada" }),
    )
    .await;
    let second = run_tail_pass(&store, pass()).await.expect("pass");
    assert_eq!(second.converged, 1);
    assert_eq!(h.downstream.users().len(), 1);

    // AND NOW IT LEAVES SCOPE. Silence here would strand a live account downstream for ever, so
    // the departure is pushed even though the event is an ordinary update.
    directory.put_out_of_scope("usr_ada");
    enqueue(
        &h.db,
        h.scope,
        "evt_3",
        "user.updated",
        json!({ "user_id": "usr_ada" }),
    )
    .await;
    let third = run_tail_pass(&store, pass()).await.expect("pass");
    assert_eq!(
        third.deprovisioned, 1,
        "leaving scope did not withdraw the subject: {third:?}"
    );
    let stored = h.downstream.users();
    let person = stored.values().next().expect("still present");
    assert_eq!(
        person["active"],
        json!(false),
        "the deactivate policy left the account active: {person}"
    );
}

#[tokio::test]
async fn a_cursor_the_feed_has_pruned_past_is_reported_rather_than_silently_restarted() {
    // WHY THIS ARM MATTERS. When a consumer's own position has been pruned, the feed answers
    // `Gone` rather than a page, and there are three things a worker could do with that. Two are
    // wrong: treating it as an empty poll makes the connection sit healthy for ever while it
    // silently skips everything that was pruned, and treating it as retryable spins for ever
    // because retention never un-prunes. The third is to stop and say so, because the decision
    // (re-enumerate, or accept the gap) belongs to an operator.
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");

    let first = enqueue(
        &h.db,
        h.scope,
        "evt_1",
        "user.created",
        json!({ "user_id": "usr_ada", "state": "active" }),
    )
    .await;
    let second = enqueue(
        &h.db,
        h.scope,
        "evt_2",
        "user.updated",
        json!({ "user_id": "usr_ada" }),
    )
    .await;
    let _third = enqueue(
        &h.db,
        h.scope,
        "evt_3",
        "user.updated",
        json!({ "user_id": "usr_ada" }),
    )
    .await;

    // The connection is checkpointed at the first event, and then retention removes it and the
    // one after it.
    h.start_tailing_from(first).await;
    sqlx::query("DELETE FROM outbox_messages WHERE sequence <= $1")
        .bind(second)
        .execute(h.db.owner_pool())
        .await
        .expect("prune");

    let store = h.db.store().scoped(h.scope);
    let client = h.client();
    let outcome = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await;

    match outcome {
        Err(WorkerError::Permanent(why)) => assert!(
            why.contains("pruned"),
            "the refusal must say what happened: {why}"
        ),
        other => panic!("a pruned cursor must stop the pass permanently: {other:?}"),
    }

    // AND NOTHING MOVED. A worker that reported the gap and advanced anyway would have skipped
    // the pruned events, which is the outcome this arm exists to prevent.
    let after = store
        .scim_push_sync_state()
        .get(&h.connection)
        .await
        .expect("get")
        .expect("state");
    assert_eq!(
        after.cursor_sequence,
        Some(first),
        "the pruned pass moved the cursor"
    );
    assert!(
        h.downstream.users().is_empty(),
        "the pruned pass pushed something: {:?}",
        h.downstream.users()
    );
}

#[tokio::test]
async fn a_paused_connection_reads_nothing_and_moves_nothing() {
    let h = Harness::start().await;
    let directory = Directory::with("usr_ada", "ada");
    h.start_tailing_from(0).await;
    enqueue(
        &h.db,
        h.scope,
        "evt_1",
        "user.created",
        json!({ "user_id": "usr_ada", "state": "active" }),
    )
    .await;

    let store = h.db.store().scoped(h.scope);
    store
        .scim_push_sync_state()
        .record_failure(
            &h.connection,
            "downstream answered 503",
            Some(now_micros(&h.env) + 300_000_000),
        )
        .await
        .expect("pause");

    let client = h.client();
    let progress = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: now_micros(&h.env),
            organization_id: h.org.clone(),
        },
    )
    .await
    .expect("a paused pass is not an error");

    assert_eq!(
        progress,
        Progress::default(),
        "a paused pass did work: {progress:?}"
    );
    assert!(
        h.downstream.requests().is_empty(),
        "a paused connection contacted the downstream: {:?}",
        h.downstream.requests()
    );

    // AND IT RESUMES ONCE THE DEADLINE PASSES, with no intervention: that self-clearing property
    // is why the pause is a timestamp and not a flag, and it was untestable while the worker read
    // the system clock. The pass runs AT a moment after the deadline rather than sleeping to
    // reach one.
    let after_the_pause = now_micros(&h.env) + 600_000_000;
    let resumed = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: after_the_pause,
            organization_id: h.org.clone(),
        },
    )
    .await
    .expect("the pass resumes once the pause expires");
    assert_eq!(
        resumed.converged, 1,
        "the connection did not resume after its pause expired: {resumed:?}"
    );
    assert_eq!(h.downstream.users().len(), 1);

    // A MICROSECOND EARLY IS STILL PAUSED. That boundary is what the comparison decides, and it
    // is the half a "does it eventually resume" test cannot see: `>=` and `>` both eventually
    // resume.
    let deadline = now_micros(&h.env) + 900_000_000;
    store
        .scim_push_sync_state()
        .record_failure(&h.connection, "paused again", Some(deadline))
        .await
        .expect("re-pause");
    let just_before = run_tail_pass(
        &store,
        Pass {
            connection_id: &h.connection,
            client: &client,
            subjects: &directory,
            deletion_policy: DeletionPolicy::Deactivate,
            limit: 50,
            scope: h.scope,
            now_unix_micros: deadline - 1,
            organization_id: h.org.clone(),
        },
    )
    .await
    .expect("still paused");
    assert_eq!(
        just_before,
        Progress::default(),
        "a pass one microsecond before the deadline ran anyway: {just_before:?}"
    );
}
