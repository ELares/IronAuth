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
use ironauth_admin::scim_push_worker::{Pass, Progress, SubjectSource, WorkerError, run_tail_pass};
use ironauth_env::Env;
use ironauth_scim::downstream::{Downstream, Health};
use ironauth_store::test_support::TestDatabase;
use ironauth_store::{
    CorrelationId, EventCursor, NewScimPushConnection, OrganizationId, ScimDeletionPolicy,
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
async fn enqueue(
    db: &TestDatabase,
    scope: Scope,
    id: &str,
    event_type: &str,
    payload: Value,
) -> i64 {
    let envelope = json!({
        "type": event_type,
        "payload": payload,
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
    downstream: Downstream,
}

impl Harness {
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
            downstream: Downstream::new(TOKEN),
        }
    }

    /// Marks the backfill done and puts the cursor at the feed's current head.
    async fn start_tailing_from(&self, sequence: i64) {
        let store = self.db.store().scoped(self.scope);
        store
            .scim_push_sync_state()
            .begin_backfill(&self.connection)
            .await
            .expect("begin");
        store
            .scim_push_sync_state()
            .complete_backfill(
                &self.connection,
                &EventCursor::after_sequence(sequence).to_wire(),
            )
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
    assert_eq!(
        state.cursor.as_deref(),
        Some(EventCursor::after_sequence(last).to_wire().as_str())
    );
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
        .cursor;

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
        .cursor;
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
        after.cursor.as_deref(),
        Some(EventCursor::after_sequence(first).to_wire().as_str()),
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
