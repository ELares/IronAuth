// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token issuance runs no inline query over the event feed (issue #107, criterion 5).
//!
//! # What already covered this, and what did not
//!
//! `crates/ironauth-store/tests/impersonation_sessions.rs` already carries
//! `a_sign_in_reads_the_event_feed_zero_times`, written for this criterion. It asserts the exact
//! delta of a `FEED_READS` counter that `events_page_after` increments, so it proves the
//! INSTRUMENTED read path is never called on a sign-in or an issuance.
//!
//! What it cannot see is a read that never goes through that function. A hand-rolled
//! `SELECT ... FROM outbox_messages` folded into the redemption bypasses the counter entirely
//! and leaves that test green, because nothing increments it.
//!
//! This file closes that: it captures the ACTUAL SQL the redemption executes and asserts over
//! it. The two are complements, and neither alone is the criterion. Read them together.
//!
//! # What is measured, and how
//!
//! sqlx emits every statement it executes to the `sqlx::query` tracing target, so a subscriber
//! installed around a real token exchange sees the ACTUAL SQL the path runs. The assertion is
//! that none of it READS the event feed.
//!
//! Read, not touch. Issuance WRITES to `outbox_messages`: emitting the event is the whole
//! design, and metering happens later by folding those events. So an INSERT is the correct
//! behaviour and a SELECT is the defect, and the two must be told apart rather than the table
//! avoided.
//!
//! # Why the positive control is not optional
//!
//! An assertion of the form "the capture contains no X" passes just as happily when the
//! capture is empty, when the subscriber never installed, when sqlx logs at a level the filter
//! drops, and when the matcher is simply wrong. Three guards close those:
//!
//!   * the capture must be NON-EMPTY and must contain a statement the path provably runs;
//!   * a deliberate feed READ, executed under the same capture, must be DETECTED by the same
//!     matcher (the positive control);
//!   * the exchange itself must have SUCCEEDED, since a 400 issues no token and runs almost
//!     no SQL.
//!
//! Without the second, this file would pass unchanged against an issuance path that folded
//! usage inline on every login.

mod common;

use axum::http::StatusCode;
use common::{
    Harness, PKCE_CHALLENGE, PKCE_VERIFIER, REDIRECT_URI, enc, form, json, location_param,
};
use std::io::Write;
use std::sync::{Arc, Mutex};

/// A `tracing_subscriber` writer that captures formatted lines into a shared buffer.
#[derive(Clone)]
struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // A poisoned lock here would fail the test for the wrong reason; the buffer holds only
        // log bytes, so recovering it is safe and keeps the failure the one under test.
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// How many sqlx statements the captured text records.
fn statement_count(text: &str) -> usize {
    text.lines()
        .filter(|line| line.contains("sqlx::query"))
        .count()
}

/// The statements captured so far, one per line, lowercased for matching.
fn captured(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    let guard = buffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    String::from_utf8_lossy(&guard).to_lowercase()
}

/// One captured statement, flattened so its SPELLING cannot decide whether it is detected.
///
/// sqlx logs the raw SQL with newlines Debug-escaped, so a statement broken across lines
/// arrives as `from\n         outbox_messages`. Collapsing the escapes and whitespace runs, and
/// dropping a `public.` qualifier, means the same read written three ways normalises to one.
fn flatten(line: &str) -> String {
    line.replace("\\n", " ")
        .replace("\\t", " ")
        .replace("public.", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `text` contains a statement that TOUCHES the event feed other than by appending to
/// it.
///
/// An ALLOWLIST, not a pattern for the defect. The first version paired `select` with the exact
/// bytes `from outbox_messages`, reasoning that direction is what separates emitting from
/// metering. The reasoning was right and the implementation was three-quarters blind: review
/// planted the same inline read schema-qualified (`from public.outbox_messages`), as a join
/// (`from grants g join outbox_messages o on ...`), and line-broken, and ALL THREE passed. Only
/// the one canonical spelling was ever caught.
///
/// So the question is inverted. The only legitimate touch of the feed on this path is the
/// enqueue INSERT, so anything else that mentions the table at all is a finding, whatever verb
/// or shape it wears. That keeps the emit/read distinction the original comment argued for
/// without letting a schema prefix or a line break decide the verdict.
fn touches_the_event_feed_other_than_appending(text: &str) -> bool {
    text.lines().any(|line| {
        let flat = flatten(line);
        flat.contains("outbox_messages") && !flat.contains("insert into outbox_messages")
    })
}

/// How many statements one authorization-code redemption executes.
///
/// A RATCHET, not an observation: move it deliberately and say why in the commit, the same way
/// `MINIMUM_ENTRIES` and the migration chain's applied count are moved.
///
/// # 64 -> 69, issue #113's claim-mapping resolver
///
/// Five statements, and they are one scoped read: `BEGIN`, two `set_config` for the RLS scope,
/// the `SELECT` from `claims_mappings`, `COMMIT`. That is what `begin_scoped` costs, so it is
/// the same shape every other scoped read in the tree has rather than anything this path does
/// unusually.
///
/// MEASURED rather than reasoned: removing only the code-exchange resolver call and re-running
/// this test returns the count to exactly 64. So the five are the resolver and nothing else
/// drifted underneath it.
///
/// It is NOT metering, which is the regression this ratchet exists to catch. The criterion's
/// concern is a counter, a tally, or a materialized view updated on the way through a login --
/// something whose cost grows with what it aggregates and which the feed's async fold exists to
/// avoid. This is a per-client config read whose result shapes the token being minted, on the
/// path that mints it, and whose absence would mean the mapping did not apply.
///
/// The cost is real and worth stating rather than absorbing: five statements on every code
/// exchange, for a feature most clients have not configured. Making it cheaper means either
/// caching per (scope, client) with an invalidation story, or threading the resolver into a
/// transaction the redemption already opens. Both are their own change.
/// 69 -> 71 (#107 criterion 2): the two event inserts a redemption performs each now take
/// the per-scope append lock, and `pg_advisory_xact_lock` is its own statement.
///
/// This is the ratchet working. The cost is a round trip per event insert on the hot path,
/// and per-environment serialisation of event-producing writes from the lock to the commit,
/// which is the price criterion 2 names for ordering that matches commit order. Stated
/// rather than absorbed, because it is the token redemption path.
///
/// It can be bought back. Folding the lock into the insert as
/// `INSERT ... SELECT ... FROM (SELECT pg_advisory_xact_lock($n)) l` takes it in the same
/// statement and returns this to 69, since the lock is then evaluated to produce the source
/// row before the sequence default is computed. It is not done here because it trades an
/// obvious two-statement sequence for a subtle one-statement argument about executor
/// ordering, and this PR's job is the ordering guarantee itself. The three tests that would
/// have to keep passing already exist:
/// `an_event_enqueue_blocks_on_the_per_scope_append_lock` (the lock is taken),
/// `serialising_appenders_on_a_scope_lock_makes_sequence_order_equal_commit_order` (it
/// orders), and this count (the round trip is gone).
const REDEMPTION_STATEMENTS: usize = 71;

/// Redeeming an authorization code touches the event feed ONLY to append to it.
///
/// # What this measures, precisely
///
/// Two things, and neither is the whole criterion. First a query BUDGET: the number of
/// statements the redemption executes is pinned, so ANY added inline work fails here whatever
/// shape it wears -- which is what "a query-count regression test" literally asks for, and the
/// only assertion that catches metering added against a table this file has never heard of.
/// Second, that no captured statement touches `outbox_messages` except to INSERT into it.
///
/// What it does NOT measure is the LOGIN path. The fixture seeds an authenticated session
/// rather than driving a sign-in, so the capture brackets the token exchange only.
/// `a_sign_in_reads_the_event_feed_zero_times` covers the sign-in through the instrumented
/// counter; between them the two halves of "token issuance and login paths" are covered by
/// different mechanisms, and this one is honest about which half it holds.
///
/// The grant choice is load-bearing and was got WRONG first. `client_credentials` is the
/// shortest path that issues a token, and it never meters. A version of this test built on it
/// passed with an inline `SELECT count(*) FROM outbox_messages` planted in the metering
/// producer, because that producer never ran on the path under test.
///
/// Being precise about why, since the first version of this comment was not: THREE grants share
/// the unmetered machine-grant body. Only `client_credentials` is exempt by covenant, enforced
/// by `scripts/no-m2m-metering.sh`; jwt-bearer and token exchange are unmetered pending the
/// owner decision recorded at `repository.rs:10114`. So "the one path that never meters" was
/// wrong on the count and wrong on the reason.
///
/// The authorization-code redemption is the path criterion 5 names, it is user-bound, and it
/// does meter. Verified by planting that read and watching this go red.
#[tokio::test]
async fn redeeming_a_code_runs_no_query_that_reads_the_event_feed() {
    // `set_global_default`, not `set_default`, and this test is ALONE in its binary.
    // `tracing` caches each callsite's `Interest` process-wide the first time it is evaluated,
    // so a sibling test reaching sqlx's callsite first with no subscriber on its thread would
    // cache `Interest::never` and silence it for the whole process. `tests/device.rs` records
    // the same trap, measured. A capture that quietly stops capturing is worse than none.
    let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufferWriter(Arc::clone(&buffer)))
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("this is the only test in this binary that installs a subscriber");

    let harness = Harness::start().await;
    let client_id = harness.client_id().to_string();

    // The feed window opens HERE, after the harness has migrated the database.
    //
    // Review suggested opening it at 0 on the reasoning that none of the fixture's statements
    // are feed reads. Measured, that is false: the migrations themselves name
    // `outbox_messages` -- 0099 creates it, and several carry it in comment text that sqlx logs
    // verbatim -- so a window at 0 fires on schema setup and reports a metering read that is a
    // CREATE TABLE. Opening after migration keeps the /authorize leg inside the window, which
    // is the part worth having, without swallowing the schema.
    let after_migrations = captured(&buffer).len();
    let cookie = harness.authenticated_cookie().await;
    let (status, headers, body) = harness
        .authorize_with_cookie(
            &format!(
                "response_type=code&client_id={client_id}&redirect_uri={}&state=xyz&nonce=n-1&\
                 scope={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
                enc(REDIRECT_URI),
                enc("openid profile"),
            ),
            &cookie,
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize: {body}");
    let code = location_param(&headers, "code").expect("code in redirect");

    // TWO windows, because the two assertions want different things.
    //
    // The FEED assertion spans everything from process start: none of the fixture's statements
    // touch the feed either, so asserting over the whole capture is strictly stronger and has
    // nothing to lose. An offset here would silently exclude whatever ran before it, and the
    // /authorize leg is exactly what gets excluded by accident.
    //
    // The BUDGET spans the redemption alone, marked just below. Counting the fixture's
    // statements would pin harness startup and migrations, which are not the property and would
    // make the number meaningless.
    let redemption_start = captured(&buffer).len();
    let (status, _headers, body) = harness
        .token(&form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", PKCE_VERIFIER),
        ]))
        .await;
    let after = captured(&buffer);
    // The authorize leg plus the redemption: everything this test drives, minus the schema.
    let driven = after[after_migrations..].to_owned();
    let redemption = after[redemption_start..].to_owned();

    // GUARD 1: the redemption SUCCEEDED. A refused one issues no token and runs almost no SQL,
    // which would make every assertion below true and meaningless.
    assert_eq!(status, StatusCode::OK, "code redemption: {body}");
    assert!(
        json(&body)["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty()),
        "a token was actually issued: {body}"
    );

    // GUARD 2: the capture SAW the path. sqlx logs every statement to `sqlx::query`, so an
    // empty slice here means the subscriber never took effect, not that issuance is
    // query-free.
    assert!(
        redemption.contains("sqlx::query"),
        "the capture must contain sqlx statements, or it is measuring nothing. Captured {} \
         bytes during the redemption.",
        redemption.len()
    );

    // GUARD 3: the METERING PRODUCER ran. This is the guard the first version of this test
    // lacked, and it is the one that matters: without it, a path that never meters passes
    // trivially, which is exactly what `client_credentials` did. A `token.issued` event
    // written to the outbox proves the producer executed on this path.
    assert!(
        redemption.contains("insert into outbox_messages"),
        "the redemption must have EMITTED its metering event, or this test is measuring a \
         path that does no metering at all:\n{redemption}"
    );

    // THE CRITERION, first half: a QUERY BUDGET. "A query-count regression test" is what the
    // criterion asks for, and a count is the only assertion that catches metering added against
    // a table this file has never heard of -- a counter row, a materialized view, anything. The
    // feed-shaped assertion below cannot see those; this can.
    //
    // An EXACT pin, and a band was tried first. 40..=90 tolerated twenty-six extra statements,
    // which means it would NOT have caught a single added counter UPDATE -- the very shape this
    // file's header claims to guard. A budget that cannot see +1 is not a budget.
    //
    // So it is a RATCHET, the same shape as `MINIMUM_ENTRIES` and the migration chain's
    // `already_applied` count: a number you must move deliberately, with the reason in the
    // commit. That is the cost of an assertion that actually catches one added statement.
    let statements = statement_count(&redemption);
    assert_eq!(
        statements, REDEMPTION_STATEMENTS,
        "the redemption executed {statements} statements rather than {REDEMPTION_STATEMENTS}. \
         If this is legitimate drift, move the constant and say why in the commit; if it is \
         metering folded into the issuance path, that is the regression criterion 5 exists to \
         catch. A count is the only assertion here that sees metering added against a table \
         this file has never heard of."
    );

    // Second half: the feed itself. Issuance may APPEND to it (that is the event being emitted);
    // anything else that touches it is folding usage inline.
    assert!(
        !touches_the_event_feed_other_than_appending(&driven),
        "token issuance executed a query against the event feed other than appending to it, so \
         metering is no longer asynchronous: usage.rs claims 'nothing here runs during a \
         login'. Statements:\n{driven}"
    );

    // GUARD 4 (the positive control): the matcher can DETECT a feed read. Without this the
    // assertion above passes against a broken matcher, a dropped log level, or a capture that
    // silently stopped.
    let mark = captured(&buffer).len();
    // Deliberately MORE than four words and carrying a bind, so it takes the same logging path
    // every production statement takes: sqlx's summary is the first four words, and anything
    // longer is truncated with the full SQL moved into `db.statement`. A short control exercises
    // a shape production never emits, so it could keep passing while the real detection went
    // dead.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM outbox_messages WHERE tenant_id = $1")
            .bind(harness.scope().tenant().to_string())
            .fetch_one(harness.db().owner_pool())
            .await
            .expect("the control query runs");
    let control = captured(&buffer)[mark..].to_owned();
    assert!(
        control.contains("db.statement=\"\\n\\nselect"),
        "the control must be logged through the TRUNCATED-summary path, or it is not exercising \
         what production statements exercise and a sqlx reformat would disarm the assertion \
         above silently:\n{control}"
    );
    assert!(
        touches_the_event_feed_other_than_appending(&control),
        "the positive control must be DETECTED, or the assertion above proves nothing. A read \
         of the feed returning {count} rows produced:\n{control}"
    );
}
