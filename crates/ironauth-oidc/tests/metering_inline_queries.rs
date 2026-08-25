// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token issuance runs NO metering query inline (issue #107, acceptance criterion 5).
//!
//! `crates/ironauth-admin/src/usage.rs` opens by asserting this:
//!
//! > "#107 wants metering 'computed asynchronously off the stream ... with export via API',
//! > and the *asynchronously* matters as much as the numbers: **nothing here runs during a
//! > login**."
//!
//! Until this file, that was a sentence. The property is true by CONSTRUCTION -- there is no
//! metering counter table at all, and `UsageTally` is folded from the event feed at export
//! time -- but nothing measured it, so a change that added an inline counter update to the
//! issuance path would have contradicted the module's own first paragraph with every test
//! still green. That is the shape criterion 5 exists to close.
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

/// The statements captured so far, one per line, lowercased for matching.
fn captured(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    let guard = buffer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    String::from_utf8_lossy(&guard).to_lowercase()
}

/// Whether `text` contains a statement that READS the event feed.
///
/// `outbox_messages` is written by issuance (that is the event being emitted) and read by the
/// usage fold, so the direction is what distinguishes them. Matching on the pairing of a
/// `select` with a `from outbox_messages` rather than on the table alone is what makes this a
/// question about metering rather than about the table.
fn reads_the_event_feed(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line.contains("select") && line.contains("from outbox_messages")
    })
}

/// AC5: redeeming an authorization code executes no query that reads the event feed.
///
/// The grant choice is load-bearing and was got WRONG first. `client_credentials` is the
/// shortest path that issues a token, and it is the one path that never meters: the machine
/// grant is exempt from `tokens_issued` BY COVENANT, so it does not call `meter_token_issued`
/// at all. A version of this test built on it passed with an inline `SELECT count(*) FROM
/// outbox_messages` planted in the metering producer, because that producer never ran.
///
/// The authorization-code redemption is the path criterion 5 actually names, and it is
/// user-bound, so it does meter. Verified by planting exactly that read and watching this go
/// red.
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

    // Everything above this line is fixture. Only the REDEMPTION below is the path under test.
    let before = captured(&buffer).len();
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
    let issuance = after[before..].to_owned();

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
        issuance.contains("sqlx::query"),
        "the capture must contain sqlx statements, or it is measuring nothing. Captured {} \
         bytes during the redemption.",
        issuance.len()
    );

    // GUARD 3: the METERING PRODUCER ran. This is the guard the first version of this test
    // lacked, and it is the one that matters: without it, a path that never meters passes
    // trivially, which is exactly what `client_credentials` did. A `token.issued` event
    // written to the outbox proves the producer executed on this path.
    assert!(
        issuance.contains("insert into outbox_messages"),
        "the redemption must have EMITTED its metering event, or this test is measuring a \
         path that does no metering at all:\n{issuance}"
    );

    // THE CRITERION. Issuance may WRITE the feed (that is the event being emitted); it must
    // never READ it, because reading is what folding usage inline would look like.
    assert!(
        !reads_the_event_feed(&issuance),
        "token issuance executed a query that READS the event feed, so metering is no longer \
         asynchronous: usage.rs claims 'nothing here runs during a login'. \
         Statements:\n{issuance}"
    );

    // GUARD 4 (the positive control): the matcher can DETECT a feed read. Without this the
    // assertion above passes against a broken matcher, a dropped log level, or a capture that
    // silently stopped.
    let mark = captured(&buffer).len();
    let count: i64 = sqlx::query_scalar("SELECT count(*)::bigint FROM outbox_messages")
        .fetch_one(harness.db().owner_pool())
        .await
        .expect("the control query runs");
    let control = captured(&buffer)[mark..].to_owned();
    assert!(
        reads_the_event_feed(&control),
        "the positive control must be DETECTED, or the assertion above proves nothing. A read \
         of the feed returning {count} rows produced:\n{control}"
    );
}
