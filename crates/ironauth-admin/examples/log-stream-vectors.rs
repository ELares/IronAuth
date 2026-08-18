// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit the log-stream signature conformance corpus (issue #110 criterion 5).
//!
//! The corpus is GENERATED from the Rust implementation rather than written by hand, for the
//! reason `scripts/event-catalog.sh` generates the event catalog: two implementations that
//! agree on a corpus somebody typed out agree only about that person's understanding. These
//! vectors are what the shipped signer actually produces, so a sample consumer that passes
//! them agrees with the code, not with a document about the code.
//!
//! Every vector carries its own `expect`, so the corpus states what should happen rather than
//! leaving a consumer to infer it from whether a case looks adversarial.

use ironauth_admin::log_stream_signature::{canonical_string, sign};
use serde_json::json;

// The length is a DATA TABLE, not logic: one entry per adversarial substitution, each with
// the reason it exists. Splitting it to satisfy the line count would scatter a table whose
// whole value is being read top to bottom in one place.
#[allow(clippy::too_many_lines)]
fn main() {
    // A fixed key, because the corpus is a CONFORMANCE artifact and not a secret: it exists
    // so two implementations can be compared, and a random key would make the file churn on
    // every regeneration and its diff unreadable.
    let key = b"ironauth-log-stream-conformance-key";
    let events = r#"[{"class_uid":3002,"activity_id":1,"time":1735689600000}]"#;
    let two_events = r#"[{"class_uid":3002,"activity_id":1},{"class_uid":3002,"activity_id":2}]"#;

    let base = canonical_string("lst_conformance", 7, "out_00000000", 1, events);
    let signature = sign(key, &base);

    let mut vectors = vec![json!({
        "name": "a well formed batch verifies",
        "why": "the happy path, so a consumer that fails everything is not mistaken for a \
                strict one",
        "stream_id": "lst_conformance",
        "cursor_sequence": 7,
        "cursor_id": "out_00000000",
        "event_count": 1,
        "events_json": events,
        "signature": signature,
        "expect": "verify",
    })];

    // Each field, substituted one at a time. The signature stays the ORIGINAL one throughout:
    // that is what makes each case a real forgery attempt rather than a re-signing.
    for (name, why, stream, seq, cursor, count, body) in [
        (
            "a batch lifted into another stream is refused",
            "two streams may share a key; the stream id is what stops a batch moving between \
             them",
            "lst_other",
            7_i64,
            "out_00000000",
            1_usize,
            events,
        ),
        (
            "a replayed position is refused",
            "the cursor sequence is monotonic per stream, so a position already seen is a \
             replay and must not verify",
            "lst_conformance",
            6,
            "out_00000000",
            1,
            events,
        ),
        (
            "a different cursor id is refused",
            "the position is a pair; signing only the sequence would let the id be rewritten",
            "lst_conformance",
            7,
            "out_ffffffff",
            1,
            events,
        ),
        (
            "a miscounted batch is refused",
            "the count is redundant for integrity and kept for diagnosis: a consumer can say \
             whether it got a different NUMBER of events or the same number with different \
             content",
            "lst_conformance",
            7,
            "out_00000000",
            2,
            events,
        ),
        (
            "tampered events are refused",
            "the integrity case: same count, different content",
            "lst_conformance",
            7,
            "out_00000000",
            1,
            two_events,
        ),
    ] {
        vectors.push(json!({
            "name": name,
            "why": why,
            "stream_id": stream,
            "cursor_sequence": seq,
            "cursor_id": cursor,
            "event_count": count,
            "events_json": body,
            "signature": signature,
            "expect": "refuse",
        }));
    }

    // A signature that is not hex at all. A verifier must answer FALSE rather than throw:
    // one that throws on malformed input hands a caller a denial of service in place of a
    // refusal, and this is the case a hand-written consumer most often gets wrong.
    vectors.push(json!({
        "name": "a malformed signature is refused, not thrown on",
        "why": "a verifier that throws on bad input is a denial of service, not a verifier",
        "stream_id": "lst_conformance",
        "cursor_sequence": 7,
        "cursor_id": "out_00000000",
        "event_count": 1,
        "events_json": events,
        "signature": "not-hex-at-all",
        "expect": "refuse",
    }));

    let corpus = json!({
        "canonical_version": ironauth_admin::log_stream_signature::CANONICAL_VERSION,
        "algorithm": "HMAC-SHA256",
        "key_utf8": String::from_utf8_lossy(key),
        "note": "Generated by `cargo run -p ironauth-admin --example log-stream-vectors`. \
                 Do not edit by hand: it is what the shipped signer produces.",
        "vectors": vectors,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&corpus).expect("the corpus serializes")
    );
}
