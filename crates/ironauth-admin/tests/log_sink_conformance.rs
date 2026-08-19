// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared sink conformance suite (issue #110).
//!
//! Every sink behind [`LogSink`] is held to the SAME properties, driven from one table, so
//! a sink added later is covered by construction rather than by whoever adds it
//! remembering to write these five tests again. A per-sink test file is how the fourth
//! adapter ends up with two of the checks and nobody notices which two.
//!
//! These run without a socket. What they cover is the part that is wrong before a request
//! is ever made: refusing a misconfiguration instead of sending a doomed request, and
//! never putting the credential into a reason that is stored and read back.

use std::sync::Arc;

use ironauth_admin::log_shipper::{
    DatadogSink, HttpLogSink, LogSink, S3LogSink, SinkOutcome, SplunkHecSink, datadog_body,
    s3_batch_metadata, signed_batch_headers, splunk_body,
};
use ironauth_store::log_stream::{LogStreamRecord, SinkType, StreamHealth, StreamSource};
use serde_json::{Value, json};

/// A token no legitimate reason string would ever contain, so finding it in one is proof
/// the credential leaked rather than a coincidence.
const CANARY: &str = "canary-secret-do-not-log-8f2a1c";

fn fetcher() -> Arc<ironauth_fetch::Fetcher> {
    Arc::new(ironauth_fetch::Fetcher::for_tests(
        ironauth_fetch::FetchLimits::default(),
    ))
}

/// Every sink under test, behind the common interface.
fn sinks() -> Vec<(SinkType, Arc<dyn LogSink>)> {
    vec![
        (SinkType::Http, Arc::new(HttpLogSink::new(fetcher()))),
        (SinkType::Datadog, Arc::new(DatadogSink::new(fetcher()))),
        (SinkType::SplunkHec, Arc::new(SplunkHecSink::new(fetcher()))),
        (
            SinkType::S3,
            Arc::new(S3LogSink::new(fetcher(), ironauth_env::Env::system())),
        ),
    ]
}

fn stream(sink_type: SinkType, sink_config: Value) -> LogStreamRecord {
    LogStreamRecord {
        id: "lgs_conformance".to_string(),
        description: String::new(),
        source: StreamSource::Both,
        sink_type,
        sink_config,
        credential_secret_name: None,
        signing_secret_name: None,
        event_type_filter: None,
        organization_id: None,
        active: true,
        cursor: None,
        health: StreamHealth::default(),
    }
}

/// A `sink_config` that satisfies THIS sink's shape requirements.
///
/// Per sink, because a shared fixture makes the credential assertions pass for the wrong
/// reason: S3 needs a bucket as well as an endpoint, so with an endpoint-only config it
/// refuses for the missing bucket before it ever looks at the credential, and the test
/// would report the credential rule as enforced without having exercised it.
fn complete_config(sink_type: SinkType) -> Value {
    match sink_type {
        SinkType::S3 => json!({
            "endpoint": "https://s3.example",
            "bucket": "audit",
            "region": "us-east-1",
        }),
        _ => json!({ "endpoint": "https://sink.example/in" }),
    }
}

fn events() -> Vec<Value> {
    vec![json!({"class_uid": 3004, "activity_name": "client.create", "uid": "aud_1"})]
}

/// Every sink reports the type it is registered under.
///
/// The shipper matches a stream to a sink on this value, so a sink that misreports it is
/// silently never selected, and its stream reports "no sink implementation" forever.
#[tokio::test]
async fn every_sink_reports_its_own_type() {
    for (expected, sink) in sinks() {
        assert_eq!(
            sink.sink_type(),
            expected,
            "a sink that misreports its type is never selected by the shipper"
        );
    }
}

/// Every sink REFUSES a stream with no endpoint rather than sending somewhere.
#[tokio::test]
async fn every_sink_refuses_a_stream_with_no_endpoint() {
    for (sink_type, sink) in sinks() {
        let configured = stream(sink_type, json!({}));
        let outcome = sink
            .deliver(
                &configured,
                Some(CANARY),
                &events(),
                None,
                (1, "aud_fixture"),
            )
            .await;
        assert!(
            matches!(outcome, SinkOutcome::Rejected(_)),
            "{} accepted a batch with no endpoint configured",
            sink_type.as_str()
        );
    }
}

/// A vendor sink REFUSES when it has no credential, rather than sending an
/// unauthenticated batch that cannot succeed.
///
/// Datadog and Splunk both reject unauthenticated intake, so sending anyway spends a
/// retry budget on a request that was never going to work, and the operator sees a
/// transport-shaped failure rather than the configuration mistake it is.
#[tokio::test]
async fn a_vendor_sink_refuses_without_a_credential() {
    for (sink_type, sink) in sinks() {
        if sink_type == SinkType::Http {
            // The plain HTTP sink authenticates however the operator's endpoint does, so
            // a missing credential is not on its own a misconfiguration.
            continue;
        }
        let configured = stream(sink_type, complete_config(sink_type));
        let outcome = sink
            .deliver(&configured, None, &events(), None, (1, "aud_fixture"))
            .await;
        match outcome {
            SinkOutcome::Rejected(reason) => assert!(
                reason.contains("credential_secret_name"),
                "{} must name the missing setting: {reason}",
                sink_type.as_str()
            ),
            SinkOutcome::Accepted => {
                panic!("{} accepted an unauthenticated batch", sink_type.as_str())
            }
        }
    }
}

/// No sink ever puts the credential into the reason it returns.
///
/// This is the secret-handling criterion, and it is checked at the interface rather than
/// per sink because the reason is STORED on the stream row and read back through a status
/// API. A credential in a reason is a credential in an operator's console and in whatever
/// scrapes it.
///
/// The UNSENDABLE credential is the case that matters and the first version of this test
/// missed it. With a well-formed credential every sink fails at DNS with a message that
/// never mentions it, so the assertion held for a reason unrelated to what it claimed to
/// check: a mutation interpolating the value into the header-encoding failure SURVIVED.
/// A credential containing a newline cannot become a header value, which forces that
/// branch to run, and that branch is exactly where a naive implementation says which
/// value would not encode.
#[tokio::test]
async fn no_sink_leaks_the_credential_into_its_reason() {
    let unsendable = format!("{CANARY}\nx");
    for (sink_type, sink) in sinks() {
        for credential in [CANARY.to_string(), unsendable.clone()] {
            // Both shapes: a stream that cannot resolve an endpoint, and one that can and
            // so reaches the transport, since the reason is built on both paths.
            for config in [json!({}), complete_config(sink_type)] {
                let configured = stream(sink_type, config);
                let outcome = sink
                    .deliver(
                        &configured,
                        Some(credential.as_str()),
                        &events(),
                        None,
                        (1, "aud_fixture"),
                    )
                    .await;
                if let SinkOutcome::Rejected(reason) = outcome {
                    assert!(
                        !reason.contains(CANARY),
                        "{} leaked the credential into a stored reason: {reason}",
                        sink_type.as_str()
                    );
                }
            }
        }
    }
}

/// The header-encoding refusal is REACHED by an unsendable credential.
///
/// Without this, the leak test above could go back to passing vacuously: if no input ever
/// drove a sink into that branch, "the reason does not contain the credential" would be
/// true of a branch that never runs.
#[tokio::test]
async fn an_unsendable_credential_is_refused_at_the_header() {
    let sink = SplunkHecSink::new(fetcher());
    let configured = stream(
        SinkType::SplunkHec,
        json!({"endpoint": "https://sink.invalid/in"}),
    );
    let outcome = sink
        .deliver(
            &configured,
            Some(&format!("{CANARY}\nx")),
            &events(),
            None,
            (1, "aud_fixture"),
        )
        .await;
    match outcome {
        SinkOutcome::Rejected(reason) => assert!(
            reason.contains("header"),
            "the refusal must name the header encoding, so the leak test is exercising \
             that branch: {reason}"
        ),
        SinkOutcome::Accepted => panic!("an unsendable credential must never be accepted"),
    }
}

// ===========================================================================
// Body shapes. These are the vendor-specific parts, and getting one wrong fails as an
// opaque 400 that reads like a credential problem.

/// Datadog takes a JSON ARRAY of envelopes carrying the OCSF event whole.
#[test]
fn the_datadog_body_is_an_array_carrying_the_event() {
    let body = datadog_body(&events());
    let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
    let array = parsed.as_array().expect("datadog takes an array");
    assert_eq!(array.len(), 1);
    assert_eq!(array[0]["ddsource"], "ironauth");
    assert_eq!(
        array[0]["message"]["uid"], "aud_1",
        "the OCSF event must be carried whole, not flattened away"
    );
}

/// Splunk HEC takes NEWLINE-DELIMITED objects and REJECTS a JSON array.
///
/// This is the difference most likely to be got wrong, because an array is what every
/// other sink here wants.
#[test]
fn the_splunk_body_is_newline_delimited_and_not_an_array() {
    let two = vec![
        json!({"uid": "aud_1", "class_uid": 3004}),
        json!({"uid": "aud_2", "class_uid": 3002}),
    ];
    let body = splunk_body(&two, None);
    assert!(
        serde_json::from_str::<Value>(&body).is_err(),
        "a HEC body must NOT parse as one JSON value; that would mean it is an array or \
         a single object, both of which HEC rejects: {body}"
    );
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "one line per event");
    for (line, expected) in lines.iter().zip(["aud_1", "aud_2"]) {
        let parsed: Value = serde_json::from_str(line).expect("each line is one object");
        assert_eq!(parsed["event"]["uid"], expected);
        assert_eq!(parsed["sourcetype"], "ironauth:ocsf");
        assert!(
            parsed.get("index").is_none(),
            "no index must be emitted when none is configured, or HEC routes to a index \
             the operator did not choose"
        );
    }
}

/// A configured index is carried per event, which is where HEC takes it.
#[test]
fn a_configured_splunk_index_is_carried_on_every_event() {
    let body = splunk_body(&events(), Some("ironauth_audit"));
    let parsed: Value = serde_json::from_str(body.lines().next().expect("a line")).expect("JSON");
    assert_eq!(parsed["index"], "ironauth_audit");
}

/// An empty batch produces a body every sink can send without special casing.
#[test]
fn an_empty_batch_produces_a_well_formed_body() {
    assert_eq!(datadog_body(&[]), "[]");
    assert_eq!(splunk_body(&[], None), "");
}

/// A signed batch carries its POSITION beside its signature, or nothing can verify it
/// (issue #110 criterion 5).
///
/// # Why this test exists
///
/// `POSITION_HEADER` was defined, documented as "sent BESIDE the signature", and sent by
/// nothing: the entire workspace held one reference to it, its own `pub const`. The `LogSink`
/// trait did not carry the position at all, so no sink could have sent it.
///
/// That made the signed stream INERT. The signature covers
/// `(stream id, sequence, cursor id, count, digest)` and only the last two are derivable from
/// the payload, so a consumer holding the body and the signature could not rebuild the
/// canonical string, and therefore could not verify it, detect a gap, or detect a replay. The
/// shipper spent an HMAC per batch that nothing could check.
///
/// The signature header had no test either, which is how both went unnoticed for so long.
///
/// This pins the VALUES, not the presence. A header carrying the wrong position verifies
/// nothing while looking correct, and the position is the half a consumer cannot cross-check
/// against the payload.
#[test]
fn a_signed_batch_carries_the_position_its_signature_covers() {
    let headers = signed_batch_headers("lgs_stream", Some("deadbeefcafe"), (4242, "aud_01J8ZQ"));
    assert_eq!(
        headers,
        vec![
            ("x-ironauth-log-signature", "deadbeefcafe".to_string()),
            (
                "x-ironauth-log-position",
                "lgs_stream 4242 aud_01J8ZQ".to_string()
            ),
        ],
        "a signed batch ships the signature AND the position it covers"
    );
}

/// An UNSIGNED batch carries neither header.
///
/// The pair is meaningless without a signing secret, and a position header on an unsigned
/// batch would tell a consumer there is something to verify when there is not.
#[test]
fn an_unsigned_batch_carries_no_signature_and_no_position() {
    assert!(
        signed_batch_headers("lgs_stream", None, (4242, "aud_01J8ZQ")).is_empty(),
        "an unsigned batch must not advertise a position to verify against"
    );
}

/// The S3 sink's object metadata carries the signature AND the position (issue #110).
///
/// # Why this exists as a unit test rather than a wire test
///
/// The S3 metadata is built twice: once into the `SigV4` canonical headers that get signed,
/// and once onto the outgoing request. Review mutated each half independently and both
/// survived the suite, because the two lists were built separately: it was possible to sign
/// metadata that was not sent, or send metadata that was not signed, and nothing noticed.
///
/// The fix is that both halves now call one function, so the two cannot diverge and deleting
/// the position is a single edit in one place. This pins that function by value, which is the
/// same shape that already catches the HTTP-side header pair.
#[test]
fn an_s3_batch_carries_the_signature_and_position_as_object_metadata() {
    let metadata = s3_batch_metadata("lgs_stream", Some("deadbeefcafe"), (4242, "aud_01J8ZQ"));
    assert_eq!(
        metadata,
        vec![
            (
                "x-amz-meta-ironauth-log-signature",
                "deadbeefcafe".to_string()
            ),
            (
                "x-amz-meta-ironauth-log-position",
                "lgs_stream 4242 aud_01J8ZQ".to_string()
            ),
        ],
        "an object has no headers once written, so both travel as metadata or a consumer \
         reading the bucket cannot verify"
    );
}

/// An UNSIGNED S3 batch carries neither metadata key, for the same reason the HTTP pair is
/// absent: advertising a position to verify against when there is nothing to verify is worse
/// than silence.
#[test]
fn an_unsigned_s3_batch_carries_no_metadata() {
    assert!(s3_batch_metadata("lgs_stream", None, (4242, "aud_01J8ZQ")).is_empty());
}
