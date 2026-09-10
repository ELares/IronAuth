// SPDX-License-Identifier: MIT OR Apache-2.0

//! SSF 1.0 add-subject and remove-subject (issue #143).
//!
//! # What this owes
//!
//! #143 asks for "per-stream subject filtering (add/remove subjects where the stream config
//! requests it)". The properties that matter are the ones a receiver and an operator each
//! depend on and cannot verify from outside:
//!
//! - the list is PER STREAM and fenced on the receiver. A subject added to one stream must not
//!   appear on another's, and another receiver must not be able to add to, remove from, or
//!   learn about a stream that is not its;
//! - the identifier is SEALED at rest and keyed by a blind index that also binds the stream, so
//!   a database dump neither names the subject nor lets one receiver test whether a neighbour
//!   is watching somebody it knows;
//! - a subject added under one JSON member order is the SAME subject when removed under
//!   another, because the key is derived from the parsed identifier rather than the request
//!   bytes;
//! - `verified` is recorded and not acted on.
//!
//! # Nothing reads the list yet, and that is deliberate
//!
//! The fan-out that consults it lands with the CAEP and RISC vocabularies (issue #144), which
//! is the same staging `queue` and `enqueue_push` shipped under. What this suite pins is the
//! surface and the store, so that fan-out has something true to build on.

#![cfg(feature = "testing")]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::Harness;
use ironauth_oidc::ClientAuthMethod;
use ironauth_store::{
    ClientId, CorrelationId, NewSsfStream, SsfDelivery, SsfStreamId, SsfSubjectFormat, StoreError,
};

fn basic(client_id: &ClientId, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

async fn provision_envelope(harness: &Harness, env: &ironauth_env::Env) {
    let acting = harness
        .db()
        .store()
        .scoped(harness.scope())
        .acting(harness.db().test_actor(env), CorrelationId::generate(env));
    for (label, outcome) in [
        (
            "kek",
            acting
                .envelope()
                .provision_kek(env, &harness.db().master_key())
                .await
                .map(|_| ()),
        ),
        (
            "dek",
            acting
                .envelope()
                .provision_dek(env, &harness.db().master_key())
                .await
                .map(|_| ()),
        ),
    ] {
        match outcome {
            Ok(()) | Err(StoreError::Conflict) => {}
            Err(error) => panic!("provision the scope {label}: {error:?}"),
        }
    }
}

async fn stream_for(harness: &Harness, client: &ClientId) -> SsfStreamId {
    let env = harness.state().env().clone();
    let scope = harness.scope();
    provision_envelope(harness, &env).await;
    let id = SsfStreamId::generate(&env, &scope);
    let audience = vec!["https://receiver.example.com".to_owned()];
    let none: Vec<String> = Vec::new();
    harness
        .db()
        .store()
        .scoped(scope)
        .acting(harness.db().test_actor(&env), CorrelationId::generate(&env))
        .ssf_streams()
        .create(
            &env,
            NewSsfStream {
                id: &id,
                client_id: client,
                delivery: &SsfDelivery::Poll,
                events_requested: &none,
                events_delivered: &none,
                subject_format: SsfSubjectFormat::Email,
                audience: &audience,
                description: None,
            },
            20,
            None,
        )
        .await
        .expect("seed a stream");
    id
}

async fn post(
    harness: &Harness,
    path: &str,
    auth: Option<&str>,
    body: String,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!(
            "/t/{}/e/{}{path}",
            harness.scope().tenant(),
            harness.scope().environment()
        ))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = auth {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    let request = builder.body(Body::from(body)).expect("request builds");
    let (status, _headers, text) = harness.send(request).await;
    (status, text)
}

fn email(address: &str) -> serde_json::Value {
    serde_json::json!({ "format": "email", "email": address })
}

async fn subjects_of(harness: &Harness, stream: &SsfStreamId) -> Vec<String> {
    harness
        .db()
        .store()
        .scoped(harness.scope())
        .ssf_stream_subjects()
        .list(stream, 100)
        .await
        .expect("list the subjects")
        .into_iter()
        .map(|subject| subject.rendered)
        .collect()
}

/// A receiver adds a subject, sees it stored, and removes it again.
///
/// READ THROUGH THE STORE rather than through a listing endpoint, because SSF defines no
/// endpoint that returns the subject list: the only way to know the add did anything is to look
/// at what it wrote.
#[tokio::test]
async fn a_receiver_adds_and_removes_a_subject_on_its_own_stream() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    let body = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email("alice@example.test"),
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), body).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        subjects_of(&harness, &stream).await,
        vec!["{\"email\":\"alice@example.test\",\"format\":\"email\"}".to_owned()],
        "the add stored nothing, or stored something else"
    );

    let body = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email("alice@example.test"),
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/remove", Some(&auth), body).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    assert!(
        subjects_of(&harness, &stream).await.is_empty(),
        "the removal left the subject on the list"
    );
}

/// A repeated add is the same row, and refreshes only what the receiver asserted.
///
/// SSF has a repeated add SUCCEED rather than conflict, so this pins both halves: the same 200,
/// and one row rather than two.
#[tokio::test]
async fn adding_the_same_subject_twice_is_one_row_and_refreshes_verified() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    for verified in [false, true] {
        let body = serde_json::json!({
            "stream_id": stream.to_string(),
            "subject": email("bob@example.test"),
            "verified": verified,
        })
        .to_string();
        let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "add with verified={verified}: {text}"
        );
    }

    let stored = harness
        .db()
        .store()
        .scoped(harness.scope())
        .ssf_stream_subjects()
        .list(&stream, 100)
        .await
        .expect("list");
    assert_eq!(stored.len(), 1, "a repeated add created a second row");
    assert!(
        stored[0].verified,
        "the second add did not refresh the receiver's assertion"
    );
}

/// `verified` is RECORDED, not defaulted.
///
/// The column DEFAULTs to true, so a suite that only ever observes a `true` cannot tell the
/// stored value from the default: hard-coding the bind to `true`, or dropping the request member
/// entirely, would pass. This drives a `false` and reads it back, and then drives the OMITTED
/// case, which section 8.1.4 says means true.
#[tokio::test]
async fn verified_is_stored_as_sent_and_defaults_to_true_only_when_omitted() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    let unverified = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email("unverified@example.test"),
        "verified": false,
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), unverified).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    let omitted = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email("assumed@example.test"),
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), omitted).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    let stored = harness
        .db()
        .store()
        .scoped(harness.scope())
        .ssf_stream_subjects()
        .list(&stream, 100)
        .await
        .expect("list");
    let by_address: std::collections::HashMap<&str, bool> = stored
        .iter()
        .map(|subject| (subject.rendered.as_str(), subject.verified))
        .collect();
    let unverified_key = "{\"email\":\"unverified@example.test\",\"format\":\"email\"}";
    let omitted_key = "{\"email\":\"assumed@example.test\",\"format\":\"email\"}";
    assert_eq!(
        by_address.get(unverified_key),
        Some(&false),
        "a subject the receiver said it had NOT verified was stored as verified: {stored:?}"
    );
    assert_eq!(
        by_address.get(omitted_key),
        Some(&true),
        "an omitted verified was not treated as true"
    );
}

/// Neither endpoint answers without a credential, and the answer carries a challenge.
///
/// The two conformance rows credit this suite with the credential fence and nothing drove it.
/// It also pins the SHAPE: these endpoints answered the uniform not-found, which dropped the
/// `WWW-Authenticate` header that tells a client how to authenticate and disagreed with the
/// eight sibling SSF handlers.
#[tokio::test]
async fn neither_endpoint_answers_without_a_credential() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, _) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let stream = stream_for(&harness, &client).await;

    for path in ["/ssf/subjects/add", "/ssf/subjects/remove"] {
        let body = serde_json::json!({
            "stream_id": stream.to_string(),
            "subject": email("nobody@example.test"),
        })
        .to_string();
        let request = Request::builder()
            .method("POST")
            .uri(format!(
                "/t/{}/e/{}{path}",
                harness.scope().tenant(),
                harness.scope().environment()
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("request builds");
        let (status, headers, text) = harness.send(request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{path} answered an uncredentialed request with something else: {text}"
        );
        assert!(
            headers.get(header::WWW_AUTHENTICATE).is_some(),
            "{path} refused without telling the client how to authenticate"
        );
    }
    assert!(
        subjects_of(&harness, &stream).await.is_empty(),
        "an uncredentialed request wrote to the subject list"
    );
}

/// A rendering longer than the store holds is a 400, not a 500.
///
/// The door bounded the PLAINTEXT at one number while the column bounded the CIPHERTEXT at the
/// same number, and a seal is the plaintext plus twenty-eight bytes. So a rendering in the gap
/// passed the door and violated the CHECK, answering 500 for a request the endpoint had
/// accepted. Both sides read one constant now, and this is what would notice them drifting
/// apart again.
#[tokio::test]
async fn a_subject_longer_than_the_store_holds_is_a_bad_request() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    // ONE BYTE OVER, computed from the constant rather than guessed, so an off-by-one in either
    // direction is caught. The rendering is `{"email":"...","format":"email"}`.
    let envelope = "{\"email\":\"\",\"format\":\"email\"}".len();
    let over = "x".repeat(ironauth_store::MAX_SUBJECT_BYTES - envelope + 1);
    let body = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email(&over),
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), body).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an oversized subject was not a bad request: {text}"
    );

    // AND EXACTLY AT THE BOUND IS ACCEPTED, which is the half that catches a door tightened too
    // far. If this 500s, the column cannot hold what the door admits.
    let at_bound = "x".repeat(ironauth_store::MAX_SUBJECT_BYTES - envelope);
    let body = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email(&at_bound),
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a subject exactly at the bound was refused or 500ed: {text}"
    );
}

/// The same subject sent with its members in a different order is the SAME subject.
///
/// The key is a blind index over the CANONICAL rendering, derived from the parsed identifier
/// rather than from the request bytes. If it were derived from the bytes, a receiver that
/// removed a subject with its JSON members ordered differently from the add would silently miss
/// the row and go on being told about somebody it asked to stop hearing about.
#[tokio::test]
async fn a_subject_is_keyed_by_its_meaning_and_not_by_its_json_spelling() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    // Added with `format` first.
    let added = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": { "format": "email", "email": "carol@example.test" },
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), added).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    // Removed with `email` first, and extra whitespace in the wire form.
    let removed = "{ \"stream_id\": \"".to_owned()
        + &stream.to_string()
        + "\",  \"subject\" : { \"email\" : \"carol@example.test\" , \"format\" : \"email\" } }";
    let (status, text) = post(&harness, "/ssf/subjects/remove", Some(&auth), removed).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    assert!(
        subjects_of(&harness, &stream).await.is_empty(),
        "a removal spelled differently from its add missed the row"
    );
}

/// A second receiver reaches neither endpoint, and cannot tell a stream apart from an absent one.
#[tokio::test]
async fn a_second_receiver_reaches_neither_endpoint() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (owner, _) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let (intruder, intruder_secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let intruder_auth = basic(&intruder, &intruder_secret);
    let stream = stream_for(&harness, &owner).await;
    let absent = SsfStreamId::generate(harness.state().env(), &harness.scope());

    for path in ["/ssf/subjects/add", "/ssf/subjects/remove"] {
        let theirs = serde_json::json!({
            "stream_id": stream.to_string(),
            "subject": email("mallory@evil.test"),
        })
        .to_string();
        let (theirs_status, text) = post(&harness, path, Some(&intruder_auth), theirs).await;
        assert_eq!(
            theirs_status,
            StatusCode::NOT_FOUND,
            "{path} reached another receiver's stream: {text}"
        );

        let missing = serde_json::json!({
            "stream_id": absent.to_string(),
            "subject": email("mallory@evil.test"),
        })
        .to_string();
        let (absent_status, text) = post(&harness, path, Some(&intruder_auth), missing).await;
        assert_eq!(
            absent_status, theirs_status,
            "{path} answered an absent stream differently from another receiver's: {text}"
        );
    }
    assert!(
        subjects_of(&harness, &stream).await.is_empty(),
        "an intruder wrote to the owner's subject list"
    );
}

/// The subject is not readable from the row, and the key does not travel between streams.
///
/// TWO PROPERTIES, ONE TEST, because they are the two halves of the same decision: sealing hides
/// the value, and binding the STREAM into the blind index stops the key being a cross-stream
/// oracle. Without the second, one receiver holding a dump could test whether a neighbour is
/// watching an address it knows by comparing indexes.
#[tokio::test]
async fn the_stored_subject_is_sealed_and_its_key_does_not_travel_between_streams() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let first = stream_for(&harness, &client).await;
    let second = stream_for(&harness, &client).await;

    for stream in [&first, &second] {
        let body = serde_json::json!({
            "stream_id": stream.to_string(),
            "subject": email("dave@example.test"),
        })
        .to_string();
        let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), body).await;
        assert_eq!(status, StatusCode::OK, "{text}");
    }

    // READ AS THE OWNER, which is what a database dump is: this bypasses the repository that
    // would open the seal for us, so what it sees is what an operator or an attacker with the
    // bytes sees.
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT stream_id, encode(subject_bidx, 'hex'), encode(subject_sealed, 'hex') \
         FROM ssf_stream_subjects ORDER BY stream_id",
    )
    .fetch_all(harness.db().owner_pool())
    .await
    .expect("read the rows as the owner");
    assert_eq!(rows.len(), 2, "expected one row per stream");

    let mut address_in_hex = String::new();
    for byte in "dave@example.test".as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(address_in_hex, "{byte:02x}");
    }
    for (_, _, sealed) in &rows {
        assert!(
            !sealed.contains(&address_in_hex),
            "the address is readable in the stored ciphertext"
        );
    }
    assert_ne!(
        rows[0].1, rows[1].1,
        "the same address under two streams hashed to the same index, so a dump can be used to \
         test whether another stream is watching somebody"
    );
}

/// A subject this transmitter cannot render is refused, and nothing is stored.
#[tokio::test]
async fn a_subject_in_an_unrenderable_format_is_refused() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    for (label, subject) in [
        (
            "an unknown format",
            serde_json::json!({ "format": "phone_number", "phone_number": "+15550100" }),
        ),
        ("a missing member", serde_json::json!({ "format": "email" })),
        (
            "no format at all",
            serde_json::json!({ "email": "eve@example.test" }),
        ),
        ("not an object", serde_json::json!("eve@example.test")),
    ] {
        let body = serde_json::json!({
            "stream_id": stream.to_string(),
            "subject": subject,
        })
        .to_string();
        let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), body).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{label} was accepted: {text}"
        );
    }
    assert!(
        subjects_of(&harness, &stream).await.is_empty(),
        "a refused subject was stored anyway"
    );
}

/// Removing a subject that was never added is a 204, and changes nothing.
///
/// Section 8.1.5 lets the transmitter stay silent for a subject it does not recognise. The half
/// that matters is the second: a silent answer must not also have removed something else.
#[tokio::test]
async fn removing_a_subject_that_is_not_there_is_silent_and_harmless() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    let keep = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email("frank@example.test"),
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/add", Some(&auth), keep).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    let body = serde_json::json!({
        "stream_id": stream.to_string(),
        "subject": email("never-added@example.test"),
    })
    .to_string();
    let (status, text) = post(&harness, "/ssf/subjects/remove", Some(&auth), body).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    assert_eq!(
        subjects_of(&harness, &stream).await.len(),
        1,
        "removing an absent subject removed a present one"
    );
}

/// Discovery advertises both endpoints, and they answer.
///
/// The `jwks_uri` lesson: a published path nothing serves passed every assertion about the
/// document. So each advertised endpoint is CALLED.
#[tokio::test]
async fn discovery_advertises_both_subject_endpoints_and_both_answer() {
    let mut harness = Harness::start_store_backed().await;
    harness.enable_ssf(20);
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let auth = basic(&client, &secret);
    let stream = stream_for(&harness, &client).await;

    let scope = harness.scope();
    let request = Request::builder()
        .method("GET")
        .uri(format!(
            "/.well-known/ssf-configuration/t/{}/e/{}",
            scope.tenant(),
            scope.environment()
        ))
        .body(Body::empty())
        .expect("request builds");
    let (status, _headers, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let doc: serde_json::Value = serde_json::from_str(&body).expect("a configuration document");
    // NO `default_subjects`, because nothing reads the subject list yet: advertising a default
    // for a decision no fan-out makes is the same defect as advertising an unemitted event.
    assert!(
        doc.get("default_subjects").is_none(),
        "a default-subjects policy is advertised that no fan-out applies: {body}"
    );

    for (field, expected) in [
        ("add_subject_endpoint", StatusCode::OK),
        ("remove_subject_endpoint", StatusCode::NO_CONTENT),
    ] {
        let advertised = doc[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field}: {body}"));
        let path = advertised
            .strip_prefix("https://issuer.test")
            .or_else(|| advertised.strip_prefix("http://issuer.test"))
            .unwrap_or_else(|| panic!("{field} is not on this issuer: {advertised}"));
        let suffix = path
            .strip_prefix(&format!("/t/{}/e/{}", scope.tenant(), scope.environment()))
            .unwrap_or_else(|| panic!("{field} is not under this environment: {path}"));
        let request = serde_json::json!({
            "stream_id": stream.to_string(),
            "subject": email("grace@example.test"),
        })
        .to_string();
        let (status, text) = post(&harness, suffix, Some(&auth), request).await;
        assert_eq!(
            status, expected,
            "the advertised {field} does not serve: {text}"
        );
    }
}
