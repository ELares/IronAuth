// SPDX-License-Identifier: MIT OR Apache-2.0

//! Passkey funnel and OTP conversion metrics, from synthetic flows (issue #152, criterion 5).
//!
//! The criterion asks that these metrics "populate correctly from synthetic flows in an
//! integration test". Before this file neither metric existed: a grep for `funnel` across the
//! workspace found only prose in unrelated doc comments, so the criterion had nothing behind
//! it at all.
//!
//! # What "correctly" has to mean here
//!
//! A funnel is a RATIO. Asserting that a counter moved is not enough, because the failure a
//! conversion metric actually has is the flattering one: count only the ceremonies that
//! succeeded and the rate reads near 1 however many were refused. So this drives BOTH halves
//! of each funnel and asserts BOTH labels, including a deliberate failure at the completing
//! stage, and checks the denominator is larger than the numerator afterwards.
//!
//! # Its own test binary, deliberately
//!
//! `metrics` installs one global recorder per process, and a test binary is a process. These
//! assertions read the rendered exposition, so they cannot share a binary with a suite that
//! installs its own recorder or that drives these same endpoints for other reasons and would
//! move the counters underneath them.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::{Integer, Value};
use common::{Harness, ISSUER_BASE};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

const RP_ID: &str = "issuer.test";
const SEED: [u8; 32] = [11_u8; 32];
const CRED_ID: &[u8] = b"funnel-metrics-credential";

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("cbor encodes");
    out
}

fn cose_key() -> Vec<u8> {
    let public_key = ironauth_jose::webauthn::test_util::ed25519_public_key_from_seed(&SEED);
    cbor(&Value::Map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(1)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(-8)),
        ),
        (
            Value::Integer(Integer::from(-1)),
            Value::Integer(Integer::from(6)),
        ),
        (Value::Integer(Integer::from(-2)), Value::Bytes(public_key)),
    ]))
}

fn client_data(ceremony_type: &str, challenge_b64: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony_type}","challenge":"{challenge_b64}","origin":"{ISSUER_BASE}","crossOrigin":false}}"#
    )
    .into_bytes()
}

fn auth_data(flags: u8, sign_count: u32, attested: bool) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&sha256(RP_ID.as_bytes()));
    data.push(flags);
    data.extend_from_slice(&sign_count.to_be_bytes());
    if attested {
        data.extend_from_slice(&[0xCD; 16]);
        data.extend_from_slice(
            &u16::try_from(CRED_ID.len())
                .expect("the id fits")
                .to_be_bytes(),
        );
        data.extend_from_slice(CRED_ID);
        data.extend_from_slice(&cose_key());
    }
    data
}

async fn post(harness: &Harness, path: &str, cookie: Option<&str>, body: &Json) -> StatusCode {
    let (status, _json) = post_json(harness, path, cookie, body).await;
    status
}

async fn post_json(
    harness: &Harness,
    path: &str,
    cookie: Option<&str>,
    body: &Json,
) -> (StatusCode, Json) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("origin", ISSUER_BASE);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let (status, _headers, response) = harness
        .send(
            builder
                .body(Body::from(body.to_string()))
                .expect("request builds"),
        )
        .await;
    let parsed = if response.is_empty() {
        Json::Null
    } else {
        serde_json::from_str(&response).unwrap_or(Json::Null)
    };
    (status, parsed)
}

/// The value of one labeled counter series in the rendered exposition, or 0 if absent.
///
/// ZERO FOR ABSENT, which is why [`series_present`] exists beside it. A review pointed out that
/// an assertion of `series(...) == 0` is satisfied by the series not existing at all, so
/// deleting a whole wrapper left the suite green: the stage vanished and the test read the
/// vanishing as a legitimate zero. Any assertion here that a stage did NOT fire has to say
/// whether it expects the series ABSENT or present-and-zero.
fn series(rendered: &str, name: &str, labels: &[(&str, &str)]) -> u64 {
    series_value(rendered, name, labels).unwrap_or(0)
}

/// Whether the series exists in the exposition at all, regardless of its value.
fn series_present(rendered: &str, name: &str, labels: &[(&str, &str)]) -> bool {
    series_value(rendered, name, labels).is_some()
}

/// The value of one labeled counter series, or [`None`] when the series is absent.
fn series_value(rendered: &str, name: &str, labels: &[(&str, &str)]) -> Option<u64> {
    let mut wanted: Vec<String> = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect();
    wanted.sort();
    for line in rendered.lines() {
        let Some((head, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let Some((series_name, label_text)) = head.split_once('{') else {
            continue;
        };
        if series_name != name {
            continue;
        }
        let mut found: Vec<String> = label_text
            .trim_end_matches('}')
            .split(',')
            .map(|pair| pair.trim().to_owned())
            .collect();
        found.sort();
        if found == wanted {
            return Some(value.trim().parse().unwrap_or(0));
        }
    }
    None
}

/// A well-formed credential body that will be refused by the HANDLER rather than by the
/// extractor. A body that does not deserialize is rejected inside axum's Json extractor, before
/// the wrapper runs, so it records nothing.
fn credential_for_refusal() -> Json {
    json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client_data("webauthn.get", "bm90LWEtY2hhbGxlbmdl")),
            "authenticatorData": b64(&auth_data(0b0001_1101, 1, false)),
            "signature": b64(&[0_u8; 64]),
            "userHandle": b64(b"nobody"),
        },
    })
}

/// Drive three passkey registration ceremonies: one complete, one abandoned after the
/// challenge, and one attempted with a credential the server will refuse.
///
/// Split out of the test so the assertions read as assertions. The three shapes are the
/// point: a funnel needs a denominator that counts ceremonies which did not finish, and a
/// completing stage that carries both outcomes.
async fn drive_passkey_ceremonies(harness: &Harness, cookie: &str, base: &str) {
    let (status, opts) = post_json(
        harness,
        &format!("{base}/register/options"),
        Some(cookie),
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register options: {opts}");
    let challenge_id = opts["challengeId"]
        .as_str()
        .expect("a challenge id")
        .to_owned();
    let challenge_b64 = opts["publicKey"]["challenge"]
        .as_str()
        .expect("a challenge")
        .to_owned();

    let attestation_object = cbor(&Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (
            Value::Text("authData".into()),
            Value::Bytes(auth_data(0b0101_1101, 0, true)),
        ),
    ]));
    let credential = json!({
        "id": b64(CRED_ID),
        "rawId": b64(CRED_ID),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(&client_data("webauthn.create", &challenge_b64)),
            "attestationObject": b64(&attestation_object),
            "transports": ["internal"],
        },
        "clientExtensionResults": { "credProps": { "rk": true } },
    });

    let status = post(
        harness,
        &format!("{base}/register/verify"),
        Some(cookie),
        &json!({ "challengeId": challenge_id, "credential": credential.clone() }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "the registration completes");

    // OFFERED AND ABANDONED, which is the whole reason a funnel is two numbers.
    let status = post(
        harness,
        &format!("{base}/register/options"),
        Some(cookie),
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // ATTEMPTED AND REFUSED, so the completing stage carries both outcomes.
    //
    // A WELL-FORMED body with an unknown challenge id, not a malformed one. The first version
    // sent `"credential": {}` and the counter stayed at zero: axum rejects a body that does
    // not deserialize inside the `Json` EXTRACTOR, before the handler runs, so the wrapper
    // never executes. That limit is documented in `ironauth_oidc::funnel`; what it means here
    // is that a test of the handler has to be refused BY the handler.
    let status = post(
        harness,
        &format!("{base}/register/verify"),
        Some(cookie),
        &json!({ "challengeId": "chl_does_not_exist", "credential": credential }),
    )
    .await;
    assert!(
        !status.is_success(),
        "a credential against an unknown challenge must be refused, got {status}"
    );
}

/// Drive one authenticate challenge and one refused assertion, so both authenticate stages
/// exist. A review deleted both authenticate wrappers and the suite stayed green, because
/// nothing asserted those series were present while the test's own doc claimed it covered
/// "BOTH FUNNELS ... AT BOTH STAGES".
async fn drive_authenticate_ceremony(harness: &Harness, scope_base: &str) {
    let (status, opts) = post_json(
        harness,
        &format!("{scope_base}/webauthn/authenticate/options"),
        None,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "authenticate options: {opts}");
    let status = post(
        harness,
        &format!("{scope_base}/webauthn/authenticate/verify"),
        None,
        &json!({ "challengeId": "chl_nope", "credential": credential_for_refusal() }),
    )
    .await;
    assert!(
        !status.is_success(),
        "an assertion against an unknown challenge must be refused, got {status}"
    );
}

/// Drive one email verify, one email send and one SMS send.
///
/// THE EMAIL SEND IS THE SHARPEST CASE IN THE FILE. It goes to an unknown recipient and is
/// acknowledged with the SAME uniform 200 a delivered code gets, by anti-enumeration design, so
/// it is the sample that catches a funnel keying its result label on the status. A review
/// measured the first version recording exactly that as a success.
///
/// THE SMS SEND IS WHAT MAKES THE CHANNEL LABEL LOAD-BEARING. SMS OTP is off by default and the
/// kill switch answers from the HANDLER rather than the router, so the wrapper still runs and
/// records one sms sample. Without it, folding `OtpChannel::Sms` into `Email` left the suite
/// green, because the test drove no SMS traffic and its "no sms sample" assertion was satisfied
/// by absence.
async fn drive_otp_attempts(harness: &Harness, scope_base: &str) {
    let status = post(
        harness,
        // `/otp/verify`, which is where the email OTP verify is actually mounted. This said
        // `/otp/email/verify`, a path that does not exist, so the request 404'd at the ROUTER
        // and the handler never ran: the counter stayed at zero and the test read that as a
        // missing metric rather than as its own wrong URL.
        &format!("{scope_base}/otp/verify"),
        None,
        &json!({ "identifier": "nobody@example.test", "code": "000000" }),
    )
    .await;
    assert!(
        !status.is_success(),
        "a code that was never sent must not verify, got {status}"
    );

    let status = post(
        harness,
        &format!("{scope_base}/otp/send"),
        None,
        &json!({ "identifier": "nobody@example.test" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "precondition: the send is acknowledged uniformly, which is exactly why the status \
         cannot be what the funnel keys on"
    );

    let status = post(
        harness,
        &format!("{scope_base}/otp/sms/send"),
        None,
        &json!({ "identifier": "+15555550100" }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "precondition: SMS OTP is off by default and the kill switch answers from the \
         handler, which is what puts a sample on the sms channel"
    );
}

/// Assert the OTP half of the exposition.
///
/// Split out only so the test body stays under the line cap; every assertion here is about the
/// same rendered snapshot the passkey assertions read.
fn assert_otp_funnel(rendered: &str) {
    let otp = "ironauth_otp_funnel_total";
    // THE SEND STAGE EXISTS AND THE REFUSED SEND IS AN ERROR. This is the finding that made
    // the whole metric wrong: the send returned a uniform 200, the label keyed on the status,
    // and a refused send was recorded as a delivered code.
    assert_eq!(
        series(
            rendered,
            otp,
            &[("channel", "email"), ("stage", "send"), ("result", "error")]
        ),
        1,
        "a send to an unknown recipient delivered nothing and must be counted as an \
         error, whatever status the anti-enumeration design returns:\n{rendered}"
    );
    assert!(
        !series_present(
            rendered,
            otp,
            &[("channel", "email"), ("stage", "send"), ("result", "ok")]
        ),
        "and nothing was actually delivered, so there must be no ok sample at all:\n{rendered}"
    );
    let verified = series(
        rendered,
        otp,
        &[
            ("channel", "email"),
            ("stage", "verify"),
            ("result", "error"),
        ],
    );
    assert_eq!(
        verified, 1,
        "the refused verify is counted, on the email channel, at the verify stage:\n{rendered}"
    );

    // AND THE TWO STAGES ARE DISTINCT: exactly one send sample and exactly one verify sample
    // were produced, so neither handler is incrementing both. If it were, every conversion
    // rate would be exactly 1 by construction and nothing else here would notice.
    //
    // This used to assert the send stage was ABSENT, which was true only because the test
    // never sent anything, and was satisfied by absence rather than by a count. It now drives
    // a real send and checks the two stages independently.
    let send_total: u64 = ["ok", "error"]
        .iter()
        .map(|result| {
            series(
                rendered,
                otp,
                &[("channel", "email"), ("stage", "send"), ("result", result)],
            )
        })
        .sum();
    let verify_total: u64 = ["ok", "error"]
        .iter()
        .map(|result| {
            series(
                rendered,
                otp,
                &[
                    ("channel", "email"),
                    ("stage", "verify"),
                    ("result", result),
                ],
            )
        })
        .sum();
    assert_eq!(
        (send_total, verify_total),
        (1, 1),
        "one send and one verify were driven, so each stage must hold exactly one \
         sample:\n{rendered}"
    );

    // THE CHANNEL LABEL IS THE CHANNEL. One SMS send was driven and it must land on the sms
    // series, not the email one. Asserting only that no sms sample exists would be satisfied
    // by a mislabelled sample going to email, which is exactly the slip this guards.
    assert_eq!(
        series(
            rendered,
            otp,
            &[("channel", "sms"), ("stage", "send"), ("result", "error")]
        ),
        1,
        "the SMS send must be recorded on the SMS channel:\n{rendered}"
    );
    assert!(
        !series_present(
            rendered,
            otp,
            &[("channel", "sms"), ("stage", "verify"), ("result", "error")]
        ),
        "and no sms VERIFY was driven, so that stage must not exist:\n{rendered}"
    );
}

/// BOTH FUNNELS POPULATE FROM SYNTHETIC FLOWS, AT BOTH STAGES, WITH BOTH OUTCOMES.
///
/// ONE test rather than two, because `metrics` installs a single recorder per PROCESS and a
/// test binary is one process. Two tests reading the rendered exposition would race over each
/// other's counters, and the one that lost would fail intermittently with numbers that look
/// like a real defect.
#[tokio::test]
async fn the_passkey_and_otp_funnels_populate_from_synthetic_flows() {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("no recorder installed yet in this test binary");

    let harness = Harness::start().await;
    let subject = harness
        .seed_user("funnel@example.test", "correct horse battery")
        .await;
    let (_id, cookie) = harness.session_with_id(&subject, "pwd", 0).await;
    let scope_base = format!(
        "/t/{}/e/{}",
        harness.scope().tenant(),
        harness.scope().environment()
    );

    drive_passkey_ceremonies(&harness, &cookie, &format!("{scope_base}/webauthn")).await;

    drive_authenticate_ceremony(&harness, &scope_base).await;
    drive_otp_attempts(&harness, &scope_base).await;

    let rendered = handle.render();
    let passkey = "ironauth_passkey_funnel_total";
    let offered = series(
        &rendered,
        passkey,
        &[("stage", "register_challenge"), ("result", "ok")],
    );
    let completed = series(
        &rendered,
        passkey,
        &[("stage", "register_complete"), ("result", "ok")],
    );
    let refused = series(
        &rendered,
        passkey,
        &[("stage", "register_complete"), ("result", "error")],
    );

    assert_eq!(offered, 2, "two challenges were offered:\n{rendered}");
    assert_eq!(completed, 1, "one registration completed:\n{rendered}");
    assert_eq!(refused, 1, "and one was refused:\n{rendered}");

    // THE RATIO IS THE POINT. A funnel whose denominator only counted successes would make
    // this an equality, and would read as 100 percent conversion on a deployment refusing
    // half its registrations.
    assert!(
        offered > completed,
        "the denominator must count ceremonies that did not complete, else the conversion \
         rate is always 1: offered={offered} completed={completed}"
    );

    // THE AUTHENTICATE STAGES EXIST. Asserted by PRESENCE, not by value: deleting either
    // wrapper makes the series vanish, and a value assertion against a vanished series reads
    // its absence as a zero.
    for (stage, result) in [
        ("authenticate_challenge", "ok"),
        ("authenticate_complete", "error"),
    ] {
        assert!(
            series_present(&rendered, passkey, &[("stage", stage), ("result", result)]),
            "the {stage} stage must be recorded, or every dashboard dividing by it divides \
             by an absent series:\n{rendered}"
        );
    }
    // AND THEY ARE NOT THE REGISTER STAGES WEARING THE WRONG LABEL. Relabelling an
    // authenticate wrapper as a register one is a one-token slip the four near-identical
    // wrapper blocks invite, and it would silently inflate the published enrollment rate with
    // sign-in traffic.
    assert_eq!(
        series(
            &rendered,
            passkey,
            &[("stage", "register_challenge"), ("result", "ok")]
        ),
        2,
        "the authenticate challenge must not have been counted as a register one:\n{rendered}"
    );

    assert_otp_funnel(&rendered);
}
