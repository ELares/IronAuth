// SPDX-License-Identifier: MIT OR Apache-2.0

//! The log-scrubbing corpus: seed sentinel secrets, tokens, passwords, and
//! emails through every request log path this crate creates and assert zero
//! leaks in captured output.
//!
//! This guards the structural rule that request logging carries route
//! templates and safe fields only: never query strings, `Authorization`,
//! `Cookie`, other headers, or bodies. If a future change starts logging any
//! of those, a sentinel appears here and the test fails.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{CaptureWriter, send, server_from};
use ironauth_config::LogFormat;
use ironauth_server::Redacted;

// Distinctive sentinels, unlikely to occur incidentally in any log envelope.
const Q_TOKEN: &str = "SENTINELtokenQZX1";
const Q_PASSWORD: &str = "SENTINELpwQZX2";
const BEARER: &str = "SENTINELbearerQZX3";
const COOKIE: &str = "SENTINELcookieQZX4";
const FWD_HOST: &str = "SENTINELhostQZX5.evil.example";
const PATH_SECRET: &str = "SENTINELpathQZX6";
const BODY_SECRET: &str = "SENTINELbodyQZX7";
const EMAIL: &str = "victim.SENTINELemailQZX8@example.com";
const REDACTED_FIELD: &str = "SENTINELredactQZX9";

const CONFIG: &str = "dev_mode = true\n\
    [server]\npublic_url = \"https://id.example.test\"\n\
    [database]\nurl = \"postgres://ironauth@192.0.2.1:5432/ironauth\"\n";

const ALL_SENTINELS: &[&str] = &[
    Q_TOKEN,
    Q_PASSWORD,
    BEARER,
    COOKIE,
    FWD_HOST,
    PATH_SECRET,
    BODY_SECRET,
    EMAIL,
    REDACTED_FIELD,
];

#[test]
fn no_sentinel_leaks_through_any_request_log_path() {
    let writer = CaptureWriter::new();
    let subscriber = ironauth_server::telemetry::build_subscriber(LogFormat::Json, writer.clone());

    tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime builds")
            .block_on(async {
                let server = server_from(CONFIG);

                // 1. Secrets in the query string.
                let uri = format!("/?token={Q_TOKEN}&password={Q_PASSWORD}&email={EMAIL}");
                drive(server.app(), Request::builder().uri(&uri)).await;

                // 2. Authorization header.
                drive(
                    server.app(),
                    Request::builder()
                        .uri("/")
                        .header("authorization", format!("Bearer {BEARER}")),
                )
                .await;

                // 3. Cookie header.
                drive(
                    server.app(),
                    Request::builder()
                        .uri("/")
                        .header("cookie", format!("session={COOKIE}")),
                )
                .await;

                // 4. Forwarded headers carrying a secret host.
                drive(
                    server.app(),
                    Request::builder()
                        .uri("/")
                        .header("x-forwarded-host", FWD_HOST)
                        .header("x-forwarded-proto", "http"),
                )
                .await;

                // 5. Secret embedded in an unmatched path (must log as the
                //    <unmatched> template, never the raw path).
                drive(
                    server.app(),
                    Request::builder().uri(format!("/{PATH_SECRET}/resource")),
                )
                .await;

                // 6. Secret in a request body (never read by logging).
                let with_body = Request::builder()
                    .uri("/")
                    .body(Body::from(BODY_SECRET.to_owned()))
                    .expect("request builds");
                let _ = send(server.app(), with_body).await;

                // 7. A directly logged event carrying a Redacted value.
                tracing::info!(
                    secret = %Redacted::new(REDACTED_FIELD),
                    "handled a value that must never be logged"
                );
            });
    });

    let output = writer.contents();
    assert!(
        !output.is_empty(),
        "capture must contain log output, or the test is vacuous"
    );
    for sentinel in ALL_SENTINELS {
        assert!(
            !output.contains(sentinel),
            "SECRET LEAK: {sentinel} appeared in logs:\n{output}"
        );
    }
    // The redaction placeholder must be present where the Redacted value was.
    assert!(output.contains("[redacted]"), "{output}");
}

/// Build and drive a `GET` request with an empty body, asserting it completes.
async fn drive(app: axum::Router, builder: axum::http::request::Builder) {
    let req = builder.body(Body::empty()).expect("request builds");
    let (status, _, _) = send(app, req).await;
    // Root serves 200; unmatched paths serve 404. Either is a completed
    // request whose log line must be sentinel-free.
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "unexpected status {status}"
    );
}
