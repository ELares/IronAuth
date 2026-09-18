// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token issuance rate and latency by grant type (issue #152).
//!
//! The issue asks the metric contract to carry "token issuance rate and latency by grant type".
//! Nothing did: the complete contract held forty-one series and none of them said anything about
//! the token endpoint, so the one number an operator asks for first -- are tokens still being
//! issued, and by which grant -- had to be inferred from the HTTP route counter, which cannot
//! separate an issuance from a refusal.
//!
//! # What this asserts beyond "the counter moved"
//!
//! THE LABEL IS THE HAZARD. `grant_type` arrives in the request body, from anyone, and a metric
//! that used the raw value would let an unauthenticated caller mint a time series per request:
//! the standard way to bring down a Prometheus instance, and free to attempt. So the assertions
//! that matter here are not that a serviced grant is counted, but that TWO DIFFERENT unserviced
//! values collapse to one series and that neither string appears anywhere in the exposition.
//!
//! The rest is the funnel's lesson from criterion 5: counting only what succeeded makes an
//! issuance rate read healthy through an outage of everything else, so both a success and three
//! distinct refusals are driven and the outcome label is asserted on each.
//!
//! # Its own test binary, deliberately
//!
//! `metrics` installs one global recorder per process and a test binary is a process. These
//! assertions read the rendered exposition, so they cannot share a binary with a suite that
//! installs its own recorder or drives the token endpoint for other reasons.

mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Harness, form};
use ironauth_oidc::ClientAuthMethod;

/// A standard-padded Basic credential of `client_id:client_secret`.
fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

/// The value of one labeled series, or [`None`] when the series is absent.
///
/// Reads the rendered exposition rather than the recorder's internals, because the exposition is
/// what a scrape gets and a label that never reaches it is not a label anyone can query.
fn series_value(rendered: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
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
            return value.trim().parse().ok();
        }
    }
    None
}

/// The value of one labeled series, or zero when it is absent.
fn series(rendered: &str, name: &str, labels: &[(&str, &str)]) -> f64 {
    series_value(rendered, name, labels).unwrap_or(0.0)
}

const REQUESTS: &str = "ironauth_token_requests_total";
const DURATION: &str = "ironauth_token_request_duration_seconds";

/// ONE test rather than five, because `metrics` installs a single recorder per PROCESS: a second
/// test in this binary would either fail to install one or read counters the first had moved.
#[tokio::test]
async fn token_requests_are_counted_by_grant_type_and_outcome() {
    let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("no recorder installed yet in this test binary");

    let harness = Harness::start().await;
    let (client, secret) = harness
        .create_confidential_client(ClientAuthMethod::Basic)
        .await;
    let client_id = client.to_string();
    let auth = basic_header(&client_id, &secret);

    // ISSUED: a real client-credentials exchange.
    let (status, _headers, body) = harness
        .token_with_auth(&form(&[("grant_type", "client_credentials")]), Some(&auth))
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials exchange: {body}"
    );

    // REFUSED, same grant: the identical request without client authentication.
    let (status, _headers, _body) = harness
        .token_with_auth(&form(&[("grant_type", "client_credentials")]), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // NO GRANT NAMED.
    let (status, _headers, _body) = harness
        .token_with_auth(&form(&[("scope", "openid")]), Some(&auth))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // TWO UNSERVICED GRANTS, and they are the point of this test. `password` is the ROPC grant
    // this build refuses to express at all; the second is a string with nothing behind it.
    for unserviced in ["password", "urn:example:made-up-by-the-caller"] {
        let (status, _headers, _body) = harness
            .token_with_auth(&form(&[("grant_type", unserviced)]), Some(&auth))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{unserviced} is unserviced"
        );
    }

    let rendered = handle.render();

    assert_eq!(
        series(
            &rendered,
            REQUESTS,
            &[("grant_type", "client_credentials"), ("outcome", "issued")]
        ),
        1.0,
        "the successful exchange is counted as issued"
    );
    assert_eq!(
        series(
            &rendered,
            REQUESTS,
            &[
                ("grant_type", "client_credentials"),
                ("outcome", "invalid_client")
            ]
        ),
        1.0,
        "the unauthenticated exchange is counted under the SAME grant with a refusing outcome, \
         which is what makes the ratio readable"
    );
    assert_eq!(
        series(
            &rendered,
            REQUESTS,
            &[("grant_type", "none"), ("outcome", "invalid_request")]
        ),
        1.0,
        "a request naming no grant is counted"
    );

    // THE CARDINALITY BOUND, asserted rather than described. Two distinct unserviced values
    // produce ONE series with a count of two, not two series.
    assert_eq!(
        series(
            &rendered,
            REQUESTS,
            &[
                ("grant_type", "none"),
                ("outcome", "unsupported_grant_type")
            ]
        ),
        2.0,
        "both unserviced grant types collapse into one series"
    );
    for leaked in ["password", "made-up-by-the-caller"] {
        assert!(
            !rendered.contains(leaked),
            "the caller's grant_type string {leaked:?} reached the exposition, so an \
             unauthenticated request can mint a series"
        );
    }

    // LATENCY, by grant type and NOT by outcome. The histogram's count for the serviced grant
    // covers both of its requests, which is the check that the two metrics are recorded from the
    // same place and cannot drift apart.
    assert_eq!(
        series_value(
            &rendered,
            &format!("{DURATION}_count"),
            &[("grant_type", "client_credentials")]
        ),
        Some(2.0),
        "the histogram counts every request for the grant, issued and refused alike"
    );
    assert!(
        series_value(
            &rendered,
            &format!("{DURATION}_count"),
            &[("grant_type", "none")]
        )
        .is_some_and(|count| count >= 3.0),
        "the three requests that named no serviced grant are timed too"
    );
    // AND THE ELAPSED COMES OFF THE CLOCK SEAM, which is what this harness can prove and a
    // "greater than zero" assertion cannot. `Harness` runs on a `ManualClock` that nothing
    // advances during a request, so a duration read through `env().clock()` is exactly zero
    // while a raw wall-clock read of the same interval would be some small positive number. A
    // sum of zero is therefore positive evidence rather than an absent measurement: it fails
    // the moment the handler starts timing itself around the seam.
    assert_eq!(
        series_value(
            &rendered,
            &format!("{DURATION}_sum"),
            &[("grant_type", "client_credentials")]
        ),
        Some(0.0),
        "the duration is measured through the Clock seam, which this harness holds frozen"
    );
}
