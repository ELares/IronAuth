// SPDX-License-Identifier: MIT OR Apache-2.0

//! Token issuance rate and latency by grant type (issue #152).
//!
//! The issue asks the metric contract to carry "token issuance rate and latency by grant type".
//! Nothing did. Three contract entries are emitted from this endpoint's module
//! (`ironauth_oidc_code_reuse_total`, `ironauth_oidc_redeem_error_total` and
//! `ironauth_oidc_refresh_reuse_total`), but each counts one specific abuse signal and none of
//! them is a request rate. `ironauth_http_requests_total{route,status}` does separate a 200 from
//! a 400 on `/token`, so the gap is narrower than "no visibility": what could not be asked was
//! which GRANT the traffic is, and which OAuth error the refusals carry.
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

/// The value of one labeled counter series, or zero when it is absent.
///
/// A counter and a histogram's `_count` are whole numbers, so they are compared as integers: a
/// float equality on a metric value is a lint here and a rounding argument nobody wants to have.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "counters are whole"
)]
fn series(rendered: &str, name: &str, labels: &[(&str, &str)]) -> u64 {
    series_value(rendered, name, labels).unwrap_or(0.0).round() as u64
}

/// The value of one labeled counter series, or [`None`] when it is absent.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "counters are whole"
)]
fn count(rendered: &str, name: &str, labels: &[(&str, &str)]) -> Option<u64> {
    series_value(rendered, name, labels).map(|value| value.round() as u64)
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

    // A BODY THE ENDPOINT CANNOT PARSE, which is the branch the recording site sits before the
    // parse to reach. Repeating a scalar parameter is a duplicate field to `serde_urlencoded`,
    // so the whole body is refused and NO field is read, including the two serviced grant names
    // in it. That is the case worth pinning: the label is `none` because the request could not
    // be read, not because it named nothing.
    let (status, _headers, _body) = harness
        .token_with_auth(
            "grant_type=client_credentials&grant_type=refresh_token",
            Some(&auth),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unparsable body is refused"
    );

    // TWO UNSERVICED GRANTS, and they are the point of this test. Both are strings with nothing
    // behind them, and both are spelled so they cannot occur anywhere else in the exposition:
    // the leak assertion below greps the whole rendered document, and "password" would have
    // matched seven of this build's own metric names had it been used as a probe.
    for unserviced in [
        "urn:example:probe-alpha-Nn7Qv",
        "urn:example:probe-beta-Zk2Rw",
    ] {
        let (status, _headers, _body) = harness
            .token_with_auth(&form(&[("grant_type", unserviced)]), Some(&auth))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{unserviced} is unserviced"
        );
    }

    assert_exposition(&handle.render());
}

/// Every assertion about the rendered exposition, split out because the driving half and the
/// checking half of this test are both long and read better apart.
fn assert_exposition(rendered: &str) {
    assert_eq!(
        series(
            rendered,
            REQUESTS,
            &[("grant_type", "client_credentials"), ("outcome", "issued")]
        ),
        1,
        "the successful exchange is counted as issued"
    );
    assert_eq!(
        series(
            rendered,
            REQUESTS,
            &[
                ("grant_type", "client_credentials"),
                ("outcome", "invalid_client")
            ]
        ),
        1,
        "the unauthenticated exchange is counted under the SAME grant with a refusing outcome, \
         which is what makes the ratio readable"
    );

    // THE CARDINALITY BOUND, asserted rather than described. Two distinct unserviced values
    // produce ONE series with a count of two, not two series.
    assert_eq!(
        series(
            rendered,
            REQUESTS,
            &[
                ("grant_type", "none"),
                ("outcome", "unsupported_grant_type")
            ]
        ),
        2,
        "both unserviced grant types collapse into one series"
    );
    for leaked in ["probe-alpha-Nn7Qv", "probe-beta-Zk2Rw"] {
        assert!(
            !rendered.contains(leaked),
            "the caller's grant_type string {leaked:?} reached the exposition, so an \
             unauthenticated request can mint a series"
        );
    }
    // AND THE UNPARSABLE BODY WAS COUNTED, which is the only assertion behind placing the
    // recording site before the parse. It lands as `invalid_request` alongside the request that
    // named no grant, so the series carries both.
    assert_eq!(
        series(
            rendered,
            REQUESTS,
            &[("grant_type", "none"), ("outcome", "invalid_request")]
        ),
        2,
        "the request naming no grant AND the body that could not be parsed are both counted"
    );

    // LATENCY, by grant type and NOT by outcome. The histogram's count for the serviced grant
    // covers both of its requests, which is the check that the two metrics are recorded from the
    // same place and cannot drift apart.
    assert_eq!(
        count(
            rendered,
            &format!("{DURATION}_count"),
            &[("grant_type", "client_credentials")]
        ),
        Some(2),
        "the histogram counts every request for the grant, issued and refused alike"
    );
    assert_eq!(
        count(
            rendered,
            &format!("{DURATION}_count"),
            &[("grant_type", "none")]
        ),
        Some(4),
        "all four requests that named no serviced grant are timed: the one with no grant, the \
         unparsable body, and the two unserviced values"
    );
    // THE ELAPSED IS READ THROUGH THE SEAM. `Harness` runs a `ManualClock` that nothing advances
    // during a request, so a duration read through `env().clock()` is exactly zero while a raw
    // wall-clock read of the same interval is a small positive number: this fails the moment the
    // handler times itself around the seam.
    //
    // WHAT IT CANNOT SAY, because a frozen clock renders a real measurement and no measurement
    // identically: that the value is the elapsed time at all. A hardcoded zero passes here.
    // `elapsed_is_read_from_the_clock_seam` in `src/token.rs` is where that is pinned, against a
    // clock it can advance.
    assert_eq!(
        series_value(
            rendered,
            &format!("{DURATION}_sum"),
            &[("grant_type", "client_credentials")]
        ),
        Some(0.0),
        "the duration is measured through the Clock seam, which this harness holds frozen"
    );
}
