// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TIMING harness for the outbound verify endpoint's uniform not-found (issue #250).
//!
//! # Why this exists as a file rather than as a sentence
//!
//! `outbound_verification.rs` proves the six refusal states are byte identical in
//! STATUS, HEADERS, and BODY. That says nothing about how long each of them takes, and
//! the endpoint's whole posture is that an armed environment is indistinguishable from
//! a disabled one to a caller holding nothing. The first version of issue #250 shipped
//! a conceded residual on the strength of an argument ("it needs a valid bearer and
//! many samples") that was measured and found wrong on both halves:
//!
//! * it is FULLY UNAUTHENTICATED. `Authorization: Bearer garbage` reaches the envelope
//!   open, and `ratelimit.rs` stamps constant placeholder headers and counts nothing,
//!   so there is no budget on how many samples a prober may take;
//! * it was not the AEAD. The cheap read issues ONE `SELECT` on a miss and THREE on a
//!   hit (`environment_secrets`, then `tenant_deks`, then `tenant_keks`). The delta was
//!   two database round trips, and the armed distribution's 1st percentile sat ABOVE
//!   the disabled distribution's median in every run.
//!
//! The fix is `EnvironmentSecretRepo::open_value_under_platform_key_at_uniform_cost`,
//! whose miss branch spends the same two key lookups and the same three AEAD opens.
//! This file is what MEASURES that, and it is the reason the claim in
//! `crates/ironauth-admin/src/migration.rs` and in the CHANGELOG carries a number.
//!
//! # Why it is `#[ignore]`d
//!
//! A wall-clock assertion in CI is a flake generator: the whole signal being measured
//! is smaller than the scheduling noise of a loaded build agent, so a threshold tight
//! enough to catch a regression would go red on an unrelated busy machine, and one
//! loose enough to be stable would catch nothing. So this runs on demand, prints its
//! distribution, and asserts only what is deterministic (both branches answer the
//! uniform not-found). The numbers it produced are quoted in the CHANGELOG next to the
//! command that reproduces them:
//!
//! ```text
//! scripts/with-test-db.sh cargo test -p ironauth-admin --features testing \
//!     --test outbound_timing_probe -- --ignored --nocapture
//! ```

mod common;

use axum::http::StatusCode;
use common::{Harness, bearer};
use ironauth_store::Scope;

/// A token long enough to clear the 32-byte floor the write surface enforces.
const TOKEN: &str = "outbound-timing-probe-token-32-plus-bytes";

/// The bearer the prober presents. It is GARBAGE, and that is the point: the whole
/// question is what an unauthenticated caller can read off the endpoint, and this is
/// what an unauthenticated caller has.
const GARBAGE_BEARER: &str = "garbage-bearer-not-a-real-token-x";

/// Samples per branch. Large enough for a stable median and a meaningful 1st
/// percentile, small enough that a manual run finishes in seconds.
const SAMPLES: usize = 600;

/// Requests spent before any sample is recorded, so pool warm-up, the first statement
/// prepare, and the first envelope key fetch are not attributed to the branch that
/// happened to run first.
const WARMUP: usize = 60;

fn verify_path(scope: Scope) -> String {
    format!(
        "/v1/tenants/{}/environments/{}/migration/verify-credential",
        scope.tenant(),
        scope.environment()
    )
}

/// One unauthenticated probe, returning the status and the elapsed nanoseconds.
async fn probe(harness: &Harness, path: &str) -> (StatusCode, u128) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::AUTHORIZATION, bearer(GARBAGE_BEARER))
        .body(axum::body::Body::from(
            r#"{"identifier":"probe@exit.test","password":"probe"}"#,
        ))
        .expect("request builds");
    let start = std::time::Instant::now(); // invariant-allow: time-via-env -- a TIMING harness measures elapsed wall time by definition; it is `#[ignore]`d, asserts no wall clock, and is not protocol logic
    let (status, _headers, _body) = harness.send(request).await;
    let elapsed = start.elapsed().as_nanos(); // invariant-allow: time-via-env -- the second half of the same measurement; the Clock seam has no monotonic elapsed and injecting one would measure the seam
    (status, elapsed)
}

/// The value at `percentile` (0.0 to 1.0) of an already-sorted sample vector.
fn at(sorted: &[u128], percentile: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let index = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[index]
}

/// The measurement, reported rather than asserted. See the module docs.
#[tokio::test]
#[ignore = "a timing harness: prints a distribution, asserts no wall clock, run it by hand"]
async fn the_armed_and_disabled_branches_cost_the_same_to_an_unauthenticated_prober() {
    let harness = Harness::start_with_outbound_verification(TOKEN).await;
    let armed = verify_path(harness.outbound_scope());
    // A live environment in the same database that has NEVER been armed: the other half
    // of the pair a prober is trying to tell apart.
    let disabled = verify_path(harness.seed_scope().await);

    for _ in 0..WARMUP {
        let (status, _) = probe(&harness, &armed).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the armed branch refuses");
        let (status, _) = probe(&harness, &disabled).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the disabled branch refuses");
    }

    // INTERLEAVED rather than one branch then the other, so a drift in machine load
    // over the run cannot be read as a difference between the branches.
    let mut armed_ns: Vec<u128> = Vec::with_capacity(SAMPLES);
    let mut disabled_ns: Vec<u128> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (status, elapsed) = probe(&harness, &armed).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the armed branch refuses");
        armed_ns.push(elapsed);
        let (status, elapsed) = probe(&harness, &disabled).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the disabled branch refuses");
        disabled_ns.push(elapsed);
    }
    armed_ns.sort_unstable();
    disabled_ns.sort_unstable();

    let armed_median = at(&armed_ns, 0.50);
    let disabled_median = at(&disabled_ns, 0.50);
    // The classifier the concession was measured with: one sample, thresholded at the
    // midpoint of the two medians, calling "armed" for anything slower. Recall is the
    // fraction of armed samples it catches; the false-positive rate is the fraction of
    // DISABLED samples it wrongly calls armed. A flat pair puts both near one half,
    // which is a coin toss and carries no information.
    let midpoint = armed_median.midpoint(disabled_median);
    #[allow(clippy::cast_precision_loss)]
    let recall = armed_ns.iter().filter(|ns| **ns > midpoint).count() as f64 / SAMPLES as f64;
    #[allow(clippy::cast_precision_loss)]
    let false_positive =
        disabled_ns.iter().filter(|ns| **ns > midpoint).count() as f64 / SAMPLES as f64;
    #[allow(clippy::cast_precision_loss)]
    let ratio = armed_median as f64 / disabled_median as f64;

    println!("issue #250 outbound verify timing, {SAMPLES} interleaved samples per branch");
    println!("  branch    p01        p50        p99");
    println!(
        "  armed     {:<10} {:<10} {:<10}",
        at(&armed_ns, 0.01),
        armed_median,
        at(&armed_ns, 0.99)
    );
    println!(
        "  disabled  {:<10} {:<10} {:<10}",
        at(&disabled_ns, 0.01),
        disabled_median,
        at(&disabled_ns, 0.99)
    );
    println!("  median ratio armed/disabled: {ratio:.4}");
    println!(
        "  single-sample classifier at the median midpoint: recall {recall:.3}, \
         false positives {false_positive:.3}"
    );
    println!(
        "  the separating question: is the armed p01 ({}) above the disabled p50 ({})? {}",
        at(&armed_ns, 0.01),
        disabled_median,
        at(&armed_ns, 0.01) > disabled_median
    );
}
