// SPDX-License-Identifier: MIT OR Apache-2.0

//! The published failure matrix cannot drift from behavior (issue #149 criterion 5).
//!
//! Criterion 5 asks that the matrix be "generated from test output, so docs cannot drift from
//! behavior". The generator derives the page from `DegradedTier::ALL` and its own prose, and
//! `scripts/failure-matrix-check.sh` fails CI when the committed page is stale. What neither
//! of those can see is the WIRE: the `/readyz` bodies live in `routes.rs`, not in anything the
//! generator reads. These tests drive the real handler through every state and compare each
//! answer with the published table, so a body that drifts from the code fails here even if the
//! generator were edited to match the drift.

mod common;

use axum::http::StatusCode;
use common::{config_from, get, server_from};
use ironauth_server::{DatabaseHealth, DegradedTier};

/// The committed page, embedded at compile time.
const DOC: &str = include_str!("../../../docs/FAILURE-MATRIX.md");

#[tokio::test]
async fn the_matrix_tiers_are_exactly_the_builds_tiers() {
    // The tier table sits between "## The tiers" and "## Combined failures". Every row starts
    // with the tier and its token, back to back: `| `backbone_absent` | `backbone_absent` |`.
    let tiers_section = DOC
        .split("## The tiers")
        .nth(1)
        .expect("the doc has a tiers section")
        .split("## Combined failures")
        .next()
        .expect("the doc has a combined-failures section");

    let mut documented: Vec<&str> = tiers_section
        .lines()
        .filter_map(|line| {
            let token = line
                .strip_prefix("| `")
                .and_then(|rest| rest.split_once('`'))
                .map(|(token, _)| token)?;
            (line.contains("| `") && line.contains("| `") && line.split('|').count() >= 3)
                .then_some(token)
        })
        .collect();

    // BOTH DIRECTIONS, so the set can drift in either direction without notice: a tier with no
    // row is an operator with no runbook, and a row with no tier is a page describing
    // something this build cannot report.
    let expected: Vec<&str> = DegradedTier::ALL.iter().map(|tier| tier.token()).collect();
    documented.sort_unstable();
    let mut expected_sorted = expected.clone();
    expected_sorted.sort_unstable();
    assert_eq!(
        documented, expected_sorted,
        "the matrix tier table must be exactly DegradedTier::ALL: \
         documented {documented:?} against build {expected:?}"
    );
}

/// `/readyz` against a reachable listener with the given database answer, so every wire state
/// can be driven without a real Postgres in the loop.
async fn readyz_for(extra: &str, health: Option<DatabaseHealth>) -> (StatusCode, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to listen on");
    let port = listener.local_addr().expect("a bound address").port();
    let server = server_from(&format!(
        "[database]\nurl = \"postgres://ironauth@127.0.0.1:{port}/ironauth\"\n{extra}"
    ));
    let server = match health {
        Some(health) => server.with_database_probe(std::sync::Arc::new(FixedProbe(health))),
        None => server,
    };
    let (status, _, body) = get(server.management_app(), "/readyz").await;
    drop(listener);
    (status, body)
}

/// The socket-only healthy answer: a REACHABLE address and no database probe, which is the
/// fallback shape the server takes when no probe could be attached.
#[tokio::test]
async fn the_matrix_socket_only_row_matches_the_handler() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port to listen on");
    let port = listener.local_addr().expect("a bound address").port();
    let server = server_from(&format!(
        "[database]\nurl = \"postgres://ironauth@127.0.0.1:{port}/ironauth\"\n"
    ));
    let (status, _, body) = get(server.management_app(), "/readyz").await;
    drop(listener);

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ready: probe=socket-only\n");
    assert!(
        DOC.contains("| healthy (socket-only probe) | 200 | `ready: probe=socket-only` |"),
        "the published wire table must carry the socket-only row"
    );
}

/// The other five rows of the wire table, each driven through the REAL handler and compared
/// against the published row.
#[tokio::test]
async fn the_matrix_wire_contract_matches_the_real_handler() {
    let cases = [
        (
            "healthy",
            StatusCode::OK,
            "ready\n",
            "| healthy | 200 | `ready` |",
        ),
        (
            "degraded: backbone absent",
            StatusCode::OK,
            "degraded: backbone_absent\n",
            "| degraded: backbone absent | 200 | `degraded: backbone_absent` |",
        ),
        (
            "degraded: accelerator absent",
            StatusCode::OK,
            "degraded: accelerator_absent\n",
            "| degraded: accelerator absent | 200 | `degraded: accelerator_absent` |",
        ),
        (
            "database unreachable",
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready: database unreachable\n",
            "| database unreachable | 503 | `not ready: database unreachable` |",
        ),
        (
            "schema not migrated",
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready: schema not migrated\n",
            "| schema not migrated | 503 | `not ready: schema not migrated` |",
        ),
    ];
    for (state, expected_status, expected_body, documented_row) in cases {
        let (extra, health) = match state {
            "degraded: backbone absent" => (
                "\n[outbox]\nironbus_addr = \"127.0.0.1:1\"\n",
                Some(DatabaseHealth::Serving),
            ),
            "degraded: accelerator absent" => (
                "\n[hot_state]\nironcache_addr = \"127.0.0.1:1\"\n",
                Some(DatabaseHealth::Serving),
            ),
            "database unreachable" => ("", Some(DatabaseHealth::Unreachable)),
            "schema not migrated" => ("", Some(DatabaseHealth::SchemaNotReady)),
            _ => ("", Some(DatabaseHealth::Serving)),
        };
        let (status, body) = readyz_for(extra, health).await;
        assert_eq!(
            status, expected_status,
            "{state}: the status must match the published row"
        );
        assert_eq!(
            body, expected_body,
            "{state}: the body must match the published row"
        );
        assert!(
            DOC.contains(documented_row),
            "{state}: the published wire table must carry the row"
        );
    }
}

/// A database probe that answers whatever the test needs, so the readiness contract can be
/// driven through every state without a real Postgres in the loop (issue #149).
#[derive(Debug)]
struct FixedProbe(DatabaseHealth);

impl ironauth_server::DatabaseProbe for FixedProbe {
    fn check(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = ironauth_server::DatabaseHealth> + Send + '_>,
    > {
        let health = self.0;
        Box::pin(async move { health })
    }
}

// The two degraded cases need a config section and a key; the healthy case needs none. This
// guards the accidental reuse of the exact TOML fragments above without a compile-time link.
#[test]
fn the_degraded_case_configs_parse() {
    let _ = config_from("[outbox]\nironbus_addr = \"127.0.0.1:1\"\n");
    let _ = config_from("[hot_state]\nironcache_addr = \"127.0.0.1:1\"\n");
}
