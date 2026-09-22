// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit the published failure matrix as markdown (issue #149 criterion 5), for
//! `scripts/failure-matrix-check.sh`.
//!
//! # Why the document is generated
//!
//! Criterion 5 asks that the failure matrix "be generated from test output, so docs cannot
//! drift from behavior". The readiness surface ships its contract as types - `Readiness`,
//! [`DegradedTier`] - and the tests pin the wire format through the real handler. What was
//! missing was the PUBLISHED half: an operator who wants the per-tier runbook has to read
//! source today.
//!
//! This example writes the whole page, prose included, so the page cannot disagree with the
//! generator and the generator cannot disagree with the types it derives the rows from. A
//! tier added to `DegradedTier::ALL` with no row here fails the generator's own both-directions
//! check; a tier renamed fails the committed-page diff in CI. The wire table is pinned against
//! the real `/readyz` handler by `crates/ironauth-server/tests/failure_matrix.rs`, which is the
//! half this file cannot see: the bodies live in `routes.rs`, not in a constant this example
//! could read.
//!
//! An example binary rather than a build script, mirroring `metrics-doc.rs`: the generator is
//! something a person can run and read the output of, and nothing in the shipped build depends
//! on it having run.

use ironauth_server::DegradedTier;

fn main() {
    let tiers = DegradedTier::ALL;
    for tier in tiers {
        assert!(
            TIER_ROWS.iter().any(|(token, ..)| *token == tier.token()),
            "a DegradedTier has no row in this matrix: {:?} ({})",
            tier,
            tier.token()
        );
    }
    for (token, ..) in TIER_ROWS {
        assert!(
            tiers.iter().any(|tier| tier.token() == token),
            "a matrix row names a tier this build does not have: {token}"
        );
    }

    let mut out = String::new();
    out.push_str(PREAMBLE);
    out.push('\n');
    out.push_str(WIRE_CONTRACT_PREAMBLE);
    out.push_str("| state | status | body |\n| --- | --- | --- |\n");
    for (state, status, body) in WIRE_ROWS {
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!("| {state} | {status} | `{body}` |\n"),
        );
    }
    out.push('\n');
    out.push_str(TIERS_PREAMBLE);
    out.push_str("| tier | token | absent component | how it attaches | request paths | RPO / RTO | operator signal |\n| --- | --- | --- | --- | --- | --- | --- |\n");
    for (token, absent, attaches, paths, rpo_rto, signal) in TIER_ROWS {
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "| `{token}` | `{token}` | {absent} | {attaches} | {paths} | {rpo_rto} | {signal} |\n"
            ),
        );
    }
    out.push_str(FOOTER);
    print!("{out}");
}

/// How each tier is attached and what an operator sees, written next to the token so a
/// generator cannot render a token with no runbook and a runbook cannot ride an unknown token.
///
/// The "how it attaches" column names the config key the probe's wiring reads
/// (`ReadinessProbe::from_config`), pinned by the `wiring_tests` in `readiness.rs`. The
/// request-path and RPO/RTO columns are the DESIGN of each tier as the code implements it;
/// whether a deployment has enough bootstrapped state to exercise them is a separate claim,
/// and the matrix's scope section says which parts are currently verified end to end.
const TIER_ROWS: [(&str, &str, &str, &str, &str, &str); 2] = [
    (
        "backbone_absent",
        "the async backbone (IronBus) is unreachable",
        "`outbox.ironbus_addr` set but not answering",
        "none: no request path consults the backbone; outbox work accumulates in Postgres and drains on recovery, because the drain is a Postgres poll and the backbone only decides WHEN it runs",
        "RPO 0 (nothing is dropped; the outbox is the store of record and the drain resumes on recovery). RTO: delivery latency degrades to the poll interval; no request path is affected",
        "`/readyz` answers `200 degraded: backbone_absent`; queue-lag metrics rise and recover as the drain catches up",
    ),
    (
        "accelerator_absent",
        "the shared hot-state accelerator (IronCache) is unreachable",
        "`hot_state.ironcache_addr` set but not answering",
        "none today: `ironauth-hot` is not a dependency of any crate that serves a request, so this is a LATENCY tier - reported only when a deployment declared the accelerator, and reported for reachability, never for correctness",
        "RPO 0 / RTO: latency only. `ironauth_hot::Tiered`'s outage tests measure every answer identical with the accelerator failing every call",
        "`/readyz` answers `200 degraded: accelerator_absent`",
    ),
];

/// The readiness wire contract, as the handler renders it. Mirrors `routes::readyz`; the
/// test file pins this table against the REAL handler, so a body that drifts from the code
/// fails there even if this generator were edited to match the drift.
const WIRE_ROWS: [(&str, &str, &str); 6] = [
    ("healthy", "200", "ready"),
    (
        "healthy (socket-only probe)",
        "200",
        "ready: probe=socket-only",
    ),
    (
        "degraded: backbone absent",
        "200",
        "degraded: backbone_absent",
    ),
    (
        "degraded: accelerator absent",
        "200",
        "degraded: accelerator_absent",
    ),
    (
        "database unreachable",
        "503",
        "not ready: database unreachable",
    ),
    (
        "schema not migrated",
        "503",
        "not ready: schema not migrated",
    ),
];

const PREAMBLE: &str = r"# The failure matrix

What this build does when a component goes down, per failure class: which `/readyz` state it
reports, what keeps serving, what fails, and what an operator should page about. GENERATED
from `DegradedTier::ALL` and the rows in `crates/ironauth-server/examples/failure-matrix.rs`
by `scripts/failure-matrix-check.sh`, which CI runs; a hand edit here fails that gate. Do not
write this page, write the generator.

## How to read a row

Each tier is one *optional* component whose absence degrades rather than stops the
deployment. Degraded is SERVING: every flow still completes, and only latency or timeliness
suffers. That is why `/readyz` answers `200` for a degraded tier - a `503` would have a
Kubernetes readiness probe pull the pod out of its Service because an optional component is
down, turning an accelerator outage into an availability outage. HARD DOWN is the only `503`,
because Postgres is the tier everything is complete on.

The readiness probe has two depths, and the body says which one answered: `query` is a real
database query, `socket-only` is a bare TCP connect (a deployment that could not attach a
database probe falls back to it). A weaker check never renders identically to a stronger one.
";

const WIRE_CONTRACT_PREAMBLE: &str = r"## The `/readyz` wire contract

Three outcomes across two status codes, rendered by `routes::readyz` and pinned against the
real handler by `tests/failure_matrix.rs`:

";

const TIERS_PREAMBLE: &str = r"## The tiers

One row per `DegradedTier::ALL` entry; a tier with no row, or a row with no tier, fails the
generator. The attachment column is pinned by the wiring tests in `readiness.rs`.

";

const FOOTER: &str = r"
## Combined failures

Two rules, each pinned by a test:

- **The database dominates.** Whatever else is absent, an unreachable or unqueryable database
  is hard down - `503` - because Postgres is the tier everything is complete on
  (`an_unreachable_database_is_hard_down_whatever_else_answers`). There is no degraded tier
  above a down database.
- **Among optional components, the first declared names the tier.** `ReadinessProbe` reports
  in declaration order, backbone before cache: when both are absent, an operator is told about
  the queue that is not draining before the cache that is not answering.

## What is deliberately NOT in this matrix

This page documents what the readiness surface REPORTS and the design of each tier. It does
not claim system-level verification that is not there:

- **Postgres-down serving of discovery/JWKS/validation** is designed (fresh-cache,
  publication-only, per the #149 criterion 2 work) but is not a system-level chaos property
  in CI yet; it needs a bootstrapped tenant, which is the milestone's shared bootstrap gap.
- **IronCache-down flow completion within stall bounds** is measured at the `ironauth_hot`
  crate level only; no request path consults the accelerator yet, so there is no system-level
  tier to verify.
- **IronBus-down outbox drain** follows from the outbox's Postgres poll by construction; the
  drain-and-recovery chaos test does not exist yet.

The matrix will grow rows as those properties become system-level, and the both-directions
checks in the generator and the test file are what keep the page honest while it does.

## Regenerating

    scripts/failure-matrix-check.sh
";
