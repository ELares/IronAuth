// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit the published metric contract as markdown (issue #152), for `scripts/metrics-doc.sh`.
//!
//! # Why the document is generated
//!
//! `metrics::CONTRACT` already IS the contract: `tests/metric_contract.rs` checks it against the
//! emit sites in both directions, so a metric cannot be exported without an entry and an entry
//! cannot be promised without an emit site. What was missing was the PUBLISHING half of the
//! issue's title. A dashboard author outside this repository had no way to read the contract
//! except by opening a Rust source file.
//!
//! Generating it from the same value is the point rather than a convenience. A hand-written
//! metrics page is the exact artifact this repository keeps re-learning about: the code stays
//! right because tests check it, the page rots because nothing regenerates it, and a reader
//! believes the page. Here the page cannot disagree with the contract, and the contract cannot
//! disagree with the code.
//!
//! An example binary rather than a build script, mirroring `ironauth-store`'s `event-catalog`:
//! the generator is something a person can run and read the output of, and nothing in the
//! shipped build depends on it having run.

use std::fmt::Write as _;

use ironauth_server::metrics::{CONTRACT, MetricSpec};

fn main() {
    let mut specs: Vec<&MetricSpec> = CONTRACT.iter().collect();
    specs.sort_by_key(|spec| spec.name);

    let mut out = String::new();
    out.push_str(PREAMBLE);
    out.push_str("\n| metric | type | labels | meaning |\n| --- | --- | --- | --- |\n");
    for spec in &specs {
        let labels = if spec.labels.is_empty() {
            "none".to_owned()
        } else {
            let mut names: Vec<&str> = spec.labels.to_vec();
            names.sort_unstable();
            names
                .iter()
                .map(|label| format!("`{label}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            spec.name,
            spec.kind.type_word(),
            labels,
            spec.help
        );
    }
    let _ = writeln!(
        out,
        "\n{} metrics, {} of them carrying no labels at all.",
        specs.len(),
        specs.iter().filter(|spec| spec.labels.is_empty()).count()
    );
    out.push_str(FOOTER);
    print!("{out}");
}

const PREAMBLE: &str = r"# The metric contract

Every series this build exports, with its type, its labels and what it means. GENERATED from
`metrics::CONTRACT` in `crates/ironauth-server/src/metrics.rs` by `scripts/metrics-doc.sh`,
which CI runs; a hand edit here fails that gate. Do not write this page, write the contract.

## What the contract promises

`crates/ironauth-server/tests/metric_contract.rs` checks the contract against the emit sites in
BOTH directions, which is what makes this page worth writing a dashboard against:

- a metric listed here whose emit sites have all been DELETED fails the build, so a panel does
  not go quiet because the series it queries stopped existing. This is a check on the source,
  not on coverage: a site that still exists on a path nothing reaches passes it, and only a
  test that drives the path can say the series is actually produced; and
- a metric emitted and not listed here fails the build, so a series cannot appear on your
  scrape without having been reviewed.

The labels and kind are checked too: an emitted label this page does not list, a declared
label absent from every emit site, or a gauge this page calls a counter fails. An individual
site may emit a subset of the declared labels; the check compares their union across sites.

THAT SENTENCE WAS PUBLISHED BEFORE IT WAS TRUE, which is worth leaving here rather than quietly
correcting. The label check ran over emit sites resolved through one crate's constants only, so
it reached eleven of the metrics in the table below while this page told a dashboard author it
reached all of them. A `tenant` label added to any of the others left every test green. The scan
now resolves a metric named by a string literal and by a constant declared anywhere in the
workspace, `both_scans_find_the_same_emit_sites` asserts the two independently written walks
over the tree agree about what an emit site is, and the mutation above now fails.

## Cardinality

NO METRIC HERE CARRIES A TENANT, CLIENT, USER OR ENVIRONMENT LABEL, and that is a deliberate
bound rather than an omission. Such a label multiplies every series it touches by the number of
distinct values a deployment has, which is unbounded from this repository's side: it is the
standard way to bring down a Prometheus instance, and it puts identifiers on a surface that is
usually scraped by something less protected than the database.

Two labels are worth reading carefully, because both are named `route` and they are not the
same quantity. On the HTTP metrics it is the route TEMPLATE, normalised before it is used as a
label for exactly this reason, so a request to an unrouted path cannot mint a series. On
`ironauth_sms_route_throttled_total` it is the destination route derived from the E.164 number,
so its domain is the set of dialling destinations rather than the set of phone numbers.

The per-tenant view is not missing, it is somewhere else. Per-tenant counts come from the
events and usage-metering API, which is authenticated, scoped, and paginated, and where a
tenant identifier is the point rather than a cardinality hazard.

`no_metric_carries_a_per_principal_label` in the contract test enforces the paragraph above,
including on any label name ending in `_id`. It reads BOTH the contract's declared labels and
the labels the emit sites actually set, which is the difference between a promise and the
behaviour: its first version read the contract alone, so adding `tenant` to an emit site put the
label on the wire with every test green.
";

const FOOTER: &str = r"
## Scope

Every metric this workspace emits, wherever it is emitted from. The contract is DECLARED in the
server crate and is not limited to it: most of the table above is emitted from `ironauth-oidc`,
the rest from the binary crate, `ironauth-fetch` and the server.

An earlier version of this paragraph gave the split as a measured count, and the next change to
add a metric falsified every number in it while this page regenerated byte-identically, because
the prose travels inside the generator and only the table is derived. A count that is not
computed from the contract does not belong on a page generated from the contract.

Two tests hold that boundary from different sides.
`the_contract_covers_every_metric_this_module_declares` refuses a metric constant declared in
the server's metrics module with no contract entry, and
`the_contract_covers_every_metric_the_workspace_emits` refuses a metric emitted anywhere in the
workspace with no contract entry. So a new series cannot reach a scrape without appearing on
this page.

## Regenerating

    scripts/metrics-doc.sh
";
