#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# PUBLISH THE METRIC CONTRACT (issue #152).
#
#     scripts/metrics-doc.sh
#
# Regenerates docs/METRICS.md from `metrics::CONTRACT` and fails if the committed page drifted,
# the same shape every generated artifact in this repository uses.
#
# The contract was already checked against the emit sites in both directions by
# `crates/ironauth-server/tests/metric_contract.rs`. What it was not was PUBLISHED: the issue's
# title asks for the contract, the benchmarks and the sizing guide, and the other two are
# documents in docs/ while this one was a Rust constant. Someone writing a dashboard against
# this build had to read a source file to find out what it exports.
#
# Generated rather than written, because a hand-maintained metrics page is a page that rots
# while the code it describes stays right, and a reader has no way to tell which one is current.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

cargo run --quiet -p ironauth-server --example metrics-doc > docs/METRICS.md

echo "metrics-doc: docs/METRICS.md regenerated"
require_tracked "metrics-doc" docs/METRICS.md || exit 1
if ! git diff --exit-code docs/METRICS.md >/dev/null 2>&1; then
    echo "metrics-doc: the committed metric contract page is STALE."
    echo "  A metric, a label or a help string changed in metrics::CONTRACT and the published"
    echo "  page still describes the old one. Commit the regenerated page: a dashboard written"
    echo "  against a stale label list breaks silently, which is the failure this diff exists"
    echo "  to surface."
    git --no-pager diff -- docs/METRICS.md || true
    exit 1
fi
echo "metrics-doc: clean"
