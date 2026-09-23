#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# PUBLISH THE FAILURE MATRIX (issue #149 criterion 5).
#
#     scripts/failure-matrix-check.sh
#
# Regenerates docs/FAILURE-MATRIX.md from the generator
# (crates/ironauth-server/examples/failure-matrix.rs) and fails if the committed page
# drifted, the same shape every generated artifact in this repository uses.
#
# The matrix was already pinned against the CODE by
# `crates/ironauth-server/tests/failure_matrix.rs` (tier tokens and the /readyz wire bodies
# against the real handler). What it was not was PUBLISHED: criterion 5 asks for a failure
# matrix "generated from test output, so docs cannot drift from behavior", and an operator
# who wanted the per-tier runbook had to read the readiness source.
#
# Generated rather than written, because a hand-maintained matrix is a page that rots while
# the code it describes stays right, and a reader has no way to tell which one is current.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

cargo run --quiet -p ironauth-server --example failure-matrix > docs/FAILURE-MATRIX.md

echo "failure-matrix-check: docs/FAILURE-MATRIX.md regenerated"
require_tracked "failure-matrix-check" docs/FAILURE-MATRIX.md || exit 1
if ! git diff --exit-code docs/FAILURE-MATRIX.md >/dev/null 2>&1; then
    echo "failure-matrix-check: the committed failure matrix is STALE."
    echo "  A tier, a token, a /readyz body or the prose in the generator changed, and the"
    echo "  published page still describes the old one. Commit the regenerated page: an"
    echo "  operator reading a stale tier token mid-incident opens the wrong runbook, which"
    echo "  is the failure this diff exists to surface."
    git --no-pager diff -- docs/FAILURE-MATRIX.md || true
    exit 1
fi
echo "failure-matrix-check: clean"