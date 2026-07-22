#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Golden-path replay gate (issue #92, PR 7): re-execute every committed journey transcript under
# docs/journey-transcripts against its journey artifact's compiled routing, and FAIL on any
# behavioral drift between flow versions. A transcript records a WHOLE journey run as the scenario
# that drives it (a sequence of per-step outcome signals plus the subject context the guards read)
# and the step sequence the routing is expected to produce. Replaying it walks the compiled
# transition table with the SAME document-order-first-true-guard rule the live engine drives, with
# no clock, no entropy, and no database (the evaluation context is pinned by the transcript and the
# evaluator is pure), so a version whose routing changed (a guard edited, a transition added or
# reordered) makes the recorded transcript diverge and this gate trips LOUDLY.
#
# Runnable both in the deployer's CI (over their own committed transcripts) and in IronAuth's own
# CI. Mirrors scripts/flow-golden.sh: the default CHECK mode fails on drift, and the --regenerate
# mode recomputes the expected outcomes and rewrites the transcripts so an author who deliberately
# changes routing updates the goldens by a reviewable diff. Idempotent: --regenerate on a corpus
# with no drift rewrites to byte-identical files.
#
# Usage:
#   scripts/journey-replay.sh              # check every transcript, fail on drift
#   scripts/journey-replay.sh --regenerate # rewrite expected outcomes from current routing
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

cargo run --quiet -p ironauth-journey --example journey-replay -- "$@"
