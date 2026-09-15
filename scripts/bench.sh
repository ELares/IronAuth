#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# THE BENCHMARK HARNESS, as one command (issue #152 criterion 2).
#
#     PG_BIN=<postgresql bin dir> scripts/bench.sh
#
# Criterion 2 asks that "the benchmark harness reproduces published numbers from a clean
# checkout with ONE documented command, and CI runs it per release". There were three
# commands and three documents, each reproduced separately, and nothing ran any of them on a
# release. Two of the three ran nowhere at all: `scripts/startup-rss-bench.sh` appears in no
# workflow and no gate, and the unit-costs example is compiled by CI and never executed.
#
# That is how docs/UNIT-COSTS.md came to be wrong. Its own "what this does not yet cover"
# section records it: the table is hand-transcribed, and a review re-running the example found
# the published figures off by 0.5 to 1.4 ms against a run-to-run spread of about 0.2 ms.
#
# # What this does NOT do, and why
#
# It does not check the published numbers against the run. It cannot: a benchmark is not
# reproducible across hardware, so a gate comparing a table to a fresh measurement would fail
# on every machine that is not the one the table was written on, and the repair for that is
# always to widen the tolerance until the check means nothing.
#
# What closes the drift is generating the tables from a run on a NAMED instance class rather
# than transcribing them, which is the release-pipeline half of criterion 4 and needs the
# hardware the sizing guide recommends. This command is the half that can exist now: one
# entry point, one output file, and a release lane that runs it.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

OUT="${BENCH_OUT:-target/bench}"
mkdir -p "$OUT"
failures=0

# EVERY BENCHMARK RUNS EVEN IF AN EARLIER ONE FAILS. A harness that stops at the first
# failure publishes a partial result set that looks like a complete one, and the missing rows
# are invisible in the output rather than named in it.
run() {
    name="$1"
    shift
    echo "bench: $name"
    if "$@" > "$OUT/$name.log" 2>&1; then
        echo "bench: $name ok -> $OUT/$name.log"
    else
        echo "::error::bench: $name FAILED (see $OUT/$name.log)"
        tail -20 "$OUT/$name.log" || true
        failures=$((failures + 1))
    fi
}

# Per-operation unit costs: password hashing at each parameter set, and token mint.
run unit-costs cargo run --release -q -p ironauth-oidc --example unit_costs

# Startup time and idle RSS. Needs a Postgres binary directory; skipped rather than failed
# when there is none, because a machine without one can still run the other two and a hard
# failure here would stop anyone from getting any numbers.
if [ -n "${PG_BIN:-}" ]; then
    run startup-rss scripts/startup-rss-bench.sh
else
    echo "bench: startup-rss SKIPPED (set PG_BIN to the postgresql bin directory)"
    echo "skipped: PG_BIN unset" > "$OUT/startup-rss.log"
fi

# WASM hook latency.
#
# THIS ONE IS A GATE, NOT ONLY A BENCHMARK, and the harness must not inherit its verdict. The
# hook script compares a measured p95 against a committed target and exits 1 when the machine
# is over it. A CI runner is slower than a developer machine, so wiring that verdict into the
# harness's exit status would paint every release red for a threshold rather than for a failure
# to reproduce, and the repair anyone would reach for is raising the threshold.
#
# So the harness asks a different question of this one: did it MEASURE? The gate prints one
# `hook-bench-gate: measured {...}` line carrying the samples as JSON, before it reaches any
# verdict, and it prints that line in EVERY arm. So the line separates "ran, and was over the
# target" from "could not run at all". Only the second is a harness failure.
#
# NOT the measurement file. `target/hook-bench-measurement.json` looks like the obvious
# discriminator and is the wrong one: the gate only writes it on the pinned runner class, so on
# any other machine it is absent whether the run succeeded or failed. Keying on it classified a
# perfectly good local run as unmeasured. A discriminator that is false on most machines
# discriminates nothing.
#
# This does not un-gate hook latency. The threshold is enforced by the `hook-bench` CI job,
# which runs this same script on every push and does inherit its exit status.
echo "bench: hook-latency"
hook_status=0
scripts/hook-bench-gate.sh > "$OUT/hook-latency.log" 2>&1 || hook_status=$?
if grep -q "hook-bench-gate: measured" "$OUT/hook-latency.log"; then
    # Publish the samples from the log, so the harness emits numbers on every machine rather
    # than only on the one where the gate also writes them to a file of its own.
    grep "hook-bench-gate: measured" "$OUT/hook-latency.log" \
        | sed 's/^hook-bench-gate: measured //' > "$OUT/hook-latency-samples.json"
    if [ "$hook_status" -eq 0 ]; then
        echo "bench: hook-latency ok -> $OUT/hook-latency.log"
    else
        echo "bench: hook-latency measured, OVER ITS TARGET -> $OUT/hook-latency.log"
        echo "bench: that verdict is enforced by the hook-bench CI job, not by this harness"
        tail -20 "$OUT/hook-latency.log" || true
    fi
else
    echo "::error::bench: hook-latency did not measure (see $OUT/hook-latency.log)"
    tail -20 "$OUT/hook-latency.log" || true
    failures=$((failures + 1))
fi

echo
echo "bench: results in $OUT"
ls -1 "$OUT"

if [ "$failures" -ne 0 ]; then
    echo "::error::bench: $failures benchmark(s) failed"
    exit 1
fi
echo "bench: all benchmarks completed"
