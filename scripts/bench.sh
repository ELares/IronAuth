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
# workflow and no gate, and the unit-costs example is compiled by `--all-targets` and never
# executed.
#
# That is how docs/UNIT-COSTS.md came to be wrong. Its own "what this does not yet cover"
# section now records the size of it: re-running the example put six of its ten published
# figures outside their own ranges.
#
# It is also how a measurement nobody had taken decided an open design question. The JWKS render
# and the socket round trip below bracket the value of a cache in front of the published JWKS
# document, and running them answered issue #146's wiring question in the opposite direction
# from the one the code was heading.
#
# # Every benchmark reports RAN, SKIPPED, or FAILED, and a SKIP IS NOT SILENT
#
# The first draft of this script had two silent holes. A missing PG_BIN printed "all
# benchmarks completed" and exited 0 with a third of the harness not run, and a stale output
# file from a previous run was listed as this run's results. A harness that reports success
# while publishing a partial result set is worse than one that fails, because the missing
# rows are invisible in the output rather than named in it.
#
# So: outputs are cleared before the run, every benchmark lands in the summary with its
# status, and ON CI THE DOC-BACKED BENCHMARKS MAY NOT SKIP. That last rule is decided here,
# from $GITHUB_ACTIONS, rather than passed in by the workflow. A required-benchmark list
# supplied by the caller is a list the caller can forget, which puts the silent skip back.
#
# # What this does NOT do, and why
#
# It does not check the published numbers against the run. It cannot: a benchmark is not
# reproducible across hardware, so a gate comparing a table to a fresh measurement would fail
# on every machine that is not the one the table was written on, and the repair for that is
# always to widen the tolerance until the check means nothing. What closes the drift is
# generating the tables from a PINNED run on a NAMED instance class, which is criterion 4 and
# needs hardware this lane does not have. See docs/UNIT-COSTS.md.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)" || {
    echo "::error::bench: not inside a git repository" >&2
    exit 1
}
cd "$ROOT" || exit 1

OUT="${BENCH_OUT:-target/bench}"
mkdir -p "$OUT" || {
    echo "::error::bench: cannot create $OUT" >&2
    exit 1
}

# ON CI THE DOC-BACKED BENCHMARKS ARE REQUIRED. Off CI a developer without Postgres installed
# should still get the benchmarks that do not need it, with the gap named in the summary.
on_ci=false
[ "${GITHUB_ACTIONS:-}" = "true" ] && on_ci=true

# STALE OUTPUTS ARE THIS RUN'S OUTPUTS UNTIL THEY ARE REMOVED. Named files rather than
# `rm -rf "$OUT"`, because BENCH_OUT is a caller-supplied path and this script should not
# recursively delete one.
for stale in unit-costs startup-rss socket-rtt hook-latency; do
    rm -f "$OUT/$stale.log"
done
rm -f "$OUT/hook-latency-samples.json" "$OUT/SUMMARY.txt"

summary=""
failures=0

record() { summary="${summary}$1"$'\n'; }

# EVERY BENCHMARK RUNS EVEN IF AN EARLIER ONE FAILS, so one failure does not hide the state of
# the others.
run() {
    name="$1"
    shift
    echo "bench: $name"
    if "$@" > "$OUT/$name.log" 2>&1; then
        echo "bench: $name RAN -> $OUT/$name.log"
        record "RAN      $name"
    else
        echo "::error::bench: $name FAILED (see $OUT/$name.log)"
        tail -20 "$OUT/$name.log" || true
        record "FAILED   $name"
        failures=$((failures + 1))
    fi
}

# A skip is a failure wherever the benchmark is required, and a named line in the summary
# wherever it is not.
skip() {
    name="$1"
    reason="$2"
    required="$3"
    echo "skipped: $reason" > "$OUT/$name.log"
    if [ "$required" = required ]; then
        echo "::error::bench: $name SKIPPED but required here: $reason"
        record "FAILED   $name (required, skipped: $reason)"
        failures=$((failures + 1))
    else
        echo "bench: $name SKIPPED: $reason"
        record "SKIPPED  $name ($reason)"
    fi
}

# Per-operation unit costs: password hashing at each parameter set, and token mint. Backs
# docs/UNIT-COSTS.md. Needs no database.
run unit-costs cargo run --release -q -p ironauth-oidc --example unit_costs

# Startup time and idle RSS, backing docs/PERFORMANCE.md. The script initdb's and starts its
# own throwaway cluster from $PG_BIN, so this needs a Postgres bin directory and no service.
if [ -n "${PG_BIN:-}" ]; then
    run startup-rss scripts/startup-rss-bench.sh
elif [ "$on_ci" = true ]; then
    skip startup-rss "PG_BIN unset" required
else
    skip startup-rss "PG_BIN unset; set it to the postgresql bin directory" optional
fi

# The cost of one socket round trip, which is what decides whether a cache in front of an
# operation pays for itself. Backs the accelerator section of docs/UNIT-COSTS.md. Needs a
# Postgres bin directory for pgbench, and starts its own throwaway cluster.
if [ -n "${PG_BIN:-}" ]; then
    run socket-rtt scripts/socket-rtt-bench.sh
elif [ "$on_ci" = true ]; then
    skip socket-rtt "PG_BIN unset" required
else
    skip socket-rtt "PG_BIN unset; set it to the postgresql bin directory" optional
fi

# WASM hook latency.
#
# THIS ONE IS A GATE PINNED TO A MACHINE, NOT A PORTABLE BENCHMARK, and on CI this harness
# does not run it. `scripts/hook-bench-gate.sh` validates the `runs-on` of the `hook-bench`
# job in ci.yml against crates/ironauth-hooks/bench-config.toml, and then refuses to run as
# any other job, because a p95 measured somewhere else is held to a baseline recorded for a
# machine it was not measured on. Running it from a second CI job asks it to break that rule.
#
# The first draft did exactly that, and every release would have gone red: the gate exits on
# the job-identity check BEFORE it measures, and the harness reported that as "hook-latency
# did not measure", which reads as a broken benchmark rather than as a job name this script
# chose. That draft was built on the premise that the gate prints its measurement in every
# arm. It does not; ci.yml says so in as many words, and there are seven arms that exit first.
#
# None of this un-gates hook latency, and nothing here needs to: the threshold is enforced by
# the `hook-bench` job on every push to main and on every pull request, which is a stricter
# schedule than per-release. Hook latency also backs no published document; the harness's job
# is the numbers in docs/, and those are the two above.
if [ "$on_ci" = true ]; then
    skip hook-latency "gated by ci.yml's hook-bench job, which pins the runner class" optional
else
    run hook-latency scripts/hook-bench-gate.sh
    # Publish the samples from the log, so a local run emits numbers even on a machine where
    # the gate does not write its own measurement file (it writes one only on the pinned
    # runner class).
    if grep -q "hook-bench-gate: measured" "$OUT/hook-latency.log" 2>/dev/null; then
        grep "hook-bench-gate: measured" "$OUT/hook-latency.log" \
            | sed 's/^hook-bench-gate: measured //' > "$OUT/hook-latency-samples.json"
    fi
fi

printf '%s' "$summary" > "$OUT/SUMMARY.txt"

echo
echo "bench: results in $OUT"
printf '%s' "$summary"

if [ "$failures" -ne 0 ]; then
    echo "::error::bench: $failures benchmark(s) failed"
    exit 1
fi
echo "bench: every benchmark above either ran or is recorded as skipped"
