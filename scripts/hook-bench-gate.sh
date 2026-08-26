#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The hook latency gate (issue #114, criterion 4).
#
# Runs the benchmark, compares it against the two hard bounds and against the committed
# baseline, and fails on either. Three separate refusals, because they answer different
# questions:
#
#   - the GATES are the criterion's absolute bounds. Crossing one is a failure whatever the
#     baseline says, because a deployment feels the absolute number.
#   - the REGRESSION tolerance catches a step change that is still inside the gates. Generous
#     on purpose: a shared runner is noisy, and a benchmark that fails on ordinary variance
#     teaches people to re-run it until it passes.
#   - the RUNNER CLASS must match the one the config names. A p95 is a property of the machine
#     as much as of the code, so a workflow edited to a different runner must fail rather than
#     silently publish numbers from somewhere else. That binding is the reason this script
#     reads the workflow at all.
#
# A MISSING baseline is a FAILURE, not a skip, and a baseline recorded on a different runner
# class is a failure too. Both are the same defect wearing different clothes: a regression check
# with nothing to compare against passes for every possible measurement, so the criterion's
# "fails on regression" would be satisfied by a job that cannot fail. The first run on a new
# runner class is expected to fail and prints the exact line to commit.
#
# LOCAL runs are a different thing and are treated as one. The runner-class check above compares
# the config to the WORKFLOW, which is a claim about a claim: both files can agree perfectly on a
# laptop. So the baseline arm -- both recording and comparing -- runs only under GitHub Actions,
# where the class the workflow names is the class the numbers came from. Locally the two absolute
# gates still apply, because a laptop that cannot hit 1 ms is worth knowing about; the baseline
# is not something a laptop may speak to.
set -euo pipefail

# Set by GitHub Actions on every runner, and by nothing else. The one fact available here that
# distinguishes "this ran on the pinned class" from "this ran somewhere".
ON_THE_PINNED_RUNNER="${GITHUB_ACTIONS:-false}"

cd "$(dirname "$0")/.."

CONFIG="crates/ironauth-hooks/bench-config.toml"
BASELINE="crates/ironauth-hooks/bench-baseline.json"
WORKFLOW=".github/workflows/ci.yml"

read -r RUNNER COLD_GATE WARM_GATE TOLERANCE TARGET <<EOF
$(python3 - "$CONFIG" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    cfg = tomllib.load(fh)
print(
    cfg["runner"]["class"],
    cfg["gates"]["cold_p95_micros"],
    cfg["gates"]["warm_p95_micros"],
    cfg["regression"]["tolerance_percent"],
    cfg["target"]["cold_p95_micros"],
)
PY
)
EOF

# The binding between the config and the job. Without this the config's runner class is a
# sentence nobody checks, and the criterion asks for numbers taken on the class it NAMES.
if ! python3 - "$WORKFLOW" "$RUNNER" <<'PY'
import sys, yaml
with open(sys.argv[1], encoding="utf-8") as fh:
    workflow = yaml.safe_load(fh)
job = workflow["jobs"].get("hook-bench")
if job is None:
    print("hook-bench-gate: no `hook-bench` job in the workflow")
    sys.exit(1)
if job.get("runs-on") != sys.argv[2]:
    print(f"hook-bench-gate: the job runs on {job.get('runs-on')!r}, the config names {sys.argv[2]!r}")
    print("            A p95 is a property of the machine. Published numbers must come from")
    print("            the class the config names, or they are not comparable across releases.")
    sys.exit(1)
PY
then
  exit 1
fi

echo "hook-bench-gate: runner class ${RUNNER}, gates cold<=${COLD_GATE}us warm<=${WARM_GATE}us, tolerance ${TOLERANCE}%"

MEASURED="$(cargo bench -p ironauth-hooks --bench hook_latency 2>/dev/null | grep -E '^\{' | tail -1)"
if [ -z "$MEASURED" ]; then
  echo "hook-bench-gate: the benchmark produced no measurement" >&2
  exit 1
fi
echo "hook-bench-gate: measured ${MEASURED}"

python3 - "$MEASURED" "$BASELINE" "$COLD_GATE" "$WARM_GATE" "$TOLERANCE" "$TARGET" "$RUNNER" "$ON_THE_PINNED_RUNNER" <<'PY'
import json, os, sys

measured = json.loads(sys.argv[1])
baseline_path, cold_gate, warm_gate, tolerance, target, runner = (
    sys.argv[2], float(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]), float(sys.argv[6]),
    sys.argv[7],
)
on_the_pinned_runner = sys.argv[8] == "true"

failures = []
for name, gate in (("cold_p95_micros", cold_gate), ("warm_p95_micros", warm_gate)):
    value = measured[name]
    if value > gate:
        failures.append(f"{name} is {value:.3f}us, over the {gate:.0f}us gate")

# The stated TARGET is reported and never enforced, exactly as the issue asks.
cold = measured["cold_p95_micros"]
print(f"hook-bench-gate: cold {cold:.3f}us against the {target:.0f}us stated target "
      f"({'under' if cold <= target else 'over'}; not a gate)")

def to_commit():
    """The exact file contents that make this run the baseline."""
    return json.dumps(
        {
            "runner_class": runner,
            "cold_p95_micros": round(measured["cold_p95_micros"], 3),
            "warm_p95_micros": round(measured["warm_p95_micros"], 3),
        },
        indent=2,
    )


if not on_the_pinned_runner:
    print("hook-bench-gate: NOT on the pinned runner class, so the baseline arm did not run.")
    print("            These numbers are a local signal against the absolute gates and nothing")
    print("            more: they cannot be committed as a baseline and are not compared to one.")
elif os.path.exists(baseline_path):
    with open(baseline_path, encoding="utf-8") as fh:
        baseline = json.load(fh)
    # A baseline from ANOTHER machine is not a baseline. Comparing against it would either fail
    # for a reason that is not a regression or pass for a reason that is not an improvement, and
    # the tolerance would be measuring the gap between two runner classes.
    recorded_on = baseline.get("runner_class")
    if recorded_on != runner:
        failures.append(
            f"the baseline was recorded on {recorded_on!r}, this job runs on {runner!r}. "
            "Numbers from two classes are not comparable; re-record on the pinned class."
        )
    else:
        for name in ("cold_p95_micros", "warm_p95_micros"):
            before, after = baseline.get(name), measured[name]
            if before is None:
                failures.append(f"the baseline records no {name}, so nothing bounds it")
                continue
            allowed = before * (1.0 + tolerance / 100.0)
            if after > allowed:
                failures.append(
                    f"{name} regressed: {before:.3f}us -> {after:.3f}us, over the "
                    f"{tolerance:.0f}% tolerance ({allowed:.3f}us)"
                )
else:
    failures.append(
        f"no baseline at {baseline_path}. A regression check with nothing to compare against "
        "cannot fail, so a missing baseline is a failure rather than a skip."
    )
    print("hook-bench-gate: commit this as " + baseline_path + " to record this run:")
    print(to_commit())

if failures:
    print("hook-bench-gate: FAILED")
    for failure in failures:
        print(f"  {failure}")
    sys.exit(1)
print("hook-bench-gate: clean")
PY
