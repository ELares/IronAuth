#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The hook latency gate (issue #114, criterion 4).
#
# Runs the benchmark, compares it against the criterion's absolute bounds and against the
# committed baseline, and fails on either. Three separate refusals, because they answer
# different questions:
#
#   - the GATES are the criterion's absolute bounds. Crossing one is a failure whatever the
#     baseline says, because a deployment feels the absolute number.
#   - the REGRESSION tolerance catches a step change that is still inside the gates. Generous,
#     because a shared runner is noisy and a benchmark that fails on ordinary variance teaches
#     people to re-run it until it passes -- but BOUNDED, because an unbounded tolerance is a
#     regression check that cannot fail.
#   - the MACHINE must be the one the numbers are published against. A p95 is a property of the
#     machine as much as of the code.
#
# A MISSING baseline is a FAILURE, not a skip. With nothing to compare against, every possible
# measurement passes, so the criterion's "fails on regression" would be satisfied by a job that
# cannot fail. The first run on a new machine is expected to fail and prints the line to commit.
#
# WHAT COUNTS AS "THE MACHINE", and why the first version got it wrong. That version wrote the
# config's `runner.class` into the baseline and then compared the baseline's class against the
# config's -- both sides read from one file, so the check could not fail for the reason it
# existed. It happily stamped numbers taken on an arm64 laptop as `ubuntu-latest`. The identity
# recorded now is MEASURED from the environment the job is actually running in (`RUNNER_OS`,
# `RUNNER_ARCH`, `ImageOS`), so a rotated runner image refuses the comparison and asks for a
# re-record -- which is precisely the event the "property of the machine" argument is about.
set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG="crates/ironauth-hooks/bench-config.toml"
BASELINE="crates/ironauth-hooks/bench-baseline.json"
WORKFLOW=".github/workflows/ci.yml"
# The job this gate belongs to. Named here as well as in the workflow so a second job cannot
# quietly run this script and be measured against the first job's machine.
JOB="hook-bench"

# THE CONFIG, read in a way that cannot fail silently.
#
# A `python3 - <<PY` inside `$(...)` that exits non-zero leaves the shell continuing with EMPTY
# variables: `set -e` does not see the failure, and every later comparison then fails for a
# reason that has nothing to do with the real fault. Measured on the first version -- a missing
# `[regression]` section reported "the job runs on 'ubuntu-latest', the config names ''". So the
# read is checked on its own line, and its status is checked.
if ! CONFIG_VALUES="$(python3 - "$CONFIG" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    cfg = tomllib.load(fh)
# Every value is required. `.get(...)` with a default would invent a bound nobody wrote.
print(cfg["runner"]["class"])
print(cfg["gates"]["cold_p95_micros"])
print(cfg["gates"]["warm_p95_micros"])
print(cfg["regression"]["tolerance_percent"])
print(cfg["regression"]["max_tolerance_percent"])
print(cfg["target"]["cold_p95_micros"])
print(cfg["samples"]["min_cold_iterations"])
print(cfg["samples"]["min_warm_iterations"])
PY
)"; then
  echo "hook-bench-gate: $CONFIG could not be read; the message above is the reason" >&2
  exit 1
fi
# One value per LINE, not one line split on whitespace: `read -r a b c` word-splits, so a runner
# class containing a space would shift every field after it.
{
  IFS= read -r RUNNER
  IFS= read -r COLD_GATE
  IFS= read -r WARM_GATE
  IFS= read -r TOLERANCE
  IFS= read -r MAX_TOLERANCE
  IFS= read -r TARGET
  IFS= read -r MIN_COLD_ITERATIONS
  IFS= read -r MIN_WARM_ITERATIONS
} <<EOF
$CONFIG_VALUES
EOF

# The binding between the config and the job. Without it the config's runner class is a sentence
# nobody checks, and the criterion asks for numbers taken on the class it NAMES.
if ! python3 - "$WORKFLOW" "$RUNNER" "$JOB" <<'PY'
import sys, yaml

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        workflow = yaml.safe_load(fh)
except FileNotFoundError:
    print(f"hook-bench-gate: {sys.argv[1]} is missing")
    sys.exit(1)

declared, job_name = sys.argv[2], sys.argv[3]
job = workflow["jobs"].get(job_name)
if job is None:
    print(f"hook-bench-gate: no `{job_name}` job in the workflow")
    sys.exit(1)

runs_on = job.get("runs-on")
# `runs-on` has three spellings for one machine: a string, a one-element list, and a mapping
# with `labels`. Refusing a reformat that names the SAME runner would make this a lint on YAML
# style rather than a check on where the numbers come from.
if isinstance(runs_on, dict):
    runs_on = runs_on.get("labels")
if isinstance(runs_on, list):
    runs_on = runs_on[0] if len(runs_on) == 1 else runs_on
if runs_on != declared:
    print(f"hook-bench-gate: the job runs on {runs_on!r}, the config names {declared!r}")
    print("            A p95 is a property of the machine. Published numbers must come from")
    print("            the class the config names, or they are not comparable across releases.")
    sys.exit(1)
PY
then
  exit 1
fi

# AM I ACTUALLY ON THAT MACHINE?
#
# Everything above compares one file in this repository against another; both agree perfectly on
# a laptop. `GITHUB_ACTIONS` is set to the string "true" by Actions and by nothing else, so it is
# the one fact here that is not self-referential.
#
# Any OTHER value is a FAILURE rather than a fall-through to the local path. The first version
# tested `== "true"` and treated everything else as local, so `GITHUB_ACTIONS=TRUE` -- or `1`, or
# a typo -- silently took the branch that skips the baseline and exits 0. A check whose disarmed
# state is green is not a check.
GITHUB_ACTIONS_VALUE="${GITHUB_ACTIONS:-}"
case "$GITHUB_ACTIONS_VALUE" in
  true) ON_CI=true ;;
  "") ON_CI=false ;;
  *)
    echo "hook-bench-gate: GITHUB_ACTIONS is set to '${GITHUB_ACTIONS_VALUE}'." >&2
    echo "            Actions sets it to exactly 'true'. Refusing rather than guessing:" >&2
    echo "            treating an unrecognized value as 'not CI' would skip the baseline" >&2
    echo "            check and exit clean, which is the failure this gate is about." >&2
    exit 1
    ;;
esac

if [ "$ON_CI" = true ] && [ "${GITHUB_JOB:-$JOB}" != "$JOB" ]; then
  echo "hook-bench-gate: running as job '${GITHUB_JOB:-}', not '${JOB}'." >&2
  echo "            The runner-class check above validates ${JOB}'s \`runs-on\`, so another" >&2
  echo "            job running this script would be measured against a machine it is not on." >&2
  exit 1
fi

echo "hook-bench-gate: runner class ${RUNNER}, gates cold<=${COLD_GATE}us warm<=${WARM_GATE}us, tolerance ${TOLERANCE}%"

# The benchmark. Stderr is KEPT: the likeliest CI failure is a missing `wasm32-wasip2` target,
# which `build.rs` asserts on with a fix-it message, and discarding it leaves a red job with no
# diagnostic. The output is captured to a file rather than a `$(...)` pipeline so a build failure
# is distinguishable from a benchmark that ran and printed nothing -- under `pipefail` a `grep`
# that matches nothing ends the script before any message about it can be printed.
BENCH_OUTPUT="$(mktemp)"
trap 'rm -f "$BENCH_OUTPUT"' EXIT
if ! cargo bench -p ironauth-hooks --bench hook_latency >"$BENCH_OUTPUT" 2>&1; then
  echo "hook-bench-gate: the benchmark did not run. Its output:" >&2
  cat "$BENCH_OUTPUT" >&2
  exit 1
fi
MEASURED="$(grep -E '^\{' "$BENCH_OUTPUT" | tail -1 || true)"
if [ -z "$MEASURED" ]; then
  echo "hook-bench-gate: the benchmark produced no measurement. Its output:" >&2
  cat "$BENCH_OUTPUT" >&2
  exit 1
fi
echo "hook-bench-gate: measured ${MEASURED}"

# The MEASURED machine identity, from the environment rather than from a file in this repo.
# Empty off CI, where the baseline arm does not run at all.
MACHINE="${RUNNER_OS:-}/${RUNNER_ARCH:-}/${ImageOS:-}"

# The measurement, published for the release to pick up (criterion 4: "numbers are published per
# release"). Written unconditionally, so a run that PASSES publishes its numbers too -- the
# baseline file only changes when somebody commits one, which is not often enough to be what a
# release reads.
MEASUREMENT_OUT="${HOOK_BENCH_MEASUREMENT_PATH:-target/hook-bench-measurement.json}"

python3 - "$MEASURED" "$BASELINE" "$COLD_GATE" "$WARM_GATE" "$TOLERANCE" "$TARGET" \
  "$RUNNER" "$ON_CI" "$MACHINE" "$MAX_TOLERANCE" "$MIN_COLD_ITERATIONS" \
  "$MIN_WARM_ITERATIONS" "$MEASUREMENT_OUT" <<'PY'
import json, os, pathlib, sys

measured = json.loads(sys.argv[1])
baseline_path = sys.argv[2]
cold_gate, warm_gate, tolerance, target = (float(sys.argv[i]) for i in (3, 4, 5, 6))
runner = sys.argv[7]
on_ci = sys.argv[8] == "true"
machine = sys.argv[9]
max_tolerance = float(sys.argv[10])
min_cold, min_warm = int(sys.argv[11]), int(sys.argv[12])
measurement_out = sys.argv[13]

failures = []

# THE TOLERANCE'S OWN BOUND. `allowed = before * (1 + tolerance/100)` with a large enough
# tolerance admits any measurement, so one config line retires the regression arm while the run
# still prints "clean". This is the same shape as `invariant-lints.sh`'s exemption ceiling, and
# the same rule applies: raise the maximum in the change that needs it, where a reviewer sees it.
if not 0 < tolerance <= max_tolerance:
    failures.append(
        f"regression.tolerance_percent is {tolerance:g}, outside (0, {max_tolerance:g}]. "
        "A tolerance large enough to admit any measurement is a regression check that "
        "cannot fail."
    )

# THE SAMPLE COUNTS. The benchmark reports them and nothing read them, so `COLD_ITERATIONS`
# could fall to 1 -- making the "p95" a single sample -- with the gate none the wiser and the
# baseline recording a number that means something different from the one it is compared to.
for name, floor in (("cold_iterations", min_cold), ("warm_iterations", min_warm)):
    taken = measured.get(name)
    if taken is None or taken < floor:
        failures.append(f"{name} is {taken}, under the {floor} the config requires")

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
            "machine": machine,
            "cold_p95_micros": round(measured["cold_p95_micros"], 3),
            "warm_p95_micros": round(measured["warm_p95_micros"], 3),
            "cold_iterations": measured["cold_iterations"],
            "warm_iterations": measured["warm_iterations"],
        },
        indent=2,
    )


if on_ci:
    published = pathlib.Path(measurement_out)
    published.parent.mkdir(parents=True, exist_ok=True)
    published.write_text(to_commit() + "\n", encoding="utf-8")
    print(f"hook-bench-gate: measurement written to {measurement_out}")

    if os.path.exists(baseline_path):
        with open(baseline_path, encoding="utf-8") as fh:
            baseline = json.load(fh)
        # The MEASURED identity, not the declared label. GitHub rotates what `ubuntu-latest`
        # points at; the label does not change when it does, and that rotation is exactly the
        # event "a p95 is a property of the machine" is about.
        recorded_on = baseline.get("machine")
        if recorded_on != machine:
            failures.append(
                f"the baseline was recorded on {recorded_on!r}, this run is on {machine!r}. "
                "Numbers from two machines are not comparable; re-record on this one."
            )
        elif baseline.get("runner_class") != runner:
            failures.append(
                f"the baseline names runner class {baseline.get('runner_class')!r}, the "
                f"config names {runner!r}."
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
            f"no baseline at {baseline_path}. A regression check with nothing to compare "
            "against cannot fail, so a missing baseline is a failure rather than a skip."
        )
    if failures:
        print("hook-bench-gate: commit this as " + baseline_path + " to record this run:")
        print(to_commit())
else:
    print("hook-bench-gate: NOT on the pinned runner class, so the baseline arm did not run.")
    print("            These numbers are a local signal against the absolute gates and nothing")
    print("            more: they cannot be committed as a baseline and are not compared to one.")

if failures:
    print("hook-bench-gate: FAILED")
    for failure in failures:
        print(f"  {failure}")
    sys.exit(1)
print("hook-bench-gate: clean")
PY
