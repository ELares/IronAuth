#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The hook latency gate (issue #114, criterion 4).
#
# THE RULE THIS FILE IS ORGANIZED AROUND: config may make a bound STRICTER, never looser.
#
# Two rounds of review found the same defect four times, each time one level further out. A
# check was disarmed by a config value; the config value was bounded by another config value in
# the same file; the sample floors that guarded the measurement were themselves unbounded; and
# the criterion's own absolute gates -- the 1 ms and 100 us the issue names -- were plain
# unbounded numbers a single edit could raise to a second. Every one printed "clean".
#
# The mistake was structural, not four separate oversights: the bounds lived in a data file the
# gate merely read, so "the check" and "what the check permits" were the same editable thing.
#
# So the criterion's numbers are CONSTANTS HERE, in the enforcement code. `bench-config.toml`
# can still set every one of them, and a stricter value is honoured -- an operator tightening
# the gate as the runtime improves is the point of having the file. A LOOSER one is refused,
# named, and the run fails. Raising what this gate permits is then an edit to this script, in a
# diff a reviewer reads, which is the property the config file could never have.
set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG="crates/ironauth-hooks/bench-config.toml"
BASELINE="crates/ironauth-hooks/bench-baseline.json"
WORKFLOW=".github/workflows/ci.yml"
# The job this gate belongs to. Named here as well as in the workflow so a second job cannot
# quietly run this script and be measured against the first job's machine.
JOB="hook-bench"

# THE CRITERION, verbatim:
#
#   "AOT cold start p95 is below 1 ms and warm invocation p95 below 100 microseconds... the job
#    fails on regression beyond the configured threshold."
#
# These are the loosest values this gate will ever enforce. A config that asks for more is not
# configuration, it is a repeal.
CRITERION_COLD_GATE_MICROS=1000
CRITERION_WARM_GATE_MICROS=100
# A tolerance past a doubling is not variance on any runner, and a regression check that admits
# a doubling admits nearly everything a real regression looks like.
MAX_TOLERANCE_PERCENT=100
# A p95 over a handful of samples is not a p95. These are the counts the benchmark was written
# with; a config may ask for more.
MIN_COLD_ITERATIONS=200
MIN_WARM_ITERATIONS=5000

# THE CONFIG, read in a way that cannot fail silently.
#
# A `python3 - <<PY` inside `$(...)` that exits non-zero leaves the shell continuing with EMPTY
# variables: `set -e` does not see the failure, and every later comparison then fails for a
# reason that has nothing to do with the real fault. Measured on an earlier version -- a missing
# `[regression]` section reported "the job runs on 'ubuntu-latest', the config names ''".
#
# Every numeric value is parsed and range-checked HERE, before the benchmark runs, so a
# malformed one costs a second rather than an hour.
if ! CONFIG_VALUES="$(python3 - "$CONFIG" "$CRITERION_COLD_GATE_MICROS" \
  "$CRITERION_WARM_GATE_MICROS" "$MAX_TOLERANCE_PERCENT" "$MIN_COLD_ITERATIONS" \
  "$MIN_WARM_ITERATIONS" <<'PY'
import sys, tomllib

path = sys.argv[1]
cold_ceiling, warm_ceiling, tolerance_ceiling, cold_floor, warm_floor = (
    float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
)

with open(path, "rb") as fh:
    cfg = tomllib.load(fh)

# Every value is REQUIRED. `.get(...)` with a default would invent a bound nobody wrote, and a
# missing section would then read as a configured one.
runner = cfg["runner"]["class"]
cold_gate = float(cfg["gates"]["cold_p95_micros"])
warm_gate = float(cfg["gates"]["warm_p95_micros"])
tolerance = float(cfg["regression"]["tolerance_percent"])
target = float(cfg["target"]["cold_p95_micros"])
min_cold = int(cfg["samples"]["min_cold_iterations"])
min_warm = int(cfg["samples"]["min_warm_iterations"])

# CONFIG MAY TIGHTEN, NEVER LOOSEN. Each comparison names the constant it is measured against,
# because "the config is wrong" is not actionable and "the config asks for 1e9, this gate
# enforces at most 100" is.
looser = []
if not 0 < cold_gate <= cold_ceiling:
    looser.append(f"gates.cold_p95_micros is {cold_gate:g}, outside (0, {cold_ceiling:g}]")
if not 0 < warm_gate <= warm_ceiling:
    looser.append(f"gates.warm_p95_micros is {warm_gate:g}, outside (0, {warm_ceiling:g}]")
if not 0 < tolerance <= tolerance_ceiling:
    looser.append(
        f"regression.tolerance_percent is {tolerance:g}, outside (0, {tolerance_ceiling:g}]"
    )
if min_cold < cold_floor:
    looser.append(f"samples.min_cold_iterations is {min_cold}, under {cold_floor}")
if min_warm < warm_floor:
    looser.append(f"samples.min_warm_iterations is {min_warm}, under {warm_floor}")
if looser:
    print(f"hook-bench-gate: {path} asks this gate to enforce LESS than it may:", file=sys.stderr)
    for line in looser:
        print(f"  {line}", file=sys.stderr)
    print(
        "            This file may only tighten a bound. Loosening one is an edit to\n"
        "            scripts/hook-bench-gate.sh, where a reviewer sees it.",
        file=sys.stderr,
    )
    sys.exit(1)

# A value containing a newline would shift every field after it, so refuse rather than emit it.
if "\n" in runner or not runner.strip():
    print(f"hook-bench-gate: runner.class {runner!r} is empty or spans lines", file=sys.stderr)
    sys.exit(1)

for value in (runner, cold_gate, warm_gate, tolerance, target, min_cold, min_warm):
    print(value)
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
  IFS= read -r TARGET
  IFS= read -r MIN_COLD
  IFS= read -r MIN_WARM
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
# Any OTHER value is a FAILURE rather than a fall-through to the local path. An earlier version
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

if [ "$ON_CI" = true ]; then
  # NOT `${GITHUB_JOB:-$JOB}`. That default supplied the expected value whenever the fact was
  # absent, so the check passed in exactly the case where there was no job identity to check --
  # the disarmed-state-is-green defect again, two lines below its own fix.
  if [ "${GITHUB_JOB:-}" != "$JOB" ]; then
    echo "hook-bench-gate: running as job '${GITHUB_JOB:-<unset>}', not '${JOB}'." >&2
    echo "            The runner-class check above validates ${JOB}'s \`runs-on\`, so another" >&2
    echo "            job running this script would be measured against a machine it is not" >&2
    echo "            on, and an unset GITHUB_JOB means there is nothing to check at all." >&2
    exit 1
  fi

  # THE MEASURED MACHINE, and every component required.
  #
  # An earlier version built this from three `${VAR:-}` defaults with nothing asserting the
  # result was non-degenerate, so on a laptop with only GITHUB_ACTIONS=true it produced "//" --
  # which then compared equal to a committed "//" and printed clean. Both sides of the check
  # came from nothing, which is the same shape as the config-compared-to-itself defect it
  # replaced.
  #
  # `ImageVersion` and not only `ImageOS`: `ImageOS` is the OS major (`ubuntu24`) and does not
  # change when GitHub rotates the image, which is precisely the event this is here to catch.
  for required in RUNNER_OS RUNNER_ARCH ImageOS ImageVersion; do
    if [ -z "${!required:-}" ]; then
      echo "hook-bench-gate: ${required} is not set, so the machine cannot be identified." >&2
      echo "            A baseline records the machine it was measured on. An unidentified" >&2
      echo "            one compares equal to every other unidentified one, which is a" >&2
      echo "            comparison that cannot fail." >&2
      exit 1
    fi
  done
  MACHINE="${RUNNER_OS}/${RUNNER_ARCH}/${ImageOS}/${ImageVersion}"
else
  MACHINE=""
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

# The measurement, published for the release to pick up (criterion 4: "numbers are published per
# release"). Written unconditionally on CI, so a run that PASSES publishes its numbers too -- the
# baseline file only changes when somebody commits one, which is not often enough to be what a
# release reads.
MEASUREMENT_OUT="${HOOK_BENCH_MEASUREMENT_PATH:-target/hook-bench-measurement.json}"

python3 - "$MEASURED" "$BASELINE" "$COLD_GATE" "$WARM_GATE" "$TOLERANCE" "$TARGET" \
  "$RUNNER" "$ON_CI" "$MACHINE" "$MIN_COLD" "$MIN_WARM" "$MEASUREMENT_OUT" <<'PY'
import json, os, pathlib, sys

measured = json.loads(sys.argv[1])
baseline_path = sys.argv[2]
cold_gate, warm_gate, tolerance, target = (float(sys.argv[i]) for i in (3, 4, 5, 6))
runner = sys.argv[7]
on_ci = sys.argv[8] == "true"
machine = sys.argv[9]
min_cold, min_warm = int(sys.argv[10]), int(sys.argv[11])
measurement_out = sys.argv[12]

failures = []

# THE SAMPLE COUNTS. The benchmark reports them and nothing read them, so `COLD_ITERATIONS`
# could fall from 200 to 1 -- making the "p95" a single sample -- with the gate none the wiser
# and the baseline recording a number that means something different from the one it is
# compared to. The floors themselves are bounded in the shell above.
for name, floor in (("cold_iterations", min_cold), ("warm_iterations", min_warm)):
    taken = measured.get(name)
    if taken is None or taken < floor:
        failures.append(f"{name} is {taken}, under the {floor} required")

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
        # event "a p95 is a property of the machine" is about. The shell above has already
        # refused an unidentifiable machine, so an empty value cannot reach here -- but a
        # BASELINE carrying one can, and it must not be treated as a match.
        recorded_on = baseline.get("machine")
        if not recorded_on or not isinstance(recorded_on, str):
            failures.append(
                f"the baseline records no machine ({recorded_on!r}), so there is nothing to "
                "compare against. Re-record it."
            )
        elif recorded_on != machine:
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
                if not isinstance(before, (int, float)) or before <= 0:
                    failures.append(
                        f"the baseline's {name} is {before!r}; a non-positive or missing "
                        "baseline bounds nothing"
                    )
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
