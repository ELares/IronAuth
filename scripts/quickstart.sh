#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run a quickstart's DOCUMENTED COMMANDS, verbatim, and fail on drift or budget (issue #116).
#
#     scripts/quickstart.sh python
#
# > a CI job executes the quickstart's documented commands VERBATIM against a clean project and
# > completes a real login; the scripted run finishes within the 15-minute budget and FAILS ON
# > DOC DRIFT.
#
# # There is no second copy of the steps, and that IS the doc-drift check
#
# This script does not know what the quickstart does. It extracts every ```bash quickstart block
# from `docs/quickstart-<name>.md`, in order, and runs them.
#
# So a doc that drifts from what works fails here BY CONSTRUCTION rather than by comparison: the
# thing being run is the thing being published. A gate that kept its own copy of the commands
# would pass while the document rotted, which is the ordinary way quickstart guides die -- and
# comparing two copies would only prove they match each other.
#
# # The budget is a real bound, not a note
#
# Fifteen minutes, wall clock, enforced. A quickstart that takes an hour is not a quickstart, and
# the criterion says so; measuring it is the only way that stays true as the steps grow.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

NAME="${1:-}"
if [ -z "$NAME" ]; then
  echo "usage: scripts/quickstart.sh <name>    (e.g. python)" >&2
  exit 2
fi
DOC="docs/quickstart-${NAME}.md"
if [ ! -f "$DOC" ]; then
  echo "quickstart: $DOC does not exist" >&2
  exit 1
fi

BUDGET_SECONDS="${QUICKSTART_BUDGET_SECONDS:-900}"
QS_DIR="$(mktemp -d -t ironauth-quickstart-XXXXXX)"
export QS_DIR
SCRIPT="${QS_DIR}/steps.sh"

# EXTRACTED IN ORDER, and the count is reported so a document whose fences were mangled shows up
# as "ran 0 steps" rather than as a silent pass.
python3 - "$DOC" "$SCRIPT" <<'PYEXTRACT'
import pathlib, re, sys

doc = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
blocks = re.findall(r"^```bash quickstart\n(.*?)^```$", doc, re.M | re.S)
if len(blocks) < 3:
    print(f"quickstart: {sys.argv[1]} has only {len(blocks)} runnable blocks; the guide or the fence tag is wrong", file=sys.stderr)
    raise SystemExit(1)
# EACH BLOCK RUNS UNDER `set -e`, in a subshell that inherits and re-exports the environment.
#
# The first version checked only `$?` after the whole block, which reads as "did the step work"
# and is not: a block whose FIRST command fails and whose last succeeds passes. Measured -- step 3
# is `python3 ...` followed by `cat`, the python exited 1 with a connection error, `cat` printed
# an empty file, and the step was recorded as passing.
#
# A reader typing these commands would stop at the failure, so stopping at the failure is what
# "runs the documented commands" means.
out = ["# GENERATED from " + sys.argv[1] + " by scripts/quickstart.sh. Do not edit."]
for index, block in enumerate(blocks, start=1):
    out.append(f'echo "quickstart: --- step {index} ---"')
    # `set -e` inside the block, and `set +e` after, so a later block still runs if this one
    # deliberately tolerates a failure (the teardown step does).
    out.append("set -e")
    out.append(block.rstrip())
    out.append("set +e")
    out.append(f'__rc=$?; if [ "$__rc" != 0 ]; then echo "quickstart: step {index} failed (exit $__rc)" >&2; exit "$__rc"; fi')
pathlib.Path(sys.argv[2]).write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"quickstart: extracted {len(blocks)} documented steps from {sys.argv[1]}")
PYEXTRACT
extract_status=$?
if [ "$extract_status" != 0 ]; then
  rm -rf "$QS_DIR"
  exit "$extract_status"
fi

cleanup() {
  # Whatever the guide started, stop. A quickstart that leaked an emulator would leave a Postgres
  # cluster behind on every CI run.
  if [ -f "${QS_DIR}/emulator.pid" ]; then
    kill "$(cat "${QS_DIR}/emulator.pid")" 2>/dev/null || true
  fi
  rm -rf "$QS_DIR"
}
trap cleanup EXIT INT TERM

started=$SECONDS
bash "$SCRIPT"
status=$?
elapsed=$((SECONDS - started))

if [ "$status" != 0 ]; then
  echo "quickstart: ${NAME} FAILED after ${elapsed}s" >&2
  [ -f "${QS_DIR}/emulator.log" ] && tail -20 "${QS_DIR}/emulator.log" >&2
  exit "$status"
fi

if [ "$elapsed" -gt "$BUDGET_SECONDS" ]; then
  echo "quickstart: ${NAME} completed but took ${elapsed}s, over the ${BUDGET_SECONDS}s budget" >&2
  exit 1
fi

echo "quickstart: ${NAME} clean (${elapsed}s, budget ${BUDGET_SECONDS}s)"
