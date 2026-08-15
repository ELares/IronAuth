#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Measure `ironauth dev` from launch to SERVING, and fail if it exceeds the budget
# (issue #121, criterion 1: "boots seeded and ready in under 5 seconds").
#
# The measured instant is the one that matters to a user: discovery answering 200. Not the
# process starting, not a log line, not the port opening. A server that has bound its socket
# but has no signing key answers 404, and calling that "ready" would let the emulator regress
# into exactly the state it shipped in twice during this issue: up, quiet, and useless.
#
# The whole chain is inside the measurement, because all of it happens before a user can do
# anything: locate Postgres, initdb, start the cluster, provision roles, apply the schema,
# seed the scope and client, provision the signing key, boot the server.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

BUDGET_SECS="${BUDGET_SECS:-5}"
PORT="${PORT:-18099}"
BIN="${BIN:-./target/debug/ironauth}"
LOG="$(mktemp -t ironauth-boot-XXXXXX)"

if [ ! -x "$BIN" ]; then
  echo "dev-boot-time: $BIN is not built. Run: cargo build -p ironauth --bin ironauth" >&2
  exit 1
fi

cleanup() {
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  # The emulator deletes its own cluster on drop; give it the moment to do so before the
  # script exits, so a CI run does not leave one behind on a timeout path.
  sleep 2
  rm -f "$LOG"
}
trap cleanup EXIT INT TERM

# DATABASE_URL is deliberately unset: the point is to measure the full cold path, including
# bringing a cluster up. Measuring against a database someone already started would report a
# number no user ever experiences.
start=$(python3 -c 'import time; print(time.time())')
env -u DATABASE_URL "$BIN" dev --bind "127.0.0.1:${PORT}" > "$LOG" 2>&1 &
DEV_PID=$!

issuer=""
elapsed=""
# Poll rather than sleep-then-check: a fixed sleep measures the sleep, not the boot.
for _ in $(seq 1 200); do
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "dev-boot-time: the emulator exited before serving. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  if [ -z "$issuer" ]; then
    issuer=$(grep -o 'issuer http://[^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/issuer //')
  fi
  if [ -n "$issuer" ] && curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"; then
    now=$(python3 -c 'import time; print(time.time())')
    elapsed=$(python3 -c "print(f'{${now}-${start}:.2f}')")
    break
  fi
  sleep 0.1
done

if [ -z "$elapsed" ]; then
  echo "dev-boot-time: never served discovery within the poll window. Log:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

echo "dev-boot-time: serving discovery in ${elapsed}s (budget ${BUDGET_SECS}s)"
python3 -c "
import sys
elapsed, budget = float('${elapsed}'), float('${BUDGET_SECS}')
if elapsed > budget:
    print(f'dev-boot-time: {elapsed:.2f}s exceeds the {budget}s budget', file=sys.stderr)
    sys.exit(1)
"
