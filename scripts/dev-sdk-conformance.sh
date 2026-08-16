#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run the published SDK conformance suite against the emulator (issue #122, criterion 2:
# "a third-party SDK (or a from-scratch reference client written without reading official
# SDK source) passes the published conformance suite against the emulator").
#
# Boots `ironauth dev`, discovers its MANAGEMENT listener, and runs the suite through the
# from-scratch reference client in `clients/reference`.
#
# The management port is EPHEMERAL, like every other port the emulator binds, so it is read
# out of the boot log rather than assumed. A fixed port would make two emulators, or one
# emulator beside anything else holding it, fail to bind.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

PORT="${PORT:-18130}"
SEED="${SEED:-1}"
BIN="${BIN:-./target/debug/ironauth}"
LOG="$(mktemp -t ironauth-sdk-XXXXXX)"

if [ ! -x "$BIN" ]; then
  echo "dev-sdk-conformance: $BIN is not built. Run: cargo build -p ironauth --bin ironauth" >&2
  exit 1
fi

cleanup() {
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  sleep 2
  rm -f "$LOG"
}
trap cleanup EXIT INT TERM

env -u DATABASE_URL "$BIN" dev --bind "127.0.0.1:${PORT}" --seed "$SEED" > "$LOG" 2>&1 &
DEV_PID=$!

issuer=""
management=""
for _ in $(seq 1 300); do
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "dev-sdk-conformance: the emulator exited before serving. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  [ -z "$issuer" ] && issuer=$(grep -o 'issuer http://[^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/issuer //')
  # The management listener reports itself in the structured "ironauth serving" line.
  [ -z "$management" ] && management=$(grep -o 'management.addr":"Some([^)]*' "$LOG" 2>/dev/null | head -1 | sed 's/.*Some(//')
  if [ -n "$issuer" ] && [ -n "$management" ] \
     && curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"; then
    break
  fi
  sleep 0.1
done

if [ -z "$management" ]; then
  echo "dev-sdk-conformance: the emulator never reported a management listener." >&2
  echo "  Without admin.bootstrap_operator_token the management API is NOT MOUNTED, which" >&2
  echo "  is the state the emulator shipped in before this criterion was worked." >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# The token the emulator generates its config with. Deterministic by design, which is what
# makes it nameable here at all.
TOKEN="${TOKEN:-ironauth-dev-operator-token-not-for-production}"

echo "dev-sdk-conformance: management API at http://${management}"
python3 scripts/sdk-conformance.py --management-url "http://${management}" --token "$TOKEN"
