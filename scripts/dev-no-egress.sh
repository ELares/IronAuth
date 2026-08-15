#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Assert `ironauth dev` reaches NOTHING off this machine (issue #121, criterion 2:
# "fully offline ... verified by a no-egress test harness").
#
# What this checks, precisely: while the emulator is up and serving, the process holds no
# TCP connection whose peer is outside the loopback range. It is inspection, not enforcement:
# a sandbox that severed the network would be stronger, but it would also prove only that the
# emulator SURVIVES having no network, not that it never tries to use one. A process that
# quietly phoned a telemetry endpoint and ignored the failure would pass a severed-network
# test and fail this one, and that is the failure worth catching.
#
# What it deliberately does NOT claim: that no egress can EVER happen. It observes a live
# process over a window in which it boots, serves discovery, and serves JWKS. A call made
# only on some later path is out of its reach, and pretending otherwise would be the kind of
# guarantee-by-assertion this project keeps finding and removing.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

PORT="${PORT:-18097}"
BIN="${BIN:-./target/debug/ironauth}"
LOG="$(mktemp -t ironauth-egress-XXXXXX)"

if [ ! -x "$BIN" ]; then
  echo "dev-no-egress: $BIN is not built. Run: cargo build -p ironauth --bin ironauth" >&2
  exit 1
fi
if ! command -v lsof >/dev/null 2>&1; then
  echo "dev-no-egress: needs lsof to inspect the process's connections." >&2
  exit 1
fi

cleanup() {
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  sleep 2
  rm -f "$LOG"
}
trap cleanup EXIT INT TERM

env -u DATABASE_URL "$BIN" dev --bind "127.0.0.1:${PORT}" > "$LOG" 2>&1 &
DEV_PID=$!

issuer=""
for _ in $(seq 1 200); do
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "dev-no-egress: the emulator exited before serving. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  if [ -z "$issuer" ]; then
    issuer=$(grep -o 'issuer http://[^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/issuer //')
  fi
  if [ -n "$issuer" ] && curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"; then
    break
  fi
  sleep 0.1
done

if [ -z "$issuer" ]; then
  echo "dev-no-egress: never served discovery. Log:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# Exercise the surfaces before looking: a check run against an idle process would pass
# without the emulator having done anything.
curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"
curl -sf -o /dev/null "${issuer}/jwks.json"

# Every TCP peer this process (and its children, notably the Postgres it started) holds.
# `-n` keeps names out of it, which also means this inspection performs no DNS lookup of
# its own and cannot manufacture the egress it is looking for.
peers=$(lsof -nP -p "$DEV_PID" -a -i TCP 2>/dev/null | awk 'NR>1 {print $NF, $9}')

# Anything whose remote side is not loopback. A listener has no peer and is skipped; only
# the "local->remote" form carries one.
foreign=$(printf '%s\n' "$peers" \
  | grep -oE '\->[0-9a-fA-F:.\[\]]+:[0-9]+' \
  | sed 's/^->//' \
  | grep -vE '^(127\.|\[?::1\]?:|localhost)' \
  || true)

if [ -n "$foreign" ]; then
  echo "dev-no-egress: the emulator holds connections off this machine:" >&2
  printf '%s\n' "$foreign" >&2
  exit 1
fi

echo "dev-no-egress: no off-machine connections while serving discovery and JWKS"
