#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# THE COST OF ONE HOP (issue #152, and the measurement issue #146 turns on).
#
#     PG_BIN=<postgresql bin dir> scripts/socket-rtt-bench.sh
#
# A sizing guide needs the cost of the operations a request performs. It also needs the cost of
# ASKING SOMETHING ELSE, because that is what decides whether a cache in front of an operation
# pays for itself. A hop that costs more than the work it saves is a pessimization however fast
# the thing at the other end answers.
#
# `docs/UNIT-COSTS.md` records the case that made this worth measuring: rendering the published
# JWKS document costs about a microsecond, and `IssuerRegistry` consults its optional hot state
# only AFTER the entry is already resolved, so a hit saves that render and nothing else. The
# question "is the accelerator worth it here" is then entirely a question of what a hop costs.
#
# # What this measures, and why it is a FLOOR rather than an estimate
#
# One `SELECT 1` over loopback TCP to a Postgres on this same machine, through pgbench, with no
# disk in the path and nothing to plan. A real accelerator read does more than this: a real
# query against a real table, or a Redis round trip across an actual network. So the number
# below is the cheapest a socket round trip can be on this hardware, and every real hop is
# slower. A floor is the right shape for this argument: if the saving does not beat the floor,
# it cannot beat the real thing.
#
# It is NOT a measurement of Postgres, of IronCache, or of any accelerator's throughput, and it
# should not be quoted as one.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)" || {
    echo "::error::socket-rtt-bench: not inside a git repository" >&2
    exit 1
}
cd "$ROOT" || exit 1

if [ -z "${PG_BIN:-}" ] || [ ! -x "${PG_BIN}/pgbench" ]; then
    echo "socket-rtt-bench: set PG_BIN to a postgresql bin directory containing pgbench" >&2
    exit 1
fi

SECONDS_TO_RUN="${RTT_SECONDS:-5}"
PORT="${RTT_PORT:-55997}"
WORK="$(mktemp -d)"
cleanup() {
    "${PG_BIN}/pg_ctl" -D "$WORK/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

"${PG_BIN}/initdb" -D "$WORK/data" -U ironauth_super --auth=trust >/dev/null 2>&1 || {
    echo "::error::socket-rtt-bench: initdb failed" >&2
    exit 1
}
# LOOPBACK TCP, NOT THE UNIX SOCKET, and that is the point rather than an oversight. An
# accelerator is reached over a socket; measuring the unix-domain path would flatter the hop by
# removing the protocol stack a real one pays for.
"${PG_BIN}/pg_ctl" -D "$WORK/data" \
    -o "-p $PORT -k $WORK -c listen_addresses=127.0.0.1" \
    -l "$WORK/pg.log" -w start >/dev/null 2>&1 || {
    echo "::error::socket-rtt-bench: could not start the throwaway cluster" >&2
    cat "$WORK/pg.log" >&2 || true
    exit 1
}

echo "SELECT 1;" > "$WORK/rtt.sql"
OUTPUT="$("${PG_BIN}/pgbench" -h 127.0.0.1 -p "$PORT" -U ironauth_super \
    -n -c 1 -T "$SECONDS_TO_RUN" -f "$WORK/rtt.sql" postgres 2>&1)" || {
    echo "::error::socket-rtt-bench: pgbench failed" >&2
    echo "$OUTPUT" >&2
    exit 1
}

LATENCY="$(printf '%s\n' "$OUTPUT" | sed -n 's/^latency average = \(.*\) ms$/\1/p')"
if [ -z "$LATENCY" ]; then
    echo "::error::socket-rtt-bench: pgbench printed no latency average" >&2
    echo "$OUTPUT" >&2
    exit 1
fi

echo "socket-rtt-bench: host"
echo "  postgres  $("${PG_BIN}/postgres" --version 2>/dev/null || echo unknown)"
echo "  seconds   $SECONDS_TO_RUN"
echo "  path      loopback TCP to 127.0.0.1, one client, SELECT 1"
echo
echo "socket-rtt-bench: one socket round trip costs ${LATENCY} ms"
# MICROSECONDS TOO, because the figure this is compared against (a JWKS render) is quoted in
# microseconds, and a reader should not have to convert one of the two sides by hand.
printf 'socket-rtt-bench: that is %.1f us, the FLOOR for any accelerator hop on this machine\n' \
    "$(printf '%s * 1000\n' "$LATENCY" | bc -l)"
