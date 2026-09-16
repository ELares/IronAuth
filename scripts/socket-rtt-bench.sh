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
# # What this measures, stated exactly, because the first version overclaimed it twice
#
# ONE POSTGRES ROUND TRIP running `SELECT 1` over loopback TCP to a cluster on this same
# machine. That is the whole claim.
#
# It was previously labelled "the FLOOR for any accelerator hop", which was wrong in two
# separate ways that a review caught. It is not a floor: the figure is a MEAN over the run, and
# a mean is not a lower bound on anything. And it is not a socket floor even in spirit, because
# a `SELECT 1` pays Postgres parsing, planning and execution on top of the round trip, so a bare
# socket exchange on this hardware is cheaper than what this prints.
#
# It is also NOT a figure for IronCache or any Redis-shaped accelerator. Those speak a lighter
# protocol over the same kind of socket, and nothing here measures them. A reader sizing one
# should substitute their own hop cost; this number is offered as a concrete example of what a
# hop costs, not as a bound on what every hop costs.
#
# What it IS good for is the comparison in docs/UNIT-COSTS.md: rendering the published JWKS
# document costs under a microsecond of net saving, and this shows what asking another process
# instead costs on the most favourable topology there is, one where the other process is on the
# same machine.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)" || {
    echo "::error::socket-rtt-bench: not inside a git repository" >&2
    exit 1
}
cd "$ROOT" || exit 1

# PSQL IS THE REQUIREMENT, NOT PGBENCH. pgbench ships in `postgresql-contrib` on Debian and
# Ubuntu, so a machine with a working `initdb` need not have it; psql comes with the server.
# Requiring pgbench here made the fallback below unreachable, which a test of that path found.
for tool in initdb pg_ctl psql; do
    if [ -z "${PG_BIN:-}" ] || [ ! -x "${PG_BIN}/$tool" ]; then
        echo "socket-rtt-bench: set PG_BIN to a postgresql bin directory containing $tool" >&2
        exit 1
    fi
done

SECONDS_TO_RUN="${RTT_SECONDS:-5}"
# A FREE PORT, ASKED FOR RATHER THAN ASSUMED, matching scripts/startup-rss-bench.sh. A
# hardcoded port is a wrong number waiting to happen: another cluster holding it makes this
# either fail to start or, worse, connect to a database that is not the one it created and
# publish that database's latency as ours. Two of these can also run at once, which the release
# lane does not do today and should not be made fragile against.
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')" || {
    echo "::error::socket-rtt-bench: could not find a free port" >&2
    exit 1
}
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

# PGBENCH IS NOT GUARANTEED. On Debian and Ubuntu it ships in `postgresql-contrib` rather than
# with the server or the client, so a runner that has `initdb` need not have this. It is the
# better instrument when present, because it times the round trip without a client formatting a
# result set for each one, so it is tried first and `psql` carries the measurement when it is
# absent. Which one produced the number is printed, because they do not measure quite the same
# thing and a reader comparing two runs has to be able to see that.
if [ -x "${PG_BIN}/pgbench" ]; then
    METHOD="pgbench, one client, SELECT 1"
    OUTPUT="$("${PG_BIN}/pgbench" -h 127.0.0.1 -p "$PORT" -U ironauth_super \
        -n -c 1 -T "$SECONDS_TO_RUN" -f <(echo "SELECT 1;") postgres 2>&1)" || {
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
else
    # STATEMENTS IN ONE SESSION, so the connection handshake is paid once and the figure is a
    # round trip rather than a connect. This reads HIGHER than pgbench on the same machine (24.6
    # against 20.4 us when both were run here) because psql parses and formats each result, so
    # it is an UPPER bound on the floor. The argument this number serves survives that: the
    # saving it is compared against is over an order of magnitude smaller either way.
    METHOD="psql, one session, SELECT 1 (pgbench absent; includes client per-statement overhead)"
    STATEMENTS="${RTT_STATEMENTS:-20000}"
    python3 -c "import sys;print('\n'.join(['SELECT 1;']*int(sys.argv[1])))" \
        "$STATEMENTS" > "$WORK/rtt.sql" || {
        echo "::error::socket-rtt-bench: could not build the statement file" >&2
        exit 1
    }
    python3 -c "import sys;print('\n'.join(['SELECT 1;']*500))" > "$WORK/warm.sql"
    "${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U ironauth_super -q -t -A \
        -f "$WORK/warm.sql" postgres >/dev/null 2>&1
    STARTED="$(python3 -c 'import time;print(time.monotonic())')"
    "${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U ironauth_super -q -t -A \
        -f "$WORK/rtt.sql" postgres >/dev/null 2>&1 || {
        echo "::error::socket-rtt-bench: psql failed" >&2
        exit 1
    }
    ENDED="$(python3 -c 'import time;print(time.monotonic())')"
    LATENCY="$(python3 -c "print(f'{(float('$ENDED')-float('$STARTED'))*1000/int('$STATEMENTS'):.3f}')")" || {
        echo "::error::socket-rtt-bench: could not compute the latency" >&2
        exit 1
    }
fi

# THE HOST IS NAMED, because an archived latency that cannot be attributed to a machine is a
# number nobody can compare anything against. The block used to be titled "host" and identify
# none.
echo "socket-rtt-bench: host"
echo "  cpu       $(sysctl -n machdep.cpu.brand_string 2>/dev/null \
    || sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1 \
    || echo unknown)"
echo "  kernel    $(uname -smr 2>/dev/null || echo unknown)"
echo "  postgres  $("${PG_BIN}/postgres" --version 2>/dev/null || echo unknown)"
echo "  seconds   $SECONDS_TO_RUN"
echo "  path      loopback TCP to 127.0.0.1"
echo "  method    $METHOD"
echo
echo "socket-rtt-bench: one Postgres round trip costs ${LATENCY} ms on average"
# MICROSECONDS TOO, because the figure this is compared against (a JWKS render) is quoted in
# microseconds, and a reader should not have to convert one of the two sides by hand.
#
# PYTHON RATHER THAN `bc`, which is not installed everywhere and, being invoked in a command
# substitution feeding printf, would have printed an EMPTY figure on a machine without it
# instead of failing. A missing tool has to be an error, never a blank where a number goes.
MICROS="$(python3 -c "print(f'{float('$LATENCY')*1000:.1f}')")" || {
    echo "::error::socket-rtt-bench: could not convert the latency to microseconds" >&2
    exit 1
}
echo "socket-rtt-bench: that is ${MICROS} us to ask another process on this same machine"
echo "socket-rtt-bench: a mean, not a floor, and it includes Postgres parse, plan and execute"
