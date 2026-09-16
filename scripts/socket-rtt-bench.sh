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
    METHOD="pgbench, one client"
else
    # STATEMENTS IN ONE SESSION, so the connection handshake is paid once and the figure is a
    # round trip rather than a connect. This reads HIGHER than pgbench on the same machine
    # because psql parses and formats each result, so it is an UPPER bound.
    METHOD="psql, one session (pgbench absent; includes client per-statement overhead)"
fi

# Measure one statement's mean latency in milliseconds, printed to stdout.
#
# ONE FUNCTION FOR BOTH INSTRUMENTS AND BOTH STATEMENTS, so the two figures this script reports
# are produced the same way and can be subtracted from each other. Two copies of this logic
# would be two chances for the comparison to measure different things.
measure_latency() {
    statement="$1"
    if [ -x "${PG_BIN}/pgbench" ]; then
        printf '%s\n' "$statement" > "$WORK/stmt.sql"
        output="$("${PG_BIN}/pgbench" -h 127.0.0.1 -p "$PORT" -U ironauth_super \
            -n -c 1 -T "$SECONDS_TO_RUN" -f "$WORK/stmt.sql" postgres 2>&1)" || {
            echo "::error::socket-rtt-bench: pgbench failed" >&2
            echo "$output" >&2
            return 1
        }
        latency="$(printf '%s\n' "$output" | sed -n 's/^latency average = \(.*\) ms$/\1/p')"
        if [ -z "$latency" ]; then
            echo "::error::socket-rtt-bench: pgbench printed no latency average" >&2
            echo "$output" >&2
            return 1
        fi
        printf '%s\n' "$latency"
        return 0
    fi

    statements="${RTT_STATEMENTS:-20000}"
    python3 -c "import sys;print((sys.argv[1]+'\n')*int(sys.argv[2]))" \
        "$statement" "$statements" > "$WORK/stmt.sql" || return 1
    python3 -c "import sys;print((sys.argv[1]+'\n')*500)" "$statement" > "$WORK/warm.sql" || return 1
    "${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U ironauth_super -q -t -A \
        -f "$WORK/warm.sql" postgres >/dev/null 2>&1
    started="$(python3 -c 'import time;print(time.monotonic())')"
    "${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U ironauth_super -q -t -A \
        -f "$WORK/stmt.sql" postgres >/dev/null 2>&1 || {
        echo "::error::socket-rtt-bench: psql failed" >&2
        return 1
    }
    ended="$(python3 -c 'import time;print(time.monotonic())')"
    # ARGV, for the reason `to_micros` gives below.
    python3 -c \
        'import sys;print(f"{(float(sys.argv[2])-float(sys.argv[1]))*1000/int(sys.argv[3]):.3f}")' \
        "$started" "$ended" "$statements"
}

# THE SECOND MEASUREMENT IS THE ONE THE ACCELERATOR QUESTION ACTUALLY NEEDS.
#
# `SELECT 1` prices the round trip and nothing else. What an accelerator would replace is not a
# round trip: it is a REAL single-row lookup by key, which is what a token introspection, a
# client load or a tenant config read does. If that lookup costs about what a bare round trip
# costs, then putting a cache on the same machine in front of it saves nothing, and the seam
# only pays where the accelerator is genuinely faster than the database rather than merely
# closer.
#
# A NARROW TABLE WITH A UNIQUE INDEX and a row that exists, because that is the shape of the
# reads in question and a miss would measure something else. Seeded small on purpose: this is
# the cost of the round trip plus an index descent, not a benchmark of Postgres under volume.
"${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U ironauth_super -q -f - postgres >/dev/null 2>&1 <<'SEED' || {
CREATE TABLE lookup_probe (k text PRIMARY KEY, v text NOT NULL);
INSERT INTO lookup_probe
SELECT 'k' || g, repeat('v', 64) FROM generate_series(1, 10000) AS g;
ANALYZE lookup_probe;
SEED
    echo "::error::socket-rtt-bench: could not seed the lookup table" >&2
    exit 1
}

LATENCY="$(measure_latency "SELECT 1;")" || exit 1
LOOKUP="$(measure_latency "SELECT v FROM lookup_probe WHERE k = 'k5000';")" || exit 1

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
# MICROSECONDS, because the figures these are compared against are quoted in microseconds and a
# reader should not have to convert one side by hand.
#
# PYTHON RATHER THAN `bc`, which is not installed everywhere and, being invoked in a command
# substitution feeding printf, would have printed an EMPTY figure on a machine without it
# instead of failing. A missing tool has to be an error, never a blank where a number goes.
# ARGV, NOT INTERPOLATION. The first version built the Python source by substituting the value
# into a quoted string, which does not survive the shell's quoting and produced a SyntaxError.
to_micros() {
    python3 -c 'import sys;print(f"{float(sys.argv[1])*1000:.1f}")' "$1"
}

# CHECKED AT THE CALL SITE, because `exit 1` inside a command substitution exits the SUBSHELL and
# the caller carries on. That is how the broken version above printed two empty figures and
# still reported success: the same "blank where a number goes" failure this script's own comment
# warns about, in the guard written to prevent it.
RTT_US="$(to_micros "$LATENCY")"
LOOKUP_US="$(to_micros "$LOOKUP")"
if [ -z "$RTT_US" ] || [ -z "$LOOKUP_US" ]; then
    echo "::error::socket-rtt-bench: could not convert a latency to microseconds" >&2
    exit 1
fi

echo "socket-rtt-bench: what asking the database costs, on this machine"
printf '  %-46s %8s us\n' "bare round trip (SELECT 1)" "$RTT_US"
printf '  %-46s %8s us\n' "one indexed single-row lookup by key" "$LOOKUP_US"
echo
echo "socket-rtt-bench: both are MEANS, not floors, and both include Postgres parse, plan and"
echo "socket-rtt-bench: execute. The gap between them is what an index descent and a row fetch"
echo "socket-rtt-bench: cost ON TOP of the round trip, which is the number that decides whether"
echo "socket-rtt-bench: a same-machine cache in front of such a read can save anything at all."
