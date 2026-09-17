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
# FOUR STATEMENTS against a cluster on this same machine over loopback TCP: a bare `SELECT 1`,
# one autocommit indexed lookup, one SCOPED read shaped as `begin_scoped` plus a join issues it,
# and one scoped read shaped as `HotStateRepo::get` issues it. The first three are each a strict
# superset of the one before, which is what lets a reader see where the cost sits instead of
# taking a ratio on trust; the fourth is what a hit against the Postgres tier costs.
#
# MEASURED AS A NON-SUPERUSER, because connecting as one bypasses row-level security outright and
# the policies would cost nothing. The script asserts the policies bite before measuring.
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
# NOR IS IT "the most favourable topology there is", which this header used to claim. A unix
# socket is cheaper than loopback TCP, and the hot-state seam admits an in-process tier that
# costs no socket at all. Loopback TCP is the topology an accelerator in a separate process on
# the same host has, which is the one worth pricing, not a lower bound over all of them.
#
# What these ARE good for is the comparison in docs/UNIT-COSTS.md: what a cache hit can save is
# whatever an operation costs ABOVE one round trip, and these price that for the two shapes of
# read this codebase actually performs.
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
        output="$(PGPASSWORD=probe "${PG_BIN}/pgbench" -h 127.0.0.1 -p "$PORT" -U probe_app \
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
    PGPASSWORD=probe "${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U probe_app -q -t -A \
        -v ON_ERROR_STOP=1 -f "$WORK/warm.sql" postgres >/dev/null 2>&1 || {
        echo "::error::socket-rtt-bench: psql failed during warm-up" >&2
        return 1
    }
    started="$(python3 -c 'import time;print(time.monotonic())')"
    # ON_ERROR_STOP=1, because psql exits 0 after a failed statement without it. A typo in the
    # SQL, or a table the seed did not create, would otherwise have every iteration error out
    # fast and the timing published as a plausible-looking low number. A benchmark that cannot
    # tell "ran quickly" from "failed quickly" reports the failure as a good result.
    PGPASSWORD=probe "${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U probe_app -q -t -A \
        -v ON_ERROR_STOP=1 -f "$WORK/stmt.sql" postgres >/dev/null 2>&1 || {
        echo "::error::socket-rtt-bench: psql failed while measuring" >&2
        return 1
    }
    ended="$(python3 -c 'import time;print(time.monotonic())')"
    # ARGV, for the reason `to_micros` gives below.
    python3 -c \
        'import sys;print(f"{(float(sys.argv[2])-float(sys.argv[1]))*1000/int(sys.argv[3]):.3f}")' \
        "$started" "$ended" "$statements"
}

# WHAT AN ACCELERATOR WOULD ACTUALLY REPLACE, which is not one statement.
#
# The first version of this script measured `SELECT 1` against one autocommit indexed lookup and
# concluded a cache could save only the difference. A review measured the real thing and the
# conclusion inverted. NO READ IN THIS CODEBASE IS AN AUTOCOMMIT STATEMENT: every scoped read
# goes through `begin_scoped`, which issues BEGIN, `SET TRANSACTION ISOLATION LEVEL READ
# COMMITTED`, and two `SELECT set_config(...)` calls to bind the row-level-security scope, then
# the query, then COMMIT. Six sequential round trips, and the query itself is a join against
# tables under FORCE ROW LEVEL SECURITY whose policies re-read those settings.
#
# It is 550 call sites against 16 direct-pool reads, so this is the shape of essentially every
# read the accelerator question is about, and the autocommit figure describes none of them.
#
# So three statements are measured, each a strict superset of the one before, and publishing all
# three is what lets a reader see where the cost actually sits rather than taking a ratio on
# trust.
"${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U ironauth_super -q -v ON_ERROR_STOP=1 \
    -f - postgres 2>&1 <<'SEED' | tee "$WORK/seed.log" >/dev/null || {
CREATE TABLE probe_grants (
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    grant_id text PRIMARY KEY,
    subject text NOT NULL
);
CREATE TABLE probe_tokens (
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    token_hash text PRIMARY KEY,
    grant_id text NOT NULL,
    expires_at timestamptz NOT NULL,
    scope text NOT NULL
);
INSERT INTO probe_grants
SELECT 't1', 'e1', 'g' || g, 's' || g FROM generate_series(1, 10000) AS g;
INSERT INTO probe_tokens
SELECT 't1', 'e1', encode(sha256(('t' || g)::bytea), 'hex'), 'g' || g,
       now() + interval '1 hour', 'openid profile'
FROM generate_series(1, 10000) AS g;
-- FORCE, and as a non-owner role, because a policy the connecting role bypasses costs nothing
-- and would measure a read this codebase does not perform.
ALTER TABLE probe_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE probe_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY probe_tokens_scope ON probe_tokens USING (
    tenant_id = current_setting('ironauth.tenant_id', true)
    AND environment_id = current_setting('ironauth.environment_id', true)
);
CREATE POLICY probe_grants_scope ON probe_grants USING (
    tenant_id = current_setting('ironauth.tenant_id', true)
    AND environment_id = current_setting('ironauth.environment_id', true)
);
-- SHAPED AS `hot_state` IS, so the fourth row measures the statement `HotStateRepo::get`
-- actually issues: four equality predicates plus the expiry comparison against an epoch offset,
-- not a single-key lookup on a different table.
CREATE TABLE hot_state_probe (
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    use_name text NOT NULL,
    key text NOT NULL,
    value bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, environment_id, use_name, key)
);
INSERT INTO hot_state_probe
SELECT 't1', 'e1', 'introspection', 'k' || g, repeat('v', 512)::bytea,
       now() + interval '1 hour'
FROM generate_series(1, 10000) AS g;
ALTER TABLE hot_state_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE hot_state_probe FORCE ROW LEVEL SECURITY;
CREATE POLICY hot_state_probe_scope ON hot_state_probe USING (
    tenant_id = current_setting('ironauth.tenant_id', true)
    AND environment_id = current_setting('ironauth.environment_id', true)
);
-- A LOGIN ROLE THAT IS NEITHER SUPERUSER NOR OWNER, because the measurements below connect as
-- it. Connecting as the superuser BYPASSES row-level security entirely, so the policies above
-- would cost nothing and "under RLS" would be a label on a read that never evaluated one. A
-- review caught exactly that.
--
-- GRANTED LAST, after every table exists: naming a table before its CREATE is an error the seed
-- guard now surfaces rather than swallows.
CREATE ROLE probe_app LOGIN PASSWORD 'probe';
GRANT SELECT ON probe_tokens, probe_grants, hot_state_probe TO probe_app;
ANALYZE probe_tokens;
ANALYZE probe_grants;
ANALYZE hot_state_probe;
SEED
    echo "::error::socket-rtt-bench: could not seed the lookup tables" >&2
    cat "$WORK/seed.log" >&2 || true
    exit 1
}

# ON_ERROR_STOP=1 ABOVE IS LOAD-BEARING. Without it psql exits 0 after a failed statement, so
# the guard could not fire and the script would go on to measure against tables that do not
# exist, publishing whatever the error path happened to produce.
PROBE_KEY="$("${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U ironauth_super -q -t -A \
    -c "SELECT encode(sha256('t5000'::bytea), 'hex')" postgres 2>/dev/null)"
if [ -z "$PROBE_KEY" ]; then
    echo "::error::socket-rtt-bench: could not compute the probe key" >&2
    exit 1
fi

# PROVE THE POLICIES ACTUALLY BITE, because "under RLS" was a label on a read that never
# evaluated one: the first version measured as the superuser, which bypasses row-level security
# outright. A policy that costs nothing would make the scoped figures too cheap and the whole
# comparison too flattering to the cache.
#
# The check is a contrast, not a presence test: the SAME query must return zero rows with the
# scope settings unset and one row with them set. Asserting only the second would pass against a
# policy that admits everything.
rls_rows() {
    PGPASSWORD=probe "${PG_BIN}/psql" -h 127.0.0.1 -p "$PORT" -U probe_app -q -t -A \
        -c "$1" postgres 2>/dev/null | tr -d ' '
}
UNSCOPED="$(rls_rows "SELECT count(*) FROM probe_tokens WHERE token_hash = '$PROBE_KEY'")"
SCOPED_ROWS="$(rls_rows "BEGIN; SELECT set_config('ironauth.tenant_id','t1',true); \
    SELECT set_config('ironauth.environment_id','e1',true); \
    SELECT count(*) FROM probe_tokens WHERE token_hash = '$PROBE_KEY'; COMMIT;" | tail -1)"
if [ "$UNSCOPED" != "0" ] || [ "$SCOPED_ROWS" != "1" ]; then
    echo "::error::socket-rtt-bench: row-level security is not being enforced on the probe" >&2
    echo "  unscoped rows: '${UNSCOPED}' (expected 0), scoped rows: '${SCOPED_ROWS}' (expected 1)" >&2
    echo "  Without this the scoped figures below measure a read with no policy to evaluate." >&2
    exit 1
fi

LATENCY="$(measure_latency "SELECT 1;")" || exit 1
LOOKUP="$(measure_latency "SELECT scope FROM probe_tokens WHERE token_hash = '$PROBE_KEY';")" || exit 1
# THE SCOPED READ, statement for statement as `begin_scoped` plus one join issues it. pgbench
# sends each line separately and reports per-ITERATION latency, so this is the full sequence.
SCOPED="$(measure_latency "BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SELECT set_config('ironauth.tenant_id', 't1', true);
SELECT set_config('ironauth.environment_id', 'e1', true);
SELECT t.scope, t.grant_id, g.subject, EXTRACT(EPOCH FROM t.expires_at)::bigint
  FROM probe_tokens t LEFT JOIN probe_grants g ON g.grant_id = t.grant_id
 WHERE t.token_hash = '$PROBE_KEY';
COMMIT;")" || exit 1
# WHAT THE POSTGRES-BACKED HOT STATE COSTS TO READ, which is the row that decides whether the
# accelerator seam can do anything at all in the default configuration.
#
# `HotStateRepo::get` goes through `begin_scoped` like every other scoped read, so a cache hit
# against the Postgres tier pays the same BEGIN, isolation level, two set_config calls and
# COMMIT as the read it is standing in front of. Only the query inside differs: a single-table
# lookup by key instead of a join. This measures that shape.
HOTGET="$(measure_latency "BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SELECT set_config('ironauth.tenant_id', 't1', true);
SELECT set_config('ironauth.environment_id', 'e1', true);
SELECT value FROM hot_state_probe
 WHERE tenant_id = 't1' AND environment_id = 'e1' AND use_name = 'introspection'
   AND key = 'k5000'
   AND expires_at > TIMESTAMPTZ 'epoch' + (1758000000000000::text || ' microseconds')::interval;
COMMIT;")" || exit 1

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
SCOPED_US="$(to_micros "$SCOPED")"
HOTGET_US="$(to_micros "$HOTGET")"
if [ -z "$RTT_US" ] || [ -z "$LOOKUP_US" ] || [ -z "$SCOPED_US" ] || [ -z "$HOTGET_US" ]; then
    echo "::error::socket-rtt-bench: could not convert a latency to microseconds" >&2
    exit 1
fi

# THE HOST IS NAMED, because an archived latency that cannot be attributed to a machine is a
# number nobody can compare anything against. (This block was lost in a rewrite of the section
# below and is restored here.)
echo "socket-rtt-bench: host"
echo "  cpu       $(sysctl -n machdep.cpu.brand_string 2>/dev/null \
    || sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1 \
    || echo unknown)"
echo "  kernel    $(uname -smr 2>/dev/null || echo unknown)"
echo "  postgres  $("${PG_BIN}/postgres" --version 2>/dev/null || echo unknown)"
echo "  path      loopback TCP to 127.0.0.1"
echo "  method    $METHOD"
if [ -x "${PG_BIN}/pgbench" ]; then
    echo "  duration  ${SECONDS_TO_RUN}s per statement"
else
    # NOT "seconds", which the header printed on both paths while psql times a fixed COUNT and
    # never reads SECONDS_TO_RUN. A run parameter that does not apply is worse than none.
    echo "  duration  ${RTT_STATEMENTS:-20000} iterations per statement"
fi
echo
echo "socket-rtt-bench: what asking the database costs, on this machine"
printf '  %-52s %8s us\n' "bare round trip (SELECT 1)" "$RTT_US"
printf '  %-52s %8s us\n' "one autocommit indexed lookup" "$LOOKUP_US"
printf '  %-52s %8s us\n' "one SCOPED read (begin_scoped + a join, under RLS)" "$SCOPED_US"
printf '  %-52s %8s us\n' "a SCOPED single-key read (what PgHotState::get costs)" "$HOTGET_US"
echo
echo "socket-rtt-bench: all four are MEANS over the run, not floors, taken by one client with"
echo "socket-rtt-bench: no other load. A contended database is slower and the gaps widen."
echo "socket-rtt-bench: THE THIRD ROW IS THE ONE TO SIZE AN ACCELERATOR AGAINST. No read in"
echo "socket-rtt-bench: IronAuth is an autocommit statement: every scoped read pays BEGIN, an"
echo "socket-rtt-bench: isolation level, two set_config calls and a COMMIT around its query."
echo "socket-rtt-bench: A cache hit replaces that whole sequence with one round trip of its own,"
echo "socket-rtt-bench: so what it saves is the third row minus a hop, not the second minus the"
echo "socket-rtt-bench: first."
echo
echo "socket-rtt-bench: THE FOURTH ROW IS WHAT A HIT AGAINST THE POSTGRES TIER COSTS."
echo "socket-rtt-bench: HotStateRepo::get goes through begin_scoped too, so a hit pays the same"
echo "socket-rtt-bench: six round trips as a scoped read. Fronting ONE scoped read it therefore"
echo "socket-rtt-bench: saves almost nothing; the saving scales with how many scoped"
echo "socket-rtt-bench: transactions the cached answer stands in front of, which is a wiring"
echo "socket-rtt-bench: choice and not a property of the tier."
