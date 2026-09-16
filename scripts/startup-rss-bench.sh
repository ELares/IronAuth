#!/usr/bin/env bash
# Measure startup time to readiness and idle RSS (issue #152 criterion 3).
#
# ONE COMMAND, from a clean checkout:
#
#   PG_BIN=<postgres bin dir> scripts/startup-rss-bench.sh
#
# It builds the release binary, starts a throwaway Postgres, launches the server
# N times, and reports the MEDIAN time from exec to the first successful
# readiness probe, plus resident set size once idle.
#
# WHAT IT MEASURES, precisely, because each of these is a different number and
# publishing the wrong one is how a target gets met on paper:
#
#   startup  = wall time from exec() to the FIRST /readyz that answers ready.
#
#              WHAT THAT ACTUALLY PROVES, stated precisely because this comment
#              has been wrong in both directions. It first claimed readiness came
#              after "the first database round trip", which was false: the probe
#              was a bare TcpStream::connect whose own doc said "no bytes are
#              exchanged and no database protocol is spoken", and a review
#              confirmed /readyz answering `ready` against a database holding zero
#              tables, with log_statement=all recording no SQL at all.
#
#              Issue #149 made readiness run a real query on the serving pool, so
#              on a build carrying that change the first `ready` DOES follow a
#              completed round trip. Which one this harness measures depends on
#              whether the binary under test mounts a plane: with none configured
#              there is no pool to ask and the socket check still runs, and the
#              body says `ready: probe=socket-only` when it does. The figures in
#              docs/PERFORMANCE.md were taken before the change and record the
#              socket path.
#
#              So this measures process start to listener-up, with the Postgres
#              address proven TCP-reachable. That is a real and useful number,
#              and it is NOT time-to-serving-traffic. A reader sizing a rollout
#              on it should know the pool has not yet spoken a byte of protocol.
#   rss      = resident set size after readiness plus a settle period, with NO
#              traffic. Idle means idle: a number taken under load is a
#              different measurement wearing the same name.
#
# It reports the MEDIAN of N runs and also the max, over ONE population: there is
# no cold-versus-warm split, because with the binary already exec'd and the schema
# already applied there is no difference to report. A single sample on a shared
# laptop is not a measurement, and the max is printed because a target stated as
# a median hides the tail an operator actually waits for.
set -euo pipefail

cd "$(dirname "$0")/.."

RUNS="${RUNS:-5}"
SETTLE_SECS="${SETTLE_SECS:-2}"
: "${PG_BIN:?set PG_BIN to a PostgreSQL bin directory}"

echo "startup-rss-bench: building the release binary"
cargo build -q --release -p ironauth

BIN="target/release/ironauth"
[ -x "$BIN" ] || { echo "no release binary at $BIN" >&2; exit 1; }

# EXEC IT ONCE, BEFORE ANY MEASUREMENT, AND THROW THAT AWAY.
#
# The build above re-creates the binary at a NEW INODE every invocation, and macOS validates a
# binary on first exec from a given inode. That validation cost about 0.85 s and was charged
# entirely to whichever `serve` ran first, which was the sample this script labelled COLD and
# published. A review measured the mechanism directly: three consecutive no-op release builds
# produced three different inodes, and the first `ironauth --version` after each cost 0.87,
# 0.81 and 0.83 s at user 0.00 and sys 0.00 (blocked in validation, burning no CPU), while the
# very next exec cost 0.00 s. With this one line the same harness against the same database
# reported 237 ms instead of 1194 ms.
#
# So the published headline, "cold start 1191 ms, over the sub-second target", was measuring
# the operating system inspecting a file the harness had just written. `--version` opens no
# config and never touches Postgres, so it pays the validation and nothing else.
#
# It also would not have reproduced on the Linux runner criterion 2 asks CI to use, where
# there is no such validation at all, which is its own warning about publishing a number whose
# cause was never identified.
"$BIN" --version >/dev/null 2>&1 || true

# Hardware class, printed with the numbers so a result is never quoted without it.
echo "startup-rss-bench: host"
if [ "$(uname -s)" = "Darwin" ]; then
  echo "  os       $(sw_vers -productName) $(sw_vers -productVersion)"
  echo "  cpu      $(sysctl -n machdep.cpu.brand_string)"
  echo "  cores    $(sysctl -n hw.ncpu)"
  echo "  memory   $(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 )) GiB"
else
  echo "  os       $(uname -sr)"
  echo "  cpu      $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
  echo "  cores    $(nproc)"
  echo "  memory   $(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 / 1024 )) GiB"
fi
echo "  build    release"
echo "  runs     $RUNS"

exec 3>&1
run_one() {
  local config="$1" port="$2" mgmt="$3"
  local started ready_at rss pid
  "$BIN" serve --config "$config" >/dev/null 2>&1 &
  pid=$!
  started="$(python3 -c 'import time; print(time.monotonic())')"
  # Poll readiness. A ceiling so a wedged start fails loudly instead of hanging.
  local deadline
  deadline="$(python3 -c 'import time; print(time.monotonic() + 60)')"
  while :; do
    if curl -fsS "http://127.0.0.1:${mgmt}/readyz" >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "  the server exited before becoming ready" >&2
      return 1
    fi
    if python3 -c "import sys,time; sys.exit(0 if time.monotonic() > $deadline else 1)"; then
      echo "  the server never became ready within 60s" >&2
      kill "$pid" 2>/dev/null || true
      return 1
    fi
    sleep 0.02
  done
  ready_at="$(python3 -c 'import time; print(time.monotonic())')"

  sleep "$SETTLE_SECS"
  # RSS in KiB from ps, which reports it in KiB on both platforms here.
  rss="$(ps -o rss= -p "$pid" | tr -d ' ')"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  python3 -c "print(f'{($ready_at - $started)*1000:.0f} $rss')"
}

# A throwaway Postgres for the run, torn down on exit.
WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "startup-rss-bench: starting a throwaway database"
PGDATA="$WORK/pgdata"
PGPORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
"$PG_BIN/initdb" -D "$PGDATA" -U ironauth_super --auth=trust >/dev/null 2>&1
"$PG_BIN/pg_ctl" -D "$PGDATA" -o "-p $PGPORT -k $WORK -c listen_addresses=127.0.0.1" -l "$WORK/pg.log" -w start >/dev/null
stop_pg() { "$PG_BIN/pg_ctl" -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap stop_pg EXIT
"$PG_BIN/createdb" -h 127.0.0.1 -p "$PGPORT" -U ironauth_super ironauth >/dev/null

# THE THREE ROLES THE SCHEMA GRANTS TO, provisioned out of band.
#
# Migration 0001 says so explicitly: it GRANTs to `ironauth_app` and never creates it, because
# shipping a CREATE ROLE ... PASSWORD literal in a public repository would hand every reader a
# working credential for the isolation-boundary role. "If the role is absent when this runs,
# the GRANTs below fail loudly: that fail-closed behavior is intended."
#
# So a benchmark that wants a migrated database has to do what an operator does. Throwaway
# passwords on a throwaway cluster that is torn down on exit.
for role in ironauth_app ironauth_control ironauth_audit_retention; do
  "$PG_BIN/psql" -h 127.0.0.1 -p "$PGPORT" -U ironauth_super -d ironauth -v ON_ERROR_STOP=1 \
    -c "CREATE ROLE $role LOGIN PASSWORD '$role'" >/dev/null 2>&1 || true
done

DATA_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
MGMT_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
CONFIG="$WORK/ironauth.toml"
cat > "$CONFIG" <<TOML
[server]
bind = "127.0.0.1:${DATA_PORT}"
management_bind = "127.0.0.1:${MGMT_PORT}"
public_url = "http://127.0.0.1:${DATA_PORT}"
[database]
url = "postgres://ironauth_super@127.0.0.1:${PGPORT}/ironauth"
master_key = { env = "IRONAUTH_MASTER_KEY" }
[admin]
control_database_url = "postgres://ironauth_super@127.0.0.1:${PGPORT}/ironauth"
TOML
export IRONAUTH_MASTER_KEY="${IRONAUTH_MASTER_KEY:-$(python3 -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')}"

# APPLY THE SCHEMA, because `serve` does not.
#
# This script printed "startup COLD (fresh database, migrations run)" and the doc attributed
# the cold cost to migrations. A review queried the benchmarked database afterwards and found
# ZERO tables: `migrate` is a separate subcommand, dispatched beside `serve` rather than by it,
# and nothing here ever invoked it. With `log_statement=all`, the whole session logged four
# statements, all from createdb and psql, and none from the server.
#
# So every figure this script produced described a server booted against an empty database,
# which is a configuration no deployment runs. Migrating first makes the measured shape the
# real one, and it removes the cold-versus-warm framing entirely: with the schema already
# applied and the binary already exec'd, every run measures the same thing.
echo "startup-rss-bench: applying the schema (serve does not migrate; migrate is its own command)"
"$BIN" migrate --config "$CONFIG" >/dev/null 2>&1 || {
  echo "startup-rss-bench: the schema could not be applied" >&2
  exit 1
}

echo "startup-rss-bench: measuring"
starts=(); rsses=()
for i in $(seq 1 "$RUNS"); do
  if ! out="$(run_one "$CONFIG" "$DATA_PORT" "$MGMT_PORT")"; then
    echo "startup-rss-bench: run $i failed" >&2
    exit 1
  fi
  starts+=("$(echo "$out" | cut -d' ' -f1)")
  rsses+=("$(echo "$out" | cut -d' ' -f2)")
  echo "  run $i: startup $(echo "$out" | cut -d' ' -f1) ms, rss $(( $(echo "$out" | cut -d' ' -f2) / 1024 )) MiB"
done

python3 - "$RUNS" "${starts[@]}" "${rsses[@]}" <<'PY'
import sys, statistics

# COLD AND WARM ARE DIFFERENT OPERATIONS AND GET DIFFERENT ROWS.
#
# The first boot against a fresh database runs every migration; the rest do not. Reporting
# one median over both hides that, and the first version of this script did exactly that:
# it printed "within both targets" on a run whose cold start was 1217 ms against a
# sub-second target, because the median of five was 240 ms.
#
# That is the failure this whole file exists to avoid. A published number that passes by
# choosing the convenient statistic is worse than no number, because it is quoted.
runs = int(sys.argv[1])
starts = [float(v) for v in sys.argv[2:2+runs]]
rsses = [float(v) / 1024 for v in sys.argv[2+runs:2+2*runs]]

TARGET_MS, TARGET_MIB = 1000.0, 100.0

# ONE POPULATION, NOT A COLD AND A WARM ONE.
#
# This reported `starts[0]` as COLD and the rest as WARM, and published the COLD figure as the
# headline. Two reviews showed the split was an artifact rather than a property: the first
# sample was expensive because macOS was validating a freshly-written binary, and with that
# charged to a throwaway exec the samples are indistinguishable. A control run with an
# already-exec'd binary gave 322, 359 and 276 ms, with no ordering at all.
#
# The split was also a statistics problem on its own terms. COLD was n=1 while the doc claimed
# "a MEDIAN and a MAX over five runs", and the verdict turned on that single unreplicated
# sample sitting either side of the threshold: three unmodified invocations gave 1194, 1005 and
# 1068 ms, so one more draw would have flipped the published conclusion with no change to the
# code being measured.
print("startup-rss-bench: results")
print(f"  startup to ready   median {statistics.median(starts):.0f} ms   max {max(starts):.0f} ms"
      f"   over {runs} run(s)"
      f"{'' if max(starts) < TARGET_MS else '   MAX IS OVER the < 1000 ms target'}")
print(f"  rss idle           median {statistics.median(rsses):.1f} MiB   max {max(rsses):.1f} MiB"
      f"{'' if max(rsses) < TARGET_MIB else '   MAX IS OVER the < 100 MiB target'}")

# THE MAX, NOT THE MEDIAN, DECIDES. The first version of this file chose the median and
# printed "within both targets" on a run whose own max exceeded one of them. A published
# number that passes by choosing the convenient statistic is worse than no number, because it
# is quoted. Reporting both and judging on the worse one is the whole point.
start_ok = max(starts) < TARGET_MS
rss_ok = max(rsses) < TARGET_MIB
print()
if runs < 3:
    print(f"  NOTE: {runs} run(s) is not enough to report a median. Re-run with RUNS>=3.")
if start_ok and rss_ok:
    print("startup-rss-bench: within every stated target, on the WORST sample of each")
else:
    print("startup-rss-bench: a stated target is NOT met:")
    if not start_ok:
        print(f"  startup max {max(starts):.0f} ms exceeds {TARGET_MS:.0f} ms")
    if not rss_ok:
        print(f"  idle rss max {max(rsses):.1f} MiB exceeds {TARGET_MIB:.0f} MiB")
PY
