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
#              Not to "the process exists", which is microseconds and says
#              nothing, and not to the first listening socket, which precedes
#              migrations and the first database round trip.
#   rss      = resident set size after readiness plus a settle period, with NO
#              traffic. Idle means idle: a number taken under load is a
#              different measurement wearing the same name.
#
# It reports the MEDIAN of N runs and also the max. A single sample on a shared
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

cold, warm = starts[0], starts[1:]
TARGET_MS, TARGET_MIB = 1000.0, 100.0

print("startup-rss-bench: results")
print(f"  startup COLD (fresh database, migrations run)   {cold:.0f} ms" 
      f"{'' if cold < TARGET_MS else '   OVER the < 1000 ms target'}")
if warm:
    print(f"  startup WARM (already migrated, the restart    "
          f"  median {statistics.median(warm):.0f} ms   max {max(warm):.0f} ms"
          f"{'' if max(warm) < TARGET_MS else '   OVER the < 1000 ms target'}")
    print( "               and rolling-upgrade case)")
print(f"  rss idle                                        median {statistics.median(rsses):.1f} MiB"
      f"   max {max(rsses):.1f} MiB"
      f"{'' if max(rsses) < TARGET_MIB else '   OVER the < 100 MiB target'}")

warm_ok = not warm or max(warm) < TARGET_MS
cold_ok = cold < TARGET_MS
rss_ok = max(rsses) < TARGET_MIB
print()
if cold_ok and warm_ok and rss_ok:
    print("startup-rss-bench: within every stated target, cold and warm")
else:
    print("startup-rss-bench: a stated target is NOT met:")
    if not cold_ok:
        print(f"  cold startup {cold:.0f} ms exceeds {TARGET_MS:.0f} ms. This is the fresh-install")
        print( "  case: every migration runs before the first readiness. A deployment restarting")
        print( "  an already-migrated database gets the warm number instead.")
    if not warm_ok:
        print(f"  warm startup max {max(warm):.0f} ms exceeds {TARGET_MS:.0f} ms")
    if not rss_ok:
        print(f"  idle rss max {max(rsses):.1f} MiB exceeds {TARGET_MIB:.0f} MiB")
    # Reported, not hidden. Whether a fresh install is in scope for the target is a
    # product decision; publishing only the half that passes is not.
PY
