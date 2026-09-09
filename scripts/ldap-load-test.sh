#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The large-directory load test (issue #142): a synthetic directory of tens of thousands of
# entries, swept end to end, with duration and peak memory RECORDED rather than asserted.
#
# WHY RECORDED AND NOT ASSERTED. A wall-clock budget or a megabyte ceiling checked on a shared CI
# runner is a flake generator: the same code measures differently on a loaded box, and a threshold
# tuned to make that stop failing is a threshold that no longer means anything. What this produces
# is a number in the job's artifact, so a reader comparing two runs can SEE a regression, and the
# one thing it does assert is the property that is not a measurement: that the pass COMPLETED and
# provisioned every person in the directory.
#
# THE MEMORY IS PROPORTIONAL, AND THAT IS INHERENT. Paging bounds what is on the wire at once, not
# what the process holds: the diff compares the whole directory against the whole previous
# snapshot, so the set is resident by construction. Measured at about 1.8KB per entry marginal
# (see the table on `MAX_ENTRIES` in `ldap_boot`, which this script produced). `MAX_ENTRIES` is
# what turns "too big" into a refusal naming the connector rather than an allocator killing the
# sweep.
#
# WHAT THE REPORT'S PER-ENTRY FIGURE IS NOT. `raw_peak_bytes_per_entry` below divides the WHOLE
# binary's peak by the entry count, and most of that peak is the harness -- a test database,
# every migration, libtest -- not the directory. It is a run-to-run comparison at a FIXED size,
# not the marginal cost; the marginal figure is a subtraction against the five-entry baseline and
# is quoted where the table is.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

: "${IRONAUTH_LDAP_URL:?IRONAUTH_LDAP_URL must point at the directory to load}"
: "${IRONAUTH_LDAP_ADMIN_DN:=cn=admin,dc=example,dc=test}"
: "${IRONAUTH_LDAP_ADMIN_PASSWORD:=adminpw}"
ENTRIES="${IRONAUTH_LDAP_LOAD_ENTRIES:-20000}"
REPORT="${IRONAUTH_LDAP_LOAD_REPORT:-target/ldap-load-report.txt}"

host_port() { printf '%s' "${IRONAUTH_LDAP_URL#ldap://}"; }

echo "ldap-load-test: generating ${ENTRIES} entries"
tmp="$(mktemp -t ldap-bulk)"
trap 'rm -f "$tmp"' EXIT
python3 - "$ENTRIES" > "$tmp" <<'PY'
import sys
n = int(sys.argv[1])
for i in range(n):
    print(f"""dn: uid=bulk{i:06d},ou=People,dc=example,dc=test
objectClass: inetOrgPerson
uid: bulk{i:06d}
cn: Bulk Person {i:06d}
sn: Person{i:06d}
mail: bulk{i:06d}@example.test
""")
PY

echo "ldap-load-test: loading them"
load_start=$(date +%s)
# `-c` so one duplicate from a re-run does not abort the load; the count is verified below.
ldapadd -x -c -H "$IRONAUTH_LDAP_URL" -D "$IRONAUTH_LDAP_ADMIN_DN" \
  -w "$IRONAUTH_LDAP_ADMIN_PASSWORD" -f "$tmp" >/dev/null 2>&1 || true
load_secs=$(( $(date +%s) - load_start ))

# THE DIRECTORY IS THE SIZE THE TEST THINKS IT IS. Without this the pass below could sweep five
# people and the report would record a load test that never loaded anything.
present=$(ldapsearch -x -E "pr=500/noprompt" -H "$IRONAUTH_LDAP_URL" \
  -D "$IRONAUTH_LDAP_ADMIN_DN" -w "$IRONAUTH_LDAP_ADMIN_PASSWORD" \
  -b "ou=People,dc=example,dc=test" "(objectClass=inetOrgPerson)" dn 2>/dev/null \
  | grep -c "^dn: uid" || true)
if [ "$present" -lt "$ENTRIES" ]; then
  echo "ldap-load-test: the directory holds ${present} people, fewer than the ${ENTRIES} loaded"
  exit 1
fi
echo "ldap-load-test: ${present} people present"

# THE PEAK RSS OF THE PASS ITSELF, not of cargo: the test binary is invoked directly so the
# figure is the sweep's, and a compile does not land in the measurement.
# `set -e` OFF FOR THE GLOB. Under `pipefail` a non-matching glob makes `ls` and then the whole
# pipeline non-zero, so the assignment terminates the script and the friendly message below never
# prints -- the guard was unreachable.
set +e
binary=$(ls -t target/debug/deps/ldap_live_pass-* 2>/dev/null | grep -v '\.d$' | head -1)
set -e
if [ -z "$binary" ]; then
  echo "ldap-load-test: no ldap_live_pass binary; build the tests first"
  exit 1
fi

measured="$(mktemp -t ldap-load-time)"
trap 'rm -f "$tmp" "$measured"' EXIT
# THE TEST IS TOLD WHAT TO EXPECT, and its EXIT STATUS is the answer. It used to be told nothing
# and the count was scraped out of its panic message, which inverted the assertion: a pass that
# reached every person printed no `provisioned:` line at all and the script called it incomplete.
export IRONAUTH_LDAP_EXPECT_PEOPLE="$present"
run_start=$(date +%s000)
set +e
if /usr/bin/time -v true >/dev/null 2>&1; then
  /usr/bin/time -v "$binary" --ignored >"$measured" 2>&1   # GNU time, Linux
else
  /usr/bin/time -l "$binary" --ignored >"$measured" 2>&1   # BSD time, macOS
fi
status=$?
set -e
run_ms=$(( $(date +%s000) - run_start ))

# THE PARSE FAILS LOUDLY. A silent miss would record a load test with no memory figure, which is
# the one number the artifact exists for.
peak_kb=$(grep -oE "Maximum resident set size \(kbytes\): [0-9]+" "$measured" | grep -oE "[0-9]+$" || true)
if [ -z "$peak_kb" ]; then
  peak_bytes=$(grep -oE "^[[:space:]]*[0-9]+[[:space:]]+maximum resident set size" "$measured" \
    | grep -oE "[0-9]+" | head -1 || true)
  [ -n "$peak_bytes" ] && peak_kb=$(( peak_bytes / 1024 ))
fi
if [ -z "${peak_kb:-}" ]; then
  echo "ldap-load-test: could not read a peak RSS from the timing output"
  tail -20 "$measured"
  exit 1
fi

mkdir -p "$(dirname "$REPORT")"
{
  echo "entries_loaded=${present}"
  echo "load_seconds=${load_secs}"
  echo "pass_milliseconds=${run_ms}"
  echo "peak_rss_kb=${peak_kb}"
  # RAW, NOT MARGINAL. This divides the WHOLE binary's peak by the entry count, and most of that
  # peak is the harness -- a test database, every migration, libtest -- not the directory. At the
  # fixture's five entries the same binary peaks around 15MB, so this number is dominated by the
  # baseline at small N and only approaches the true per-entry cost at large N. A reader
  # comparing two runs AT THE SAME N sees a real regression; a reader comparing across N does
  # not. The marginal figure quoted in `ldap_boot`'s MAX_ENTRIES doc is this minus that baseline.
  echo "raw_peak_bytes_per_entry=$(( peak_kb * 1024 / present ))"
  echo "pass_exit_status=${status}"
} | tee "$REPORT"

# THE ONE ASSERTION, and it is not a measurement: the pass reached every person. The test was
# told the count above, so a non-zero exit IS that failure and nothing has to be parsed.
if [ "$status" -ne 0 ]; then
  echo "ldap-load-test: the pass over ${present} people did not complete (exit ${status})"
  tail -30 "$measured"
  exit 1
fi
echo "ldap-load-test: clean (${present} entries, ${run_ms}ms, ${peak_kb}KB peak)"
exit 0
