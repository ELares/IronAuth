#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run a command with DATABASE_URL pointing at a THROWAWAY local Postgres.
#
# The ironauth-store isolation tests (RLS, IDOR) need a real database. To keep
# the dependency tree permissive-licensed and MSRV/musl clean, the crate does
# not embed a Postgres; it drives one via DATABASE_URL instead. This wrapper
# brings up a disposable cluster in a temp directory, exports DATABASE_URL, runs
# the given command, and tears the cluster (and every temp database in it) down
# on exit. No docker, no persistent service.
#
# Usage:
#   scripts/with-test-db.sh cargo test -p ironauth-store --all-features
#
# If DATABASE_URL is already set, the command runs against that database instead
# and no cluster is started (use this to target a CI Postgres service).
#
# ON THAT PATH THIS SCRIPT IS A PASS-THROUGH, and one thing it deliberately does NOT do is
# set IRONAUTH_TEST_DB_DISPOSABLE. That marker says "every database in this cluster is mine
# to reclaim", which is true of a cluster this script created and unknowable for one you
# handed it. The store harness refuses to run when IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS
# LOWERS the leftover sweep below its six-hour default and the marker is absent, in EVERY
# test binary rather than in one test, so set it yourself when the cluster really is
# disposable:
#
#   DATABASE_URL=... IRONAUTH_TEST_DB_DISPOSABLE=1 scripts/with-test-db.sh cargo test ...
#
# Postgres binaries are found via (in order): $PG_BIN, pg_ctl on PATH,
# /usr/lib/postgresql/*/bin (Debian/Ubuntu), and ~/.theseus/postgresql/*/bin.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: scripts/with-test-db.sh <command...>" >&2
  exit 2
fi

# Respect an externally provided database (for example a CI service). Note that
# IRONAUTH_TEST_DB_DISPOSABLE is NOT set here: see the header for why the caller owns that
# decision on this path.
if [ -n "${DATABASE_URL:-}" ]; then
  exec "$@"
fi

find_pg_bin() {
  if [ -n "${PG_BIN:-}" ] && [ -x "${PG_BIN}/initdb" ]; then
    echo "${PG_BIN}"
    return 0
  fi
  local dir
  if command -v pg_ctl >/dev/null 2>&1; then
    dir="$(dirname "$(command -v pg_ctl)")"
    [ -x "${dir}/initdb" ] && { echo "${dir}"; return 0; }
  fi
  local cand
  for cand in /usr/lib/postgresql/*/bin "${HOME}"/.theseus/postgresql/*/bin; do
    if [ -x "${cand}/initdb" ] && [ -x "${cand}/pg_ctl" ]; then
      echo "${cand}"
      return 0
    fi
  done
  return 1
}

PG_BIN_DIR="$(find_pg_bin)" || {
  echo "with-test-db: could not find a Postgres install (initdb/pg_ctl)." >&2
  echo "Install Postgres, or set PG_BIN to its bin directory, or set DATABASE_URL." >&2
  exit 1
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ironauth-pg.XXXXXX")"
PGDATA="${WORKDIR}/data"
SOCKDIR="${WORKDIR}/sock"
mkdir -p "${SOCKDIR}"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
SUPERUSER="ironauth_super"

cleanup() {
  "${PG_BIN_DIR}/pg_ctl" -D "${PGDATA}" -m immediate stop >/dev/null 2>&1 || true
  rm -rf "${WORKDIR}"
}
trap cleanup EXIT INT TERM

echo "with-test-db: initializing throwaway cluster in ${PGDATA} on port ${PORT}"
"${PG_BIN_DIR}/initdb" -D "${PGDATA}" -U "${SUPERUSER}" -A trust >/dev/null

# Listen on loopback TCP only; keep the socket in the temp dir.
"${PG_BIN_DIR}/pg_ctl" -D "${PGDATA}" -w -o \
  "-p ${PORT} -k ${SOCKDIR} -c listen_addresses=127.0.0.1" start >/dev/null

export DATABASE_URL="postgres://${SUPERUSER}@127.0.0.1:${PORT}/postgres"
# THIS CLUSTER IS DISPOSABLE, and one test needs to know that rather than assume it.
#
# `test_db_reclaim` drives a sweep with IRONAUTH_TEST_DB_RECLAIM_MIN_AGE_SECS lowered to
# five minutes, which is cluster-wide: it would also reclaim a CONCURRENT harness run's
# databases in the same cluster. That is safe here, because this script just created the
# cluster and tears it down on exit, and it is not safe against a DATABASE_URL somebody
# set by hand. The test refuses to run that arm without this marker rather than skipping
# it, so the protection can never be lost silently.
export IRONAUTH_TEST_DB_DISPOSABLE=1
echo "with-test-db: DATABASE_URL=${DATABASE_URL}"

set +e
"$@"
status=$?
set -e
exit "${status}"
