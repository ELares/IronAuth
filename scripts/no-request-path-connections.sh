#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The no-request-path-connections lint (issue #155 acceptance criterion 3).
#
# The multi-region architecture rule: cross-region flows are ASYNCHRONOUS ONLY, and no
# synchronous cross-region database call may exist on any request path. The structural
# guarantee this lint pins is the one that makes a cross-region call impossible to write
# rather than merely forbidden: a request-path crate NEVER constructs a database
# connection. The request path receives its `Store` from the boot wiring; a connection
# constructed in a request-path crate would be a NEW database target chosen by request
# code, which is precisely the seam a synchronous cross-region call (or any
# second-database coupling) would have to come through.
#
# The lint scans the crates that serve requests — ironauth-oidc (the OIDC/authorize/login
# surface), and the helper crates it calls from handlers (hot, journey, screening,
# quota, connector) — for connection construction:
#
#     Store::connect        ironauth_store::Store::connect
#     PgPool::connect       sqlx::PgPool::connect / connect_with
#     PgPoolOptions::new    the builder form of PgPool::connect
#
# Integration-test trees are excluded: test scaffolding legitimately connects to a
# throwaway database. The boot wiring that constructs connections lives in
# crates/ironauth/src/main.rs, which is NOT a request-path crate and is not scanned.
#
# This is the same class of grep-based structural backstop as
# scripts/hashing-pool-boundary.sh and scripts/canonicalization-seam.sh. An exceptional
# line may carry the marker "request-path-connection-allow: <reason>" with a written
# justification; use sparingly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The request-path crates. Every one is scanned and every one is expected to contain
# ZERO connection constructions: a new entry in this list must first be true of the
# crate, or the lint fails and the exception has to be written down.
CRATES='crates/ironauth-oidc crates/ironauth-hot crates/ironauth-journey crates/ironauth-screening crates/ironauth-quota crates/ironauth-connector'

# The construction call forms this lint owns. Each name is the whole reachable surface:
# the qualified path and the bare call (the `use`d form) both match.
PATTERN='Store::connect|PgPool::connect|PgPoolOptions::new'

fail=0
for crate in $CRATES; do
  hits=$(grep -rn --include='*.rs' -E "$PATTERN" "$crate/src/" 2>/dev/null \
    | grep -v 'request-path-connection-allow:' || true)
  if [ -n "$hits" ]; then
    echo "request-path connection constructed in $crate/src/:" >&2
    echo "$hits" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "no-request-path-connections: FAILED. The request path receives its Store from" >&2
  echo "boot wiring; a connection constructed here is a new database target chosen by" >&2
  echo "request code, which is the seam a synchronous cross-region call would come" >&2
  echo "through (issue #155)." >&2
  exit 1
fi

echo "no-request-path-connections: the request path constructs no database connections"