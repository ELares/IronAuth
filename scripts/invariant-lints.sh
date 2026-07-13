#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Structural invariants that ordinary compiler lints cannot express, enforced
# as grep rules over the workspace. Each rule names the invariant it guards.
# An exceptional call site may carry the marker "invariant-allow: <rule>" on
# the same line together with a written reason; use sparingly.
#
# Rule time-via-env: all wall-clock and monotonic time flows through
#   crates/ironauth-env (Clock trait). No raw SystemTime::now or Instant::now
#   anywhere else, so protocol logic stays deterministic under test.
# Rule entropy-via-env: all randomness flows through crates/ironauth-env
#   (Entropy trait). No direct getrandom or rand usage anywhere else, so
#   identifier and nonce generation stays deterministic under test.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

scan() {
  local rule="$1" pattern="$2"
  local hits
  hits=$(grep -rn --include='*.rs' -E "$pattern" crates \
    | grep -v '^crates/ironauth-env/' \
    | grep -v "invariant-allow: ${rule}" || true)
  if [ -n "$hits" ]; then
    echo "invariant-lints: rule '${rule}' violated:"
    echo "$hits"
    fail=1
  fi
}

scan time-via-env 'SystemTime::now|Instant::now'
scan entropy-via-env 'getrandom::|(^|[^a-z_])rand::|rand_core::'

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "invariant-lints: clean"
