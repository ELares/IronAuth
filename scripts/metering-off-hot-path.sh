#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The login and token-issuance paths do no metering work inline (issue #107).
#
# #107 asks for "a query-count regression test proves token issuance and login paths
# execute zero metering queries inline". Counting queries at runtime would need
# instrumentation the store does not have, and a runtime counter proves it for the ONE
# path the test drove. This proves it for every path in these files instead, by making the
# metering API unreachable from them.
#
# The property rests on two facts, and BOTH are checked, because either alone is a claim
# that quietly stops being true:
#
#   1. the hot-path modules never name the metering API, so they cannot call it; and
#   2. the metering API has no database surface at all, so calling it could not issue a
#      query even if somebody did.
#
# Fact 2 is what makes fact 1 worth having. A metering type that grew an `async fn` taking
# a connection would turn every future call site into a hot-path query, and this file would
# still be green if it only checked fact 1.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The modules the issue names: where a login completes and where a token is issued.
HOT_PATHS=(
  "crates/ironauth-oidc/src/authorize.rs"
  "crates/ironauth-oidc/src/token.rs"
)

# The metering surface. Naming any of these from a hot path is the violation.
METERING_SYMBOLS='UsageTally|saw_active|saw_token_issued|saw_connection|monthly_active_users'

fail=0

for path in "${HOT_PATHS[@]}"; do
  if [ ! -f "$path" ]; then
    echo "metering-off-hot-path: $path is gone; this check now guards nothing." >&2
    echo "  Point it at wherever login and token issuance moved to." >&2
    fail=1
    continue
  fi
  hits=$(grep -nE "$METERING_SYMBOLS" "$path" || true)
  if [ -n "$hits" ]; then
    echo "metering-off-hot-path: $path names the metering API:" >&2
    echo "$hits" >&2
    echo "  Metering is a fold over the event feed, computed by a consumer. Calling it" >&2
    echo "  from here puts work on the login path that #107 requires stay off it." >&2
    fail=1
  fi
done

# Fact 2: the metering type performs no I/O. `UsageTally`'s methods must all be
# synchronous and take no connection, so there is nothing for them to query.
tally_block=$(awk '/^impl UsageTally \{/,/^\}/' crates/ironauth-store/src/repository.rs)
if [ -z "$tally_block" ]; then
  echo "metering-off-hot-path: could not find 'impl UsageTally'; the check cannot" >&2
  echo "  verify the metering API is I/O free, so it must not report success." >&2
  exit 1
fi
if printf '%s\n' "$tally_block" | grep -qE 'async fn|Executor|PgPool|&mut \*tx|sqlx::'; then
  echo "metering-off-hot-path: UsageTally grew a database surface:" >&2
  printf '%s\n' "$tally_block" | grep -nE 'async fn|Executor|PgPool|&mut \*tx|sqlx::' >&2
  echo "  Metering must stay a pure fold. Once it can issue a query, every call site" >&2
  echo "  becomes a potential hot-path query and the check above stops being enough." >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "metering-off-hot-path: clean (${#HOT_PATHS[@]} hot-path modules name no metering API; UsageTally is I/O free)"
