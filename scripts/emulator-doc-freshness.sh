#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The emulator doc's CI recipe stays true (issue #121, criterion 2).
#
# docs/EMULATOR.md ships a copy-pasteable GitHub Actions recipe, and a recipe has to carry
# LITERALS: a reader cannot paste a cross-reference. The deterministic OTP code is the one
# that matters, because it is the assertion that makes the whole job meaningful, and it is
# also the one that rots invisibly. If seeding changes, this repo's own CI fails loudly on
# its pinned EXPECT_CODE while the doc goes on telling every reader to assert the old value.
# A doc that computes nothing and states a number is only as good as the thing that checks it.
#
# So the doc's number is checked against CI's, and both must exist: a missing pin on either
# side is a failure, not a pass, because "found nothing to compare" is exactly how a check
# like this reports success while guarding nothing.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DOC="docs/EMULATOR.md"
WORKFLOW=".github/workflows/ci.yml"

for file in "$DOC" "$WORKFLOW"; do
  if [ ! -f "$file" ]; then
    echo "emulator-doc-freshness: $file is gone; this check now guards nothing." >&2
    exit 1
  fi
done

# CI's pin: the EXPECT_CODE the dev-otp-login job asserts.
ci_code="$(grep -oE 'EXPECT_CODE=[0-9]+' "$WORKFLOW" | head -1 | cut -d= -f2 || true)"
if [ -z "$ci_code" ]; then
  echo "emulator-doc-freshness: no EXPECT_CODE found in $WORKFLOW." >&2
  echo "  The doc's code is checked against CI's pin; with no pin there is nothing to" >&2
  echo "  check it against, so this must fail rather than report clean." >&2
  exit 1
fi

# The doc's copies. Every occurrence must agree, not just the first: the recipe states the
# code once in the comparison and once in the failure message, and one of them going stale
# is the same defect as both.
doc_codes="$(grep -oE '\b[0-9]{6}\b' "$DOC" | sort -u || true)"
if [ -z "$doc_codes" ]; then
  echo "emulator-doc-freshness: $DOC states no six-digit code." >&2
  echo "  The recipe's whole point is asserting the DETERMINISTIC code; without it the" >&2
  echo "  documented job would pass against any code at all." >&2
  exit 1
fi

fail=0
for code in $doc_codes; do
  if [ "$code" != "$ci_code" ]; then
    echo "emulator-doc-freshness: $DOC states $code, but $WORKFLOW pins $ci_code." >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "  Seeding changed, or one side was edited alone. CI fails loudly on its own pin;" >&2
  echo "  the doc does not, so every reader would keep asserting a code that no longer" >&2
  echo "  appears. Update $DOC to match." >&2
  exit 1
fi

echo "emulator-doc-freshness: clean (the documented OTP code $ci_code matches CI's pin)"
