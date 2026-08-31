#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The browser-app guidance says what the BCP says (issue #117 criterion 5).
#
# Two properties, and the second is the one worth a gate.
#
#   1. The ranking page EXISTS and ranks all three architectures. A criterion satisfied by a page
#      nobody wrote is the ordinary failure; this is the cheap half.
#
#   2. NO IronAuth document describes storing a token in `localStorage`. That is a prohibition on
#      the whole corpus rather than a sentence on one page, because the way this guidance goes
#      wrong is not that someone edits the ranking -- it is that a quickstart three directories
#      away shows the easy thing.
#
# The scan is deliberately BROAD: any mention at all outside the one page that forbids it is a
# failure, including a well-meant "do not use localStorage" written somewhere else. That reads as
# over-strict until you notice the alternative is a regex trying to tell advice from warning, and
# a regex that guesses is a gate that eventually guesses wrong in the permissive direction.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

PAGE="docs/bff.md"

if [ ! -f "$PAGE" ]; then
  echo "bff-docs: $PAGE is missing; issue #117 criterion 5 needs the BCP ranking page" >&2
  exit 1
fi

# The three architectures, each by the name the BCP uses.
missing=()
grep -qi 'backend-for-frontend' "$PAGE" || missing+=("backend-for-frontend")
grep -qi 'token-mediating backend' "$PAGE" || missing+=("token-mediating backend")
grep -qi 'browser-held tokens' "$PAGE" || missing+=("browser-held tokens")
if [ ${#missing[@]} -ne 0 ]; then
  echo "bff-docs: $PAGE does not rank: ${missing[*]}" >&2
  exit 1
fi

# The two mitigations the BCP requires before browser-held tokens are acceptable at all. A page
# that ranked them last WITHOUT naming both would be ranking without the tradeoff, which is the
# thing this criterion exists to prevent.
grep -qi 'DPoP' "$PAGE" || { echo "bff-docs: $PAGE ranks browser-held tokens without naming DPoP" >&2; exit 1; }
grep -qi 'rotation' "$PAGE" || { echo "bff-docs: $PAGE ranks browser-held tokens without naming refresh rotation" >&2; exit 1; }

# And the prohibition, over every AUTHORED document except the page that states it.
#
# `docs/llms.txt` and `docs/llms-full.txt` are excluded because they are GENERATED: the corpus
# concatenates every published page, so it necessarily contains whatever `docs/bff.md` says about
# localStorage. Flagging that would be flagging the prohibition itself for existing, and the fix
# an author would reach for -- softening the wording on the page that owns the subject -- is
# exactly backwards.
#
# The exclusion is safe because a generated concatenation cannot introduce guidance: anything it
# carries came from a source file this scan already reads.
offenders=$(grep -rliE 'localstorage' docs packages/*/README.md 2>/dev/null \
  | grep -v "^${PAGE}$" \
  | grep -vE '^docs/llms(-full)?\.txt$' || true)
if [ -n "$offenders" ]; then
  echo "bff-docs: localStorage is mentioned outside ${PAGE}:" >&2
  printf '  %s\n' $offenders >&2
  echo "  No IronAuth document may describe storing a token there. If this is a warning rather" >&2
  echo "  than advice, it belongs in ${PAGE}, which is the one page that owns the subject." >&2
  exit 1
fi

echo "bff-docs: clean (the BCP ranking is present and no document describes localStorage token storage)"
