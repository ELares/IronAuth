#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Emit the API-surface changelog for THIS change (issue #122 criterion 5).
#
# The criterion asks that "a deliberate test change to a management endpoint produces an
# auto-generated changelog entry enumerating the diff, demonstrated in CI". The self-test in
# `openapi-changelog.py` proves the GENERATOR is correct against synthetic diffs; this proves
# it runs against the real one, on every change, which is the half a self-test cannot show.
#
# It is deliberately NOT a gate. A breaking change is a release decision, and failing the
# build on one would make this a policy engine rather than a changelog. What it does is make
# the diff impossible to miss: it prints to the log and, on GitHub, to the step summary where
# a reviewer sees it beside the diff itself.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SPEC="docs/openapi/management.json"
BASE="${1:-origin/main}"

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "openapi-changelog-ci: '$BASE' is not a revision here; nothing to compare against." >&2
  echo "  Pass a base revision as the first argument." >&2
  exit 1
fi

# The base's spec, or an empty document when the file is new, so a first-time addition
# enumerates every operation rather than failing to resolve a path.
before=$(mktemp)
trap 'rm -f "$before"' EXIT
if git cat-file -e "$BASE:$SPEC" 2>/dev/null; then
  git show "$BASE:$SPEC" > "$before"
else
  echo '{"openapi":"3.1.0","paths":{}}' > "$before"
fi

if git diff --quiet "$BASE" -- "$SPEC"; then
  echo "openapi-changelog-ci: the published contract is unchanged against $BASE."
  exit 0
fi

echo "openapi-changelog-ci: the published contract changed against $BASE."
echo
changelog=$(python3 scripts/openapi-changelog.py "$before" "$SPEC")
printf '%s\n' "$changelog"

# On GitHub, put it where a reviewer reads it rather than only in a log nobody opens.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    printf '## API surface change in this PR\n\n'
    printf '%s\n' "$changelog"
  } >> "$GITHUB_STEP_SUMMARY"
fi

# Breaking changes are REPORTED, never failed on: deciding to ship one is the release's call.
if printf '%s' "$changelog" | grep -q '\*\*BREAKING\*\*'; then
  echo
  echo "openapi-changelog-ci: this change is BREAKING for existing clients. That is not an"
  echo "  error and this check does not fail on it; it needs a major version and a"
  echo "  deprecation note, per the stability policy in docs/SDK-CONTRACT.md."
fi
