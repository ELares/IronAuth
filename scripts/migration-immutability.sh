#!/usr/bin/env bash
#
# A landed migration's bytes are frozen, comments included.
#
# migrate.rs digests the WHOLE FILE (`Sha256::digest(self.sql.as_bytes())`, and its own
# comment: "the checksum is over exactly the text that will run"), embeds each one with
# `include_str!`, and returns `MigrationError::ChecksumMismatch` when an ALREADY-APPLIED
# migration's text has moved. So editing a shipped migration -- even to fix a comment that
# is genuinely wrong -- makes every already-migrated database refuse to boot.
#
# Nothing else catches this. Every test suite runs against a FRESH database whose
# `_schema_migrations` ledger is empty, so the drift comparison iterates zero times: the
# local gate is green, CI is green, and production is broken. This gate is the only place
# the invariant is enforced rather than merely documented.
#
# The correction for a wrong comment in a shipped migration goes on the Rust type or in the
# crate CHANGELOG, never in the file. See migration 0073's correction on
# `PolicyDecisionInputs` and migration 0099's in `ironauth-store/CHANGELOG.md`.
#
# Usage: scripts/migration-immutability.sh [base-ref]   (default origin/main)
set -euo pipefail

BASE="${1:-origin/main}"

# A guard that no-ops when its anchor is missing protects nothing. Locally, an unresolvable
# base is a developer running the script in a clone without the remote, and skipping is
# right. In CI it means the check could not run, which is NOT the same as "no migration was
# edited", so there it is a hard failure. The `invariants` job checks out with
# `fetch-depth: 0` precisely because a shallow checkout has no `origin/main` to resolve.
if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "migration-immutability: FAILED. '$BASE' is not a revision here, so the check could" >&2
    echo "  not run. That is not the same as 'no migration changed'. The job needs" >&2
    echo "  actions/checkout with fetch-depth: 0." >&2
    exit 1
  fi
  echo "migration-immutability: '$BASE' is not a revision here; nothing to compare against." >&2
  exit 0
fi

# Deletions and renames count: a landed migration must still be there, byte for byte.
changed=$(git diff --name-only --diff-filter=MDR "$BASE" -- 'crates/*/migrations/*.sql' || true)

violations=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  # Only files that EXIST in the base are frozen. A brand new migration is the normal case.
  if git cat-file -e "$BASE:$file" 2>/dev/null; then
    echo "migration-immutability: FROZEN MIGRATION MODIFIED: $file"
    before=$(git show "$BASE:$file" | shasum -a 256 | cut -d' ' -f1)
    if [ -f "$file" ]; then
      after=$(shasum -a 256 "$file" | cut -d' ' -f1)
    else
      after="(deleted)"
    fi
    echo "    checksum in $BASE : $before"
    echo "    checksum here     : $after"
    violations=$((violations + 1))
  fi
done <<< "$changed"

if [ "$violations" -gt 0 ]; then
  cat >&2 <<'MSG'

migration-immutability: FAILED.

A migration that has landed on the base branch is frozen, comments included, because
migrate.rs checksums the whole file. Editing one makes every already-migrated database
refuse to boot with ChecksumMismatch, and no test catches it, because tests always run
against a fresh database.

If the migration's text is WRONG, do not fix it here. Record the correction where it can
safely live:
  * on the Rust type it describes (see migration 0073 on `PolicyDecisionInputs`), or
  * in the crate CHANGELOG (see migration 0099's entry in ironauth-store/CHANGELOG.md).

If you need to change the SCHEMA, add a NEW migration.
MSG
  exit 1
fi

echo "migration-immutability: clean (no landed migration modified against $BASE)."
