#!/usr/bin/env bash
#
# A landed migration's bytes are frozen, comments included.
#
# migrate.rs digests the WHOLE FILE (`Sha256::digest(self.sql.as_bytes())`, and its own
# comment: "the checksum is over exactly the text that will run"), embeds each one with
# `include_str!`, and returns `MigrationError::ChecksumMismatch` when an ALREADY-APPLIED
# migration's text has moved. So editing a shipped migration -- even to fix a comment that
# is genuinely wrong -- makes every already-migrated database refuse to boot. REMOVING one is
# worse still: the version disappears from the registry and the ledger row has nothing to
# match, which is `MigrationError::UnknownApplied`.
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

BASE_REF="${1:-origin/main}"

# Locally the remote ref can be stale, and a migration that landed since your last fetch is
# precisely the one you would be tempted to correct. In CI the checkout is already exact.
if [ -z "${GITHUB_ACTIONS:-}" ] && [ "$BASE_REF" = "origin/main" ]; then
  git fetch -q origin main 2>/dev/null ||
    echo "migration-immutability: could not fetch origin/main; comparing against the local ref." >&2
fi

# A guard that no-ops when its anchor is missing protects nothing. Locally, an unresolvable
# base is a developer running the script in a clone without the remote, and skipping is
# right. In CI it means the check could not run, which is NOT the same as "no migration was
# edited", so there it is a hard failure. The `invariants` job checks out with
# `fetch-depth: 0` precisely because a shallow checkout has no `origin/main` to resolve.
if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "migration-immutability: FAILED. '$BASE_REF' is not a revision here, so the check" >&2
    echo "  could not run. That is not the same as 'no migration changed'. The job needs" >&2
    echo "  actions/checkout with fetch-depth: 0." >&2
    exit 1
  fi
  echo "migration-immutability: '$BASE_REF' is not a revision here; nothing to compare against." >&2
  exit 0
fi

# Compare against the MERGE BASE, not the tip. A branch that is merely behind main has not
# touched a migration just because main landed one since; comparing against the tip reports
# every such migration as deleted. A gate that cries wolf on an untouched tree is a gate
# people learn to skip, which is exactly how the defect this exists to stop got through four
# rounds of review. Every true positive survives, because an edit on this branch is still an
# edit relative to the merge base.
BASE=$(git merge-base "$BASE_REF" HEAD 2>/dev/null || echo "$BASE_REF")

# --no-renames is load bearing. With rename detection ON (the default) `--name-only` prints
# only the DESTINATION path for a rename, and the base-side existence probe below then asks
# about a path that by definition is not in the base, so the entry silently vanishes. That is
# not a hypothetical: deleting a migration while adding a similar one, which is the ordinary
# way a new migration gets written (copy the last one), is detected as a rename.
#
# No --diff-filter either. It is an allowlist, so any status not named is exempt: a type
# change (replacing a migration with a symlink) alters the digest and would pass. The
# base-side existence probe is the correct and complete discriminator on its own.
#
# The git failure is NOT swallowed. `|| true` here would turn a broken git invocation into a
# clean report, which is the same vacuous pass this script's own base-ref handling refuses.
if ! changed=$(git diff --no-renames --name-only "$BASE" -- 'crates/*/migrations/*.sql'); then
  echo "migration-immutability: FAILED. 'git diff' against '$BASE' did not complete, so the" >&2
  echo "  check could not run. That is not the same as 'no migration changed'." >&2
  exit 1
fi

violations=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  # Only files that EXIST in the base are frozen. A brand new migration is the normal case.
  git cat-file -e "$BASE:$file" 2>/dev/null || continue

  before=$(git show "$BASE:$file" | shasum -a 256 | cut -d' ' -f1)
  if [ -f "$file" ]; then
    after=$(shasum -a 256 "$file" | cut -d' ' -f1)
  else
    after="(deleted)"
  fi
  # A mode-only change (chmod) leaves the bytes, and therefore the digest, untouched. It is
  # not what this gate is about, and reporting it would print two identical checksums under a
  # heading that says the file changed.
  [ "$before" = "$after" ] && continue

  echo "migration-immutability: FROZEN MIGRATION MODIFIED: $file"
  echo "    checksum in $BASE : $before"
  echo "    checksum here     : $after"
  violations=$((violations + 1))
done <<< "$changed"

if [ "$violations" -gt 0 ]; then
  cat >&2 <<'MSG'

migration-immutability: FAILED.

A migration that has landed on the base branch is frozen, comments included, because
migrate.rs checksums the whole file. Editing one makes every already-migrated database
refuse to boot with ChecksumMismatch, and REMOVING one makes it fail with UnknownApplied.
No test catches either, because tests always run against a fresh database.

If the migration's text is WRONG, do not fix it here. Record the correction where it can
safely live:
  * on the Rust type it describes (see migration 0073 on `PolicyDecisionInputs`), or
  * in the crate CHANGELOG (see migration 0099's entry in ironauth-store/CHANGELOG.md).

If you need to change the SCHEMA, add a NEW migration. To supersede a table, add a new
migration that alters it; do not delete the one that created it.
MSG
  exit 1
fi

echo "migration-immutability: clean (no landed migration modified against $BASE)."
