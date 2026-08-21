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

# Enumerate from the BASE SIDE rather than diffing.
#
# `git diff --name-only` was the original approach and it leaked three different ways, each
# of which made an entry vanish with no diagnostic:
#
#   * RENAMES. Detection is on by default and `--name-only` prints only the DESTINATION
#     path, which by definition is not in the base, so the probe found nothing. Deleting a
#     migration while adding a similar one is detected as a rename, and that is the ordinary
#     way a new migration gets written: copy the last one.
#   * C-QUOTED PATHS. `core.quotePath` defaults to true, so a path containing a non-ASCII
#     byte, a quote, a backslash or a control character is printed as a quoted C string,
#     which does not resolve as a path either. `-c core.quotePath=false` is NOT enough: it
#     un-quotes the non-ASCII case and still quotes the rest.
#   * CLEAN/SMUDGE FILTERS. A `.gitattributes` entry such as `*.sql text eol=crlf` makes the
#     WORKTREE bytes differ from the blob while `git diff` reports NOTHING, because the
#     filter is applied before comparison. `include_str!` compiles the worktree bytes, so
#     every checksum would move at once while the diff listed zero files.
#
# Listing the base's own migrations and comparing each one's blob against the bytes on disk
# has none of those failure modes: there is no rename to detect, `-z` output is never quoted,
# and neither side passes through a filter. A file the base does not carry is simply absent
# from the list, which is what makes a brand new migration the normal case.
list_file=$(mktemp)
cleanup() { rm -f "$list_file"; }
trap cleanup EXIT

if ! git ls-files -z --with-tree="$BASE" -- 'crates/*/migrations/*.sql' > "$list_file"; then
  echo "migration-immutability: FAILED. Could not list migrations at '$BASE', so the check" >&2
  echo "  could not run. That is not the same as 'no migration changed'." >&2
  exit 1
fi

if [ ! -s "$list_file" ]; then
  echo "migration-immutability: FAILED. '$BASE' carries NO migrations, which cannot be right" >&2
  echo "  for this repository. Refusing to report clean on an empty comparison set." >&2
  exit 1
fi

violations=0
# NUL delimited, and read from a FILE rather than a pipe: a pipe would run the loop in a
# subshell and `violations` would be discarded when it exited.
while IFS= read -r -d '' file; do
  [ -n "$file" ] || continue

  # `--with-tree` lists the UNION of the index and the tree, not the tree alone, so a
  # migration this branch ADDS is in the list too. That is the normal case and must pass:
  # a file the base does not carry is not frozen, it is new. Without this probe every PR
  # that adds a migration fails, which is most of them.
  git cat-file -e "$BASE:$file" 2>/dev/null || continue

  if ! before=$(git show "$BASE:$file" | shasum -a 256 | cut -d' ' -f1); then
    echo "migration-immutability: FAILED. Could not read '$file' at '$BASE'." >&2
    exit 1
  fi
  if [ -L "$file" ]; then
    # A symlink where a regular file has to be. Whatever `include_str!` would compile, it is
    # not this path's own bytes.
    after="(not a regular file)"
  elif [ -f "$file" ]; then
    after=$(shasum -a 256 < "$file" | cut -d' ' -f1)
  elif [ -e "$file" ]; then
    after="(not a regular file)"
  else
    after="(missing)"
  fi

  # A mode-only change (chmod) leaves the bytes, and therefore the digest, untouched. It is
  # not what this gate is about, and reporting it would print two identical checksums under a
  # heading saying the file changed.
  [ "$before" = "$after" ] && continue

  echo "migration-immutability: FROZEN MIGRATION CHANGED: $file"
  echo "    checksum in $BASE : $before"
  echo "    checksum here     : $after"
  violations=$((violations + 1))
done < "$list_file"

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
