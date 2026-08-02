# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The shared precondition of every "regenerate, then `git diff --exit-code`" freshness
# gate in scripts/. Sourced, not executed.
#
# THE HOLE IT CLOSES. `git diff --exit-code <path>` compares the working tree against the
# INDEX. For a path git does not TRACK there is nothing in the index to compare, so git
# reports no difference and exits 0. A freshness gate built on that comparison therefore
# passes on ANY content whatsoever the moment its artifact is untracked, and it passes
# quietly: the regeneration ran, the diff came back empty, the gate printed "clean".
#
# Measured (issue #241) on docs/design/user-bound-mint-sites.txt: with the inventory
# untracked, adding a second mint call to a file already listed left the lint clean. The
# rule whose job is to catch an unexamined mint must not itself be defeatable by
# forgetting to `git add`.
#
# Every artifact these gates guard is tracked TODAY, so at five of the six call sites the
# guard is latent rather than live. That is the argument FOR lifting it here rather than
# leaving it at the one site that was measured: the failure is silent, it is one `git rm
# --cached` or one new generated file away at each of them, and a guard that exists in one
# script is a guard the next author will not know to copy.
#
# Usage, after the caller has cd'd to the repository root:
#
#   . scripts/lib/generated-artifact.sh
#   require_tracked "<gate name>" path [path ...] || fail=1   # gates that COLLECT failures
#   require_tracked "<gate name>" path [path ...]             # gates under `set -e`: aborts
#
# Both call shapes are used. A gate that accumulates a `fail` variable wants the `|| fail=1`
# form; a gate that runs a bare `git diff --exit-code` under `set -e` wants the bare form,
# where the non-zero return aborts the script exactly as the diff itself would.

# Refuse a generated artifact that git does not track. Returns 0 when every path is
# tracked, 1 otherwise, naming each offender.
require_tracked() {
  local gate="$1"
  shift
  local path
  local untracked=0
  for path in "$@"; do
    if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
      echo "${gate}: '${path}' is a GENERATED artifact that git does not track, so the"
      echo "  freshness diff below compares it against nothing and would report clean for"
      echo "  any content at all. git add it."
      untracked=1
    fi
  done
  return "$untracked"
}
