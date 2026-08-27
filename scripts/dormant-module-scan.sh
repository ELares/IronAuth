#!/usr/bin/env bash
# Fail when a module's public surface has NO caller anywhere (issue #774).
#
# The defect this catches has shipped five times: a pure, sans-IO decision core is written
# first, unit-tested thoroughly, and merged. It looks finished in review because it IS
# finished as a unit. The tests call its functions directly, so they pass and prove the
# logic while proving nothing about whether anything calls it. The issue reads as advanced
# and the feature does not exist. `prm.rs` had five public functions and a complete RFC
# 9728 implementation that no request could reach.
#
# DETECTION is by qualified path (`mod::` and `use ...::mod::`), not by item name. Item
# names give false positives on common identifiers: `token_exchange_decision` scores 139
# hits by name and zero by path, because `decide`-shaped words appear everywhere.
#
# The ALLOWLIST is the half that makes this usable. A check with no escape hatch for a
# deliberate seam gets disabled the first time it is wrong. With one, "nothing calls this
# yet" becomes a claim someone writes down in the diff that adds it, rather than something
# discovered a milestone later.
set -euo pipefail

cd "$(dirname "$0")/.."

# Modules that are deliberately callerless, each with the reason. Adding a line here is a
# statement; leaving one stale is the thing review should catch -- and, as of this change, the
# thing the script itself catches. Two of the five entries that used to live here were stale:
# `cimd` had 17 callers and `message_feedback` had 3, both wired long ago, and the scan said
# nothing because a module with callers never reaches the allowlist at all. An allowlist that
# only ever grows is a list of claims nobody rechecks.
#
# One entry per line, `crate/module`, with the reason in the comment above it.
# Comment lines and blanks are stripped, so each entry can carry its reason next to it.
allowlist_entries() {
  sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d' <<'ALLOWLIST'
# untraced; see #774
ironauth-oidc/mds3_sync

# `ironauth-store/token_customize` was allowlisted here as a contract landed before either
# transport bound to it. #1005 bound one: `token_hook::PAYLOAD_VERSION` is now an alias of
# `TOKEN_CUSTOMIZE_VERSION`, so the module has a real caller and the entry went INERT --
# which this scan refuses, because an exemption nobody rechecks is a claim nobody rechecks.
# Removed rather than reworded. That is the scan doing its job: it noticed the day the
# reason stopped being true, and it failed at the FIRST step of the lane, so nothing after
# it ran.

ALLOWLIST
}

allow() {
  allowlist_entries | grep -qxF "$1"
}

# How many places refer to a module, by name.
#
# ONE function, called by both loops below, so the two cannot drift into disagreeing about
# what a reference is. That matters more than it looks: the main loop treats "zero refs" as
# dormant and the staleness loop treats "more than zero" as an entry doing nothing, and those
# are exact complements only while both count the same way. Two copies of this pipeline would
# be a review obligation; one function is a structural guarantee.
#
# `|| true` wraps the WHOLE pipeline, not just the first grep: under `set -o pipefail` a
# no-match grep exits 1 and kills the pipeline, which would make this script exit silently on
# the FIRST module nobody references. That is the failure mode where a gate reports nothing
# and looks like it passed.
#
# A rustdoc link counts, as does a mention in a test. That is deliberate and long-standing:
# this scan asks "does anything in the tree name this module", not "is it on a request path",
# and narrowing it to call sites would need a parser rather than a grep.
#
# Guest workspaces are excluded, and this is a CONSISTENCY fix rather than a narrowing. The main
# loop globs `crates/*/src/*.rs`, which never matches `crates/<crate>/guests/*/src/lib.rs`, so a
# guest fixture is not a module this scan can flag -- but the reference count was recursive over
# `crates/`, so those same files counted as callers. One half of the scan could see them and the
# other could not. They are separate cargo workspaces compiled to another target and they link
# into nothing here.
#
# ANCHORED to `crates/<crate>/guests/`, not a bare `/guests/` substring. Unanchored, a future
# host module at `crates/<crate>/src/guests/handler.rs` -- exactly the wiring the allowlist
# entries are waiting on -- would have its references swallowed and the entry would read as
# callerless forever.
refs_for() {
  count="$( { grep -rn --include='*.rs' -e "${1}::" crates/ 2>/dev/null \
    | grep -v "/${1}\.rs:" \
    | grep -vE '^crates/[^/]+/guests/' | wc -l; } || true )"
  count="$(echo "$count" | tr -d ' ')"
  [ -n "$count" ] || count=0
  echo "$count"
}

# A module with a smaller surface than this is a helper, not a feature, and flagging every
# two-function utility would bury the signal this exists to surface.
min_public_items=3

violations=0
checked=0
for file in crates/*/src/*.rs; do
  module="$(basename "$file" .rs)"
  crate="$(basename "$(dirname "$(dirname "$file")")")"
  case "$module" in
    lib | main | mod) continue ;;
  esac

  public_items="$(grep -cE '^pub (fn|struct|enum|trait|async fn|const)' "$file" || true)"
  [ "$public_items" -ge "$min_public_items" ] || continue
  checked=$((checked + 1))

  refs="$(refs_for "$module")"
  [ "$refs" -eq 0 ] || continue

  if allow "$crate/$module"; then
    echo "dormant-module-scan: $crate/$module is callerless (allowlisted)"
    continue
  fi
  echo "dormant-module-scan: $crate/$module has $public_items public items and NO caller." >&2
  echo "  Wire it, or add it to the allowlist in this script with the reason." >&2
  violations=$((violations + 1))
done

# An allowlist entry is a claim that a module has no caller TODAY. Once it acquires one the
# entry is a stale statement about the tree, and the loop above can never notice: it skips a
# module with callers before the allowlist is ever consulted. So check the entries directly.
stale=0
while read -r entry; do
  [ -n "$entry" ] || continue
  entry_crate="${entry%%/*}"
  entry_module="${entry#*/}"

  # A nested path can never be flagged in either direction: the main loop globs
  # crates/*/src/*.rs so it never sees one, and a Rust path has no `/`, so `refs_for` on
  # `flow/consent` matches nothing and the entry reads as permanently callerless. Rejected
  # rather than tolerated, because the format comment above already calls it invalid.
  case "$entry_module" in
    */*)
      echo "dormant-module-scan: allowlist entry $entry is not crate/module." >&2
      echo "  The scan only sees crates/<crate>/src/<module>.rs; a nested path can never" >&2
      echo "  be flagged, so an entry for one is unfalsifiable. Remove it." >&2
      stale=$((stale + 1))
      continue
      ;;
  esac

  # An entry naming a module that is gone is stale in the other direction, and nothing caught
  # it: renaming a file leaves the allowlist asserting something about a path that does not
  # exist, and the scan stays green forever because the loop above never sees the module
  # either. This also catches a mistyped crate half, which nothing checked at all.
  #
  # Both layouts count as existing. `foo/mod.rs` is a real module the tree already uses, and
  # calling it missing would print a false statement and ask the author to delete a still-valid
  # claim.
  entry_file="crates/${entry_crate}/src/${entry_module}.rs"
  if [ ! -f "$entry_file" ]; then
    if [ -f "crates/${entry_crate}/src/${entry_module}/mod.rs" ]; then
      entry_file="crates/${entry_crate}/src/${entry_module}/mod.rs"
    else
      echo "dormant-module-scan: allowlist entry $entry names no module:" >&2
      echo "  $entry_file does not exist. Remove or fix the line." >&2
      stale=$((stale + 1))
      continue
    fi
  fi

  # The main loop skips a module for TWO reasons, and until now this checked only one. A
  # module under the public-surface floor is skipped before the allowlist is ever consulted, so
  # its entry decides nothing -- and shrinking a module's surface, or raising the floor, made
  # every entry below it silently inert while the gate stayed green.
  entry_items="$(grep -cE '^pub (fn|struct|enum|trait|async fn|const)' "$entry_file" || true)"
  entry_items="$(echo "$entry_items" | tr -d ' ')"
  [ -n "$entry_items" ] || entry_items=0
  if [ "$entry_items" -lt "$min_public_items" ]; then
    echo "dormant-module-scan: allowlist entry $entry is INERT: $entry_items public items." >&2
    echo "  The scan skips anything under $min_public_items, so this entry decides nothing." >&2
    echo "  Remove the line rather than leaving a claim nobody rechecks." >&2
    stale=$((stale + 1))
    continue
  fi

  entry_refs="$(refs_for "$entry_module")"
  if [ "$entry_refs" -gt 0 ]; then
    echo "dormant-module-scan: allowlist entry $entry is INERT: $entry_refs references." >&2
    echo "  The scan would not flag this module anyway, so the entry does nothing." >&2
    echo "  Remove the line rather than leaving a claim nobody rechecks." >&2
    stale=$((stale + 1))
  fi
done <<EOF
$(allowlist_entries)
EOF

if [ "$violations" -gt 0 ] || [ "$stale" -gt 0 ]; then
  exit 1
fi
echo "dormant-module-scan: clean ($checked modules with a public surface, all reachable or allowlisted)"
