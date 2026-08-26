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
  sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' <<'ALLOWLIST'
# untraced; see #774
ironauth-oidc/mds3_sync

# issue #113: the pre-token hook's contract, deliberately landed before either transport
# that binds to it (#113's HTTP dispatch and #114's WASM one), so neither inherits the
# other's shape. The seam it needs is recorded on #113: `tokens::mint` signs the ID token
# before `mint_access` builds its claims, so no point today holds both unsigned.
ironauth-store/token_customize

# issue #113: both halves of the reserved-claim fence, the declarative one an operator
# configures and the one a hook's returned claims pass through. Callerless for the same
# reason as token_customize above: the mint seam that would call it is #113's remaining
# work, and landing the fence first means the seam cannot be written without one.
ironauth-oidc/claims_mapping
ALLOWLIST
}

allow() {
  allowlist_entries | grep -qxF "$1"
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

  # `|| true` on the whole pipeline, not just the first grep: under `set -o pipefail` a
  # no-match grep exits 1 and kills the pipeline, which would make this script exit
  # silently on the FIRST module nobody references. That is the failure mode where a gate
  # reports nothing and looks like it passed.
  refs="$( { grep -rn --include='*.rs' -e "${module}::" crates/ 2>/dev/null \
    | grep -v "/${module}\.rs:" | wc -l; } || true )"
  refs="$(echo "$refs" | tr -d ' ')"
  [ -n "$refs" ] || refs=0
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
  entry_module="${entry#*/}"
  entry_refs="$( { grep -rn --include='*.rs' -e "${entry_module}::" crates/ 2>/dev/null \
    | grep -v "/${entry_module}\.rs:" | wc -l; } || true )"
  entry_refs="$(echo "$entry_refs" | tr -d ' ')"
  [ -n "$entry_refs" ] || entry_refs=0
  if [ "$entry_refs" -gt 0 ]; then
    echo "dormant-module-scan: allowlist entry $entry is STALE: $entry_refs callers." >&2
    echo "  It is wired now. Remove the line rather than leaving a claim nobody rechecks." >&2
    stale=$((stale + 1))
  fi
done <<EOF
$(allowlist_entries)
EOF

if [ "$violations" -gt 0 ] || [ "$stale" -gt 0 ]; then
  exit 1
fi
echo "dormant-module-scan: clean ($checked modules with a public surface, all reachable or allowlisted)"
