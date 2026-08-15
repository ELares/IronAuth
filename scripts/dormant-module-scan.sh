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
# statement; leaving one stale is the thing review should catch.
allow() {
  case "$1" in
    # Wiring is the remaining work of the issue that owns each, and #774 tracks them.
    ironauth-oidc/cimd) return 0 ;;                      # issue #128
    ironauth-oidc/mds3_sync) return 0 ;;                 # untraced; see #774
    ironauth-store/message_feedback) return 0 ;;         # issue #111
    *) return 1 ;;
  esac
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

if [ "$violations" -gt 0 ]; then
  exit 1
fi
echo "dormant-module-scan: clean ($checked modules with a public surface, all reachable or allowlisted)"
