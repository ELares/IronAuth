#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Structural invariants that ordinary compiler lints cannot express, enforced
# as grep rules over the workspace. Each rule names the invariant it guards.
# An exceptional call site may carry the marker "invariant-allow: <rule>" on
# the same line together with a written reason; use sparingly.
#
# SCOPE: `scan` walks every Rust tree in the repository, crates/ and the
#   top-level fuzz/, minus crates/ironauth-env/ (which IS the seam the time and
#   entropy rules funnel everything through, so it is the one place the raw calls
#   belong). fuzz/ is walked because it is Rust that links the same crates, not
#   because it violates anything today; a rule that stopped at crates/ would be
#   one `cargo fuzz add` away from a blind spot. packages/ is deliberately out:
#   it is the TypeScript SPA and none of these rules can apply to it. A NEW Rust
#   tree must be added to the walk here at the same time it is added to the
#   workspace.
#
# Rule time-via-env: all wall-clock and monotonic time flows through
#   crates/ironauth-env (Clock trait). No raw SystemTime::now or Instant::now
#   anywhere else, so protocol logic stays deterministic under test.
# Rule entropy-via-env: all randomness flows through crates/ironauth-env
#   (Entropy trait). No direct getrandom or rand usage anywhere else, so
#   identifier and nonce generation stays deterministic under test.
# Rule typ-via-declaration: a token's JOSE `typ` media type is stamped from the
#   ironauth-jose TokenTyp declaration (EmissionOptions::with_token_typ), never
#   from a bare string at the mint site. TokenTyp is the SAME declaration the
#   verifier's ExpectedTyp reads, so a profile cannot be minted under one
#   spelling and required under another, and a typo cannot mint a token that
#   nothing will ever accept. Foreign media types (a peer's dictated header) and
#   tests that mint a deliberately wrong typ carry the allow marker and a reason.
#   Both spellings of the call are caught, the method form `.with_typ(` and the
#   UFCS form `EmissionOptions::with_typ(`: the same function reached the second
#   way is the same hole, and a rule that only knew the first would be defeated by
#   a spelling rather than by a decision.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

scan() {
  local rule="$1" pattern="$2"
  local hits
  hits=$(grep -rn --include='*.rs' -E "$pattern" crates fuzz \
    | grep -v '^crates/ironauth-env/' \
    | grep -v "invariant-allow: ${rule}" || true)
  if [ -n "$hits" ]; then
    echo "invariant-lints: rule '${rule}' violated:"
    echo "$hits"
    fail=1
  fi
}

scan time-via-env 'SystemTime::now|Instant::now'
# The `rand::` guard requires a non-identifier char (or start of line) before `rand`
# so a real `rand` crate path is caught while an identifier that merely ENDS in "rand"
# (for example a `Brand::` associated call) is not a false positive.
scan entropy-via-env 'getrandom::|(^|[^A-Za-z0-9_])rand::|rand_core::'
scan typ-via-declaration '(\.|::)\s*with_typ\s*\('

# Rule session-mint-registry: every call site of `interaction::establish_session`, the ONE
#   function that mints a primary session (and carries the issue #80/#52 account-lifecycle
#   fence), is pinned in docs/design/session-mint-sites.txt and justified in
#   docs/design/SESSION-MINT-SITES.md.
#
#   The gap this closes: issue #267's `factor_downgrade::GatedSessionPath` is a STRUCTURAL
#   registry with eight sweeps behind it, but it is deliberately narrow (it fences only the
#   WEAK POSSESSION factors), so a new session-minting surface that is not one of those gets
#   neither a sweep nor a compiler error. Issue #295 added exactly such a surface. This is a
#   COUNT, not a proof: what it guarantees is that a new mint site cannot be added silently,
#   because the author has to regenerate the inventory and write down what mints there.
#
#   The shape mirrors scripts/rfc9700-scan.sh: generate from source, diff the committed copy,
#   then require every path in the generated inventory to be named in the prose doc.
mint_inventory="docs/design/session-mint-sites.txt"
mint_doc="docs/design/SESSION-MINT-SITES.md"
python3 - "crates/ironauth-oidc/src" "$mint_inventory" <<'PY'
import pathlib, re, sys

src, out = pathlib.Path(sys.argv[1]), sys.argv[2]
# A CALL to establish_session. The definition (`pub async fn establish_session(`) is not a
# call and is excluded by name; the private `establish_session_page(` wrapper does not match
# this pattern at all, because the paren follows `_page`.
call = re.compile(r"\bestablish_session\s*\(")
counts = {}
for path in sorted(src.rglob("*.rs")):
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if "fn establish_session" in line:
            continue
        if call.search(line):
            n += 1
    if n:
        counts[path.as_posix()] = n

header = (
    "# Primary-session mint sites (generated)\n"
    "#\n"
    "# Generated by scripts/invariant-lints.sh (rule session-mint-registry) from every call\n"
    "# to interaction::establish_session under crates/ironauth-oidc/src; do not edit by hand.\n"
    "# Every path here MUST be named, with the gate that governs it, in\n"
    "# docs/design/SESSION-MINT-SITES.md, so a new primary-session mint cannot ship\n"
    "# unexamined just because it is not one of the weak possession factors issue #267's\n"
    "# GatedSessionPath registry fences.\n"
    "#\n"
    "# <count>\\t<path>\n"
)
body = "".join(f"{count}\t{path}\n" for path, count in sorted(counts.items()))
open(out, "w", encoding="utf-8").write(header + body)
PY
if ! git diff --exit-code "$mint_inventory" >/dev/null 2>&1; then
  echo "invariant-lints: rule 'session-mint-registry' violated: ${mint_inventory} is stale"
  echo "  (a call to interaction::establish_session was added, moved, or removed)."
  echo "  It has been regenerated; review it, name the file in ${mint_doc}, and commit both."
  git --no-pager diff -- "$mint_inventory" || true
  fail=1
fi
while IFS=$'\t' read -r _count path; do
  case "${_count}" in ''|'#'*) continue ;; esac
  if ! grep -qF -- "$(basename "$path")" "$mint_doc"; then
    echo "invariant-lints: rule 'session-mint-registry' violated: '${path}' mints a primary"
    echo "  session but is not named in ${mint_doc}."
    fail=1
  fi
done < "$mint_inventory"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "invariant-lints: clean"
