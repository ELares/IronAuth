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

# `require_tracked`: the shared guard both registry rules below need before they trust a
# `git diff --exit-code`. See that file for the hole and the measurement.
# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

fail=0
allow_report=""

scan() {
  local rule="$1" pattern="$2" allow_ceiling="$3"
  local matched hits allows
  matched=$(grep -rn --include='*.rs' -E "$pattern" crates fuzz \
    | grep -v '^crates/ironauth-env/' || true)
  hits=$(printf '%s\n' "$matched" | grep -v "invariant-allow: ${rule}" | grep -v '^$' || true)
  if [ -n "$hits" ]; then
    echo "invariant-lints: rule '${rule}' violated:"
    echo "$hits"
    fail=1
  fi
  # The exemption CEILING. Every `invariant-allow` marker silently removes a line from this
  # rule's scrutiny, so an unbounded number of them retires the rule one call site at a time
  # and the run still prints clean. This is the mirror of the FLOORS in test-registration.sh
  # and scoped-table-registration.sh: those stop a check shrinking, this stops one being
  # bypassed. RAISE it in the same change that adds a justified exemption and say why, exactly
  # as those scripts require for lowering; a raise is then a reviewable line in the diff rather
  # than a silent grep -v.
  allows=$(printf '%s\n' "$matched" | grep -c "invariant-allow: ${rule}" || true)
  if [ "$allows" -gt "$allow_ceiling" ]; then
    echo "invariant-lints: rule '${rule}' carries ${allows} exemptions, ceiling is ${allow_ceiling}."
    echo "  An exemption retires a call site from this rule. Justify the new one and raise the"
    echo "  ceiling in the same change, or remove it."
    printf '%s\n' "$matched" | grep "invariant-allow: ${rule}"
    fail=1
  fi
  allow_report="${allow_report}  ${rule}: ${allows}/${allow_ceiling} exemptions\n"
}

scan time-via-env 'SystemTime::now|Instant::now' 2
# The `rand::` guard requires a non-identifier char (or start of line) before `rand`
# so a real `rand` crate path is caught while an identifier that merely ENDS in "rand"
# (for example a `Brand::` associated call) is not a false positive.
scan entropy-via-env 'getrandom::|(^|[^A-Za-z0-9_])rand::|rand_core::' 1
scan typ-via-declaration '(\.|::)\s*with_typ\s*\(' 11

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
require_tracked "invariant-lints: rule 'session-mint-registry' violated" "$mint_inventory" || fail=1
if ! git diff --exit-code "$mint_inventory" >/dev/null 2>&1; then
  echo "invariant-lints: rule 'session-mint-registry' violated: ${mint_inventory} is stale"
  echo "  (a call to interaction::establish_session was added, moved, or removed)."
  echo "  It has been regenerated; review it, name the file in ${mint_doc}, and commit both."
  git --no-pager diff -- "$mint_inventory" || true
  fail=1
fi
# The doc check greps the FULL PATH, not the basename. A basename grep degrades this rule
# to count-only for any new file whose basename is already listed: measured (issue #241) by
# creating a second `token.rs` under a subdirectory, which fired the inventory diff and
# then passed the doc check unexamined because `token.rs` was already named. The doc table
# therefore carries full paths too.
while IFS=$'\t' read -r _count path; do
  case "${_count}" in ''|'#'*) continue ;; esac
  if ! grep -qF -- "$path" "$mint_doc"; then
    echo "invariant-lints: rule 'session-mint-registry' violated: '${path}' mints a primary"
    echo "  session but is not named in ${mint_doc}."
    fail=1
  fi
done < "$mint_inventory"

# Rule user-token-mint-registry: every call site of the five `crate::tokens` functions that
#   mint an OAuth/OIDC token artifact is pinned in docs/design/user-bound-mint-sites.txt and
#   given a lifecycle verdict in docs/design/USER-BOUND-MINT-SITES.md.
#
#   The gap this closes: issue #52 established that a blocked, disabled, or deleted user
#   obtains NO new tokens by ANY path, and then TWO user-bound mint paths (jwt-bearer's
#   mapped principal, the legacy device grant) sat outside it for four milestones, written
#   down in an issue rather than enforced. Issue #241 fenced them and found a THIRD nobody
#   had written down at all (the legacy `session_ref IS NULL` code exchange). A count is
#   what would have surfaced all three: none of them was hidden, each was simply never
#   enumerated against the invariant.
#
#   Same shape as session-mint-registry, and deliberately so: generate from source, diff the
#   committed copy, then require every path in the inventory to be named in the prose doc.
#   Like that rule this is a COUNT, not a proof of correctness. What it guarantees is that a
#   new token mint cannot ship without its author writing down whose lifecycle governs it.
# Longest alternative first, so an engine that takes the FIRST matching alternative rather
# than the longest one still reaches `mint_refresh_token` before it settles for `mint`.
mint_names='mint_client_credentials_access_token|mint_refresh_token|mint_access_token|mint_id_token|mint'
# The qualification is load-bearing: `mint(` unqualified matches prose ("the mint (issue
# #279)") and unrelated methods (`pow_gate`'s token bucket, `recovery_proof`'s pure helper),
# so the inventory counts `tokens::<name>(` only. That is exact TODAY because every mint
# caller imports `crate::tokens::{self, ..}` and calls through the module, and this rule
# keeps it exact by refusing the spellings that would evade the count: importing a mint
# function by bare name, and ALIASING THE MODULE so the call no longer reads `tokens::`.
#
# Read the pattern as two arms over `use <path>tokens`:
#
#   `::` <anything ending in a non-word char>? <mint name> <non-word char or end of line>
#     catches `use crate::tokens::mint_refresh_token;` (bare),
#     `use crate::tokens::{mint_refresh_token};` (braced),
#     `use crate::tokens::{self, mint};` (mixed), and
#     `use crate::tokens::mint as m;` (renamed).
#   <space> `as` <space>
#     catches `use crate::tokens as t;`, after which `t::mint(..)` is a mint the
#     `tokens::<name>(` inventory count cannot see.
#
# The leading `([A-Za-z0-9_]+::)*` accepts any module path ending in `tokens` rather than
# `crate::` alone, because `use super::tokens::mint;` from a submodule is the same hole and
# that spelling is idiomatic in this tree (flow/golden.rs already writes
# `use super::consent::..`), and because `pub use tokens::mint;` in lib.rs would re-export
# a mint under a crate-root name the count never sees.
#
# WHAT WAS WRONG BEFORE, measured: the previous spelling put the `(^|[^A-Za-z0-9_])`
# separator AFTER the literal `crate::tokens::`, so it required a non-word character that
# the BRACED form supplies and the BARE form does not.
# `use crate::tokens::mint_refresh_token;` evaded it; `use crate::tokens::{mint_refresh_token};`
# was caught. Worse, whether it evaded depended on the grep implementation, so a hand-run
# grep and this gate could disagree about the same line.
#
# RESIDUAL, recorded because the doc states what this rule buys: grep is LINE based, so a
# `use` statement rustfmt has split across lines (it does past 100 columns, which a list of
# these five names exceeds) puts the imported names on continuation lines carrying no
# `use ... tokens`, and this rule does not see them. docs/design/USER-BOUND-MINT-SITES.md
# lists that limit beside the other two.
scan user-token-mint-qualified "use[[:space:]]+([A-Za-z0-9_]+::)*tokens(::([^;]*[^A-Za-z0-9_])?(${mint_names})([^A-Za-z0-9_]|$)|[[:space:]]+as[[:space:]])" 0

token_inventory="docs/design/user-bound-mint-sites.txt"
token_doc="docs/design/USER-BOUND-MINT-SITES.md"
python3 - "crates/ironauth-oidc/src" "$token_inventory" <<'PY'
import pathlib, re, sys

src, out = pathlib.Path(sys.argv[1]), sys.argv[2]
names = [
    "mint",
    "mint_access_token",
    "mint_id_token",
    "mint_refresh_token",
    "mint_client_credentials_access_token",
]
# A CALL through the module path. The definitions live in tokens.rs and are written
# `pub fn <name>(`, which carries no `tokens::` qualifier and so cannot match.
call = re.compile(r"\btokens::(" + "|".join(sorted(names, key=len, reverse=True)) + r")\s*\(")
counts = {}
for path in sorted(src.rglob("*.rs")):
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if call.search(line):
            n += 1
    if n:
        counts[path.as_posix()] = n

header = (
    "# User-bound token mint sites (generated)\n"
    "#\n"
    "# Generated by scripts/invariant-lints.sh (rule user-token-mint-registry) from every\n"
    "# call to a crate::tokens mint function under crates/ironauth-oidc/src; do not edit by\n"
    "# hand. Every path here MUST be named, with the principal it mints for and the\n"
    "# lifecycle fence that governs it, in docs/design/USER-BOUND-MINT-SITES.md, so a new\n"
    "# token mint cannot ship without an answer to 'whose account can revoke this token'.\n"
    "#\n"
    "# <count>\\t<path>\n"
)
body = "".join(f"{count}\t{path}\n" for path, count in sorted(counts.items()))
open(out, "w", encoding="utf-8").write(header + body)
PY
# The diff below compares the regenerated inventory against the INDEX, so an inventory
# git does not track produces an empty diff and the rule silently passes on every input.
# Measured: with the file untracked, adding a second mint call to a file already listed
# left the lint clean. The rule that catches an unexamined mint must not itself be
# defeatable by forgetting to `git add`, so being untracked is a violation in its own
# right rather than a quiet no-op. The guard is shared with every other freshness gate in
# scripts/ (see scripts/lib/generated-artifact.sh), because the shape is identical at all
# of them and a guard living in one script is one the next author will not know to copy.
require_tracked "invariant-lints: rule 'user-token-mint-registry' violated" "$token_inventory" || fail=1
if ! git diff --exit-code "$token_inventory" >/dev/null 2>&1; then
  echo "invariant-lints: rule 'user-token-mint-registry' violated: ${token_inventory} is stale"
  echo "  (a call to a crate::tokens mint function was added, moved, or removed)."
  echo "  It has been regenerated; review it, name the file in ${token_doc}, and commit both."
  git --no-pager diff -- "$token_inventory" || true
  fail=1
fi
# FULL PATH, not basename, for the reason recorded on the session-mint rule above: a
# basename grep lets a NEW mint file whose basename collides with one already named pass
# the doc check unexamined, which degrades this rule to a bare count for exactly the file
# an author is least likely to have thought about.
while IFS=$'\t' read -r _count path; do
  case "${_count}" in ''|'#'*) continue ;; esac
  if ! grep -qF -- "$path" "$token_doc"; then
    echo "invariant-lints: rule 'user-token-mint-registry' violated: '${path}' mints a token"
    echo "  but is not named in ${token_doc}."
    fail=1
  fi
done < "$token_inventory"

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "invariant-lints: clean"
# Report the exemption budget on every run. A ceiling that is never shown is a ceiling
# nobody notices approaching: the point is that a reviewer sees 11/11 before the twelfth
# exemption is written, not after the run fails. This is the counterpart to the counts
# the registration scripts already print in their own clean lines.
printf "%b" "$allow_report"
