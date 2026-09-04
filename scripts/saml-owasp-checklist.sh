#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The OWASP SAML checklist names REAL tests (issue #138, criterion 6).
#
# `crates/ironauth-saml/tests/owasp_checklist.rs` maps every cheat-sheet item to a test or to a
# written N/A. The rows that name tests are only worth anything if those tests exist, and this
# script is what makes that true.
#
# WHY THIS IS A SHELL SCRIPT AND NOT AN ASSERTION IN THAT FILE.
#
# It was an assertion in that file, twice, and both versions were unsound because a Rust test
# cannot see the test registry: `libtest` exposes no list of the tests linked into a binary. So
# both versions SCANNED THE SOURCE for `fn <name>(`, and a source scan cannot decide what the
# compiler decided.
#
#   * The first scanned a hand-written list of four filenames, and the row it was written for
#     named a test in a fifth file the same commit added. The build was red on arrival.
#   * The second walked the directories and required a `#[test]` attribute within four lines
#     above the function. That attributes a HELPER declared just after a test, and it misses a
#     one-line `#[test] fn foo() {}` entirely, and it descends into `tests/compile-fail/`, whose
#     files are `trybuild` fixtures that are never compiled into any test binary.
#
# `cargo test -- --list` prints exactly the tests the compiler produced, so this has no scanning
# problem to get wrong. The Rust file keeps the checks that ARE structural -- every row has a
# rationale, no two rows share a control, an N/A names an owner -- and gives up the one it could
# never do soundly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

checklist=crates/ironauth-saml/tests/owasp_checklist.rs
[ -f "$checklist" ] || { echo "saml-owasp-checklist: $checklist is missing" >&2; exit 1; }

# The names the checklist claims. Taken from the `Coverage::Tests(&[..])` rows only: a
# NotApplicable or Gap row names no test by design.
named=$(python3 - "$checklist" <<'PY'
import re, sys

source = open(sys.argv[1]).read()
names = []
for block in re.findall(r"Coverage::Tests\(&\[(.*?)\]\)", source, re.S):
    names.extend(re.findall(r'"([A-Za-z0-9_]+)"', block))
if not names:
    print("saml-owasp-checklist: no Coverage::Tests rows found, which cannot be right", file=sys.stderr)
    raise SystemExit(1)
# EXACT COUNTS, IN THE OTHER FILE FROM THE TABLE. A floor with slack is what the previous
# version had -- `len(names) < 20` against 44 actual -- so a row could be cut from four names to
# one, or written in a shape the regex does not match (a hoisted `const` instead of an inline
# `&[..]`, an array closing `] )`), and this script would print "clean" having checked fewer
# names than it did yesterday. `re.findall` does not report what it skipped.
#
# The Rust side asserts the ROW counts and this side asserts the NAME and BLOCK counts, so the
# two halves are no longer blind in opposite directions: a row that stops parsing here changes
# BLOCKS without changing the row count there, and a row losing names changes NAMES.
#
# Both numbers live beside the thing they count, which is the weakest kind of bound. What they
# buy is that a change has to be made deliberately, in two files, with the diff visible.
BLOCKS = 20
NAMES = 53
blocks = re.findall(r"Coverage::Tests\(&\[(.*?)\]\)", source, re.S)
if len(blocks) != BLOCKS:
    print(
        f"saml-owasp-checklist: parsed {len(blocks)} Coverage::Tests blocks, expected {BLOCKS}. "
        "A row was added, removed, or written in a shape the parser does not match.",
        file=sys.stderr,
    )
    raise SystemExit(1)
if len(names) != NAMES:
    print(
        f"saml-owasp-checklist: parsed {len(names)} test names, expected {NAMES}. "
        "A row gained or lost a name.",
        file=sys.stderr,
    )
    raise SystemExit(1)
print("\n".join(sorted(set(names))))
PY
)

# The tests the compiler actually produced.
existing=$(cargo test -p ironauth-saml --features test-util -- --list 2>/dev/null \
  | sed -n 's/^\(.*\): test$/\1/p' \
  | sed 's/.*:://' \
  | sort -u)

if [ -z "$existing" ]; then
  echo "saml-owasp-checklist: cargo test --list produced nothing" >&2
  exit 1
fi

missing=""
while read -r name; do
  [ -z "$name" ] && continue
  printf '%s\n' "$existing" | grep -qx "$name" || missing="$missing $name"
done <<< "$named"

if [ -n "$missing" ]; then
  echo "saml-owasp-checklist: the checklist names tests that do not exist:" >&2
  for name in $missing; do echo "  $name" >&2; done
  exit 1
fi

echo "saml-owasp-checklist: clean ($(printf '%s\n' "$named" | wc -l | tr -d ' ') named tests, all present)"
