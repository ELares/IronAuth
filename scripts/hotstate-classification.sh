#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Every use of the hot-state interface declares what it is allowed to lose (issue #146).
#
# > Ship a per-use classification matrix: safe-to-lose accelerator, lossy-degrades-security
# > (fail open with alerting or fail closed, per config), or correctness-relevant (atomic ops
# > required plus a documented cache-down fallback). Every trait use must declare its class in
# > code; CI rejects unclassified uses.
#
# THE COMPILER ALREADY DOES HALF OF IT. `HotState`'s methods take a `&'static HotUse`, so a call
# with no use does not compile, and `HotUse::declare`'s const assertion refuses a correctness use
# with no fallback. What a compiler cannot do is insist the declaration be somewhere a person can
# read, and that is this script's whole job.
#
# TWO RULES, both checkable and both necessary:
#
#   1. `HotUse::declare` appears ONLY in the registry. A declaration beside its caller satisfies
#      "classified in code" and defeats the matrix: the classification is then spread across
#      however many call sites there are, and nobody has ever seen it at once.
#   2. Every `pub static` in the registry appears in `ALL`. A use the list omits is one the
#      matrix does not show, which is the same defect as not declaring it.
#
# Rule 2 is also a unit test (`registry::tests::every_declared_use_is_listed`). It is here as
# well because the two catch it at different moments: the test fails a `cargo test`, and this
# fails a static lane that runs before anything is compiled.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

registry="crates/ironauth-hot/src/registry.rs"
status=0

# RULE 1. `git ls-files` rather than a find, so an untracked scratch file cannot make this pass
# or fail -- the same reason every other scan in this directory walks tracked files.
while IFS= read -r file; do
    [ "$file" = "$registry" ] && continue
    # The trait's own definition names the type in prose and in signatures; what rule 1 forbids
    # is CONSTRUCTING one, which is the `::declare(` call.
    if grep -n "HotUse::declare(" "$file" >/dev/null 2>&1; then
        echo "hotstate-classification: $file declares a hot-state use outside the registry." >&2
        grep -n "HotUse::declare(" "$file" >&2
        echo "  Move it to $registry so the classification matrix stays readable in one place." >&2
        status=1
    fi
done < <(git ls-files '*.rs')

# RULE 2, from the file rather than from the compiler, so this lane needs no build.
declared="$(grep -c '^pub static [A-Z_]*: HotUse' "$registry" || true)"
listed="$(sed -n '/^pub static ALL/,/^\];/p' "$registry" | grep -c '^    &[A-Z_]*,' || true)"
if [ "$declared" -eq 0 ]; then
    echo "hotstate-classification: parsed zero declarations from $registry." >&2
    echo "  That is a broken parse rather than an empty registry: this check would pass" >&2
    echo "  vacuously, which is the one outcome it must not have." >&2
    exit 1
fi
if [ "$declared" -ne "$listed" ]; then
    echo "hotstate-classification: $registry declares $declared uses and ALL lists $listed." >&2
    echo "  A use missing from ALL is one the classification matrix does not show." >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "hotstate-classification: clean ($declared uses, all declared in the registry and listed)"
fi
exit "$status"
