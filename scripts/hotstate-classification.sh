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
# THE COMPILER ALREADY DOES MOST OF IT, and more than it did in the first version of this file:
#
#   * `HotState`'s methods take a `&'static HotUse`, so a call with no declared use does not
#     compile;
#   * `HotUse::declare` is `pub(crate)`, so NO OTHER CRATE CAN CONSTRUCT ONE AT ALL. Every call
#     site the matrix is about lives in another crate, so for all of them "declared in the
#     registry" is a privacy rule rather than a grep;
#   * `declare`'s const assertion refuses a correctness use with no fallback.
#
# What is left for this script is the part a compiler cannot say: inside `ironauth-hot` itself
# there is no way to express "this function may be called from registry.rs and nowhere else".
#
#   1. `declare` is called ONLY from the registry. A declaration beside its caller satisfies
#      "classified in code" and defeats the matrix: the classification is then spread across
#      however many call sites there are, and nobody has ever seen it at once.
#   2. Every `pub static ...: HotUse` in the registry appears in `ALL`, BY NAME.
#
# # Both rules were defeated by a spelling before they were rewritten, and how
#
# Rule 1 was `grep "HotUse::declare("`. `use HotUse as Cache; Cache::declare(...)` compiles and
# walked straight past it, as did `<HotUse>::declare(`. It now matches the METHOD NAME with any
# receiver, which is the thing that cannot be renamed without renaming the function.
#
# Rule 2 compared two COUNTS. A registry that declared `A` and `B` and listed `A` twice had
# `declared == listed == 2` and passed, while `B` -- the use missing from the matrix, the whole
# defect -- went unreported. It now compares the two NAME SETS, so a mismatch names the use.
# Its identifier pattern was `[A-Z_]*`, which silently skipped any name with a digit in it (an
# `L2_CACHE` was invisible to BOTH counts, so it stayed equal and the gate printed "clean").
#
# # This script may not pass vacuously
#
# Every parse below is checked for having found something before its result is trusted, and a
# missing registry is a hard failure rather than "zero declarations, zero listed, equal, clean".
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

registry="crates/ironauth-hot/src/registry.rs"
crate_src="crates/ironauth-hot/src"
status=0

if [ ! -f "$registry" ]; then
    echo "hotstate-classification: $registry does not exist." >&2
    echo "  A moved or renamed registry must update this gate in the same commit: every rule" >&2
    echo "  below reads that file, and a gate that cannot find its subject reports nothing." >&2
    exit 1
fi

# RULE 1. `git ls-files` rather than a find, so an untracked scratch file cannot make this pass
# or fail -- the same reason every other scan in this directory walks tracked files. (The first
# version of this rule was measured against an UNTRACKED crate and reported a clean sweep of
# nothing at all; see the note in the PR.)
#
# The pattern is the method name with any receiver: `HotUse::declare(`, `<HotUse>::declare(`,
# `Self::declare(` and an aliased `Cache::declare(` all match, and so does a bare `declare(`
# reached through `use HotUse::declare`. The trait's own prose mentions the name in backticks, so
# comment and doc lines are excluded before matching rather than after -- a rule that fired on
# its own documentation would be turned off within a week. The DEFINITION (`fn declare`) is
# excluded too, for the same reason and no other: it is the one site that is not a call.
declare_re='(^|[^A-Za-z0-9_])declare[[:space:]]*\('
while IFS= read -r file; do
    [ "$file" = "$registry" ] && continue
    hits="$(grep -nE "$declare_re" "$file" \
        | grep -vE '^[0-9]+:[[:space:]]*(//|/\*|\*)' \
        | grep -vE '(^|[^A-Za-z0-9_])fn[[:space:]]+declare' || true)"
    if [ -n "$hits" ]; then
        echo "hotstate-classification: $file declares a hot-state use outside the registry." >&2
        echo "$hits" >&2
        echo "  Move it to $registry so the classification matrix stays readable in one place." >&2
        status=1
    fi
done < <(git ls-files "$crate_src/*.rs" "$crate_src/**/*.rs" | sort -u)

# RULE 2, from the file rather than from the compiler, so this lane needs no build.
#
# `[A-Za-z0-9_]` and not `[A-Z_]`: a screaming-snake convention is a convention, and a gate that
# enforces it by NOT SEEING the names that break it is the worst of both.
ident='[A-Za-z_][A-Za-z0-9_]*'
declared="$(grep -oE "^pub static ${ident}: HotUse" "$registry" \
    | sed -E 's/^pub static //; s/: HotUse$//' | sort -u)"
listed="$(sed -n '/^pub static ALL/,/^\];/p' "$registry" \
    | grep -oE "^[[:space:]]+&${ident}," | tr -d ' &,' | sort -u)"

if [ -z "$declared" ]; then
    echo "hotstate-classification: parsed zero declarations from $registry." >&2
    echo "  That is a broken parse rather than an empty registry: every comparison below" >&2
    echo "  would hold trivially, which is the one outcome this check must not have." >&2
    exit 1
fi
if [ -z "$listed" ]; then
    echo "hotstate-classification: parsed an empty ALL from $registry." >&2
    echo "  Either the list is empty or its shape changed; both need a person." >&2
    exit 1
fi

# MEMBERSHIP, BOTH WAYS, by name.
missing="$(comm -23 <(printf '%s\n' "$declared") <(printf '%s\n' "$listed"))"
extra="$(comm -13 <(printf '%s\n' "$declared") <(printf '%s\n' "$listed"))"
if [ -n "$missing" ]; then
    echo "hotstate-classification: declared but absent from ALL:" >&2
    printf '  %s\n' $missing >&2
    echo "  A use missing from ALL is one the classification matrix does not show." >&2
    status=1
fi
if [ -n "$extra" ]; then
    echo "hotstate-classification: listed in ALL but not declared here:" >&2
    printf '  %s\n' $extra >&2
    echo "  ALL is the matrix; an entry with no declaration beside it does not compile, so" >&2
    echo "  this means the declaration moved out of the registry." >&2
    status=1
fi

if [ "$status" -eq 0 ]; then
    count="$(printf '%s\n' "$declared" | wc -l | tr -d ' ')"
    echo "hotstate-classification: clean ($count uses, each declared in the registry and in ALL)"
fi
exit "$status"
