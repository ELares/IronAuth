#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Every token-minting entry point consults the access rules (issue #154 criterion 4).
#
# The rules engine's first attempt at gating issuance (PR #1309) was written at the GRANT
# handlers, and a review found six of the seven ungated. The gate now sits at the mints
# instead, because the seven handlers funnel into three of them -- but "three" is a fact about
# today's tree, and the failure mode of a fourth appearing is silent: a new grant mints tokens
# nothing refuses, and every test of the other three still passes.
#
# So this counts the doors. `crates/ironauth-oidc/src/tokens.rs` is the only module that signs
# a token, and every `fn mint*` in it either
#
#   * calls `issuance_refusal` (it is a door), or
#   * carries the marker `issuance-gate-allow: <reason>` on its `fn` line (it is not).
#
# THE MARKER IS READ FROM THE DOC COMMENT IMMEDIATELY ABOVE THE `fn`, and nowhere else.
#
# Not from the `fn` line, which is where it was written first and where it does not survive:
# `cargo fmt` moves a trailing comment off a multi-line signature onto the first body line, so
# every marker silently stopped counting the moment the file was formatted.
#
# And not from the body either, which is what the second attempt did and what a review took
# apart. That version accepted a marker in the first COMMENT anywhere in the body rather than
# the first line, so one buried a hundred lines down exempted a door; and when a body carried
# no comment at all it absorbed the NEXT item's doc comment, so a marker written for the
# function below exempted the ungated one above it. Both fail OPEN. One position, read from a
# buffer that is cleared by any line that is not a comment or an attribute, has neither
# failure, and it is the position the reason belongs in anyway.
#
# WHAT IS NOT A DOOR, and why the marker exists rather than a hard rule: `mint_refresh_token`
# mints an opaque successor to a grant that was already approved and gated at its own issuance,
# and the internal helpers (`mint_at_jwt`, `mint_opaque_access`) are the format arms BELOW a
# door that has already checked. Gating those would either double-charge the check or refuse a
# rotation for a rule written after the grant, which is a different policy question.
#
# THIS IS A TEXT SCAN over Rust and an author who wants to evade it can. What it catches is the
# shape a new mint would ACCIDENTALLY take: added beside its siblings, named like them, and
# forgotten.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

TOKENS="crates/ironauth-oidc/src/tokens.rs"
GATE="issuance_refusal"
MARKER="issuance-gate-allow:"
fail=0

if [ ! -f "$TOKENS" ]; then
    echo "issuance-gate: $TOKENS is missing; this scan is pinned to the module that signs tokens"
    exit 1
fi

# The gate has to EXIST, or every door below would pass by calling nothing.
if ! grep -q "fn ${GATE}(" "$TOKENS"; then
    echo "issuance-gate: ${GATE} is not defined in $TOKENS."
    echo "  Every check below is against a function that no longer exists, so this scan would"
    echo "  pass while nothing is gated."
    exit 1
fi

# Every `fn mint*` in the module, with its line number. `awk` walks the file once and reports
# the body of each, so a door is judged by what it CALLS rather than by what sits near it.
# THE DOOR PATTERN, kept in ONE place because the count below is checked against it.
#
# Deliberately wider than the shapes present today: `async`, any `pub(...)` visibility, a
# generic parameter list, and a digit or capital in the name all count. The first version
# matched `^(pub )?(pub\(crate\) )?fn mint[a-z_]*\(` and a review pointed out that
# `pub async fn mint_device_bound_token(` -- the natural next shape in a module that already
# has `pub(crate) async fn` in it -- was not a door at all: the scan skipped it silently and
# still printed "clean", because the pre-existing doors kept the count non-zero.
#
# NO ESCAPED PARENTHESES, deliberately. The first version wrote the visibility as
# `pub(\([a-z:]+\))?` and passed it to awk through `-v`, which processes escape sequences in
# an assignment: awk received `pub(([a-z:]+))?`, where the parens are GROUPS rather than
# literals, so `pub(super) fn mint_widget` stopped being a door. The count cross-check below
# caught it, which is what it is for -- but `pub[^[:space:]]*` needs no escaping at all and
# cannot be mangled in transit.
DOOR_RE='^[[:space:]]*(pub[^[:space:]]*[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+mint'

doors=$(awk -v gate="$GATE" -v marker="$MARKER" -v door_re="$DOOR_RE" '
    # The comment or attribute block immediately above an item. Any other line clears it, so a
    # block can only ever be credited to the item it actually precedes.
    /^[[:space:]]*(\/\/|#\[)/ {
        preceding = preceding $0 "\n"
        next
    }
    $0 ~ door_re {
        if (name != "") { emit() }
        name = $0
        sub(/^.*fn[[:space:]]+/, "", name)
        sub(/[<(].*$/, "", name)
        line = NR
        marked = (index(preceding, marker) > 0)
        preceding = ""
        gated = 0
        next
    }
    # A new top-level item ends the previous body.
    /^(pub[^ ]* )?(async )?(fn|struct|enum|impl|trait|const|static|mod) / {
        if (name != "") { emit(); name = "" }
        preceding = ""
        next
    }
    {
        preceding = ""
        if (name != "" && index($0, gate "(") > 0) { gated = 1 }
    }
    END { if (name != "") { emit() } }
    function emit() {
        printf "%s\t%d\t%d\t%d\n", name, line, gated, marked
    }
' "$TOKENS")

if [ -z "$doors" ]; then
    echo "issuance-gate: no mint function found in $TOKENS."
    echo "  Either the module was renamed or the pattern stopped matching; a scan that finds"
    echo "  nothing to check is not a passing scan."
    exit 1
fi

# THE COUNT IS CHECKED AGAINST A SECOND, DUMBER READING OF THE SAME FILE.
#
# The awk above is the only thing that decides what a door IS, so a pattern that quietly stops
# matching one shape removes a door and leaves every remaining one passing -- the failure is
# invisible because the output still says "clean". `grep -c` over the same expression is not an
# independent implementation, but it is an independent PASS: if the two disagree, the awk's
# state machine dropped something it matched (a door inside a block it treated as another
# item's body, say), and that is exactly the case a reader would never notice.
found=$(printf '%s\n' "$doors" | grep -c . || true)
lines=$(grep -cE "$DOOR_RE" "$TOKENS" || true)
if [ "$found" -ne "$lines" ]; then
    echo "issuance-gate: the scan reports ${found} mint entry points and the file has ${lines}"
    echo "  lines matching the same pattern. One of them is wrong, and the direction that"
    echo "  matters is a door the state machine dropped: it would be ungated and unreported."
    exit 1
fi

checked=0
while IFS=$'\t' read -r name line gated marked; do
    [ -n "$name" ] || continue
    checked=$((checked + 1))
    if [ "$gated" = "1" ] || [ "$marked" = "1" ]; then
        continue
    fi
    echo "issuance-gate: ${TOKENS}:${line} \`${name}\` mints tokens and does not consult the"
    echo "  access rules. Call ${GATE} in it, or put"
    echo "  \`${MARKER} <why this is not an issuance decision>\` in its DOC COMMENT."
    fail=1
done <<< "$doors"

if [ "$fail" -ne 0 ]; then
    echo
    echo "Issue #154 criterion 4 asks that one rule set gate every OIDC token issuance. A mint"
    echo "that skips the check is a door the policy does not cover, and nothing else notices."
    exit 1
fi
echo "issuance-gate: clean (${checked} mint entry points, each gated or marked)"
