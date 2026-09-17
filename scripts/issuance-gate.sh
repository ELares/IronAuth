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
# The marker is read from the FIRST LINE of the body, or from the doc comment immediately above
# the `fn`. Not from anywhere in the body: a marker buried a hundred lines down exempts a door
# nobody reading the signature would know was exempt, and a comment mentioning the string in
# passing would do it by accident.
#
# Not from the `fn` line either, which is where this was written first and where it does not
# survive: `cargo fmt` moves a trailing comment off a multi-line signature and onto the first
# body line, so every marker silently stopped counting the moment the file was formatted. The
# accepted positions are the two rustfmt leaves alone.
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
doors=$(awk -v gate="$GATE" -v marker="$MARKER" '
    # The doc comment or attribute block immediately above an item, kept so the marker can
    # live where `cargo fmt` will not move it.
    /^[[:space:]]*(\/\/|#\[)/ {
        if (name == "") { preceding = preceding $0 "\n" }
        else if (body_lines == 0) { first_body = first_body $0 "\n"; body_lines = 1 }
        else if (name != "" && index($0, gate "(") > 0) { gated = 1 }
        next
    }
    # A mint definition at top level: `fn mint...(` or `pub fn mint...(`, column zero.
    /^(pub )?(pub\(crate\) )?fn mint[a-z_]*\(/ {
        if (name != "") { emit() }
        name = $0
        sub(/^.*fn /, "", name)
        sub(/\(.*$/, "", name)
        line = NR
        marked = (index(preceding, marker) > 0)
        preceding = ""
        first_body = ""
        body_lines = 0
        gated = 0
        next
    }
    # A new top-level item ends the previous body.
    /^(pub )?(pub\(crate\) )?(fn|struct|enum|impl|trait|const|static|mod) / {
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
        if (index(first_body, marker) > 0) { marked = 1 }
        printf "%s\t%d\t%d\t%d\n", name, line, gated, marked
    }
' "$TOKENS")

if [ -z "$doors" ]; then
    echo "issuance-gate: no mint function found in $TOKENS."
    echo "  Either the module was renamed or the pattern stopped matching; a scan that finds"
    echo "  nothing to check is not a passing scan."
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
    echo "  access rules. Call ${GATE} in it, or mark the \`fn\` line"
    echo "  \`${MARKER} <why this is not an issuance decision>\`."
    fail=1
done <<< "$doors"

if [ "$fail" -ne 0 ]; then
    echo
    echo "Issue #154 criterion 4 asks that one rule set gate every OIDC token issuance. A mint"
    echo "that skips the check is a door the policy does not cover, and nothing else notices."
    exit 1
fi
echo "issuance-gate: clean (${checked} mint entry points, each gated or marked)"
