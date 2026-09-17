#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# NO SYNCHRONOUS CROSS-REGION CALL ON ANY REQUEST PATH (issue #155 criterion 3).
#
#     scripts/no-cross-region-sync.sh
#
# Criterion 3 is the issue's one HARD ARCHITECTURAL RULE: "No synchronous cross-region DB call may
# exist on any request path; enforce with an architectural test or lint on the storage layer."
#
# # Why this exists BEFORE the code it constrains
#
# Multi-region replication is not built. A lint written afterwards is fitted to whatever was
# already written, and by then the shape it was supposed to forbid is the shape that exists: the
# rule becomes a description. Written first, it is a constraint the replication work has to be
# designed around, which is what the issue asks for and why it lands in the exploratory phase.
#
# A GATE OVER ZERO VIOLATIONS IS NOT AUTOMATICALLY VACUOUS, but it is worth proving rather than
# asserting. Both rules below hold today and both FAIL against a planted violation.
#
# # What this is, and what it is not
#
# It is a TEXT SCAN, and a text scan over Rust is evadable by an author who wants to evade it.
# Four evasions were found and closed before this landed -- production code after a test module,
# a bodyless `#[cfg(test)] mod x;`, a `#[cfg(test)]` item nested in an `impl`, and a deref
# assignment whose leading `*` read as a comment -- and the fourth is the one worth remembering,
# because `rustfmt` PRESERVES that shape, so `cargo fmt` would not have disturbed it.
#
# So the honest claim is narrow: this catches the shapes a cross-region call would ACCIDENTALLY
# take while the replication work is designed, which is what the exploratory phase needs. It is
# not a security boundary against a determined author, and a reviewer who finds a fifth evasion
# should close it here rather than conclude the rule does not hold.
#
# # What a cross-region synchronous call would require
#
# Reaching another region's database needs one of exactly two things, and this forbids both.
#
# RULE 1: A SECOND CONNECTION. A serving crate would have to open its own pool. Today every
# `Store::connect` and every `PgPool`/`PgPoolOptions` construction in production source lives in
# the binary's boot path; the serving crates receive a `Store` and never build one. A request path
# that dialled a regional DSN would have to break that, and this sees it.
#
# RULE 2: ROUTING BY REGION. Failing a second pool, the code would have to choose a target using
# the residency attributes. `home_region` and the per-environment region pin are RECORDED
# attributes: the management plane validates and stores them, and nothing reads them to decide
# where a query goes. A request path consulting them to route is the other shape this forbids.
#
# What it deliberately does NOT forbid is the management plane validating or returning those
# attributes, which is what #46 landed and what the tenant API is for.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)" || {
    echo "::error::no-cross-region-sync: not inside a git repository" >&2
    exit 1
}
cd "$ROOT" || exit 1

# THE SERVING CRATES: every crate that handles a request. The binary is excluded because it IS
# the boot path, and `ironauth-store` because it owns the pool type this rule is about.
# EVERY CRATE THAT IS NOT THE BOOT PATH OR THE STORAGE LAYER, enumerated rather than sampled. The
# first version listed seven by hand and missed most of the workspace, including crates squarely
# on a request path. Excluded, each for a stated reason:
#   ironauth         -- IS the boot path; opening the pool is its job
#   ironauth-store   -- owns the pool type this rule is about
#   ironauth-config  -- parses the region set an operator configures, by design
#   ironauth-env     -- the clock and entropy seam, no request surface
#   ironauth-admin-ui -- static assets
SERVING_CRATES=()
for dir in crates/*/; do
    crate="$(basename "$dir")"
    case "$crate" in
        ironauth | ironauth-store | ironauth-config | ironauth-env | ironauth-admin-ui) continue ;;
    esac
    [ -d "$dir/src" ] && SERVING_CRATES+=("$crate")
done

status=0

# Production source only. A test opening its own pool is a test harness, and `#[cfg(test)]`
# modules live in the same files as the code they cover, so the scan strips them rather than
# skipping whole files -- which would blind it to the production half of any file with tests.
production_source() {
    crate="$1"
    find "crates/$crate/src" -name '*.rs' 2>/dev/null | while read -r file; do
        python3 - "$file" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read().split("\n")
# Drop each `#[cfg(test)]` item, and ONLY that item.
#
# THREE EVASIONS FOUND THIS LOGIC IN SUCCESSION, which is why it is fussier than it looks and why
# each shape is named rather than summarised.
#
#   1. Truncating from the first attribute to end of file hid production code appended AFTER a
#      test module. The comment excusing it claimed a mid-file test module "would only make the
#      scan STRICTER" -- the opposite of true.
#   2. Skipping to the next `}` at COLUMN ZERO is right for `mod tests { ... }` and wrong for
#      `#[cfg(test)] mod testpki;`, a file-module declaration ending in a semicolon, which
#      `ironauth-webauthn` has. With no brace to find, the skip ran to end of file and
#      reproduced (1).
#   3. Skipping to a column-zero brace also over-runs a `#[cfg(test)]` item NESTED in an `impl`,
#      whose own close is indented. That blanked 133 live lines of `claims_request.rs`, and a
#      violation planted inside them passed.
#
# So the close must match the ATTRIBUTE'S OWN INDENTATION, which rustfmt guarantees and which
# needs no brace counting (and so cannot be fooled by a brace inside a string literal).
kept = []
index = 0
while index < len(text):
    line = text[index]
    attribute = re.match(r'^(\s*)#\[cfg\(test\)\]\s*$', line)
    if not attribute:
        kept.append(line)
        index += 1
        continue
    # Blank lines replace skipped ones so reported line numbers stay true.
    indent = attribute.group(1)
    kept.append("")
    index += 1
    if index < len(text) and text[index].rstrip().endswith(";"):
        kept.append("")
        index += 1
        continue
    closer = indent + "}"
    while index < len(text):
        kept.append("")
        closing = text[index] == closer
        index += 1
        if closing:
            break
text = kept
in_block_comment = False
for number, line in enumerate(text, 1):
    # FULL-LINE COMMENTS ARE NOT CODE, and this scan was bitten by treating prose as a violation:
    # its first run flagged a comment in `ironauth-scim` reading "The pool `Store::connect`
    # builds", a sentence ABOUT the rule rather than a breach of it -- the same defect
    # `query-audit.sh` hit on a doc comment saying "per-table grants".
    #
    # A LEADING `*` IS A DEREF ASSIGNMENT, NOT A COMMENT, and treating it as one was a hole a
    # review walked through: `*slot = sqlx::postgres::PgPoolOptions::new()` evaded every rule, and
    # rustfmt PRESERVES that shape, so `cargo fmt` would not have disturbed it. Block comments are
    # tracked with a state machine instead, so a continuation line is only skipped when a `/*` is
    # genuinely open.
    #
    # Only whole-line comments are dropped, never the tail of a code line: blanking from `//`
    # would also truncate any line carrying a `postgres://` URL, and a violation after one on the
    # same line would become invisible.
    if in_block_comment:
        if "*/" in line:
            in_block_comment = False
        continue
    stripped = line.lstrip()
    if stripped.startswith("/*"):
        if "*/" not in stripped[2:]:
            in_block_comment = True
        continue
    if stripped.startswith("//"):
        continue
    print(f"{path}:{number}:{line}")
PY
    done
}

# RULE 1: no serving crate opens a database connection.
for crate in "${SERVING_CRATES[@]}"; do
    [ -d "crates/$crate/src" ] || continue
    hits="$(production_source "$crate" \
        | grep -nE 'Store::connect|PgPool::connect|PgPoolOptions' \
        | grep -v 'no-cross-region-allow' || true)"
    if [ -n "$hits" ]; then
        echo "::error::no-cross-region-sync: a serving crate opens its own database connection:" >&2
        printf '%s\n' "$hits" | sed 's/^/  /' >&2
        status=1
    fi
done

# RULE 2: no serving crate outside the management plane reads a residency attribute.
#
# THE ENVIRONMENT PIN'S COLUMN IS `region`, not `region_pin`. The first version of this scan
# matched only `home_region`, so it missed the per-environment pin entirely -- and that pin is the
# WRITE-AUTHORITY UNIT the issue names, the more important of the two attributes.
#
# Matched as `.region` (a field access) rather than as a bare word, because routing looks like
# reading a field off a tenant or environment, while a bare `region` also matches a claim named
# "region" in a mapping fixture. A string literal is not a routing decision.
#
# `ironauth-admin` is exempt BY NAME and not by accident: the tenant API validates `home_region`
# against the operator's configured region set and returns it, which is the feature #46 landed.
# The exemption is the management plane, not "anywhere it happens to appear".
for crate in "${SERVING_CRATES[@]}"; do
    [ "$crate" = "ironauth-admin" ] && continue
    [ -d "crates/$crate/src" ] || continue
    hits="$(production_source "$crate" \
        | grep -nE 'home_region|\.region\b|region_pin|pinned_region' \
        | grep -v 'no-cross-region-allow' || true)"
    if [ -n "$hits" ]; then
        echo "::error::no-cross-region-sync: a request path reads a residency attribute:" >&2
        printf '%s\n' "$hits" | sed 's/^/  /' >&2
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    echo >&2
    echo "Cross-region flows must be ASYNCHRONOUS (issue #155). A request path may not open a" >&2
    echo "second connection, nor route by a residency attribute. Replication belongs on the" >&2
    echo "outbox stream, which is applied by a follower rather than read across a region." >&2
    echo "If a line is genuinely neither, mark it 'no-cross-region-allow: <reason>'." >&2
    exit 1
fi

echo "no-cross-region-sync: clean (${#SERVING_CRATES[@]} serving crates open no connection and route by no region)"
