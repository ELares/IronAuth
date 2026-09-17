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
# asserting. Both rules below hold today and both FAIL against a planted violation; the PR that
# added this demonstrates each.
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
SERVING_CRATES=(
    ironauth-oidc
    ironauth-server
    ironauth-admin
    ironauth-scim
    ironauth-saml
    ironauth-quota
    ironauth-hot
)

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
# Drop from a `#[cfg(test)]` module header to the end of file. Test modules are conventionally
# last in this codebase; a mid-file one would only make the scan STRICTER, never blinder.
for index, line in enumerate(text):
    if re.match(r'^\s*#\[cfg\(test\)\]\s*$', line):
        text = text[:index]
        break
for number, line in enumerate(text, 1):
    # FULL-LINE COMMENTS ARE NOT CODE, and this scan has already been bitten by treating prose as
    # a violation: its first run flagged a comment in `ironauth-scim` reading "The pool
    # `Store::connect` builds", which is a sentence ABOUT the rule rather than a breach of it.
    # That is the same defect `query-audit.sh` hit on a doc comment saying "per-table grants".
    #
    # Only whole-line comments are dropped, not the tail of a code line: blanking from `//` would
    # also truncate any line containing a `postgres://` URL, and a violation sitting after one on
    # the same line would then be invisible. A trailing comment cannot hide a call this way.
    if re.match(r'^\s*(//|/\*|\*)', line):
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
# `ironauth-admin` is exempt BY NAME and not by accident: the tenant API validates `home_region`
# against the operator's configured region set and returns it, which is the feature #46 landed.
# The exemption is the management plane, not "anywhere it happens to appear".
for crate in "${SERVING_CRATES[@]}"; do
    [ "$crate" = "ironauth-admin" ] && continue
    [ -d "crates/$crate/src" ] || continue
    hits="$(production_source "$crate" \
        | grep -nE 'home_region|region_pin|pinned_region' \
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
