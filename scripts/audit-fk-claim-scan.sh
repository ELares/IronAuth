#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Audit foreign key claim scan (issue #404).
#
# `audit_log` (migration 0002) carries exactly TWO foreign keys, to `tenants` and
# to `environments`, and nothing anywhere references `audit_log`. `target_id` is a
# single polymorphic `text` column naming the target of every Action variant, so a
# foreign key from it to a data table is not merely absent, it is unaddable: a
# column can reference only one table, and nineteen hard DELETE statements in
# repository.rs run inside an audited write closure, thirteen of them deleting the
# very row the audit row names.
#
# The idiom this scan bans is the ADJECTIVAL form: "the audit foreign key", "the
# audit_log foreign key", "the audit log's foreign key". It names no table, so it
# reads as an assertion that a foreign key protects whatever row the sentence is
# about, and it was written across the tree about tables that have no such
# constraint. Retention of a soft-deleted row is an APPLICATION rule.
#
# Say instead either:
#   - "the foreign key from `audit_log` to `environments`" (name the table), or
#   - "this audit row's target stays resolvable" plus why nothing enforces it.
#
# The correction lives in the doc on `Action` in crates/ironauth-store/src/audit.rs
# and in the header of migration 0092.
#
# WHAT THIS SCAN DOES NOT SEE, stated rather than implied. It reads LINE comment
# paragraphs (`//`, `///`, `//!`, `--`, `#`) and, in markdown, prose paragraphs. It
# does not read `/* ... */` block comments, string literals, or gitignored paths.
# The first two are deliberate holes an author could walk through; they are left
# open because the tree writes neither for prose of this kind, and the cost of
# closing them is a parser that has to know each language's lexer. The third is
# deliberate: an ignored file is not shipped.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Shipped migrations are checksummed: migrate.rs digests the whole file, so
# editing one (including its comments) makes every deployed database refuse to
# boot with ChecksumMismatch. These NINE files carry ELEVEN occurrences of the
# idiom between them (0027 carries three, the rest one each) and CANNOT be
# corrected in place. They are frozen, not forgiven, and the correction for them
# lives on `Action`.
#
# Checked in BOTH directions and by COUNT: a NEW migration that repeats the idiom
# fails, an entry that stops matching fails, and the total staying at exactly
# FROZEN_OCCURRENCES means an edit that ADDS an occurrence to a file already on
# this list fails too, which a per-file membership test would wave through.
frozen=(
  "crates/ironauth-store/migrations/0003_management_api.sql"
  "crates/ironauth-store/migrations/0027_resource_model_apis.sql"
  "crates/ironauth-store/migrations/0084_org_membership.sql"
  "crates/ironauth-store/migrations/0086_org_roles.sql"
  "crates/ironauth-store/migrations/0087_org_groups.sql"
  "crates/ironauth-store/migrations/0088_org_group_members.sql"
  "crates/ironauth-store/migrations/0089_org_role_assignments.sql"
  "crates/ironauth-store/migrations/0090_org_auth_policies.sql"
  "crates/ironauth-store/migrations/0091_permissions.sql"
)
frozen_occurrences=11

# This file states the idiom in order to ban it, so it exempts itself.
self="scripts/audit-fk-claim-scan.sh"

# `${frozen[*]}` on an empty array is an unbound-variable abort under bash 3.2,
# which ships as /bin/bash on macOS. Fail-closed but baffling, so spell the
# default; the emptiness itself is caught below, with a message that says so.
#
# Tracked files AND untracked-but-not-ignored ones. A migration written but not yet
# `git add`ed is exactly when an author most wants to be told, and a check that only
# looks at the index would pass on it (measured: it did).
git ls-files -z --cached --others --exclude-standard \
  | FROZEN="${frozen[*]:-}" SELF="$self" EXPECTED="$frozen_occurrences" python3 -c '
import os
import re
import sys

# The adjectival idiom, tolerant of a line break and a comment marker between
# words (a doc comment wraps mid phrase) and of backticks around audit_log.
IDIOM = re.compile(
    r"`?\baudit(?:_log|\s+log)?\b`?(?:.s)?\s+foreign\s+keys?\b", re.IGNORECASE
)
MARKER = re.compile(r"^\s*(///!?|//!|///|//|--|#)\s?")

# Anything that is not prose. Everything else is read, rather than an allowlist of
# extensions: the previous allowlist meant a .py, a .rb, a .go, a Dockerfile or an
# extensionless script could carry the idiom unseen, and the point of the scan is
# that the claim is false wherever it is written.
BINARY_EXT = {
    "png", "jpg", "jpeg", "gif", "ico", "webp", "pdf", "zip", "gz", "tgz", "bz2",
    "xz", "zst", "woff", "woff2", "ttf", "otf", "eot", "wasm", "so", "dylib", "dll",
    "a", "o", "rlib", "bin", "jar", "class", "mp4", "mov", "mp3", "wav",
}
MAX_BYTES = 8 * 1024 * 1024

frozen = set(os.environ["FROZEN"].split())
me = os.environ["SELF"]
expected = int(os.environ["EXPECTED"])

def flatten(text):
    """Yield (line_number, flattened_paragraph) for every run of consecutive line
    comments sharing a marker, so an idiom split over a line break is one string.

    Deliberately NOT sensitive to indentation. Requiring every line of a paragraph
    to share the first line s indent meant a continuation line indented differently
    started a fresh paragraph, and an idiom straddling that break was invisible
    (measured, issue #404 review). Over-joining two adjacent comment blocks is the
    safe direction for a scan whose only job is to find a phrase."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        m = MARKER.match(lines[i])
        if not m:
            i += 1
            continue
        prefix = m.group(1)
        j, body = i, []
        while j < len(lines):
            m2 = MARKER.match(lines[j])
            if not m2 or m2.group(1) != prefix:
                break
            rest = lines[j][m2.end():]
            if rest.strip() == "":
                break
            body.append(rest.strip())
            j += 1
        if body:
            yield i + 1, " ".join(body)
        i = max(j, i + 1)

def flatten_md(text):
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        if lines[i].strip() == "":
            i += 1
            continue
        j = i
        while j < len(lines) and lines[j].strip() != "":
            j += 1
        yield i + 1, " ".join(l.strip() for l in lines[i:j])
        i = j

paths = [p.decode() for p in sys.stdin.buffer.read().split(b"\x00") if p]
if not paths:
    sys.exit(
        "audit-fk-claim-scan: git listed no files, so this scan read nothing.\n"
        "A scan over an empty file set reports clean while proving nothing."
    )

offenders = []
frozen_hits = {}
scanned = 0
for path in paths:
    if path == me:
        continue
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if ext in BINARY_EXT:
        continue
    try:
        if os.path.getsize(path) > MAX_BYTES:
            continue
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        continue
    scanned += 1
    walker = flatten_md if ext == "md" else flatten
    for lineno, para in walker(text):
        for hit in IDIOM.finditer(para):
            if path in frozen:
                frozen_hits[path] = frozen_hits.get(path, 0) + 1
                continue
            offenders.append((path, lineno, hit.group(0), para[max(0, hit.start() - 70):hit.end() + 70]))

failed = False
if not frozen:
    failed = True
    print("audit-fk-claim-scan: the frozen list is EMPTY. It is not supposed to be:")
    print("nine shipped migrations carry the idiom and cannot be edited. An empty")
    print("list means the array or its expansion broke, not that the tree is clean.")

if offenders:
    failed = True
    print("audit-fk-claim-scan: the adjectival audit foreign key idiom asserts a")
    print("constraint that does not exist. Name the table the foreign key really")
    print("references (`tenants` or `environments`), or say the retention is an")
    print("application rule. See the doc on Action in ironauth-store/src/audit.rs.")
    for path, lineno, phrase, ctx in offenders:
        print(f"  {path}:{lineno}: {phrase!r} in ...{ctx}...")

stale = frozen - set(frozen_hits)
if stale:
    failed = True
    print("audit-fk-claim-scan: these files are listed as FROZEN carriers of the")
    print("idiom but no longer contain it. Either a shipped migration was edited")
    print("(which breaks its checksum) or the list is stale; remove the entry.")
    for path in sorted(stale):
        print(f"  {path}")

total_frozen = sum(frozen_hits.values())
if total_frozen != expected:
    failed = True
    print(f"audit-fk-claim-scan: the frozen migrations carry {total_frozen} occurrences")
    print(f"of the idiom, not the {expected} this scan is pinned to. A shipped migration")
    print("gained or lost one, which means either its checksum is now broken or the")
    print("pinned count in this script is wrong. Per file:")
    for path in sorted(frozen_hits):
        print(f"  {frozen_hits[path]}  {path}")

if failed:
    sys.exit(1)
print(
    f"audit-fk-claim-scan: clean ({scanned} files read, {total_frozen} occurrences "
    f"in {len(frozen_hits)} frozen migrations, 0 elsewhere)"
)
'
