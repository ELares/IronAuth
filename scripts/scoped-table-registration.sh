#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Scoped table registration (issue #446, the same defect as the migration
# registry).
#
# `scripts/query-audit.sh` keeps a hand-written `SCOPED_TABLES` alternation and
# greps it against every crate source, so SQL naming a scoped table outside the
# repository module fails the build. That list is the only thing the lint knows
# about: a table added by a migration and never added to the list is simply never
# grepped for, so raw SQL against it from any crate passes silently, which is the
# isolation bypass query-audit exists to prevent.
#
# Two places asserted the obligation in prose and nothing enforced it: the header
# of query-audit.sh ("CHECKLIST for a new tenant-scoped table ... (b) add the name
# here") and the module doc of crates/ironauth-store/src/migrate.rs. This is that
# enforcement, in BOTH directions:
#
#   - every table the migrations put under FORCE ROW LEVEL SECURITY must be in
#     SCOPED_TABLES;
#   - every name in SCOPED_TABLES must either be such a table or be one of the
#     documented exceptions below.
#
# The source of truth is the migrations directory, enumerated rather than listed,
# for the reason scripts/fuzz-matrix-freshness.sh gives about its own walk: a file
# at an unexpected path would otherwise be invisible to the check that exists to
# catch exactly that omission. The walk is RECURSIVE, so a migration in a
# subdirectory is seen here; `only_sql_files_live_in_the_migrations_directory` in
# migrate.rs is the check that says such a file is not in the shipped chain at all.
#
# What the derivation tolerates, because a check that only sees one spelling of a
# statement is a check an author defeats by accident (each of these was probed and
# each used to return clean):
#
#   - a statement wrapped across lines, which the tree already writes for ALTER
#     TABLE ... ADD COLUMN, so it is not a hypothetical spelling;
#   - a schema-qualified name (`ALTER TABLE public.x FORCE ...`);
#   - ENABLE without FORCE, which is the shape that MATTERS: row-level security a
#     table owner can bypass, on a table that is then in neither the derived set
#     nor SCOPED_TABLES, which is exactly the isolation bypass described above.
#     Every table with row-level security ENABLED must also have it FORCED.
#
# What it does not tolerate is its own scope shrinking: FORCED_FLOOR below fails
# the run if the derived set gets smaller, so a pattern that quietly stops matching
# cannot report clean.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Names in SCOPED_TABLES that are deliberately NOT forced-RLS tables. Each is
# documented at length in the query-audit.sh header; the reasons are summarized
# here so this list is readable on its own. Checked in both directions: an
# exception that becomes a real forced-RLS table, or that disappears from
# SCOPED_TABLES, fails.
#
#   idempotency_keys      CREDENTIAL-scoped, not row-level-security scoped: an
#                         operator-plane POST is looked up for a replay before any
#                         tenant exists (0003). Still repository-module only.
#   environment_guardrails  a definer VIEW, not a table, so it has no row-level
#                         security of its own; it is listed to keep its SQL out of
#                         every other file.
#
# These two are the whole list. Running this check for the first time turned up no
# third case: every other name in SCOPED_TABLES is a table a migration forces
# row-level security on, and every such table is in SCOPED_TABLES.
exceptions=(
  "idempotency_keys"
  "environment_guardrails"
)

python3 - "${exceptions[@]}" <<'PY'
import glob
import re
import sys

exceptions = set(sys.argv[1:])

# The size of the derived set today. Raise it when tables are added; LOWER it only
# in the change that deliberately drops one. Its job is to make a pattern that
# stops matching fail loudly instead of reporting a smaller clean run.
FORCED_FLOOR = 117


def statements(text):
    """SQL statements, comments removed and whitespace flattened.

    Line comments are stripped QUOTE-AWARE, so a `--` inside a string literal does
    not truncate the statement around it, and a commented-out ALTER TABLE does not
    count as one. Flattening is what lets the patterns below see a statement the
    author wrapped across lines, which the tree already does for ALTER TABLE ...
    ADD COLUMN.
    """
    out = []
    for line in text.split("\n"):
        quote = None
        cut = len(line)
        i = 0
        while i < len(line):
            c = line[i]
            if quote is not None:
                if c == quote:
                    quote = None
            elif c in "'\"":
                quote = c
            elif c == "-" and line.startswith("--", i):
                cut = i
                break
            i += 1
        out.append(line[:cut])
    return [re.sub(r"\s+", " ", s).strip() for s in " \n".join(out).split(";")]


# 1. The source of truth: every table the shipped migrations put row-level security
#    on. FORCE is what the migration safety obligation names and what makes the
#    policy inescapable even for the table owner; ENABLE alone is collected too, so
#    that the gap between the two can be refused rather than ignored.
#
#    The optional `schema.` qualifier is stripped: `public.clients` and `clients`
#    are the same table, and SCOPED_TABLES holds the bare name.
FORCE_RE = re.compile(
    r"^ALTER\s+TABLE\s+(?:(?:IF\s+EXISTS|ONLY)\s+)*"
    r"(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)\s+FORCE\s+ROW\s+LEVEL\s+SECURITY$",
    re.IGNORECASE,
)
ENABLE_RE = re.compile(
    r"^ALTER\s+TABLE\s+(?:(?:IF\s+EXISTS|ONLY)\s+)*"
    r"(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY$",
    re.IGNORECASE,
)

forced = set()
enabled = set()
for path in sorted(glob.glob("crates/ironauth-store/migrations/**/*.sql", recursive=True)):
    with open(path, encoding="utf-8") as fh:
        for statement in statements(fh.read()):
            m = FORCE_RE.match(statement)
            if m:
                forced.add(m.group(1).lower())
            m = ENABLE_RE.match(statement)
            if m:
                enabled.add(m.group(1).lower())

if not forced:
    sys.exit(
        "scoped-table-registration: found NO forced row-level-security table in the\n"
        "migrations. The pattern this check greps for must have changed; fix the\n"
        "pattern rather than deleting the check, or it reports green while proving\n"
        "nothing."
    )

# 2. The registered list, read out of the lint that consumes it.
audit = open("scripts/query-audit.sh", encoding="utf-8").read()
m = re.search(r"^SCOPED_TABLES='([^']*)'", audit, re.MULTILINE)
if m is None:
    sys.exit(
        "scoped-table-registration: could not find the SCOPED_TABLES assignment in\n"
        "scripts/query-audit.sh. If it was renamed, update this check; do not leave\n"
        "the registration unenforced."
    )
registered = [t for t in m.group(1).split("|") if t]
if len(registered) != len(set(registered)):
    dupes = sorted({t for t in registered if registered.count(t) > 1})
    sys.exit(f"scoped-table-registration: SCOPED_TABLES lists duplicates: {dupes}")
registered = set(registered)

problems = []

if len(forced) < FORCED_FLOOR:
    problems.append(
        f"derived only {len(forced)} forced row-level-security tables, and at least\n"
        f"{FORCED_FLOOR} are expected. A statement spelling has stopped matching, so this\n"
        "check is now looking at a SMALLER set than it was and would not notice a table\n"
        "missing from SCOPED_TABLES. Fix the pattern; lower FORCED_FLOOR only in the\n"
        "change that deliberately removes a table."
    )

enabled_not_forced = sorted(enabled - forced)
if enabled_not_forced:
    problems.append(
        "these tables have row-level security ENABLED but never FORCED, so the table\n"
        "owner bypasses every isolation policy on them, and because this check derives\n"
        "its set from FORCE they are also invisible to the SCOPED_TABLES comparison\n"
        f"below: {enabled_not_forced}. Add FORCE ROW LEVEL SECURITY in a new migration."
    )

missing = sorted(forced - registered)
if missing:
    problems.append(
        "these tables are FORCE ROW LEVEL SECURITY in a migration but are absent from\n"
        "SCOPED_TABLES in scripts/query-audit.sh, so raw SQL against them anywhere in\n"
        f"the workspace is never flagged: {missing}"
    )

extra = sorted(registered - forced - exceptions)
if extra:
    problems.append(
        "these names are in SCOPED_TABLES but are not a forced row-level-security\n"
        "table in any migration. Either the table was dropped and the entry is stale,\n"
        "or the migration forgot to FORCE row-level security on it, which is the more\n"
        f"serious reading: {extra}"
    )

stale_exceptions = sorted(exceptions - registered)
if stale_exceptions:
    problems.append(
        "these documented exceptions are no longer in SCOPED_TABLES, so the exception\n"
        f"list in this script is stale: {stale_exceptions}"
    )

promoted = sorted(exceptions & forced)
if promoted:
    problems.append(
        "these are listed here as exceptions to the forced row-level-security rule but\n"
        "a migration now forces row-level security on them; drop them from the\n"
        f"exception list so they are checked normally: {promoted}"
    )

if problems:
    print("scoped-table-registration: FAILED")
    for problem in problems:
        print("  " + problem.replace("\n", "\n  "))
    sys.exit(1)

print(
    f"scoped-table-registration: clean ({len(forced)} forced row-level-security tables, "
    f"{len(enabled)} with it enabled, {len(registered)} registered, "
    f"{len(exceptions)} documented exceptions)"
)
PY
