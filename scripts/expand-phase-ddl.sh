#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# An EXPAND migration may not contain destructive DDL (issue #148 criterion 3).
#
# > Every migration ships as expand-contract; CI rejects a migration whose expand phase
# > contains destructive DDL.
#
# # What expand-contract means, and why a text scan can enforce this half of it
#
# A rolling upgrade runs two binary versions against one database at once. The EXPAND phase is
# the half that must be backward compatible: the OLD binary keeps running against the new schema
# while replicas are replaced. So an expand migration may ADD -- a table, a column, an index, a
# nullable column with a default -- and may not take anything away or change the shape of
# anything the old binary reads or writes.
#
# That is a property of the STATEMENTS rather than of the data, which is why a scan can hold it.
# What a scan cannot hold is the other half (that the contract phase waits until no old binary
# is running), and this does not claim to.
#
# # The seven statement kinds, each with the version it breaks
#
#   DROP TABLE / DROP COLUMN  the old binary SELECTs it and gets an error
#   TRUNCATE                  the old binary reads rows that are gone
#   RENAME TO / RENAME COLUMN the old binary addresses the former name
#   ALTER COLUMN ... TYPE     the old binary decodes the former type
#   SET NOT NULL              the old binary INSERTs rows omitting the column
#   DROP NOT NULL             the old binary READS the column into a non-nullable field
#
# The last is the one that looks harmless and is not: relaxing a constraint arms every reader
# that already decodes the column as always-present, and those readers are the version still
# running.
#
# # Why there is an allow list, and why it can only shrink
#
# FIVE MIGRATIONS ALREADY ON MAIN VIOLATE THIS, found by writing the scan before writing the
# gate. Their bytes are frozen -- `migrate.rs` digests each file whole, so editing one makes
# every migrated database refuse to boot -- so they cannot be corrected, only recorded. Each is
# listed below with what it does, and the ceiling stops the list growing: a sixth needs this
# number raised in the same diff, which is the moment somebody has to justify it.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MIGRATIONS="crates/ironauth-store/migrations"
REGISTRY="crates/ironauth-store/src/migrate.rs"

# (file, kind) pairs that predate this gate. Each line is one accepted violation.
#
# 0028 is the worst of them and the reason the others are worth recording rather than waved
# through: it DROPs two columns and adds NOT NULL to two more, in one migration declared Expand.
# That is a contract phase wearing an expand label, and a rolling upgrade across it would have
# had the old binary selecting columns that no longer exist.
ALLOW=$(cat <<'ALLOWED'
0028_envelope_encryption.sql|DROP COLUMN|drops identifier and claims after backfilling their sealed replacements
0028_envelope_encryption.sql|SET NOT NULL|makes the sealed replacements mandatory in the same statement
0124_membership_principal_arc.sql|DROP NOT NULL|relaxes user_id so a membership can name a non-user principal
0181_agent_vault_refresh.sql|SET NOT NULL|makes action_digest mandatory after a backfill
0201_org_connections_saml_target.sql|DROP NOT NULL|relaxes connector_id so a SAML connection can have no upstream connector
ALLOWED
)
ALLOW_CEILING=5

python3 - "$MIGRATIONS" "$REGISTRY" "$ALLOW" "$ALLOW_CEILING" <<'PY'
import re, sys, pathlib

migrations, registry, allow_raw, ceiling = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

allowed = set()
allow_lines = [line for line in allow_raw.strip().split("\n") if line.strip()]
for line in allow_lines:
    parts = line.split("|")
    if len(parts) != 3:
        print(f"expand-phase-ddl: malformed allow entry: {line!r}", file=sys.stderr)
        raise SystemExit(1)
    allowed.add((parts[0].strip(), parts[1].strip()))

if len(allowed) != len(allow_lines):
    print("expand-phase-ddl: the allow list has duplicate entries", file=sys.stderr)
    raise SystemExit(1)
if len(allowed) > ceiling:
    print(
        f"expand-phase-ddl: {len(allowed)} allowed violations, ceiling {ceiling}.\n"
        "  Raising it is a decision: an expand migration with destructive DDL cannot be\n"
        "  rolled through, so the upgrade it is part of is not zero-downtime.",
        file=sys.stderr,
    )
    raise SystemExit(1)

# THE PHASE COMES FROM THE REGISTRY, not from the file name or a comment. `migrate.rs` is the
# only place a phase is declared, so a migration cannot escape this by being named differently.
source = pathlib.Path(registry).read_text()
entries = re.findall(r"Migration \{(.*?)\n        \}", source, re.S)
phase_of = {}
for entry in entries:
    name = re.search(r'include_str!\("\.\./migrations/([^"]+)"\)', entry)
    phase = re.search(r"phase: Phase::(\w+)", entry)
    if name and phase:
        phase_of[name.group(1)] = phase.group(1)

if len(phase_of) < 200:
    print(
        f"expand-phase-ddl: parsed {len(phase_of)} migrations from {registry}, which is too few\n"
        "  to be reading the registry. That is a broken parse rather than an empty chain, and\n"
        "  this check would pass vacuously.",
        file=sys.stderr,
    )
    raise SystemExit(1)

DESTRUCTIVE = [
    (r"\bDROP\s+TABLE\b", "DROP TABLE"),
    (r"\bDROP\s+COLUMN\b", "DROP COLUMN"),
    (r"\bTRUNCATE\b", "TRUNCATE"),
    (r"\bRENAME\s+(?:TO|COLUMN)\b", "RENAME"),
    (r"\bALTER\s+COLUMN\s+\w+\s+TYPE\b", "ALTER COLUMN TYPE"),
    (r"\bSET\s+NOT\s+NULL\b", "SET NOT NULL"),
    (r"\bDROP\s+NOT\s+NULL\b", "DROP NOT NULL"),
]

scanned = 0
failures = []
used = set()
for name, phase in sorted(phase_of.items()):
    if phase != "Expand":
        continue
    path = pathlib.Path(migrations) / name
    if not path.exists():
        print(f"expand-phase-ddl: {name} is registered and its file is missing", file=sys.stderr)
        raise SystemExit(1)
    scanned += 1
    # COMMENTS ARE STRIPPED BEFORE MATCHING. Every migration in this tree opens with a long
    # header explaining what it does, and those headers say "DROP COLUMN" and "NOT NULL"
    # constantly. A rule that fired on its own documentation is one somebody turns off.
    for number, line in enumerate(path.read_text().split("\n"), start=1):
        if line.strip().startswith("--"):
            continue
        body = line.split("--", 1)[0]
        for pattern, kind in DESTRUCTIVE:
            if re.search(pattern, body, re.I):
                if (name, kind) in allowed:
                    used.add((name, kind))
                    continue
                failures.append((name, number, kind, line.strip()))

if scanned < 150:
    print(f"expand-phase-ddl: scanned only {scanned} expand migrations", file=sys.stderr)
    raise SystemExit(1)

# AN ALLOW ENTRY THAT MATCHES NOTHING IS A STALE ENTRY, and a stale allow list is how a ceiling
# stops meaning anything: it leaves room nobody is using and nobody notices being spent.
stale = sorted(allowed - used)
if stale:
    print("expand-phase-ddl: these allow entries match nothing and should be deleted:", file=sys.stderr)
    for name, kind in stale:
        print(f"  {name} | {kind}", file=sys.stderr)
    raise SystemExit(1)

if failures:
    print("expand-phase-ddl: destructive DDL in a migration declared Phase::Expand:", file=sys.stderr)
    for name, number, kind, line in failures:
        print(f"  {name}:{number}  {kind}\n      {line}", file=sys.stderr)
    print(
        "\n  An expand migration runs while the PREVIOUS binary is still serving. Each of the\n"
        "  statements above breaks that binary: it selects a column that is gone, writes a row\n"
        "  omitting one that became mandatory, or reads a column that became nullable into a\n"
        "  field that is not.\n"
        "\n"
        "  Move the statement to a CONTRACT migration, which runs after the old binary is gone.",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(
    f"expand-phase-ddl: clean ({scanned} expand migrations scanned, "
    f"{len(allowed)}/{ceiling} documented exceptions, all still matching)"
)
PY
