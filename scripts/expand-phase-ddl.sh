#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# An EXPAND migration may not contain destructive DDL (issue #148 criterion 3).
#
# > Every migration ships as expand-contract; CI rejects a migration whose expand phase
# > contains destructive DDL.
#
# # What expand-contract means, and what this scan does and does not hold
#
# A rolling upgrade runs two binary versions against one database at once. EXPAND and MIGRATE are
# the halves that must be backward compatible: the OLD binary keeps serving while replicas are
# replaced, so neither may take anything away or change the shape of anything that binary reads
# or writes. CONTRACT is not scanned, because running after the old binary is gone is the phase's
# entire purpose.
#
# `Phase::Migrate` is scanned and scanning only expand was the first version's hole. Migrate is
# documented as "backfill: populate the new shape from the old", and a backfill runs BEFORE
# contract, so the old binary is still serving through it. Leaving it out was a one-word escape
# hatch, and including it surfaced a violation nothing had looked at.
#
# # THE SCAN IS NARROWER THAN THE RULE, and the difference is where the next bug is
#
# The rule above is about statements, which is why a scan can hold SOME of it. It holds the eight
# shapes listed below and nothing else. Three classes it does NOT check are present in this tree
# today and are not all harmless:
#
#   DROP INDEX (1 statement)  usually recreated in the same file; an arbiter-inference break if
#                             an ON CONFLICT names it, which none currently does.
#   REVOKE (29 statements     narrows a grant the old binary may still be exercising.
#    across 8 files)          CHECKED, not merely written down: the count below is asserted,
#                             because the first version of this comment carried a hand-written
#                             number that was wrong within one PR of being written.
#   any CHECK widened without DROP CONSTRAINT (an ALTER ... ADD CONSTRAINT alone) -- not a shape
#                             this scan can see at all.
#
# A green run therefore means "none of the eight shapes appeared", not "this migration is safe to
# roll". Saying otherwise would be the kind of sentence a reviewer carries away and a gate cannot
# support.
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
# EIGHTEEN (file, kind) PAIRS ACROSS FIFTEEN MIGRATIONS already on main match these shapes,
# found by running the scan before wiring the gate. Their bytes are frozen -- `migrate.rs`
# digests each file whole, so editing one makes every migrated database refuse to boot -- so they
# are RECORDED and not corrected. The ceiling stops the list growing: a nineteenth needs this
# number raised in the same diff, which is where somebody has to justify it.
#
# A FIRST VERSION OF THIS COMMENT SAID "FIVE MIGRATIONS", which was wrong twice over. Those five
# entries spanned four files, not five; and five was the count for seven shapes while the
# sentence read as the census for the whole rule. Adding DROP CONSTRAINT took it to eighteen.
#
# RECORDED IS NOT THE SAME AS ACCEPTED, and 0057 is why the distinction is written here.
# `0057_registration_abuse_defenses.sql` is declared Expand and widens the `users_state_valid`
# CHECK to admit 'waitlisted'. `UserState::from_wire` answers `None` for a tag it does not know,
# and that `None` is fatal at every read site that ends `.ok_or(StoreError::Encryption)?`. So a
# replica running the previous binary fails every read of a waitlisted user for the length of the
# rollout. It is on this list because its bytes cannot change, NOT because it is safe.
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
# Each line is one (file, kind) pair that predates this gate. The description says what the file
# DOES, read off its statements, not that it is safe: see the note on 0057 above.
ALLOW=$(cat <<'ALLOWED'
0028_envelope_encryption.sql|DROP COLUMN|drops identifier and claims after backfilling their sealed replacements
0028_envelope_encryption.sql|SET NOT NULL|makes four sealed replacement columns mandatory in the same file
0047_step_up_policies.sql|DROP CONSTRAINT|drops and re-adds 1 constraint under the same name
0057_registration_abuse_defenses.sql|DROP CONSTRAINT|WIDENS users_state_valid to admit waitlisted; a pre-0057 binary cannot decode it
0124_membership_principal_arc.sql|DROP NOT NULL|relaxes user_id so a membership can name a non-user principal
0132_backfill_login_index_job_kind.sql|DROP CONSTRAINT|drops and re-adds 1 constraint under the same name
0134_audit_stream_backfill.sql|SET NOT NULL|a Migrate-phase backfill that makes its new column mandatory
0150_scope_fk_naming.sql|DROP CONSTRAINT|drops 2 constraints and does not re-add either under the same name
0156_messages_sending_state.sql|DROP CONSTRAINT|drops and re-adds 1 constraint under the same name
0166_token_hook_component_bound.sql|DROP CONSTRAINT|drops and re-adds 2 constraints under the same names
0181_agent_vault_refresh.sql|DROP CONSTRAINT|drops and re-adds 2 constraints under the same names
0181_agent_vault_refresh.sql|SET NOT NULL|makes action_digest mandatory after a backfill
0201_org_connections_saml_target.sql|DROP NOT NULL|relaxes connector_id so a SAML connection can have no upstream connector
0209_portal_certificate_renewal_intent.sql|DROP CONSTRAINT|drops and re-adds 2 constraints under the same names
0210_portal_contacts_intent.sql|DROP CONSTRAINT|drops and re-adds 2 constraints under the same names
0211_portal_audit_intent.sql|DROP CONSTRAINT|drops and re-adds 2 constraints under the same names
0213_ldap_connector_optional_groups.sql|DROP CONSTRAINT|drops and re-adds 2 constraints under the same names
0222_trusted_device_upstream_compromise.sql|DROP CONSTRAINT|drops and re-adds 1 constraint under the same name
ALLOWED
)
ALLOW_CEILING=18

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
    # `COLUMN` is optional in Postgres, `SET DATA TYPE` is the SQL-standard synonym for `TYPE`,
    # and an identifier may be quoted. The first version pinned `ALTER COLUMN <word> TYPE`, so
    # `ALTER COLUMN v SET DATA TYPE bigint` and `ALTER v TYPE bigint` both walked past it -- and
    # those are the spellings a generator or a standards-minded author reaches for, not
    # obfuscations.
    (r'\bALTER\s+(?:COLUMN\s+)?(?:"[^"]+"|\w+)\s+(?:SET\s+DATA\s+)?TYPE\b', "ALTER COLUMN TYPE"),
    (r"\bSET\s+NOT\s+NULL\b", "SET NOT NULL"),
    (r"\bDROP\s+NOT\s+NULL\b", "DROP NOT NULL"),
    # THE CLASS THIS GATE'S OWN ARGUMENT DEMANDED AND THE FIRST VERSION OMITTED. A CHECK dropped
    # and re-added WIDER admits a value the old binary cannot decode; dropped and re-added
    # NARROWER rejects a value the old binary still writes. Both break the version still running,
    # by exactly the reasoning used above to include DROP NOT NULL. 0057 is the worked example.
    (r"\bDROP\s+CONSTRAINT\b", "DROP CONSTRAINT"),
]

scanned = 0
failures = []
used = set()
for name, phase in sorted(phase_of.items()):
    if phase not in ("Expand", "Migrate"):
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
    print(f"expand-phase-ddl: scanned only {scanned} expand and migrate migrations", file=sys.stderr)
    raise SystemExit(1)

# THE CENSUS OF WHAT THIS GATE DOES NOT SCAN IS ITSELF CHECKED.
#
# The header names three classes the scan cannot hold and gives the population of each, so a
# reader can size the residual gap. A hand-written population rots on the next migration that
# adds one, silently, because prose in a comment is not run -- and this one did rot: it said 27
# one PR after being written, while the tree held 29. Counting it here makes the number a
# measurement rather than a claim, and makes adding a REVOKE a deliberate act.
#
# Raising it is not a defeat. A REVOKE in an expand migration is sometimes exactly right (it is
# how a table-wide grant gets narrowed to the columns a caller writes). The point is that the
# number moves only when someone moves it.
REVOKE_CENSUS = 29
revoke_count = 0
revoke_files = set()
for name, phase in sorted(phase_of.items()):
    if phase not in ("Expand", "Migrate"):
        continue
    path = pathlib.Path(migrations) / name
    if not path.exists():
        continue
    for line in path.read_text().splitlines():
        if line.strip().startswith("--"):
            continue
        if re.search(r"\bREVOKE\b", line.split("--", 1)[0], re.I):
            revoke_count += 1
            revoke_files.add(name)
if revoke_count != REVOKE_CENSUS:
    print(
        f"expand-phase-ddl: the header says this gate does not scan {REVOKE_CENSUS} REVOKE "
        f"statements, and the tree now holds {revoke_count} across {len(revoke_files)} files.\n"
        "  A REVOKE in an expand migration narrows a grant the PREVIOUS binary may still be\n"
        "  exercising, and this gate cannot tell a safe narrowing from an unsafe one. Read the\n"
        "  new statement, satisfy yourself the old binary never uses what it removes, then\n"
        "  update REVOKE_CENSUS and the header count together.",
        file=sys.stderr,
    )
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
    print("expand-phase-ddl: destructive DDL in a migration declared Phase::Expand or Phase::Migrate:", file=sys.stderr)
    for name, number, kind, line in failures:
        print(f"  {name}:{number}  {kind}\n      {line}", file=sys.stderr)
    print(
        "\n  An expand or migrate migration runs while the PREVIOUS binary is still serving. Each\n"
        "  statements above breaks that binary: it selects a column that is gone, writes a row\n"
        "  omitting one that became mandatory, reads a column that became nullable into a field\n"
        "  field that is not.\n"
        "\n"
        "  Move the statement to a CONTRACT migration, which runs after the old binary is gone.",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(
    f"expand-phase-ddl: clean ({scanned} expand and migrate migrations scanned, "
    f"{len(allowed)}/{ceiling} documented exceptions, all still matching)"
)
PY
