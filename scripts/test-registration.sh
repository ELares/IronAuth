#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Test registration (issue #446, the same defect as the migration registry).
#
# Eight crates set `autotests = false` and list every integration test as an
# explicit `[[test]]` entry. With autodiscovery off, a `tests/*.rs` file that has
# no entry is NOT COMPILED and NOT RUN. Nothing said so: `cargo test` reports the
# registered tests passing, the file looks like part of the suite, and its
# assertions never execute. That is the migration-registry failure in a second
# place, and a worse one, because the artifact that vanishes is a test.
#
# Both directions are checked, per crate:
#
#   - every `tests/*.rs` file must have a `[[test]]` entry naming it;
#   - every `[[test]]` entry must have its file, at the `path` it declares.
#
# Crates that leave `autotests` unset keep cargo's autodiscovery and are skipped;
# there the compiler is the check. Directories under `tests/` (shared `common`
# modules, `compile-fail` corpora, fixture trees) are not test binaries and are
# not considered.
#
# A check whose SCOPE can shrink silently has the defect it exists to catch. The
# first version of this script recognised `autotests = false` only at end of line,
# so `autotests = false  # explicit registration below` dropped the crate out of
# the walk entirely: the run then reported "clean (7 crates, 150 registered)"
# with an unregistered dead test file sitting in that crate, exit 0 (measured,
# issue #404 review). Two things follow, and both are below: the comment is
# tolerated, and the FLOORS are asserted, so the number of crates and entries
# examined can never fall without a deliberate edit here.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 - <<'PY'
import glob
import os
import re
import sys

# A narrow hand parser over the manifest, so this check needs no toml library and
# runs in every lane. tomllib (3.11+) is used only as a CROSS CHECK when it is
# importable: a disagreement between the two is itself a failure, because it means
# the narrow parser has stopped seeing what cargo sees.
try:
    import tomllib
except ImportError:
    tomllib = None


def narrow(text):
    """[(name, path)] for each [[test]] table, in declaration order."""
    entries = []
    for block in re.split(r"^\[\[test\]\]\s*$", text, flags=re.MULTILINE)[1:]:
        block = re.split(r"^\[", block, flags=re.MULTILINE)[0]
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        path = re.search(r'^\s*path\s*=\s*"([^"]+)"', block, re.MULTILINE)
        entries.append((name.group(1) if name else None, path.group(1) if path else None))
    return entries


"""The floors. Raise them when a crate or an integration test is legitimately
added; LOWER them only in the same change that deliberately removes one, and say
so in the commit. Their whole job is to make a silent shrink impossible, which is
the failure mode this script exists to catch and which its own first version had:
one tolerated trailing comment took the walk from 8 crates and 214 entries to 7
and 150, and it still printed clean."""
MINIMUM_CRATES = 8
MINIMUM_ENTRIES = 221


def autotests_off_narrow(text):
    # A trailing comment is legal TOML and says nothing about the value. Requiring
    # end of line here is what let `autotests = false  # explicit registration
    # below` remove a whole crate from this check.
    m = re.search(r"^\s*autotests\s*=\s*(true|false)\s*(#.*)?$", text, re.MULTILINE)
    return m is not None and m.group(1) == "false"


def autotests_off_strict(text):
    """tomllib's reading of `[package] autotests`, or None without tomllib."""
    if tomllib is None:
        return None
    return tomllib.loads(text).get("package", {}).get("autotests") is False


problems = []
checked = 0
total_entries = 0

for manifest in sorted(glob.glob("crates/*/Cargo.toml")) + ["Cargo.toml"]:
    crate = os.path.dirname(manifest) or "."
    text = open(manifest, encoding="utf-8").read()
    narrow_off = autotests_off_narrow(text)
    strict_off = autotests_off_strict(text)
    # Cross checked BEFORE the skip, not after. Deciding to skip on the narrow
    # parser alone is how a crate leaves the walk without anything noticing: the
    # tomllib cross check below never ran for it.
    if strict_off is not None and strict_off != narrow_off:
        problems.append(
            f"{manifest}: the narrow autotests parser and tomllib disagree "
            f"({narrow_off} vs {strict_off}). Fix the parser; a check that misreads "
            "the manifest silently drops the crate."
        )
        continue
    if not narrow_off:
        continue
    checked += 1
    entries = narrow(text)

    if tomllib is not None:
        parsed = tomllib.loads(text).get("test", [])
        strict = [(t.get("name"), t.get("path")) for t in parsed]
        if strict != entries:
            problems.append(
                f"{manifest}: the narrow [[test]] parser and tomllib disagree "
                f"({entries} vs {strict}). Fix the parser; a check that misreads the "
                "manifest reports green while proving nothing."
            )
            continue

    nameless = [e for e in entries if e[0] is None]
    if nameless:
        problems.append(f"{manifest}: a [[test]] entry has no name")
        continue
    total_entries += len(entries)

    names = [name for name, _ in entries]
    if len(names) != len(set(names)):
        dupes = sorted({n for n in names if names.count(n) > 1})
        problems.append(f"{manifest}: duplicate [[test]] names {dupes}")

    on_disk = {
        os.path.basename(p)[:-3] for p in glob.glob(f"{crate}/tests/*.rs")
    }
    unregistered = sorted(on_disk - set(names))
    if unregistered:
        problems.append(
            f"{crate}: these integration tests exist on disk but have no [[test]] entry "
            f"in Cargo.toml. autotests is FALSE for this crate, so they are never "
            f"compiled and never run: {unregistered}"
        )

    for name, path in entries:
        declared = path if path is not None else f"tests/{name}.rs"
        if not os.path.isfile(os.path.join(crate, declared)):
            problems.append(
                f"{crate}: [[test]] {name!r} declares path {declared!r}, which does not exist"
            )
        elif path is not None and declared != f"tests/{name}.rs":
            problems.append(
                f"{crate}: [[test]] {name!r} declares path {declared!r}; keep name and "
                "path in the tests/<name>.rs convention so the two cannot drift apart"
            )

if checked < MINIMUM_CRATES:
    problems.append(
        f"this check examined {checked} crates with autotests off, and at least "
        f"{MINIMUM_CRATES} are expected. A crate has dropped out of the walk. Either the "
        "manifest pattern stopped matching it (fix the pattern; do NOT lower the floor), "
        "or the crate genuinely turned autodiscovery back on or was removed, in which "
        "case lower MINIMUM_CRATES in this script deliberately."
    )

if total_entries < MINIMUM_ENTRIES:
    problems.append(
        f"this check examined {total_entries} registered [[test]] entries, and at least "
        f"{MINIMUM_ENTRIES} are expected. Entries have vanished from the walk. A test "
        "binary that stops being examined here is exactly the thing that stops being RUN "
        "without anyone noticing; find out why before lowering MINIMUM_ENTRIES."
    )

if problems:
    print("test-registration: FAILED")
    for problem in problems:
        print(f"  {problem}")
    sys.exit(1)

print(
    f"test-registration: clean ({checked} crates with autotests off, "
    f"{total_entries} registered integration tests, all present, none unregistered)"
)
PY
