#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fuzz matrix freshness (issue #419): the set of fuzz targets REGISTERED in the
# repository must equal the set the scheduled fuzz workflow actually RUNS.
#
# This check exists because that matrix has silently drifted twice. Targets were
# written, registered as `[[bin]]` entries, and simply never listed in
# `.github/workflows/fuzz.yml`, so they had never executed once: seven found in
# issue #419, one the round before. A target that never runs is indistinguishable
# from no fuzzing at all, and the char boundary panic class that prompted #419 was
# found ONLY by that lane. The workflow carries a comment stating the invariant,
# but a comment is not a check, so this script enforces it.
#
# Three way check, over the repository root `fuzz/` crate and every
# `crates/*/fuzz/` crate:
#
#   1. the `[[bin]]` entries in each fuzz crate's Cargo.toml   (AUTHORITATIVE)
#   2. the `fuzz_targets/*.rs` files on disk
#   3. the `include:` rows of the workflow matrix
#
# Set 1 is authoritative because it is what cargo actually builds, and therefore
# exactly what `cargo fuzz list` enumerates and what `cargo fuzz run <name>` can
# name. A `fuzz_targets/*.rs` file with no `[[bin]]` entry is dead code no lane
# could ever run; a `[[bin]]` entry with no file does not build. Sets 2 and 3 are
# each compared against set 1, so both drift directions are caught, and so is the
# separate silent failure of a target file that was never registered at all.
#
# Deliberately STATIC: it never invokes `cargo fuzz`, `cargo`, or a nightly
# toolchain. gate.sh runs on developer machines that may have neither nightly nor
# cargo-fuzz installed, and a check that silently skips itself there is worse than
# no check, because it reports green while proving nothing. The parsers below use
# only the Python 3 standard library, adding no new toolchain requirement; where a
# stricter stdlib parser happens to be importable it is used as a CROSS CHECK of
# the narrow parser rather than as a dependency.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 - <<'PY'
import glob
import os
import re
import sys

WORKFLOW = ".github/workflows/fuzz.yml"

# tomllib is stdlib from Python 3.11 and PyYAML is a third party package that the
# repository does not require (scripts/conformance-check.sh already treats it as
# optional). Neither is a dependency here: the narrow parsers below are the
# primary path, and each of these is used only to CROSS CHECK that parser when
# the interpreter happens to have it.
try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None
try:
    import yaml
except ModuleNotFoundError:
    yaml = None

problems = []


def fail(headline, items):
    problems.append((headline, sorted(items)))


def describe(entry):
    directory, target = entry
    return f"{target}  (dir: {directory})"


def fuzz_crates():
    """Every fuzz crate as (matrix_dir, crate_path).

    `matrix_dir` is the key the workflow matrix uses: the fuzz crate's PARENT,
    with the repository root written as ".". Today that is the root `fuzz/` crate
    plus one per `crates/*/`, but this walks for any directory NAMED `fuzz` that
    holds a Cargo.toml rather than matching those two shapes: a fuzz crate added
    at an unexpected path would otherwise be invisible to this check, which is
    the same silent omission the check exists to catch. Build output, vendored
    packages, and git internals are pruned so `fuzz/target/` is never scanned.
    """
    prune = {"target", "node_modules", ".git", "artifacts", "corpus"}
    crates = []
    for root, dirs, files in os.walk("."):
        dirs[:] = sorted(d for d in dirs if d not in prune)
        if os.path.basename(root) == "fuzz" and "Cargo.toml" in files:
            crate = os.path.relpath(root, ".")
            crates.append((os.path.dirname(crate) or ".", crate))
    return sorted(crates)


def bins_narrow(text):
    """`[[bin]] name = "..."` pairs, without a TOML library."""
    names = []
    in_bin = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("["):
            in_bin = stripped == "[[bin]]"
            continue
        if in_bin:
            match = re.match(r'name\s*=\s*"([^"]+)"', stripped)
            if match:
                names.append(match.group(1))
    return names


def bin_names(manifest, text):
    narrow = bins_narrow(text)
    if tomllib is not None:
        strict = [b["name"] for b in tomllib.loads(text).get("bin", []) if "name" in b]
        if sorted(strict) != sorted(narrow):
            fail(
                f"internal parser disagreement on {manifest} (report this)",
                [f"narrow: {sorted(narrow)}", f"tomllib: {sorted(strict)}"],
            )
            return strict
    return narrow


def matrix_narrow(text):
    """The `include:` rows of the fuzz matrix, without a YAML library.

    The shape is narrow and fixed: a block sequence of two key mappings, each
    `- dir: <path>` followed by `target: <name>`. Blank lines and comments are
    skipped, and the block ends at the first content line that is not indented
    deeper than the `include:` key itself.
    """
    lines = text.splitlines()
    start = None
    outer = 0
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)include:\s*$", line)
        if match:
            start, outer = index + 1, len(match.group(1))
            break
    if start is None:
        return None

    rows, current = [], None
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= outer:
            break
        if stripped.startswith("- "):
            current = {}
            rows.append(current)
            stripped = stripped[2:].strip()
        if current is None:
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(\S+)\s*$", stripped)
        if match:
            current[match.group(1)] = match.group(2).strip("\"'")
    return rows


def matrix_entries(text):
    rows = matrix_narrow(text)
    if rows is None:
        print(f"fuzz-matrix-freshness: no `include:` matrix found in {WORKFLOW}")
        sys.exit(1)
    if yaml is not None:
        strict = yaml.safe_load(text)["jobs"]["fuzz"]["strategy"]["matrix"]["include"]
        if [dict(r) for r in rows] != [dict(r) for r in strict]:
            fail(
                "internal parser disagreement on the workflow matrix (report this)",
                [f"narrow: {rows}", f"pyyaml: {strict}"],
            )
            rows = strict
    entries, malformed = set(), []
    for row in rows:
        if "dir" not in row or "target" not in row:
            malformed.append(str(row))
            continue
        entries.add((row["dir"], row["target"]))
    if malformed:
        fail("matrix row missing a `dir` or a `target` key", malformed)
    return entries


registered = set()   # authoritative: the [[bin]] entries
on_disk = set()      # the fuzz_targets/*.rs files

for matrix_dir, crate in fuzz_crates():
    with open(f"{crate}/Cargo.toml", encoding="utf-8") as handle:
        manifest_text = handle.read()
    for name in bin_names(f"{crate}/Cargo.toml", manifest_text):
        registered.add((matrix_dir, name))
    for path in glob.glob(f"{crate}/fuzz_targets/*.rs"):
        on_disk.add((matrix_dir, os.path.basename(path)[: -len(".rs")]))

with open(WORKFLOW, encoding="utf-8") as handle:
    in_matrix = matrix_entries(handle.read())

if registered - in_matrix:
    fail(
        "registered fuzz target with NO workflow matrix row (it has never run in CI)",
        (describe(e) for e in registered - in_matrix),
    )
if in_matrix - registered:
    fail(
        "workflow matrix row for a target that is not registered as a `[[bin]]`"
        " (the lane cannot run it)",
        (describe(e) for e in in_matrix - registered),
    )
if on_disk - registered:
    fail(
        "fuzz_targets file with no `[[bin]]` entry (it is dead code; nothing builds it)",
        (describe(e) for e in on_disk - registered),
    )
if registered - on_disk:
    fail(
        "`[[bin]]` entry with no fuzz_targets file (the fuzz crate does not build)",
        (describe(e) for e in registered - on_disk),
    )

if problems:
    for headline, items in problems:
        print(f"fuzz-matrix-freshness: {headline}:")
        for item in items:
            print(f"  {item}")
    print(
        "fuzz-matrix-freshness: the registered fuzz targets and"
        f" {WORKFLOW} must name exactly the same set."
    )
    sys.exit(1)

print(
    f"fuzz-matrix-freshness: clean ({len(registered)} registered fuzz targets,"
    f" {len(on_disk)} target files, {len(in_matrix)} matrix rows, all agree)"
)
PY
