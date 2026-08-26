#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Every package in the resolved dependency graph must declare a rust-version at
# or below the workspace MSRV.
#
# This exists because the gate did NOT have it and CI did, and the gap is where a
# thirteen-hour outage hid: main was RED on the `msrv (1.85)` lane for ten
# consecutive runs while every PR merged in that window was legitimately green
# locally. The workflow is merge-on-green-local-gate without waiting for CI, so a
# lane the gate does not run is a lane nobody sees until somebody goes looking.
#
# It reads `cargo metadata` rather than running `cargo +<msrv> check` a second
# time, deliberately. The full second compile is what CI does and takes minutes;
# this takes about a second and catches the SAME failure, because the CI error is
# the resolver refusing on DECLARED rust-version metadata:
#
#     error: rustc 1.85.1 is not supported by the following packages:
#       tonic@0.14.6 requires rustc 1.88
#
# What it therefore does NOT catch, stated so nobody reads it as the stronger
# check: code that needs a newer compiler while declaring an older rust-version,
# which only a real 1.85 build finds. CI still runs that build. This is the fast
# tripwire for the common case, not a replacement for the lane.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# --filter-platform is load-bearing, not tidiness. Without it the resolve graph
# includes target-specific packages that never compile for us, and the audit
# reports them: measured, `wasip2@1.0.4 requires rustc 1.87.0` is in the graph
# while `cargo +1.85 check` passes cleanly, because nothing builds it for a Linux
# or macOS host. A check that fires on a tree the real build accepts is a check
# people learn to ignore.
#
# The triple is the one the CI msrv lane runs on. The musl lane builds a
# different target, and a package that raised its rust-version ONLY under musl
# would slip past this; that lane still runs in CI and is the backstop.
# TWO GRAPHS, and the difference between them is the whole point.
#
# The promise in docs/COMPATIBILITY.md is about what a DEFAULT build compiles, so that is the
# graph the ceiling is enforced against. `--all-features` is a different graph and always was:
# it turns on every optional dependency in the workspace, including ones no deployment ships.
#
# This script used to read only the `--all-features` graph, and it was fine right up until an
# optional feature pulled in a dependency above the ceiling. Issue #114 did exactly that:
# `ironauth-oidc/wasm-hooks` is off by default and pulls wasmtime, which declares 1.95. The
# audit reported 30-odd offenders for a graph nothing deploys, and the CI lane failed the same
# way for the same reason -- `cargo check --workspace --all-features --exclude ironauth-hooks`
# does NOT exclude wasmtime, because `--exclude` drops a workspace MEMBER from the check list
# and says nothing about what the members still being checked depend on.
#
# So: the default graph must be CLEAN, and the all-features graph must be COVERED -- every
# package above the ceiling that only `--all-features` reaches has to be matched by a workspace
# member that declares a rust-version at least that high, because that declaration is what CI
# uses to pick the toolchain it checks that combination under. An optional dependency that
# outruns every declared member MSRV is one nothing compiles at a high enough version anywhere,
# and that is a real hole rather than a feature nobody enables.
DEFAULT_GRAPH="$(mktemp)"
ALL_GRAPH="$(mktemp)"
trap 'rm -f "$DEFAULT_GRAPH" "$ALL_GRAPH"' EXIT
# Errors are SHOWN and the failure is named. Under `set -e` a redirected `cargo metadata` that
# cannot resolve (an unbuildable manifest, a feature naming a dependency that is no longer
# optional) would otherwise abort this script with no output at all, which reads exactly like a
# clean run to anyone skimming a CI log.
for graph in "DEFAULT_GRAPH:" "ALL_GRAPH:--all-features"; do
  destination="${graph%%:*}"
  extra="${graph#*:}"
  # shellcheck disable=SC2086 # `extra` is one optional flag, deliberately unquoted when empty
  if ! cargo metadata --format-version 1 $extra \
    --filter-platform x86_64-unknown-linux-gnu >"${!destination}"; then
    echo "msrv-audit: cargo metadata ${extra:-(default features)} FAILED, so no graph could be"
    echo "            read. That is a failure of this audit, not an absence of offenders."
    exit 1
  fi
done
python3 - "$DEFAULT_GRAPH" "$ALL_GRAPH" <<'PYAUDIT'
import json
import sys
import tomllib
from pathlib import Path

with Path("Cargo.toml").open("rb") as fh:
    manifest = tomllib.load(fh)
msrv = manifest["workspace"]["package"]["rust-version"]


def parts(version):
    """A dotted version as a comparable tuple, short forms padded with zeros."""
    return tuple(int(piece) for piece in version.split(".")) + (0,) * (3 - len(version.split(".")))


ceiling = parts(msrv)

# The roots are what the CI msrv lane COMPILES, which is the workspace minus the crates that
# lane excludes -- not the binary alone. Rooting at `ironauth` was narrower than the lane and
# made `ironauth-importers`, which the lane does compile, invisible to this audit.
EXCLUDED = {"ironauth-hooks", "ironauth-cel"}


def load(path):
    """The metadata document at `path`, refusing a degenerate one."""
    with Path(path).open(encoding="utf-8") as fh:
        metadata = json.load(fh)
    nodes = {n["id"]: n for n in (metadata.get("resolve") or {}).get("nodes") or []}
    # A degenerate document must FAIL, not read as clean. `cargo metadata --no-deps` and any
    # future flag change produce no resolve graph, and an empty graph makes every package
    # unreachable, which this audit would otherwise report as "no package declares a
    # rust-version above 1.85" while 37 of them do. A scoped audit that cannot see anything is
    # not a clean audit.
    if not nodes:
        print(f"msrv-audit: {path} carried no resolve graph, so nothing could be scoped.")
        print("            This is a FAILURE rather than a clean run: with no graph every")
        print("            package is unreachable and every offender is silently skipped.")
        sys.exit(1)
    return metadata, nodes


def offenders_in(path, dev=True):
    """(name, version, declared) for every reachable package above the ceiling.

    `dev=False` drops DEV-DEPENDENCY edges, which is what the published promise is about: a
    consumer of this workspace compiles its libraries and its binary, never its test harnesses.
    The distinction is not academic. `ironauth-oidc` dev-depends on `ironauth-hooks` so its
    integration tests can deploy the shipped guest fixtures, and that edge alone put wasmtime
    (rust-version 1.95) into the DEFAULT graph -- with the `wasm-hooks` feature off, nothing
    linked into a deployment touching it. Reading that as an MSRV violation would have forced a
    published promise to move because a test wanted a fixture.
    """
    metadata, nodes = load(path)
    by_id = {p["id"]: p for p in metadata["packages"]}
    roots = [
        package_id
        for package_id in metadata.get("workspace_members", [])
        if by_id.get(package_id, {}).get("name") not in EXCLUDED
    ]
    if not roots:
        print("msrv-audit: no workspace members to scope the audit to")
        sys.exit(1)
    reachable, stack = set(), list(roots)
    while stack:
        node_id = stack.pop()
        if node_id in reachable:
            continue
        reachable.add(node_id)
        if dev:
            stack.extend(nodes.get(node_id, {}).get("dependencies", []))
            continue
        # `deps` carries the edge KINDS that the flat `dependencies` list has already thrown
        # away. An edge with no kinds at all is a normal one (cargo writes `kind: null` for
        # those), so an unknown shape counts as shipped rather than being skipped.
        for edge in nodes.get(node_id, {}).get("deps", []):
            kinds = {entry.get("kind") for entry in edge.get("dep_kinds") or [{}]}
            if kinds <= {"dev"}:
                continue
            stack.append(edge["pkg"])
    found = []
    for package_id in sorted(reachable):
        package = by_id.get(package_id)
        if package is None:
            continue
        declared = package.get("rust_version")
        if declared and parts(declared) > ceiling:
            found.append((package["name"], package["version"], declared))
    return sorted(found), metadata, by_id


default_path, all_path = sys.argv[1], sys.argv[2]

# PASS ONE. The shipped graph, and the ceiling is a hard failure here.
shipped, _, _ = offenders_in(default_path, dev=False)
if shipped:
    print(f"msrv-audit: {len(shipped)} package(s) in the DEFAULT feature graph declare a")
    print(f"            rust-version above the workspace MSRV of {msrv}, which is the exact")
    print("            error the CI msrv lane fails with. This is the graph a deployment")
    print("            compiles, so pin them back, or move the MSRV deliberately (it is a")
    print("            published promise, not a build detail).")
    for name, version, declared in shipped:
        print(f"  {name}@{version} requires rustc {declared}")
    print()
    print("            Siblings usually have to move as a SET: pinning one alone")
    print("            fails when another holds it forward through its own dependency.")
    sys.exit(1)

# PASS TWO. What only a non-default feature reaches. Not a ceiling violation, but it has to be
# COVERED by a member that declares a compiler high enough to build it.
optional, metadata, by_id = offenders_in(all_path)
if optional:
    declared_by_members = [
        parts(by_id[m]["rust_version"])
        for m in metadata.get("workspace_members", [])
        if by_id.get(m, {}).get("rust_version")
    ]
    highest_member = max(declared_by_members) if declared_by_members else ceiling
    uncovered = [entry for entry in optional if parts(entry[2]) > highest_member]
    if uncovered:
        as_text = ".".join(str(piece) for piece in highest_member)
        print(f"msrv-audit: {len(uncovered)} package(s) reachable only with --all-features need")
        print(f"            a newer compiler than ANY workspace member declares ({as_text}).")
        print("            Nothing checks that combination at a version that can build it, so")
        print("            it compiles nowhere. Declare it on the member that gates the")
        print("            feature, and give CI a lane at that toolchain.")
        for name, version, declared in uncovered:
            print(f"  {name}@{version} requires rustc {declared}")
        sys.exit(1)
    gated = ", ".join(sorted({entry[2] for entry in optional}))
    print(f"msrv-audit: {len(optional)} package(s) sit above {msrv} behind a NON-DEFAULT feature")
    print(f"            (declaring {gated}); each is covered by a workspace member that declares")
    print("            at least as much, and CI checks those at their own toolchain.")

print(f"msrv-audit: clean (the default feature graph declares nothing above {msrv})")
PYAUDIT
