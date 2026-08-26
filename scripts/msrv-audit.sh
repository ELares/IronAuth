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
cargo metadata --format-version 1 --all-features \
  --filter-platform x86_64-unknown-linux-gnu 2>/dev/null | python3 -c '
import json
import sys
import tomllib
from pathlib import Path

with Path("Cargo.toml").open("rb") as fh:
    msrv = tomllib.load(fh)["workspace"]["package"]["rust-version"]


def parts(version):
    """A dotted version as a comparable tuple, short forms padded with zeros."""
    return tuple(int(piece) for piece in version.split(".")) + (0,) * (3 - len(version.split(".")))


ceiling = parts(msrv)

# The ceiling applies to what the SHIPPED BINARY compiles, which is what the MSRV promises.
#
# A workspace member that nothing in the `ironauth` binary graph reaches cannot break that
# promise, because no deployment compiles it -- and neither can its dependencies. Two members
# are in that position today, `ironauth-cel` (its `cel` dependency declares 1.86) and
# `ironauth-hooks` (wasmtime and cranelift declare 1.95), and the CI msrv lane excludes exactly
# those two for exactly this reason.
#
# Reachability rather than a name list, deliberately. A list is a claim somebody has to
# recheck; reachability rechecks itself. The day either crate is wired into the binary it
# becomes reachable, this audit starts failing on it again, and raising the published promise
# becomes an explicit decision rather than something that happened quietly.
metadata = json.load(sys.stdin)

by_id = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata.get("resolve", {}).get("nodes", [])}
roots = [p["id"] for p in metadata["packages"] if p["name"] == "ironauth"]
if not roots:
    print("msrv-audit: no `ironauth` package in the metadata; cannot scope the audit")
    sys.exit(1)

reachable, stack = set(), list(roots)
while stack:
    node_id = stack.pop()
    if node_id in reachable:
        continue
    reachable.add(node_id)
    stack.extend(nodes.get(node_id, {}).get("dependencies", []))

offenders = []
for package_id in sorted(reachable):
    package = by_id.get(package_id)
    if package is None:
        continue
    declared = package.get("rust_version")
    if declared and parts(declared) > ceiling:
        offenders.append((package["name"], package["version"], declared))

if offenders:
    print(f"msrv-audit: {len(offenders)} package(s) declare a rust-version above the")
    print(f"            workspace MSRV of {msrv}, which is the exact error the CI")
    print("            msrv lane fails with. Pin them back, or move the MSRV")
    print("            deliberately (it is a published promise, not a build detail).")
    for name, version, declared in sorted(offenders):
        print(f"  {name}@{version} requires rustc {declared}")
    print()
    print("            Siblings usually have to move as a SET: pinning one alone")
    print("            fails when another holds it forward through its own dependency.")
    sys.exit(1)

print(f"msrv-audit: clean (no package declares a rust-version above {msrv})")
'
