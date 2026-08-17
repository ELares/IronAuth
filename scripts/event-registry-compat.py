#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Reject a BREAKING event payload change that did not bump its version (issue #108, c4).

Criterion 4 asks that "a breaking payload change without a version bump is rejected by a
registry compatibility check in CI".

`event-catalog.sh` already fails when the committed catalog is stale, and its message asks a
human to review the diff -- its own words are "which is what this diff exists to surface".
Surfacing is not rejecting. Once the catalog is regenerated and committed, a breaking change
under an unchanged version passes, and the only thing standing between it and a consumer is
that somebody read the diff carefully. This is the check that refuses it.

# Additive versus breaking

The published policy in `docs/EVENTS.md` is "additive changes extend a version; a breaking
change mints a new one", so this cannot simply reject every edit -- that would forbid the
additive case the policy explicitly permits, and the first person to add an optional field
would have to bump a version for no reason and strand every pinned consumer.

BREAKING, for the shapes this registry uses:

  * a property disappears -- a consumer reading it now reads nothing;
  * a property becomes required -- a producer that omitted it now fails validation;
  * a property's type changes -- a consumer's decode breaks;
  * an enum loses a value -- a payload that used to validate no longer does;
  * a `minLength` / `minItems` / `minimum` rises -- same.

ADDITIVE, permitted under an unchanged version: a new OPTIONAL property, an enum gaining a
value, a constraint loosening. A consumer written against the old schema still works.

DELIBERATELY NOT FLAGGED: tightening `additionalProperties` to `false`. It reads like a
narrowing and is not one for the party this check protects. These rules exist to defend the
CONSUMER contract, and a consumer cannot break from it -- what it receives is unchanged.
The only thing constrained is a PRODUCER sending undeclared fields, and every producer is in
this repository and verified conforming. Flagging it would force a version bump on all types
at once, stranding every pinned consumer to fix a break that nobody can experience.

An event type that DISAPPEARS entirely is breaking too, and is reported: a consumer
subscribed to it will wait forever, which is the same defect the registry's producer rule
exists to prevent from the other direction.

Usage:
    event-registry-compat.py [BASE_REVISION]      default: origin/main
"""

from __future__ import annotations

import json
import subprocess
import sys

CATALOG = "docs/events/catalog.json"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def catalog_at(revision: str) -> dict[str, dict] | None:
    """The registry as of `revision`, keyed by wire type. `None` when it did not exist."""
    shown = run("git", "show", f"{revision}:{CATALOG}")
    if shown.returncode != 0:
        return None
    return {entry["type"]: entry for entry in json.loads(shown.stdout)["event_types"]}


def constraint_breaks(before: dict, after: dict, path: str) -> list[str]:
    """Every way `after` refuses something `before` accepted."""
    broken = []

    if before.get("type") != after.get("type"):
        broken.append(f"{path}: type {before.get('type')!r} -> {after.get('type')!r}")

    before_enum, after_enum = before.get("enum"), after.get("enum")
    if before_enum is not None:
        lost = [v for v in before_enum if v not in (after_enum or [])]
        if lost:
            broken.append(f"{path}: enum no longer accepts {lost}")
    elif after_enum is not None:
        # Gaining an enum where there was none narrows an unconstrained field.
        broken.append(f"{path}: newly constrained to enum {after_enum}")

    for bound in ("minLength", "minItems", "minimum"):
        was, now = before.get(bound), after.get(bound)
        if now is not None and (was is None or now > was):
            broken.append(f"{path}: {bound} {was} -> {now}")

    # Nested item schemas, which is how the registry expresses list payloads.
    if isinstance(before.get("items"), dict) and isinstance(after.get("items"), dict):
        broken += constraint_breaks(before["items"], after["items"], f"{path}[]")

    return broken


def schema_breaks(before: dict, after: dict) -> list[str]:
    """Every breaking difference between two payload schemas."""
    broken = []

    before_props = before.get("properties", {})
    after_props = after.get("properties", {})
    for name in before_props:
        if name not in after_props:
            broken.append(f"property {name!r} removed")
        else:
            broken += constraint_breaks(before_props[name], after_props[name], f"property {name!r}")

    newly_required = set(after.get("required", [])) - set(before.get("required", []))
    for name in sorted(newly_required):
        broken.append(f"property {name!r} became required")

    return broken


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"

    if run("git", "rev-parse", "--verify", base).returncode != 0:
        # NOT a pass. A check that cannot see the base revision has not compared anything,
        # and reporting success would be indistinguishable from finding no breaking change.
        print(f"event-registry-compat: {base!r} is not a revision here, so nothing was", file=sys.stderr)
        print("  compared. Fetch the base branch (CI needs fetch-depth: 0) or pass one.", file=sys.stderr)
        return 1

    before = catalog_at(base)
    if before is None:
        print(f"event-registry-compat: no {CATALOG} at {base}; nothing to compare against.")
        return 0

    after = {entry["type"]: entry for entry in json.loads(open(CATALOG).read())["event_types"]}

    failures: list[str] = []
    for wire, old in sorted(before.items()):
        new = after.get(wire)
        if new is None:
            failures.append(
                f"{wire}: REMOVED from the registry. A consumer subscribed to it will wait "
                f"forever; retire it deliberately, with a note here."
            )
            continue
        breaks = schema_breaks(old["payload_schema"], new["payload_schema"])
        if not breaks:
            continue
        if new["payload_schema_version"] > old["payload_schema_version"]:
            print(
                f"  ok   {wire}: breaking change carried a version bump "
                f"({old['payload_schema_version']} -> {new['payload_schema_version']})"
            )
            continue
        detail = "; ".join(breaks)
        failures.append(
            f"{wire}: BREAKING payload change under an unchanged version "
            f"{new['payload_schema_version']} -- {detail}"
        )

    if failures:
        print("event-registry-compat: a breaking payload change did not bump its version:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(file=sys.stderr)
        print("  The policy in docs/EVENTS.md: additive changes extend a version, a breaking", file=sys.stderr)
        print("  change mints a new one. Bump payload_schema_version, or make the change", file=sys.stderr)
        print("  additive (a new OPTIONAL property, a widened enum, a loosened bound).", file=sys.stderr)
        return 1

    print(
        f"event-registry-compat: clean ({len(before)} types compared against {base}; "
        f"{len(after) - len(before)} added)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
