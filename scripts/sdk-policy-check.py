#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The published SDK policy still describes the SDKs that exist (issue #116, criterion 8).

Criterion 8 asks that "the public docs state the deferred-SDK policy with the priority matrix
rationale". A policy page is only worth publishing while it is TRUE, and this one makes two
falsifiable claims an integrator acts on:

  * a "what ships today" table, and
  * a deferral list, each entry with a revisit trigger.

Both rot in opposite directions, and neither rots loudly:

  * a shipped SDK is removed or renamed, and the page keeps advertising it -- an integrator
    picks IronAuth for a language it no longer supports;
  * a new SDK lands and nobody updates the page, so it is documented as unsupported and the
    work goes unused.

So the table is checked AGAINST THE TREE, in both directions. This is deliberately not a
freshness diff against a generated file: the prose here is a set of DECISIONS (why an order,
what would change our mind) and must stay hand-written. What must not be hand-written is the
list of what exists, which is a fact.

A deferral that names a language the tree now ships is also caught: that is the sharpest
version of the rot, because the page would be telling an integrator not to wait for something
already delivered.

Usage:
    sdk-policy-check.py
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    ).stdout.strip()
)
POLICY = ROOT / "docs" / "SDK-POLICY.md"

# Where a shipped client lives. A directory here is a claim the policy must account for.
SDK_ROOTS = (ROOT / "sdks", ROOT / "clients")


def shipped_directories() -> set[str]:
    """Every client directory in the tree, by name."""
    found = set()
    for root in SDK_ROOTS:
        if not root.is_dir():
            continue
        for entry in root.iterdir():
            if entry.is_dir() and not entry.name.startswith((".", "_")):
                found.add(entry.name)
    return found


def main() -> int:
    if not POLICY.is_file():
        print(f"sdk-policy-check: {POLICY.relative_to(ROOT)} is missing.", file=sys.stderr)
        print("  Issue #116 criterion 8 requires the deferred-SDK policy to be PUBLISHED.", file=sys.stderr)
        return 1

    text = POLICY.read_text()
    shipped = shipped_directories()
    if not shipped:
        # Not a pass. Finding no SDKs at all means the roots moved, and a check with an empty
        # denominator agrees with any document.
        print("sdk-policy-check: no client directories found under sdks/ or clients/.", file=sys.stderr)
        print("  They moved, or this check is pointed at the wrong roots; either way it is", file=sys.stderr)
        print("  comparing the policy against nothing.", file=sys.stderr)
        return 1

    # The "ships today" table cites each one by its path, which is what makes the claim
    # checkable rather than a language name that could mean anything.
    ships_section = text.split("## Deferred")[0]
    failures = []

    for name in sorted(shipped):
        cited = re.search(rf"`(?:sdks|clients)/{re.escape(name)}`", ships_section)
        if not cited:
            failures.append(
                f"{name}: exists in the tree but the policy's 'what ships today' table does "
                f"not cite `sdks/{name}` or `clients/{name}`. It is documented as unsupported."
            )

    # ...and the other direction: a cited path that no longer exists.
    for cited in re.findall(r"`((?:sdks|clients)/[A-Za-z0-9_.-]+)`", ships_section):
        if not (ROOT / cited).exists():
            failures.append(f"{cited}: cited by the policy as shipping, but it is not in the tree.")

    # A deferral naming something the tree ships is the sharpest rot: the page would be telling
    # an integrator not to wait for what is already delivered.
    deferred_section = text.split("## Deferred", 1)[1] if "## Deferred" in text else ""
    for name in sorted(shipped):
        for match in re.finditer(r"^\s*- \*\*What\*\*:(.+)$", deferred_section, re.MULTILINE):
            entry = match.group(1)
            if re.search(rf"\b{re.escape(name)}\b", entry, re.IGNORECASE):
                failures.append(
                    f"{name}: ships in the tree but a deferral entry still names it "
                    f"({entry.strip()[:60]}...)."
                )

    if failures:
        print("sdk-policy-check: the published SDK policy no longer matches the tree:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(file=sys.stderr)
        print(f"  Update {POLICY.relative_to(ROOT)}. An integrator chooses a stack on this page.", file=sys.stderr)
        return 1

    print(
        f"sdk-policy-check: clean ({len(shipped)} shipped clients, all cited; "
        f"no deferral names a shipped one)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
