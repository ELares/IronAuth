#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# OIDF conformance results gate.
#
# The OIDF Python runner distinguishes a test that FINISHED from one that
# PASSED, and a finished test carries a result of PASSED, WARNING, REVIEW,
# FAILED, or SKIPPED. Treating "finished" as success is the classic way a
# conformance gate goes silently green while the protocol is actually broken:
# a test that ran to completion and reported WARNING or FAILED still counts as
# a regression. This gate therefore fails on ANY non-PASS.
#
#   PASSED   -> pass.
#   WARNING  -> BLOCKS, unless the exact test is listed in the reviewed waiver
#               file with a written reason (an "unreviewed warning" is one with
#               no such entry, and it blocks). Only WARNING is waivable.
#   REVIEW   -> BLOCKS (a human must look; it can never auto-pass).
#   FAILED   -> BLOCKS.
#   SKIPPED  -> BLOCKS (a silently skipped assertion is not a pass).
#   status not FINISHED (CREATED/WAITING/RUNNING/INTERRUPTED) -> BLOCKS.
#   zero modules -> BLOCKS (a vacuously empty run is never a green run).
#
# The parser is intentionally dependency-free (Python standard library only) so
# its unit tests (test_parse_results.py) run anywhere, including in the always-on
# CI static-check lane where the live suite is not provisioned.
#
# Input format (results file, JSON): the run-conformance.sh wrapper collects each
# module's status and result from the suite REST API into a normalized document:
#
#   {"plan_name": "...", "plan_id": "...", "modules": [
#       {"name": "oidcc-server", "id": "abc", "status": "FINISHED", "result": "PASSED"},
#       ...
#   ]}
#
# A bare list of module objects is also accepted. Each module needs a status and
# a result; the name (or testName / testModule) is used for reporting and waiver
# matching.
#
# Waiver file (JSON, optional):
#
#   {"waived_warnings": [
#       {"test": "oidcc-server-client-secret-basic", "reason": "...", "reviewer": "..."}
#   ]}
#
# A waiver downgrades a WARNING (and only a WARNING) for that exact test to a
# pass-with-note. A waiver entry without a non-empty reason is not a review and
# does not waive anything.

import argparse
import json
import sys

PASS = "PASSED"
WARNING = "WARNING"
REVIEW = "REVIEW"
FAILED = "FAILED"
SKIPPED = "SKIPPED"
FINISHED = "FINISHED"


class Verdict:
    """The outcome of grading one results document."""

    def __init__(self):
        self.ok = True
        self.lines = []
        self.passed = 0
        self.waived = 0
        self.blocked = 0

    def record(self, ok, line, *, waived=False):
        if ok and waived:
            self.waived += 1
        elif ok:
            self.passed += 1
        else:
            self.blocked += 1
            self.ok = False
        self.lines.append(line)


def _modules(document):
    """Normalize the accepted input shapes to a list of module dicts."""
    if isinstance(document, list):
        return document
    if isinstance(document, dict) and isinstance(document.get("modules"), list):
        return document["modules"]
    raise ValueError(
        "results document must be a list of modules or an object with a "
        "'modules' list"
    )


def _name(module):
    for key in ("name", "testName", "testModule", "test", "id"):
        value = module.get(key)
        if value:
            return str(value)
    return "<unnamed>"


def _upper(module, key):
    value = module.get(key)
    return str(value).strip().upper() if value is not None else ""


def _waived_tests(waivers):
    """The set of test names with a valid (reason-bearing) warning waiver."""
    if not waivers:
        return set()
    entries = waivers.get("waived_warnings", []) if isinstance(waivers, dict) else []
    waived = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        test = entry.get("test")
        reason = (entry.get("reason") or "").strip()
        # A waiver with no written reason is not a review; it waives nothing.
        if test and reason:
            waived.add(str(test))
    return waived


def evaluate(document, waivers=None):
    """Grade a results document. Returns a Verdict; verdict.ok is the gate result."""
    verdict = Verdict()
    modules = _modules(document)

    if not modules:
        verdict.record(False, "BLOCK  (vacuous): the run contained zero test modules")
        return verdict

    waived_tests = _waived_tests(waivers)

    for module in modules:
        name = _name(module)
        status = _upper(module, "status")
        result = _upper(module, "result")

        if status != FINISHED:
            verdict.record(
                False,
                f"BLOCK  {name}: status {status or '<none>'} (did not finish)",
            )
            continue

        if result == PASS:
            verdict.record(True, f"PASS   {name}")
        elif result == WARNING and name in waived_tests:
            verdict.record(
                True,
                f"WAIVED {name}: WARNING waived by a reviewed entry",
                waived=True,
            )
        elif result == WARNING:
            verdict.record(
                False,
                f"BLOCK  {name}: WARNING (unreviewed; add a reviewed waiver to accept)",
            )
        elif result == REVIEW:
            verdict.record(
                False,
                f"BLOCK  {name}: REVIEW (needs human review; never auto-passes)",
            )
        elif result == SKIPPED:
            verdict.record(
                False,
                f"BLOCK  {name}: SKIPPED (a skipped assertion is not a pass)",
            )
        else:
            verdict.record(
                False,
                f"BLOCK  {name}: {result or '<no result>'}",
            )

    return verdict


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fail the conformance gate on any non-PASS OIDF result."
    )
    parser.add_argument("results", help="path to the normalized results JSON")
    parser.add_argument(
        "--waivers",
        help="path to a reviewed warning-waiver JSON file (optional)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the built-in unit tests and exit",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        import test_parse_results  # noqa: F401 (imported for its side effects)

        return test_parse_results.run()

    document = load_json(args.results)
    waivers = load_json(args.waivers) if args.waivers else None
    verdict = evaluate(document, waivers)

    for line in verdict.lines:
        print(line)
    print(
        f"\nsummary: {verdict.passed} passed, {verdict.waived} waived, "
        f"{verdict.blocked} blocked"
    )
    if verdict.ok:
        print("conformance gate: PASS")
        return 0
    print("conformance gate: FAIL (non-PASS result present)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
