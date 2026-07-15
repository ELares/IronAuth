#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Unit tests for the conformance results gate (parse_results.py).
#
# These prove the gate's discriminating property locally, without the live OIDF
# suite: it passes ONLY on a real PASS, and blocks on finished-but-failed, on an
# unreviewed WARNING, on REVIEW, on SKIPPED, on a test that never finished, and
# on a vacuously empty run. A reviewed WARNING waiver (with a written reason)
# is the one path that downgrades a WARNING to a pass.
#
# Run directly (python3 test_parse_results.py) or via unittest discovery. Uses
# only the Python standard library.

import unittest

import normalize_runner_export as norm
import parse_results as gate


def doc(*modules):
    return {"plan_name": "test", "plan_id": "t", "modules": list(modules)}


def module(name, status="FINISHED", result="PASSED"):
    return {"name": name, "status": status, "result": result}


class GateTests(unittest.TestCase):
    def test_all_passed_is_green(self):
        verdict = gate.evaluate(doc(module("a"), module("b")))
        self.assertTrue(verdict.ok)
        self.assertEqual(verdict.passed, 2)
        self.assertEqual(verdict.blocked, 0)

    def test_finished_but_failed_blocks(self):
        # The core trap: the module FINISHED, so a naive "finished == success"
        # gate would pass it. Result is FAILED, so this gate must block.
        verdict = gate.evaluate(doc(module("a"), module("b", result="FAILED")))
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.blocked, 1)

    def test_unreviewed_warning_blocks(self):
        verdict = gate.evaluate(doc(module("a", result="WARNING")))
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.blocked, 1)

    def test_reviewed_warning_is_waived(self):
        waivers = {
            "waived_warnings": [
                {"test": "a", "reason": "known suite quirk, tracked in #999", "reviewer": "op"}
            ]
        }
        verdict = gate.evaluate(doc(module("a", result="WARNING")), waivers)
        self.assertTrue(verdict.ok)
        self.assertEqual(verdict.waived, 1)
        self.assertEqual(verdict.blocked, 0)

    def test_warning_waiver_without_reason_still_blocks(self):
        # A waiver entry with no written reason is not a review, so it waives
        # nothing: an unjustified warning cannot be silently accepted.
        waivers = {"waived_warnings": [{"test": "a", "reason": "", "reviewer": "op"}]}
        verdict = gate.evaluate(doc(module("a", result="WARNING")), waivers)
        self.assertFalse(verdict.ok)

    def test_warning_waiver_does_not_leak_to_other_results(self):
        # A waiver only downgrades WARNING; a FAILED for the same test still blocks.
        waivers = {"waived_warnings": [{"test": "a", "reason": "x"}]}
        verdict = gate.evaluate(doc(module("a", result="FAILED")), waivers)
        self.assertFalse(verdict.ok)

    def test_review_blocks_and_is_not_waivable(self):
        waivers = {"waived_warnings": [{"test": "a", "reason": "x"}]}
        verdict = gate.evaluate(doc(module("a", result="REVIEW")), waivers)
        self.assertFalse(verdict.ok)

    def test_skipped_blocks(self):
        verdict = gate.evaluate(doc(module("a", result="SKIPPED")))
        self.assertFalse(verdict.ok)

    def test_not_finished_blocks(self):
        verdict = gate.evaluate(doc(module("a", status="RUNNING", result="")))
        self.assertFalse(verdict.ok)

    def test_interrupted_blocks(self):
        verdict = gate.evaluate(doc(module("a", status="INTERRUPTED", result="PASSED")))
        self.assertFalse(verdict.ok)

    def test_empty_run_is_vacuous_failure(self):
        verdict = gate.evaluate(doc())
        self.assertFalse(verdict.ok)

    def test_bare_list_input_is_accepted(self):
        verdict = gate.evaluate([module("a"), module("b")])
        self.assertTrue(verdict.ok)

    def test_case_insensitive_status_and_result(self):
        verdict = gate.evaluate([{"name": "a", "status": "finished", "result": "passed"}])
        self.assertTrue(verdict.ok)

    def test_mixed_one_failure_fails_the_whole_run(self):
        verdict = gate.evaluate(
            doc(module("a"), module("b"), module("c", result="FAILED"), module("d"))
        )
        self.assertFalse(verdict.ok)
        self.assertEqual(verdict.passed, 3)
        self.assertEqual(verdict.blocked, 1)


class NormalizeTests(unittest.TestCase):
    def test_flattens_oidf_info_objects(self):
        objects = [
            {"testName": "oidcc-server", "id": "m1", "status": "FINISHED", "result": "PASSED"},
            {"testName": "oidcc-userinfo", "id": "m2", "status": "FINISHED", "result": "WARNING"},
        ]
        out = norm.normalize_modules(objects)
        self.assertEqual(len(out["modules"]), 2)
        self.assertEqual(out["modules"][0]["name"], "oidcc-server")
        self.assertEqual(out["modules"][1]["result"], "WARNING")

    def test_expands_plan_info_instances(self):
        plan = [
            {
                "modules": [
                    {
                        "testModule": "oidcc-server",
                        "instances": [{"id": "i1", "status": "FINISHED", "result": "PASSED"}],
                    }
                ]
            }
        ]
        out = norm.normalize_modules(plan)
        self.assertEqual(out["modules"][0]["name"], "oidcc-server")
        self.assertEqual(out["modules"][0]["status"], "FINISHED")

    def test_normalized_output_feeds_the_gate(self):
        # End to end: a normalized failing export must block the gate.
        objects = [
            {"testName": "a", "status": "FINISHED", "result": "PASSED"},
            {"testName": "b", "status": "FINISHED", "result": "FAILED"},
        ]
        verdict = gate.evaluate(norm.normalize_modules(objects))
        self.assertFalse(verdict.ok)


def run():
    """Run the suite and return a process exit code (0 green, 1 on any failure)."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(
        loader.loadTestsFromTestCase(case) for case in (GateTests, NormalizeTests)
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    import sys

    sys.exit(run())
