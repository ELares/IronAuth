#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline observer tests. No real benchmark, perf session or service is started."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("hook-bench-diagnostics.py")
SPEC = importlib.util.spec_from_file_location("diagnostics", SCRIPT)
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)
MEASURED = {"runner_class": "ubuntu-latest", "machine": "offline-test-only",
            "cold_p95_micros": 400.0, "warm_p95_micros": 120.0,
            "cold_iterations": 200, "warm_iterations": 5000}

STUB = r'''
import json, os, pathlib, subprocess, sys, time
name = pathlib.Path(sys.argv[0]).name
mode = os.environ.get("OBSERVER_TEST_MODE", "success")
with open("calls.jsonl", "a") as stream:
    stream.write(json.dumps([name] + sys.argv[1:]) + "\n")
pathlib.Path("last-child.pid").write_text(str(os.getpid()))
if name == "cargo":
    binary = pathlib.Path("target/release/deps/hook_latency-fixture").resolve()
    if mode == "outside": binary = pathlib.Path("outside").resolve()
    if mode == "query-failure": sys.exit(9)
    if mode == "invalid-json": print("invalid"); sys.exit(0)
    for item in ([binary, binary.with_name("second")] if mode == "ambiguous" else [binary]):
        print(json.dumps({"reason": "compiler-artifact", "target": {"name": "hook_latency", "kind": ["bench"]}, "executable": str(item)}))
elif sys.argv[1] == "stat":
    if mode == "permission-timeout": time.sleep(60)
    if mode == "denied": sys.exit(7)
elif sys.argv[1] == "record":
    if mode == "record-timeout": time.sleep(60)
    if mode == "record-failure": sys.exit(8)
    data = pathlib.Path(sys.argv[sys.argv.index("-o") + 1])
    if mode != "missing-data": data.write_bytes(b"offline-profile-fixture")
    if mode == "tamper": pathlib.Path("target/hook-bench-measurement.json").write_text("{}")
    sys.exit(subprocess.run([sys.argv[-1]], check=False).returncode)
elif sys.argv[1] == "report":
    if mode == "report-failure": sys.exit(6)
    print("offline fixture, not a performance sample")
else:
    print("perf offline fixture")
'''


class ObserverTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.previous = Path.cwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, self.previous)
        self.env = patch.dict(os.environ, {"HOOK_BENCH_AUTHORITATIVE_OUTCOME": "failure"})
        self.env.start()
        self.addCleanup(self.env.stop)
        Path("bin").mkdir()
        self.binary = Path("target/release/deps/hook_latency-fixture")
        self.binary.parent.mkdir(parents=True)
        self.write_executable(self.binary, 'from pathlib import Path\nPath("executed").write_text("once")\nprint("diagnostic-only")\n')
        for name in ("cargo", "perf"):
            self.write_executable(Path("bin") / name, STUB)
        self.path_env = patch.dict(os.environ, {"PATH": str(Path("bin").resolve())})
        self.path_env.start()
        self.addCleanup(self.path_env.stop)
        self.before = DIAG.OUT / "before/metadata.json"
        self.before.parent.mkdir(parents=True)
        self.before.write_text(json.dumps({"measurement_before_gate": None}))
        DIAG.MEASUREMENT.write_text(json.dumps(MEASURED) + "\n")
        self.measurement = DIAG.MEASUREMENT.read_bytes()

    def write_executable(self, path, body):
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o700)

    def calls(self):
        path = Path("calls.jsonl")
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def result(self):
        return json.loads((DIAG.OUT / "profile/result.json").read_text())

    def profile(self, mode="success", quick=False):
        original = DIAG.Capture.run

        def run(capture, name, argv, seconds, stream_limit=65536):
            if (mode, name) in (("permission-timeout", "permission"), ("record-timeout", "record")):
                seconds = min(seconds, 1)
            return original(capture, name, argv, seconds, stream_limit)

        with patch.dict(os.environ, {"OBSERVER_TEST_MODE": mode}):
            if quick:
                with patch.object(DIAG.Capture, "run", run):
                    DIAG.profile()
            else:
                DIAG.profile()
        self.assertEqual(DIAG.MEASUREMENT.read_bytes(), self.measurement)
        self.assertTrue(self.result()["authoritative_measurement_preserved"])
        self.assertFalse(self.result()["performance_qualified"])
        self.assertLessEqual(self.result()["profile_executions"], 1)
        self.assertIsNone(DIAG.ACTIVE)
        return self.result()

    def test_one_profile_preserves_first_failure_measurement_and_argv(self):
        result = self.profile()
        self.assertEqual(result["status"], "captured")
        self.assertEqual(result["profile_executions"], 1)
        self.assertEqual(Path("executed").read_text(), "once")
        self.assertEqual(result["executable"]["sha256"], DIAG.digest(self.binary))
        calls = self.calls()
        self.assertEqual([c[:2] for c in calls], [["perf", "--version"], ["perf", "stat"],
                         ["cargo", "bench"], ["perf", "record"], ["perf", "report"]])
        self.assertEqual(calls[2], ["cargo", "bench", "-p", "ironauth-hooks", "--bench",
                                   "hook_latency", "--no-run", "--message-format=json"])
        self.assertIn("--freq=997", calls[3])
        self.assertIn("--call-graph=dwarf,8192", calls[3])
        self.assertEqual(calls[3][-1], str(self.binary.resolve()))
        first = (DIAG.OUT / "profile/result.json").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "already attempted"):
            DIAG.profile()
        self.assertEqual((DIAG.OUT / "profile/result.json").read_bytes(), first)
        self.assertEqual(self.calls(), calls)

    def test_nonfailure_never_starts_a_profile(self):
        with patch.dict(os.environ, {"HOOK_BENCH_AUTHORITATIVE_OUTCOME": "success"}):
            self.profile()
        self.assertEqual(self.calls(), [])

    def test_invalid_measurement_never_starts_a_profile(self):
        DIAG.MEASUREMENT.write_text("{}")
        self.measurement = b"{}"
        self.profile()
        self.assertEqual(self.calls(), [])

    def test_missing_measurement_never_starts_a_profile(self):
        DIAG.MEASUREMENT.unlink()
        DIAG.profile()
        self.assertEqual(self.calls(), [])
        self.assertTrue(self.result()["authoritative_measurement_preserved"])

    def test_stale_measurement_never_starts_a_profile(self):
        self.before.write_text(json.dumps({"measurement_before_gate": "earlier-run-hash"}))
        self.profile()
        self.assertEqual(self.calls(), [])

    def test_missing_perf_is_explicit(self):
        Path("bin/perf").unlink()
        self.assertIn("not installed", self.profile()["reason"])
        self.assertEqual(self.calls(), [])

    def test_permission_denial_does_not_build_or_execute_benchmark(self):
        self.assertIn("permission unavailable", self.profile("denied")["reason"])
        self.assertEqual(len(self.calls()), 2)

    def test_permission_probe_has_real_deadline(self):
        started = time.monotonic()
        result = self.profile("permission-timeout", quick=True)
        self.assertEqual(result["commands"]["permission"]["reason"], "deadline")
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(self.calls()), 2)

    def test_ambiguous_binary_does_not_execute(self):
        self.assertIn("ambiguous", self.profile("ambiguous")["reason"])
        self.assertFalse(Path("executed").exists())

    def test_external_binary_does_not_execute(self):
        self.assertIn("outside", self.profile("outside")["reason"])
        self.assertFalse(Path("executed").exists())

    def test_failed_query_does_not_execute(self):
        self.assertIn("could not resolve", self.profile("query-failure")["reason"])
        self.assertFalse(Path("executed").exists())

    def test_invalid_query_does_not_execute(self):
        self.profile("invalid-json")
        self.assertFalse(Path("executed").exists())

    def test_record_failure_is_retained_without_retry(self):
        result = self.profile("record-failure")
        self.assertEqual(result["commands"]["record"]["exit_code"], 8)
        self.assertEqual(len([c for c in self.calls() if c[1] == "record"]), 1)

    def test_record_timeout_is_retained_without_retry(self):
        result = self.profile("record-timeout", quick=True)
        self.assertEqual(result["commands"]["record"]["reason"], "deadline")
        self.assertEqual(len([c for c in self.calls() if c[1] == "record"]), 1)

    def test_missing_data_does_not_claim_capture(self):
        result = self.profile("missing-data")
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(any(c[1] == "report" for c in self.calls()))

    def test_report_failure_is_explicit(self):
        result = self.profile("report-failure")
        self.assertEqual(result["status"], "report unavailable")
        self.assertEqual(result["commands"]["report"]["exit_code"], 6)

    def test_authoritative_measurement_tamper_fails(self):
        with self.assertRaisesRegex(RuntimeError, "modified the authoritative"):
            self.profile("tamper")
        self.assertFalse(self.result()["authoritative_measurement_preserved"])

    def test_metadata_is_allowlisted_and_records_unavailable_tools(self):
        with patch.dict(os.environ, {"SECRET_TEST_TOKEN": "must-not-appear", "GITHUB_RUN_ID": "owned-test"}):
            DIAG.snapshot("after")
        data = json.loads((DIAG.OUT / "after/metadata.json").read_text())
        self.assertEqual(data["environment"]["GITHUB_RUN_ID"], "owned-test")
        self.assertNotIn("SECRET_TEST_TOKEN", data["environment"])
        self.assertNotEqual(data["commands"]["kernel"]["reason"], "completed")
        self.assertFalse(any(b"must-not-appear" in p.read_bytes() for p in DIAG.OUT.rglob("*") if p.is_file()))
        self.assertEqual(DIAG.MEASUREMENT.read_bytes(), self.measurement)

    def test_capture_bounds_stream_bytes(self):
        capture = DIAG.Capture(DIAG.OUT / "flood", 5)
        result = capture.run("flood", [sys.executable, "-c", "import os; os.write(1, b'x' * 100000)"], 3, 1024)
        self.assertEqual(result["reason"], "output_limit")
        self.assertEqual((capture.directory / "flood.stdout").stat().st_size, 1024)
        self.assertIsNone(DIAG.ACTIVE)

    def test_capture_enforces_whole_step_deadline(self):
        capture = DIAG.Capture(DIAG.OUT / "deadline", 0.2)
        started = time.monotonic()
        result = capture.run("sleep", [sys.executable, "-c", "import time; time.sleep(60)"], 20)
        self.assertEqual(result["reason"], "deadline")
        result = capture.run("never", [sys.executable, "-c", "raise RuntimeError('must not run')"], 20)
        self.assertEqual(result["reason"], "whole_step_deadline")
        self.assertLess(time.monotonic() - started, 4)

    def test_timeout_stops_owned_descendant(self):
        # The descendant holds both pipes after its parent exits; the helper must kill it.
        code = ('import subprocess,sys; from pathlib import Path; '
                'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); '
                'Path("descendant.pid").write_text(str(p.pid))')
        capture = DIAG.Capture(DIAG.OUT / "descendant", 0.3)
        result = capture.run("tree", [sys.executable, "-c", code], 10)
        self.assertEqual(result["reason"], "deadline")
        pid = int(Path("descendant.pid").read_text())
        # Linux may retain an adopted zombie briefly; neither running nor sleeping is allowed.
        status = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True, check=False)
        self.assertTrue(status.returncode == 1 or status.stdout.strip().startswith("Z"), status.stdout)

    def test_child_generated_file_is_bounded(self):
        capture = DIAG.Capture(DIAG.OUT / "file-limit", 5)
        with patch.object(DIAG, "CHILD_FILE_LIMIT", 4096):
            result = capture.run("write", [sys.executable, "-c", "open('bounded.data', 'wb').write(b'x' * 100000)"], 3)
        self.assertNotEqual(result["exit_code"], 0)
        self.assertLessEqual(Path("bounded.data").stat().st_size, 4096)

    def test_outer_term_preserves_receipt_and_stops_owned_child(self):
        with patch.dict(os.environ, {"OBSERVER_TEST_MODE": "permission-timeout"}):
            helper = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "profile"],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 4
            while not any(c[:2] == ["perf", "stat"] for c in self.calls()):
                self.assertLess(time.monotonic(), deadline, "fixture did not reach permission probe")
                time.sleep(0.02)
            pid = int(Path("last-child.pid").read_text())
            helper.send_signal(signal.SIGTERM)
            stdout, stderr = helper.communicate(timeout=5)
            self.assertEqual(helper.returncode, 128 + signal.SIGTERM, (stdout, stderr))
            self.assertTrue(self.result()["authoritative_measurement_preserved"])
            self.assertEqual(self.result()["profile_executions"], 0)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            if helper.poll() is None:
                helper.send_signal(signal.SIGTERM)
                helper.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
