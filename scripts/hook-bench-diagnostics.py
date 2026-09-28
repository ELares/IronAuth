#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Bounded hosted-runner diagnostics; never a replacement benchmark verdict."""

import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import time


OUT = Path("target/hook-bench-diagnostics")
MEASUREMENT = Path("target/hook-bench-measurement.json")
ARTIFACT_LIMIT = 64 * 1024 * 1024
CHILD_FILE_LIMIT = 32 * 1024 * 1024
ACTIVE = None


def stop_group(process):
    """Stop only this helper's child process group, including lingering descendants."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for attempt in range(3):
            try:
                os.killpg(process.pid, sig)
                break
            except ProcessLookupError:
                break
            except PermissionError:
                # Darwin can report EPERM while an orphaned zombie group is reaped.
                # Retry briefly only after our leader exited; persistent denial is fatal.
                if process.poll() is None or attempt == 2:
                    raise
                time.sleep(0.05)
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    process.wait(timeout=2)


def on_signal(signum, _frame):
    if ACTIVE is not None:
        stop_group(ACTIVE)
    raise SystemExit(128 + signum)


def child_bounds():
    resource.setrlimit(resource.RLIMIT_FSIZE, (CHILD_FILE_LIMIT, CHILD_FILE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Capture:
    def __init__(self, directory, budget):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.end = time.monotonic() + budget

    def run(self, name, argv, seconds, stream_limit=64 * 1024):
        global ACTIVE
        result = {"argv": argv, "exit_code": None, "reason": "unavailable"}
        if time.monotonic() >= self.end:
            result["reason"] = "whole_step_deadline"
            return result
        deadline = min(self.end, time.monotonic() + seconds)
        with (self.directory / (name + ".stdout")).open("wb") as stdout, \
                (self.directory / (name + ".stderr")).open("wb") as stderr:
            try:
                process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True, preexec_fn=child_bounds)
            except OSError as error:
                result["reason"] = str(error)
                return result
            ACTIVE = process
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ, [stdout, 0])
            selector.register(process.stderr, selectors.EVENT_READ, [stderr, 0])
            reason = "completed"
            try:
                while selector.get_map():
                    if time.monotonic() >= deadline and reason == "completed":
                        reason = "deadline"
                        stop_group(process)
                    for key, _ in selector.select(0.05):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        target, count = key.data
                        remaining = max(0, stream_limit - count)
                        target.write(chunk[:remaining])
                        key.data[1] += len(chunk)
                        if len(chunk) > remaining and reason == "completed":
                            reason = "output_limit"
                            stop_group(process)
                try:
                    code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = "deadline"
                    stop_group(process)
                    code = process.returncode
            finally:
                # A child can exit while an independently running descendant remains.
                try:
                    stop_group(process)
                finally:
                    ACTIVE = None
                    selector.close()
                    process.stdout.close()
                    process.stderr.close()
            result.update(exit_code=code, reason=reason)
        size = sum(p.stat().st_size for p in OUT.rglob("*") if p.is_file())
        if size > ARTIFACT_LIMIT:
            raise RuntimeError("diagnostic artifact exceeds its 64 MiB ceiling")
        return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def snapshot(phase):
    capture = Capture(OUT / phase, 50)
    result = {"phase": phase, "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "environment": {k: os.environ.get(k) for k in (
                  "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_SHA",
                  "RUNNER_OS", "RUNNER_ARCH", "RUNNER_NAME", "ImageOS", "ImageVersion")},
              "commands": {}, "files": {}, "source_hashes": {}}
    if phase == "before":
        # Refuse a later profile if an earlier run left a measurement behind.
        result["measurement_before_gate"] = digest(MEASUREMENT) if MEASUREMENT.is_file() else None
    write_json(capture.directory / "metadata.json", result)
    commands = {"kernel": ["uname", "-a"], "cpu": ["lscpu", "--json"],
                "compiler": ["rustc", "-vV"], "cargo": ["cargo", "-V"],
                "toolchain": ["rustup", "show", "active-toolchain"], "cpu-count": ["nproc"],
                "affinity": ["taskset", "-pc", str(os.getpid())],
                "source": ["git", "rev-parse", "HEAD"]}
    for name, argv in commands.items():
        result["commands"][name] = capture.run(name, argv, 10)
        write_json(capture.directory / "metadata.json", result)
    for path in [Path("/proc/loadavg"), Path("/proc/stat"), Path("/proc/pressure/cpu")]:
        try:
            with path.open("rb") as stream:
                data = stream.read(65537)
            result["files"][str(path)] = {"text": data[:65536].decode(errors="replace"),
                                          "truncated": len(data) > 65536}
        except OSError as error:
            result["files"][str(path)] = {"unavailable": str(error)}
    governors = sorted(Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_governor"))
    for path in governors[:64]:
        try:
            with path.open("rb") as stream:
                result["files"][str(path)] = stream.read(128).decode(errors="replace")
        except OSError as error:
            result["files"][str(path)] = {"unavailable": str(error)}
    result["governor_paths_omitted"] = max(0, len(governors) - 64)
    for name in ("rust-toolchain.toml", "Cargo.lock", "Cargo.toml",
                 "scripts/hook-bench-gate.sh", "crates/ironauth-hooks/bench-config.toml",
                 "crates/ironauth-hooks/bench-baseline.json", "crates/ironauth-hooks/build.rs",
                 "crates/ironauth-hooks/src/engine.rs", "crates/ironauth-hooks/src/sandbox.rs",
                 "crates/ironauth-hooks/benches/hook_latency.rs",
                 "crates/ironauth-hooks/guests/good/src/lib.rs"):
        path = Path(name)
        result["source_hashes"][name] = digest(path) if path.is_file() else None
    write_json(capture.directory / "metadata.json", result)


def profile():
    capture = Capture(OUT / "profile", 165)
    if (capture.directory / "result.json").exists():
        raise RuntimeError("this job already attempted its one diagnostic profile")
    result = {"diagnostic_only": True, "performance_qualified": False, "commands": {},
              "profile_executions": 0, "status": "unavailable", "reason": "diagnostic did not complete"}
    measurement_before = MEASUREMENT.read_bytes() if MEASUREMENT.is_file() else None
    try:
        if os.environ.get("HOOK_BENCH_AUTHORITATIVE_OUTCOME") != "failure":
            result["reason"] = "authoritative gate did not fail"
            return
        before = json.loads((OUT / "before/metadata.json").read_text())
        if "measurement_before_gate" not in before or before["measurement_before_gate"] is not None:
            result["reason"] = "no clean pre-gate measurement provenance"
            return
        measured = json.loads(measurement_before) if measurement_before is not None else None
        if (not isinstance(measured, dict)
                or any(not isinstance(measured.get(k), str) or not measured[k] for k in ("machine", "runner_class"))
                or any(type(measured.get(k)) not in (float, int) or not math.isfinite(measured[k]) or measured[k] < 0
                       for k in ("cold_p95_micros", "warm_p95_micros"))
                or any(type(measured.get(k)) is not int or measured[k] <= 0
                       for k in ("cold_iterations", "warm_iterations"))):
            result["reason"] = "no completed authoritative measurement"
            return
        result["authoritative_measurement_sha256"] = hashlib.sha256(measurement_before).hexdigest()
        if shutil.which("perf") is None:
            result["reason"] = "perf is not installed; no privilege or system changes attempted"
            return
        result["commands"]["perf-version"] = capture.run("perf-version", ["perf", "--version"], 5)
        permission = capture.run("permission", ["perf", "stat", "-e", "task-clock", "--", "true"], 5)
        result["commands"]["permission"] = permission
        if permission["exit_code"] != 0 or permission["reason"] != "completed":
            result["reason"] = "perf sampling permission unavailable"
            return
        query = capture.run("build-metadata", ["cargo", "bench", "-p", "ironauth-hooks", "--bench",
                            "hook_latency", "--no-run", "--message-format=json"], 45, 1024 * 1024)
        result["commands"]["build-metadata"] = query
        if query["exit_code"] != 0 or query["reason"] != "completed":
            result["reason"] = "could not resolve the existing benchmark executable"
            return
        binaries = set()
        for line in (capture.directory / "build-metadata.stdout").read_text().splitlines():
            item = json.loads(line)
            if (item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "hook_latency"
                    and "bench" in item.get("target", {}).get("kind", []) and item.get("executable")):
                binaries.add(Path(item["executable"]).resolve())
        if len(binaries) != 1:
            result["reason"] = "benchmark executable missing or ambiguous"
            return
        binary = binaries.pop()
        if not binary.is_relative_to(Path("target/release/deps").resolve()) or not os.access(binary, os.X_OK):
            result["reason"] = "benchmark executable outside the expected release directory"
            return
        result["executable"] = {"path": str(binary), "sha256": digest(binary)}
        data = capture.directory / "perf.data"
        result["profile_executions"] = 1
        recording = capture.run("record", ["perf", "record", "--freq=997", "--call-graph=dwarf,8192",
                                 "-o", str(data), "--", str(binary)], 90, 1024 * 1024)
        result["commands"]["record"] = recording
        if recording["exit_code"] != 0 or recording["reason"] != "completed" or not data.is_file() or not data.stat().st_size:
            result["reason"] = "profile failed, timed out, exceeded a bound or produced no data"
            return
        result["profile"] = {"bytes": data.stat().st_size, "sha256": digest(data)}
        report = capture.run("report", ["perf", "report", "--stdio", "-i", str(data)], 15, 2 * 1024 * 1024)
        result["commands"]["report"] = report
        result["status"] = "captured" if report["exit_code"] == 0 and report["reason"] == "completed" else "report unavailable"
        result.pop("reason")
        result["interpretation"] = "Sampling quality and warm-path attribution require inspection; this is not a replacement gate result."
    except (OSError, ValueError, RuntimeError) as error:
        result["reason"] = str(error)
    finally:
        unchanged = (MEASUREMENT.read_bytes() if MEASUREMENT.is_file() else None) == measurement_before
        result["authoritative_measurement_preserved"] = unchanged
        write_json(capture.directory / "result.json", result)
        if not unchanged:
            raise RuntimeError("diagnostic modified the authoritative measurement")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    if sys.argv[1:] in (["snapshot", "before"], ["snapshot", "after"]):
        snapshot(sys.argv[2])
    elif sys.argv[1:] == ["profile"]:
        profile()
    else:
        raise SystemExit("usage: hook-bench-diagnostics.py snapshot before|after | profile")
