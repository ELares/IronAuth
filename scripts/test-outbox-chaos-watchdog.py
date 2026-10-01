#!/usr/bin/env python3
"""Focused observer checks; no broker, database, HTTP request or cargo test."""
import copy
import datetime
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

SPEC = importlib.util.spec_from_file_location('watchdog', Path(__file__).with_name('outbox-chaos-watchdog.py'))
WATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WATCH)


def row(pid, parent, group, start=100, state='S'):
    return {'pid': pid, 'ppid': parent, 'pgid': group, 'start': start, 'state': state}


class JobClock(unittest.TestCase):
    def setUp(self):
        self.jobs = {'total_count': 1, 'jobs': [{'id': 8, 'name': 'outbox (ironbus mode)', 'run_id': 7, 'run_attempt': 2, 'head_sha': 'a'*40, 'status': 'in_progress', 'started_at': '2026-09-29T00:00:00Z'}]}
        self.headers = {'Date': 'Tue, 29 Sep 2026 00:05:00 GMT'}
        self.wall = datetime.datetime(2026, 9, 29, 0, 5, tzinfo=datetime.timezone.utc).timestamp()

    def clock(self, jobs=None, headers=None, after=101):
        return WATCH.clock_from_response(jobs or self.jobs, headers or self.headers, 100, after, self.wall, 7, 2, 'a'*40, 'boot')

    def test_actual_job_elapsed_and_reserved_cleanup_bound(self):
        clock = self.clock()
        self.assertEqual(clock['job_deadline_monotonic'], 1598)
        self.assertEqual(WATCH.step_budget(clock, 101, 'boot'), 600)
        self.assertEqual(WATCH.step_budget(clock, 1400, 'boot'), 78)
        with self.assertRaises(ValueError): WATCH.step_budget(clock, 1478, 'boot')
        with self.assertRaises(ValueError): WATCH.step_budget(clock, 100, 'boot')
        with self.assertRaises(ValueError): WATCH.step_budget(clock, 101, 'reboot')

    def test_stale_ambiguous_foreign_or_slow_clock_fails_closed(self):
        for field, bad in [('run_id', 9), ('run_attempt', 3), ('head_sha', 'b'*40), ('status', 'completed'), ('name', 'unrelated')]:
            with self.subTest(field=field):
                jobs = copy.deepcopy(self.jobs); jobs['jobs'][0][field] = bad
                with self.assertRaises(ValueError): self.clock(jobs)
        duplicate = copy.deepcopy(self.jobs); duplicate['jobs'] *= 2
        with self.assertRaises(ValueError): self.clock(duplicate)
        with self.assertRaises(ValueError): self.clock(headers=self.headers | {'Age': '1'})
        with self.assertRaises(ValueError): self.clock(headers={'Date': 'Tue, 29 Sep 2026 00:04:00 GMT'})
        with self.assertRaises(ValueError): self.clock(after=111)
        jobs = copy.deepcopy(self.jobs); jobs['jobs'][0]['started_at'] = '2026-09-28T23:35:00Z'
        with self.assertRaises(ValueError): self.clock(jobs)


class ProcessOwnership(unittest.TestCase):
    def test_stat_start_identity_and_descendants_across_groups(self):
        raw = '10 (name with ) spaces) S 9 10 ' + '0 '*16 + '1234 0 0'
        self.assertEqual(WATCH.parse_stat(raw), row(10, 9, 10, 1234))
        known = {(10, 100): row(10, 9, 10)}
        snapshot = {10: row(10, 9, 10), 11: row(11, 10, 11), 12: row(12, 11, 11), 99: row(99, 8, 99)}
        WATCH.register_descendants(snapshot, known)
        self.assertEqual(WATCH.owned_groups(snapshot, known), [10, 11])
        self.assertNotIn((99, 100), known)

    def test_reused_pid_or_unrelated_group_is_never_authority(self):
        known = {(10, 100): row(10, 9, 10)}
        reused = {10: row(10, 9, 10, 200), 11: row(11, 10, 10, 201)}
        WATCH.register_descendants(reused, known)
        self.assertEqual(WATCH.owned_groups(reused, known), [])
        shared = {10: row(10, 9, 10), 99: row(99, 8, 10)}
        with self.assertRaises(ValueError): WATCH.owned_groups(shared, known)
        orphan = {11: row(11, 1, 11)}
        WATCH.register_descendants(orphan, known)
        self.assertNotIn((11, 100), known)

    def test_cleanup_refuses_foreign_group_before_sending_signal(self):
        known = {(10, 100): row(10, 9, 10)}
        with patch.object(WATCH.os, 'killpg') as kill:
            with self.assertRaises(ValueError):
                WATCH.cleanup(None, known, lambda: {10: row(10, 9, 10), 99: row(99, 8, 10)}, kill)
            kill.assert_not_called()


class BoundedInvocation(unittest.TestCase):
    """Use real subprocess I/O/deadlines; portable tests model the proc census.

    Linux additionally exercises the actual /proc identity and cleanup below.
    """
    def run_fixture(self, script, seconds=1, broken_census=False, output_limit=None, interrupt=False, later_census_failure=False, require_stages=False):
        with tempfile.TemporaryDirectory(prefix='outbox-watchdog-test-') as directory:
            output = Path(directory)/'evidence'
            spawned = []
            popen = subprocess.Popen

            def spawn(*args, **kwargs):
                process = popen(*args, **kwargs); spawned.append(process); return process

            observations = 0

            def snapshot():
                nonlocal observations
                observations += 1
                if interrupt and observations == 2:
                    os.kill(os.getpid(), signal.SIGTERM)
                if broken_census or (later_census_failure and observations > 1):
                    raise OSError('unavailable fixture census')
                return {p.pid: row(p.pid, os.getpid(), p.pid, 123) for p in spawned if p.poll() is None}

            with patch.object(WATCH.subprocess, 'Popen', side_effect=spawn):
                with patch.object(WATCH, 'OUTPUT_BYTES', output_limit or WATCH.OUTPUT_BYTES):
                    code = WATCH.run_once([sys.executable, '-c', script], output, seconds, snapshot_fn=snapshot, require_stages=require_stages)
            self.assertEqual(len(spawned), 1)
            self.assertTrue(all(p.poll() is not None for p in spawned))
            result = json.loads((output/'result.json').read_text())
            result['retained_bytes'] = (output/'command.log').stat().st_size
            return code, result

    def test_one_success_and_original_nonzero_are_preserved(self):
        code, result = self.run_fixture('print("fixture success")')
        self.assertEqual(code, 0); self.assertTrue(result['passed']); self.assertEqual(result['invocations'], 1)
        code, result = self.run_fixture('raise SystemExit(17)')
        self.assertEqual(code, 17); self.assertFalse(result['passed'])

    def test_success_requires_real_chaos_stage_completion_when_enabled(self):
        code, result = self.run_fixture('print("SKIPPED: no broker")', require_stages=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(result['reason'], 'required_stage_evidence_missing')
        script = 'import json,os; f=open(os.environ["IRONAUTH_CHAOS_STAGE_FILE"],"a"); [f.write(json.dumps({"stage":s})+"\\n") for s in ["test.assertions.end","broker.drop.end"]]; f.close()'
        code, result = self.run_fixture(script, require_stages=True)
        self.assertEqual(code, 0)
        self.assertTrue(result['passed'])

    def test_stall_is_failed_once_and_owned_child_is_reaped(self):
        start = time.monotonic()
        code, result = self.run_fixture('import time; time.sleep(60)', seconds=.1)
        self.assertLess(time.monotonic()-start, 4)
        self.assertNotEqual(code, 0); self.assertEqual(result['reason'], 'deadline')
        self.assertTrue(result['observed_process_cleanup_complete'])
        self.assertTrue(result['forced_test_database_cleanup_unconfirmed'])

    def test_output_is_capped_and_failure_not_retried(self):
        code, result = self.run_fixture('print("x"*4096)', output_limit=64)
        self.assertNotEqual(code, 0); self.assertEqual(result['reason'], 'output_limit')
        self.assertEqual(result['retained_bytes'], 64); self.assertEqual(result['invocations'], 1)

    def test_initial_census_failure_still_reaps_created_child(self):
        code, result = self.run_fixture('import time; time.sleep(60)', broken_census=True)
        self.assertNotEqual(code, 0); self.assertEqual(result['reason'], 'observer_failed')
        self.assertFalse(result['observed_process_cleanup_complete'])

    def test_later_census_failure_stops_direct_child_without_claiming_descendants(self):
        code, result = self.run_fixture('import time; time.sleep(60)', later_census_failure=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(result['reason'], 'observer_failed')
        self.assertFalse(result['observed_process_cleanup_complete'])
        self.assertTrue(any(r.get('direct_child_reaped') for r in result['cleanup']))

    def test_actual_interrupt_runs_cleanup_and_restores_signal_handler(self):
        before = signal.getsignal(signal.SIGTERM)
        code, result = self.run_fixture('import time; time.sleep(60)', interrupt=True)
        self.assertNotEqual(code, 0)
        self.assertEqual(result['reason'], 'interrupted')
        self.assertTrue(result['observed_process_cleanup_complete'])
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual /proc ownership is Linux-only; portable process/deadline tests run above')
    def test_actual_linux_process_identity_deadline_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='outbox-watchdog-linux-') as directory:
            output = Path(directory)/'evidence'
            code = WATCH.run_once([sys.executable, '-c', 'import subprocess,sys,time; subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True); time.sleep(60)'], output, .3)
            result = json.loads((output/'result.json').read_text())
            self.assertNotEqual(code, 0)
            self.assertEqual(result['reason'], 'deadline')
            self.assertTrue(result['observed_process_cleanup_complete'])
            self.assertEqual(len(result['owned_processes']), 2)
            self.assertGreater(result['owned_processes'][0]['start'], 0)


if __name__ == '__main__': unittest.main()
