#!/usr/bin/env python3
"""Bound one real chaos invocation and retain safe, failure-only stage evidence."""
import argparse
import datetime
import email.utils
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import urllib.request

COMMAND = ['cargo', 'test', '-p', 'ironauth-store', '--features', 'testing,ironbus', '--test', 'outbox_chaos', '--', '--test-threads=1']
JOB_SECONDS, RESERVE_SECONDS, STEP_SECONDS = 1800, 120, 600
OUTPUT_BYTES, LEDGER_BYTES = 8 * 1024 * 1024, 1024 * 1024


def private_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def parse_stat(raw):
    # Linux proc_pid_stat fields3,4,5,22. comm can contain spaces and parentheses.
    pid = int(raw.split(' ', 1)[0])
    end = raw.rfind(') ')
    if end < 0:
        raise ValueError('invalid proc stat')
    fields = raw[end+2:].split()
    return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]), 'pgid': int(fields[2]), 'start': int(fields[19])}


def process_snapshot():
    values = {}
    entries = list(Path('/proc').iterdir())
    if len(entries) > 16384:
        raise ValueError('process census exceeds bound')
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            values[int(entry.name)] = parse_stat((entry/'stat').read_text())
        except (FileNotFoundError, ProcessLookupError):
            pass  # Process exited during this single census.
    return values


def identity(row):
    return row['pid'], row['start']


def register_descendants(snapshot, known):
    changed = True
    while changed:
        changed = False
        for row in snapshot.values():
            parent = snapshot.get(row['ppid'])
            if identity(row) not in known and parent and identity(parent) in known:
                known[identity(row)] = row.copy()
                changed = True


def owned_groups(snapshot, known):
    groups = sorted({r['pgid'] for r in snapshot.values() if identity(r) in known and r['state'] != 'Z'})
    for group in groups:
        members = [r for r in snapshot.values() if r['pgid'] == group and r['state'] != 'Z']
        if group <= 1 or any(identity(r) not in known for r in members):
            raise ValueError('refuse cleanup of an unproven or reused process group')
    return groups


def cleanup(process, known, snapshot_fn=process_snapshot, kill_group=os.killpg):
    results = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        rows = snapshot_fn()
        register_descendants(rows, known)
        for group in owned_groups(rows, known):
            try:
                kill_group(group, sig)
                results.append({'pgid': group, 'signal': sig.name, 'sent': True})
            except ProcessLookupError:
                results.append({'pgid': group, 'signal': sig.name, 'already_exited': True})
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        if sig == signal.SIGTERM:
            time.sleep(0.1)
    rows = snapshot_fn()
    alive = [r for r in rows.values() if identity(r) in known and r['state'] != 'Z']
    if alive:
        raise ValueError('owned process cleanup did not complete')
    process.wait(timeout=1)
    return results


def clock_from_response(jobs, headers, mono_before, mono_after, now_wall, run, attempt, head, boot):
    if mono_after < mono_before or mono_after-mono_before > 10:
        raise ValueError('job-clock request exceeded bound')
    server = email.utils.parsedate_to_datetime(headers['Date']).timestamp()
    if abs(now_wall-server) > 30 or int(headers.get('Age', '0')) != 0:
        raise ValueError('job-clock response time is not fresh')
    if jobs['total_count'] > 100:
        raise ValueError('job pagination exceeds clock observer scope')
    found = [j for j in jobs['jobs'] if j['name'] == 'outbox (ironbus mode)' and j['run_id'] == run and j['run_attempt'] == attempt and j['head_sha'] == head and j['status'] == 'in_progress']
    if len(found) != 1:
        raise ValueError('current outbox job is not uniquely bound')
    job = found[0]
    started = datetime.datetime.fromisoformat(job['started_at'].replace('Z', '+00:00')).timestamp()
    # Subtract RTT and two seconds of HTTP Date precision, never extend the budget.
    remaining = JOB_SECONDS-(server-started)-(mono_after-mono_before)-2
    if remaining <= RESERVE_SECONDS or remaining > JOB_SECONDS:
        raise ValueError('job has insufficient diagnostic reserve')
    return {'schema': 1, 'job': job['id'], 'run': run, 'attempt': attempt, 'head': head, 'boot': boot, 'observed_monotonic': mono_after, 'job_deadline_monotonic': mono_after+remaining, 'job_started_at': job['started_at'], 'server_date': headers['Date'], 'request_seconds': mono_after-mono_before}


def save_clock(path):
    run, attempt = int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT'])
    head = os.environ['IRONAUTH_CI_HEAD']
    if not re.fullmatch('[0-9a-f]{40}', head):
        raise ValueError('invalid head')
    url = f'https://api.github.com/repos/ELares/IronAuth/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100'
    request = urllib.request.Request(url, headers={'Authorization': 'Bearer '+os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json', 'Cache-Control': 'no-cache'})
    before = time.monotonic()
    with urllib.request.urlopen(request, timeout=8) as response:
        raw = response.read(1024*1024+1)
        if len(raw) > 1024*1024:
            raise ValueError('job-clock response exceeds bound')
        value = clock_from_response(json.loads(raw), response.headers, before, time.monotonic(), time.time(), run, attempt, head, boot_id())
    private_json(path, value)


def step_budget(clock, now, boot):
    if clock['schema'] != 1 or clock['boot'] != boot or now < clock['observed_monotonic']:
        raise ValueError('clock provenance changed')
    seconds = min(STEP_SECONDS, clock['job_deadline_monotonic']-RESERVE_SECONDS-now)
    if seconds <= 0:
        raise ValueError('job diagnostic reserve reached before chaos')
    return seconds


class Interrupted(Exception):
    pass


def run_once(command, directory, seconds, snapshot_fn=process_snapshot, kill_group=os.killpg, clock_evidence=None, require_stages=False):
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    if clock_evidence is not None:
        private_json(directory/'job-clock.json', clock_evidence)
    ledger = directory/'stages.jsonl'
    ledger.touch(mode=0o600)
    env = os.environ.copy()
    env['IRONAUTH_CHAOS_STAGE_FILE'] = str(ledger.resolve())
    start, known, size, reason = time.monotonic(), {}, 0, 'completed'
    process, selector, clean, cleanup_result = None, None, False, []
    error_type = None
    previous_handlers = {}

    def interrupted(signum, _frame):
        raise Interrupted(str(signum))

    # Logs go to a capped regular file, never a potentially blocked console pipe.
    # Register signal cleanup before spawning the one owned command.
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[sig] = signal.signal(sig, interrupted)
    try:
        with (directory/'command.log').open('xb') as log:
            process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            rows = snapshot_fn()
            root = rows.get(process.pid)
            if not root or root['pgid'] != process.pid:
                raise ValueError('cannot bind owned command process start')
            known[identity(root)] = root
            register_descendants(rows, known)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                rows = snapshot_fn()
                register_descendants(rows, known)
                if ledger.stat().st_size > LEDGER_BYTES:
                    reason = 'ledger_limit'
                    break
                if time.monotonic()-start >= seconds:
                    reason = 'deadline'
                    break
                for key, _ in selector.select(0.05):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    room = max(0, OUTPUT_BYTES-size)
                    log.write(chunk[:room])
                    log.flush()
                    size += len(chunk)
                    if len(chunk) > room:
                        reason = 'output_limit'
                        break
                if reason != 'completed' or (process.poll() is not None and not selector.get_map()):
                    break
    except Interrupted:
        reason = 'interrupted'
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        reason, error_type = 'observer_failed', type(error).__name__
    finally:
        # Repeated runner signals cannot interrupt the bounded owned cleanup.
        for sig in previous_handlers:
            signal.signal(sig, signal.SIG_IGN)
        if selector:
            selector.close()
        if process and process.stdout:
            process.stdout.close()
        if process:
            try:
                if not known:
                    # The unreaped Popen handle proves this direct child, not an
                    # arbitrary PID. Descendant ownership remains unconfirmed.
                    process.kill()
                    process.wait(timeout=2)
                    raise ValueError('descendant ownership not established')
                rows = snapshot_fn()
                register_descendants(rows, known)
                if reason == 'completed' and any(identity(r) in known and r['state'] != 'Z' for r in rows.values()):
                    reason = 'descendant_leak'
                cleanup_result = cleanup(process, known, snapshot_fn, kill_group)
                clean = True
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                cleanup_result.append({'error_type': type(error).__name__})
                # A failed later census must not strand our unreaped direct child.
                # This handle does not authorize signalling unproven descendants.
                if process.poll() is None:
                    try:
                        process.kill()
                        process.wait(timeout=2)
                        cleanup_result.append({'direct_child_reaped': True, 'descendant_cleanup_unconfirmed': True})
                    except (OSError, subprocess.TimeoutExpired) as direct_error:
                        cleanup_result.append({'direct_child_error_type': type(direct_error).__name__})
        else:
            clean = True  # No process was created.
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
        if require_stages and reason == 'completed' and process and process.poll() == 0:
            try:
                if ledger.stat().st_size > LEDGER_BYTES:
                    raise ValueError('stage ledger exceeds bound')
                labels = [json.loads(line)['stage'] for line in ledger.read_text().splitlines()]
                if 'test.assertions.end' not in labels or not labels or labels[-1] != 'broker.drop.end':
                    reason = 'required_stage_evidence_missing'
            except (OSError, ValueError, KeyError, TypeError):
                reason = 'required_stage_evidence_invalid'
        result = {'command': command, 'invocations': int(process is not None), 'reason': reason, 'error_type': error_type,
                  'exit_code': process.poll() if process else None, 'seconds': time.monotonic()-start,
                  'budget_seconds': seconds, 'output_bytes_observed': size,
                  'observed_process_cleanup_complete': clean, 'cleanup': cleanup_result,
                  'owned_processes': list(known.values()),
                  'ownership_scope': 'observed process start identities and descendant chains; service databases remain job-owned',
                  'forced_test_database_cleanup_unconfirmed': reason != 'completed'}
        result['passed'] = reason == 'completed' and result['exit_code'] == 0 and clean
        private_json(directory/'result.json', result)
    return 0 if result['passed'] else (result['exit_code'] if isinstance(result['exit_code'], int) and result['exit_code'] > 0 else 1)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['clock', 'run'])
    parser.add_argument('--clock', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.mode == 'clock':
        save_clock(args.clock)
        return 0
    if args.output is None:
        parser.error('--output required for run')
    clock = json.loads(args.clock.read_text())
    if clock['run'] != int(os.environ['GITHUB_RUN_ID']) or clock['attempt'] != int(os.environ['GITHUB_RUN_ATTEMPT']) or clock['head'] != os.environ['IRONAUTH_CI_HEAD']:
        raise ValueError('job clock binding changed')
    try:
        budget = step_budget(clock, time.monotonic(), boot_id())
    except ValueError:
        args.output.mkdir(mode=0o700)
        private_json(args.output/'job-clock.json', clock)
        private_json(args.output/'result.json', {'passed': False, 'invocations': 0, 'reason': 'clock_or_remaining_budget_refused', 'processes_started': False})
        return 1
    return run_once(COMMAND, args.output, budget, clock_evidence=clock, require_stages=True)


if __name__ == '__main__':
    sys.exit(main())
