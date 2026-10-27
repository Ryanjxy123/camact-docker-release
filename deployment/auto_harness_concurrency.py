"""Review a completed four-Harness User before authorizing six-Harness dispatch.

This observer makes no model requests and never reads credentials or raw traces.
It changes only the existing scheduler's hot-reloaded outer concurrency policy.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import fcntl
import json
import math
import os
from pathlib import Path
import subprocess
import time

from preflight_full_benchmark import read, write, now

TERMINAL = {'historical_scored', 'scored', 'infrastructure_error'}
GIB = 1024 ** 3


def quantile(values, fraction):
    values = sorted(v for v in values if v is not None)
    return values[min(len(values) - 1, math.ceil(fraction * len(values)) - 1)] if values else None


def machine():
    cpu = [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    quota = Path('/sys/fs/cgroup/cpu/cpu.cfs_quota_us')
    period = Path('/sys/fs/cgroup/cpu/cpu.cfs_period_us')
    cores = len(os.sched_getaffinity(0))
    if quota.is_file() and period.is_file() and int(quota.read_text()) > 0:
        cores = min(cores, int(quota.read_text()) / int(period.read_text()))
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        memory[key] = int(value.split()[0]) * 1024
    limit = Path('/sys/fs/cgroup/memory/memory.limit_in_bytes')
    used = Path('/sys/fs/cgroup/memory/memory.usage_in_bytes')
    headroom = int(limit.read_text()) - int(used.read_text()) if limit.is_file() and used.is_file() else None
    return dict(cpu=cpu, effective_cores=cores, host_cores=os.cpu_count(),
                memory_available_bytes=memory['MemAvailable'], cgroup_memory_headroom_bytes=headroom,
                swap_used_bytes=memory.get('SwapTotal', 0) - memory.get('SwapFree', 0))


def live_task_counts(manifest):
    counts = Counter()
    seen = set()
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    for slot in manifest['tasks']:
        if slot.get('status') != 'running' or not slot.get('attempts'):
            continue
        identity = slot['attempts'][-1].get('worker_identity') or {}
        pid = identity.get('pid')
        if not pid or pid in seen or identity.get('boot_id') != boot:
            continue
        try:
            stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            if stat[0] != 'Z' and int(stat[19]) == identity.get('start_ticks'):
                counts[slot['harness']] += 1
                seen.add(pid)
        except OSError:
            continue
    return dict(counts)


def review(samples, slots, remaining_slots, archive_bytes, current, criteria):
    """Use measured overlap, resource headroom and remaining artifact budget."""
    reasons = []
    if not slots or not all(s['status'] in TERMINAL for s in slots):
        return dict(eligible=False, reasons=['validation_user_not_complete'])
    def is_loaded(row):
        return len(row['active_counts']) >= 4 and sum(row['active_counts'].values()) >= 16
    loaded = [r for r in samples if is_loaded(r)]
    overlap_seconds = 0
    for before, after in zip(samples, samples[1:]):
        gap = (dt.datetime.fromisoformat(after['timestamp']) - dt.datetime.fromisoformat(before['timestamp'])).total_seconds()
        if is_loaded(before) and is_loaded(after) and 0 < gap <= 45:
            overlap_seconds += gap
    peak = max((sum(r['active_counts'].values()) for r in samples), default=0)
    if peak < 20 or overlap_seconds < criteria['min_loaded_seconds']:
        reasons.append('insufficient_measured_four_harness_load')
    busy = quantile([r.get('busy_cores') for r in loaded], .95)
    iowait = quantile([r.get('iowait_percent') for r in loaded], .95)
    cores = current['effective_cores']
    latest_busy = current.get('busy_cores')
    if (busy is None or busy * 1.5 > cores * criteria['cpu_quota_fraction'] or
            latest_busy is not None and latest_busy * 1.5 > cores * criteria['cpu_quota_fraction']):
        reasons.append('cpu_headroom_for_thirty_tasks_insufficient_or_unknown')
    if (iowait is None or iowait > criteria['max_iowait_percent'] or
            current.get('iowait_percent', 0) > criteria['max_iowait_percent']):
        reasons.append('io_wait_high_or_unknown')
    memory = min([current['memory_available_bytes']] + [r['memory_available_bytes'] for r in loaded])
    if memory < criteria['min_memory_gib'] * GIB:
        reasons.append('host_memory_headroom_low')
    cg_memory = [r['cgroup_memory_headroom_bytes'] for r in loaded + [current]
                 if r.get('cgroup_memory_headroom_bytes') is not None]
    if cg_memory and min(cg_memory) < criteria['min_cgroup_memory_gib'] * GIB:
        reasons.append('container_memory_headroom_low')
    if max([current['swap_used_bytes']] + [r['swap_used_bytes'] for r in loaded]) > GIB:
        reasons.append('swap_pressure')
    windows = [r.get('api_statuses', {}) for r in loaded] + [current.get('api_statuses', {})]
    worst_error_rate = 0
    max_successes = 0
    for counts in windows:
        total = sum(counts.values())
        errors = sum(n for code, n in counts.items() if code == 'timeout' or code.isdigit() and int(code) >= 400)
        worst_error_rate = max(worst_error_rate, errors / max(1, total))
        max_successes = max(max_successes, counts.get('200', 0))
    if max_successes < criteria['min_window_successes'] or worst_error_rate > criteria['max_api_error_rate']:
        reasons.append('api_window_unhealthy_or_insufficient')
    if current.get('api_window_age_seconds', float('inf')) > 90:
        reasons.append('latest_api_observation_stale')
    infrastructure_rate = sum(s['status'] == 'infrastructure_error' for s in slots) / len(slots)
    if infrastructure_rate > criteria['max_infrastructure_rate']:
        reasons.append('validation_user_infrastructure_error_rate_high')
    free = current['disk_free_bytes']
    consumed = max(archive_bytes, samples[0]['disk_free_bytes'] - free if samples else 0)
    required = consumed / len(slots) * remaining_slots + criteria['disk_reserve_gib'] * GIB
    if free < max(criteria['min_disk_free_gib'] * GIB, required):
        reasons.append('remaining_disk_budget_insufficient')
    return dict(eligible=not reasons, reasons=reasons, peak_tasks=peak,
                loaded_overlap_seconds=round(overlap_seconds), p95_busy_cores=busy,
                p95_iowait_percent=iowait, effective_cpu_cores=cores,
                min_memory_available_gib=memory / GIB,
                min_container_headroom_gib=min(cg_memory) / GIB if cg_memory else None,
                worst_observed_api_window_error_rate=worst_error_rate,
                max_observed_window_successes=max_successes,
                infrastructure_error_rate=infrastructure_rate,
                free_disk_gib=free / GIB, projected_remaining_disk_and_reserve_gib=required / GIB,
                remaining_slots=remaining_slots,
                disk_projection_limitation='Linear estimate using max(User allocated artifacts, shared disk decrease); not a capacity guarantee.')


def promote(archive, expected_policy, decision, audit):
    if (not decision.get('eligible') or expected_policy.get('max_tasks_per_harness') != 5 or
            expected_policy.get('max_parallel_users') != 1 or expected_policy.get('max_parallel_harnesses') != 4):
        return False
    with (archive / 'scheduler_policy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if read(archive / 'scheduler_policy.json') != expected_policy:
            return False
        policy = json.loads(json.dumps(expected_policy))
        policy.update(max_parallel_harnesses=6, revision='20261025-six-harnesses-after-reviewed-user', changed_at=now())
        policy['auto_promotion'].update(status='promoted', decision_file=str(audit / 'promotion.json'))
        write(audit / 'promotion.json', dict(timestamp=now(), decision=decision,
                                           previous_policy=expected_policy, promoted_policy=policy))
        write(archive / 'scheduler_policy.json', policy)
        return True


def observe(archive):
    audit = archive / 'audit/harness_autoscale_6_20261025'
    with (audit / 'observer.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        identity = dict(pid=os.getpid(), start_ticks=int(Path(f'/proc/{os.getpid()}/stat').read_text().rsplit(')', 1)[1].split()[19]),
                        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        write(audit / 'observer.json', dict(timestamp=now(), identity=identity, status='running'))
        samples_path = audit / 'samples.jsonl'
        samples = {}
        if samples_path.is_file():
            for line in samples_path.read_text().splitlines():
                try:
                    row = json.loads(line)
                    samples.setdefault(row['user_id'], []).append(row)
                except (ValueError, KeyError):
                    continue
        reviewed = read(audit / 'reviewed_users.json') if (audit / 'reviewed_users.json').is_file() else {}
        previous = None
        while True:
            policy = read(archive / 'scheduler_policy.json')
            automatic = policy.get('auto_promotion', {})
            if (automatic.get('status') != 'enabled' or policy.get('max_parallel_harnesses') != 4 or
                    policy.get('max_tasks_per_harness') != 5 or policy.get('max_parallel_users') != 1):
                write(audit / 'observer.json', dict(timestamp=now(), identity=identity, status='policy_no_longer_pending'))
                return
            manifest = read(archive / 'run_manifest.json')
            if manifest.get('benchmark_complete'):
                write(audit / 'observer.json', dict(timestamp=now(), identity=identity, status='benchmark_finished'))
                return
            eligible_users = manifest['users'][manifest['users'].index(automatic['validation_user']):]
            user = manifest.get('active_user')
            current = machine()
            disk = os.statvfs(archive)
            current['disk_free_bytes'] = disk.f_bavail * disk.f_frsize
            current['api_statuses'] = manifest.get('resource_state', {}).get('api_statuses', {})
            stamp = manifest.get('resource_state', {}).get('timestamp')
            current['api_window_age_seconds'] = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(stamp)).total_seconds() if stamp else float('inf')
            if previous:
                changes = [a - b for a, b in zip(current['cpu'], previous['cpu'])]
                total = sum(changes)
                if total > 0 and all(x >= 0 for x in changes):
                    current['busy_cores'] = (total - changes[3] - changes[4]) / total * current['host_cores']
                    current['iowait_percent'] = changes[4] / total * 100
            if user in eligible_users and manifest['status'] == 'running':
                row = dict(timestamp=now(), user_id=user, **current,
                           active_counts=live_task_counts(manifest),
                           api_window_timestamp=manifest.get('resource_state', {}).get('timestamp'))
                samples.setdefault(user, []).append(row)
                with samples_path.open('a') as stream:
                    stream.write(json.dumps(row) + '\n')
                    stream.flush()
                    os.fsync(stream.fileno())
            previous = current
            for candidate in eligible_users:
                slots = [s for s in manifest['tasks'] if s['user_id'] == candidate]
                if candidate in reviewed or not slots or not all(s['status'] in TERMINAL for s in slots):
                    continue
                if manifest['status'] != 'running' or manifest.get('dispatch_fault'):
                    continue
                result = subprocess.run(['du', '-sk', str(archive / 'users' / candidate)], capture_output=True, text=True)
                if result.returncode:
                    continue
                allocated = int(result.stdout.split()[0]) * 1024
                remaining = sum(s['status'] not in TERMINAL for s in manifest['tasks'])
                decision = review(samples.get(candidate, []), slots, remaining, allocated, current, automatic['criteria'])
                decision.update(timestamp=now(), validation_user=candidate)
                write(audit / 'reviews' / f'{candidate}.json', decision)
                reviewed[candidate] = decision
                write(audit / 'reviewed_users.json', reviewed)
                if decision['eligible'] and promote(archive, policy, decision, audit):
                    write(audit / 'observer.json', dict(timestamp=now(), identity=identity, status='promoted_to_six', validation_user=candidate))
                    return
            write(audit / 'observer.json', dict(timestamp=now(), identity=identity,
                  status='waiting_for_completed_four_harness_user', validation_user=automatic['validation_user'],
                  active_user=user, reviewed_users=list(reviewed)))
            time.sleep(15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    archive = args.archive.resolve()
    while True:
        try:
            observe(archive)
            return
        except Exception as exc:
            # Exception text is deliberately omitted; credentials are never needed.
            write(archive / 'audit/harness_autoscale_6_20261025/observer_error.json',
                  dict(timestamp=now(), error_type=type(exc).__name__, retry_seconds=30))
            time.sleep(30)


if __name__ == '__main__':
    main()
