"""Independent, credential-free resource samples for a dated benchmark archive."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import time


def sample(root: Path) -> dict:
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        memory[key] = int(value.split()[0]) * 1024
    processes = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit():
            continue
        try:
            # Never record argv or environment: other workloads may contain secrets.
            command = (proc / 'comm').read_text().strip()
            cwd = (proc / 'cwd').resolve()
            if not cwd.is_relative_to(root):
                continue
            status = (proc / 'status').read_text().splitlines()
            rss = next((int(s.split()[1]) * 1024 for s in status if s.startswith('VmRSS:')), 0)
            processes.append({'pid': int(proc.name), 'comm': command, 'rss_bytes': rss})
        except (OSError, ValueError, StopIteration):
            continue
    disk = shutil.disk_usage(root)
    pressure = {}
    for kind in ('cpu', 'memory', 'io'):
        path = Path('/proc/pressure') / kind
        pressure[kind] = path.read_text() if path.exists() else None
    return {'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(),
            'cpu_count': os.cpu_count(), 'load_average': os.getloadavg(),
            'proc_stat': Path('/proc/stat').read_text(),
            'meminfo_bytes': memory, 'disk_total_bytes': disk.total,
            'disk_free_bytes': disk.free, 'diskstats': Path('/proc/diskstats').read_text(),
            'pressure': pressure, 'processes': processes,
            'file_descriptor_limit': resource.getrlimit(resource.RLIMIT_NOFILE)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--interval', type=float, default=15)
    p.add_argument('--seconds', type=float, default=0, help='0: run until SIGTERM')
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    archive = args.archive.resolve()
    if not archive.is_relative_to(root / 'test_log'):
        p.error('archive must be in project test_log')
    os.umask(0o077)
    target = archive / 'resource_monitor'
    target.mkdir(parents=True, exist_ok=True)
    session = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S') + f'-{os.getpid()}'
    stop = False

    def stopping(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    start = time.monotonic()
    oom = subprocess.run(['dmesg', '--level=err,warn'], capture_output=True, text=True)
    (target / f'{session}-oom-access.json').write_text(json.dumps({
        'returncode': oom.returncode, 'stderr': oom.stderr,
        'oom_lines': [s for s in oom.stdout.splitlines()
                      if any(k in s.lower() for k in ('oom', 'out of memory', 'killed process'))]}, indent=2) + '\n')
    with (target / f'{session}-samples.jsonl').open('x') as stream:
        while not stop:
            stream.write(json.dumps(sample(root)) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
            if args.seconds and time.monotonic() - start >= args.seconds:
                break
            time.sleep(max(1, min(args.interval, 60)))
    (target / f'{session}-terminal.json').write_text(json.dumps({
        'status': 'stopped', 'duration_seconds': time.monotonic() - start,
        'reason': 'signal' if stop else 'preflight_sample_window_complete'}) + '\n')


if __name__ == '__main__':
    main()
