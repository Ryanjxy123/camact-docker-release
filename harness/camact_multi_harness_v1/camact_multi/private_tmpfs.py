"""Trusted mount-namespace steward for explicit OpenClaw tmpfs runs.

Invoke via: unshare --user --map-current-user --keep-caps --mount --fork
python -B private_tmpfs.py --parent PATH --recovery PATH -- COMMAND ...
Both paths must be under the installation's workspace. The CLI remains inside
its own gVisor boundary; only the trusted Coordinator shares this mount view.
Pass --outer-mount-namespace from readlink('/proc/self/ns/mnt') BEFORE unshare.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time
import sys
import uuid

def authorized_project():
    project = Path(__file__).resolve().parents[3]
    if '.repair-workspaces' in project.parts:
        project = Path(*project.parts[:project.parts.index('.repair-workspaces')])
    return project


AUTHORIZED = Path(os.environ.get('CAMACT_DATA_ROOT') or authorized_project()).resolve()


def launch_if_needed(output, cli_args):
    """Use the existing steward when the configured tmpfs is not mounted yet.

    The inner CLI sees the same explicit backend and still passes every
    OpenClawHome permission/filesystem check. No native policy is changed.
    """
    current = os.environ.get('CAMACT_OPENCLAW_TMPDIR')
    if current and Path(current).is_dir() and subprocess.check_output(
            ['stat', '-f', '-c', '%T', current], text=True).strip() == 'tmpfs':
        return None
    identifier = uuid.uuid4().hex
    parent = Path(os.environ.get('CAMACT_SCRATCH_ROOT') or AUTHORIZED / '.at') / ('openclaw-' + identifier)
    output = Path(output).resolve()
    recovery = output.parent / (output.name + '-private-tmpfs-' + identifier)
    command = ['unshare', '--user', '--map-current-user', '--keep-caps', '--mount', '--fork',
               sys.executable, '-B', str(Path(__file__).resolve()),
               '--outer-mount-namespace', os.readlink('/proc/self/ns/mnt'),
               '--parent', str(parent), '--recovery', str(recovery), '--',
               sys.executable, '-B', '-m', 'camact_multi.cli', *cli_args]
    process = subprocess.Popen(command, start_new_session=True)
    try:
        return process.wait()
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--recovery', type=Path, required=True)
    parser.add_argument('--outer-mount-namespace', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    os.umask(0o077)
    for path in (args.parent, args.recovery):
        if path.is_symlink() or not path.resolve().is_relative_to(AUTHORIZED):
            raise ValueError('Private tmpfs paths must be within the authorized workspace')
    args.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    args.recovery.mkdir(mode=0o700, parents=True, exist_ok=False)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        raise ValueError('A trusted Coordinator command is required')
    libc = ctypes.CDLL(None, use_errno=True)
    # Refuse to run in the host mount namespace; this script never unshares it
    # implicitly or changes the host's mount propagation.
    if os.readlink('/proc/self/ns/mnt') == args.outer_mount_namespace:
        raise RuntimeError('An independent mount namespace is required')
    if libc.mount(None, b'/', None, (1 << 18) | (1 << 14), None):
        raise OSError(ctypes.get_errno(), 'private mount propagation')
    if libc.mount(b'tmpfs', str(args.parent).encode(), b'tmpfs', 2 | 4, b'size=256m,mode=0700'):
        raise OSError(ctypes.get_errno(), 'private tmpfs mount')
    # Keep the namespace available for recovery if the outer process group is
    # cancelled. Its parent-death signal initiates shutdown and preservation.
    os.setsid()
    stop = False
    def cancel(*_):
        nonlocal stop
        stop = True
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, cancel)
    original_parent = os.getppid()
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'parent-death signal')
    if os.getppid() != original_parent:
        stop = True
    env = dict(os.environ, CAMACT_OPENCLAW_TMPDIR=str(args.parent))
    process = subprocess.Popen(command, env=env, start_new_session=True)
    while process.poll() is None:
        if stop:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
            break
        time.sleep(.05)
    rc = process.wait(15)
    # OpenClawHome normally verified and removed every live HOME. If the
    # Coordinator died or its archive failed, preserve all remaining bytes
    # before releasing this namespace. Failed preservation retains the mount.
    retained = list(args.parent.iterdir())
    copied = []
    if retained:
        while True:
            try:
                target = args.recovery/'retained-home'
                shutil.copytree(args.parent, target, symlinks=True, dirs_exist_ok=True)
                for source in args.parent.rglob('*'):
                    if source.is_file() and not source.is_symlink():
                        relative = source.relative_to(args.parent)
                        digest = hashlib.sha256(source.read_bytes()).hexdigest()
                        if hashlib.sha256((target/relative).read_bytes()).hexdigest() != digest:
                            raise RuntimeError('tmpfs recovery copy failed verification')
                        copied.append({'path': str(relative), 'sha256': digest, 'bytes': source.stat().st_size})
                break
            except Exception as exc:
                (args.recovery/'recovery-pending.json').write_text(json.dumps({
                    'namespace_pid': os.getpid(), 'source': str(args.parent),
                    'error': f'{type(exc).__name__}: {exc}', 'unique_evidence_retained': True}))
                time.sleep(5)
    proof = {'returncode': rc, 'cancelled': stop, 'filesystem': 'tmpfs',
             'capacity_bytes': 268435456, 'retained_sources': len(retained),
             'recovered_files': copied, 'namespace_pid': os.getpid(), 'uid': os.getuid()}
    if libc.umount2(str(args.parent).encode(), 0):
        raise OSError(ctypes.get_errno(), 'private tmpfs unmount')
    args.parent.rmdir()
    proof['unmounted_and_removed'] = True
    (args.recovery/'private-tmpfs.json').write_text(json.dumps(proof, indent=2) + '\n')
    return rc if rc >= 0 else 128 - rc


if __name__ == '__main__':
    raise SystemExit(main())
