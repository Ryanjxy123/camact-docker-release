"""Optional rootless Systrap boundary and a parent-lifetime supervisor.

The native CLI and its relay run unchanged. runsc's bwrap personality drops
host-UDS options and does not implement die-with-parent; use OCI directly.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

PROJECT = Path(__file__).resolve().parents[3]
RUNSC = Path(os.environ.get('CAMACT_RUNSC') or PROJECT / '.tools/gvisor/20261012.0/runsc')
SYSTEM = ('/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc/ssl/certs',
          '/etc/fonts', '/etc/ld.so.cache', '/etc/localtime')


def trusted_secret_name(key):
    return key.startswith(('AGENT_API_KEY', 'JUDGE_API_KEY', 'SIMULATOR_API_KEY')) or key in {
        'CAMACT_ZCLOUD_API_KEY', 'HF_TOKEN', 'HUGGING_FACE_HUB_TOKEN', 'HUGGINGFACE_HUB_TOKEN'}


def command(argv, workspace, home, entry, transport=None, *, relay=True,
            home_guest='/home/agent', relay_script='/tmp/.camact/multi_launcher.py',
            environment=None):
    """Build an explicit allowlist; all package resources keep their layout."""
    from harness.camact_prompt_parity_v1.sandbox import memory_alias_mounts
    workspace, home = Path(workspace).resolve(strict=True), Path(home).resolve(strict=True)
    roots, mounts = [], []
    def bind(source, destination, readonly=True):
        mounts.append({'type': 'bind', 'source': str(source), 'destination': destination,
                       'options': ['rbind', 'nosuid', 'nodev', 'ro' if readonly else 'rw']})
    for source in SYSTEM:
        if Path(source).exists():
            bind(source, source)
    for index, source in enumerate(entry.get('runtime_roots', ())):
        source = Path(source).resolve(strict=True)
        tools = (PROJECT / '.tools').resolve(strict=True)
        if source == tools or not source.is_relative_to(tools) or not source.is_dir():
            raise ValueError('gVisor runtime roots must be individual packages under .tools')
        target = f'/opt/camact/runtime/{index}'
        roots.append((source, target))
        bind(source, target)
        for hidden in ('.env', '.npmrc', '.git'):
            child = source / hidden
            if child.is_file():
                bind('/dev/null', target + '/' + hidden)
            elif child.is_dir():
                mounts.append({'type': 'tmpfs', 'destination': target + '/' + hidden,
                               'options': ['mode=700', 'size=1048576']})
    def mapped(value):
        for source, target in sorted(roots, key=lambda r: len(str(r[0])), reverse=True):
            if value == str(source) or value.startswith(str(source) + '/'):
                return target + value[len(str(source)):]
        return value
    executable = Path(shutil.which(str(argv[0])) or argv[0]).resolve(strict=True)
    if not any(executable.is_relative_to(root) for root, _ in roots) and not any(
            executable.is_relative_to(Path(p)) for p in ('/usr', '/bin', '/sbin')):
        raise ValueError('Executable must be inside an allowlisted runtime')
    inner = [mapped(str(executable)), *[mapped(str(a)) for a in argv[1:]]]
    if entry.get('node_executable'):
        node = Path(entry['node_executable']).resolve(strict=True)
        if not any(node.is_relative_to(root) for root, _ in roots):
            raise ValueError('Node must be in an allowlisted runtime')
        bind(node, '/opt/node')
    # Sentry supplies these interfaces; no host procfs or device tree is bound.
    mounts += [{'type': kind, 'destination': dest} for dest, kind in (
        ('/proc', 'proc'), ('/sys', 'sysfs'), ('/dev', 'devtmpfs'), ('/dev/pts', 'devpts'))]
    mounts += [{'type': 'tmpfs', 'destination': dest,
                'options': ['nosuid', 'nodev', 'mode=1777', 'size=268435456']}
               for dest in ('/run', '/mnt', '/root')]
    # A writable per-task run directory is needed by the existing relay.
    mounts.append({'type': 'tmpfs', 'destination': '/run/camact',
                   'options': ['nosuid', 'nodev', 'mode=700', 'size=67108864',
                               f'uid={os.getuid()}', f'gid={os.getgid()}']})
    bind(workspace, '/tmp', False)
    bind(home, home_guest, False)
    for name in ('album', 'context', '.camact'):
        if (workspace / name).exists():
            bind(workspace / name, '/tmp/' + name)
    aliases = memory_alias_mounts(workspace)
    for index in range(0, len(aliases), 3):
        if aliases[index] != '--ro-bind':
            raise ValueError('Unsupported memory alias mount')
        bind(aliases[index + 1], aliases[index + 2])
    if transport:
        bind(Path(transport).resolve(strict=True), '/transport')
    if relay:
        inner = ['/usr/bin/python3', relay_script, *inner]
    metadata = workspace.parent / 'sandbox-launches' / uuid.uuid4().hex
    metadata.mkdir(parents=True, mode=0o700)
    plan = {'schema': 'camact.gvisor.launch.v1', 'argv': inner, 'mounts': mounts,
            'cwd': '/tmp', 'environment': {key: value for key, value in (environment or {}).items()
                                          if not trusted_secret_name(key)},
            'state_parent': str(Path(os.environ.get('CAMACT_GVISOR_STATE_ROOT') or
                               PROJECT.parent / '.camact-tmp/camact-gvisor')),
            'runsc': str(RUNSC),
            'runtime_mapping': [{'host': str(s), 'guest': t} for s, t in roots],
            'metadata': str(metadata)}
    path = metadata / 'plan.json'
    path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)
    return [sys.executable, '-B', str(Path(__file__).resolve()), str(path)]


def _prctl(option, value):
    if ctypes.CDLL(None, use_errno=True).prctl(option, value, 0, 0, 0):
        raise OSError(ctypes.get_errno(), 'prctl')


def _supervise(plan, parent_fd, guest_env):
    """Survive the invocation process group to clean up even after SIGKILL."""
    _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER, reap detached runsc children too.
    parent = Path(plan.get('state_parent') or PROJECT.parent / '.camact-tmp/camact-gvisor')
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if parent.is_symlink() or parent.stat().st_uid != os.getuid():
        raise RuntimeError('Unsafe gVisor state parent')
    state = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
    for name in ('rootfs', 'tmp', 'home'):
        (state / name).mkdir(mode=0o700)
    cid = 'camact-' + uuid.uuid4().hex
    spec = {'ociVersion': '1.2.1', 'root': {'path': str(state/'rootfs'), 'readonly': True},
            'process': {'terminal': False, 'user': {'uid': os.getuid(), 'gid': os.getgid()},
                        'args': plan['argv'], 'cwd': plan['cwd'],
                        'env': [f'{k}={v}' for k, v in guest_env.items()],
                        'noNewPrivileges': True,
                        'capabilities': {key: [] for key in (
                            'bounding', 'effective', 'permitted', 'inheritable', 'ambient')}},
            'mounts': plan['mounts'], 'linux': {'namespaces': [{'type': 'user'}],
                'uidMappings': [{'containerID': os.getuid(), 'hostID': os.getuid(), 'size': 1}],
                'gidMappings': [{'containerID': os.getgid(), 'hostID': os.getgid(), 'size': 1}]}}
    (state / 'config.json').write_text(json.dumps(spec))
    host_env = {'PATH': '/usr/bin:/bin', 'HOME': str(state/'home'), 'TMPDIR': str(state/'tmp'),
                'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    # --rootless is the special bootstrap for `do`. OCI obtains rootless
    # isolation from the explicit single-ID user namespace above.
    prefix = [plan.get('runsc') or str(RUNSC), f'--root={state}/runtime', '--platform=systrap',
              '--network=none', '--gofer-network-namespace=new',
              '--ignore-cgroups', '--host-uds=open']
    started, abandoned, rc, cleanup = time.monotonic(), False, 125, None
    process = None
    try:
        process = subprocess.Popen(prefix + ['run', '--bundle', str(state), cid], env=host_env)
        while process.poll() is None:
            if select.select([parent_fd], [], [], .05)[0] and not os.read(parent_fd, 1):
                abandoned = True
                process.terminate()
                try:
                    process.wait(3)
                except subprocess.TimeoutExpired:
                    process.kill()
                break
        rc = process.wait(10)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(10)
        cleanup = subprocess.run(prefix + ['delete', '--force', cid], env=host_env,
                                 capture_output=True, text=True, timeout=15)
        # The subreaper also observes gofer/sentry exit, without matching or
        # signalling any other user's processes.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    time.sleep(.03)
            except ChildProcessError:
                break
        row = {'backend': 'gvisor', 'release': '20261012.0', 'platform': 'systrap',
               'container_id': cid, 'state': str(state), 'returncode': rc,
               'parent_disconnected': abandoned, 'cleanup_returncode': cleanup.returncode,
               'cleanup_stderr': cleanup.stderr, 'seconds': time.monotonic() - started,
               'guest_environment_keys': sorted(guest_env), 'network': 'none',
               'host_proc_bound': False, 'runtime_mapping': plan['runtime_mapping']}
        if cleanup.returncode == 0:
            shutil.rmtree(state)
        row['state_removed'] = not state.exists()
        (Path(plan['metadata'])/'lifecycle.json').write_text(json.dumps(row, indent=2) + '\n')
        os.close(parent_fd)
    return rc if cleanup.returncode == 0 and rc >= 0 else 125


def main():
    os.umask(0o077)
    plan_path = Path(sys.argv[1]).resolve(strict=True)
    if plan_path.stat().st_uid != os.getuid():
        raise RuntimeError('Launch plan has the wrong owner')
    plan = json.loads(plan_path.read_text())
    if plan.get('schema') != 'camact.gvisor.launch.v1':
        raise ValueError('Unsupported launch plan')
    guest_env = dict(os.environ)
    # Real provider keys remain with the trusted host relay, never in OCI JSON.
    guest_env.update(plan['environment'])
    for key in list(guest_env):
        if trusted_secret_name(key):
            guest_env.pop(key)
    for key, value in list(guest_env.items()):
        for mapping in plan['runtime_mapping']:
            value = value.replace(mapping['host'], mapping['guest'])
        guest_env[key] = value
    read_fd, write_fd = os.pipe()
    parent_pid = os.getppid()
    supervisor = os.fork()
    if supervisor == 0:
        os.close(write_fd)
        os.setsid()
        try:
            code = _supervise(plan, read_fd, guest_env)
        except BaseException as exc:
            print(f'CamAct gVisor supervisor: {type(exc).__name__}: {exc}', file=sys.stderr, flush=True)
            code = 125
        os._exit(code)
    os.close(read_fd)
    def disconnect(*_):
        nonlocal write_fd
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, disconnect)
    _prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG for Coordinator death.
    if os.getppid() != parent_pid:
        disconnect()
    try:
        _, status = os.waitpid(supervisor, 0)
    finally:
        disconnect()
    return os.waitstatus_to_exitcode(status)


if __name__ == '__main__':
    raise SystemExit(main())
