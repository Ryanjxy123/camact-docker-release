#!/usr/bin/env python3
"""Check the pinned official executables with private disposable CLI state."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile


def sandbox_checks(root, lock):
    """Run the exact pinned CLI version probes through production OCI builder."""
    sys.path.insert(0, str(root))
    from harness.camact_multi_harness_v1.camact_multi.gvisor import command
    results = {}
    parent = os.environ.get('CAMACT_SCRATCH_ROOT')
    if parent:
        Path(parent).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='camact-sandbox-check-', dir=parent) as temporary:
        state = Path(temporary)
        for name, package in lock['cli'].items():
            workspace, home = state / name / 'workspace', state / name / 'home'
            workspace.mkdir(parents=True, mode=0o700)
            home.mkdir(mode=0o700)
            entry = {'runtime_roots': [str(root / '.tools' / name), str(root / '.tools/node')],
                     'node_executable': str(root / '.tools/node/bin/node')}
            executable = root / '.tools' / name / 'node_modules/.bin' / package['executable']
            env = {'PATH': '/opt:/usr/local/bin:/usr/bin:/bin', 'HOME': '/home/agent',
                   'XDG_CONFIG_HOME': '/home/agent/.config', 'XDG_DATA_HOME': '/home/agent/.local/share',
                   'XDG_CACHE_HOME': '/home/agent/.cache', 'XDG_STATE_HOME': '/home/agent/.local/state',
                   'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'NO_COLOR': '1', 'CI': '1',
                   'OPENCODE_DISABLE_AUTOUPDATE': '1', 'OPENCODE_DISABLE_MODELS_FETCH': '1'}
            argv = command([str(executable), '--version'], workspace, home, entry, relay=False)
            # Verification owns a unique state tree even when invoked without
            # deployment environment variables on a development host.
            plan_path = Path(argv[-1])
            plan = json.loads(plan_path.read_text())
            plan['state_parent'] = str(state / 'gvisor-state')
            plan_path.write_text(json.dumps(plan) + '\n')
            process = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=120)
            lifecycle = json.loads((Path(argv[-1]).parent / 'lifecycle.json').read_text())
            if (process.returncode or package['version'] not in process.stdout or
                    lifecycle.get('cleanup_returncode') != 0 or not lifecycle.get('state_removed')):
                raise RuntimeError(f'{name}: production gVisor executable/lifecycle probe failed: {process.stderr[-600:]}')
            results[name] = {'version': package['version'], 'returncode': process.returncode,
                             'actual': process.stdout.strip(), 'lifecycle': lifecycle}
        workspace, home = state / 'credential-boundary/workspace', state / 'credential-boundary/home'
        workspace.mkdir(parents=True, mode=0o700)
        home.mkdir(mode=0o700)
        names = ['AGENT_API_KEY', 'AGENT_API_KEY_CODEX', 'JUDGE_API_KEY', 'JUDGE_API_KEY_CANARY',
                 'SIMULATOR_API_KEY', 'SIMULATOR_API_KEY_CANARY', 'HF_TOKEN',
                 'HUGGING_FACE_HUB_TOKEN', 'HUGGINGFACE_HUB_TOKEN', 'CAMACT_ZCLOUD_API_KEY']
        canaries = {key: 'synthetic-secret-canary-' + key.lower() for key in names}
        probe = 'import os,json; names=' + repr(names) + '; assert not any(key in os.environ for key in names); print(json.dumps({"trusted_credentials_absent":True,"checked_names":len(names)}))'
        entry = {'runtime_roots': [str(root / '.tools/node')]}
        argv = command(['/usr/bin/python3', '-c', probe], workspace, home, entry, relay=False, environment=canaries)
        plan_path = Path(argv[-1])
        plan = json.loads(plan_path.read_text())
        plan['state_parent'] = str(state / 'gvisor-state')
        plan_path.write_text(json.dumps(plan) + '\n')
        process = subprocess.run(argv, env={'PATH': '/usr/bin:/bin', **canaries}, capture_output=True, text=True, timeout=60)
        lifecycle = json.loads((plan_path.parent / 'lifecycle.json').read_text())
        evidence = plan_path.read_text() + json.dumps(lifecycle) + process.stdout + process.stderr
        if (process.returncode or '"trusted_credentials_absent": true' not in process.stdout
                or any(value in evidence for value in canaries.values())
                or any(key in lifecycle['guest_environment_keys'] for key in names)
                or lifecycle['cleanup_returncode'] != 0 or not lifecycle['state_removed']):
            raise RuntimeError('Trusted provider/Hugging Face credential boundary probe failed')
        results['credential_boundary'] = {'synthetic_only': True, 'checked_names': len(names),
            'trusted_credentials_absent': True, 'plan_and_lifecycle_canary_values_absent': True,
            'lifecycle': lifecycle}
    return results


def check(root, *, codecs=True, sandbox=False):
    lock = json.loads((root / 'locks/runtimes.json').read_text())
    results = {}
    if platform.system() != 'Linux' or platform.machine() not in {'x86_64', 'amd64'}:
        raise RuntimeError('The verified runtime/codec lock requires Linux x86_64')
    with tempfile.TemporaryDirectory(prefix='camact-runtime-check-') as temporary:
        state = Path(temporary)
        env = {'PATH': f'{root}/.tools/node/bin:/usr/local/bin:/usr/bin:/bin',
               'HOME': str(state), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'CI': '1', 'NO_COLOR': '1', 'OPENCODE_DISABLE_AUTOUPDATE': '1',
               'OPENCODE_DISABLE_MODELS_FETCH': '1',
               'XDG_CONFIG_HOME': str(state / 'config'), 'XDG_DATA_HOME': str(state / 'data'),
               'XDG_STATE_HOME': str(state / 'state'), 'XDG_CACHE_HOME': str(state / 'cache')}
        checks = {'node': (root / '.tools/node/bin/node', lock['node']['version']),
                  'gvisor': (root / '.tools/gvisor' / lock['gvisor']['version'] / 'runsc', lock['gvisor']['version'])}
        checks.update({name: (root / '.tools' / name / 'node_modules/.bin' / entry['executable'], entry['version'])
                       for name, entry in lock['cli'].items()})
        for name, (executable, version) in checks.items():
            process = subprocess.run([str(executable), '--version'], env=env,
                                     capture_output=True, text=True, timeout=90)
            if process.returncode or version not in process.stdout:
                raise RuntimeError(f'{name}: executable/version check failed (exit={process.returncode})')
            results[name] = {'version': version, 'executable': str(executable.relative_to(root)),
                             'actual': process.stdout.strip()}
    if codecs:
        registry = json.loads((root / 'evaluation/camact_eval/native_codecs.json').read_text())
        checked = []
        def visit(value):
            if isinstance(value, dict):
                if 'path' in value and 'sha256' in value:
                    path = root / value['path']
                    if hashlib.sha256(path.read_bytes()).hexdigest() != value['sha256']:
                        raise RuntimeError(f'Native image codec digest mismatch: {value["path"]}')
                    checked.append(value['path'])
                for child in value.values(): visit(child)
            elif isinstance(value, list):
                for child in value: visit(child)
        visit(registry)
        results['native_image_codecs'] = {'verified_files': len(checked)}
    if sandbox:
        results['sandbox'] = sandbox_checks(root, lock)
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-codecs', action='store_true')
    parser.add_argument('--sandbox', action='store_true', help='Also create/exit production gVisor for all five CLIs')
    args = parser.parse_args()
    print(json.dumps(check(Path(__file__).resolve().parents[1], codecs=not args.skip_codecs, sandbox=args.sandbox), indent=2))
