#!/usr/bin/env python3
"""Recreate exact image replay dependencies from pinned official CLI/source bytes.

The Rust helper is built from its original source and Cargo.lock. Its generated
binary digest is written into the image's existing codec registry; every static
upstream/source digest remains enforced. No scoring or image decision rule changes.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def build(root):
    registry_file = root / 'evaluation/camact_eval/native_codecs.json'
    registry = json.loads(registry_file.read_text())
    def pinned(reference):
        path = root / reference['path']
        if hashlib.sha256(path.read_bytes()).hexdigest() != reference['sha256']:
            raise RuntimeError(f'Pinned image codec input differs: {reference["path"]}')
        return path
    pinned(registry['node'])
    claude = registry['codecs']['claude']
    executable = pinned(claude['cli']).read_bytes()
    # Public pinned CLI's original embedded ELF/N-API image encoder, unchanged.
    addon = executable[240840417:240840417 + 1471800]
    if addon[:4] != b'\x7fELF' or hashlib.sha256(addon).hexdigest() != claude['module']['sha256']:
        raise RuntimeError('Claude embedded image encoder extraction digest mismatch')
    target = root / claude['module']['path']
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(addon)
    codex = registry['codecs']['codex']
    for family in registry['codecs'].values():
        pinned(family['cli']); pinned(family['package'])
        for source in family.get('sources', []): pinned(source)
    expected = json.loads((root / 'locks/runtimes.json').read_text())['rust']['version']
    rust = subprocess.check_output(['rustc', '--version'], text=True).strip()
    if rust.split()[1] != expected:
        raise RuntimeError(f'The replay helper requires rustc {expected}')
    source = root / 'harness/camact_visual_provenance_v1/native_codex_replay'
    with tempfile.TemporaryDirectory(prefix='camact-codec-build-') as directory:
        environment = dict(os.environ, CARGO_TARGET_DIR=directory)
        environment['RUSTFLAGS'] = '--remap-path-prefix=' + str(root) + '=/camact'
        subprocess.run(['cargo', 'build', '--locked', '--release', '--manifest-path', str(source / 'Cargo.toml')],
                       check=True, env=environment)
        helper = root / codex['helper']['path']
        shutil.copy2(Path(directory) / 'release/camact-native-codex-image-replay', helper)
        helper.chmod(0o755)
    codex['helper']['sha256'] = hashlib.sha256(helper.read_bytes()).hexdigest()
    registry['build_provenance'] = {'rustc': rust, 'cargo_locked': True,
        'native_cli_bytes_unchanged': True, 'claude_embedded_offset': 240840417,
        'claude_embedded_length': 1471800}
    # Build metadata, not a scoring rule: the replay dispatcher still validates
    # this local executable as strictly as the original generated registry.
    registry_file.write_text(json.dumps(registry, indent=2) + '\n')
    subprocess.run(['python3', str(root / 'scripts/check-runtimes.py')], check=True)


if __name__ == '__main__':
    build(Path(__file__).resolve().parents[1])
