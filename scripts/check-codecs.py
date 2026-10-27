#!/usr/bin/env python3
"""Offline encoded-byte replay smoke for Claude, Codex and OpenCode image readers."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from PIL import Image


def run(root):
    node = root / '.tools/node/bin/node'
    dispatcher = root / 'evaluation/camact_eval/visual_replay.cjs'
    registry = json.loads((root / 'evaluation/camact_eval/native_codecs.json').read_text())
    results = {}
    with tempfile.TemporaryDirectory(prefix='camact-codecs-smoke-') as directory:
        source = Path(directory) / 'synthetic-image.jpg'
        # Large enough to exercise each pinned reader's actual resize path.
        image = Image.new('RGB', (2100, 1400))
        pixels = bytearray()
        for y in range(1400):
            for x in range(2100):
                pixels.extend(((x // 20) % 256, (y // 20) % 256, ((x + y) // 20) % 256))
        image.frombytes(bytes(pixels))
        image.save(source, 'JPEG', quality=94)
        raw = source.read_bytes()
        for family, size in (('claude', [1000, 667]), ('codex', [1000, 667]), ('opencode', [2000, 1333])):
            if family == 'codex':
                encoded = subprocess.check_output([str(root / registry['codecs']['codex']['helper']['path'])],
                    input=f'{source}\n{size[0]}\n{size[1]}\n'.encode())
            else:
                script = r'''
const fs=require('node:fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
(async()=>{
  const bytes=fs.readFileSync(input.source);
  let output;
  if(input.family==='claude') {
    const native=require(input.module);
    const image=await native.processImage(bytes);
    image.resize(input.size[0],input.size[1],{fit:'inside',withoutEnlargement:true});
    output=await image.toBuffer();
  } else {
    const photon=require(input.module);
    const image=photon.PhotonImage.new_from_byteslice(bytes);
    const resized=photon.resize(image,input.size[0],input.size[1],photon.SamplingFilter.Lanczos3);
    try { output=Buffer.from(resized.get_bytes()); }
    finally { resized.free();image.free(); }
  }
  process.stdout.write(output);
})().catch(error=>{console.error(error);process.exit(1)});
'''
                entry = registry['codecs'][family]
                module = entry['module'] if family == 'claude' else entry['photon_module']
                encoded = subprocess.check_output([str(node), '-e', script], input=json.dumps({
                    'source': str(source), 'family': family, 'size': size,
                    'module': str(root / module['path'])}).encode())
            value = {'native': family, 'native_version': registry['codecs'][family]['version'],
                     'source': str(source), 'source_sha256': hashlib.sha256(raw).hexdigest(),
                     'size': size, 'target_sha256': hashlib.sha256(encoded).hexdigest()}
            proof = json.loads(subprocess.check_output([str(node), str(dispatcher)], input=json.dumps(value).encode()))
            if (not proof or proof.get('verification') != 'encoded_sha256_exact' or
                    proof.get('replayed_sha256') != value['target_sha256']):
                raise RuntimeError(f'{family}: exact generated encoded-byte replay failed')
            value['target_sha256'] = '0' * 64
            rejected = json.loads(subprocess.check_output([str(node), str(dispatcher)], input=json.dumps(value).encode()))
            if rejected is not None:
                raise RuntimeError(f'{family}: wrong payload digest was accepted')
            results[family] = {'encoded_bytes': len(encoded), 'dimensions': size,
                               'exact_replay': True, 'wrong_digest_rejected': True}
    return {'real_model_calls': 0, 'synthetic_fixture_only': True, 'codecs': results}


if __name__ == '__main__':
    print(json.dumps(run(Path(__file__).resolve().parents[1]), indent=2))
