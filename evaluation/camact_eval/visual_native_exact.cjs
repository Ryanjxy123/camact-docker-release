// Fixed read-only native codecs. No captured command, shell, or provider runs.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const hash = data => crypto.createHash('sha256').update(data).digest('hex');

module.exports = async function nativeExact(input) {
  const batched = Object.hasOwn(input, 'sources');
  if (batched && (!Array.isArray(input.sources) || input.sources.length < 1 || input.sources.length > 32))
    throw new Error('invalid native codec batch');
  const inputs = batched ? input.sources.map(source => ({...input,
    source:source.source, source_sha256:source.source_sha256})) : [input];
  if (batched && !inputs.every(value => typeof value.source === 'string' &&
      typeof value.source_sha256 === 'string' && /^[a-f0-9]{64}$/.test(value.source_sha256)))
    throw new Error('invalid native codec source');
  const registryPath = path.join(__dirname, 'native_codecs.json');
  const registryBytes = fs.readFileSync(registryPath);
  const registry = JSON.parse(registryBytes);
  const codec = registry.codecs[input.native];
  if (!codec || codec.version !== input.native_version) return null;
  const root = path.resolve(__dirname, '../..');
  const pins = new Map();
  function pinned(reference) {
    const filename = path.resolve(root, reference.path);
    if (!filename.startsWith(root + path.sep))
      throw new Error('native codec implementation digest mismatch');
    if (pins.has(filename)) {
      if (pins.get(filename) !== reference.sha256)
        throw new Error('native codec implementation digest mismatch');
      return filename;
    }
    if (hash(fs.readFileSync(filename)) !== reference.sha256)
      throw new Error('native codec implementation digest mismatch');
    pins.set(filename, reference.sha256);
    return filename;
  }
  const node = pinned(registry.node);
  if (hash(fs.readFileSync(process.execPath)) !== hash(fs.readFileSync(node))) return null;
  const cli = pinned(codec.cli);
  const packagePath = pinned(codec.package);
  if (JSON.parse(fs.readFileSync(packagePath, 'utf8')).version !== codec.version) return null;
  for (const reference of codec.sources || []) pinned(reference);
  const size = input.size;
  if (!Array.isArray(size) || size.length !== 2 ||
      !size.every(value => Number.isSafeInteger(value) && value > 0) || size[0] * size[1] > 25000000)
    return null;
  let native, executable, replayOpenCode;
  if (input.native === 'claude') native = require(pinned(codec.module));
  else if (input.native === 'codex') executable = pinned(codec.helper);
  else if (input.native === 'opencode') {
    replayOpenCode = require(pinned(codec.helper_module)).prepare(codec, pinned);
    if (!replayOpenCode) return null;
  } else return null;
  // Verify each complete source before encoding. A source error rejects the
  // whole batch; the caller receives no partial output to cache.
  async function replay(value) {
    const source = fs.readFileSync(value.source);
    if (hash(source) !== value.source_sha256) {
      if (batched) throw new Error('native codec source digest mismatch');
      return null;
    }
    let output, implementation;
    if (input.native === 'claude') {
      const image = await native.processImage(source);
      image.resize(size[0], size[1], {fit:'inside', withoutEnlargement:true});
      output = await image.toBuffer();
      implementation = {engine:'claude_embedded_image_processor', native_module:codec.module,
        resize:{width:size[0], height:size[1], fit:'inside', withoutEnlargement:true}};
    } else if (input.native === 'codex') {
      // Exact executable, zero argv, fixed line protocol; no output files or shell.
      if (/[\r\n]/.test(value.source)) return null;
      const replay = require('node:child_process').spawnSync(executable, [], {
        input:`${value.source}\n${size[0]}\n${size[1]}\n`, env:{},
        timeout:30000, maxBuffer:16*1024*1024, windowsHide:true,
      });
      if (replay.error) throw replay.error;
      if (replay.status !== 0) {
        // The fixed helper's explicit geometry rejection is deterministic.
        // Timeouts, signals and other failures must not populate a negative cache.
        const reason = String(replay.stderr || '').trim();
        if (replay.status === 1 && ['Error: "invalid replay dimensions"',
            'Error: "dimensions do not preserve the native full frame"'].includes(reason)) return null;
        throw new Error('native codec execution failed');
      }
      output = replay.stdout;
      implementation = {engine:'codex_rust_image', helper:codec.helper,
        resize:{width:size[0], height:size[1], filter:'Triangle'}, quality:85};
    } else if (input.native === 'opencode') {
      const result = replayOpenCode(value, source);
      if (!result) return null;
      output = result.output;
      implementation = result.implementation;
    } else return null;
    const replayed = hash(output);
    if (replayed !== input.target_sha256) return null;
    return {...implementation, version:codec.version, cli:{path:cli, sha256:codec.cli.sha256},
      registry_sha256:hash(registryBytes), source_sha256:hash(source),
      verification:'encoded_sha256_exact', replayed_sha256:replayed};
  }
  if (!batched) return replay(input);
  const proofs = [];
  for (const value of inputs) proofs.push(await replay(value));
  return proofs;
};
