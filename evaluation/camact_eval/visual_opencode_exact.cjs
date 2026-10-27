// Replay OpenCode 2.0.32's embedded Image.Photon.normalize, without running CLI.
const fs = require('node:fs');
const crypto = require('node:crypto');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');

function prepareOpenCode(codec, pinned) {
  if (codec.version !== '2.0.32') return null;
  const cli = fs.readFileSync(pinned(codec.cli));
  const wasmPath = pinned(codec.photon_wasm);
  const wasm = fs.readFileSync(wasmPath);
  const embedded = codec.embedded_wasm;
  if (!embedded || !Number.isSafeInteger(embedded.offset) ||
      embedded.length !== wasm.length || embedded.sha256 !== hash(wasm) ||
      !cli.subarray(embedded.offset, embedded.offset + embedded.length).equals(wasm))
    return null;
  const modulePath = pinned(codec.photon_module);
  if (JSON.parse(fs.readFileSync(pinned(codec.photon_package), 'utf8')).version !== '0.3.4')
    return null;
  const photon = require(modulePath);
  return function replayOpenCode(input, source) {
    if (input.native !== 'opencode' || input.native_version !== '2.0.32') return null;
    source = source || fs.readFileSync(input.source);
    if (hash(source) !== input.source_sha256) return null;
    const image = photon.PhotonImage.new_from_byteslice(source);
    const maxWidth = 2000, maxHeight = 2000, maxBase64Bytes = 5242880;
    const jpegQualities = [80, 85, 70, 55, 40];
    const attempts = [];
    let output, selected, geometry;
    try {
      const width = image.get_width(), height = image.get_height();
      if (width <= maxWidth && height <= maxHeight &&
          Math.ceil(source.length / 3) * 4 <= maxBase64Bytes) {
        output = source;
        geometry = [width, height];
        selected = {mime:'source', encoding:'unchanged'};
      } else {
        const factor = Math.min(1, maxWidth / width, maxHeight / height);
        const sizes = Array.from({length:32}).reduce((items) => {
          const previous = items.at(-1) || {
            width:Math.max(1, Math.round(width * factor)),
            height:Math.max(1, Math.round(height * factor)),
          };
          const next = items.length === 0 ? previous : {
            width:previous.width === 1 ? 1 : Math.max(1, Math.floor(previous.width * 0.75)),
            height:previous.height === 1 ? 1 : Math.max(1, Math.floor(previous.height * 0.75)),
          };
          return items.some(size => size.width === next.width && size.height === next.height)
            ? items : [...items, next];
        }, []);
        outer: for (const size of sizes) {
          const resized = photon.resize(image, size.width, size.height, photon.SamplingFilter.Lanczos3);
          try {
            const encoders = [
              {mime:'image/png', encode:() => resized.get_bytes()},
              ...jpegQualities.map(quality => ({
                mime:'image/jpeg', quality, encode:() => resized.get_bytes_jpeg(quality),
              })),
            ];
            for (const encoder of encoders) {
              const data = Buffer.from(encoder.encode());
              const accepted = Math.ceil(data.length / 3) * 4 <= maxBase64Bytes;
              const attempt = {dimensions:[size.width,size.height], mime:encoder.mime,
                ...(encoder.quality === undefined ? {} : {quality:encoder.quality}),
                bytes:data.length, base64_bytes:Math.ceil(data.length / 3) * 4,
                sha256:hash(data), fits_limit:accepted};
              attempts.push(attempt);
              if (accepted) {
                output = data; selected = attempt; geometry = attempt.dimensions;
                break outer;
              }
            }
          } finally { resized.free(); }
        }
      }
    } finally { image.free(); }
    if (!output || !Array.isArray(input.size) ||
        geometry[0] !== input.size[0] || geometry[1] !== input.size[1] ||
        hash(output) !== input.target_sha256) return null;
    return {output, implementation:{
      engine:'opencode_embedded_photon', photon_version:'0.3.4',
      photon_module:codec.photon_module, photon_wasm:codec.photon_wasm,
      embedded_wasm:embedded, orientation:'stored',
      normalize:{autoResize:true, maxWidth, maxHeight, maxBase64Bytes,
        initial_geometry:'Math.round(source_axis * min(1, maxWidth/width, maxHeight/height))',
        subsequent_geometry:'Math.floor(previous_axis * 0.75), min 1; maximum 32 sizes',
        filter:'Lanczos3', format_order:['image/png','image/jpeg'], jpeg_qualities:jpegQualities},
      selected, attempts,
    }};
  };
}

module.exports = function replayOpenCode(input, codec, pinned, source) {
  if (input.native !== 'opencode' || input.native_version !== '2.0.32') return null;
  const replay = prepareOpenCode(codec, pinned);
  return replay ? replay(input, source) : null;
};
module.exports.prepare = prepareOpenCode;
