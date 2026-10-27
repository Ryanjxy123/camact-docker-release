// Fixed offline transformation decoder. Captured Agent code is never evaluated.
const fs = require('node:fs');
const crypto = require('node:crypto');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const sharp = input.native ? null : require(input.sharp);
if (sharp) sharp.concurrency(1);
const hash = b => crypto.createHash('sha256').update(b).digest('hex');
(async () => {
  if (input.native) {
    const proof = await require('./visual_native_exact.cjs')(input);
    process.stdout.write(JSON.stringify(proof));
    return;
  }
  const source = fs.readFileSync(input.source);
  // OpenClaw's public raster layer uses Photon, not Sharp. Execute only this
  // pinned decoder with fixed encode options; no captured Agent code runs.
  if (input.rastermill) {
    const {pathToFileURL} = require('node:url');
    const {createRastermill} = await import(pathToFileURL(input.rastermill).href);
    const raster = createRastermill({execution:'internal',
      limits:{inputPixels:25000000,outputPixels:25000000}});
    const sources = [{data:source,stage:'direct'}];
    // Native Read first fits 2000x2000 at quality 80. The outer tool sanitizer
    // independently fits 1200px at quality 85. Reproduce the public pipeline.
    const probe = await raster.probe(source);
    if (probe && (Math.max(probe.width,probe.height)>2000 ||
                  Math.ceil(source.length/3)*4 >= 4.5*1024*1024)) {
      try {
        const normalized = await raster.encode(source,{format:'auto',
          limits:{maxWidth:2000,maxHeight:2000},maxBytes:Math.floor(4.5*1024*1024/4)*3,
          opaque:{format:'jpeg',quality:80},transparent:{format:'png'},
          search:{quality:[80,85,70,55,40,35],compressionLevel:[6,9]}});
        sources.unshift({data:normalized.data,stage:'native_read_2000px_quality80'});
      } catch (_) {}
    }
    for (const normalized of sources) {
      for (const quality of [85,75,65,55,45,35]) {
        try {
          const out = await raster.encode(normalized.data, {format:'jpeg',
            resize:{maxSide:Math.max(...input.size),enlarge:false}, quality});
          if (hash(out.data) === input.target_sha256) {
            const path = require('node:path');
            const version = JSON.parse(fs.readFileSync(path.join(path.dirname(input.rastermill),'../package.json'))).version;
            process.stdout.write(JSON.stringify({engine:'rastermill',version,
              backend:'photon_internal',input_stage:normalized.stage,
              maxSide:Math.max(...input.size),quality,verification:'encoded_sha256_exact',
              replayed_sha256:hash(out.data)}));
            return;
          }
        } catch (_) { break; }
      }
    }
  }
  // DeepSeek's pinned attachment store first enforces its public 4 Mi-pixel
  // normalization budget, then derives the model request's long-edge size.
  // Replay only fixed source-backed decoder operations, never Agent code.
  const metadata = await sharp(source, {limitInputPixels:false}).metadata();
  const transposed = metadata.orientation >= 5;
  const sourceWidth = transposed ? metadata.height : metadata.width;
  const sourceHeight = transposed ? metadata.width : metadata.height;
  const maxPixels = 4194304;
  if (sourceWidth * sourceHeight > maxPixels) {
    const scale = Math.sqrt(maxPixels / (sourceWidth * sourceHeight));
    const byWidth = sourceWidth >= sourceHeight;
    let long = Math.max(1, Math.floor((byWidth ? sourceWidth : sourceHeight) * scale));
    const short = () => Math.max(1, Math.round(long *
      (byWidth ? sourceHeight / sourceWidth : sourceWidth / sourceHeight)));
    while (long * short() > maxPixels && long > 1) long -= 1;
    const normalizedSize = byWidth ? {width:long,height:short()} : {width:short(),height:long};
    for (const normalizationQuality of [85,75,60]) {
      const normalized = await sharp(source, {limitInputPixels:false}).rotate().toColourspace('srgb')
        .resize({...normalizedSize,fit:'inside',withoutEnlargement:true})
        .jpeg({quality:normalizationQuality}).toBuffer();
      for (const quality of [85,75,60]) {
        const out = await sharp(normalized, {limitInputPixels:false}).toColourspace('srgb')
          .resize({...byWidth ? {width:input.size[0]} : {height:input.size[1]},withoutEnlargement:true})
          .jpeg({quality}).toBuffer();
        if (hash(out) === input.target_sha256) {
          process.stdout.write(JSON.stringify({engine:'sharp',versions:sharp.versions,
            pipeline:'deepseek_attachment_pixel_cap_v1',normalization_max_pixels:maxPixels,
            normalized_dimensions:normalizedSize,normalization_quality:normalizationQuality,
            quality,verification:'encoded_sha256_exact',replayed_sha256:hash(out)}));
          return;
        }
      }
    }
  }
  for (const normalize of [false, true]) {
    const normalized = normalize ? await sharp(source).rotate().toColourspace('srgb').jpeg({quality:85}).toBuffer() : source;
    for (const rotate of [false, true]) {
      for (const kernel of ['lanczos3', 'cubic', 'linear']) {
        for (const quality of [85, 80, 90, 75, 60, 100]) {
          let p = sharp(normalized, {limitInputPixels:false});
          if (rotate) p = p.rotate();
          p = p.toColourspace('srgb').resize({width:input.size[0], height:input.size[1], fit:'fill', kernel});
          const out = await p.jpeg({quality}).toBuffer();
          if (hash(out) === input.target_sha256) {
            process.stdout.write(JSON.stringify({engine:'sharp', versions:sharp.versions,
              normalize_jpeg85:normalize, exif_transpose:rotate, kernel, quality,
              verification:'encoded_sha256_exact', replayed_sha256:hash(out)}));
            return;
          }
        }
      }
    }
  }
  process.stdout.write('null');
})().catch(() => { process.stdout.write('null'); process.exitCode=1; });
