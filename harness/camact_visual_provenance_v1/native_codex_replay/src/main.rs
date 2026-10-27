//! Fixed offline replay of Codex rust-v0.147.0 utils/image's JPEG path.
//! No captured Agent code or model call is executed.
use std::{fs, io::{self, Cursor, Read, Write}, path::Path};
use image::{DynamicImage, ImageDecoder, ImageEncoder, ImageReader};
use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let stdio = args.len() == 1;
    let values = if stdio {
        let mut input = String::new();
        io::stdin().take(16384).read_to_string(&mut input)?;
        let lines: Vec<String> = input.lines().map(str::to_owned).collect();
        if lines.len() != 3 { return Err("expected source, width, height on stdin".into()); }
        vec![args[0].clone(), lines[0].clone(), String::new(), lines[1].clone(), lines[2].clone()]
    } else { args };
    if values.len() != 5 {
        return Err("usage: replay SOURCE OUTPUT WIDTH HEIGHT".into());
    }
    let source = fs::read(Path::new(&values[1]))?;
    let width: u32 = values[3].parse()?;
    let height: u32 = values[4].parse()?;
    if width == 0 || height == 0 || width as u64 * height as u64 > 25_000_000 {
        return Err("invalid replay dimensions".into());
    }
    let mut decoder = ImageReader::new(Cursor::new(&source))
        .with_guessed_format()?.into_decoder()?;
    let icc_profile = decoder.icc_profile()?.filter(|p| p.get(16..20) == Some(b"RGB "));
    let exif = decoder.exif_metadata()?;
    let decoded = DynamicImage::from_decoder(decoder)?;
    // The public ResizeWithLimits routine preserves the complete stored frame.
    // Its dimension rounding can lose at most one output pixel per axis; an
    // arbitrary stretch or enlargement is not a supported native replay.
    let aspect_error = (width as i64 * decoded.height() as i64
        - height as i64 * decoded.width() as i64).unsigned_abs();
    if width > decoded.width() || height > decoded.height() || width > 2048 || height > 2048
        || aspect_error > decoded.width() as u64 + decoded.height() as u64 {
        return Err("dimensions do not preserve the native full frame".into());
    }
    let resized = decoded.resize_exact(width, height, FilterType::Triangle);
    let mut bytes = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut bytes, 85);
    if let Some(profile) = icc_profile { encoder.set_icc_profile(profile)?; }
    if let Some(exif) = exif { encoder.set_exif_metadata(exif)?; }
    encoder.encode_image(&resized)?;
    if stdio {
        io::stdout().write_all(&bytes)?;
    } else {
        fs::write(Path::new(&values[2]), &bytes)?;
        println!("source={}x{} output={}x{} bytes={}", decoded.width(), decoded.height(), width, height, bytes.len());
    }
    Ok(())
}
