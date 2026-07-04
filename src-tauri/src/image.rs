use std::io::Cursor;
use std::path::Path;
use image::{ImageFormat, ImageReader, DynamicImage, imageops::FilterType};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ImageError {
    #[error("Image decode error: {0}")]
    Decode(String),
    #[error("Image encode error: {0}")]
    Encode(String),
    #[error("Image save error: {0}")]
    Save(String),
    #[error("Invalid input: {0}")]
    Invalid(String),
}

pub type ImageResult<T> = Result<T, ImageError>;

/// Generated image variants for a single source image.
pub struct ImageVariants {
    pub original: Vec<u8>,
    pub medium: Vec<u8>,
    pub thumb: Vec<u8>,
    pub original_width: u32,
    pub original_height: u32,
}

/// Generate three variants from a source image:
/// - original: max 1024px, WebP quality 85
/// - medium: max 600px, WebP quality 80
/// - thumb: 150x150px square crop, WebP quality 75
pub fn generate_variants(source_bytes: &[u8]) -> ImageResult<ImageVariants> {
    let reader = ImageReader::new(Cursor::new(source_bytes))
        .with_guessed_format()
        .map_err(|e| ImageError::Decode(e.to_string()))?;

    let format = reader.format().ok_or(ImageError::Invalid(
        "Could not detect image format".to_string(),
    ))?;

    let img = reader
        .decode()
        .map_err(|e| ImageError::Decode(e.to_string()))?;

    let (orig_w, orig_h) = (img.width(), img.height());

    // Original: resize to max 1024px maintaining aspect ratio
    let original = resize_to_max(&img, 1024);
    let original_bytes = encode_webp(&original, 85)?;

    // Medium: resize to max 600px maintaining aspect ratio
    let medium = resize_to_max(&img, 600);
    let medium_bytes = encode_webp(&medium, 80)?;

    // Thumb: 150x150 square crop
    let thumb = crop_square(&img, 150);
    let thumb_bytes = encode_webp(&thumb, 75)?;

    Ok(ImageVariants {
        original: original_bytes,
        medium: medium_bytes,
        thumb: thumb_bytes,
        original_width: orig_w,
        original_height: orig_h,
    })
}

fn resize_to_max(img: &DynamicImage, max_dim: u32) -> DynamicImage {
    let (w, h) = (img.width(), img.height());
    if w <= max_dim && h <= max_dim {
        return img.clone();
    }
    let ratio = w as f32 / h as f32;
    let (new_w, new_h) = if w > h {
        (max_dim, (max_dim as f32 / ratio) as u32)
    } else {
        ((max_dim as f32 * ratio) as u32, max_dim)
    };
    img.resize_exact(new_w, new_h, FilterType::Lanczos3)
}

fn crop_square(img: &DynamicImage, size: u32) -> DynamicImage {
    let (w, h) = (img.width(), img.height());
    let min_dim = w.min(h);
    let x = (w - min_dim) / 2;
    let y = (h - min_dim) / 2;
    let cropped = img.crop_imm(x, y, min_dim, min_dim);
    cropped.resize_exact(size, size, FilterType::Lanczos3)
}

fn encode_webp(img: &DynamicImage, quality: u8) -> ImageResult<Vec<u8>> {
    let mut buf = Cursor::new(Vec::new());
    img.write_to(&mut buf, ImageFormat::WebP)
        .map_err(|e| ImageError::Encode(e.to_string()))?;
    Ok(buf.into_inner())
}

/// Save image bytes to a file path, creating parent directories if needed.
pub fn save_to_file(bytes: &[u8], path: &Path) -> ImageResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ImageError::Save(e.to_string()))?;
    }
    std::fs::write(path, bytes)
        .map_err(|e| ImageError::Save(e.to_string()))
}

/// Delete a file if it exists. Does not error if file doesn't exist.
pub fn delete_file(path: &Path) -> ImageResult<()> {
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|e| ImageError::Save(e.to_string()))?;
    }
    Ok(())
}

/// Calculate total size of all files in a directory tree (in bytes).
pub fn dir_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    let mut total: u64 = 0;
    for entry in walkdir::WalkDir::new(path).into_iter().flatten() {
        if entry.file_type().is_file() {
            total += entry
                .metadata()
                .map(|m| m.len())
                .unwrap_or(0);
        }
    }
    total
}
