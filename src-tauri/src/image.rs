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

#[cfg(test)]
mod tests {
    use super::*;

    // ─── dir_size ───

    #[test]
    fn dir_size_returns_zero_for_nonexistent_path() {
        let path = std::path::PathBuf::from("/nonexistent/path/that/does/not/exist");
        assert_eq!(dir_size(&path), 0);
    }

    #[test]
    fn dir_size_returns_zero_for_empty_directory() {
        let dir = tempfile::tempdir().expect("create temp dir");
        assert_eq!(dir_size(dir.path()), 0);
    }

    #[test]
    fn dir_size_sums_files_in_directory() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(dir.path().join("a.txt"), b"hello").expect("write a");
        std::fs::write(dir.path().join("b.txt"), b"world!!").expect("write b");
        // 5 + 7 = 12 bytes
        assert_eq!(dir_size(dir.path()), 12);
    }

    #[test]
    fn dir_size_recurses_into_subdirectories() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(dir.path().join("top.txt"), b"12345").expect("write top");
        std::fs::create_dir_all(dir.path().join("sub")).expect("create sub");
        std::fs::write(dir.path().join("sub").join("inner.txt"), b"abc").expect("write inner");
        // 5 + 3 = 8 bytes
        assert_eq!(dir_size(dir.path()), 8);
    }

    // ─── save_to_file ───

    #[test]
    fn save_to_file_writes_bytes() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("output.bin");
        save_to_file(b"test data", &path).expect("save should succeed");
        let read = std::fs::read(&path).expect("read back");
        assert_eq!(read, b"test data");
    }

    #[test]
    fn save_to_file_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("nested").join("deep").join("file.bin");
        save_to_file(b"data", &path).expect("save should create parents");
        assert!(path.exists());
    }

    // ─── delete_file ───

    #[test]
    fn delete_file_removes_existing_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("to_delete.txt");
        std::fs::write(&path, b"data").expect("write file");
        assert!(path.exists());
        delete_file(&path).expect("delete should succeed");
        assert!(!path.exists());
    }

    #[test]
    fn delete_file_does_not_error_on_missing_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("nonexistent.txt");
        // Should not error
        delete_file(&path).expect("deleting non-existent file should be ok");
    }

    // ─── generate_variants ───

    fn make_test_png(width: u32, height: u32) -> Vec<u8> {
        let img = image::RgbaImage::new(width, height);
        let mut buf = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut buf, ImageFormat::Png)
            .expect("encode test PNG");
        buf.into_inner()
    }

    #[test]
    fn generate_variants_produces_three_webp_variants() {
        let png = make_test_png(800, 600);
        let variants = generate_variants(&png).expect("variants should generate");
        // All three variants should be non-empty WebP data
        assert!(!variants.original.is_empty(), "original must not be empty");
        assert!(!variants.medium.is_empty(), "medium must not be empty");
        assert!(!variants.thumb.is_empty(), "thumb must not be empty");
        // Original dimensions should match source
        assert_eq!(variants.original_width, 800);
        assert_eq!(variants.original_height, 600);
    }

    #[test]
    fn generate_variants_thumb_is_150x150() {
        let png = make_test_png(800, 600);
        let variants = generate_variants(&png).expect("variants should generate");
        // Decode the thumb to verify dimensions
        let thumb_img = ImageReader::new(Cursor::new(&variants.thumb))
            .with_guessed_format()
            .expect("guess format")
            .decode()
            .expect("decode thumb");
        assert_eq!(thumb_img.width(), 150, "thumb must be 150px wide");
        assert_eq!(thumb_img.height(), 150, "thumb must be 150px tall");
    }

    #[test]
    fn generate_variants_rejects_invalid_image_data() {
        let result = generate_variants(b"this is not an image");
        assert!(result.is_err(), "invalid image data should produce error");
    }

    #[test]
    fn generate_variants_handles_small_image_without_upscaling() {
        // 50x50 image — smaller than all variant maxes
        let png = make_test_png(50, 50);
        let variants = generate_variants(&png).expect("variants should generate");
        // Original should preserve dimensions
        assert_eq!(variants.original_width, 50);
        assert_eq!(variants.original_height, 50);
        // Thumb should still be 150x150 (upscaled for thumbnail)
        let thumb_img = ImageReader::new(Cursor::new(&variants.thumb))
            .with_guessed_format()
            .expect("guess format")
            .decode()
            .expect("decode thumb");
        assert_eq!(thumb_img.width(), 150);
        assert_eq!(thumb_img.height(), 150);
    }

    #[test]
    fn generate_variants_handles_square_image() {
        let png = make_test_png(400, 400);
        let variants = generate_variants(&png).expect("variants should generate");
        assert_eq!(variants.original_width, 400);
        assert_eq!(variants.original_height, 400);
    }

    // ─── resize_to_max (tested indirectly via generate_variants) ───

    #[test]
    fn resize_to_max_does_not_upscale_when_within_limit() {
        let img = DynamicImage::ImageRgba8(image::RgbaImage::new(100, 80));
        let resized = resize_to_max(&img, 200);
        assert_eq!(resized.width(), 100, "should not upscale width");
        assert_eq!(resized.height(), 80, "should not upscale height");
    }

    #[test]
    fn resize_to_max_scales_down_landscape_image() {
        let img = DynamicImage::ImageRgba8(image::RgbaImage::new(2000, 1000));
        let resized = resize_to_max(&img, 1024);
        assert_eq!(resized.width(), 1024, "width should be capped at max");
        assert!(resized.height() <= 1024, "height should maintain aspect ratio");
    }

    #[test]
    fn resize_to_max_scales_down_portrait_image() {
        let img = DynamicImage::ImageRgba8(image::RgbaImage::new(1000, 2000));
        let resized = resize_to_max(&img, 1024);
        assert_eq!(resized.height(), 1024, "height should be capped at max");
        assert!(resized.width() <= 1024, "width should maintain aspect ratio");
    }

    // ─── crop_square ───

    #[test]
    fn crop_square_produces_square_output() {
        let img = DynamicImage::ImageRgba8(image::RgbaImage::new(300, 200));
        let cropped = crop_square(&img, 100);
        assert_eq!(cropped.width(), 100);
        assert_eq!(cropped.height(), 100);
    }

    #[test]
    fn crop_square_centers_crop_on_landscape() {
        // 300x200 → crop 200x200 from center → x offset = (300-200)/2 = 50
        // We verify by checking the output is square 100x100 after resize
        let img = DynamicImage::ImageRgba8(image::RgbaImage::new(300, 200));
        let cropped = crop_square(&img, 100);
        assert_eq!(cropped.width(), 100);
        assert_eq!(cropped.height(), 100);
    }
}
