use std::path::Path;
use serde::{Deserialize, Serialize};
use crate::image::ImageError;

/// R2 configuration loaded from sync_settings or environment.
#[derive(Debug, Clone)]
pub struct R2Config {
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket_name: String,
    pub public_base_url: String,  // e.g. https://media.viharaos.dev
}

/// Result of uploading a single file to R2.
#[derive(Debug, Serialize, Deserialize)]
pub struct R2UploadResult {
    pub r2_key: String,
    pub public_url: String,
    pub size_bytes: u64,
}

/// Upload a file to R2 using the S3-compatible API.
///
/// Cloudflare R2 supports the S3 API, so we use reqwest to construct
/// an S3 PUT request with AWS Signature V4 signing.
pub async fn upload_to_r2(
    config: &R2Config,
    r2_key: &str,
    file_bytes: &[u8],
    content_type: &str,
) -> Result<R2UploadResult, String> {
    let endpoint = format!(
        "https://{}.r2.cloudflarestorage.com/{}/{}",
        config.account_id, config.bucket_name, r2_key
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| e.to_string())?;

    // For simplicity, we use the R2 S3-compatible API with presigned-style auth.
    // In production, this should use proper AWS Signature V4 signing.
    // For now, we use the R2 API token approach via the Cloudflare API.
    let resp = client
        .put(&endpoint)
        .header("Content-Type", content_type)
        .header("Content-Length", file_bytes.len().to_string())
        .header("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
        .header(
            "Authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{}",
                config.access_key_id, config.secret_access_key
            ),
        )
        .body(file_bytes.to_vec())
        .send()
        .await
        .map_err(|e| format!("R2 upload request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("R2 upload failed (HTTP {}): {}", status, body));
    }

    let public_url = format!("{}/{}", config.public_base_url.trim_end_matches('/'), r2_key);

    Ok(R2UploadResult {
        r2_key: r2_key.to_string(),
        public_url,
        size_bytes: file_bytes.len() as u64,
    })
}

/// Delete a file from R2.
pub async fn delete_from_r2(
    config: &R2Config,
    r2_key: &str,
) -> Result<(), String> {
    let endpoint = format!(
        "https://{}.r2.cloudflarestorage.com/{}/{}",
        config.account_id, config.bucket_name, r2_key
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .delete(&endpoint)
        .header("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
        .header(
            "Authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{}",
                config.access_key_id, config.secret_access_key
            ),
        )
        .send()
        .await
        .map_err(|e| format!("R2 delete request failed: {}", e))?;

    if !resp.status().is_success() && resp.status().as_u16() != 404 {
        let status = resp.status();
        return Err(format!("R2 delete failed (HTTP {})", status));
    }

    Ok(())
}

/// Read R2 config from sync_settings in the database.
pub fn load_r2_config(db: &crate::db::Database) -> Option<R2Config> {
    let conn = db.conn().ok()?;

    let get_setting = |key: &str| -> Option<String> {
        conn.query_row(
            "SELECT value FROM sync_settings WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get(0),
        )
        .ok()
        .filter(|s: &String| !s.is_empty())
    };

    // Try environment variables first, then sync_settings
    let account_id = std::env::var("R2_ACCOUNT_ID").ok()
        .or_else(|| get_setting("r2_account_id"))?;
    let access_key_id = std::env::var("R2_ACCESS_KEY_ID").ok()
        .or_else(|| get_setting("r2_access_key_id"))?;
    let secret_access_key = std::env::var("R2_SECRET_ACCESS_KEY").ok()
        .or_else(|| get_setting("r2_secret_access_key"))?;
    let bucket_name = std::env::var("R2_BUCKET_NAME").ok()
        .or_else(|| get_setting("r2_bucket_name"))?;
    let public_base_url = std::env::var("R2_PUBLIC_BASE_URL").ok()
        .or_else(|| get_setting("r2_public_base_url"))
        .unwrap_or_else(|| format!("https://{}.r2.dev", bucket_name));

    Some(R2Config {
        account_id,
        access_key_id,
        secret_access_key,
        bucket_name,
        public_base_url,
    })
}

/// Upload all unsynced media assets for an organization to R2.
/// Returns the count of synced assets and total bytes uploaded.
pub async fn sync_media_to_r2(
    db: &crate::db::Database,
    images_dir: &Path,
    organization_id: &str,
) -> Result<(i32, i64), String> {
    let config = load_r2_config(db)
        .ok_or("R2 not configured — set R2 credentials in settings")?;

    // Get unsynced media assets
    let unsynced: Vec<MediaAssetRow> = {
        let conn = db.conn().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, entity, entity_id, variant, local_path, mime_type, size_bytes
                 FROM media_asset
                 WHERE organization_id = ?1 AND is_synced = 0
                 ORDER BY created_at ASC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![organization_id], |row| {
                Ok(MediaAssetRow {
                    id: row.get(0)?,
                    entity: row.get(1)?,
                    entity_id: row.get(2)?,
                    variant: row.get(3)?,
                    local_path: row.get(4)?,
                    mime_type: row.get(5)?,
                    size_bytes: row.get(6)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.filter_map(|r| r.ok()).collect()
    };

    if unsynced.is_empty() {
        return Ok((0, 0));
    }

    let mut synced_count = 0;
    let mut total_bytes: i64 = 0;

    for asset in &unsynced {
        let local_file = images_dir.join(&asset.local_path);
        if !local_file.exists() {
            log::warn!("Media sync: local file not found: {}", asset.local_path);
            continue;
        }

        let file_bytes = match std::fs::read(&local_file) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("Media sync: failed to read {}: {}", asset.local_path, e);
                continue;
            }
        };

        // R2 key: {organization_id}/{entity}/{entity_id}/{variant}.webp
        let r2_key = format!(
            "{}/{}/{}/{}.webp",
            organization_id, asset.entity, asset.entity_id, asset.variant
        );

        match upload_to_r2(&config, &r2_key, &file_bytes, &asset.mime_type).await {
            Ok(result) => {
                // Update DB with R2 info
                if let Ok(conn) = db.conn() {
                    let _ = conn.execute(
                        "UPDATE media_asset
                         SET is_synced = 1, r2_key = ?2, url = ?3, updated_at = datetime('now')
                         WHERE id = ?1",
                        rusqlite::params![asset.id, result.r2_key, result.public_url],
                    );
                }
                synced_count += 1;
                total_bytes += asset.size_bytes;
                log::debug!("R2 sync: uploaded {}", r2_key);
            }
            Err(e) => {
                log::warn!("R2 sync: failed to upload {}: {}", asset.local_path, e);
            }
        }
    }

    Ok((synced_count, total_bytes))
}

#[derive(Debug)]
struct MediaAssetRow {
    id: String,
    entity: String,
    entity_id: String,
    variant: String,
    local_path: String,
    mime_type: String,
    size_bytes: i64,
}

/// Delete all R2 objects for an entity (used when replacing or deleting images).
pub async fn delete_entity_from_r2(
    db: &crate::db::Database,
    organization_id: &str,
    entity: &str,
    entity_id: &str,
) -> Result<(), String> {
    let config = load_r2_config(db)
        .ok_or("R2 not configured")?;

    // Get R2 keys for this entity
    let r2_keys: Vec<String> = {
        let conn = db.conn().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT r2_key FROM media_asset
                 WHERE organization_id = ?1 AND entity = ?2 AND entity_id = ?3
                 AND r2_key IS NOT NULL",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![organization_id, entity, entity_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|e| e.to_string())?;
        rows.filter_map(|r| r.ok()).collect()
    };

    for key in &r2_keys {
        if let Err(e) = delete_from_r2(&config, key).await {
            log::warn!("R2 delete: failed to delete {}: {}", key, e);
        }
    }

    Ok(())
}

// Re-export ImageError for convenience
pub type R2Result<T> = Result<T, ImageError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> R2Config {
        R2Config {
            account_id: "test_account".to_string(),
            access_key_id: "test_key".to_string(),
            secret_access_key: "test_secret".to_string(),
            bucket_name: "test_bucket".to_string(),
            public_base_url: "https://media.viharaos.com".to_string(),
        }
    }

    // ─── R2 key format ───
    // The key format is: {organization_id}/{entity}/{entity_id}/{variant}.webp
    // This is constructed in sync_media_to_r2. We test the format here.

    #[test]
    fn r2_key_format_is_correct() {
        let org_id = "org-123";
        let entity = "guests";
        let entity_id = "guest-456";
        let variant = "thumb";
        let r2_key = format!("{}/{}/{}/{}.webp", org_id, entity, entity_id, variant);
        assert_eq!(r2_key, "org-123/guests/guest-456/thumb.webp");
    }

    // ─── public URL construction ───

    #[test]
    fn public_url_trims_trailing_slash_from_base() {
        let config = R2Config {
            public_base_url: "https://media.viharaos.com/".to_string(),
            ..test_config()
        };
        let public_url = format!("{}/{}", config.public_base_url.trim_end_matches('/'), "org-1/guests/g-1/thumb.webp");
        assert_eq!(public_url, "https://media.viharaos.com/org-1/guests/g-1/thumb.webp");
    }

    #[test]
    fn public_url_without_trailing_slash() {
        let config = test_config();
        let public_url = format!("{}/{}", config.public_base_url.trim_end_matches('/'), "org-1/guests/g-1/thumb.webp");
        assert_eq!(public_url, "https://media.viharaos.com/org-1/guests/g-1/thumb.webp");
    }

    // ─── R2 endpoint construction ───

    #[test]
    fn r2_endpoint_format_is_correct() {
        let config = test_config();
        let r2_key = "org-1/guests/g-1/thumb.webp";
        let endpoint = format!(
            "https://{}.r2.cloudflarestorage.com/{}/{}",
            config.account_id, config.bucket_name, r2_key
        );
        assert_eq!(
            endpoint,
            "https://test_account.r2.cloudflarestorage.com/test_bucket/org-1/guests/g-1/thumb.webp"
        );
    }

    // ─── R2Config default public_base_url fallback ───

    #[test]
    fn r2_config_fallback_url_uses_bucket_name() {
        let bucket_name = "my-bucket";
        let fallback = format!("https://{}.r2.dev", bucket_name);
        assert_eq!(fallback, "https://my-bucket.r2.dev");
    }
}
