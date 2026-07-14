use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::db::models::StorageQuota;
use crate::image::{delete_file, dir_size, generate_variants, save_to_file, ImageError};
use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveImageRequest {
    pub entity: String, // menu-items, guests, employees, rooms, etc.
    pub entity_id: String,
    pub file_name: String,
    pub file_bytes: Vec<u8>,
    pub mime_type: String,
    pub organization_id: String,
    pub property_id: String,
    pub uploaded_by: String,
    pub role: String,          // user role for permission check
    pub is_always_cloud: bool, // true for menu items, logo
}

/// Role-based folder permissions:
/// - PLATFORM_ADMIN, HOTEL_ADMIN, OWNER: all folders
/// - GENERAL_MANAGER: all except employees (HR-only)
/// - RECEPTIONIST: guests, visitors
/// - KITCHEN: menu-items
/// - HR: employees
/// - SECURITY: visitors, lost-found
/// - HOUSEKEEPING: rooms
fn check_folder_permission(role: &str, entity: &str) -> bool {
    let role = role.to_uppercase();
    match role.as_str() {
        "PLATFORM_ADMIN" | "HOTEL_ADMIN" | "OWNER" => true,
        "GENERAL_MANAGER" => entity != "employees",
        "RECEPTIONIST" | "FRONT_DESK" => matches!(entity, "guests" | "visitors"),
        "KITCHEN" | "CHEF" => matches!(entity, "menu-items"),
        "HR" | "HR_MANAGER" => matches!(entity, "employees"),
        "SECURITY" | "SECURITY_OFFICER" => matches!(entity, "visitors" | "lost-found"),
        "HOUSEKEEPING" => matches!(entity, "rooms"),
        "WAITER" | "STEWARD" => matches!(entity, "menu-items"),
        _ => false,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveImageResponse {
    pub thumb_path: String,
    pub medium_path: String,
    pub original_path: String,
    pub thumb_url: String,
    pub medium_url: String,
    pub original_url: String,
    pub width: u32,
    pub height: u32,
    pub size_bytes: u64,
}

/// Save an image locally with auto-generated variants (thumb, medium, original).
/// Old variants for the same entity are deleted first (delete-on-replace).
/// Role-based folder permissions are enforced before saving.
#[tauri::command]
pub async fn save_image_local(
    request: SaveImageRequest,
    state: State<'_, Arc<AppState>>,
) -> Result<SaveImageResponse, String> {
    // Check folder permission
    if !check_folder_permission(&request.role, &request.entity) {
        return Err(format!(
            "Permission denied: role '{}' cannot upload to folder '{}'",
            request.role, request.entity
        ));
    }

    // Check storage quota
    let quota = check_storage_usage(request.organization_id.clone(), state.clone()).await?;
    let total_quota = quota.free_quota_bytes + quota.addon_bytes;
    if quota.used_bytes >= total_quota && !request.is_always_cloud {
        return Err(format!(
            "Storage quota exceeded: used {} bytes, limit {} bytes. Upgrade your plan for more storage.",
            quota.used_bytes, total_quota
        ));
    }

    let images_dir = &state.images_dir;
    let entity_dir = images_dir.join(&request.entity);

    // Delete old variants for this entity (delete-on-replace)
    delete_old_variants(&state, &request.entity, &request.entity_id).map_err(|e| e.to_string())?;

    // Generate image variants
    let variants = generate_variants(&request.file_bytes).map_err(|e| e.to_string())?;

    // Generate unique filename
    let timestamp = Utc::now().timestamp();
    let unique_id = Uuid::new_v4().to_string()[..8].to_string();
    let base_name = format!("{}_{}_{}", request.entity_id, timestamp, unique_id);

    // Save variants
    let thumb_file = format!("{}-thumb.webp", base_name);
    let medium_file = format!("{}-medium.webp", base_name);
    let original_file = format!("{}-original.webp", base_name);

    let thumb_path = entity_dir.join(&thumb_file);
    let medium_path = entity_dir.join(&medium_file);
    let original_path = entity_dir.join(&original_file);

    save_to_file(&variants.thumb, &thumb_path).map_err(|e| e.to_string())?;
    save_to_file(&variants.medium, &medium_path).map_err(|e| e.to_string())?;
    save_to_file(&variants.original, &original_path).map_err(|e| e.to_string())?;

    // Relative paths for storage in DB
    let thumb_rel = format!("{}/{}", request.entity, thumb_file);
    let medium_rel = format!("{}/{}", request.entity, medium_file);
    let original_rel = format!("{}/{}", request.entity, original_file);

    let total_size = variants.thumb.len() + variants.medium.len() + variants.original.len();

    // Store media asset records in SQLite
    for (variant, rel_path, size) in &[
        ("thumb", &thumb_rel, variants.thumb.len()),
        ("medium", &medium_rel, variants.medium.len()),
        ("original", &original_rel, variants.original.len()),
    ] {
        let asset_id = Uuid::new_v4().to_string();
        let conn = state.db.conn().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO media_asset (id, organization_id, property_id, entity, entity_id, variant, local_path, mime_type, size_bytes, width, height, is_synced, is_always_cloud, uploaded_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13)",
            rusqlite::params![
                asset_id,
                request.organization_id,
                request.property_id,
                request.entity,
                request.entity_id,
                variant,
                rel_path,
                "image/webp",
                size,
                if *variant == "original" { Some(variants.original_width as i32) } else { None },
                if *variant == "original" { Some(variants.original_height as i32) } else { None },
                request.is_always_cloud,
                request.uploaded_by,
            ],
        )
        .map_err(|e| e.to_string())?;
    }

    // Queue sync outbox entry for cloud upload
    let outbox_id = Uuid::new_v4().to_string();
    let idempotency_key = format!(
        "media_{}_{}_{}",
        request.entity, request.entity_id, timestamp
    );
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO sync_outbox (id, idempotency_key, entity_type, entity_id, operation, payload, device_id, property_id)
         VALUES (?1, ?2, 'media', ?3, 'CREATE', ?4, ?5, ?6)",
        rusqlite::params![
            outbox_id,
            idempotency_key,
            request.entity_id,
            serde_json::json!({
                "entity": request.entity,
                "entityId": request.entity_id,
                "thumbPath": thumb_rel,
                "mediumPath": medium_rel,
                "originalPath": original_rel,
                "isAlwaysCloud": request.is_always_cloud,
            }).to_string(),
            "desktop", // TODO: use actual device id
            request.property_id,
        ],
    )
    .map_err(|e| e.to_string())?;

    // Build response with tauri:// URLs for the frontend
    Ok(SaveImageResponse {
        thumb_path: thumb_rel.clone(),
        medium_path: medium_rel.clone(),
        original_path: original_rel.clone(),
        thumb_url: format!("tauri://localhost/images/{}", thumb_rel),
        medium_url: format!("tauri://localhost/images/{}", medium_rel),
        original_url: format!("tauri://localhost/images/{}", original_rel),
        width: variants.original_width,
        height: variants.original_height,
        size_bytes: total_size as u64,
    })
}

/// Delete all image variants for an entity (local + R2 deletion)
#[tauri::command]
pub async fn delete_image_local(
    entity: String,
    entity_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    // Get organization_id before deleting local records
    let org_id: Option<String> = {
        let conn = state.db.conn().map_err(|e| e.to_string())?;
        conn.query_row(
            "SELECT organization_id FROM media_asset WHERE entity = ?1 AND entity_id = ?2 LIMIT 1",
            rusqlite::params![entity, entity_id],
            |row| row.get(0),
        )
        .ok()
    };

    // Delete local files and DB records
    delete_old_variants(&state, &entity, &entity_id).map_err(|e| e.to_string())?;

    // Try immediate R2 deletion if configured
    if let Some(org) = org_id {
        if let Err(e) = crate::r2::delete_entity_from_r2(&state.db, &org, &entity, &entity_id).await
        {
            log::warn!("R2 delete failed (will retry via sync outbox): {}", e);
        }
    }

    // Queue sync outbox for R2 deletion (in case immediate delete failed)
    let outbox_id = Uuid::new_v4().to_string();
    let idempotency_key = format!(
        "media_delete_{}_{}_{}",
        entity,
        entity_id,
        Utc::now().timestamp()
    );
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO sync_outbox (id, idempotency_key, entity_type, entity_id, operation, payload, device_id, property_id)
         VALUES (?1, ?2, 'media', ?3, 'DELETE', ?4, ?5, ?6)",
        rusqlite::params![
            outbox_id,
            idempotency_key,
            entity_id,
            serde_json::json!({ "entity": entity }).to_string(),
            "desktop",
            "",
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Get the local file path for an image (used by the frontend to resolve URLs)
#[tauri::command]
pub async fn get_local_image_path(
    relative_path: String,
    state: State<'_, Arc<AppState>>,
) -> Result<String, String> {
    let full_path = state.images_dir.join(&relative_path);
    // Prevent path traversal — canonicalize and verify it's within images_dir
    let canonical_base = state
        .images_dir
        .canonicalize()
        .map_err(|e| format!("Invalid images dir: {}", e))?;
    let canonical_path = full_path
        .canonicalize()
        .map_err(|_| "Image not found locally".to_string())?;
    if !canonical_path.starts_with(&canonical_base) {
        return Err("Image not found locally".to_string());
    }
    Ok(canonical_path.to_string_lossy().to_string())
}

/// Check current storage usage against quota
#[tauri::command]
pub async fn check_storage_usage(
    organization_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<StorageQuota, String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;

    // Get or create quota record
    let quota: Option<StorageQuota> = conn
        .query_row(
            "SELECT id, organization_id, free_quota_bytes, addon_bytes, used_bytes
             FROM storage_quota WHERE organization_id = ?1",
            rusqlite::params![organization_id],
            |row| {
                Ok(StorageQuota {
                    id: row.get(0)?,
                    organization_id: row.get(1)?,
                    free_quota_bytes: row.get(2)?,
                    addon_bytes: row.get(3)?,
                    used_bytes: row.get(4)?,
                })
            },
        )
        .ok();

    let quota = match quota {
        Some(q) => q,
        None => {
            // Create default quota (1GB free)
            let id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO storage_quota (id, organization_id, free_quota_bytes, addon_bytes, used_bytes)
                 VALUES (?1, ?2, 1073741824, 0, 0)",
                rusqlite::params![id, organization_id.clone()],
            )
            .map_err(|e| e.to_string())?;
            StorageQuota {
                id,
                organization_id: organization_id.clone(),
                free_quota_bytes: 1073741824,
                addon_bytes: 0,
                used_bytes: 0,
            }
        }
    };

    // Calculate actual usage from local images directory
    let actual_used = dir_size(&state.images_dir) as i64;

    // Update used_bytes
    conn.execute(
        "UPDATE storage_quota SET used_bytes = ?1, updated_at = datetime('now') WHERE organization_id = ?2",
        rusqlite::params![actual_used, organization_id],
    )
    .map_err(|e| e.to_string())?;

    Ok(StorageQuota {
        used_bytes: actual_used,
        ..quota
    })
}

/// Manually trigger media sync to cloud (R2)
#[tauri::command]
pub async fn sync_media_to_cloud(
    organization_id: String,
    state: State<'_, Arc<AppState>>,
) -> Result<SyncMediaResponse, String> {
    let (synced_count, total_bytes) =
        crate::r2::sync_media_to_r2(&state.db, &state.images_dir, &organization_id).await?;

    Ok(SyncMediaResponse {
        synced_count,
        total_bytes,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncMediaResponse {
    pub synced_count: i32,
    pub total_bytes: i64,
}

/// Delete old image variants from local filesystem and DB
fn delete_old_variants(
    state: &Arc<AppState>,
    entity: &str,
    entity_id: &str,
) -> Result<(), ImageError> {
    let conn = state
        .db
        .conn()
        .map_err(|_| ImageError::Save("DB connection error".to_string()))?;

    // Get old local paths
    let old_paths: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT local_path FROM media_asset WHERE entity = ?1 AND entity_id = ?2")
            .map_err(|_| ImageError::Save("Query error".to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![entity, entity_id], |row| {
                row.get::<_, Option<String>>(0)
            })
            .map_err(|_| ImageError::Save("Query error".to_string()))?;
        rows.filter_map(|r| r.ok()).filter_map(|p| p).collect()
    };

    // Delete old files from filesystem
    for path in &old_paths {
        let full_path = state.images_dir.join(path);
        let _ = delete_file(&full_path);
    }

    // Delete old records from DB
    conn.execute(
        "DELETE FROM media_asset WHERE entity = ?1 AND entity_id = ?2",
        rusqlite::params![entity, entity_id],
    )
    .map_err(|_| ImageError::Save("Delete error".to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_folder_permission;

    // ─── Admin roles → all folders ───

    #[test]
    fn platform_admin_can_access_all_folders() {
        for entity in &[
            "guests",
            "employees",
            "menu-items",
            "rooms",
            "visitors",
            "lost-found",
        ] {
            assert!(
                check_folder_permission("PLATFORM_ADMIN", entity),
                "PLATFORM_ADMIN should access '{}'",
                entity
            );
        }
    }

    #[test]
    fn hotel_admin_can_access_all_folders() {
        for entity in &["guests", "employees", "menu-items", "rooms"] {
            assert!(
                check_folder_permission("HOTEL_ADMIN", entity),
                "HOTEL_ADMIN should access '{}'",
                entity
            );
        }
    }

    #[test]
    fn owner_can_access_all_folders() {
        for entity in &["guests", "employees", "menu-items", "rooms"] {
            assert!(
                check_folder_permission("OWNER", entity),
                "OWNER should access '{}'",
                entity
            );
        }
    }

    // ─── General Manager → all except employees ───

    #[test]
    fn gm_can_access_non_hr_folders() {
        assert!(check_folder_permission("GENERAL_MANAGER", "guests"));
        assert!(check_folder_permission("GENERAL_MANAGER", "menu-items"));
        assert!(check_folder_permission("GENERAL_MANAGER", "rooms"));
    }

    #[test]
    fn gm_cannot_access_employees() {
        assert!(
            !check_folder_permission("GENERAL_MANAGER", "employees"),
            "GM must not access employees (HR-only)"
        );
    }

    // ─── Receptionist → guests, visitors only ───

    #[test]
    fn receptionist_can_access_guests_and_visitors() {
        assert!(check_folder_permission("RECEPTIONIST", "guests"));
        assert!(check_folder_permission("RECEPTIONIST", "visitors"));
    }

    #[test]
    fn receptionist_cannot_access_other_folders() {
        assert!(!check_folder_permission("RECEPTIONIST", "employees"));
        assert!(!check_folder_permission("RECEPTIONIST", "menu-items"));
        assert!(!check_folder_permission("RECEPTIONIST", "rooms"));
    }

    #[test]
    fn front_desk_alias_works() {
        assert!(check_folder_permission("FRONT_DESK", "guests"));
        assert!(check_folder_permission("FRONT_DESK", "visitors"));
        assert!(!check_folder_permission("FRONT_DESK", "employees"));
    }

    // ─── Kitchen → menu-items only ───

    #[test]
    fn kitchen_can_access_menu_items() {
        assert!(check_folder_permission("KITCHEN", "menu-items"));
        assert!(check_folder_permission("CHEF", "menu-items"));
    }

    #[test]
    fn kitchen_cannot_access_other_folders() {
        assert!(!check_folder_permission("KITCHEN", "guests"));
        assert!(!check_folder_permission("KITCHEN", "employees"));
        assert!(!check_folder_permission("KITCHEN", "rooms"));
    }

    // ─── HR → employees only ───

    #[test]
    fn hr_can_access_employees() {
        assert!(check_folder_permission("HR", "employees"));
        assert!(check_folder_permission("HR_MANAGER", "employees"));
    }

    #[test]
    fn hr_cannot_access_other_folders() {
        assert!(!check_folder_permission("HR", "guests"));
        assert!(!check_folder_permission("HR", "menu-items"));
    }

    // ─── Security → visitors, lost-found ───

    #[test]
    fn security_can_access_visitors_and_lost_found() {
        assert!(check_folder_permission("SECURITY", "visitors"));
        assert!(check_folder_permission("SECURITY", "lost-found"));
        assert!(check_folder_permission("SECURITY_OFFICER", "visitors"));
    }

    #[test]
    fn security_cannot_access_other_folders() {
        assert!(!check_folder_permission("SECURITY", "guests"));
        assert!(!check_folder_permission("SECURITY", "employees"));
    }

    // ─── Housekeeping → rooms only ───

    #[test]
    fn housekeeping_can_access_rooms() {
        assert!(check_folder_permission("HOUSEKEEPING", "rooms"));
    }

    #[test]
    fn housekeeping_cannot_access_other_folders() {
        assert!(!check_folder_permission("HOUSEKEEPING", "guests"));
        assert!(!check_folder_permission("HOUSEKEEPING", "menu-items"));
    }

    // ─── Waiter/Steward → menu-items ───

    #[test]
    fn waiter_can_access_menu_items() {
        assert!(check_folder_permission("WAITER", "menu-items"));
        assert!(check_folder_permission("STEWARD", "menu-items"));
    }

    // ─── Unknown role → deny all ───

    #[test]
    fn unknown_role_denied_everywhere() {
        assert!(!check_folder_permission("UNKNOWN_ROLE", "guests"));
        assert!(!check_folder_permission("UNKNOWN_ROLE", "menu-items"));
        assert!(!check_folder_permission("", "guests"));
    }

    // ─── Case insensitivity ───

    #[test]
    fn permission_check_is_case_insensitive() {
        assert!(check_folder_permission("platform_admin", "guests"));
        assert!(check_folder_permission("Platform_Admin", "guests"));
        assert!(check_folder_permission("receptionist", "guests"));
    }
}
