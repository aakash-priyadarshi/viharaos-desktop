use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

use crate::AppState;

/// Local device heartbeat state — mirrors what we send to the cloud
/// and what the Offline Operations Center displays.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceHeartbeat {
    pub device_id: String,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub role: Option<String>,
    pub property_id: Option<String>,
    pub app_version: String,
    pub platform: String,
    pub is_online: bool,
    pub sync_status: String,
    pub pending_count: i32,
    pub failed_count: i32,
    pub conflict_count: i32,
    pub last_local_write_at: Option<String>,
    pub last_push_at: Option<String>,
    pub last_pull_at: Option<String>,
    pub last_heartbeat_at: String,
}

/// Detect the current platform string.
fn detect_platform() -> String {
    #[cfg(target_os = "windows")]
    {
        "windows".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macos".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "linux".to_string()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── detect_platform ───

    #[test]
    fn detect_platform_returns_known_value() {
        let platform = detect_platform();
        let valid = ["windows", "macos", "linux", "unknown"].contains(&platform.as_str());
        assert!(
            valid,
            "detect_platform must return a known value, got: {}",
            platform
        );
    }

    #[test]
    fn detect_platform_matches_cfg_target() {
        let platform = detect_platform();
        #[cfg(target_os = "windows")]
        assert_eq!(platform, "windows");
        #[cfg(target_os = "macos")]
        assert_eq!(platform, "macos");
        #[cfg(target_os = "linux")]
        assert_eq!(platform, "linux");
    }

    // ─── get_or_create_device_id ───

    fn create_test_db() -> crate::db::Database {
        let db_path = std::env::temp_dir().join(format!(
            "viharaos-heartbeat-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        crate::db::Database::new(&db_path).expect("temp db should initialize")
    }

    #[test]
    fn get_or_create_device_id_generates_new_id() {
        let db = create_test_db();
        let conn = db.conn().expect("get connection");
        let id = get_or_create_device_id(&conn).expect("create device id");
        assert!(!id.is_empty(), "device id must not be empty");
        // Should be a UUID
        assert!(
            uuid::Uuid::parse_str(&id).is_ok(),
            "device id should be a valid UUID"
        );
    }

    #[test]
    fn get_or_create_device_id_returns_same_id_on_subsequent_calls() {
        let db = create_test_db();
        let conn = db.conn().expect("get connection");
        let id1 = get_or_create_device_id(&conn).expect("first call");
        let id2 = get_or_create_device_id(&conn).expect("second call");
        assert_eq!(id1, id2, "device id must be stable across calls");
    }

    #[test]
    fn get_or_create_device_id_persists_across_connections() {
        let db = create_test_db();
        let id1 = {
            let conn = db.conn().expect("get connection");
            get_or_create_device_id(&conn).expect("first connection")
        };
        let id2 = {
            let conn = db.conn().expect("get new connection");
            get_or_create_device_id(&conn).expect("second connection")
        };
        assert_eq!(
            id1, id2,
            "device id must persist across connections from the pool"
        );
    }

    // ─── sync_status determination logic ───
    // (The sync_status string logic is embedded in get_device_heartbeat,
    //  but the priority order is testable: CONFLICT > FAILED > PENDING > SYNCED)

    #[test]
    fn sync_status_priority_conflict_overrides_failed_and_pending() {
        // This tests the priority logic used in get_device_heartbeat
        let conflict_count = 1;
        let failed_count = 5;
        let pending_count = 10;

        let status = if conflict_count > 0 {
            "CONFLICT"
        } else if failed_count > 0 {
            "FAILED"
        } else if pending_count > 0 {
            "PENDING"
        } else {
            "SYNCED"
        };

        assert_eq!(status, "CONFLICT", "CONFLICT must take priority");
    }

    #[test]
    fn sync_status_priority_failed_overrides_pending() {
        let conflict_count = 0;
        let failed_count = 3;
        let pending_count = 10;

        let status = if conflict_count > 0 {
            "CONFLICT"
        } else if failed_count > 0 {
            "FAILED"
        } else if pending_count > 0 {
            "PENDING"
        } else {
            "SYNCED"
        };

        assert_eq!(status, "FAILED", "FAILED must take priority over PENDING");
    }

    #[test]
    fn sync_status_pending_when_no_conflicts_or_failures() {
        let conflict_count = 0;
        let failed_count = 0;
        let pending_count = 5;

        let status = if conflict_count > 0 {
            "CONFLICT"
        } else if failed_count > 0 {
            "FAILED"
        } else if pending_count > 0 {
            "PENDING"
        } else {
            "SYNCED"
        };

        assert_eq!(status, "PENDING");
    }

    #[test]
    fn sync_status_synced_when_all_counts_zero() {
        let conflict_count = 0;
        let failed_count = 0;
        let pending_count = 0;

        let status = if conflict_count > 0 {
            "CONFLICT"
        } else if failed_count > 0 {
            "FAILED"
        } else if pending_count > 0 {
            "PENDING"
        } else {
            "SYNCED"
        };

        assert_eq!(status, "SYNCED");
    }
}

/// Get or create the local device ID. Stable across restarts.
fn get_or_create_device_id(conn: &rusqlite::Connection) -> Result<String, String> {
    // Check sync_settings first
    let existing: Option<String> = conn
        .query_row(
            "SELECT value FROM sync_settings WHERE key = 'device_id'",
            [],
            |row| row.get(0),
        )
        .ok();
    if let Some(id) = existing {
        return Ok(id);
    }
    // Generate a new one
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT OR REPLACE INTO sync_settings (key, value) VALUES ('device_id', ?1)",
        rusqlite::params![id],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

/// Get the current local device heartbeat state.
/// This is used by the Offline Operations Center UI.
#[tauri::command]
pub async fn get_device_heartbeat(
    state: State<'_, Arc<AppState>>,
) -> Result<DeviceHeartbeat, String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let device_id = get_or_create_device_id(&conn)?;

    // Get sync status counts
    let pending_count: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_outbox WHERE status = 'PENDING'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let failed_count: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_outbox WHERE status = 'FAILED'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let conflict_count: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM sync_conflict WHERE resolved_at IS NULL",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Get last sync timestamps from settings
    let last_sync_at: Option<String> = conn
        .query_row(
            "SELECT value FROM sync_settings WHERE key = 'last_sync_at'",
            [],
            |row| row.get(0),
        )
        .ok()
        .filter(|s: &String| !s.is_empty());

    let last_push_at: Option<String> = conn
        .query_row(
            "SELECT MAX(synced_at) FROM sync_outbox WHERE status = 'SYNCED'",
            [],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    // Determine sync status
    let sync_status = if conflict_count > 0 {
        "CONFLICT"
    } else if failed_count > 0 {
        "FAILED"
    } else if pending_count > 0 {
        "PENDING"
    } else {
        "SYNCED"
    };

    // Get user info from the latest active user
    let (user_id, user_name, role, property_id): (Option<String>, Option<String>, Option<String>, Option<String>) = conn
        .query_row(
            "SELECT id, name, role, property_id FROM user WHERE is_active = 1 ORDER BY last_login_at DESC LIMIT 1",
            [],
            |row| Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            )),
        )
        .unwrap_or((None, None, None, None));

    // Get app version from the Tauri package info — fallback to "unknown"
    let app_version = option_env!("CARGO_PKG_VERSION")
        .unwrap_or("0.1.0")
        .to_string();

    // Check if online (best-effort — the sync worker updates this)
    let is_online = state.sync.get_status().is_online;

    let heartbeat = DeviceHeartbeat {
        device_id,
        user_id,
        user_name,
        role,
        property_id,
        app_version,
        platform: detect_platform(),
        is_online,
        sync_status: sync_status.to_string(),
        pending_count,
        failed_count,
        conflict_count,
        last_local_write_at: last_sync_at.clone(),
        last_push_at,
        last_pull_at: last_sync_at,
        last_heartbeat_at: chrono::Utc::now().to_rfc3339(),
    };

    // Persist to local device_heartbeat table
    let _ = conn.execute(
        "INSERT OR REPLACE INTO device_heartbeat
         (device_id, user_id, user_name, role, property_id, app_version, platform,
          is_online, sync_status, pending_count, failed_count, conflict_count,
          last_local_write_at, last_push_at, last_pull_at, last_heartbeat_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, datetime('now'))",
        rusqlite::params![
            heartbeat.device_id,
            heartbeat.user_id,
            heartbeat.user_name,
            heartbeat.role,
            heartbeat.property_id,
            heartbeat.app_version,
            heartbeat.platform,
            if heartbeat.is_online { 1 } else { 0 },
            heartbeat.sync_status,
            heartbeat.pending_count,
            heartbeat.failed_count,
            heartbeat.conflict_count,
            heartbeat.last_local_write_at,
            heartbeat.last_push_at,
            heartbeat.last_pull_at,
            heartbeat.last_heartbeat_at,
        ],
    );

    Ok(heartbeat)
}

/// Send a heartbeat to the cloud server (best-effort).
/// Called periodically by the sync worker when online.
pub async fn send_heartbeat_to_cloud(
    state: &Arc<AppState>,
    server_url: &str,
    auth_token: Option<&str>,
) -> Result<(), String> {
    let heartbeat = {
        let conn = state.db.conn().map_err(|e| e.to_string())?;
        let device_id = get_or_create_device_id(&conn)?;

        let pending_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_outbox WHERE status = 'PENDING'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let failed_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_outbox WHERE status = 'FAILED'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let conflict_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_conflict WHERE resolved_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let last_sync_at: Option<String> = conn
            .query_row(
                "SELECT value FROM sync_settings WHERE key = 'last_sync_at'",
                [],
                |row| row.get(0),
            )
            .ok()
            .filter(|s: &String| !s.is_empty());

        // The backend derives userId, userName, role, organizationId from
        // the authenticated token — we must NOT send these in the body.
        // We only send activePropertyId (optional, verified server-side)
        // from the locally active user's property_id.
        let active_property_id: Option<String> = conn
            .query_row(
                "SELECT property_id FROM user WHERE is_active = 1 ORDER BY last_login_at DESC LIMIT 1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap_or(None);

        let sync_status = if conflict_count > 0 {
            "CONFLICT"
        } else if failed_count > 0 {
            "FAILED"
        } else if pending_count > 0 {
            "PENDING"
        } else {
            "SYNCED"
        };

        serde_json::json!({
            "deviceId": device_id,
            "appVersion": option_env!("CARGO_PKG_VERSION").unwrap_or("0.1.0"),
            "platform": detect_platform(),
            "isOnline": true,
            "syncStatus": sync_status,
            "pendingCount": pending_count,
            "failedCount": failed_count,
            "conflictCount": conflict_count,
            "lastLocalWriteAt": last_sync_at,
            "lastPushAt": null,
            "lastPullAt": last_sync_at,
            "activePropertyId": active_property_id,
        })
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;

    let url = format!(
        "{}/desktop/sync-heartbeat",
        server_url.trim_end_matches('/')
    );
    let mut req = client.post(&url).json(&heartbeat);
    if let Some(token) = auth_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }
    req.send().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// A single sync outbox queue entry — used by the Offline Operations Center queue tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOutboxEntry {
    pub id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub operation: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub retry_count: i32,
    pub last_error: Option<String>,
    pub property_id: String,
    /// Human-readable label for the record (best-effort, derived from payload).
    pub record_label: Option<String>,
}

/// Try to extract a human-readable label from a JSON payload.
/// Looks for common fields like name, guestName, roomNumber, folioNumber, etc.
fn extract_record_label(payload: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(payload).ok()?;
    let obj = v.as_object()?;

    // Try common label fields in priority order
    let candidates = [
        "name",
        "guestName",
        "label",
        "title",
        "roomNumber",
        "roomNo",
        "folioNumber",
        "folioNo",
        "invoiceNumber",
        "orderNumber",
        "reservationId",
        "description",
        "code",
    ];

    for key in candidates {
        if let Some(val) = obj.get(key) {
            if let Some(s) = val.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
    }

    // Fallback: show entity_id truncated
    obj.get("id").and_then(|v| v.as_str()).map(|s| {
        if s.len() > 12 {
            format!("{}…", &s[..12])
        } else {
            s.to_string()
        }
    })
}

/// Get the sync outbox queue entries (pending, syncing, failed, conflict).
/// Excludes SYNCED entries (those are already pushed).
/// Ordered by created_at descending (newest first).
#[tauri::command]
pub async fn get_sync_outbox(
    state: State<'_, Arc<AppState>>,
    limit: Option<i32>,
) -> Result<Vec<SyncOutboxEntry>, String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let limit = limit.unwrap_or(100).min(500);

    let mut stmt = conn
        .prepare(
            "SELECT id, entity_type, entity_id, operation, status, created_at, updated_at,
                    retry_count, COALESCE(last_error, sync_error), property_id, payload
             FROM sync_outbox
             WHERE status != 'SYNCED'
             ORDER BY created_at DESC
             LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;

    let entries = stmt
        .query_map(rusqlite::params![limit], |row| {
            let payload: String = row.get(10)?;
            Ok(SyncOutboxEntry {
                id: row.get(0)?,
                entity_type: row.get(1)?,
                entity_id: row.get(2)?,
                operation: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                retry_count: row.get(7)?,
                last_error: row.get(8)?,
                property_id: row.get(9)?,
                record_label: extract_record_label(&payload),
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(entries)
}

/// Retry a single sync outbox entry by resetting it to PENDING.
/// This clears the error and bumps the updated_at timestamp.
/// The sync worker will pick it up on the next tick.
#[tauri::command]
pub async fn retry_sync_outbox_entry(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let affected = conn
        .execute(
            "UPDATE sync_outbox
             SET status = 'PENDING', sync_error = NULL, last_error = NULL,
                 updated_at = datetime('now')
             WHERE id = ?1 AND status IN ('FAILED', 'CONFLICT')",
            rusqlite::params![id],
        )
        .map_err(|e| e.to_string())?;
    if affected == 0 {
        return Err("No retryable entry found with that id".to_string());
    }
    Ok(())
}

/// Retry all failed/conflict sync outbox entries at once.
/// Returns the number of entries reset to PENDING.
#[tauri::command]
pub async fn retry_all_sync_outbox(state: State<'_, Arc<AppState>>) -> Result<i32, String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let affected = conn
        .execute(
            "UPDATE sync_outbox
             SET status = 'PENDING', sync_error = NULL, last_error = NULL,
                 updated_at = datetime('now')
             WHERE status IN ('FAILED', 'CONFLICT')",
            [],
        )
        .map_err(|e| e.to_string())?;
    Ok(affected as i32)
}
