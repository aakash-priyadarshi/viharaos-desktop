use std::sync::Arc;
use tauri::State;
use serde::{Deserialize, Serialize};

use crate::AppState;

/// A sync conflict entry from the local SQLite database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConflict {
    pub id: String,
    pub entity_type: String,
    pub entity_id: String,
    pub local_payload: String,
    pub server_payload: String,
    pub conflict_type: String,
    pub resolution: Option<String>,
    pub resolved_payload: Option<String>,
    pub resolved_by: Option<String>,
    pub resolved_at: Option<String>,
    pub created_at: String,
    pub property_id: String,
}

/// Get all unresolved sync conflicts.
#[tauri::command]
pub async fn get_sync_conflicts(
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<SyncConflict>, String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT id, entity_type, entity_id, local_payload, server_payload,
                    conflict_type, resolution, resolved_payload, resolved_by, resolved_at,
                    created_at, property_id
             FROM sync_conflict
             WHERE resolved_at IS NULL
             ORDER BY created_at DESC",
        )
        .map_err(|e| e.to_string())?;

    let conflicts = stmt
        .query_map([], |row| {
            Ok(SyncConflict {
                id: row.get(0)?,
                entity_type: row.get(1)?,
                entity_id: row.get(2)?,
                local_payload: row.get(3)?,
                server_payload: row.get(4)?,
                conflict_type: row.get(5)?,
                resolution: row.get(6)?,
                resolved_payload: row.get(7)?,
                resolved_by: row.get(8)?,
                resolved_at: row.get(9)?,
                created_at: row.get(10)?,
                property_id: row.get(11)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    Ok(conflicts)
}

/// Resolve a sync conflict by keeping the local version.
#[tauri::command]
pub async fn resolve_conflict_keep_local(
    state: State<'_, Arc<AppState>>,
    conflict_id: String,
    resolved_by: String,
) -> Result<(), String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;

    // Get the local payload
    let local_payload: String = conn
        .query_row(
            "SELECT local_payload FROM sync_conflict WHERE id = ?1",
            rusqlite::params![conflict_id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE sync_conflict
         SET resolution = 'KEEP_LOCAL', resolved_payload = ?1, resolved_by = ?2,
             resolved_at = datetime('now')
         WHERE id = ?3",
        rusqlite::params![local_payload, resolved_by, conflict_id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Resolve a sync conflict by accepting the server version.
#[tauri::command]
pub async fn resolve_conflict_accept_server(
    state: State<'_, Arc<AppState>>,
    conflict_id: String,
    resolved_by: String,
) -> Result<(), String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;

    // Get the server payload
    let server_payload: String = conn
        .query_row(
            "SELECT server_payload FROM sync_conflict WHERE id = ?1",
            rusqlite::params![conflict_id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE sync_conflict
         SET resolution = 'ACCEPT_SERVER', resolved_payload = ?1, resolved_by = ?2,
             resolved_at = datetime('now')
         WHERE id = ?3",
        rusqlite::params![server_payload, resolved_by, conflict_id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Resolve a sync conflict manually with a merged payload.
/// NOTE: Full merge logic is not yet implemented — this accepts a
/// manually-merged JSON payload from the admin.
#[tauri::command]
pub async fn resolve_conflict_manual(
    state: State<'_, Arc<AppState>>,
    conflict_id: String,
    resolved_payload: String,
    resolved_by: String,
) -> Result<(), String> {
    let conn = state.db.conn().map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE sync_conflict
         SET resolution = 'MERGED', resolved_payload = ?1, resolved_by = ?2,
             resolved_at = datetime('now')
         WHERE id = ?3",
        rusqlite::params![resolved_payload, resolved_by, conflict_id],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}
