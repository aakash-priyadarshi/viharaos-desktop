use serde::Serialize;
use std::sync::Arc;
use tauri::State;

use crate::db::models::SyncStatus;
use crate::AppState;

/// Manually trigger a sync cycle (push + pull) + heartbeat
#[tauri::command]
pub async fn trigger_sync(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    state.sync.trigger_sync().await?;
    // Send a heartbeat after manual sync so the cloud status is fresh.
    // Best-effort — never blocks.
    state.sync.send_heartbeat(&state).await;
    Ok(())
}

/// Get current sync status
#[tauri::command]
pub async fn get_sync_status(state: State<'_, Arc<AppState>>) -> Result<SyncStatus, String> {
    Ok(state.sync.get_status())
}

/// Enable or disable auto-sync
#[tauri::command]
pub async fn set_sync_enabled(
    enabled: bool,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    state.sync.set_enabled(enabled);
    Ok(())
}

/// Send a best-effort heartbeat to the cloud.
/// Called by the frontend on app startup, after login, and after local writes.
/// Never fails — heartbeat is always best-effort.
#[tauri::command]
pub async fn send_heartbeat(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    state.sync.send_heartbeat(&state).await;
    Ok(())
}
