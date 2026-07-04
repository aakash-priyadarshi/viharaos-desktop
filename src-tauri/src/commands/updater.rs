use std::sync::Arc;
use serde::Serialize;
use tauri::State;

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub version: Option<String>,
    pub current_version: String,
    pub body: Option<String>,
    pub date: Option<String>,
}

/// Check if an update is available
#[tauri::command]
pub async fn check_for_updates(
    app: tauri::AppHandle,
    _state: State<'_, Arc<AppState>>,
) -> Result<UpdateInfo, String> {
    let current_version = app.package_info().version.to_string();

    match tauri_plugin_updater::UpdaterExt::updater(&app) {
        Ok(updater) => {
            match updater.check().await {
                Ok(Some(update)) => {
                    log::info!(
                        "Update available: {} (current: {})",
                        update.version,
                        current_version
                    );
                    Ok(UpdateInfo {
                        available: true,
                        version: Some(update.version.clone()),
                        current_version,
                        body: update.body.clone(),
                        date: update.date.map(|d| d.to_string()),
                    })
                }
                Ok(None) => {
                    Ok(UpdateInfo {
                        available: false,
                        version: None,
                        current_version,
                        body: None,
                        date: None,
                    })
                }
                Err(e) => {
                    log::warn!("Update check failed: {}", e);
                    Ok(UpdateInfo {
                        available: false,
                        version: None,
                        current_version,
                        body: None,
                        date: None,
                    })
                }
            }
        }
        Err(e) => {
            log::warn!("Updater plugin not available: {}", e);
            Ok(UpdateInfo {
                available: false,
                version: None,
                current_version,
                body: None,
                date: None,
            })
        }
    }
}

/// Download and install the update, then relaunch the app
#[tauri::command]
pub async fn download_and_install_update(
    app: tauri::AppHandle,
    _state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    match tauri_plugin_updater::UpdaterExt::updater(&app) {
        Ok(updater) => {
            match updater.check().await {
                Ok(Some(update)) => {
                    log::info!("Downloading and installing update {}...", update.version);
                    update
                        .download_and_install(
                            |chunk_length, content_length| {
                                log::debug!(
                                    "Downloaded {} bytes of {:?}",
                                    chunk_length, content_length
                                );
                            },
                            || {
                                log::info!("Download complete, preparing to install...");
                            },
                        )
                        .await
                        .map_err(|e| e.to_string())?;

                    log::info!("Update installed, relaunching app...");
                    app.request_restart();
                    Ok(())
                }
                Ok(None) => Err("No update available".to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}
