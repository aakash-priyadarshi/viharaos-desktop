use serde::Serialize;
use std::sync::Arc;
use tauri::State;

use crate::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub platform: String,
    pub arch: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub available: bool,
    pub version: Option<String>,
    pub current_version: String,
    pub body: Option<String>,
    pub date: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInstallResult {
    pub version: Option<String>,
    pub restart_required: bool,
}

#[tauri::command]
pub async fn get_app_info(app: tauri::AppHandle) -> Result<AppInfo, String> {
    Ok(AppInfo {
        name: "ViharaOS".to_string(),
        version: app.package_info().version.to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    })
}

#[tauri::command]
pub async fn check_for_updates(
    app: tauri::AppHandle,
    _state: State<'_, Arc<AppState>>,
) -> Result<UpdateInfo, String> {
    let current_version = app.package_info().version.to_string();

    let updater = match tauri_plugin_updater::UpdaterExt::updater(&app) {
        Ok(updater) => updater,
        Err(e) => {
            let error = format!("Updater plugin is not available: {}", e);
            log::warn!("{}", error);
            return Ok(UpdateInfo {
                available: false,
                version: None,
                current_version,
                body: None,
                date: None,
                error: Some(error),
            });
        }
    };

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
                error: None,
            })
        }
        Ok(None) => Ok(UpdateInfo {
            available: false,
            version: None,
            current_version,
            body: None,
            date: None,
            error: None,
        }),
        Err(e) => {
            let error = format!("Update check failed: {}", e);
            log::warn!("{}", error);
            Ok(UpdateInfo {
                available: false,
                version: None,
                current_version,
                body: None,
                date: None,
                error: Some(error),
            })
        }
    }
}

#[tauri::command]
pub async fn download_and_install_update(
    app: tauri::AppHandle,
    _state: State<'_, Arc<AppState>>,
) -> Result<UpdateInstallResult, String> {
    let updater = tauri_plugin_updater::UpdaterExt::updater(&app).map_err(|e| e.to_string())?;

    match updater.check().await {
        Ok(Some(update)) => {
            let version = update.version.clone();
            log::info!("Downloading and installing update {}...", version);
            update
                .download_and_install(
                    |chunk_length, content_length| {
                        log::debug!("Downloaded {} bytes of {:?}", chunk_length, content_length);
                    },
                    || {
                        log::info!("Download complete, preparing to install...");
                    },
                )
                .await
                .map_err(|e| e.to_string())?;

            log::info!("Update installed. Restart is required to apply it.");
            Ok(UpdateInstallResult {
                version: Some(version),
                restart_required: true,
            })
        }
        Ok(None) => Err("No update available".to_string()),
        Err(e) => Err(e.to_string()),
    }
}
