mod commands;
mod db;
mod image;
mod menu;
mod r2;
mod sync;

use std::sync::Arc;
use tauri::Manager;
use tauri_plugin_deep_link::DeepLinkExt;

use db::Database;
use sync::SyncEngine;

/// Shared application state accessible by all Tauri commands
pub struct AppState {
    pub db: Arc<Database>,
    pub sync: Arc<SyncEngine>,
    pub app_data_dir: std::path::PathBuf,
    pub images_dir: std::path::PathBuf,
}

/// Set up file-based logging in addition to env_logger.
/// Writes to `viharaos-desktop.log` in the app data directory so crashes
/// can be diagnosed even when the console window is hidden.
fn setup_file_logging(app_data_dir: &std::path::Path) {
    let log_path = app_data_dir.join("viharaos-desktop.log");

    // Rotate: if the log file is > 5 MB, move it to .old and start fresh
    if log_path.exists() {
        if let Ok(meta) = std::fs::metadata(&log_path) {
            if meta.len() > 5 * 1024 * 1024 {
                let old_path = log_path.with_extension("log.old");
                let _ = std::fs::rename(&log_path, &old_path);
            }
        }
    }

    // Open the log file for appending
    let log_file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Warning: could not open log file {}: {}", log_path.display(), e);
            return;
        }
    };

    // Build a logger that writes to both stderr and the file
    let target = env_logger::Target::Pipe(Box::new(log_file));
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(target)
        .format_timestamp_secs()
        .try_init();
}

/// Install a panic hook that logs the panic and shows a dialog before
/// the process exits. Without this, panics in release mode would silently
/// crash the app with no diagnostic information.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Log the panic
        let payload = panic_info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".to_string());

        log::error!("PANIC at {}: {}", location, msg);

        // Also print to stderr in case the console is visible
        eprintln!("PANIC at {}: {}", location, msg);

        // Show a dialog to the user (best-effort — may not work if the
        // panic happened very early in startup)
        let full_msg = format!(
            "ViharaOS Desktop encountered an error and needs to close.\n\n\
             Error: {}\n\
             Location: {}\n\n\
             Please report this to hello@viharaos.com with the log file from:\n\
             %APPDATA%\\com.viharaos.desktop\\viharaos-desktop.log (Windows)\n\
             ~/Library/Application Support/com.viharaos.desktop/viharaos-desktop.log (macOS)",
            msg, location
        );

        // Use a thread to show the dialog so we don't block the panic handler
        std::thread::spawn(move || {
            // Try to show a native dialog
            #[cfg(target_os = "windows")]
            {
                use std::process::Command;
                let _ = Command::new("msg")
                    .arg("*")
                    .arg(&full_msg)
                    .spawn();
            }
            #[cfg(target_os = "macos")]
            {
                use std::process::Command;
                let _ = Command::new("osascript")
                    .args(["-e", &format!("display dialog \"{}\" buttons {{\"OK\"}} with title \"ViharaOS Error\"", msg)])
                    .spawn();
            }
        });

        // Call the default hook for stack unwinding
        default_hook(panic_info);
    }));
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Install panic hook FIRST, before anything else can panic
    install_panic_hook();

    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_deep_link::init())
        // Dispatch custom menu item clicks to the handler.
        // Predefined items (About/Quit/Undo/Cut/Copy/Paste/Minimize/Close)
        // are handled by the OS and never reach this closure.
        .on_menu_event(|app, event| {
            menu::handle_menu_event(app, event.id().as_ref());
        });

    #[cfg(feature = "e2e-testing")]
    {
        builder = builder.plugin(tauri_plugin_playwright::init_with_config(
            tauri_plugin_playwright::PluginConfig::new().tcp_port(6274),
        ));
    }

    builder
        .setup(|app| {
            // Resolve data directories — use graceful error handling, not .expect()
            let app_data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| {
                    log::error!("Failed to resolve app data directory: {}", e);
                    e.to_string()
                })?;
            let images_dir = app_data_dir.join("images");

            // Set up file logging now that we know the app data dir
            setup_file_logging(&app_data_dir);

            log::info!("ViharaOS Desktop starting up...");
            log::info!("App data directory: {}", app_data_dir.display());

            // Create directories if they don't exist — log errors instead of panicking
            if let Err(e) = std::fs::create_dir_all(&app_data_dir) {
                log::error!("Failed to create app data directory: {}", e);
                return Err(format!("Failed to create app data directory: {}", e).into());
            }
            if let Err(e) = std::fs::create_dir_all(&images_dir) {
                log::error!("Failed to create images directory: {}", e);
                return Err(format!("Failed to create images directory: {}", e).into());
            }

            // Create subfolders for each entity type
            for folder in &[
                "menu-items", "guests", "employees", "rooms",
                "lost-found", "transport", "visitors", "properties",
            ] {
                let path = images_dir.join(folder);
                if let Err(e) = std::fs::create_dir_all(&path) {
                    log::warn!("Failed to create image subfolder {}: {}", folder, e);
                    // Don't fail the entire setup for a single subfolder
                }
            }

            // Initialize SQLite database — log errors instead of panicking
            let db_path = app_data_dir.join("viharaos.db");
            log::info!("Database path: {}", db_path.display());
            let db = match Database::new(&db_path) {
                Ok(db) => db,
                Err(e) => {
                    log::error!("Failed to initialize SQLite database: {}", e);
                    return Err(format!("Failed to initialize database: {}", e).into());
                }
            };
            log::info!("Database initialized successfully");
            let db = Arc::new(db);

            // Initialize sync engine
            let sync = Arc::new(SyncEngine::new(db.clone()));

            // Build shared state
            let state = Arc::new(AppState {
                db: db.clone(),
                sync: sync.clone(),
                app_data_dir: app_data_dir.clone(),
                images_dir: images_dir.clone(),
            });

            // Spawn local API server in a background task
            let api_state = state.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = commands::api::start_server(api_state).await {
                    log::error!("Local API server error: {}", e);
                }
            });

            // Start sync engine background worker
            // With panic = "unwind" (default), tokio catches panics in spawned
            // tasks automatically — a panic here won't crash the entire app.
            let sync_state = state.clone();
            tauri::async_runtime::spawn(async move {
                sync_state.sync.clone().start_worker(sync_state.clone()).await;
            });

            app.manage(state);

            // Build and install the platform-adaptive native menu bar.
            // On macOS the first submenu becomes the app menu; on Windows
            // all submenus appear as top-level menu bar entries.
            let menu_handle = app.handle().clone();
            match menu::build_menu(&menu_handle) {
                Ok(menu) => {
                    if let Err(e) = app.set_menu(menu) {
                        log::warn!("Failed to set menu bar: {}", e);
                    } else {
                        log::info!("Native menu bar installed");
                    }
                }
                Err(e) => {
                    log::warn!("Failed to build menu bar: {}", e);
                }
            }

            // Handle deep links (viharaos://) — focus the window when a link is received.
            // This is used by the browser login flow: after the user authorizes in the
            // browser, the page redirects to viharaos://auth?device_code=XXX, which
            // brings the desktop app to the foreground so the user sees the login complete.
            // The viharaos:// scheme is registered in tauri.conf.json under
            // plugins.deep-link.desktop.schemes / mobile.schemes.
            let deep_link_app = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                log::info!("Deep link received ({} URLs)", event.urls().len());
                if let Some(window) = deep_link_app.get_webview_window("main") {
                    let _ = window.set_focus();
                    let _ = window.unminimize();
                }
            });

            log::info!("ViharaOS Desktop setup complete");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::media::save_image_local,
            commands::media::delete_image_local,
            commands::media::get_local_image_path,
            commands::media::check_storage_usage,
            commands::media::sync_media_to_cloud,
            commands::sync::trigger_sync,
            commands::sync::get_sync_status,
            commands::sync::set_sync_enabled,
            commands::updater::check_for_updates,
            commands::updater::download_and_install_update,
            commands::heartbeat::get_device_heartbeat,
            commands::heartbeat::get_sync_outbox,
            commands::heartbeat::retry_sync_outbox_entry,
            commands::heartbeat::retry_all_sync_outbox,
            commands::sync::send_heartbeat,
            commands::conflicts::get_sync_conflicts,
            commands::conflicts::resolve_conflict_keep_local,
            commands::conflicts::resolve_conflict_accept_server,
            commands::conflicts::resolve_conflict_manual,
            commands::api::store_password_hash,
            commands::auth::login_with_browser,
        ])
        // Run generate_context!() in a separate thread with a larger stack
        // (8MB) to avoid stack overflow on Windows where the main thread
        // defaults to 1MB. See .cargo/config.toml for the linker-level fix
        // and https://github.com/tauri-apps/tauri/issues/9882 for context.
        .run(
            std::thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(|| tauri::generate_context!())
                .unwrap()
                .join()
                .unwrap(),
        )
        .expect("error while running ViharaOS desktop");
}
