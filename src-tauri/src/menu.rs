use tauri::menu::{AboutMetadata, Menu, MenuBuilder, MenuItem, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, Runtime};

/// Build the platform-adaptive native menu bar.
///
/// On macOS the first submenu becomes the application menu (named "ViharaOS")
/// and gets the standard About/Quit items placed there by the OS.
/// On Windows/Linux every submenu appears as a top-level menu bar entry.
pub fn build_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    // ─── App / File menu ───
    // On macOS this is the app menu ("ViharaOS"); on Windows it's "File".
    let app_menu_label = if cfg!(target_os = "macos") {
        "ViharaOS"
    } else {
        "&File"
    };

    let app_menu = SubmenuBuilder::new(app, app_menu_label)
        .about(Some(AboutMetadata {
            name: Some("ViharaOS".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            ..Default::default()
        }))
        .separator()
        .item(&MenuItem::with_id(
            app,
            "check-updates",
            "Check for Updates…",
            true,
            None::<&str>,
        )?)
        .separator()
        .quit()
        .build()?;

    // ─── Edit menu ───
    let edit_menu = SubmenuBuilder::new(app, "&Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    // ─── View menu ───
    let view_menu = SubmenuBuilder::new(app, "&View")
        .item(&MenuItem::with_id(app, "reload", "Reload", true, Some("F5"))?)
        .item(&MenuItem::with_id(
            app,
            "toggle-devtools",
            "Toggle Developer Tools",
            true,
            Some("F12"),
        )?)
        .separator()
        .item(&MenuItem::with_id(
            app,
            "toggle-dark-mode",
            "Toggle Dark Mode",
            true,
            None::<&str>,
        )?)
        .build()?;

    // ─── Sync menu (ViharaOS-specific) ───
    let sync_menu = SubmenuBuilder::new(app, "&Sync")
        .item(&MenuItem::with_id(
            app,
            "sync-now",
            "Sync Now",
            true,
            None::<&str>,
        )?)
        .item(&MenuItem::with_id(
            app,
            "open-logs",
            "Open Logs Folder",
            true,
            None::<&str>,
        )?)
        .build()?;

    // ─── Window menu ───
    let window_menu = SubmenuBuilder::new(app, "&Window")
        .minimize()
        .separator()
        .close_window()
        .build()?;

    // ─── Help menu ───
    let help_menu = SubmenuBuilder::new(app, "&Help")
        .item(&MenuItem::with_id(
            app,
            "website",
            "ViharaOS Website",
            true,
            None::<&str>,
        )?)
        .item(&MenuItem::with_id(
            app,
            "report-issue",
            "Report an Issue",
            true,
            None::<&str>,
        )?)
        .build()?;

    // Assemble the menu bar from all submenus.
    MenuBuilder::new(app)
        .item(&app_menu)
        .item(&edit_menu)
        .item(&view_menu)
        .item(&sync_menu)
        .item(&window_menu)
        .item(&help_menu)
        .build()
}

/// Handle a custom menu item click.
///
/// Predefined items (About, Quit, Undo, Redo, Cut, Copy, Paste, Select All,
/// Minimize, Close Window) are handled by the OS/Tauri automatically and
/// never reach this handler. Only items created with `MenuItem::with_id`
/// are dispatched here.
pub fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, id: &str) {
    match id {
        // ─── View ───
        "reload" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.eval("window.location.reload()");
            }
        }
        "toggle-devtools" => {
            if let Some(window) = app.get_webview_window("main") {
                if window.is_devtools_open() {
                    window.close_devtools();
                } else {
                    window.open_devtools();
                }
            }
        }
        "toggle-dark-mode" => {
            if let Some(window) = app.get_webview_window("main") {
                // Toggle the `dark` class on <html> and persist to localStorage.
                // This mirrors the manual toggle in the dashboard sidebar.
                let _ = window.eval(
                    "(function(){\
                       var d=document.documentElement.classList;\
                       d.toggle('dark');\
                       localStorage.setItem('theme',d.contains('dark')?'dark':'light');\
                     })()",
                );
            }
        }

        // ─── App-specific (emit to frontend) ───
        "check-updates" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.emit("menu-action", "check-updates");
            }
        }
        "sync-now" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.emit("menu-action", "sync-now");
            }
        }

        // ─── Open external resources ───
        "open-logs" => {
            if let Some(state) = app.try_state::<std::sync::Arc<crate::AppState>>() {
                let log_dir = state.app_data_dir.clone();
                // Open the folder in the OS file explorer.
                // If it fails on some platforms, try opening the parent.
                if let Err(e) = open::that(&log_dir) {
                    log::warn!("Failed to open logs folder: {}", e);
                }
            }
        }
        "website" => {
            if let Err(e) = open::that("https://www.viharaos.com") {
                log::warn!("Failed to open website: {}", e);
            }
        }
        "report-issue" => {
            if let Err(e) = open::that("mailto:hello@viharaos.com?subject=Desktop%20App%20Issue") {
                log::warn!("Failed to open mail client: {}", e);
            }
        }

        _ => {
            log::debug!("Unhandled menu event: {}", id);
        }
    }
}
