use tauri::menu::{Menu, MenuBuilder, MenuItem, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, Runtime};

/// Build the platform-adaptive native menu bar.
///
/// On macOS the first submenu becomes the application menu (named "ViharaOS")
/// and gets app-level About/Update/Quit items. On Windows/Linux, About lives
/// in Help and File contains app actions such as updates and quit.
pub fn build_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    let app_menu_label = if cfg!(target_os = "macos") {
        "ViharaOS"
    } else {
        "&File"
    };

    let app_menu = if cfg!(target_os = "macos") {
        SubmenuBuilder::new(app, app_menu_label)
            .item(&MenuItem::with_id(
                app,
                "about-viharaos",
                "About ViharaOS",
                true,
                None::<&str>,
            )?)
            .item(&MenuItem::with_id(
                app,
                "check-updates",
                "Check for Updates...",
                true,
                None::<&str>,
            )?)
            .separator()
            .quit()
            .build()?
    } else {
        SubmenuBuilder::new(app, app_menu_label)
            .item(&MenuItem::with_id(
                app,
                "check-updates",
                "Check for Updates...",
                true,
                None::<&str>,
            )?)
            .separator()
            .quit()
            .build()?
    };

    let edit_menu = SubmenuBuilder::new(app, "&Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    let view_menu = SubmenuBuilder::new(app, "&View")
        .item(&MenuItem::with_id(
            app,
            "reload",
            "Reload",
            true,
            Some("F5"),
        )?)
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

    let window_menu = SubmenuBuilder::new(app, "&Window")
        .minimize()
        .separator()
        .close_window()
        .build()?;

    let help_menu = if cfg!(target_os = "macos") {
        SubmenuBuilder::new(app, "&Help")
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
            .build()?
    } else {
        SubmenuBuilder::new(app, "&Help")
            .item(&MenuItem::with_id(
                app,
                "about-viharaos",
                "About ViharaOS",
                true,
                None::<&str>,
            )?)
            .separator()
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
            .build()?
    };

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
pub fn handle_menu_event<R: Runtime>(app: &AppHandle<R>, id: &str) {
    match id {
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
                let _ = window.eval(
                    "(function(){\
                       var d=document.documentElement.classList;\
                       d.toggle('dark');\
                       localStorage.setItem('theme',d.contains('dark')?'dark':'light');\
                     })()",
                );
            }
        }
        "about-viharaos" => {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.emit("menu-action", "about-viharaos");
            }
        }
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
        "open-logs" => {
            if let Some(state) = app.try_state::<std::sync::Arc<crate::AppState>>() {
                let log_dir = state.app_data_dir.clone();
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
