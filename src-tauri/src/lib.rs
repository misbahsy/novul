pub mod cli;
pub mod commands;
pub mod engine;
pub mod feeds;
pub mod inventory;
pub mod mcp;
pub mod model;
pub mod notify;
pub mod scan;
pub mod store;
pub mod tray;
pub mod worker;

use std::sync::{Arc, Mutex};

// mimalloc returns freed pages to macOS promptly; the system allocator kept ~60 MB of
// fragmented scan-time memory resident while the app sat idle in the menu bar.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
use tauri::{Manager, RunEvent};
use tauri_plugin_autostart::MacosLauncher;

pub fn run() {
    // Return freed memory to the OS immediately, including from exited worker threads.
    // The crate doesn't export these two enum values (mimalloc v2 mimalloc.h).
    const MI_OPTION_ABANDONED_PAGE_PURGE: libmimalloc_sys::mi_option_t = 12;
    const MI_OPTION_PURGE_DELAY: libmimalloc_sys::mi_option_t = 15;
    // SAFETY: setting mimalloc options before any threads start.
    unsafe {
        libmimalloc_sys::mi_option_set(MI_OPTION_ABANDONED_PAGE_PURGE, 1);
        libmimalloc_sys::mi_option_set(MI_OPTION_PURGE_DELAY, 0);
    }
    // Two workers keep the idle thread count low; blocking work goes to the on-demand pool.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    tauri::async_runtime::set(runtime.handle().clone());

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, None))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_state,
            commands::scan_now,
            commands::set_muted,
            commands::get_settings,
            commands::set_settings,
            commands::open_url,
            commands::reveal_path,
            commands::take_focus_request,
            commands::save_image,
            commands::apply_fix,
            commands::suggest_roots,
            commands::agent_info,
            commands::open_in_agent,
        ])
        .setup(|app| {
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db = dir.join("novul.db");
            let store = Arc::new(store::Store::open(&db)?);
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            app.manage(engine::Shared {
                store: store.clone(),
                live: Mutex::new(engine::Live::default()),
                tx: tx.clone(),
                focus: Mutex::new(None),
            });
            tray::init(app.handle())?;
            engine::spawn(app.handle().clone(), store, db, tx, rx);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building NoVul");

    app.run(|_app, event| {
        // Closing the window must not quit; Quit in the tray menu calls app.exit(0).
        if let RunEvent::ExitRequested { code: None, api, .. } = event {
            api.prevent_exit();
        }
    });
    drop(runtime);
}
