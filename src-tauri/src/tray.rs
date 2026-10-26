// Menu bar icon and menu. The menu is rebuilt only when `engine::changed` fires; the relative
// "Checked N min ago" line is refreshed when the pointer reaches the icon, so no timer is needed.

use crate::engine::{now, Cmd, Shared};
use crate::model::*;
use crate::store::{counts_of, countable};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tauri::image::Image;
use tauri::menu::{IconMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::window::Color;
use tauri::{AppHandle, Emitter, Manager, TitleBarStyle, WebviewUrl, WebviewWindowBuilder, Wry};

pub struct TrayState {
    tray: TrayIcon,
    alert: AtomicBool,
    /// The "Checked ..." menu item and the text it currently shows.
    checked: Mutex<Option<(MenuItem<Wry>, String)>>,
}

const ICON: &[u8] = include_bytes!("../icons/tray.png");
const ICON_ALERT: &[u8] = include_bytes!("../icons/tray-alert.png");

pub fn init(app: &AppHandle) -> tauri::Result<()> {
    let tray = TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(ICON)?)
        .icon_as_template(true)
        .show_menu_on_left_click(true)
        .tooltip("NoVul")
        .menu(&Menu::new(app)?)
        .on_menu_event(on_menu)
        .on_tray_icon_event(|tray, event| {
            let hovered = matches!(event, TrayIconEvent::Enter { .. });
            let pressed = matches!(event, TrayIconEvent::Click { button_state: MouseButtonState::Down, .. });
            if hovered || pressed {
                refresh_checked(tray.app_handle());
            }
        })
        .build(app)?;
    app.manage(TrayState { tray, alert: AtomicBool::new(false), checked: Mutex::new(None) });
    refresh(app);
    Ok(())
}

/// Rebuild the menu (and icon) from the database. Safe to call from any thread.
pub fn refresh(app: &AppHandle) {
    if app.try_state::<TrayState>().is_none() {
        return;
    }
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Err(e) = rebuild(&handle) {
            log::warn!("tray rebuild failed: {e}");
        }
    });
}

fn relative(since: Option<i64>) -> String {
    let Some(t) = since.filter(|t| *t > 0) else { return "Not checked yet".into() };
    let s = (now() - t).max(0);
    match s {
        0..=59 => "Checked just now".into(),
        60..=3599 => format!("Checked {} min ago", s / 60),
        3600..=86399 => format!("Checked {} h ago", s / 3600),
        _ => format!("Checked {} d ago", s / 86400),
    }
}

fn refresh_checked(app: &AppHandle) {
    let (Some(st), Some(sh)) = (app.try_state::<TrayState>(), app.try_state::<Shared>()) else { return };
    let text = relative(sh.store.meta_i64("last_check_at"));
    let mut guard = st.checked.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((item, shown)) = guard.as_mut() {
        if *shown != text && item.set_text(&text).is_ok() {
            *shown = text;
        }
    }
}

fn dot(rgb: [u8; 3]) -> Image<'static> {
    const N: u32 = 16;
    let mut px = Vec::with_capacity((N * N * 4) as usize);
    for y in 0..N {
        for x in 0..N {
            let d = ((x as f32 + 0.5 - 8.0).powi(2) + (y as f32 + 0.5 - 8.0).powi(2)).sqrt();
            let a = (5.5 - d).clamp(0.0, 1.0);
            px.extend_from_slice(&[rgb[0], rgb[1], rgb[2], (a * 255.0) as u8]);
        }
    }
    Image::new_owned(px, N, N)
}

fn color(p: Priority) -> [u8; 3] {
    match p {
        Priority::Malicious => [0xe0, 0x7c, 0xff],
        Priority::Exploited => [0xff, 0x6b, 0x6b],
        Priority::Critical => [0xf2, 0x8b, 0x82],
        Priority::High => [0xf5, 0xb4, 0x7e],
        Priority::Medium => [0xe8, 0xde, 0x85],
        Priority::Low => [0x7e, 0xe0, 0xb8],
        Priority::Unrated => [0x8a, 0x95, 0xad],
    }
}

fn status_line(c: &Counts, live: &crate::engine::Live, paused: bool) -> String {
    if live.scanning {
        return match (live.phase.as_deref(), live.progress) {
            (Some("machine"), _) => "Checking this Mac…".into(),
            (Some("secrets"), Some((done, total))) if total > 0 => format!("Looking for secrets: {done} of {total} folders…"),
            (Some("secrets"), _) => "Looking for secrets…".into(),
            (_, Some((done, total))) if total > 0 => format!("Checking {done} of {total} lockfiles…"),
            _ => "Checking…".into(),
        };
    }
    let parts: Vec<String> = [
        (c.malicious, "malicious"),
        (c.exploited, "exploited"),
        (c.critical, "critical"),
        (c.high, "high"),
        (c.medium, "medium"),
        (c.low, "low"),
        (c.unrated, "unrated"),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .take(3)
    .map(|(n, l)| format!("{n} {l}"))
    .collect();
    let text = if parts.is_empty() { "No known issues".to_string() } else { parts.join(" · ") };
    if paused { format!("Paused · {text}") } else { text }
}

fn rebuild(app: &AppHandle) -> tauri::Result<()> {
    let (st, sh) = (app.state::<TrayState>(), app.state::<Shared>());
    let settings = sh.store.settings();
    // Loading every open finding is the only large allocation in the menu bar process:
    // keep just the counts and the top 5, then hand the memory back below.
    let findings = sh.store.open_findings().unwrap_or_default();
    let counts = counts_of(&findings, settings.show_dev, settings.show_estimated);
    // One line per package and project: several advisories on the same package are one fix.
    let mut seen = std::collections::HashSet::new();
    let top: Vec<FindingView> = findings
        .iter()
        .filter(|f| countable(f, settings.show_dev, settings.show_estimated))
        .filter(|f| seen.insert((f.name.clone(), f.installed_version.clone(), f.project_path.clone())))
        .take(5)
        .cloned()
        .collect();
    drop(findings);
    let live = sh.live.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let paused = sh.store.meta_i64("paused_until").is_some_and(|t| t > now());

    let menu = Menu::new(app)?;
    let setup = settings.roots.is_empty() && sh.store.project_count() == 0;
    let status = if setup {
        MenuItem::with_id(app, "status", "Set up NoVul…", true, None::<&str>)?
    } else {
        MenuItem::with_id(app, "status", status_line(&counts, &live, paused), false, None::<&str>)?
    };
    let checked_text = relative(sh.store.meta_i64("last_check_at"));
    let checked = MenuItem::with_id(app, "checked", &checked_text, false, None::<&str>)?;
    menu.append(&status)?;
    menu.append(&checked)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    for f in &top {
        let text = format!("{} {} · {}", f.name, f.installed_version, f.project_name);
        let item = IconMenuItem::with_id(app, format!("f:{}", f.id), text, true, Some(dot(color(f.priority))), None::<&str>)?;
        menu.append(&item)?;
    }
    if !top.is_empty() {
        menu.append(&PredefinedMenuItem::separator(app)?)?;
    }
    menu.append(&MenuItem::with_id(app, "scan", "Scan Now", true, None::<&str>)?)?;
    menu.append(&MenuItem::with_id(app, "open", "Open NoVul…", true, None::<&str>)?)?;
    let pause_label = if paused { "Resume Scanning" } else { "Pause for 1 Hour" };
    menu.append(&MenuItem::with_id(app, "pause", pause_label, true, None::<&str>)?)?;
    menu.append(&PredefinedMenuItem::separator(app)?)?;
    menu.append(&MenuItem::with_id(app, "quit", "Quit NoVul", true, None::<&str>)?)?;
    st.tray.set_menu(Some(menu))?;
    *st.checked.lock().unwrap_or_else(|e| e.into_inner()) = Some((checked, checked_text));

    let alert = counts.malicious + counts.exploited + counts.critical > 0;
    if st.alert.swap(alert, Ordering::Relaxed) != alert {
        st.tray.set_icon(Some(Image::from_bytes(if alert { ICON_ALERT } else { ICON })?))?;
        st.tray.set_icon_as_template(true)?;
    }
    sh.store.shrink_memory();
    crate::engine::release_freed_memory();
    Ok(())
}

fn on_menu(app: &AppHandle, event: tauri::menu::MenuEvent) {
    let sh = app.state::<Shared>();
    match event.id().as_ref() {
        "scan" => {
            let _ = sh.tx.send(Cmd::ScanNow);
        }
        "open" | "status" => open_window(app),
        "pause" => {
            if sh.store.meta_i64("paused_until").is_some_and(|t| t > now()) {
                let _ = sh.store.clear_meta("paused_until");
                let _ = sh.tx.send(Cmd::Tick);
            } else {
                let _ = sh.store.set_meta("paused_until", &(now() + 3600).to_string());
            }
            crate::engine::changed(app);
        }
        "quit" => {
            let _ = sh.tx.send(Cmd::Quit);
            app.exit(0);
        }
        id => {
            if let Some(n) = id.strip_prefix("f:").and_then(|n| n.parse().ok()) {
                focus_finding(app, n);
            }
        }
    }
}

/// Create the window, or focus it if it exists. Closing it destroys the webview, which frees the
/// WebKit content process.
pub fn open_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let built = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("NoVul")
        .inner_size(980.0, 640.0)
        .min_inner_size(760.0, 520.0)
        .title_bar_style(TitleBarStyle::Overlay)
        .hidden_title(true)
        .background_color(Color(0x22, 0x2a, 0x3d, 0xff))
        .build();
    match built {
        Ok(w) => {
            let _ = w.set_focus();
        }
        Err(e) => log::error!("cannot open window: {e}"),
    }
}

pub fn focus_finding(app: &AppHandle, id: i64) {
    if app.get_webview_window("main").is_some() {
        let _ = app.emit("focus-finding", id);
    } else {
        *app.state::<Shared>().focus.lock().unwrap_or_else(|e| e.into_inner()) = Some(id);
    }
    open_window(app);
}

#[cfg(test)]
mod relative_tests {
    use super::relative;

    #[test]
    fn unset_or_zero_timestamp_is_not_checked_yet() {
        assert_eq!(relative(None), "Not checked yet");
        assert_eq!(relative(Some(0)), "Not checked yet");
    }
}
