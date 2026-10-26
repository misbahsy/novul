// Notification policy: one notification per pass, summary on the very first scan.

use crate::engine::now;
use crate::model::*;
use crate::store::{countable, counts_of, Store};
use tauri::AppHandle;
use tauri_plugin_notification::NotificationExt;

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn bands(c: &Counts, threshold: Priority) -> Vec<String> {
    [
        (Priority::Malicious, c.malicious),
        (Priority::Exploited, c.exploited),
        (Priority::Critical, c.critical),
        (Priority::High, c.high),
        (Priority::Medium, c.medium),
        (Priority::Low, c.low),
    ]
    .iter()
    .filter(|(p, n)| *p <= threshold && *n > 0)
    .map(|(p, n)| format!("{n} {}", p.as_str()))
    .collect()
}

fn join_and(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [a] => a.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

fn message(new: &[FindingView], threshold: Priority) -> (String, String) {
    let first = &new[0];
    let what = format!(
        "{} {} · {}",
        first.name, first.installed_version, first.project_name
    );
    if new.len() == 1 {
        let body = if first.priority == Priority::Malicious {
            format!("{what}. Remove the package and rotate every secret this machine holds.")
        } else {
            what
        };
        return (format!("New {} issue", first.priority.as_str()), body);
    }
    let counts = counts_of(new, true, true);
    let same = new.iter().all(|f| f.priority == first.priority);
    let title = if same {
        format!("{} new {} issues", new.len(), first.priority.as_str())
    } else {
        format!(
            "{} new issues: {}",
            new.len(),
            bands(&counts, threshold).join(", ")
        )
    };
    (
        title,
        format!("{what} and {}", format!("{} more", new.len() - 1)),
    )
}

/// Notify about open, unmuted findings at or above the threshold that were never notified.
pub fn after_scan(app: &AppHandle, store: &Store, first_scan: bool) {
    let settings = store.settings();
    let Ok(unnotified) = store.unnotified() else {
        return;
    };
    let new: Vec<FindingView> = unnotified
        .into_iter()
        .filter(|f| countable(f, settings.show_dev, settings.show_estimated) && f.priority <= settings.notify_threshold)
        .collect();
    let (title, body) = if first_scan {
        let counts = store
            .open_findings()
            .map(|f| counts_of(&f, settings.show_dev, settings.show_estimated))
            .unwrap_or_default();
        let parts = bands(&counts, settings.notify_threshold);
        let projects = plural(store.project_count(), "project", "projects");
        if parts.is_empty() {
            (
                "Scan complete".to_string(),
                format!("No issues need attention across {projects}"),
            )
        } else {
            (
                "Scan complete".to_string(),
                format!("Found {} issues across {projects}", join_and(&parts)),
            )
        }
    } else if new.is_empty() {
        return;
    } else {
        message(&new, settings.notify_threshold)
    };
    if app
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .is_ok()
    {
        let ids: Vec<i64> = new.iter().map(|f| f.id).collect();
        let _ = store.mark_notified(&ids, now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str, p: Priority) -> FindingView {
        FindingView {
            id: 1,
            kind: "package".into(),
            group_id: "g".into(),
            aliases: vec![],
            summary: String::new(),
            priority: p,
            score: None,
            kev: false,
            ecosystem: "npm".into(),
            name: name.into(),
            installed_version: "1.0.0".into(),
            fixed_version: None,
            direct: None,
            dev: false,
            inferred: false,
            project_path: "/p".into(),
            project_name: "proj".into(),
            fix_command: None,
            url: String::new(),
            first_seen_at: 0,
            muted: false,
            epss: None,
        }
    }

    #[test]
    fn messages() {
        let (t, b) = message(
            &[f("lodash", Priority::Critical), f("x", Priority::Critical)],
            Priority::High,
        );
        assert_eq!(t, "2 new critical issues");
        assert_eq!(b, "lodash 1.0.0 · proj and 1 more");
        let (t, _) = message(
            &[f("a", Priority::Critical), f("b", Priority::High)],
            Priority::High,
        );
        assert_eq!(t, "2 new issues: 1 critical, 1 high");
        assert_eq!(
            join_and(&["3 critical".into(), "12 high".into()]),
            "3 critical and 12 high"
        );
    }
}
