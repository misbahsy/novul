// `novul --worker <job> --db <path> [--lockfiles <path>...]`: runs one scan job in a short-lived
// process so the menu bar process never holds scan-time memory. Progress goes to stdout as JSON lines.

use crate::engine::Job;
use crate::store::Store;
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum Event {
    /// (done, total) and the phase it belongs to: "packages" | "machine" | "secrets".
    Progress(Option<(usize, usize)>, Option<String>),
    Done,
}

impl Event {
    fn line(&self) -> String {
        match self {
            Event::Progress(p, phase) => {
                let mut v = json!({ "progress": p.map(|(done, total)| [done, total]) });
                if let Some(phase) = phase {
                    v["phase"] = json!(phase);
                }
                v
            }
            Event::Done => json!({ "done": true }),
        }
        .to_string()
    }

    pub fn parse(line: &str) -> Option<Event> {
        let v: Value = serde_json::from_str(line).ok()?;
        if v["done"] == true {
            return Some(Event::Done);
        }
        let p = v.get("progress")?;
        let counts = match (p[0].as_u64(), p[1].as_u64()) {
            (Some(done), Some(total)) => Some((done as usize, total as usize)),
            _ => None,
        };
        Some(Event::Progress(counts, v["phase"].as_str().map(String::from)))
    }

    pub fn progress(counts: Option<(usize, usize)>, phase: &str) -> Event {
        Event::Progress(counts, Some(phase.into()))
    }
}

fn emit(e: Event) {
    // The parent may be gone (app quit); the job still finishes.
    let _ = writeln!(std::io::stdout(), "{}", e.line());
}

/// `args` follow `--worker`. Returns the process exit code.
pub fn main(args: Vec<String>) -> i32 {
    let mut it = args.into_iter();
    let Some(job) = it.next() else { return 2 };
    let (mut db, mut lockfiles) = (None, vec![]);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--db" => db = it.next(),
            "--lockfiles" => lockfiles.extend(it.by_ref()),
            _ => return 2,
        }
    }
    let Some(db) = db else { return 2 };
    if !matches!(job.as_str(), "full" | "full-first" | "secrets" | "tick" | "rescan") {
        return 2;
    }
    let Ok(store) = Store::open(Path::new(&db)) else { return 1 };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return 1 };
    let job_ = Job { store: &store, report: &emit };
    rt.block_on(async {
        match job.as_str() {
            "tick" => job_.tick().await,
            "rescan" => job_.rescan_pass(lockfiles).await,
            "secrets" => job_.secrets_scan().await,
            _ => job_.full_scan().await,
        }
    });
    emit(Event::Done);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_lines_round_trip() {
        for e in [
            Event::Progress(Some((3, 430)), None),
            Event::Progress(None, None),
            Event::progress(Some((3, 430)), "packages"),
            Event::progress(None, "machine"),
            Event::Done,
        ] {
            assert_eq!(Event::parse(&e.line()), Some(e));
        }
        assert_eq!(Event::parse(r#"{"progress":[7,9]}"#), Some(Event::Progress(Some((7, 9)), None)));
        assert_eq!(Event::parse(r#"{"progress":[40,310],"phase":"secrets"}"#), Some(Event::progress(Some((40, 310)), "secrets")));
        assert_eq!(Event::parse(r#"{"progress":null,"phase":"machine"}"#), Some(Event::progress(None, "machine")));
        assert_eq!(Event::progress(None, "machine").line(), r#"{"phase":"machine","progress":null}"#);
        assert_eq!(Event::parse("osv-scanner: warning"), None);
        assert_eq!(Event::parse(r#"{"other":1}"#), None);
    }
}
