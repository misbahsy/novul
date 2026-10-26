// Owner: feeds agent.
use crate::model::RuntimeStatus;
use serde_json::Value;
use std::time::Duration;

/// Check one runtime against https://endoflife.date/api/v1/products/<product>/
/// (node->nodejs, python->python, php->php, go->go, ruby->ruby). Network errors give a
/// status with cycle/latest = None rather than an Err.
pub async fn check(client: &reqwest::Client, kind: &str, version: &str, path: &str) -> RuntimeStatus {
    let doc = match product(kind) {
        Some(p) => fetch(client, p).await,
        None => Err(format!("no endoflife.date product for {kind}")),
    };
    match doc {
        Ok(doc) => parse_release(&doc, kind, version, path),
        Err(e) => {
            log::warn!("eol check for {kind} {version}: {e}");
            status(kind, version, path)
        }
    }
}

fn product(kind: &str) -> Option<&'static str> {
    match kind {
        "node" => Some("nodejs"),
        "python" => Some("python"),
        "php" => Some("php"),
        "go" => Some("go"),
        "ruby" => Some("ruby"),
        _ => None,
    }
}

async fn fetch(client: &reqwest::Client, product: &str) -> Result<Value, String> {
    client
        .get(format!("https://endoflife.date/api/v1/products/{product}/"))
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("endoflife.date request: {e}"))?
        .json()
        .await
        .map_err(|e| format!("endoflife.date response: {e}"))
}

fn status(kind: &str, version: &str, path: &str) -> RuntimeStatus {
    RuntimeStatus {
        kind: kind.into(),
        version: version.into(),
        path: path.into(),
        cycle: None,
        latest_in_cycle: None,
        latest_date: None,
        is_eol: false,
        behind: false,
    }
}

/// node cycles are the major ("25"); everything else is major.minor ("3.13", "1.25").
fn cycle_name(kind: &str, version: &str) -> String {
    let n = if kind == "node" { 1 } else { 2 };
    version.split('.').take(n).collect::<Vec<_>>().join(".")
}

/// Pure part of `check`: finds the installed version's release in an endoflife.date product
/// document (`{"result": {"releases": [...]}}`). Unknown release -> unfilled status.
pub fn parse_release(doc: &Value, kind: &str, version: &str, path: &str) -> RuntimeStatus {
    let mut s = status(kind, version, path);
    let cycle = cycle_name(kind, version);
    let Some(rel) = doc["result"]["releases"].as_array().and_then(|rs| rs.iter().find(|r| r["name"] == cycle.as_str())) else {
        return s;
    };
    s.cycle = Some(cycle);
    s.is_eol = rel["isEol"].as_bool().unwrap_or(false);
    s.latest_in_cycle = rel["latest"]["name"].as_str().map(String::from);
    s.latest_date = rel["latest"]["date"].as_str().map(String::from);
    s.behind = s.latest_in_cycle.as_deref().is_some_and(|l| is_older(version, l));
    s
}

fn parts(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|p| p.chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap_or(0))
        .collect()
}

fn is_older(installed: &str, latest: &str) -> bool {
    let (mut a, mut b) = (parts(installed), parts(latest));
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    a < b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(file: &str) -> Value {
        serde_json::from_str(file).unwrap()
    }

    #[test]
    fn eol_node_25_is_eol_and_behind() {
        let d = doc(include_str!("../../tests/fixtures/eol/nodejs.json"));
        let s = parse_release(&d, "node", "25.6.1", "/opt/homebrew/bin/node");
        assert_eq!(s.cycle.as_deref(), Some("25"));
        assert!(s.is_eol);
        assert_eq!(s.latest_in_cycle.as_deref(), Some("25.9.0"));
        assert_eq!(s.latest_date.as_deref(), Some("2026-04-01"));
        assert!(s.behind);
    }

    #[test]
    fn maintained_node_behind_and_current() {
        let d = doc(include_str!("../../tests/fixtures/eol/nodejs.json"));
        let behind = parse_release(&d, "node", "24.9.0", "p");
        assert!(!behind.is_eol && behind.behind);
        assert_eq!(behind.latest_in_cycle.as_deref(), Some("24.22.1"));
        let current = parse_release(&d, "node", "24.22.1", "p");
        assert!(!current.is_eol && !current.behind);
        // numeric, not lexicographic: 24.9.0 < 24.22.1 but "9" > "22" as strings
        assert!(is_older("24.9.0", "24.22.1"));
    }

    #[test]
    fn python_uses_major_minor_cycle() {
        let d = doc(include_str!("../../tests/fixtures/eol/python.json"));
        let s = parse_release(&d, "python", "3.13.12", "p");
        assert_eq!(s.cycle.as_deref(), Some("3.13"));
        assert!(!s.is_eol && s.behind);
        let old = parse_release(&d, "python", "3.9.6", "/usr/bin/python3");
        assert_eq!(old.cycle.as_deref(), Some("3.9"));
        assert!(old.is_eol);
    }

    #[test]
    fn unknown_cycle_or_bad_document_gives_empty_status() {
        let d = doc(include_str!("../../tests/fixtures/eol/nodejs.json"));
        let s = parse_release(&d, "node", "99.0.0", "p");
        assert_eq!((s.cycle, s.latest_in_cycle, s.is_eol, s.behind), (None, None, false, false));
        let s = parse_release(&serde_json::json!({"error": "x"}), "node", "25.6.1", "p");
        assert!(s.cycle.is_none() && !s.is_eol);
    }

    #[test]
    fn version_compare() {
        assert!(is_older("1.25", "1.25.4"));
        assert!(!is_older("1.25.4", "1.25"));
        assert!(!is_older("8.3.1", "8.3.1"));
        assert!(is_older("1.26rc1", "1.26.1"));
    }

    #[tokio::test]
    #[ignore]
    async fn feeds_live_eol() {
        let client = reqwest::Client::new();
        let s = check(&client, "node", "25.6.1", "/x").await;
        assert_eq!(s.cycle.as_deref(), Some("25"));
        assert!(s.is_eol && s.behind, "{s:?}");
        let s = check(&client, "python", "3.13.0", "/x").await;
        assert!(!s.is_eol && s.behind && s.latest_in_cycle.is_some(), "{s:?}");
    }
}
