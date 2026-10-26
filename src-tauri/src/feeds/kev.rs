// Owner: feeds agent.
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

const URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Deserialize)]
struct Feed {
    vulnerabilities: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "cveID")]
    cve_id: String,
}

/// CVE ids in CISA's Known Exploited Vulnerabilities catalog:
/// https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
pub async fn fetch_kev(client: &reqwest::Client) -> Result<HashSet<String>, String> {
    let body = client
        .get(URL)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("KEV request: {e}"))?
        .text()
        .await
        .map_err(|e| format!("KEV request: {e}"))?;
    parse_kev(&body)
}

pub fn parse_kev(json: &str) -> Result<HashSet<String>, String> {
    let feed: Feed = serde_json::from_str(json).map_err(|e| format!("KEV parse: {e}"))?;
    Ok(feed.vulnerabilities.into_iter().map(|v| v.cve_id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_feed_excerpt() {
        let ids = parse_kev(include_str!("../../tests/fixtures/kev/known_exploited_vulnerabilities.json")).unwrap();
        assert_eq!(ids.len(), 20);
        assert!(ids.contains("CVE-2026-114625"));
        assert!(ids.iter().all(|id| id.starts_with("CVE-")));
    }

    #[test]
    fn rejects_html_error_page() {
        assert!(parse_kev("<html>Access Denied</html>").is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn feeds_live_kev() {
        let ids = fetch_kev(&reqwest::Client::new()).await.unwrap();
        assert!(ids.len() > 1000, "{}", ids.len());
        assert!(ids.contains("CVE-2021-44228"), "Log4Shell must be in KEV");
    }
}
