// Owner: v2-ranking agent.
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

const URL: &str = "https://api.first.org/data/v1/epss";
/// The API returns at most 100 rows per page (default limit), so a batch of 100 needs no paging.
const BATCH: usize = 100;

#[derive(Deserialize)]
struct Response {
    data: Vec<Row>,
}

#[derive(Deserialize)]
struct Row {
    cve: String,
    /// The API sends numbers as strings.
    epss: String,
}

/// EPSS probability (0..1) per CVE id, batched: https://api.first.org/data/v1/epss?cve=A,B,...
/// CVEs the API doesn't know are absent from the map.
pub async fn fetch_epss(client: &reqwest::Client, cves: &[String]) -> Result<HashMap<String, f32>, String> {
    let mut out = HashMap::new();
    for batch in cves.chunks(BATCH) {
        let body = client
            .get(format!("{URL}?cve={}", batch.join(",")))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("EPSS request: {e}"))?
            .text()
            .await
            .map_err(|e| format!("EPSS request: {e}"))?;
        out.extend(parse_epss(&body)?);
    }
    Ok(out)
}

pub fn parse_epss(json: &str) -> Result<HashMap<String, f32>, String> {
    let r: Response = serde_json::from_str(json).map_err(|e| format!("EPSS parse: {e}"))?;
    Ok(r.data.into_iter().filter_map(|row| Some((row.cve, row.epss.parse().ok()?))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_response() {
        let m = parse_epss(include_str!("../../tests/fixtures/epss/response.json")).unwrap();
        assert_eq!(m.len(), 4, "unknown CVE is absent");
        assert!(m["CVE-2021-44228"] > 0.99);
        assert!((m["CVE-1999-0001"] - 0.04753).abs() < 1e-6);
    }

    #[test]
    fn rejects_error_page() {
        assert!(parse_epss("<html>429</html>").is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn v2rank_live_epss() {
        let cves: Vec<String> = ["CVE-2021-44228", "CVE-2023-4863", "CVE-1999-0001"].map(String::from).to_vec();
        let m = fetch_epss(&reqwest::Client::new(), &cves).await.unwrap();
        println!("{m:?}");
        assert_eq!(m.len(), 3);
        assert!(m["CVE-2021-44228"] > 0.9);
        assert!(m["CVE-1999-0001"] < 0.9);
    }
}
