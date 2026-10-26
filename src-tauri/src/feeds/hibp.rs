use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct Breach {
    pub name: String,
    pub domain: String,
    pub breach_date: String,
    pub added_date: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Raw {
    name: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    breach_date: String,
    #[serde(default)]
    added_date: String,
}

pub(crate) fn parse(body: &[u8]) -> Result<Vec<Breach>, String> {
    let raw: Vec<Raw> = serde_json::from_slice(body).map_err(|e| format!("hibp parse: {e}"))?;
    Ok(raw
        .into_iter()
        .map(|r| Breach {
            name: r.name,
            domain: r.domain,
            breach_date: r.breach_date,
            added_date: r.added_date,
        })
        .collect())
}

/// Free HIBP breach list (no key): https://haveibeenpwned.com/api/v3/breaches
pub async fn fetch_breaches(client: &reqwest::Client) -> Result<Vec<Breach>, String> {
    let resp = client
        .get("https://haveibeenpwned.com/api/v3/breaches")
        .header("User-Agent", "NoVul")
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("hibp request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("hibp status {}", resp.status()));
    }
    let body = resp.bytes().await.map_err(|e| format!("hibp body: {e}"))?;
    parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture() {
        let body = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hibp/breaches.json")).unwrap();
        let b = parse(&body).unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(b[0], Breach {
            name: "Adobe".into(),
            domain: "adobe.com".into(),
            breach_date: "2013-10-04".into(),
            added_date: "2013-12-04T00:00:00Z".into(),
        });
        assert!(parse(b"{}").is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn v2sec_live_hibp() {
        let b = fetch_breaches(&reqwest::Client::new()).await.unwrap();
        assert!(b.len() > 500);
        assert!(b.iter().any(|x| x.name == "Adobe"));
    }
}
