// Owner: v2-ranking agent.
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::time::Duration;

/// FIRST's daily scores for every CVE (~3 MB gzipped CSV). Downloading all of them means the
/// CVEs that affect this Mac are never sent anywhere.
const URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

/// EPSS probability (0..1) for each of `cves` that FIRST scores; others are absent from the map.
pub async fn fetch_epss(client: &reqwest::Client, cves: &[String]) -> Result<HashMap<String, f32>, String> {
    let body = client
        .get(URL)
        .timeout(Duration::from_secs(120))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("EPSS download: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("EPSS download: {e}"))?;
    let csv = gunzip(&body)?;
    let wanted: HashSet<&str> = cves.iter().map(String::as_str).collect();
    parse_epss(&csv, &wanted)
}

/// The file is gzip; a proxy that already decoded it hands over plain text.
fn gunzip(body: &[u8]) -> Result<String, String> {
    if !body.starts_with(&[0x1f, 0x8b]) {
        return String::from_utf8(body.to_vec()).map_err(|e| format!("EPSS file: {e}"));
    }
    let mut out = String::new();
    flate2::read::GzDecoder::new(body).read_to_string(&mut out).map_err(|e| format!("EPSS file: {e}"))?;
    Ok(out)
}

/// `#model_version:...` then `cve,epss,percentile` rows; keeps only the `wanted` CVEs.
pub fn parse_epss(csv: &str, wanted: &HashSet<&str>) -> Result<HashMap<String, f32>, String> {
    let mut lines = csv.lines().filter(|l| !l.starts_with('#'));
    if lines.next().map(str::trim) != Some("cve,epss,percentile") {
        return Err("EPSS file: unexpected header".into());
    }
    Ok(lines
        .filter_map(|l| {
            let mut cols = l.split(',');
            let cve = cols.next()?;
            wanted.contains(cve).then(|| Some((cve.to_string(), cols.next()?.parse().ok()?)))?
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "#model_version:v2026.06.15,score_date:2026-10-26T12:03:22Z\ncve,epss,percentile\nCVE-1999-0001,0.04753,0.91819\nCVE-2021-44228,0.99999,1.00000\nCVE-2023-4863,0.93710,0.99821\n";

    #[test]
    fn keeps_only_the_wanted_cves() {
        let wanted: HashSet<&str> = ["CVE-2021-44228", "CVE-1999-0001", "CVE-2099-0000"].into();
        let m = parse_epss(CSV, &wanted).unwrap();
        assert_eq!(m.len(), 2, "unknown CVE is absent, unwanted one is skipped");
        assert!(m["CVE-2021-44228"] > 0.99);
        assert!((m["CVE-1999-0001"] - 0.04753).abs() < 1e-6);
    }

    #[test]
    fn reads_gzip_and_plain_text() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(CSV.as_bytes()).unwrap();
        assert_eq!(gunzip(&gz.finish().unwrap()).unwrap(), CSV);
        assert_eq!(gunzip(CSV.as_bytes()).unwrap(), CSV);
    }

    #[test]
    fn rejects_error_page() {
        assert!(parse_epss("<html>429</html>", &HashSet::new()).is_err());
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
