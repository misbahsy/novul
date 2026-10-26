// Owner: feeds agent.
use crate::model::{BrewVuln, VulnGroup};
use serde_json::Value;
use std::time::Duration;
use tokio::process::Command;

const BREW: [&str; 2] = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"];

/// Run `brew vulns --json` (built into Homebrew >= 7.0.9) under `taskpolicy -b` and map its
/// output. Ok(vec![]) when brew is missing.
pub async fn brew_vulns() -> Result<Vec<BrewVuln>, String> {
    let Some(brew) = BREW.iter().find(|p| std::path::Path::new(p).exists()) else {
        return Ok(vec![]);
    };
    let child = Command::new("/usr/sbin/taskpolicy")
        .args(["-b", brew, "vulns", "--json"])
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .env("HOMEBREW_NO_ENV_HINTS", "1")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(120), child)
        .await
        .map_err(|_| "brew vulns timed out after 120 s".to_string())?
        .map_err(|e| format!("brew vulns: {e}"))?;
    // brew exits non-zero when it finds something (or skips untrusted taps), so judge by stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_brew(&stdout).map_err(|e| {
        let stderr = String::from_utf8_lossy(&out.stderr);
        format!("{e}; stderr: {}", stderr.lines().next().unwrap_or(""))
    })
}

/// Maps the `findings[].vulnerabilities[]` of `brew vulns --json` (open ones only; `patched`
/// are already resolved by formula patches).
pub fn parse_brew(json: &str) -> Result<Vec<BrewVuln>, String> {
    let doc: Value = serde_json::from_str(json).map_err(|e| format!("brew vulns output: {e}"))?;
    let findings = doc["findings"].as_array().ok_or("brew vulns output has no findings")?;
    let mut out = Vec::new();
    for f in findings {
        let (Some(formula), Some(version)) = (f["formula"].as_str(), f["version"].as_str()) else { continue };
        for v in f["vulnerabilities"].as_array().into_iter().flatten() {
            let Some(advisory) = v["id"].as_str() else { continue };
            let aliases: Vec<String> = v["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).map(String::from).collect();
            let id = std::iter::once(advisory)
                .chain(aliases.iter().map(String::as_str))
                .find(|i| i.starts_with("CVE-"))
                .unwrap_or(advisory)
                .to_string();
            let fixed_version = v["fixed_versions"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).find(|x| !is_commit_sha(x)).map(String::from);
            out.push(BrewVuln {
                formula: formula.into(),
                version: version.into(),
                group: VulnGroup {
                    url: format!("https://osv.dev/vulnerability/{id}"),
                    id,
                    ids: vec![advisory.into()],
                    aliases,
                    score: severity_score(v["severity"].as_str().unwrap_or("")),
                    summary: v["summary"].as_str().unwrap_or("").into(),
                    malicious: false,
                    fixed_version,
                    modified: String::new(),
                },
            });
        }
    }
    Ok(out)
}

fn severity_score(s: &str) -> Option<f32> {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Some(9.5),
        "HIGH" => Some(8.0),
        "MODERATE" | "MEDIUM" => Some(5.5),
        "LOW" => Some(2.5),
        _ => None,
    }
}

/// brew lists unreleased upstream fixes as full commit hashes.
fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = include_str!("../../tests/fixtures/brew/vulns.json");

    #[test]
    fn maps_real_brew_output() {
        let v = parse_brew(REAL).unwrap();
        // node 4 + gh 4 + shaderc 1 + simdjson 2 = 11 open vulns... (checked below)
        let node: Vec<_> = v.iter().filter(|b| b.formula == "node").collect();
        assert_eq!(node.len(), 4);
        let high = node.iter().find(|b| b.group.id == "CVE-2026-21710").unwrap();
        assert_eq!(high.version, "25.6.1");
        assert_eq!(high.group.score, Some(8.0));
        assert_eq!(high.group.aliases, ["BIT-node-2026-21710", "BIT-node-min-2026-21710"]);
        assert_eq!(high.group.url, "https://osv.dev/vulnerability/CVE-2026-21710");
        assert!(!high.group.malicious && high.group.fixed_version.is_none());
        // libssh2 has 1 open + 2 patched in the fixture; only the open one counts
        assert_eq!(v.iter().filter(|b| b.formula == "libssh2").count(), 1);
        assert_eq!(v.len(), 12);
    }

    #[test]
    fn commit_sha_fix_is_not_a_fixed_version() {
        let v = parse_brew(REAL).unwrap();
        let s = v.iter().find(|b| b.formula == "shaderc").unwrap();
        assert_eq!(s.group.id, "OSV-2026-1069");
        assert_eq!(s.group.score, None);
        assert_eq!(s.group.fixed_version, None);
    }

    #[test]
    fn id_prefers_cve_alias_and_released_fix_is_kept() {
        let json = r#"{"findings":[{"formula":"foo","version":"1.2.3","vulnerabilities":[
            {"id":"GHSA-aaaa-bbbb-cccc","severity":"MODERATE","summary":"s","aliases":["GO-2026-1","CVE-2026-1"],
             "fixed_versions":["0123456789abcdef0123456789abcdef01234567","1.2.4"]},
            {"id":"GHSA-dddd-eeee-ffff","severity":"CRITICAL","summary":"t","aliases":[],"fixed_versions":[]}],
            "patched":[{"id":"CVE-2020-1","severity":"HIGH","summary":"x","aliases":[],"fixed_versions":[]}]}]}"#;
        let v = parse_brew(json).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].group.id, "CVE-2026-1");
        assert_eq!(v[0].group.ids, ["GHSA-aaaa-bbbb-cccc"]);
        assert_eq!(v[0].group.score, Some(5.5));
        assert_eq!(v[0].group.fixed_version.as_deref(), Some("1.2.4"));
        assert_eq!(v[1].group.id, "GHSA-dddd-eeee-ffff");
        assert_eq!(v[1].group.score, Some(9.5));
    }

    #[test]
    fn no_findings_and_garbage() {
        assert!(parse_brew(r#"{"findings":[]}"#).unwrap().is_empty());
        assert!(parse_brew("Error: Unknown command: vulns").is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn feeds_live_brew() {
        let started = std::time::Instant::now();
        let v = brew_vulns().await.unwrap();
        eprintln!("{} findings in {:?}", v.len(), started.elapsed());
        assert!(v.iter().all(|b| !b.formula.is_empty() && b.group.url.starts_with("https://osv.dev/")));
    }
}
