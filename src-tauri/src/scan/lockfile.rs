use crate::model::{LockfileScan, ScannedPackage, VulnGroup};
use crate::scan::fix;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Private mode: osv-scanner matches against OSV databases downloaded to `dir` instead of sending
/// package names to the OSV API, and skips deps.dev resolution of requirements.txt.
#[derive(Clone, Debug)]
pub struct Offline {
    pub dir: PathBuf,
}

/// osv-scanner's per-ecosystem database files are re-downloaded once they are this old.
const DB_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

impl Offline {
    pub fn new() -> Offline {
        Offline { dir: dirs::cache_dir().unwrap_or_else(std::env::temp_dir).join("dev.novul.app").join("osv-db") }
    }

    /// True when a database for one of `ecosystems` is missing or a day old: only then is
    /// osv-scanner allowed to download (each database is a full file, npm's is about 200 MB).
    pub fn needs_download<'a>(&self, ecosystems: impl IntoIterator<Item = &'a str>) -> bool {
        ecosystems.into_iter().any(|eco| {
            let zip = self.dir.join("osv-scalibr").join(eco).join("all.zip");
            std::fs::metadata(zip)
                .and_then(|m| m.modified())
                .map_or(true, |t| t.elapsed().map_or(true, |age| age > DB_MAX_AGE))
        })
    }

    /// osv-scanner says this when a database it needs isn't downloaded. It then stops matching
    /// partway and still exits 0, so its results can't be trusted.
    pub fn missing_db(stderr: &str) -> bool {
        stderr.contains("no offline version of the OSV database")
    }

    pub fn apply(&self, cmd: &mut tokio::process::Command, download: bool) {
        cmd.args(["--offline-vulnerabilities", "--no-resolve"]).env("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", &self.dir);
        if download {
            cmd.arg("--download-offline-databases");
        }
    }
}

/// Run osv-scanner once over many lockfiles:
/// `taskpolicy -b <osv_scanner> scan source -L <a> -L <b> ... --all-packages --format json`.
/// With `offline` (Private mode) it uses local databases, downloading them first when `download`.
/// Exit codes 0 and 1 are success, 128 = no packages, anything else is an error.
pub async fn scan_lockfiles(osv_scanner: &Path, lockfiles: &[PathBuf], offline: Option<(&Offline, bool)>) -> Result<Vec<LockfileScan>, String> {
    if lockfiles.is_empty() {
        return Ok(vec![]);
    }
    match run_scan(osv_scanner, lockfiles, offline).await {
        // a lockfile used an ecosystem whose database isn't downloaded yet
        Err(e) if e == MISSING_DB => run_scan(osv_scanner, lockfiles, offline.map(|(o, _)| (o, true))).await,
        r => r,
    }
}

const MISSING_DB: &str = "osv-scanner: offline database missing";

async fn run_scan(osv_scanner: &Path, lockfiles: &[PathBuf], offline: Option<(&Offline, bool)>) -> Result<Vec<LockfileScan>, String> {
    let mut cmd = tokio::process::Command::new("/usr/sbin/taskpolicy");
    // -b: background QoS keeps CPU and disk priority low
    cmd.arg("-b").arg(osv_scanner).args(["scan", "source"]);
    for l in lockfiles {
        cmd.arg("-L").arg(l);
    }
    if let Some((o, download)) = offline {
        o.apply(&mut cmd, download);
    }
    cmd.args(["--all-packages", "--format", "json", "--verbosity", "error"])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let out = cmd.output().await.map_err(|e| format!("failed to run osv-scanner: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if offline.is_some() && Offline::missing_db(&stderr) {
        return Err(MISSING_DB.into());
    }
    let tail = stderr.lines().rev().take(10).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
    match out.status.code() {
        Some(0 | 1) => parse_output(&String::from_utf8_lossy(&out.stdout)).map_err(|e| format!("{e}: {tail}")),
        Some(128) => Ok(lockfiles.iter().map(|p| LockfileScan { lockfile: p.clone(), packages: vec![] }).collect()),
        code => Err(format!("osv-scanner failed (exit {}): {tail}", code.map_or("signal".to_string(), |c| c.to_string()))),
    }
}

#[derive(Deserialize, Default)]
struct Output {
    #[serde(default)]
    results: Vec<ResultEntry>,
}

#[derive(Deserialize)]
struct ResultEntry {
    source: Source,
    #[serde(default)]
    packages: Vec<Pkg>,
}

#[derive(Deserialize)]
struct Source {
    path: String,
    #[serde(default, rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct Pkg {
    package: PkgInfo,
    #[serde(default)]
    dependency_groups: Vec<String>,
    #[serde(default)]
    vulnerabilities: Vec<Record>,
    #[serde(default)]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct PkgInfo {
    name: String,
    version: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct Record {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    modified: Option<String>,
    #[serde(default)]
    affected: Value,
}

#[derive(Deserialize)]
struct Group {
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    aliases: Vec<String>,
    max_severity: Option<String>,
}

fn summary_of(records: &[&Record]) -> String {
    if let Some(s) = records.iter().filter_map(|r| r.summary.as_deref()).map(str::trim).find(|s| !s.is_empty()) {
        return s.to_string();
    }
    records
        .iter()
        .filter_map(|r| r.details.as_deref())
        .filter_map(|d| d.lines().map(str::trim).find(|l| !l.is_empty()))
        .next()
        .map(|l| l.chars().take(200).collect())
        .unwrap_or_default()
}

fn vuln_group(pkg: &Pkg, group: &Group) -> Option<VulnGroup> {
    let first = group.ids.first()?;
    let records: Vec<&Record> = group.ids.iter().filter_map(|id| pkg.vulnerabilities.iter().find(|r| &r.id == id)).collect();
    let info = &pkg.package;
    let fixed_version = records
        .iter()
        .filter_map(|r| fix::fixed_version_for_package(&info.ecosystem, &info.name, &info.version, &r.affected))
        .min_by(|a, b| fix::compare_versions(&info.ecosystem, a, b).unwrap_or(std::cmp::Ordering::Equal));
    Some(VulnGroup {
        id: fix::canonical_id(&group.ids, &group.aliases),
        ids: group.ids.clone(),
        aliases: group.aliases.clone(),
        score: group.max_severity.as_deref().and_then(|s| s.trim().parse().ok()),
        summary: summary_of(&records),
        malicious: group.ids.iter().any(|i| i.starts_with("MAL-")),
        fixed_version,
        url: format!("https://osv.dev/vulnerability/{first}"),
        modified: records.iter().filter_map(|r| r.modified.as_deref()).max().unwrap_or_default().to_string(),
    })
}

/// Pure parser for osv-scanner JSON (see tests/fixtures/osv/*.json). Results sharing a
/// `source.path` merge into one LockfileScan; packages from a non-"lockfile" source are `inferred`.
pub fn parse_output(json: &str) -> Result<Vec<LockfileScan>, String> {
    let out: Output = serde_json::from_str(json).map_err(|e| format!("invalid osv-scanner output: {e}"))?;
    let mut scans: Vec<LockfileScan> = Vec::new();
    for result in out.results {
        let path = PathBuf::from(&result.source.path);
        let inferred = result.source.kind != "lockfile";
        let idx = match scans.iter().position(|s| s.lockfile == path) {
            Some(i) => i,
            None => {
                scans.push(LockfileScan { lockfile: path, packages: vec![] });
                scans.len() - 1
            }
        };
        let scan = &mut scans[idx];
        for pkg in &result.packages {
            let info = &pkg.package;
            if scan.packages.iter().any(|p| p.name == info.name && p.version == info.version) {
                continue;
            }
            scan.packages.push(ScannedPackage {
                ecosystem: info.ecosystem.clone(),
                name: info.name.clone(),
                version: info.version.clone(),
                dev: pkg.dependency_groups.iter().any(|g| g == "dev"),
                inferred,
                vulns: pkg.groups.iter().filter_map(|g| vuln_group(pkg, g)).collect(),
            });
        }
    }
    Ok(scans)
}

#[cfg(test)]
mod tests {

    #[test]
    fn offline_databases_download_only_when_missing_or_a_day_old() {
        let tmp = tempfile::tempdir().unwrap();
        let o = Offline { dir: tmp.path().to_path_buf() };
        assert!(o.needs_download(["npm"]), "missing");
        assert!(!o.needs_download(std::iter::empty::<&str>()), "nothing to scan");
        let zip = tmp.path().join("osv-scalibr/npm/all.zip");
        std::fs::create_dir_all(zip.parent().unwrap()).unwrap();
        std::fs::write(&zip, b"x").unwrap();
        assert!(!o.needs_download(["npm"]), "fresh");
        assert!(o.needs_download(["npm", "PyPI"]), "one of them missing");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 3600);
        std::fs::File::options().write(true).open(&zip).unwrap().set_modified(old).unwrap();
        assert!(o.needs_download(["npm"]), "a day old");
    }

    #[test]
    fn offline_flags_keep_package_names_local() {
        let o = Offline { dir: PathBuf::from("/db") };
        let mut cmd = tokio::process::Command::new("osv-scanner");
        o.apply(&mut cmd, false);
        let args: Vec<_> = cmd.as_std().get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["--offline-vulnerabilities", "--no-resolve"]);
        let env: Vec<_> = cmd.as_std().get_envs().map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned()))).collect();
        assert_eq!(env, [("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY".to_string(), Some("/db".to_string()))]);
        let mut cmd = tokio::process::Command::new("osv-scanner");
        o.apply(&mut cmd, true);
        assert!(cmd.as_std().get_args().any(|a| a == "--download-offline-databases"));
    }

    use super::*;

    const NPM: &str = include_str!("../../tests/fixtures/osv/npm-scan.json");
    const PY: &str = include_str!("../../tests/fixtures/osv/py-scan.json");

    fn pkg<'a>(scan: &'a LockfileScan, name: &str) -> &'a ScannedPackage {
        scan.packages.iter().find(|p| p.name == name).unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn npm_fixture() {
        let scans = parse_output(NPM).unwrap();
        assert_eq!(scans.len(), 1);
        assert!(scans[0].lockfile.ends_with("package-lock.json"));
        assert_eq!(scans[0].packages.len(), 2);

        let lodash = pkg(&scans[0], "lodash");
        assert_eq!((lodash.ecosystem.as_str(), lodash.version.as_str()), ("npm", "4.17.20"));
        assert!(!lodash.dev && !lodash.inferred);
        assert_eq!(lodash.vulns.len(), 5);
        let g = lodash.vulns.iter().find(|g| g.ids == ["GHSA-35jh-r3h4-6jhm"]).unwrap();
        assert_eq!(g.id, "CVE-2021-23337");
        assert_eq!(g.score, Some(7.2));
        assert_eq!(g.fixed_version.as_deref(), Some("4.17.21"));
        assert_eq!(g.summary, "Command Injection in lodash");
        assert_eq!(g.url, "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm");
        assert!(!g.malicious);
        assert!(g.modified.starts_with("2026-10-17"));
        // sibling package entries (lodash-es) in the same record must not leak into the fix
        let newest = lodash.vulns.iter().find(|g| g.id == "CVE-2026-4800").unwrap();
        assert_eq!(newest.fixed_version.as_deref(), Some("4.18.0"));

        let minimist = pkg(&scans[0], "minimist");
        assert!(minimist.dev);
        assert_eq!(minimist.vulns[0].fixed_version.as_deref(), Some("1.2.6"));
    }

    #[test]
    fn python_fixture_merges_inferred_source() {
        let scans = parse_output(PY).unwrap();
        assert_eq!(scans.len(), 1);
        let s = &scans[0];
        assert!(s.lockfile.ends_with("requirements.txt"));

        assert!(!pkg(s, "requests").inferred);
        assert!(!pkg(s, "flask").inferred);
        for n in ["urllib3", "idna", "certifi", "jinja2"] {
            assert!(pkg(s, n).inferred, "{n}");
        }
        // vuln-free packages are still returned
        assert!(pkg(s, "click").vulns.is_empty());

        let flask = pkg(s, "flask");
        assert_eq!(flask.vulns.len(), 2);
        let g = flask.vulns.iter().find(|g| g.ids.contains(&"PYSEC-2023-62".to_string())).unwrap();
        assert_eq!(g.id, "CVE-2023-30861");
        assert_eq!(g.fixed_version.as_deref(), Some("2.2.5"));
        assert_eq!(g.score, Some(8.7));
        // PYSEC-2023-62 has no summary; the GHSA record in the group supplies one
        assert!(g.summary.starts_with("Flask vulnerable to possible disclosure"));
        assert!(g.modified.starts_with("2026-09-10"));
    }

    #[test]
    fn summary_falls_back_to_first_line_of_details_and_missing_severity_is_none() {
        let json = r#"{"results":[{"source":{"path":"/p/uv.lock","type":"lockfile"},"packages":[
          {"package":{"name":"foo","version":"1.0.0","ecosystem":"PyPI"},
           "vulnerabilities":[{"id":"MAL-2024-1","details":"\n  First line here.\nSecond line.","modified":"2024-01-01T00:00:00Z"}],
           "groups":[{"ids":["MAL-2024-1"],"aliases":[],"max_severity":""}]}]}]}"#;
        let g = &parse_output(json).unwrap()[0].packages[0].vulns[0];
        assert_eq!(g.summary, "First line here.");
        assert_eq!(g.score, None);
        assert!(g.malicious);
        assert_eq!(g.id, "MAL-2024-1");
        assert_eq!(g.fixed_version, None);
    }

    #[test]
    fn details_summary_is_capped() {
        let long = "x".repeat(500);
        let json = format!(
            r#"{{"results":[{{"source":{{"path":"/p/a","type":"lockfile"}},"packages":[
              {{"package":{{"name":"foo","version":"1","ecosystem":"npm"}},
               "vulnerabilities":[{{"id":"A-1","details":"{long}"}}],
               "groups":[{{"ids":["A-1"],"aliases":[]}}]}}]}}]}}"#
        );
        assert_eq!(parse_output(&json).unwrap()[0].packages[0].vulns[0].summary.len(), 200);
    }

    #[test]
    fn bad_json_is_an_error_and_empty_results_are_fine() {
        assert!(parse_output("not json").is_err());
        assert!(parse_output("{}").unwrap().is_empty());
        assert!(parse_output(r#"{"results":[]}"#).unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_input_skips_the_scanner() {
        assert_eq!(scan_lockfiles(Path::new("/nonexistent"), &[], None).await.unwrap(), vec![]);
    }

    #[tokio::test]
    async fn spawn_failure_is_an_error() {
        let err = scan_lockfiles(Path::new("/nonexistent/osv-scanner"), &[PathBuf::from("/x/package-lock.json")], None).await.unwrap_err();
        assert!(err.contains("osv-scanner") || err.contains("invalid"), "{err}");
    }

    // Needs network (OSV API). Run: cargo test -- --ignored scan_core
    #[tokio::test]
    #[ignore]
    async fn scan_core_real_sidecar() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bin = root.join("binaries/osv-scanner-aarch64-apple-darwin");
        let lock = root.join("tests/fixtures/osv/package-lock.json");
        let scans = scan_lockfiles(&bin, &[lock.clone()], None).await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].lockfile, lock);
        let lodash = pkg(&scans[0], "lodash");
        assert!(lodash.vulns.iter().any(|g| g.id == "CVE-2021-23337" && g.fixed_version.as_deref() == Some("4.17.21")));
        assert!(pkg(&scans[0], "minimist").dev);
    }
}
