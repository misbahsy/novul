use crate::inventory::manifest::{normalize_pypi, requirement_pins};
use crate::model::{LockfileScan, ScannedPackage, VulnGroup};
use crate::scan::fix;
use std::collections::HashSet;
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
    let (venvs, rest): (Vec<PathBuf>, Vec<PathBuf>) = lockfiles.iter().cloned().partition(|l| is_requirements(l) && sibling_venv(l).is_some());
    let mut scans = if rest.is_empty() {
        vec![]
    } else {
        match run_scan(osv_scanner, &rest, offline).await {
            // a lockfile used an ecosystem whose database isn't downloaded yet
            Err(e) if e == MISSING_DB => run_scan(osv_scanner, &rest, offline.map(|(o, _)| (o, true))).await,
            r => r,
        }?
    };
    scans.iter_mut().for_each(refine_requirements);
    for (i, req) in venvs.iter().enumerate() {
        let packages = if venv_owner(req, &venvs) == Some(i) {
            let venv = sibling_venv(req).unwrap_or_default();
            let found = crate::inventory::globals::run_osv(osv_scanner, &venv.join("lib"), "python/wheelegg", offline).await?;
            let mut packages: Vec<ScannedPackage> = Vec::new();
            for p in found.into_iter().flat_map(|s| s.packages) {
                if !packages.iter().any(|q| q.name == p.name && q.version == p.version) {
                    packages.push(ScannedPackage { inferred: false, ..p });
                }
            }
            packages
        } else {
            vec![]
        };
        scans.push(LockfileScan { lockfile: req.clone(), packages });
    }
    Ok(scans)
}

/// The virtualenv next to a requirements file (`.venv` or `venv` with a pyvenv.cfg). Its installed
/// packages are the real versions, which the requirements file can only estimate.
fn sibling_venv(req: &Path) -> Option<PathBuf> {
    let dir = req.parent()?;
    [".venv", "venv"].iter().map(|n| dir.join(n)).find(|v| v.join("pyvenv.cfg").is_file())
}

/// Several requirements files can share one venv; it is reported once, under requirements.txt
/// when present, else the first file by name.
fn venv_owner(req: &Path, all: &[PathBuf]) -> Option<usize> {
    let dir = req.parent();
    let siblings = || all.iter().enumerate().filter(|(_, l)| l.parent() == dir);
    siblings().find(|(_, l)| l.file_name().is_some_and(|n| n == "requirements.txt")).or_else(|| siblings().min_by_key(|(_, l)| *l)).map(|(i, _)| i)
}

fn is_requirements(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("requirements") && n.ends_with(".txt"))
}

/// osv-scanner reads `Pillow>=10.0` as Pillow 10.0 installed. Only an exact `==` pin names the
/// installed version, so packages from other lines become estimated. Packages that come in
/// through `-r requirements.txt` are dropped, because that file is scanned on its own. This only
/// applies to an include that discovery also finds (same folder, not ignored, not a symlink), and
/// never to a malicious package: a repository must not be able to hide a package through `-r`.
fn refine_requirements(scan: &mut LockfileScan) {
    if !is_requirements(&scan.lockfile) {
        return;
    }
    let Ok(text) = std::fs::read_to_string(&scan.lockfile) else { return };
    let (own, includes) = requirement_pins(&text);
    let dir = scan.lockfile.parent().unwrap_or(Path::new(""));
    let visible = if includes.is_empty() { vec![] } else { crate::inventory::discover::visible_files(dir) };
    let included: HashSet<String> = includes
        .iter()
        .map(|f| dir.join(f.trim_start_matches("./")))
        .filter(|p| is_requirements(p) && visible.contains(p))
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| requirement_pins(&t).0.into_keys())
        .collect();
    scan.packages.retain_mut(|p| {
        if p.inferred {
            return true;
        }
        let name = normalize_pypi(&p.name);
        match own.get(&name) {
            Some(&exact) => {
                p.inferred = !exact;
                true
            }
            None => !included.contains(&name) || p.vulns.iter().any(|v| v.malicious),
        }
    });
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

    fn fake_venv(dir: &Path, name: &str, version: &str) {
        let meta = dir.join(format!(".venv/lib/python3.12/site-packages/{name}-{version}.dist-info/METADATA"));
        std::fs::create_dir_all(meta.parent().unwrap()).unwrap();
        std::fs::write(dir.join(".venv/pyvenv.cfg"), "home = /usr/bin\n").unwrap();
        std::fs::write(meta, format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")).unwrap();
    }

    #[test]
    fn one_requirements_file_per_folder_reports_the_venv() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        std::fs::create_dir_all(&b).unwrap();
        fake_venv(&a, "pillow", "11.3.0");
        let all = [a.join("requirements-gpu.txt"), a.join("requirements.txt"), a.join("requirements-dev.txt"), b.join("requirements.txt")];
        assert!(sibling_venv(&all[0]).is_some());
        assert!(sibling_venv(&all[3]).is_none(), "no pyvenv.cfg, no venv");
        assert_eq!(venv_owner(&all[0], &all), Some(1));
        let without_main = [a.join("requirements-gpu.txt"), a.join("requirements-dev.txt")];
        assert_eq!(venv_owner(&without_main[0], &without_main), Some(1));
    }

    #[tokio::test]
    #[ignore]
    async fn live_venv_versions_replace_requirements_lower_bounds() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fake_venv(d, "pillow", "11.3.0");
        std::fs::write(d.join("requirements.txt"), "Pillow>=9.5.0\n").unwrap();
        std::fs::write(d.join("requirements-dev.txt"), "-r requirements.txt\n").unwrap();
        let osv = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/binaries/osv-scanner-aarch64-apple-darwin"));
        let scans = scan_lockfiles(&osv, &[d.join("requirements.txt"), d.join("requirements-dev.txt")], None).await.unwrap();
        let main = scans.iter().find(|s| s.lockfile.ends_with("requirements.txt")).unwrap();
        let pillow = main.packages.iter().find(|p| p.name.eq_ignore_ascii_case("pillow")).expect("pillow 11.3.0 has advisories");
        assert_eq!((pillow.version.as_str(), pillow.inferred), ("11.3.0", false));
        assert!(scans.iter().find(|s| s.lockfile.ends_with("requirements-dev.txt")).unwrap().packages.is_empty());
    }

    #[test]
    fn requirements_lower_bounds_are_estimated_and_includes_are_not_repeated() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::write(d.join("requirements.txt"), "Pillow>=10.0  # images\nrequests==2.31.0\nflask[async]==2.2.*\nnumpy>=1.0,<2 ; python_version>'3.8'\n").unwrap();
        std::fs::write(d.join("requirements-dev.txt"), "-r ./requirements.txt\npytest==8.0.0\n").unwrap();
        std::fs::create_dir_all(d.join("elsewhere")).unwrap();
        std::fs::write(d.join("elsewhere/requirements.txt"), "evil==1.0\nshady==1.0\n").unwrap();
        std::fs::write(d.join("requirements-ci.txt"), "-r elsewhere/requirements.txt\n-r requirements.txt\n-r requirements-link.txt\n-r requirements-hidden.txt\nevil==1.0\n").unwrap();
        // a symlinked or gitignored include is not scanned on its own, so it can't hide anything
        std::fs::write(d.join(".gitignore"), "requirements-hidden.txt\n").unwrap();
        std::fs::write(d.join("requirements-hidden.txt"), "hidden==1.0\n").unwrap();
        std::os::unix::fs::symlink(d.join("elsewhere/requirements.txt"), d.join("requirements-link.txt")).unwrap();
        let pkg = |name: &str, inferred: bool| ScannedPackage {
            ecosystem: "PyPI".into(),
            name: name.into(),
            version: "1.0".into(),
            dev: false,
            inferred,
            vulns: if name == "flask-mal" {
                vec![VulnGroup { id: "MAL-2026-1".into(), malicious: true, ..Default::default() }]
            } else {
                vec![]
            },
        };
        let scan = |file: &str, names: &[&str]| {
            let mut s = LockfileScan { lockfile: d.join(file), packages: names.iter().map(|n| pkg(n, false)).collect() };
            s.packages.push(pkg("urllib3", true));
            refine_requirements(&mut s);
            s.packages.iter().map(|p| (p.name.clone(), p.inferred)).collect::<Vec<_>>()
        };
        let own = |v: &[(&str, bool)]| v.iter().map(|(n, i)| (n.to_string(), *i)).collect::<Vec<_>>();
        assert_eq!(
            scan("requirements.txt", &["pillow", "requests", "flask", "numpy"]),
            own(&[("pillow", true), ("requests", false), ("flask", true), ("numpy", true), ("urllib3", true)])
        );
        assert_eq!(
            scan("requirements-dev.txt", &["pillow", "requests", "pytest"]),
            own(&[("pytest", false), ("urllib3", true)]),
            "pillow and requests are reported once, by requirements.txt"
        );
        // an include outside this folder can't hide anything, and a malicious package is never dropped
        std::fs::write(d.join("requirements.txt"), "requests==2.31.0\nflask-mal==1.0\n").unwrap();
        assert_eq!(
            scan("requirements-ci.txt", &["evil", "shady", "hidden", "requests", "flask-mal"]),
            own(&[("evil", false), ("shady", false), ("hidden", false), ("flask-mal", false), ("urllib3", true)])
        );
    }

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
