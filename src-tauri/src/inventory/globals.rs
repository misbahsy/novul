use crate::inventory::manifest::normalize_pypi;
use crate::model::{LockfileScan, ScannedPackage};
use crate::scan::lockfile::{parse_output, scan_lockfiles};
use crate::store::FindingInput;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

const OSV_TIMEOUT: Duration = Duration::from_secs(300);
const CMD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Npm,
    Pnpm,
    Bun,
    Pipx,
    Uv,
    /// Cargo-auditable data embedded in binaries
    CargoBins,
    /// Crates named in ~/.cargo/.crates2.json, scanned through a synthetic Cargo.lock
    CargoCrates,
    Go,
    Gem,
}

impl Kind {
    fn project_name(self) -> &'static str {
        match self {
            Kind::Npm => "Global npm",
            Kind::Pnpm => "Global pnpm",
            Kind::Bun => "Global bun",
            Kind::Pipx => "pipx",
            Kind::Uv => "uv tools",
            Kind::CargoBins | Kind::CargoCrates => "Cargo binaries",
            Kind::Go => "Go binaries",
            Kind::Gem => "Ruby gems",
        }
    }

    /// osv-scanner extractors. The default lockfile plugins are off, so only installed artifacts count.
    fn plugins(self) -> &'static str {
        match self {
            Kind::Npm | Kind::Pnpm | Kind::Bun => "javascript/packagejson,artifact",
            Kind::Pipx | Kind::Uv => "python/wheelegg",
            Kind::CargoBins | Kind::Go => "artifact",
            Kind::Gem => "ruby/gemspec",
            Kind::CargoCrates => "",
        }
    }
}

struct Source {
    kind: Kind,
    dir: PathBuf,
}

/// Vulnerable packages installed globally, outside any project: npm/pnpm/bun globals,
/// pipx and uv tool venvs, cargo-installed binaries, Go binaries in ~/go/bin, gems.
/// kind = "global"; project_name e.g. "Global npm", project_path = the install dir.
///
/// osv-scanner reads the installed artifacts (`--x-plugins`, with `--no-ignore` because
/// /opt/homebrew is a git checkout whose .gitignore hides everything). Any failed scan
/// makes the whole call an error so the caller keeps the previous results.
pub async fn global_findings(osv_scanner: &Path) -> Result<Vec<FindingInput>, String> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    for src in sources().await {
        let scans = match src.kind {
            Kind::CargoCrates => scan_crates(osv_scanner, &src.dir).await,
            _ => run_osv(osv_scanner, &src.dir, src.kind.plugins()).await,
        };
        match scans {
            Ok(scans) => out.extend(findings_from(src.kind, &src.dir, &scans)),
            Err(e) => errors.push(format!("{} ({}): {e}", src.kind.project_name(), src.dir.display())),
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors.join("; "))
    }
}

async fn sources() -> Vec<Source> {
    let home = dirs::home_dir().unwrap_or_default();
    let mut found: Vec<Source> = Vec::new();
    let mut add = |kind: Kind, dir: PathBuf| {
        let Ok(real) = dir.canonicalize() else { return };
        if real.is_dir() && !found.iter().any(|s| s.kind == kind && s.dir == real) {
            found.push(Source { kind, dir: real });
        }
    };
    // npm lives under Homebrew/nvm-style prefixes; `npm root -g` is authoritative, the rest is the fallback
    let mut npm_dirs = vec![PathBuf::from("/opt/homebrew/lib/node_modules"), PathBuf::from("/usr/local/lib/node_modules")];
    if let Some(d) = cmd_stdout("npm", &["root", "-g"]).await {
        npm_dirs.insert(0, PathBuf::from(d));
    }
    for d in npm_dirs {
        add(Kind::Npm, d);
    }
    if let Some(d) = cmd_stdout("pnpm", &["root", "-g"]).await {
        add(Kind::Pnpm, PathBuf::from(d));
    }
    add(Kind::Bun, home.join(".bun/install/global/node_modules"));
    add(Kind::Pipx, home.join(".local/pipx/venvs"));
    add(Kind::Pipx, home.join("Library/Application Support/pipx/venvs"));
    add(Kind::Uv, std::env::var_os("UV_TOOL_DIR").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share/uv/tools")));
    add(Kind::CargoBins, home.join(".cargo/bin"));
    add(Kind::CargoCrates, home.join(".cargo/bin"));
    add(Kind::Go, std::env::var_os("GOBIN").map(PathBuf::from).unwrap_or_else(|| home.join("go/bin")));
    if let Some(d) = cmd_stdout("gem", &["env", "gemdir"]).await {
        add(Kind::Gem, PathBuf::from(d));
    }
    found
}

/// Finder-launched apps have a minimal PATH, so Homebrew's bins are added.
async fn cmd_stdout(bin: &str, args: &[&str]) -> Option<String> {
    let path = format!("{}:/opt/homebrew/bin:/usr/local/bin", std::env::var("PATH").unwrap_or_default());
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args).env("PATH", path).stdin(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true);
    let out = tokio::time::timeout(CMD_TIMEOUT, cmd.output()).await.ok()?.ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && s.starts_with('/')).then_some(s)
}

/// `taskpolicy -b <osv> scan source -r <dir> --no-ignore --x-no-default-plugins --x-plugins <plugins>`.
/// Exit 0 and 1 are success, 128 = nothing found.
async fn run_osv(osv_scanner: &Path, dir: &Path, plugins: &str) -> Result<Vec<LockfileScan>, String> {
    let mut cmd = tokio::process::Command::new("/usr/sbin/taskpolicy");
    cmd.arg("-b").arg(osv_scanner).args(["scan", "source", "-r"]).arg(dir);
    cmd.args(["--no-ignore", "--x-no-default-plugins", "--x-plugins", plugins, "--format", "json", "--verbosity", "error"])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let out = tokio::time::timeout(OSV_TIMEOUT, cmd.output())
        .await
        .map_err(|_| "osv-scanner timed out".to_string())?
        .map_err(|e| format!("failed to run osv-scanner: {e}"))?;
    match out.status.code() {
        Some(0 | 1) => parse_output(&String::from_utf8_lossy(&out.stdout)),
        Some(128) => Ok(vec![]),
        code => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let tail = stderr.lines().rev().take(5).collect::<Vec<_>>().join("\n");
            Err(format!("osv-scanner failed (exit {}): {tail}", code.map_or("signal".to_string(), |c| c.to_string())))
        }
    }
}

/// `cargo install` records what it installed in ~/.cargo/.crates2.json, but the binaries carry no
/// dependency data, so the crates become a throwaway Cargo.lock for osv-scanner.
async fn scan_crates(osv_scanner: &Path, bin_dir: &Path) -> Result<Vec<LockfileScan>, String> {
    let Some(cargo_home) = bin_dir.parent() else { return Ok(vec![]) };
    let Ok(json) = std::fs::read_to_string(cargo_home.join(".crates2.json")) else { return Ok(vec![]) };
    let crates = parse_crates2(&json)?;
    if crates.is_empty() {
        return Ok(vec![]);
    }
    let dir = std::env::temp_dir().join(format!("novul-cargo-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let lock = dir.join("Cargo.lock");
    let result = match std::fs::write(&lock, synthetic_cargo_lock(&crates)) {
        Ok(()) => scan_lockfiles(osv_scanner, &[lock]).await,
        Err(e) => Err(e.to_string()),
    };
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// (name, version) of every crates.io install in `.crates2.json`; git and path installs are skipped.
fn parse_crates2(json: &str) -> Result<Vec<(String, String)>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("invalid .crates2.json: {e}"))?;
    let installs = v.get("installs").and_then(|i| i.as_object()).ok_or("no installs in .crates2.json")?;
    let mut out: Vec<(String, String)> = installs
        .keys()
        .filter_map(|k| {
            let mut parts = k.split(' ');
            let (name, version, source) = (parts.next()?, parts.next()?, parts.next()?);
            source.starts_with("(registry+").then(|| (name.to_string(), version.to_string()))
        })
        .collect();
    out.sort();
    Ok(out)
}

fn synthetic_cargo_lock(crates: &[(String, String)]) -> String {
    let mut s = String::from("version = 3\n");
    for (n, v) in crates {
        s.push_str(&format!("\n[[package]]\nname = \"{n}\"\nversion = \"{v}\"\n"));
    }
    s
}

/// The first path component under the scanned dir, joining `@scope/name`: the global tool or venv
/// that owns a nested package.
fn owner(dir: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(dir).ok()?;
    let mut parts = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned());
    let first = parts.next()?;
    if first.starts_with('@') {
        Some(format!("{first}/{}", parts.next()?))
    } else {
        Some(first)
    }
}

fn safe_name(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.chars().all(|c| c.is_ascii_alphanumeric() || "@._/+-".contains(c))
}

/// Exact `<name>@<version>` target for a runnable `npm install -g` / `pnpm add -g`.
fn node_target(name: &str, version: &str) -> Option<String> {
    (safe_name(name) && safe_name(version)).then(|| format!("{name}@{version}"))
}

fn fix_command(kind: Kind, p: &ScannedPackage, owner: &str, is_top: bool, fixed: Option<&str>) -> Option<String> {
    let fixed = fixed?;
    match kind {
        // npm: a transitive dependency is fixed by updating the tool that bundles it
        Kind::Npm if p.ecosystem == "npm" => {
            let target = if is_top { node_target(&p.name, fixed) } else { node_target(owner, "latest") };
            target.map(|t| format!("npm install -g {t}"))
        }
        // pnpm and bun lay packages out flat or in a store, so the owner is unknown
        Kind::Pnpm => Some("pnpm update -g".into()),
        Kind::Bun => Some("bun update -g".into()),
        Kind::Pipx if p.ecosystem == "PyPI" && safe_name(owner) => Some(format!("pipx upgrade {owner}")),
        Kind::Uv if p.ecosystem == "PyPI" && safe_name(owner) => Some(format!("uv tool upgrade {owner}")),
        Kind::CargoCrates if safe_name(&p.name) && safe_name(fixed) => Some(format!("cargo install {} --version {fixed}", p.name)),
        Kind::Gem if safe_name(&p.name) => Some(format!("gem update {}", p.name)),
        _ => None,
    }
}

/// Maps scanned artifacts to findings. Packages nested in a tool (npm dependencies, venv
/// packages) are reported against that tool's directory and are not `direct`.
fn findings_from(kind: Kind, dir: &Path, scans: &[LockfileScan]) -> Vec<FindingInput> {
    let mut out: Vec<FindingInput> = Vec::new();
    for scan in scans {
        for p in scan.packages.iter().filter(|p| !p.vulns.is_empty()) {
            let owner_name = match kind {
                Kind::Gem | Kind::CargoCrates => Some(p.name.clone()),
                Kind::CargoBins | Kind::Go => scan.lockfile.file_name().map(|n| n.to_string_lossy().into_owned()),
                _ => owner(dir, &scan.lockfile),
            };
            let Some(owner_name) = owner_name else { continue };
            let (project_path, direct) = match kind {
                Kind::Npm => (dir.join(&owner_name), Some(p.name == owner_name)),
                Kind::Pnpm | Kind::Bun => (dir.to_path_buf(), None),
                Kind::Pipx | Kind::Uv => (dir.join(&owner_name), Some(normalize_pypi(&p.name) == normalize_pypi(&owner_name))),
                Kind::Gem | Kind::CargoCrates => (dir.to_path_buf(), Some(true)),
                Kind::CargoBins | Kind::Go => (scan.lockfile.clone(), Some(false)),
            };
            for v in &p.vulns {
                if out.iter().any(|f| f.project_path == project_path.to_string_lossy() && f.name == p.name && f.group_id == v.id) {
                    continue;
                }
                let mut aliases: Vec<String> = Vec::new();
                for a in v.aliases.iter().chain(&v.ids) {
                    if *a != v.id && !aliases.contains(a) {
                        aliases.push(a.clone());
                    }
                }
                let fixed = v.fixed_version.as_deref().filter(|_| !v.malicious);
                out.push(FindingInput {
                    kind: "global",
                    group_id: v.id.clone(),
                    project_name: kind.project_name().into(),
                    project_path: project_path.to_string_lossy().into_owned(),
                    ecosystem: p.ecosystem.clone(),
                    name: p.name.clone(),
                    installed_version: p.version.clone(),
                    fixed_version: v.fixed_version.clone(),
                    direct,
                    dev: false,
                    inferred: false,
                    fix_command: fix_command(kind, p, &owner_name, direct == Some(true), fixed),
                    aliases,
                    summary: v.summary.clone(),
                    score: v.score,
                    malicious: v.malicious,
                    url: v.url.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NPM: &str = include_str!("../../tests/fixtures/globals/npm-global.json");
    const UV: &str = include_str!("../../tests/fixtures/globals/uv-tools.json");
    const GEMS: &str = include_str!("../../tests/fixtures/globals/gems.json");
    const NPM_DIR: &str = "/opt/homebrew/lib/node_modules";

    fn find<'a>(f: &'a [FindingInput], name: &str) -> Vec<&'a FindingInput> {
        f.iter().filter(|f| f.name == name).collect()
    }

    #[test]
    fn npm_top_level_and_nested_packages() {
        let f = findings_from(Kind::Npm, Path::new(NPM_DIR), &parse_output(NPM).unwrap());

        let pnpm = find(&f, "pnpm");
        assert!(!pnpm.is_empty());
        let p = pnpm[0];
        assert_eq!((p.kind, p.project_name.as_str(), p.ecosystem.as_str()), ("global", "Global npm", "npm"));
        assert_eq!(p.project_path, format!("{NPM_DIR}/pnpm"));
        assert_eq!(p.direct, Some(true));
        let fixed = p.fixed_version.as_deref().expect("fixture has a fix for pnpm");
        assert_eq!(p.fix_command.as_deref(), Some(format!("npm install -g pnpm@{fixed}").as_str()));
        assert!(!p.dev && !p.inferred);

        // undici lives inside npm itself: fixed by updating npm, not by installing undici globally
        let u = find(&f, "undici")[0];
        assert_eq!(u.project_path, format!("{NPM_DIR}/npm"));
        assert_eq!(u.direct, Some(false));
        assert_eq!(u.fix_command.as_deref(), Some("npm install -g npm@latest"));

        // scoped packages nested under a scoped owner keep the whole `@scope/name` as owner
        let b = find(&f, "@fastify/busboy");
        assert!(b.is_empty() || b[0].project_path == format!("{NPM_DIR}/netlify-cli"));
        assert_eq!(find(&f, "zod")[0].project_path, format!("{NPM_DIR}/netlify-cli"));
    }

    #[test]
    fn npm_go_binary_findings_have_no_npm_fix() {
        let f = findings_from(Kind::Npm, Path::new(NPM_DIR), &parse_output(NPM).unwrap());
        let std = find(&f, "stdlib");
        assert!(!std.is_empty());
        assert_eq!(std[0].ecosystem, "Go");
        assert_eq!(std[0].fix_command, None);
        assert_eq!(std[0].project_path, format!("{NPM_DIR}/netlify-cli"));
    }

    #[test]
    fn uv_tool_packages_map_to_the_tool() {
        let dir = Path::new("/Users/dev/.local/share/uv/tools");
        let f = findings_from(Kind::Uv, dir, &parse_output(UV).unwrap());
        let a = find(&f, "anyio");
        assert!(!a.is_empty());
        assert_eq!(a[0].project_name, "uv tools");
        assert_eq!(a[0].ecosystem, "PyPI");
        assert_eq!(a[0].project_path, "/Users/dev/.local/share/uv/tools/browser-harness");
        assert_eq!(a[0].direct, Some(false));
        assert_eq!(a[0].fix_command.as_deref(), Some("uv tool upgrade browser-harness"));
        assert!(find(&f, "pillow").len() > 5);
    }

    #[test]
    fn gem_fix_is_gem_update() {
        let f = findings_from(Kind::Gem, Path::new("/Library/Ruby/Gems/2.6.0"), &parse_output(GEMS).unwrap());
        let b = find(&f, "bundler");
        assert!(!b.is_empty());
        assert_eq!((b[0].project_name.as_str(), b[0].ecosystem.as_str()), ("Ruby gems", "RubyGems"));
        assert_eq!(b[0].project_path, "/Library/Ruby/Gems/2.6.0");
        if b[0].fixed_version.is_some() {
            assert_eq!(b[0].fix_command.as_deref(), Some("gem update bundler"));
        }
    }

    #[test]
    fn go_binary_findings_point_at_the_binary() {
        // the same Go artifact result, as if found in ~/go/bin
        let scans = parse_output(NPM).unwrap();
        let go: Vec<_> = scans.into_iter().filter(|s| s.lockfile.ends_with("local-functions-proxy")).collect();
        let f = findings_from(Kind::Go, Path::new("/x/go/bin"), &go);
        assert!(!f.is_empty());
        assert!(f.iter().all(|f| f.project_path.ends_with("/bin/local-functions-proxy") && f.fix_command.is_none()));
        assert_eq!(f[0].project_name, "Go binaries");
    }

    #[test]
    fn crates2_registry_installs_become_a_cargo_lock() {
        let json = r#"{"installs":{
          "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["rg"]},
          "mytool 0.1.0 (git+https://github.com/me/mytool#abc123)":{"bins":["mytool"]},
          "local 0.2.0 (path+file:///Users/me/local)":{"bins":["local"]}}}"#;
        let crates = parse_crates2(json).unwrap();
        assert_eq!(crates, [("ripgrep".to_string(), "14.1.0".to_string())]);
        let lock = synthetic_cargo_lock(&crates);
        assert!(lock.contains("name = \"ripgrep\"\nversion = \"14.1.0\""));
        assert!(parse_crates2("{}").is_err());
    }

    #[test]
    fn cargo_crate_fix_and_unsafe_names() {
        let p = ScannedPackage { ecosystem: "crates.io".into(), name: "ripgrep".into(), version: "1.0.0".into(), dev: false, inferred: false, vulns: vec![] };
        assert_eq!(fix_command(Kind::CargoCrates, &p, "ripgrep", true, Some("14.1.1")).as_deref(), Some("cargo install ripgrep --version 14.1.1"));
        assert_eq!(fix_command(Kind::CargoBins, &p, "rg", false, Some("14.1.1")), None);
        let evil = ScannedPackage { name: "x; rm -rf ~".into(), ecosystem: "npm".into(), ..p };
        assert_eq!(fix_command(Kind::Npm, &evil, "x; rm -rf ~", true, Some("1.0.0")), None);
        assert!(!safe_name("-g") && safe_name("@openai/codex"));
    }

    #[tokio::test]
    #[ignore]
    async fn v2inv_live_globals() {
        let osv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("binaries/osv-scanner-aarch64-apple-darwin");
        let start = std::time::Instant::now();
        let f = global_findings(&osv).await.expect("global scan");
        let mut by_project = std::collections::BTreeMap::new();
        for x in &f {
            *by_project.entry(x.project_name.clone()).or_insert(0) += 1;
        }
        println!("{} findings in {:?}: {by_project:?}", f.len(), start.elapsed());
        assert!(f.iter().all(|x| x.kind == "global" && !x.group_id.is_empty()));
    }
}
