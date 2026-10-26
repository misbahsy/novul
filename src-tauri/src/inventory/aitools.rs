use crate::model::PackageKey;
use crate::scan::{fix, osv};
use crate::store::FindingInput;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

const CMD_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const CHUNK: usize = 16 << 20;
const OVERLAP: usize = 512;
const BUN_REPO: &str = "oven-sh/bun";

/// A tool and where its advisories live. Cursor CLI and LM Studio publish no advisory feed
/// (no OSV package, no GitHub advisories), so they are not probed.
struct Tool {
    name: &'static str,
    bins: &'static [&'static str],
    /// OSV package (ecosystem, name)
    osv: Option<(&'static str, &'static str)>,
    /// GitHub repo with published security advisories, and the package names they use for this tool
    github: Option<(&'static str, &'static [&'static str])>,
}

const TOOLS: [Tool; 5] = [
    Tool {
        name: "Claude Code",
        bins: &["claude"],
        osv: Some(("npm", "@anthropic-ai/claude-code")),
        github: Some(("anthropics/claude-code", &["@anthropic-ai/claude-code"])),
    },
    Tool { name: "Codex", bins: &["codex"], osv: Some(("npm", "@openai/codex")), github: Some(("openai/codex", &["@openai/codex"])) },
    Tool {
        name: "OpenCode",
        bins: &["opencode"],
        osv: Some(("npm", "opencode-ai")),
        github: Some(("anomalyco/opencode", &["opencode-ai", "opencode"])),
    },
    Tool { name: "pi", bins: &["pi"], osv: None, github: Some(("badlogic/pi-mono", &["@mariozechner/pi-coding-agent"])) },
    Tool {
        name: "Ollama",
        bins: &["ollama"],
        osv: Some(("Go", "github.com/ollama/ollama")),
        github: Some(("ollama/ollama", &["github.com/ollama/ollama", "ollama"])),
    },
];

struct Install {
    tool: &'static Tool,
    /// Path shown to the user (the binary on PATH, or the file under claude/versions)
    path: PathBuf,
    real: PathBuf,
    version: String,
    active: bool,
    /// Bun version embedded in the binary
    bun: Option<String>,
    /// Rust crates named in the binary's panic-location strings
    crates: Vec<(String, String)>,
}

/// What was read from a binary, keyed by path and valid while (size, mtime) are unchanged,
/// so a scan doesn't re-read hundreds of MB of unchanged executables.
#[derive(Default, Serialize, Deserialize)]
pub struct BinCache {
    bins: HashMap<String, BinEntry>,
}

#[derive(Serialize, Deserialize)]
struct BinEntry {
    size: u64,
    mtime_ns: u128,
    bun: Option<String>,
    crates: Vec<(String, String)>,
}

impl BinCache {
    pub fn load(json: Option<String>) -> BinCache {
        json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
    }

    pub fn dump(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Cached result for the binary if it is unchanged, else `read` it and remember the answer.
    fn get(&mut self, path: &Path, seen: &mut HashSet<String>, read: impl FnOnce(&Path) -> (Option<String>, Vec<(String, String)>)) -> (Option<String>, Vec<(String, String)>) {
        let key = path.to_string_lossy().into_owned();
        seen.insert(key.clone());
        let stamp = std::fs::metadata(path).ok().and_then(|m| {
            let ns = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos();
            Some((m.len(), ns))
        });
        if let (Some((size, mtime_ns)), Some(e)) = (stamp, self.bins.get(&key)) {
            if e.size == size && e.mtime_ns == mtime_ns {
                return (e.bun.clone(), e.crates.clone());
            }
        }
        let (bun, crates) = read(path);
        if let Some((size, mtime_ns)) = stamp {
            self.bins.insert(key, BinEntry { size, mtime_ns, bun: bun.clone(), crates: crates.clone() });
        }
        (bun, crates)
    }

    fn retain(&mut self, seen: &HashSet<String>) {
        self.bins.retain(|k, _| seen.contains(k));
    }
}

/// An advisory for one package version, from any source.
#[derive(Debug, Clone)]
struct Adv {
    id: String,
    /// id plus aliases, used to merge the same advisory from OSV and GitHub
    ids: Vec<String>,
    summary: String,
    score: Option<f32>,
    fixed: Option<String>,
    url: String,
}

/// AI coding tools and model runners (Claude Code, Codex, OpenCode, pi, Ollama) plus runtimes
/// bundled inside them: the Bun inside Claude Code binaries and the Rust crates inside Codex.
/// kind = "tool"; project_name "AI tools"; project_path = the binary path.
///
/// Advisories come from OSV (npm, Go, crates.io) and from each project's GitHub security
/// advisories, because OSV lacks Claude Code's and Bun's. A failed lookup fails the whole call
/// so the caller keeps the previous results.
pub async fn tool_findings(client: &reqwest::Client, cache: &mut BinCache) -> Result<Vec<FindingInput>, String> {
    let installs = detect(cache).await;
    if installs.is_empty() {
        return Ok(vec![]);
    }

    let mut keys: Vec<PackageKey> = Vec::new();
    for i in &installs {
        if let Some((eco, name)) = i.tool.osv {
            keys.push(key(eco, name, &i.version));
        }
        if let Some(b) = &i.bun {
            keys.push(key("npm", "bun", b));
        }
        keys.extend(i.crates.iter().map(|(n, v)| key("crates.io", n, v)));
    }
    let ids = osv::querybatch(client, &keys).await?;
    let records = fetch_osv_records(client, &ids).await?;

    let mut repos: BTreeSet<&str> = installs.iter().filter_map(|i| i.tool.github.map(|g| g.0)).collect();
    if installs.iter().any(|i| i.bun.is_some()) {
        repos.insert(BUN_REPO);
    }
    let github = fetch_github(client, repos).await?;

    let osv_advs = |k: &PackageKey| -> Vec<Adv> {
        let returned: HashSet<String> = ids.get(k).into_iter().flatten().cloned().collect();
        ids.get(k)
            .into_iter()
            .flatten()
            .filter_map(|id| osv_adv(records.get(id)?, &k.ecosystem, &k.name, &k.version, &returned))
            .collect()
    };

    let null = Value::Null;
    let mut out: Vec<FindingInput> = Vec::new();
    let mut add = |f: FindingInput| {
        if !out.iter().any(|o| o.project_path == f.project_path && o.group_id == f.group_id) {
            out.push(f);
        }
    };
    for i in &installs {
        let mut own = Vec::new();
        if let Some((eco, name)) = i.tool.osv {
            own.extend(osv_advs(&key(eco, name, &i.version)));
        }
        if let Some((repo, names)) = i.tool.github {
            own.extend(github_advs(github.get(repo).unwrap_or(&null), names, &i.version));
        }
        for a in dedupe(own) {
            add(finding(i, None, &a));
        }
        if let Some(b) = &i.bun {
            let mut advs = osv_advs(&key("npm", "bun", b));
            advs.extend(github_advs(github.get(BUN_REPO).unwrap_or(&null), &["bun"], b));
            for a in dedupe(advs) {
                add(finding(i, Some(("Bun", b)), &a));
            }
        }
        for (n, v) in &i.crates {
            for a in dedupe(osv_advs(&key("crates.io", n, v))) {
                add(finding(i, Some((n, v)), &a));
            }
        }
    }
    Ok(out)
}

fn key(ecosystem: &str, name: &str, version: &str) -> PackageKey {
    PackageKey { ecosystem: ecosystem.into(), name: name.into(), version: version.into() }
}

async fn fetch_osv_records(client: &reqwest::Client, ids: &HashMap<PackageKey, Vec<String>>) -> Result<HashMap<String, Value>, String> {
    let unique: BTreeSet<&String> = ids.values().flatten().collect();
    let mut set = tokio::task::JoinSet::new();
    for id in unique {
        let (client, id) = (client.clone(), id.clone());
        set.spawn(async move {
            let rec = get_json(&client, &format!("https://api.osv.dev/v1/vulns/{id}"), false).await;
            (id, rec)
        });
    }
    let mut out = HashMap::new();
    while let Some(joined) = set.join_next().await {
        let (id, rec) = joined.map_err(|e| e.to_string())?;
        out.insert(id, rec?);
    }
    Ok(out)
}

async fn fetch_github(client: &reqwest::Client, repos: BTreeSet<&str>) -> Result<HashMap<String, Value>, String> {
    let mut set = tokio::task::JoinSet::new();
    for repo in repos {
        let (client, repo) = (client.clone(), repo.to_string());
        set.spawn(async move {
            let list = get_json(&client, &format!("https://api.github.com/repos/{repo}/security-advisories?per_page=100"), true).await;
            (repo, list)
        });
    }
    let mut out = HashMap::new();
    while let Some(joined) = set.join_next().await {
        let (repo, list) = joined.map_err(|e| e.to_string())?;
        out.insert(repo, list?);
    }
    Ok(out)
}

async fn get_json(client: &reqwest::Client, url: &str, github: bool) -> Result<Value, String> {
    let mut req = client.get(url).timeout(HTTP_TIMEOUT).header("User-Agent", "NoVul");
    if github {
        req = req.header("Accept", "application/vnd.github+json");
    }
    let resp = req.send().await.map_err(|e| format!("{url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("{url}: HTTP {}", resp.status()));
    }
    resp.json().await.map_err(|e| format!("{url}: {e}"))
}

// ---- detection ----

async fn detect(cache: &mut BinCache) -> Vec<Install> {
    let home = dirs::home_dir().unwrap_or_default();
    let mut installs: Vec<Install> = Vec::new();
    for tool in &TOOLS {
        let Some(path) = tool.bins.iter().find_map(|b| find_bin(b, &home)) else { continue };
        let Ok(real) = path.canonicalize() else { continue };
        let Some(version) = run_version(&path).await else { continue };
        let mut found = vec![Install { tool, path, real, version, active: true, bun: None, crates: vec![] }];
        if tool.name == "Claude Code" {
            found = claude_versions(&home, found.remove(0));
        }
        installs.extend(found);
    }
    let mut taken = std::mem::take(cache);
    let Ok((installs, taken)) = tokio::task::spawn_blocking(move || {
        let mut seen = HashSet::new();
        for i in &mut installs {
            match i.tool.name {
                "Claude Code" => i.bun = taken.get(&i.real, &mut seen, |p| (bun_version_in_file(p), vec![])).0,
                "Codex" => {
                    if let Some(bin) = codex_native(&i.real) {
                        i.crates = taken.get(&bin, &mut seen, |p| (None, crates_in_file(p))).1;
                    }
                }
                _ => {}
            }
        }
        taken.retain(&seen);
        (installs, taken)
    })
    .await
    else {
        return vec![];
    };
    *cache = taken;
    installs
}

/// Every file under ~/.local/share/claude/versions/ is an installed version; the active one is the
/// binary on PATH. When PATH's claude is not in that directory (e.g. an npm install) it stays as is.
fn claude_versions(home: &Path, active: Install) -> Vec<Install> {
    let Ok(entries) = std::fs::read_dir(home.join(".local/share/claude/versions")) else { return vec![active] };
    let mut out: Vec<Install> = entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let real = path.canonicalize().ok()?;
            let version = parse_version_output(&e.file_name().to_string_lossy())?;
            real.is_file().then(|| Install { tool: active.tool, active: real == active.real, path, real, version, bun: None, crates: vec![] })
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    if !out.iter().any(|i| i.active) {
        out.push(active);
    }
    out
}

fn search_path(home: &Path) -> String {
    let extra = [".local/bin", ".bun/bin", ".opencode/bin", ".npm-global/bin"].map(|d| home.join(d).to_string_lossy().into_owned());
    // Finder-launched apps have a minimal PATH
    format!("{}:{}:/opt/homebrew/bin:/usr/local/bin", std::env::var("PATH").unwrap_or_default(), extra.join(":"))
}

fn find_bin(name: &str, home: &Path) -> Option<PathBuf> {
    search_path(home).split(':').filter(|d| !d.is_empty()).map(|d| Path::new(d).join(name)).find(|p| p.is_file())
}

async fn run_version(bin: &Path) -> Option<String> {
    let home = dirs::home_dir().unwrap_or_default();
    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg("--version").env("PATH", search_path(&home)).stdin(Stdio::null()).kill_on_drop(true);
    let out = tokio::time::timeout(CMD_TIMEOUT, cmd.output()).await.ok()?.ok()?;
    parse_version_output(&format!("{} {}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// First x.y.z token of `--version` output: "2.1.299 (Claude Code)", "codex-cli 0.160.0",
/// "ollama version is 0.33.0" (which may be preceded by a "could not connect" warning).
fn parse_version_output(s: &str) -> Option<String> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+'))
        .map(|t| t.trim_start_matches('v').trim_end_matches('.'))
        .find(|t| is_semver_like(t))
        .map(String::from)
}

fn is_semver_like(t: &str) -> bool {
    let core = t.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The Rust executable behind a Codex install: the npm package ships it under
/// node_modules/@openai/codex-<platform>/vendor/<triple>/bin/codex behind a JS launcher.
fn codex_native(real: &Path) -> Option<PathBuf> {
    if real.extension().is_none_or(|e| e != "js") {
        return real.is_file().then(|| real.to_path_buf());
    }
    let pkg = real.parent()?.parent()?;
    for platform in std::fs::read_dir(pkg.join("node_modules/@openai")).ok()?.flatten() {
        if !platform.file_name().to_string_lossy().starts_with("codex-") {
            continue;
        }
        for triple in std::fs::read_dir(platform.path().join("vendor")).ok()?.flatten() {
            let bin = triple.path().join("bin/codex");
            if bin.is_file() {
                return Some(bin);
            }
        }
    }
    None
}

// ---- reading binaries ----

/// Feeds a file to `f` in chunks that overlap, so a match straddling a chunk boundary is seen whole.
fn scan_file(path: &Path, chunk: usize, overlap: usize, mut f: impl FnMut(&[u8])) {
    let Ok(mut file) = std::fs::File::open(path) else { return };
    let mut buf = vec![0u8; chunk + overlap];
    let mut kept = 0;
    loop {
        let mut n = 0;
        while n < chunk {
            match file.read(&mut buf[kept + n..kept + chunk]) {
                Ok(0) | Err(_) => break,
                Ok(r) => n += r,
            }
        }
        if n == 0 {
            return;
        }
        f(&buf[..kept + n]);
        if n < chunk {
            return;
        }
        let keep = overlap.min(kept + n);
        buf.copy_within(kept + n - keep..kept + n, 0);
        kept = keep;
    }
}

fn find_all<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let mut from = 0;
    std::iter::from_fn(move || {
        while let Some(off) = hay.get(from..)?.iter().position(|&b| b == needle[0]) {
            let at = from + off;
            from = at + 1;
            if hay[at..].starts_with(needle) {
                return Some(at);
            }
        }
        None
    })
}

/// Versions from every "Bun v1.x.y" string in the bytes.
fn bun_versions_in(bytes: &[u8]) -> Vec<String> {
    find_all(bytes, b"Bun v1.")
        .filter_map(|at| {
            let rest = &bytes[at + 5..];
            let end = rest.iter().position(|b| !(b.is_ascii_digit() || *b == b'.')).unwrap_or(rest.len());
            let v = std::str::from_utf8(&rest[..end]).ok()?.trim_end_matches('.');
            is_semver_like(v).then(|| v.to_string())
        })
        .collect()
}

/// The embedded Bun version: the most frequent "Bun v1.x.y" string in the executable.
fn bun_version_in_file(path: &Path) -> Option<String> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    scan_file(path, CHUNK, OVERLAP, |b| {
        for v in bun_versions_in(b) {
            *counts.entry(v).or_default() += 1;
        }
    });
    counts.into_iter().max_by_key(|(v, n)| (*n, v.clone())).map(|(v, _)| v)
}

/// Cargo leaves `<registry>/<crate>-<version>/src/...` paths in panic messages, which names the
/// exact crates compiled into a binary even without cargo-auditable data.
fn crates_in_bytes(bytes: &[u8]) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for needle in [&b"index.crates.io-"[..], &b"registry/src/github.com-"[..]] {
        for at in find_all(bytes, needle) {
            let rest = &bytes[at + needle.len()..];
            let Some(slash) = rest.iter().take(24).position(|b| *b == b'/') else { continue };
            let rest = &rest[slash + 1..];
            let end = rest.iter().position(|b| !(b.is_ascii_alphanumeric() || b"_.+-".contains(b))).unwrap_or(rest.len());
            if rest.get(end) != Some(&b'/') {
                continue;
            }
            if let Some((n, v)) = std::str::from_utf8(&rest[..end]).ok().and_then(split_crate_dir) {
                out.insert((n.to_string(), v.to_string()));
            }
        }
    }
    out
}

fn crates_in_file(path: &Path) -> Vec<(String, String)> {
    let mut all = BTreeSet::new();
    scan_file(path, CHUNK, OVERLAP, |b| all.extend(crates_in_bytes(b)));
    all.into_iter().collect()
}

/// "rustls-webpki-0.103.15" -> ("rustls-webpki", "0.103.15"); the version starts at the first
/// "-" followed by x.y.z, so crate names with digits ("h2", "base64") and pre-releases work.
fn split_crate_dir(s: &str) -> Option<(&str, &str)> {
    s.match_indices('-').find_map(|(i, _)| {
        let rest = &s[i + 1..];
        (i > 0 && rest.starts_with(|c: char| c.is_ascii_digit()) && is_semver_like(rest)).then(|| (&s[..i], rest))
    })
}

// ---- advisories ----

fn severity_score(s: &str) -> Option<f32> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Some(9.5),
        "high" => Some(8.0),
        "moderate" | "medium" => Some(5.5),
        "low" => Some(2.5),
        _ => None,
    }
}

fn first_line(s: &str) -> String {
    s.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").chars().take(200).collect()
}

/// An OSV record as an advisory for this package version. Dropped: withdrawn records,
/// informational RUSTSEC notices (unmaintained, unsound), and Go vulndb entries that claim every
/// version is affected while their GHSA twin (which has the real range) did not match.
fn osv_adv(rec: &Value, ecosystem: &str, name: &str, version: &str, returned: &HashSet<String>) -> Option<Adv> {
    if rec.get("withdrawn").is_some() {
        return None;
    }
    let affected = rec.get("affected").cloned().unwrap_or(Value::Null);
    let entries = affected.as_array()?;
    if entries.iter().any(|a| a.pointer("/database_specific/informational").is_some_and(|i| !i.is_null())) {
        return None;
    }
    let id = rec["id"].as_str()?.to_string();
    let mut ids = vec![id.clone()];
    ids.extend(rec["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).map(String::from));
    if id.starts_with("GO-") {
        let has_end = |a: &Value| {
            a.get("ranges").and_then(|r| r.as_array()).into_iter().flatten().any(|r| {
                r.get("events").and_then(|e| e.as_array()).into_iter().flatten().any(|e| e.get("fixed").or(e.get("last_affected")).is_some())
            })
        };
        let twin_missing = ids.iter().any(|i| i.starts_with("GHSA-") && !returned.contains(i));
        if !entries.iter().any(has_end) && twin_missing {
            return None;
        }
    }
    let summary = rec["summary"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from).unwrap_or_else(|| first_line(rec["details"].as_str().unwrap_or("")));
    Some(Adv {
        score: rec.pointer("/database_specific/severity").and_then(|s| s.as_str()).and_then(severity_score),
        fixed: fix::fixed_version_for_package(ecosystem, name, version, &affected),
        url: format!("https://osv.dev/vulnerability/{id}"),
        id: fix::canonical_id(&[id], &ids),
        ids,
        summary,
    })
}

/// Published (non-withdrawn) GitHub repo advisories whose package is one of `names` and whose
/// vulnerable range contains `version`.
fn github_advs(list: &Value, names: &[&str], version: &str) -> Vec<Adv> {
    let mut out = Vec::new();
    for a in list.as_array().into_iter().flatten() {
        if !a["withdrawn_at"].is_null() {
            continue;
        }
        let hit = a["vulnerabilities"].as_array().into_iter().flatten().find(|v| {
            v.pointer("/package/name").and_then(|n| n.as_str()).is_some_and(|n| names.contains(&n))
                && v["vulnerable_version_range"].as_str().is_some_and(|r| in_range(r, version))
        });
        let (Some(v), Some(ghsa)) = (hit, a["ghsa_id"].as_str()) else { continue };
        let mut ids = vec![ghsa.to_string()];
        ids.extend(a["cve_id"].as_str().map(String::from));
        out.push(Adv {
            score: a.pointer("/cvss/score").and_then(|s| s.as_f64()).map(|s| s as f32).or_else(|| a["severity"].as_str().and_then(severity_score)),
            fixed: v["patched_versions"].as_str().and_then(|p| p.split([' ', ',']).map(|t| t.trim_start_matches('v')).find(|t| is_semver_like(t))).map(String::from),
            url: a["html_url"].as_str().unwrap_or_default().to_string(),
            id: fix::canonical_id(&ids, &ids),
            summary: a["summary"].as_str().unwrap_or_default().trim().to_string(),
            ids,
        });
    }
    out
}

/// Evaluates GitHub's `vulnerable_version_range` forms: ">= 1.3.14, < 1.4.4", "<v1.0.93",
/// "> 0.2.116 < 1.0.24" and "0.2.0 <= 0.38.0" (a bare leading version means ">=").
fn in_range(range: &str, version: &str) -> bool {
    let mut toks: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_is_op = false;
    for c in range.chars().chain(std::iter::once(' ')) {
        let is_op = matches!(c, '<' | '>' | '=');
        if c.is_whitespace() || c == ',' || (!cur.is_empty() && is_op != cur_is_op) {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
        }
        if !(c.is_whitespace() || c == ',') {
            cur.push(c);
            cur_is_op = is_op;
        }
    }
    let mut ok = false;
    let mut op: Option<String> = None;
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        if t.starts_with(['<', '>', '=']) {
            op = Some(t.clone());
        } else {
            let o = op.take().unwrap_or_else(|| if i == 0 && toks.len() > 1 { ">=".into() } else { "=".into() });
            let Some(ord) = fix::compare_versions("npm", version, t) else { return false };
            let holds = match o.as_str() {
                "<" => ord == Ordering::Less,
                "<=" => ord != Ordering::Greater,
                ">" => ord == Ordering::Greater,
                ">=" => ord != Ordering::Less,
                "=" | "==" => ord == Ordering::Equal,
                _ => return false,
            };
            if !holds {
                return false;
            }
            ok = true;
        }
        i += 1;
    }
    ok
}

/// Keeps the first advisory of each group of records that share any id.
fn dedupe(advs: Vec<Adv>) -> Vec<Adv> {
    let mut out: Vec<Adv> = Vec::new();
    for a in advs {
        match out.iter_mut().find(|o| o.ids.iter().any(|i| a.ids.contains(i))) {
            Some(o) => {
                if o.fixed.is_none() {
                    o.fixed = a.fixed;
                }
                if o.score.is_none() {
                    o.score = a.score;
                }
            }
            None => out.push(a),
        }
    }
    out
}

// ---- findings ----

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The tool's own updater, by install method.
fn update_command(i: &Install) -> Option<String> {
    let p = i.real.to_string_lossy();
    let npm = p.contains("/node_modules/");
    let brew = p.contains("/Cellar/") || p.contains("/Caskroom/");
    let cmd = match (i.tool.name, npm, brew) {
        ("Claude Code", true, _) => "npm install -g @anthropic-ai/claude-code@latest",
        ("Claude Code", ..) => "claude update",
        ("Codex", true, _) => "npm install -g @openai/codex@latest",
        ("Codex", _, true) => "brew upgrade codex",
        ("Codex", ..) => "codex update",
        ("OpenCode", true, _) => "npm install -g opencode-ai@latest",
        ("OpenCode", _, true) => "brew upgrade opencode",
        ("OpenCode", ..) => "opencode upgrade",
        ("pi", true, _) => "npm install -g @mariozechner/pi-coding-agent@latest",
        ("Ollama", _, true) => "brew upgrade ollama",
        _ => return None,
    };
    Some(cmd.into())
}

/// `bundled` is the runtime or crate the advisory is about, when it is not the tool itself.
fn finding(i: &Install, bundled: Option<(&str, &str)>, a: &Adv) -> FindingInput {
    let unused = if i.active { "" } else { "Unused version on disk. " };
    let (summary, fixed_version) = match bundled {
        None => (format!("{unused}{}", a.summary), a.fixed.clone()),
        Some((n, v)) => {
            let fixed = a.fixed.as_ref().map(|f| format!(" (fixed in {n} {f})")).unwrap_or_default();
            (format!("{unused}Bundled {n} {v}: {}{fixed}", a.summary), None)
        }
    };
    FindingInput {
        kind: "tool",
        group_id: a.id.clone(),
        project_name: "AI tools".into(),
        project_path: i.path.to_string_lossy().into_owned(),
        ecosystem: "AI tool".into(),
        name: i.tool.name.into(),
        installed_version: i.version.clone(),
        fixed_version,
        direct: None,
        dev: false,
        inferred: false,
        fix_command: if i.active { update_command(i) } else { Some(format!("rm {}", shell_quote(&i.path.to_string_lossy()))) },
        aliases: a.ids.iter().filter(|x| **x != a.id).cloned().collect(),
        summary,
        score: a.score,
        malicious: false,
        url: a.url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/aitools/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    fn json(name: &str) -> Value {
        serde_json::from_str(&fx(name)).unwrap()
    }
    fn bytes(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/aitools/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }
    fn ids(a: &[Adv]) -> Vec<&str> {
        let mut v: Vec<&str> = a.iter().map(|a| a.id.as_str()).collect();
        v.sort();
        v
    }

    #[test]
    fn version_output_of_real_tools() {
        assert_eq!(parse_version_output(&fx("claude-version.txt")).as_deref(), Some("2.1.299"));
        assert_eq!(parse_version_output(&fx("codex-version.txt")).as_deref(), Some("0.160.0"));
        assert_eq!(parse_version_output(&fx("ollama-version.txt")).as_deref(), Some("0.33.0"));
        let warned = "Warning: could not connect to a running Ollama instance\nWarning: client version is 0.33.0\n";
        assert_eq!(parse_version_output(warned).as_deref(), Some("0.33.0"));
        assert_eq!(parse_version_output("v1.2.3-beta.1\n").as_deref(), Some("1.2.3-beta.1"));
        assert_eq!(parse_version_output("CLI commit: 07b7252"), None);
    }

    #[test]
    fn bun_version_inside_a_real_claude_binary_slice() {
        let b = bytes("claude-bun-snippet.bin");
        assert_eq!(bun_versions_in(&b), ["1.4.3"]);
        assert_eq!(bun_versions_in(b"Bun v1.4.3.\0Bun v1.x\0Bun v12"), ["1.4.3"]);
        assert_eq!(bun_versions_in(b"xx Bun v1.2.10 (macOS arm64)"), ["1.2.10"]);
        assert!(bun_versions_in(b"Bun v1.\0 Bun v1.4").is_empty());
    }

    #[test]
    fn match_across_chunk_boundary_is_found_once_per_view() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bin");
        let mut data = vec![b'x'; 100];
        data.extend_from_slice(b"Bun v1.4.3 (macOS)");
        data.extend(vec![b'y'; 100]);
        // chunk boundary falls inside the needle
        for chunk in [101, 105, 110, 64, 1000] {
            std::fs::write(&path, &data).unwrap();
            let mut found = Vec::new();
            scan_file(&path, chunk, 16, |b| found.extend(bun_versions_in(b)));
            assert!(found.iter().all(|v| v == "1.4.3") && !found.is_empty(), "chunk {chunk}: {found:?}");
        }
        std::fs::write(&path, b"nothing here").unwrap();
        assert_eq!(bun_version_in_file(&path), None);
        std::fs::write(&path, &data).unwrap();
        assert_eq!(bun_version_in_file(&path).as_deref(), Some("1.4.3"));
    }

    #[test]
    fn crates_named_in_real_codex_binary_slice() {
        let found = crates_in_bytes(&bytes("codex-crates-snippet.bin"));
        assert!(found.contains(&("rustls-webpki".to_string(), "0.103.15".to_string())), "{found:?}");
        assert!(found.iter().all(|(n, v)| !n.is_empty() && is_semver_like(v.split(['-', '+']).next().unwrap())));
        assert_eq!(split_crate_dir("h2-0.4.5"), Some(("h2", "0.4.5")));
        assert_eq!(split_crate_dir("base64-0.22.1"), Some(("base64", "0.22.1")));
        assert_eq!(split_crate_dir("foo-bar-1.0.0-rc.1"), Some(("foo-bar", "1.0.0-rc.1")));
        assert_eq!(split_crate_dir("noversion"), None);
        let old = b"/.cargo/registry/src/github.com-1ecc6299db9ec823/serde-1.0.150/src/lib.rs";
        assert!(crates_in_bytes(old).contains(&("serde".to_string(), "1.0.150".to_string())));
    }

    #[test]
    fn range_forms_used_by_github() {
        assert!(in_range(">= 1.3.14, < 1.4.4", "1.4.3"));
        assert!(!in_range(">= 1.3.14, < 1.4.4", "1.4.4"));
        assert!(!in_range(">= 1.3.14, < 1.4.4", "1.3.13"));
        assert!(in_range("< v2.0.57", "2.0.56"));
        assert!(in_range("<v1.0.93", "1.0.92"));
        assert!(in_range("> 0.2.116 < 1.0.24", "1.0.0"));
        assert!(!in_range("> 0.2.116 < 1.0.24", "0.2.116"));
        assert!(in_range("0.2.0 <= 0.38.0", "0.38.0"));
        assert!(!in_range("0.2.0 <= 0.38.0", "0.1.9"));
        assert!(!in_range("", "1.0.0"));
        assert!(!in_range("< banana", "1.0.0"));
    }

    #[test]
    fn bun_advisories_from_github_match_the_bundled_version() {
        let list = json("github-bun-advisories.json");
        let hit = github_advs(&list, &["bun"], "1.4.3");
        assert_eq!(ids(&hit), ["CVE-2026-111497", "GHSA-26q8-h657-pf84", "GHSA-cf8x-9m69-3gg3"]);
        assert!(hit.iter().all(|a| a.fixed.as_deref() == Some("1.4.4") && a.score == Some(8.0)));
        assert_eq!(hit.iter().find(|a| a.id == "CVE-2026-111497").unwrap().ids, ["GHSA-663w-cv8g-jj2p", "CVE-2026-111497"]);
        // 1.4.0 is also hit; 1.4.4 and a package name that is not bun are not
        assert_eq!(github_advs(&list, &["bun"], "1.4.0").len(), 3);
        assert!(github_advs(&list, &["bun"], "1.4.4").is_empty());
        assert!(github_advs(&list, &["other"], "1.4.3").is_empty());
        // only the eMudhra advisory reaches back before 1.0.21
        assert_eq!(ids(&github_advs(&list, &["bun"], "1.0.20")), ["GHSA-26q8-h657-pf84"]);
    }

    #[test]
    fn claude_code_versions_against_github_advisories() {
        let list = json("github-claude-advisories.json");
        let names = ["@anthropic-ai/claude-code"];
        assert!(github_advs(&list, &names, "2.1.299").is_empty());
        let old = github_advs(&list, &names, "2.1.226");
        assert_eq!(ids(&old), ["CVE-2026-103012"]);
        assert_eq!((old[0].fixed.as_deref(), old[0].score), (Some("2.1.260"), Some(2.5)));
        // "Claude Desktop" advisories in the same repo are not Claude Code
        assert!(github_advs(&list, &names, "1.1.4000").iter().all(|a| a.id != "CVE-2026-88066"));
        // v-prefixed ranges and patched versions
        let ancient = github_advs(&list, &names, "1.0.50");
        assert!(ancient.iter().any(|a| a.id == "CVE-2025-59536" && a.fixed.as_deref() == Some("1.0.111")));
    }

    #[test]
    fn osv_record_becomes_an_advisory() {
        let rec = json("osv-RUSTSEC-2026-0382.json");
        let a = osv_adv(&rec, "crates.io", "rustls-webpki", "0.103.15", &HashSet::new()).unwrap();
        assert_eq!(a.id, "CVE-2026-111943");
        assert_eq!(a.fixed.as_deref(), Some("0.103.16"));
        assert_eq!(a.summary, "Certificate verification may accept distrusted intermediates");
        assert!(a.ids.contains(&"RUSTSEC-2026-0382".to_string()));
        assert_eq!(a.url, "https://osv.dev/vulnerability/RUSTSEC-2026-0382");

        let ghsa = json("osv-GHSA-vxw4-wv6m-9hhh.json");
        let g = osv_adv(&ghsa, "npm", "opencode-ai", "1.0.100", &HashSet::new()).unwrap();
        assert_eq!((g.id.as_str(), g.score, g.fixed.as_deref()), ("CVE-2026-22812", Some(8.0), Some("1.0.216")));
    }

    #[test]
    fn informational_rustsec_notices_are_not_advisories() {
        let rec = json("osv-RUSTSEC-2024-0449.json");
        assert!(osv_adv(&rec, "crates.io", "unsafe-libyaml", "0.2.11", &HashSet::new()).is_none());
    }

    #[test]
    fn go_vulndb_entries_without_a_range_end_are_dropped_when_the_ghsa_twin_did_not_match() {
        // OSV's answer for ollama 0.33.0: GO-* entries say "introduced 0" with no fix, while their
        // GHSA twins end at last_affected <= 0.20.2
        let q = json("osv-ollama-query.json");
        let vulns = q["vulns"].as_array().unwrap();
        assert!(vulns.len() >= 8);
        let returned: HashSet<String> = vulns.iter().map(|v| v["id"].as_str().unwrap().to_string()).collect();
        for v in vulns {
            assert!(osv_adv(v, "Go", "github.com/ollama/ollama", "0.33.0", &returned).is_none(), "{}", v["id"]);
        }
        // when the GHSA twin matched too, the entry stays
        let go = vulns[0].clone();
        let mut both = returned.clone();
        both.extend(go["aliases"].as_array().unwrap().iter().filter_map(|a| a.as_str()).map(String::from));
        assert!(osv_adv(&go, "Go", "github.com/ollama/ollama", "0.33.0", &both).is_some());
    }

    #[test]
    fn same_advisory_from_osv_and_github_is_one_finding() {
        let osv = osv_adv(&json("osv-GHSA-vxw4-wv6m-9hhh.json"), "npm", "opencode-ai", "1.0.100", &HashSet::new()).unwrap();
        let gh = github_advs(&json("github-opencode-advisories.json"), &["opencode-ai", "opencode"], "1.0.100");
        assert_eq!(ids(&gh), ["CVE-2026-22812", "CVE-2026-22813"]);
        let merged = dedupe([vec![osv], gh].concat());
        assert_eq!(ids(&merged), ["CVE-2026-22812", "CVE-2026-22813"]);
    }

    fn install(name: &str, real: &str, active: bool) -> Install {
        Install {
            tool: TOOLS.iter().find(|t| t.name == name).unwrap(),
            path: PathBuf::from(real),
            real: PathBuf::from(real),
            version: "2.1.226".into(),
            active,
            bun: None,
            crates: vec![],
        }
    }

    #[test]
    fn bundled_findings_describe_the_runtime_and_use_the_tool_updater() {
        let a = github_advs(&json("github-bun-advisories.json"), &["bun"], "1.4.3").remove(0);
        let i = install("Claude Code", "/Users/me/.local/share/claude/versions/2.1.299", true);
        let f = finding(&i, Some(("Bun", "1.4.3")), &a);
        assert_eq!((f.kind, f.project_name.as_str(), f.ecosystem.as_str(), f.name.as_str()), ("tool", "AI tools", "AI tool", "Claude Code"));
        assert!(f.summary.starts_with("Bundled Bun 1.4.3: "), "{}", f.summary);
        assert!(f.summary.ends_with("(fixed in Bun 1.4.4)"), "{}", f.summary);
        assert_eq!(f.fixed_version, None);
        assert_eq!(f.fix_command.as_deref(), Some("claude update"));
        assert_eq!(f.project_path, "/Users/me/.local/share/claude/versions/2.1.299");
    }

    #[test]
    fn unused_versions_get_a_delete_command_and_install_methods_pick_the_updater() {
        let a = Adv { id: "CVE-1".into(), ids: vec!["CVE-1".into()], summary: "s".into(), score: None, fixed: Some("2.1.260".into()), url: String::new() };
        let old = install("Claude Code", "/Users/me/it's/versions/2.1.226", false);
        let f = finding(&old, None, &a);
        assert!(f.summary.starts_with("Unused version on disk. "));
        assert_eq!(f.fix_command.as_deref(), Some(r"rm '/Users/me/it'\''s/versions/2.1.226'"));
        assert_eq!(f.fixed_version.as_deref(), Some("2.1.260"));

        let cmd = |n, p| update_command(&install(n, p, true));
        assert_eq!(cmd("Codex", "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js").as_deref(), Some("npm install -g @openai/codex@latest"));
        assert_eq!(cmd("Codex", "/opt/homebrew/Caskroom/codex/1/codex").as_deref(), Some("brew upgrade codex"));
        assert_eq!(cmd("Ollama", "/opt/homebrew/Cellar/ollama/0.33.0/bin/ollama").as_deref(), Some("brew upgrade ollama"));
        assert_eq!(cmd("Ollama", "/Applications/Ollama.app/ollama"), None);
        assert_eq!(cmd("OpenCode", "/Users/me/.opencode/bin/opencode").as_deref(), Some("opencode upgrade"));
    }

    #[test]
    fn claude_versions_dir_marks_the_active_binary() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".local/share/claude/versions");
        std::fs::create_dir_all(&dir).unwrap();
        for v in ["2.1.226", "2.1.299"] {
            std::fs::write(dir.join(v), v).unwrap();
        }
        let real = dir.join("2.1.299").canonicalize().unwrap();
        let active = Install { real, version: "2.1.299".into(), ..install("Claude Code", "/x/claude", true) };
        let all = claude_versions(home.path(), active);
        let summary: Vec<(&str, bool)> = all.iter().map(|i| (i.version.as_str(), i.active)).collect();
        assert_eq!(summary, [("2.1.226", false), ("2.1.299", true)]);
    }

    #[tokio::test]
    #[ignore]
    async fn v2inv_live_tools() {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap();
        let start = std::time::Instant::now();
        let installs = detect(&mut BinCache::default()).await;
        for i in &installs {
            println!("{} {} active={} bun={:?} crates={} {}", i.tool.name, i.version, i.active, i.bun, i.crates.len(), i.path.display());
        }
        println!("detect {:?}", start.elapsed());
        let f = tool_findings(&client, &mut BinCache::default()).await.expect("tool findings");
        for x in &f {
            println!("{} {} {} score={:?} fixed={:?} | {}", x.name, x.installed_version, x.group_id, x.score, x.fixed_version, x.summary);
        }
        println!("{} findings in {:?}", f.len(), start.elapsed());
        assert!(f.iter().all(|x| x.kind == "tool" && !x.group_id.is_empty()));
    }

    #[test]
    fn bin_cache_rereads_only_changed_binaries_and_drops_vanished_ones() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, "one").unwrap();
        std::fs::write(&b, "two").unwrap();
        let mut cache = BinCache::default();
        let mut seen = HashSet::new();
        let reads = std::cell::Cell::new(0);
        let get = |cache: &mut BinCache, p: &Path, seen: &mut HashSet<String>| {
            cache.get(p, seen, |_| {
                reads.set(reads.get() + 1);
                (Some(format!("bun{}", reads.get())), vec![])
            })
        };
        assert_eq!(get(&mut cache, &a, &mut seen).0.as_deref(), Some("bun1"));
        get(&mut cache, &b, &mut seen);
        let mut cache = BinCache::load(Some(cache.dump()));
        assert_eq!(get(&mut cache, &a, &mut seen).0.as_deref(), Some("bun1"), "unchanged: cached answer");
        assert_eq!(reads.get(), 2);
        std::fs::write(&a, "longer content").unwrap();
        assert_eq!(get(&mut cache, &a, &mut seen).0.as_deref(), Some("bun3"), "size changed: read again");
        let only_a: HashSet<String> = [a.to_string_lossy().into_owned()].into();
        cache.retain(&only_a);
        assert_eq!(cache.bins.len(), 1);
    }
}
