// Owner: v2-secrets agent. (Named leaks.rs because the user's Claude settings deny reading *secret* paths.)
use crate::feeds::hibp::Breach;
use crate::model::FindingView;
use crate::store::FindingInput;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

const BATCH_TIMEOUT: Duration = Duration::from_secs(120);
const PARALLEL: usize = 2;
/// Changed folders per gitleaks process: gitleaks costs ~1 s to start under `taskpolicy -b`.
const BATCH: usize = 40;
const FILE_TIMEOUT: Duration = Duration::from_secs(60);
const BREACH_WINDOW_DAYS: i64 = 120;
const HINT: &str = "Move it to Keychain or 1Password and reference it from there";
const PROJECT_MARKERS: [&str; 6] = [".git", "package.json", "Cargo.toml", "pyproject.toml", "go.mod", "Gemfile"];
const HOME_FILES: [&str; 13] = [
    ".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".aws/credentials", ".npmrc", ".pypirc", ".netrc",
    ".docker/config.json", ".config/gh/hosts.yml", ".claude.json", ".cursor/mcp.json", ".codex/config.toml",
];

/// (rule id prefix, service, domain, rotation page)
const PROVIDERS: [(&str, &str, &str, &str); 15] = [
    ("aws-", "AWS", "aws.amazon.com", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    ("github-", "GitHub", "github.com", "https://github.com/settings/tokens"),
    ("gitlab-", "GitLab", "gitlab.com", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    ("railway-", "Railway", "railway.app", "https://railway.app/account/tokens"),
    ("openai-", "OpenAI", "openai.com", "https://platform.openai.com/api-keys"),
    ("anthropic-", "Anthropic", "anthropic.com", "https://console.anthropic.com/settings/keys"),
    ("slack-", "Slack", "slack.com", "https://api.slack.com/apps"),
    ("stripe-", "Stripe", "stripe.com", "https://dashboard.stripe.com/apikeys"),
    ("npm-", "npm", "npmjs.com", "https://www.npmjs.com/settings/~/tokens"),
    ("pypi-", "PyPI", "pypi.org", "https://pypi.org/manage/account/#api-tokens"),
    ("huggingface-", "Hugging Face", "huggingface.co", "https://huggingface.co/settings/tokens"),
    ("vercel-", "Vercel", "vercel.com", "https://vercel.com/account/tokens"),
    ("cloudflare-", "Cloudflare", "cloudflare.com", "https://dash.cloudflare.com/profile/api-tokens"),
    ("digitalocean-", "DigitalOcean", "digitalocean.com", "https://cloud.digitalocean.com/account/api/tokens"),
    ("heroku-", "Heroku", "heroku.com", "https://dashboard.heroku.com/account/applications"),
];

const NAMES: [(&str, &str); 8] = [
    ("aws-access-token", "AWS access key"),
    ("github-pat", "GitHub personal access token"),
    ("github-fine-grained-pat", "GitHub fine-grained token"),
    ("github-oauth", "GitHub OAuth token"),
    ("openai-api-key", "OpenAI API key"),
    ("anthropic-api-key", "Anthropic API key"),
    ("npm-access-token", "npm access token"),
    ("private-key", "Private key"),
];

#[derive(Deserialize)]
struct Leak {
    #[serde(rename = "RuleID")]
    rule: String,
    #[serde(rename = "StartLine")]
    line: u32,
    #[serde(rename = "File")]
    file: String,
}

/// Plaintext secrets in project folders and well-known credential files, via the gitleaks
/// sidecar with --redact. Never stores or returns a secret value. kind = "secret".
///
/// gitleaks runs per project folder (never over a whole root), at most `PARALLEL` at a time, and
/// only for folders whose change signature differs from `cache`. The result is the complete set
/// of open secret findings: fresh ones for rescanned folders and home files, plus `old` findings
/// of folders that were skipped or failed, so syncing it resolves only what a rescan superseded.
pub async fn secret_findings(
    gitleaks: &Path,
    folders: &[PathBuf],
    exclusions: &[String],
    breaches: &[Breach],
    cache: &mut Cache,
    old: &[FindingView],
    report: &dyn Fn(usize, usize),
) -> Result<Vec<FindingInput>, String> {
    scan(gitleaks, folders, dirs::home_dir(), exclusions, breaches, cache, old, report).await
}

/// Per-folder change signature: newest mtime/ctime (ns) of any entry, and the entry count.
type Sig = (u64, u64);

/// Folder -> signature at its last successful scan, valid for one gitleaks config and app version.
#[derive(Default, Serialize, Deserialize)]
pub struct Cache {
    cfg: String,
    dirs: BTreeMap<String, Sig>,
    /// Folders that failed in the last pass (kept findings, retried next time); not persisted.
    #[serde(skip)]
    pub errors: Vec<String>,
}

impl Cache {
    pub fn load(json: Option<String>) -> Cache {
        json.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
    }

    pub fn dump(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

fn stamp(m: &std::fs::Metadata) -> u64 {
    let ns = |s: i64, n: i64| (s.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(n as u64);
    ns(m.mtime(), m.mtime_nsec()).max(ns(m.ctime(), m.ctime_nsec()))
}

/// Same walk as the gitleaks config allows: hidden and ignored files included, excluded dir names skipped.
fn folder_sig(folder: &Path, exclusions: &[String]) -> Sig {
    let exclusions = exclusions.to_vec();
    let walk = ignore::WalkBuilder::new(folder)
        .hidden(false)
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .filter_entry(move |e| {
            e.depth() == 0
                || !e.file_type().is_some_and(|t| t.is_dir())
                || !exclusions.iter().any(|x| crate::engine::glob_match(x, &e.file_name().to_string_lossy()))
        })
        .build();
    let (mut newest, mut count) = (0, 0);
    for entry in walk.flatten() {
        if let Ok(m) = entry.metadata() {
            newest = newest.max(stamp(&m));
            count += 1;
        }
    }
    // `git add` changes whether a file counts as tracked, which changes its score
    if let Ok(m) = std::fs::metadata(folder.join(".git/index")) {
        newest = newest.max(stamp(&m));
    }
    (newest, count)
}

/// A directory to start gitleaks in, and path regexes (relative to it) that skip every sibling on
/// the way down to `folders`, so one process covers a whole batch without walking anything else.
fn batch_plan(folders: &[PathBuf]) -> (PathBuf, Vec<String>) {
    let mut base = folders[0].clone();
    if folders.len() == 1 {
        return (base, vec![]);
    }
    for f in &folders[1..] {
        while !f.starts_with(&base) {
            base.pop();
        }
    }
    let mut on_path: BTreeMap<PathBuf, BTreeSet<std::ffi::OsString>> = BTreeMap::new();
    for f in folders {
        let rel: Vec<_> = f.strip_prefix(&base).unwrap_or(f).components().collect();
        for i in 0..rel.len() {
            let dir: PathBuf = rel[..i].iter().collect();
            on_path.entry(dir).or_default().insert(rel[i].as_os_str().to_os_string());
        }
    }
    let literal = |s: &std::ffi::OsStr| regex_escape(&s.to_string_lossy()).replace(['\'', '\n', '\r'], ".");
    let mut skips = vec![];
    for (dir, keep) in &on_path {
        let names: Vec<String> = std::fs::read_dir(base.join(dir))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| !keep.contains(n))
            .map(|n| literal(&n))
            .collect();
        if names.is_empty() {
            continue;
        }
        let prefix = if dir.as_os_str().is_empty() { String::new() } else { format!("{}/", literal(dir.as_os_str())) };
        skips.push(format!("^{prefix}(?:{})(/|$)", names.join("|")));
    }
    (base, skips)
}

/// Scan one batch of folders with a single gitleaks process; leaks come back with absolute paths.
async fn scan_batch(gitleaks: PathBuf, exclusions: Vec<String>, folders: Vec<(PathBuf, Sig)>) -> (Vec<(PathBuf, Sig)>, Result<Vec<(PathBuf, Leak)>, String>) {
    let dirs: Vec<PathBuf> = folders.iter().map(|(f, _)| f.clone()).collect();
    let (base, skips) = tokio::task::spawn_blocking(move || batch_plan(&dirs)).await.unwrap_or_default();
    let config = config_with(&exclusions, &skips);
    let res = run_gitleaks(&gitleaks, &config, &base, ".", BATCH_TIMEOUT).await;
    (folders, res.map(|leaks| leaks.into_iter().map(|l| (base.join(&l.file), l)).collect()).map_err(|e| format!("{}: {e}", base.display())))
}

/// Folders worth scanning: the project folders the store knows plus root-level dirs holding a `.git`.
/// A folder inside another one is covered by it; a root that contains projects is not one itself.
pub fn project_folders(known: &[PathBuf], roots: &[PathBuf], exclusions: &[String]) -> Vec<PathBuf> {
    let skip = |name: &std::ffi::OsStr| exclusions.iter().any(|x| crate::engine::glob_match(x, &name.to_string_lossy()));
    let mut set: BTreeSet<PathBuf> = BTreeSet::new();
    for k in known {
        let inside = roots.iter().find_map(|r| k.strip_prefix(r).ok());
        if inside.is_some_and(|rel| !rel.components().any(|c| skip(c.as_os_str()))) && k.is_dir() {
            set.insert(k.clone());
        }
    }
    for root in roots {
        for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) && !skip(&e.file_name()) && e.path().join(".git").exists() {
                set.insert(e.path());
            }
        }
    }
    let all: Vec<PathBuf> = set.iter().cloned().collect();
    let tops: BTreeSet<&PathBuf> = all.iter().filter(|f| !(roots.contains(f) && all.iter().any(|o| o != *f && o.starts_with(f)))).collect();
    tops.iter().filter(|f| !f.ancestors().skip(1).any(|a| tops.contains(&a.to_path_buf()))).map(|f| (*f).clone()).collect()
}

fn as_input(f: &FindingView) -> FindingInput {
    FindingInput {
        kind: "secret",
        group_id: f.group_id.clone(),
        project_name: f.project_name.clone(),
        project_path: f.project_path.clone(),
        ecosystem: f.ecosystem.clone(),
        name: f.name.clone(),
        installed_version: f.installed_version.clone(),
        fixed_version: f.fixed_version.clone(),
        direct: f.direct,
        dev: f.dev,
        inferred: f.inferred,
        fix_command: f.fix_command.clone(),
        aliases: f.aliases.clone(),
        summary: f.summary.clone(),
        score: f.score,
        malicious: false,
        url: f.url.clone(),
    }
}

async fn scan(
    gitleaks: &Path,
    folders: &[PathBuf],
    home: Option<PathBuf>,
    exclusions: &[String],
    breaches: &[Breach],
    cache: &mut Cache,
    old: &[FindingView],
    report: &dyn Fn(usize, usize),
) -> Result<Vec<FindingInput>, String> {
    let config = config_toml(exclusions);
    let cfg = sha256_hex8(format!("{config}{}", env!("CARGO_PKG_VERSION")).as_bytes());
    if cache.cfg != cfg {
        *cache = Cache { cfg, ..Default::default() };
    }
    let mut hits: Vec<(Option<PathBuf>, PathBuf, Leak)> = vec![];
    let mut errors = vec![];
    let mut dirs: BTreeMap<String, Sig> = BTreeMap::new();
    let mut rescanned: HashSet<PathBuf> = HashSet::new();

    let total = folders.len();
    let sigs: Vec<Sig> = {
        let (folders, exclusions) = (folders.to_vec(), exclusions.to_vec());
        tokio::task::spawn_blocking(move || folders.iter().map(|f| folder_sig(f, &exclusions)).collect()).await.map_err(|e| e.to_string())?
    };
    let mut todo: Vec<(PathBuf, Sig)> = vec![];
    for (folder, sig) in folders.iter().zip(sigs) {
        let key = folder.to_string_lossy().into_owned();
        if cache.dirs.get(&key) == Some(&sig) {
            dirs.insert(key, sig);
        } else {
            todo.push((folder.clone(), sig));
        }
    }
    let mut done = total - todo.len();
    report(done, total);

    // A failed batch is retried one folder at a time, so one huge folder can't sink 39 others.
    let mut queue: VecDeque<Vec<(PathBuf, Sig)>> = todo.chunks(BATCH).map(<[_]>::to_vec).collect();
    let mut set = tokio::task::JoinSet::new();
    let spawn_next = |set: &mut tokio::task::JoinSet<_>, queue: &mut VecDeque<_>| {
        if let Some(batch) = queue.pop_front() {
            set.spawn(scan_batch(gitleaks.to_path_buf(), exclusions.to_vec(), batch));
        }
    };
    for _ in 0..PARALLEL {
        spawn_next(&mut set, &mut queue);
    }
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((batch, Ok(leaks))) => {
                done += batch.len();
                for (folder, sig) in &batch {
                    dirs.insert(folder.to_string_lossy().into_owned(), *sig);
                    rescanned.insert(folder.clone());
                }
                for (path, leak) in leaks {
                    let owner = batch.iter().map(|(f, _)| f).find(|f| path.starts_with(f)).cloned();
                    hits.push((owner, path, leak));
                }
            }
            Ok((batch, Err(_))) if batch.len() > 1 => {
                queue.extend(batch.into_iter().map(|f| vec![f]));
                spawn_next(&mut set, &mut queue);
            }
            Ok((batch, Err(e))) => {
                done += 1;
                if e.ends_with("timed out") {
                    // Too big to check: keep its old findings and don't retry until it changes.
                    let (folder, sig) = &batch[0];
                    dirs.insert(folder.to_string_lossy().into_owned(), *sig);
                    errors.push(format!("{}: too large to check, skipped until it changes", folder.display()));
                } else {
                    errors.push(e);
                }
            }
            Err(e) => errors.push(format!("scan task failed: {e}")),
        }
        report(done, total);
        spawn_next(&mut set, &mut queue);
    }

    let mut home_paths: HashSet<PathBuf> = HashSet::new();
    let mut failed_home: HashSet<PathBuf> = HashSet::new();
    if let Some(home) = home {
        let files = tokio::task::spawn_blocking(move || home_files(&home)).await.unwrap_or_default();
        for file in files {
            let (Some(dir), Some(name)) = (file.parent(), file.file_name().and_then(|n| n.to_str())) else { continue };
            home_paths.insert(file.clone());
            match run_gitleaks(gitleaks, &config, dir, name, FILE_TIMEOUT).await {
                Ok(leaks) => hits.extend(leaks.into_iter().map(|l| (None, dir.join(&l.file), l))),
                Err(e) => {
                    errors.push(format!("{}: {e}", file.display()));
                    failed_home.insert(file.clone());
                }
            }
        }
    }

    let mut groups: BTreeMap<(PathBuf, String), (Option<PathBuf>, Vec<u32>)> = BTreeMap::new();
    for (root, path, leak) in hits {
        if !keep_hit(&path, &leak.rule) {
            continue;
        }
        groups.entry((path, leak.rule)).or_insert((root, vec![])).1.push(leak.line);
    }

    let today = days_now();
    let mut out = vec![];
    for ((path, rule), (root, mut lines)) in groups {
        lines.sort_unstable();
        lines.dedup();
        out.push(finding(&path, &rule, &lines, root.as_deref(), breaches, today).await);
    }
    let fresh = out.len();

    let kept: Vec<&PathBuf> = folders.iter().filter(|f| !rescanned.contains(*f)).collect();
    out.extend(
        old.iter()
            .filter(|f| f.kind == "secret")
            .filter(|f| {
                let p = Path::new(&f.project_path);
                failed_home.contains(p) || !home_paths.contains(p) && kept.iter().any(|d| p.starts_with(d))
            })
            .map(as_input),
    );
    if fresh == 0 && out.is_empty() && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    cache.dirs = dirs;
    cache.errors = errors;
    Ok(out)
}

async fn finding(path: &Path, rule: &str, lines: &[u32], root: Option<&Path>, breaches: &[Breach], today: i64) -> FindingInput {
    let file = path.to_string_lossy().into_owned();
    let loose = std::fs::metadata(path).map(|m| m.permissions().mode() & 0o044 != 0).unwrap_or(false);
    let (project_name, repo) = project_of(path, root);
    let tracked = match &repo {
        Some(r) => git_tracked(r, path).await,
        None => false,
    };
    let provider = PROVIDERS.iter().find(|p| rule.starts_with(p.0));
    let breach = provider.and_then(|p| recent_breach(p.2, breaches, today));

    let name = detector_name(rule);
    let mut summary = String::new();
    if let (Some(p), Some(b)) = (provider, breach) {
        summary += &format!("{} reported a breach on {}. Rotate this token. ", p.1, b.breach_date);
    }
    summary += &format!("{name} in plain text at line {}", lines[0]);
    if lines.len() > 1 {
        summary += &format!(" (+{} more)", lines.len() - 1);
    }
    if loose {
        summary += " · file is readable by other users";
    }
    summary += &format!(" · {HINT}");

    FindingInput {
        kind: "secret",
        group_id: format!("SECRET-{rule}"),
        project_name,
        project_path: file.clone(),
        ecosystem: "Secret".into(),
        name,
        installed_version: sha256_hex8(format!("{file}:{rule}").as_bytes()),
        fixed_version: None,
        direct: None,
        dev: false,
        inferred: false,
        fix_command: loose.then(|| format!("chmod 600 '{}'", file.replace('\'', "'\\''"))),
        aliases: vec![],
        summary,
        score: Some(if breach.is_some() { 9.0 } else if loose || tracked { 7.5 } else { 5.5 }),
        malicious: false,
        url: provider.map(|p| p.3).unwrap_or("https://github.com/gitleaks/gitleaks").into(),
    }
}

/// Project folder name (nearest marker dir at or below the root) and the git repo dir, if any.
fn project_of(path: &Path, root: Option<&Path>) -> (String, Option<PathBuf>) {
    let Some(root) = root else { return ("Home config".into(), nearest_repo(path)) };
    let mut project = None;
    let mut dir = path.parent();
    while let Some(d) = dir {
        if project.is_none() && PROJECT_MARKERS.iter().any(|m| d.join(m).exists()) {
            project = Some(d);
        }
        if d == root {
            break;
        }
        dir = d.parent();
    }
    let name = project.unwrap_or(root).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "Home config".into());
    (name, nearest_repo(path))
}

fn nearest_repo(path: &Path) -> Option<PathBuf> {
    path.ancestors().skip(1).find(|d| d.join(".git").exists()).map(Path::to_path_buf)
}

/// Whether git tracks `file`. Scanned repos are untrusted: their own config could make git run a
/// command (core.fsmonitor), so the command line overrides it and system/global config is ignored.
async fn git_tracked(repo: &Path, file: &Path) -> bool {
    Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false"])
        .args(["ls-files", "--error-unmatch", "--"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn run_gitleaks(gitleaks: &Path, config: &str, cwd: &Path, target: &str, limit: Duration) -> Result<Vec<Leak>, String> {
    let child = Command::new("/usr/sbin/taskpolicy")
        .arg("-b")
        .arg(gitleaks)
        .args(["dir", target, "--redact", "--report-format", "json", "--report-path", "-", "--no-banner", "--exit-code", "0", "--log-level", "error", "--max-target-megabytes", "1"])
        .env("GITLEAKS_CONFIG_TOML", config)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    let out = tokio::time::timeout(limit, child.wait_with_output())
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        let err: String = String::from_utf8_lossy(&out.stderr).chars().take(200).collect();
        return Err(format!("exit {}: {err}", out.status));
    }
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(vec![]);
    }
    let leaks: Option<Vec<Leak>> = serde_json::from_slice(&out.stdout).map_err(|e| format!("parse: {e}"))?;
    Ok(leaks.unwrap_or_default())
}

fn regex_escape(s: &str) -> String {
    s.chars().fold(String::new(), |mut a, c| {
        if ".^$|()[]{}*+?\\".contains(c) {
            a.push('\\');
        }
        a.push(c);
        a
    })
}

/// Gitleaks default rules plus an allowlist of skipped paths; passed via GITLEAKS_CONFIG_TOML.
fn config_toml(exclusions: &[String]) -> String {
    config_with(exclusions, &[])
}

fn config_with(exclusions: &[String], extra_paths: &[String]) -> String {
    let mut dirs: Vec<String> = exclusions
        .iter()
        .filter(|e| !e.is_empty() && !e.contains(['/', '\'']))
        .map(|e| match e.strip_suffix('*') {
            Some(prefix) => format!("(^|/){}[^/]*/", regex_escape(prefix)),
            None => format!("(^|/){}/", regex_escape(e)),
        })
        .collect();
    if !exclusions.iter().any(|e| e == ".git") {
        dirs.push("(^|/)\\.git/".into());
    }
    let mut paths = dirs;
    paths.extend(extra_paths.iter().cloned());
    paths.extend(
        [
            r"(\.lock|-lock\.json|-lock\.yaml|\.lockb|(^|/)go\.sum|shrinkwrap\.json)$",
            r"\.(example|sample|md)$",
            r"(^|/)(test|tests|fixtures|__tests__)/",
        ]
        .map(String::from),
    );
    let list: Vec<String> = paths.iter().map(|p| format!("'''{p}'''")).collect();
    format!("[extend]\nuseDefault = true\n\n[allowlist]\ndescription = \"novul\"\npaths = [{}]\n", list.join(", "))
}

fn home_files(home: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = HOME_FILES.iter().map(|f| home.join(f)).filter(|p| p.is_file()).collect();
    let walk = ignore::WalkBuilder::new(home.join(".config"))
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .max_depth(Some(4))
        .filter_entry(|e| e.file_name() != "node_modules")
        .build();
    for entry in walk.flatten() {
        let name = entry.file_name().to_string_lossy();
        if entry.file_type().is_some_and(|t| t.is_file()) && (name == ".env" || name.starts_with(".env.")) {
            files.push(entry.into_path());
        }
    }
    files
}

/// gitleaks' broad `generic-api-key` rule matches sample configs and random strings in code, notebooks
/// and docs; keep it only for files that look like configuration. Provider-specific rules always stay.
fn keep_hit(path: &Path, rule: &str) -> bool {
    if rule != "generic-api-key" {
        return true;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
    if name.starts_with(".env.") {
        return !matches!(name.as_str(), ".env.example" | ".env.sample" | ".env.template");
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    // JSON is mostly generated data (build output, fixtures, API dumps); keep only config-like names.
    let config_json = ext == "json"
        && (name.starts_with('.')
            || ["config", "settings", "credential", "secret", "auth", "token", "key", "mcp"].iter().any(|w| name.contains(w)));
    name == ".env"
        || name == "credentials"
        || name == "config"
        || (name.starts_with('.') && name.ends_with("rc"))
        || config_json
        || matches!(ext, "env" | "toml" | "yaml" | "yml" | "ini" | "cfg" | "conf" | "properties")
}

fn detector_name(rule: &str) -> String {
    if let Some((_, n)) = NAMES.iter().find(|(r, _)| *r == rule) {
        return n.to_string();
    }
    let words: Vec<String> = rule
        .split('-')
        .enumerate()
        .map(|(i, w)| match w {
            "api" | "pat" | "jwt" | "aws" | "gcp" | "id" | "ssh" | "url" | "sas" | "oauth" => w.to_uppercase(),
            _ if i == 0 => w[..1].to_uppercase() + &w[1..],
            _ => w.to_string(),
        })
        .collect();
    words.join(" ")
}

fn domain_matches(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    !a.is_empty() && !b.is_empty() && (a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")))
}

fn recent_breach<'a>(domain: &str, breaches: &'a [Breach], today: i64) -> Option<&'a Breach> {
    breaches
        .iter()
        .filter(|b| domain_matches(&b.domain, domain))
        .filter(|b| parse_day(&b.added_date).is_some_and(|d| (0..=BREACH_WINDOW_DAYS).contains(&(today - d))))
        .max_by(|a, b| a.added_date.cmp(&b.added_date))
}

fn days_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64 / 86400).unwrap_or(0)
}

/// Days since 1970-01-01 for a "YYYY-MM-DD..." string.
fn parse_day(s: &str) -> Option<i64> {
    let mut it = s.get(..10)?.split('-');
    let (y, m, d): (i64, i64, i64) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    Some(era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468)
}

/// First 8 hex chars of SHA-256; used as a stable, non-reversible id (the input holds no secret).
fn sha256_hex8(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for (a, b) in h.iter_mut().zip(v) {
            *a = a.wrapping_add(b);
        }
    }
    format!("{:08x}", h[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Made-up keys, split so key scanners and push protection don't flag this file.
    const AWS: &str = concat!("AKIA", "J7Q3ZK5M2XWT4NBV");
    const GH: &str = concat!("ghp_", "R7kQ2mZx9LpT4vNc8WbY1sDfH6jA3eUo5Gy0");

    async fn scan(gitleaks: &Path, roots: &[PathBuf], home: Option<PathBuf>, exclusions: &[String], breaches: &[Breach]) -> Result<Vec<FindingInput>, String> {
        super::scan(gitleaks, roots, home, exclusions, breaches, &mut Cache::default(), &[], &|_, _| {}).await
    }

    fn gitleaks() -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/binaries/gitleaks-aarch64-apple-darwin"))
    }

    fn write(path: &Path, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("AWS_KEY={AWS}\nGH_TOKEN={GH}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn dump(f: &FindingInput) -> String {
        [&f.group_id, &f.project_name, &f.project_path, &f.name, &f.installed_version, &f.summary, &f.url, f.fix_command.as_deref().unwrap_or("")].join("|")
    }

    fn ymd(days: i64) -> String {
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        format!("{:04}-{:02}-{:02}", yoe + era * 400 + (m <= 2) as i64, m, d)
    }

    fn excl() -> Vec<String> {
        ["node_modules", "vendor", "build", "archive*"].map(String::from).to_vec()
    }

    #[test]
    fn generic_api_key_only_kept_in_config_files() {
        let keep = [
            "/p/.env", "/p/.env.local", "/p/.env.production", "/p/prod.env", "/p/.npmrc", "/p/.netrc", "/p/.pypirc",
            "/h/.zshrc", "/p/settings.json", "/p/pyproject.toml", "/p/ci.yaml", "/p/ci.yml", "/p/a.ini", "/p/a.cfg",
            "/p/nginx.conf", "/p/app.properties", "/h/.aws/credentials", "/h/.kube/config", "/p/CONFIG.JSON", "/h/.cursor/mcp.json", "/h/.claude.json",
        ];
        let drop = [
            "/p/.env.example", "/p/.env.sample", "/p/.env.template", "/p/app.js", "/p/app.ts", "/p/a.tsx", "/p/a.jsx",
            "/p/a.mjs", "/p/a.cjs", "/p/a.py", "/p/nb.ipynb", "/p/main.go", "/p/lib.rs", "/p/A.java", "/p/A.kt",
            "/p/A.swift", "/p/a.rb", "/p/a.php", "/p/a.c", "/p/a.cpp", "/p/a.h", "/p/a.cs", "/p/a.html", "/p/a.css",
            "/p/README.md", "/p/notes.txt", "/p/uv.lock", "/p/logo.svg", "/p/run.sh", "/p/noext", "/p/rc.txt", "/p/out/render.json", "/p/jobs.json",
        ];
        for p in keep {
            assert!(keep_hit(Path::new(p), "generic-api-key"), "{p}");
        }
        for p in drop {
            assert!(!keep_hit(Path::new(p), "generic-api-key"), "{p}");
        }
        for p in keep.iter().chain(&drop) {
            assert!(keep_hit(Path::new(p), "aws-access-token"), "provider rules stay everywhere: {p}");
        }
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(sha256_hex8(b"abc"), "ba7816bf");
        assert_eq!(sha256_hex8(&[b'a'; 100]), "2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"[..8]);
    }

    #[test]
    fn day_math_roundtrips() {
        assert_eq!(parse_day("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(ymd(parse_day("2026-10-25").unwrap()), "2026-10-25");
        assert_eq!(parse_day("garbage"), None);
    }

    #[test]
    fn config_matches_exclusion_glob_rule() {
        let c = config_toml(&excl());
        assert!(c.contains("'''(^|/)node_modules/'''"));
        assert!(c.contains("'''(^|/)archive[^/]*/'''"));
        assert!(c.contains("'''(^|/)\\.git/'''"));
    }

    #[test]
    fn breach_window_and_domain_match() {
        let today = parse_day("2026-10-25").unwrap();
        let b = |domain: &str, added: &str| Breach { name: "X".into(), domain: domain.into(), breach_date: added.into(), added_date: added.into() };
        let list = [b("github.com", "2026-09-01T00:00:00Z"), b("github.com", "2026-10-01T00:00:00Z"), b("gitlab.com", "2025-01-01T00:00:00Z"), b("evilgithub.com", "2026-10-20T00:00:00Z")];
        assert_eq!(recent_breach("github.com", &list, today).unwrap().added_date, "2026-10-01T00:00:00Z");
        assert!(recent_breach("gitlab.com", &list, today).is_none());
        assert!(recent_breach("slack.com", &list, today).is_none());

        let body = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hibp/breaches.json")).unwrap();
        let fixture = crate::feeds::hibp::parse(&body).unwrap();
        assert!(PROVIDERS.iter().all(|p| recent_breach(p.2, &fixture, today).is_none()));
    }

    #[tokio::test]
    async fn finds_keys_fixes_permissions_skips_dirs_and_never_leaks_values() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("proj")).unwrap();
        fs::write(root.join("proj/package.json"), "{}").unwrap();
        write(&root.join("proj/.env"), 0o644);
        write(&root.join("proj/node_modules/pkg/.env"), 0o644);
        write(&root.join("proj/archive-old/.env"), 0o644);
        write(&root.join("proj/tests/.env"), 0o644);
        write(&root.join("proj/notes.md"), 0o644);
        write(&root.join("proj/.env.example"), 0o644);
        write(&root.join("tight/.git/HEAD"), 0o644);
        write(&root.join("tight/.env"), 0o600);

        let breaches = [Breach { name: "GitHub".into(), domain: "github.com".into(), breach_date: ymd(days_now() - 10), added_date: ymd(days_now() - 3) }];
        let found = scan(&gitleaks(), &[root.to_path_buf()], None, &excl(), &breaches).await.unwrap();

        let loose_env = root.join("proj/.env").to_string_lossy().into_owned();
        let mut paths: Vec<_> = found.iter().map(|f| (f.project_path.replace(&loose_env, "LOOSE"), f.group_id.clone())).collect();
        paths.sort();
        let tight_env = root.join("tight/.env").to_string_lossy().into_owned();
        assert_eq!(found.len(), 4, "{paths:?}");
        assert!(found.iter().all(|f| f.project_path == loose_env || f.project_path == tight_env), "{paths:?}");

        let aws = found.iter().find(|f| f.project_path == loose_env && f.group_id == "SECRET-aws-access-token").unwrap();
        assert_eq!(aws.kind, "secret");
        assert_eq!(aws.project_name, "proj");
        assert_eq!(aws.name, "AWS access key");
        assert_eq!(aws.fix_command.as_deref(), Some(format!("chmod 600 '{loose_env}'").as_str()));
        assert_eq!(aws.score, Some(7.5));
        assert_eq!(aws.installed_version.len(), 8);
        assert!(aws.summary.contains("at line 1") && aws.summary.contains("readable by other users"));

        let gh = found.iter().find(|f| f.project_path == loose_env && f.group_id == "SECRET-github-pat").unwrap();
        assert_eq!(gh.score, Some(9.0));
        assert!(gh.summary.starts_with("GitHub reported a breach on "), "{}", gh.summary);
        assert_eq!(gh.url, "https://github.com/settings/tokens");

        let tight = found.iter().find(|f| f.project_path == tight_env && f.group_id == "SECRET-aws-access-token").unwrap();
        assert_eq!(tight.fix_command, None);
        assert_eq!(tight.score, Some(5.5));
        assert_eq!(tight.project_name, "tight");

        let all: String = found.iter().map(dump).collect();
        assert!(!all.contains(AWS) && !all.contains(GH) && !all.contains("AKIA") && !all.contains("ghp_"));
    }

    #[tokio::test]
    async fn a_scanned_repo_cannot_make_git_run_its_fsmonitor_command() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        let marker = tmp.path().join("pwned");
        let hook = tmp.path().join("hook.sh");
        fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        let git = |args: &[&str]| std::process::Command::new("/usr/bin/git").arg("-C").arg(&repo).args(args).output().unwrap();
        git(&["init", "-q"]);
        fs::write(repo.join("a.txt"), "x").unwrap();
        git(&["add", "a.txt"]);
        git(&["config", "core.fsmonitor", hook.to_str().unwrap()]);

        // plain git runs the repo's command, which is what makes this a real attack
        git(&["ls-files", "--error-unmatch", "--", "a.txt"]);
        let plain_ran = marker.exists();
        let _ = fs::remove_file(&marker);

        assert!(git_tracked(&repo, &repo.join("a.txt")).await);
        assert!(!marker.exists(), "git_tracked ran the repo's fsmonitor command");
        assert!(plain_ran, "test setup: this git should run core.fsmonitor when not overridden");
    }

    #[tokio::test]
    async fn git_tracked_file_scores_high_even_with_tight_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        write(&repo.join(".env"), 0o600);
        fs::write(repo.join("package.json"), "{}").unwrap();
        let git = |args: &[&str]| std::process::Command::new("/usr/bin/git").arg("-C").arg(&repo).args(args).output().unwrap();
        git(&["init", "-q"]);
        git(&["add", ".env"]);

        let found = scan(&gitleaks(), &[tmp.path().to_path_buf()], None, &excl(), &[]).await.unwrap();
        let f = found.iter().find(|f| f.group_id == "SECRET-aws-access-token").unwrap();
        assert_eq!((f.score, f.fix_command.clone()), (Some(7.5), None));

        git(&["rm", "-q", "--cached", ".env"]);
        let found = scan(&gitleaks(), &[tmp.path().to_path_buf()], None, &excl(), &[]).await.unwrap();
        assert_eq!(found.iter().find(|f| f.group_id == "SECRET-aws-access-token").unwrap().score, Some(5.5));
    }

    #[test]
    fn home_files_lists_known_files_and_config_env() {
        let tmp = tempfile::tempdir().unwrap();
        let h = tmp.path();
        write(&h.join(".zshrc"), 0o600);
        write(&h.join(".aws/credentials"), 0o600);
        write(&h.join(".config/app/.env"), 0o600);
        write(&h.join(".config/app/node_modules/x/.env"), 0o600);
        write(&h.join("elsewhere/.env"), 0o600);
        let mut got: Vec<String> = home_files(h).iter().map(|p| p.strip_prefix(h).unwrap().to_string_lossy().into_owned()).collect();
        got.sort();
        assert_eq!(got, [".aws/credentials", ".config/app/.env", ".zshrc"]);
    }

    #[tokio::test]
    async fn scans_home_config_files_outside_roots() {
        let home = tempfile::tempdir().unwrap();
        write(&home.path().join(".zshrc"), 0o644);
        write(&home.path().join(".config/tool/.env"), 0o600);
        let found = scan(&gitleaks(), &[], Some(home.path().to_path_buf()), &excl(), &[]).await.unwrap();
        assert_eq!(found.len(), 4);
        assert!(found.iter().all(|f| f.project_name == "Home config"));
        let zsh = found.iter().find(|f| f.project_path.ends_with("/.zshrc") && f.group_id == "SECRET-aws-access-token").unwrap();
        assert_eq!(zsh.fix_command.as_deref().map(|c| c.starts_with("chmod 600 '")), Some(true));
        assert!(found.iter().any(|f| f.project_path.ends_with("/.config/tool/.env") && f.fix_command.is_none()));
    }

    #[tokio::test]
    async fn home_file_findings_survive_a_failed_gitleaks_run() {
        let home = tempfile::tempdir().unwrap();
        write(&home.path().join(".zshrc"), 0o644);
        let first = scan(&gitleaks(), &[], Some(home.path().to_path_buf()), &excl(), &[]).await.unwrap();
        assert_eq!(first.len(), 2);

        let db = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&db.path().join("t.db")).unwrap();
        store.sync_kind("secret", &first, 100).unwrap();
        let old: Vec<FindingView> = store.open_findings().unwrap();
        let mut cache = Cache::default();
        let again = super::scan(Path::new(NO_GITLEAKS), &[], Some(home.path().to_path_buf()), &excl(), &[], &mut cache, &old, &|_, _| {}).await.unwrap();
        assert_eq!(again.len(), 2, "a scanner that cannot run must not resolve what it could not check");
        assert_eq!(cache.errors.len(), 1);
    }

    async fn pass(store: &crate::store::Store, gitleaks: &Path, folders: &[PathBuf], cache: &mut Cache, t: i64) -> Result<(), String> {
        let old: Vec<FindingView> = store.open_findings().unwrap().into_iter().filter(|f| f.kind == "secret").collect();
        let out = super::scan(gitleaks, folders, None, &excl(), &[], cache, &old, &|_, _| {}).await?;
        store.sync_kind("secret", &out, t).unwrap();
        Ok(())
    }

    fn open(store: &crate::store::Store, root: &Path) -> Vec<String> {
        let mut v: Vec<String> = store
            .open_findings()
            .unwrap()
            .iter()
            .filter(|f| f.kind == "secret")
            .map(|f| format!("{}|{}", f.project_path.strip_prefix(root.to_str().unwrap()).unwrap(), f.group_id))
            .collect();
        v.sort();
        v
    }

    struct Tree {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        store: crate::store::Store,
        _db: tempfile::TempDir,
        folders: Vec<PathBuf>,
    }

    fn tree() -> Tree {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let db = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(&db.path().join("t.db")).unwrap();
        let folders = vec![root.join("a"), root.join("b")];
        for f in &folders {
            write(&f.join(".env"), 0o600);
        }
        Tree { _tmp: tmp, root, store, _db: db, folders }
    }

    const NO_GITLEAKS: &str = "/nonexistent/gitleaks";

    #[tokio::test]
    async fn unchanged_folder_is_skipped_and_its_findings_are_kept() {
        let t = tree();
        let mut cache = Cache::default();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 100).await.unwrap();
        let first = open(&t.store, &t.root);
        assert_eq!(first, ["/a/.env|SECRET-aws-access-token", "/a/.env|SECRET-github-pat", "/b/.env|SECRET-aws-access-token", "/b/.env|SECRET-github-pat"]);
        assert_eq!(cache.dirs.len(), 2);

        // gitleaks would fail to spawn, so anything that still resolves was not rescanned
        pass(&t.store, Path::new(NO_GITLEAKS), &t.folders, &mut cache, 200).await.unwrap();
        assert_eq!(open(&t.store, &t.root), first);
    }

    #[tokio::test]
    async fn changed_folder_is_rescanned_while_the_other_keeps_its_findings() {
        let t = tree();
        let mut cache = Cache::default();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 100).await.unwrap();
        let sig_a = cache.dirs[t.folders[0].to_str().unwrap()];

        write(&t.root.join("b/sub/.env"), 0o600);
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 200).await.unwrap();
        let after = open(&t.store, &t.root);
        assert!(after.contains(&"/b/sub/.env|SECRET-aws-access-token".to_string()), "{after:?}");
        assert_eq!(after.len(), 6, "{after:?}");
        assert_eq!(cache.dirs[t.folders[0].to_str().unwrap()], sig_a, "a was not touched");
    }

    #[tokio::test]
    async fn removed_key_or_file_resolves_only_in_its_folder() {
        let t = tree();
        let mut cache = Cache::default();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 100).await.unwrap();

        fs::write(t.root.join("a/.env"), "NOTHING=here\n").unwrap();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 200).await.unwrap();
        assert_eq!(open(&t.store, &t.root), ["/b/.env|SECRET-aws-access-token", "/b/.env|SECRET-github-pat"]);

        // deleting a file changes no remaining file's mtime, only its directory's
        fs::remove_file(t.root.join("b/.env")).unwrap();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 300).await.unwrap();
        assert!(open(&t.store, &t.root).is_empty());
    }

    #[tokio::test]
    async fn failed_folder_keeps_old_findings_and_is_retried() {
        let t = tree();
        let mut cache = Cache::default();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 100).await.unwrap();
        let first = open(&t.store, &t.root);

        write(&t.root.join("a/new/.env"), 0o600);
        pass(&t.store, Path::new(NO_GITLEAKS), &t.folders, &mut cache, 200).await.unwrap();
        assert_eq!(open(&t.store, &t.root), first);
        assert!(!cache.dirs.contains_key(t.folders[0].to_str().unwrap()), "retried next time");
        assert!(cache.dirs.contains_key(t.folders[1].to_str().unwrap()));
    }

    #[tokio::test]
    async fn folders_that_are_no_longer_scanned_resolve() {
        let t = tree();
        let mut cache = Cache::default();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 100).await.unwrap();
        pass(&t.store, Path::new(NO_GITLEAKS), &t.folders[..1], &mut cache, 200).await.unwrap();
        assert_eq!(open(&t.store, &t.root), ["/a/.env|SECRET-aws-access-token", "/a/.env|SECRET-github-pat"]);
    }

    #[tokio::test]
    async fn changed_exclusions_invalidate_the_cache() {
        let t = tree();
        let mut cache = Cache::default();
        pass(&t.store, &gitleaks(), &t.folders, &mut cache, 100).await.unwrap();
        let out = super::scan(Path::new(NO_GITLEAKS), &t.folders, None, &["other".to_string()], &[], &mut cache, &[], &|_, _| {}).await;
        assert!(out.is_err(), "every folder had to be rescanned (and failed to spawn)");
    }

    #[test]
    fn project_folders_are_known_projects_plus_root_level_git_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let r = tmp.path().canonicalize().unwrap();
        for d in ["app", "lib/inner", "lib/inner/node_modules/x", "media/movies", "repo/.git", "repo/pkg", "archive-old/p", "solo/.git"] {
            fs::create_dir_all(r.join(d)).unwrap();
        }
        let known = [r.join("app"), r.join("lib/inner"), r.join("lib/inner/node_modules/x"), r.join("repo/pkg"), r.join("archive-old/p"), r.join("gone"), PathBuf::from("/elsewhere")];
        let got = project_folders(&known, &[r.clone()], &excl());
        let rel: Vec<String> = got.iter().map(|p| p.strip_prefix(&r).unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(rel, ["app", "lib/inner", "repo", "solo"]);

        // a root that holds projects is never scanned whole; a root that is itself the project is
        assert_eq!(project_folders(&[r.clone(), r.join("app")], &[r.clone()], &excl()), [r.join("app"), r.join("repo"), r.join("solo")]);
        assert_eq!(project_folders(&[r.clone()], &[r.join("media")], &excl()), Vec::<PathBuf>::new());
        assert_eq!(project_folders(&[r.join("app")], &[r.join("app")], &excl()), [r.join("app")]);
    }

    #[test]
    fn signature_sees_new_deleted_and_chmodded_files_and_ignores_excluded_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        write(&d.join(".env"), 0o600);
        fs::create_dir_all(d.join("node_modules")).unwrap();
        let s0 = folder_sig(d, &excl());
        assert_eq!(folder_sig(d, &excl()), s0);
        write(&d.join("node_modules/x/.env"), 0o600);
        assert_eq!(folder_sig(d, &excl()), s0, "excluded dirs do not count");
        fs::set_permissions(d.join(".env"), fs::Permissions::from_mode(0o644)).unwrap();
        let s1 = folder_sig(d, &excl());
        assert_ne!(s1, s0, "chmod changes ctime");
        fs::remove_file(d.join(".env")).unwrap();
        assert_ne!(folder_sig(d, &excl()), s1);
    }

    #[tokio::test]
    async fn many_odd_named_folders_are_all_cached_after_one_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let names = ["My App (old)", "it's [v2]", "naïve café", "a+b#c$d&e", "space ", "-dash", "x{1}", "q?*", "\\back"];
        let mut folders = vec![];
        for i in 0..90 {
            let group = ["Development/Web", "Media/Video", "Tools"][i % 3];
            let f = root.join(group).join(format!("{} {i}", names[i % names.len()]));
            fs::create_dir_all(&f).unwrap();
            fs::write(f.join("package.json"), "{}").unwrap();
            if i % 10 == 0 {
                write(&f.join(".env"), 0o600);
            }
            fs::create_dir_all(root.join(group).join(format!("not a project {i}"))).unwrap();
            folders.push(f);
        }
        let mut cache = Cache::default();
        let found = super::scan(&gitleaks(), &folders, None, &excl(), &[], &mut cache, &[], &|_, _| {}).await.unwrap();
        assert_eq!(found.len(), 18, "two rules in each of 9 .env files");
        assert_eq!(cache.dirs.len(), folders.len(), "every batch succeeded and was cached");
    }

    #[tokio::test]
    async fn one_process_covers_a_batch_without_walking_unselected_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        for d in ["a", "b", "group/c", "group/other", "media/clips", "it's here"] {
            write(&root.join(d).join(".env"), 0o600);
        }
        write(&root.join("loose.env"), 0o600);
        let folders = [root.join("a"), root.join("b"), root.join("group/c")];
        let (base, skips) = batch_plan(&folders);
        assert_eq!(base, root);
        assert_eq!(skips.len(), 2, "{skips:?}");

        let found = super::scan(&gitleaks(), &folders, None, &excl(), &[], &mut Cache::default(), &[], &|_, _| {}).await.unwrap();
        let mut got: Vec<String> = found.iter().map(|f| f.project_path.strip_prefix(root.to_str().unwrap()).unwrap().to_string()).collect();
        got.sort();
        got.dedup();
        assert_eq!(got, ["/a/.env", "/b/.env", "/group/c/.env"]);
        assert_eq!(found.len(), 6);
        assert_eq!(batch_plan(&folders[..1]), (root.join("a"), vec![]));
    }
}
