// One long-lived task owns all scanning; commands arrive over a channel, so only one job runs at a time.

use crate::feeds::{hibp::fetch_breaches, kev::fetch_kev};
use crate::inventory::{aitools::{tool_findings, BinCache}, globals::global_findings};
use crate::scan::leaks::{project_folders, secret_findings, Cache as SecretCache};
use crate::inventory::{discover::{discover, ecosystem_for}, manifest::direct_deps, runtimes::detect_runtimes};
use crate::model::*;
use crate::scan::{brew::brew_vulns, eol, fix::fix_command, lockfile::{scan_lockfiles, Offline}, osv::querybatch};
use crate::store::{FindingInput, LocationRow, Store};
use crate::worker::Event;
use crate::{notify, tray};
use notify_debouncer_mini::{new_debouncer, notify::{RecommendedWatcher, RecursiveMode}, DebounceEventResult, Debouncer};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinSet;
use tokio::time::{sleep_until, Instant};

pub enum Cmd {
    ScanNow,
    RescanLockfiles(Vec<PathBuf>),
    SettingsChanged,
    /// Run the periodic check now (sent when scanning is resumed).
    Tick,
    Quit,
}

#[derive(Default, Clone)]
pub struct Live {
    pub scanning: bool,
    pub progress: Option<(usize, usize)>,
    /// "packages" | "machine" | "secrets" during a full scan.
    pub phase: Option<String>,
}

/// Managed Tauri state shared by commands, tray and engine.
pub struct Shared {
    pub store: Arc<Store>,
    pub live: Mutex<Live>,
    pub tx: UnboundedSender<Cmd>,
    pub focus: Mutex<Option<i64>>,
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Tell the UI and the tray that data changed.
pub fn changed(app: &AppHandle) {
    let _ = app.emit("state-changed", ());
    tray::refresh(app);
}

const KEV_MAX_AGE: i64 = 6 * 3600;
const DAILY: i64 = 24 * 3600;
const BATCH: usize = 20;
const OFFLINE_BATCH: usize = 100;
const KEY_PAGE: usize = 5000;

type Scanned = (Vec<Lockfile>, Result<Vec<LockfileScan>, String>);

struct Engine {
    app: AppHandle,
    store: Arc<Store>,
    db: PathBuf,
    tx: UnboundedSender<Cmd>,
}

pub fn spawn(app: AppHandle, store: Arc<Store>, db: PathBuf, tx: UnboundedSender<Cmd>, rx: UnboundedReceiver<Cmd>) {
    let engine = Engine { app, store, db, tx };
    tauri::async_runtime::spawn(engine.run(rx));
}

pub(crate) fn glob_match(pat: &str, name: &str) -> bool {
    match (pat.strip_prefix('*'), pat.strip_suffix('*')) {
        (Some(suffix), _) if !suffix.contains('*') => name.ends_with(suffix),
        (_, Some(prefix)) if !prefix.contains('*') => name.starts_with(prefix),
        _ => pat == name,
    }
}

fn relevant(path: &Path, exclusions: &[String]) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false };
    ecosystem_for(name).is_some()
        && !path.components().any(|c| {
            let c = c.as_os_str().to_string_lossy();
            exclusions.iter().any(|e| glob_match(e, &c))
        })
}

fn pep503(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

fn display_kind(kind: &str) -> String {
    match kind {
        "node" => "Node.js".into(),
        "php" => "PHP".into(),
        "python" | "python3" => "Python".into(),
        "go" => "Go".into(),
        "ruby" => "Ruby".into(),
        "java" => "Java".into(),
        k => k.into(),
    }
}

fn brew_formula(path: &str, kind: &str) -> String {
    for marker in ["/Cellar/", "/homebrew/opt/"] {
        if let Some(i) = path.find(marker) {
            if let Some(f) = path[i + marker.len()..].split('/').next().filter(|f| !f.is_empty()) {
                return f.to_string();
            }
        }
    }
    match kind {
        "python3" => "python".into(),
        k => k.into(),
    }
}

fn runtime_finding(r: &RuntimeStatus) -> Option<FindingInput> {
    let name = display_kind(&r.kind);
    let (group, score, summary) = if r.is_eol {
        let cycle = r.cycle.as_deref().unwrap_or(&r.version);
        ("EOL", 8.0, format!("{name} {cycle} reached end of life"))
    } else if r.behind {
        let latest = r.latest_in_cycle.as_deref()?;
        let released = r.latest_date.as_deref().map(|d| format!(" (released {d})")).unwrap_or_default();
        ("OUTDATED", 5.0, format!("{name} {} is behind the latest patch {latest}{released}", r.version))
    } else {
        return None;
    };
    let fix_command = r.path.starts_with("/opt/homebrew").then(|| {
        let formula = brew_formula(&r.path, &r.kind);
        match (r.is_eol, formula.split_once('@')) {
            (true, Some((base, _))) => format!("brew install {base}"),
            _ => format!("brew upgrade {formula}"),
        }
    });
    Some(FindingInput {
        kind: "runtime",
        group_id: group.into(),
        project_name: "Runtimes".into(),
        project_path: r.path.clone(),
        ecosystem: "Runtime".into(),
        name: r.kind.clone(),
        installed_version: r.version.clone(),
        fixed_version: if r.is_eol { None } else { r.latest_in_cycle.clone() },
        direct: None,
        dev: false,
        inferred: false,
        fix_command,
        aliases: vec![],
        summary,
        score: Some(score),
        malicious: false,
        url: format!("https://endoflife.date/{}", r.kind.trim_end_matches('3')),
    })
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder().timeout(Duration::from_secs(30)).build().map_err(|e| e.to_string())
}

fn spawn_next(set: &mut JoinSet<Scanned>, chunks: &mut impl Iterator<Item = Vec<Lockfile>>, osv: &Path, offline: &Option<Offline>) {
    if let Some(chunk) = chunks.next() {
        let (osv, offline) = (osv.to_path_buf(), offline.clone());
        set.spawn(async move {
            let paths: Vec<PathBuf> = chunk.iter().map(|l| l.path.clone()).collect();
            let download = offline.as_ref().is_some_and(|o| o.needs_download(chunk.iter().map(|l| l.ecosystem.as_str())));
            let r = scan_lockfiles(&osv, &paths, offline.as_ref().map(|o| (o, download))).await;
            (chunk, r)
        });
    }
}

impl Engine {
    fn live(&self, scanning: bool, progress: Option<(usize, usize)>, phase: Option<&str>) {
        *self.app.state::<Shared>().live.lock().unwrap_or_else(|e| e.into_inner()) = Live { scanning, progress, phase: phase.map(String::from) };
    }

    fn paused(&self) -> bool {
        self.store.meta_i64("paused_until").is_some_and(|t| t > now())
    }

    fn watch(&self, s: &Settings) -> Option<Debouncer<RecommendedWatcher>> {
        let tx = self.tx.clone();
        let exclusions = s.exclusions.clone();
        let mut d = new_debouncer(Duration::from_secs(10), move |res: DebounceEventResult| {
            let Ok(events) = res else { return };
            let paths: BTreeSet<PathBuf> = events.into_iter().map(|e| e.path).filter(|p| relevant(p, &exclusions)).collect();
            if !paths.is_empty() {
                let _ = tx.send(Cmd::RescanLockfiles(paths.into_iter().collect()));
            }
        })
        .ok()?;
        for root in &s.roots {
            if let Err(e) = d.watcher().watch(Path::new(root), RecursiveMode::Recursive) {
                log::warn!("watch {root}: {e}");
            }
        }
        Some(d)
    }

    fn first_tick_in(&self, s: &Settings) -> Duration {
        let interval = (s.interval_minutes.max(1) * 60) as i64;
        let due = self.store.meta_i64("last_check_at").map(|t| t + interval - now()).unwrap_or(interval);
        Duration::from_secs(due.max(30) as u64)
    }

    async fn run(self, mut rx: UnboundedReceiver<Cmd>) {
        let mut settings = self.store.settings();
        let mut _watcher = self.watch(&settings);
        if self.store.project_count() == 0 {
            self.run_job("full-first", &[]).await;
        }
        let mut next = Instant::now() + self.first_tick_in(&settings);
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(first) = cmd else { break };
                    let mut cmds = vec![first];
                    while let Ok(c) = rx.try_recv() {
                        cmds.push(c);
                    }
                    let (mut scan, mut tick, mut reconfigure) = (false, false, false);
                    let mut paths = BTreeSet::new();
                    for c in cmds {
                        match c {
                            Cmd::Quit => return,
                            Cmd::ScanNow => scan = true,
                            Cmd::Tick => tick = true,
                            Cmd::SettingsChanged => reconfigure = true,
                            Cmd::RescanLockfiles(p) => paths.extend(p),
                        }
                    }
                    if reconfigure {
                        let new = self.store.settings();
                        scan |= new.roots != settings.roots || new.exclusions != settings.exclusions || new.private_mode != settings.private_mode;
                        settings = new;
                        _watcher = self.watch(&settings);
                        next = Instant::now() + Duration::from_secs(settings.interval_minutes.max(1) * 60);
                        crate::engine::changed(&self.app);
                    }
                    if scan {
                        self.run_job("full", &[]).await;
                    } else {
                        if tick {
                            self.tick().await;
                        }
                        if !paths.is_empty() && !self.paused() {
                            let paths: Vec<String> = paths.into_iter().map(|p| p.to_string_lossy().into_owned()).collect();
                            self.run_job("rescan", &paths).await;
                        }
                    }
                }
                _ = sleep_until(next) => {
                    self.tick().await;
                    next = Instant::now() + Duration::from_secs(settings.interval_minutes.max(1) * 60);
                }
            }
        }
    }

    // ---------- jobs ----------

    async fn tick(&self) {
        if self.paused() {
            return;
        }
        let job = if now() - self.store.meta_i64("daily_at").unwrap_or(0) > DAILY { "full" } else { "tick" };
        self.run_job(job, &[]).await;
    }

    /// Run a job in a short-lived child of this binary, so scan-time memory never lives in this process.
    /// A full scan is two children: everything but secrets first, whose results and notifications
    /// land before the slow secrets pass starts.
    async fn run_job(&self, job: &str, lockfiles: &[String]) {
        let jobs: &[&str] = if job.starts_with("full") { &[job, "secrets"] } else { &[job] };
        for (i, j) in jobs.iter().enumerate() {
            let phase = match *j {
                "secrets" => Some("secrets"),
                j if j.starts_with("full") => Some("packages"),
                _ => None,
            };
            self.live(true, phase.map(|_| (0, 0)), phase);
            changed(&self.app);
            if let Err(e) = self.child(j, lockfiles).await {
                let _ = self.store.set_meta("last_error", &e);
            }
            self.store.shrink_memory();
            release_freed_memory();
            if i + 1 == jobs.len() {
                self.live(false, None, None);
            }
            notify::after_scan(&self.app, &self.store, *j == "full-first");
            changed(&self.app);
        }
    }

    async fn child(&self, job: &str, lockfiles: &[String]) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut cmd = Command::new("/usr/sbin/taskpolicy");
        cmd.arg("-b").arg(exe).args(["--worker", job, "--db"]).arg(&self.db);
        if !lockfiles.is_empty() {
            cmd.arg("--lockfiles").args(lockfiles);
        }
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("failed to start scan worker: {e}"))?;
        let mut lines = BufReader::new(child.stdout.take().ok_or("no worker stdout")?).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(Event::Progress(p, phase)) = Event::parse(&line) {
                self.live(true, p, phase.as_deref());
                changed(&self.app);
            }
        }
        let status = child.wait().await.map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("scan worker failed ({status})"))
        }
    }
}

/// The scan itself. Runs inside the worker process; it never touches Tauri.
pub struct Job<'a> {
    pub store: &'a Store,
    pub report: &'a dyn Fn(Event),
}

impl Job<'_> {
    fn finish(&self, errors: Vec<String>) {
        let _ = self.store.set_meta("last_error", &errors.join("; "));
    }

    fn lap(&self, name: &str, t: &mut StdInstant) {
        if std::env::var_os("NOVUL_TIMING").is_some() {
            eprintln!("[timing] {name}: {:.1}s", t.elapsed().as_secs_f32());
        }
        *t = StdInstant::now();
    }

    /// Phase 1: lockfiles, then the machine (Homebrew, runtimes, global packages, AI tools) and feeds.
    /// Secrets are a separate job (`secrets_scan`) so these results never wait for them.
    pub async fn full_scan(&self) {
        let mut t = StdInstant::now();
        let mut errors = vec![];
        let s = self.store.settings();
        let roots: Vec<PathBuf> = s.roots.iter().map(PathBuf::from).collect();
        let exclusions = s.exclusions.clone();
        let found = match tokio::task::spawn_blocking(move || discover(&roots, &exclusions)).await {
            Ok(f) => f,
            Err(e) => {
                errors.push(format!("discovery failed: {e}"));
                vec![]
            }
        };
        self.lap("discover", &mut t);
        if !found.is_empty() {
            let keep: HashSet<String> = found.iter().map(|l| l.path.to_string_lossy().into_owned()).collect();
            let gone: Vec<String> = self.store.project_paths().into_iter().filter(|p| !keep.contains(p)).collect();
            if let Err(e) = self.store.remove_projects(&gone, now()) {
                errors.push(e.to_string());
            }
        }
        self.scan_batches(found, true, &mut errors).await;
        self.lap("lockfiles (osv-scanner)", &mut t);
        (self.report)(Event::progress(None, "machine"));
        // `brew vulns` always asks the OSV API and has no offline mode
        if !s.private_mode {
            self.brew(&mut errors).await;
        }
        self.lap("brew", &mut t);
        self.runtimes(&mut errors).await;
        self.lap("runtimes", &mut t);
        self.machine(&mut errors).await;
        self.lap("machine (globals, ai tools)", &mut t);
        self.refresh_kev(&mut errors).await;
        self.refresh_epss(&mut errors).await;
        self.lap("kev+epss", &mut t);
        if !s.private_mode {
            if let Err(e) = self.check_osv(true).await {
                errors.push(e);
            }
        }
        self.lap("osv recheck", &mut t);
        let tm = now();
        let _ = self.store.set_meta("last_check_at", &tm.to_string());
        let _ = self.store.set_meta("daily_at", &tm.to_string());
        self.finish(errors);
    }

    /// Phase 2: plaintext secrets, per project folder and only where something changed since the last pass.
    pub async fn secrets_scan(&self) {
        let mut t = StdInstant::now();
        let mut errors = vec![];
        let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) else { return };
        let s = self.store.settings();
        let roots: Vec<PathBuf> = s.roots.iter().map(PathBuf::from).collect();
        let known: Vec<PathBuf> = self.store.project_paths().iter().filter_map(|p| Path::new(p).parent().map(Path::to_path_buf)).collect();
        let exclusions = s.exclusions.clone();
        let folders = tokio::task::spawn_blocking(move || project_folders(&known, &roots, &exclusions)).await.unwrap_or_default();
        (self.report)(Event::progress(Some((0, folders.len())), "secrets"));
        let breaches = match client() {
            Ok(c) => fetch_breaches(&c).await.unwrap_or_default(),
            Err(_) => vec![],
        };
        let mut cache = SecretCache::load(self.store.meta("secrets_cache"));
        let old: Vec<FindingView> = self.store.open_findings().unwrap_or_default().into_iter().filter(|f| f.kind == "secret").collect();
        let report = |done, total| (self.report)(Event::progress(Some((done, total)), "secrets"));
        match secret_findings(&dir.join("gitleaks"), &folders, &s.exclusions, &breaches, &mut cache, &old, &report).await {
            Ok(inputs) => match self.store.sync_kind("secret", &inputs, now()) {
                Ok(()) => {
                    let _ = self.store.set_meta("secrets_cache", &cache.dump());
                    if let Some(first) = cache.errors.first() {
                        errors.push(format!("secrets: {} folder(s) not checked ({first})", cache.errors.len()));
                    }
                }
                Err(e) => errors.push(format!("store: {e}")),
            },
            Err(e) => errors.push(format!("secret: {e}")),
        }
        self.lap(&format!("secrets ({} folders)", folders.len()), &mut t);
        if !errors.is_empty() {
            let prev = self.store.meta("last_error").unwrap_or_default();
            let all: Vec<String> = Some(prev).filter(|p| !p.is_empty()).into_iter().chain(errors).collect();
            let _ = self.store.set_meta("last_error", &all.join("; "));
        }
    }

    pub async fn tick(&self) {
        let mut errors = vec![];
        // Private mode has no live OSV check between daily scans: the databases refresh with those
        if self.store.settings().private_mode {
            self.refresh_kev(&mut errors).await;
            return self.finish(errors);
        }
        match self.check_osv(false).await {
            Ok((paths, deferred)) => {
                if !paths.is_empty() {
                    let lockfiles = self.lockfiles_for(&paths).await;
                    self.scan_batches(lockfiles, false, &mut errors).await;
                }
                if let Err(e) = self.store.set_package_ids(deferred.iter().map(|(k, v)| (k, v))) {
                    errors.push(e.to_string());
                }
                let _ = self.store.set_meta("last_check_at", &now().to_string());
            }
            Err(e) => errors.push(e),
        }
        self.refresh_kev(&mut errors).await;
        self.finish(errors);
    }

    fn offline(&self) -> Option<Offline> {
        self.store.settings().private_mode.then(Offline::new)
    }

    pub async fn rescan_pass(&self, paths: Vec<String>) {
        let mut errors = vec![];
        let lockfiles = self.lockfiles_for(&paths).await;
        self.scan_batches(lockfiles, false, &mut errors).await;
        self.finish(errors);
    }

    /// Known projects come from the store; new lockfiles need a discovery walk to find their manifest.
    /// Lockfiles that no longer exist are removed.
    async fn lockfiles_for(&self, paths: &[String]) -> Vec<Lockfile> {
        let (mut out, mut gone, mut unknown) = (vec![], vec![], HashSet::new());
        for p in paths {
            if !Path::new(p).exists() {
                gone.push(p.clone());
            } else if let Some(lf) = self.store.lockfile(p) {
                out.push(lf);
            } else {
                unknown.insert(PathBuf::from(p));
            }
        }
        let _ = self.store.remove_projects(&gone, now());
        if !unknown.is_empty() {
            let s = self.store.settings();
            let roots: Vec<PathBuf> = s.roots.iter().map(PathBuf::from).collect();
            if let Ok(found) = tokio::task::spawn_blocking(move || discover(&roots, &s.exclusions)).await {
                out.extend(found.into_iter().filter(|l| unknown.contains(&l.path)));
            }
        }
        out
    }

    /// Run osv-scanner over lockfiles, 20 per process and at most 2 processes at once.
    async fn scan_batches(&self, lockfiles: Vec<Lockfile>, progress: bool, errors: &mut Vec<String>) {
        if lockfiles.is_empty() {
            return;
        }
        let Some(osv) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("osv-scanner"))) else {
            errors.push("cannot locate osv-scanner".into());
            return;
        };
        let total = lockfiles.len();
        let mut done = 0;
        let offline = self.offline();
        // offline, each osv-scanner process loads the databases (npm's alone takes ~5 s), so fewer, bigger batches
        let size = if offline.is_some() { OFFLINE_BATCH } else { BATCH };
        let mut chunks = lockfiles.chunks(size).map(|c| c.to_vec()).collect::<Vec<_>>().into_iter();
        let mut set = JoinSet::new();
        for _ in 0..2 {
            spawn_next(&mut set, &mut chunks, &osv, &offline);
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((chunk, Ok(scans))) => {
                    done += chunk.len();
                    self.ingest(&chunk, scans, errors);
                }
                Ok((chunk, Err(e))) => {
                    done += chunk.len();
                    errors.push(format!("osv-scanner: {e}"));
                }
                Err(e) => errors.push(format!("scan task failed: {e}")),
            }
            if progress {
                (self.report)(Event::progress(Some((done, total)), "packages"));
            }
            spawn_next(&mut set, &mut chunks, &osv, &offline);
        }
    }

    /// A lockfile missing from `scans` was scanned with zero packages.
    fn ingest(&self, chunk: &[Lockfile], scans: Vec<LockfileScan>, errors: &mut Vec<String>) {
        let mut by_path: HashMap<PathBuf, LockfileScan> = scans.into_iter().map(|s| (s.lockfile.clone(), s)).collect();
        if !by_path.is_empty() && !chunk.iter().any(|l| by_path.contains_key(&l.path)) {
            errors.push("osv-scanner returned paths that match none of the requested lockfiles".into());
            return;
        }
        let t = now();
        for lf in chunk {
            let packages = by_path.remove(&lf.path).map(|s| s.packages).unwrap_or_default();
            self.write_scan(lf, packages, t, errors);
        }
    }

    fn write_scan(&self, lf: &Lockfile, packages: Vec<ScannedPackage>, t: i64, errors: &mut Vec<String>) {
        let direct = direct_deps(lf);
        let project_name = lf.root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let project_path = lf.path.to_string_lossy().into_owned();
        let (mut locations, mut findings) = (vec![], vec![]);
        for p in &packages {
            let is_direct = direct
                .as_ref()
                .map(|d| d.contains(&p.name) || (p.ecosystem == "PyPI" && d.contains(&pep503(&p.name))));
            locations.push(LocationRow {
                ecosystem: p.ecosystem.clone(),
                name: p.name.clone(),
                version: p.version.clone(),
                direct: is_direct,
                dev: p.dev,
                inferred: p.inferred,
            });
            for v in &p.vulns {
                let mut aliases: Vec<String> = vec![];
                for a in v.aliases.iter().chain(&v.ids) {
                    if *a != v.id && !aliases.contains(a) {
                        aliases.push(a.clone());
                    }
                }
                let fix = v.fixed_version.as_deref().filter(|_| !v.malicious);
                findings.push(FindingInput {
                    kind: "package",
                    group_id: v.id.clone(),
                    project_name: project_name.clone(),
                    project_path: project_path.clone(),
                    ecosystem: p.ecosystem.clone(),
                    name: p.name.clone(),
                    installed_version: p.version.clone(),
                    fixed_version: v.fixed_version.clone(),
                    direct: is_direct,
                    dev: p.dev,
                    inferred: p.inferred,
                    fix_command: fix.and_then(|f| fix_command(&lf.path, &p.ecosystem, &p.name, f, is_direct)),
                    aliases,
                    summary: v.summary.clone(),
                    score: v.score,
                    malicious: v.malicious,
                    url: v.url.clone(),
                });
            }
        }
        if let Err(e) = self.store.write_project(lf, &locations, &findings, t) {
            errors.push(format!("store: {e}"));
        }
    }

    /// Query OSV for every installed package key, a page at a time, and compare with the stored ids.
    /// Returns the lockfiles to rescan and the new ids to store once that rescan is done.
    /// With `overwrite` (after a full scan) everything is stored as the new baseline.
    async fn check_osv(&self, overwrite: bool) -> Result<(Vec<String>, Vec<(PackageKey, Vec<String>)>), String> {
        let client = client()?;
        let first_run = overwrite || self.store.package_ids_count() == 0;
        let (mut after, mut paths, mut deferred) = (None::<PackageKey>, BTreeSet::new(), vec![]);
        loop {
            let keys = self.store.keys_after(after.as_ref(), KEY_PAGE).map_err(|e| e.to_string())?;
            let Some(last) = keys.last().cloned() else { break };
            after = Some(last);
            let result = querybatch(&client, &keys).await?;
            let mut fresh = vec![];
            for (k, ids) in result {
                match self.store.package_ids(&k) {
                    Some(old) if !first_run && old != ids => {
                        paths.extend(self.store.lockfiles_with(&k));
                        deferred.push((k, ids));
                    }
                    _ => fresh.push((k, ids)),
                }
            }
            self.store.set_package_ids(fresh.iter().map(|(k, v)| (k, v))).map_err(|e| e.to_string())?;
        }
        let _ = self.store.prune_package_ids();
        Ok((paths.into_iter().collect(), deferred))
    }

    async fn refresh_kev(&self, errors: &mut Vec<String>) {
        if now() - self.store.meta_i64("kev_fetched_at").unwrap_or(0) < KEV_MAX_AGE {
            return;
        }
        let res = match client() {
            Ok(c) => fetch_kev(&c).await,
            Err(e) => Err(e),
        };
        match res {
            Ok(set) => {
                if self.store.replace_kev(&set).is_ok() {
                    let _ = self.store.set_meta("kev_fetched_at", &now().to_string());
                }
            }
            Err(e) => errors.push(format!("KEV: {e}")),
        }
    }

    async fn refresh_epss(&self, errors: &mut Vec<String>) {
        if now() - self.store.meta_i64("epss_fetched_at").unwrap_or(0) < DAILY {
            return;
        }
        let cves = self.store.open_cves();
        if cves.is_empty() {
            return;
        }
        let res = match client() {
            Ok(c) => crate::feeds::epss::fetch_epss(&c, &cves).await,
            Err(e) => Err(e),
        };
        match res {
            Ok(m) => {
                if self.store.set_epss(&m).is_ok() {
                    let _ = self.store.set_meta("epss_fetched_at", &now().to_string());
                }
            }
            Err(e) => errors.push(format!("EPSS: {e}")),
        }
    }

    async fn brew(&self, errors: &mut Vec<String>) {
        match brew_vulns().await {
            Ok(vulns) => {
                let inputs: Vec<FindingInput> = vulns
                    .into_iter()
                    .map(|b| FindingInput {
                        kind: "brew",
                        group_id: b.group.id.clone(),
                        project_name: "Homebrew".into(),
                        project_path: "homebrew".into(),
                        ecosystem: "Homebrew".into(),
                        fix_command: b.group.fixed_version.as_ref().map(|_| format!("brew upgrade {}", b.formula)),
                        name: b.formula,
                        installed_version: b.version,
                        fixed_version: b.group.fixed_version,
                        direct: None,
                        dev: false,
                        inferred: false,
                        aliases: b.group.aliases.iter().chain(&b.group.ids).filter(|a| **a != b.group.id).cloned().collect(),
                        summary: b.group.summary,
                        score: b.group.score,
                        malicious: b.group.malicious,
                        url: b.group.url,
                    })
                    .collect();
                if let Err(e) = self.store.sync_kind("brew", &inputs, now()) {
                    errors.push(format!("store: {e}"));
                }
            }
            Err(e) => errors.push(format!("brew: {e}")),
        }
    }

    /// Global packages and AI tools. A source that fails keeps its previous
    /// findings (no sync), so an offline run or a rate limit never resolves real issues.
    async fn machine(&self, errors: &mut Vec<String>) {
        let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) else {
            return errors.push("cannot locate sidecars".into());
        };
        let mut sync = |kind: &str, res: Result<Vec<FindingInput>, String>| match res {
            Ok(inputs) => {
                if let Err(e) = self.store.sync_kind(kind, &inputs, now()) {
                    errors.push(format!("store: {e}"));
                }
            }
            Err(e) => errors.push(format!("{kind}: {e}")),
        };
        let mut t = StdInstant::now();
        let offline = self.offline();
        sync("global", global_findings(&dir.join("osv-scanner"), offline.as_ref()).await);
        self.lap("  globals", &mut t);
        let client = match client() {
            Ok(c) => c,
            Err(e) => return sync("tool", Err(e)),
        };
        let mut bins = BinCache::load(self.store.meta("aitools_cache"));
        let tools = tool_findings(&client, &mut bins, offline.is_some()).await;
        let _ = self.store.set_meta("aitools_cache", &bins.dump());
        sync("tool", tools);
        self.lap("  ai tools", &mut t);
    }

    async fn runtimes(&self, errors: &mut Vec<String>) {
        let detected = tokio::task::spawn_blocking(detect_runtimes).await.unwrap_or_default();
        let client = match client() {
            Ok(c) => c,
            Err(e) => return errors.push(e),
        };
        // every product is fetched, installed or not, so the requests say nothing about this Mac
        let docs = eol::fetch_all(&client).await;
        let statuses: Vec<RuntimeStatus> = detected.iter().map(|(kind, version, path)| eol::check(&docs, kind, version, path)).collect();
        let inputs: Vec<FindingInput> = statuses.iter().filter_map(runtime_finding).collect();
        let _ = self.store.set_runtimes(&statuses);
        if let Err(e) = self.store.sync_kind("runtime", &inputs, now()) {
            errors.push(format!("store: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_and_watch_filter() {
        assert!(glob_match("archive*", "archive-2024"));
        assert!(glob_match("node_modules", "node_modules"));
        assert!(!glob_match("node_modules", "node_modules2"));
        let ex = vec!["node_modules".to_string(), "archive*".to_string()];
        assert!(relevant(Path::new("/w/app/package-lock.json"), &ex));
        assert!(!relevant(Path::new("/w/app/node_modules/x/package-lock.json"), &ex));
        assert!(!relevant(Path::new("/w/archive-old/app/package-lock.json"), &ex));
        assert!(!relevant(Path::new("/w/app/index.js"), &ex));
    }

    #[test]
    fn runtime_findings() {
        let mut r = RuntimeStatus {
            kind: "php".into(),
            version: "8.3.30".into(),
            path: "/opt/homebrew/Cellar/php/8.3.30/bin/php".into(),
            cycle: Some("8.3".into()),
            latest_in_cycle: Some("8.3.36".into()),
            latest_date: Some("2026-10-21".into()),
            is_eol: false,
            behind: true,
        };
        let f = runtime_finding(&r).unwrap();
        assert_eq!(f.group_id, "OUTDATED");
        assert_eq!(f.summary, "PHP 8.3.30 is behind the latest patch 8.3.36 (released 2026-10-21)");
        assert_eq!(f.fix_command.as_deref(), Some("brew upgrade php"));
        r.is_eol = true;
        assert_eq!(runtime_finding(&r).unwrap().group_id, "EOL");
        r.is_eol = false;
        r.behind = false;
        assert!(runtime_finding(&r).is_none());
    }

    #[test]
    fn pypi_names_normalize() {
        assert_eq!(pep503("Foo_Bar.baz"), "foo-bar-baz");
    }
}

/// Hand scan-time memory back to macOS so the menu bar app returns to its idle footprint:
/// mimalloc (the Rust heap) purges its cached segments, and the system zones (used by
/// Apple frameworks) release free pages.
#[cfg(target_os = "macos")]
pub(crate) fn release_freed_memory() {
    extern "C" {
        fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
    }
    // SAFETY: plain C calls; a null zone means "all zones", goal 0 means "as much as possible".
    unsafe {
        libmimalloc_sys::mi_collect(true);
        malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn release_freed_memory() {}
