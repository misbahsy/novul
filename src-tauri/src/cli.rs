// `novul findings | finding | projects | scan | mcp | help | --version`: the agent bridge CLI.
// Reads the app's SQLite database read-only; `scan` runs the worker job in a child process.

use crate::inventory::discover::{discover, ecosystem_for};
use crate::model::{Priority, Settings};
use crate::store::priority_of;
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

macro_rules! out {
    ($($a:tt)*) => {{
        use std::io::Write;
        // A closed pipe (`| head`) is not an error worth a panic.
        let _ = writeln!(std::io::stdout(), $($a)*);
    }};
}

macro_rules! eout {
    ($($a:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($a)*);
    }};
}

pub const MISSING_DB: &str = "NoVul hasn't scanned yet: open the app first";

const PRIORITIES: [&str; 6] = [
    "malicious",
    "exploited",
    "critical",
    "high",
    "medium",
    "low",
];

const HELP: &str = "novul: read NoVul findings, from the terminal or a coding agent

USAGE
  novul findings [--json] [--project <path>]... [--min critical|high|medium|low]
                    [--include-dev] [--include-estimated] [--kind package,brew,...] [--limit N]
  novul finding <id> [--json]
  novul projects [--json]
  novul scan [<lockfile-or-dir>...] [--json]   rescan (default: current directory)
  novul scan --all [--json]                     full scan: projects, this Mac, then secrets
  novul mcp                                    MCP server on stdin/stdout
  novul --version | help

--project matches findings whose lockfile is inside that directory.
Estimated findings (version guessed from requirements.txt) are hidden unless
--include-estimated is given; malicious ones always show, and actively exploited
dev-only ones show too.
Secret findings never contain the secret value, only a fingerprint.";

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Query {
    pub projects: Vec<String>,
    pub min: Option<Priority>,
    pub include_dev: bool,
    pub include_estimated: bool,
    pub kinds: Vec<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, PartialEq)]
pub enum Cmd {
    Findings { json: bool, q: Query },
    Finding { id: i64, json: bool },
    Projects { json: bool },
    Scan { json: bool, paths: Vec<String>, all: bool },
    Mcp,
    Help,
    Version,
}

pub fn parse_min(s: &str) -> Result<Priority, String> {
    if PRIORITIES.contains(&s) {
        Ok(Priority::parse(s))
    } else {
        Err(format!("--min must be one of: {}", PRIORITIES.join(", ")))
    }
}

/// `args[0]` is the subcommand.
pub fn parse(args: &[String]) -> Result<Cmd, String> {
    let Some(cmd) = args.first() else {
        return Ok(Cmd::Help);
    };
    match cmd.as_str() {
        "help" | "--help" => return Ok(Cmd::Help),
        "--version" => return Ok(Cmd::Version),
        "mcp" => return Ok(Cmd::Mcp),
        "findings" | "finding" | "projects" | "scan" => {}
        other => return Err(format!("unknown command: {other}")),
    }
    let (mut json, mut all, mut q, mut positional) = (false, false, Query::default(), vec![]);
    let mut it = args[1..].iter().flat_map(|a| match a.split_once('=') {
        Some((k, v)) if k.starts_with("--") => vec![k.to_string(), v.to_string()],
        _ => vec![a.clone()],
    });
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--all" if cmd == "scan" => all = true,
            "--include-dev" => q.include_dev = true,
            "--include-estimated" => q.include_estimated = true,
            "--project" => q.projects.push(value("--project")?),
            "--min" => q.min = Some(parse_min(&value("--min")?)?),
            "--kind" => q.kinds.extend(
                value("--kind")?
                    .split(',')
                    .filter(|k| !k.is_empty())
                    .map(String::from),
            ),
            "--limit" => {
                q.limit = Some(
                    value("--limit")?
                        .parse()
                        .map_err(|_| "--limit needs a number")?,
                )
            }
            f if f.starts_with("--") => return Err(format!("unknown flag: {f}")),
            _ => positional.push(a),
        }
    }
    match cmd.as_str() {
        "findings" if positional.is_empty() => Ok(Cmd::Findings { json, q }),
        "finding" if positional.len() == 1 => {
            let id = positional[0]
                .trim_start_matches('#')
                .parse()
                .map_err(|_| "finding needs a numeric id")?;
            Ok(Cmd::Finding { id, json })
        }
        "projects" if positional.is_empty() => Ok(Cmd::Projects { json }),
        "scan" if all && !positional.is_empty() => Err("scan --all takes no paths".into()),
        "scan" => Ok(Cmd::Scan {
            json,
            paths: positional,
            all,
        }),
        _ => Err(format!(
            "unexpected arguments for {cmd}: {}",
            positional.join(" ")
        )),
    }
}

pub fn db_path() -> PathBuf {
    if let Ok(p) = std::env::var("NOVUL_DB") {
        return p.into();
    }
    dirs::data_dir()
        .unwrap_or_default()
        .join("dev.novul.app")
        .join("novul.db")
}

pub fn open_ro(db: &Path) -> Result<Connection, String> {
    if !db.exists() {
        return Err(MISSING_DB.into());
    }
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("cannot open {}: {e}", db.display()))?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    Ok(conn)
}

struct Row {
    id: i64,
    kind: String,
    group_id: String,
    aliases: Vec<String>,
    summary: String,
    score: Option<f64>,
    epss: Option<f64>,
    kev: bool,
    priority: Priority,
    ecosystem: String,
    name: String,
    installed_version: String,
    fixed_version: Option<String>,
    direct: Option<bool>,
    dev: bool,
    estimated: bool,
    project_path: String,
    fix_command: Option<String>,
    url: String,
    muted: bool,
}

impl Row {
    fn json(&self) -> Value {
        json!({
            "id": self.id, "kind": self.kind, "priority": self.priority.as_str(), "score": self.score,
            "epss": self.epss, "kev": self.kev, "group_id": self.group_id, "aliases": self.aliases,
            "summary": self.summary, "ecosystem": self.ecosystem, "name": self.name,
            "installed_version": self.installed_version, "fixed_version": self.fixed_version,
            "direct": self.direct, "dev": self.dev, "estimated": self.estimated, "project_path": self.project_path,
            "fix_command": self.fix_command, "url": self.url, "muted": self.muted,
        })
    }
}

fn load(conn: &Connection, id: Option<i64>) -> Result<Vec<Row>, String> {
    let e = |e: rusqlite::Error| format!("database error: {e}");
    let kev: HashSet<String> = match conn.prepare("SELECT cve FROM kev") {
        Ok(mut s) => s
            .query_map([], |r| r.get(0))
            .map_err(e)?
            .flatten()
            .collect(),
        Err(_) => HashSet::new(),
    };
    // Column added by the EPSS feed; absent on older databases.
    let epss = if conn.prepare("SELECT epss FROM finding LIMIT 0").is_ok() {
        "f.epss"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT f.id, f.kind, f.group_id, f.aliases, f.summary, f.score, f.malicious, f.ecosystem, f.name,
                f.installed_version, f.fixed_version, f.direct, f.dev, f.project_path, f.fix_command, f.url,
                {epss},
                EXISTS (SELECT 1 FROM mute m WHERE m.group_id=f.group_id AND m.ecosystem=f.ecosystem AND m.name=f.name),
                f.inferred
         FROM finding f WHERE f.resolved_at IS NULL AND (?1 IS NULL OR f.id = ?1)"
    );
    let mut stmt = conn.prepare(&sql).map_err(e)?;
    let rows = stmt
        .query_map([id], |r| {
            let group_id: String = r.get(2)?;
            let aliases: Vec<String> =
                serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default();
            let score: Option<f64> = r.get::<_, Option<f64>>(5)?.map(|s| (s * 10.0).round() / 10.0);
            let is_kev = kev.contains(&group_id) || aliases.iter().any(|a| kev.contains(a));
            Ok(Row {
                id: r.get(0)?,
                kind: r.get(1)?,
                priority: priority_of(r.get(6)?, is_kev, score.map(|s| s as f32)),
                kev: is_kev,
                group_id,
                aliases,
                summary: r.get(4)?,
                score,
                epss: r.get::<_, Option<f64>>(16)?.map(|e| (e * 10000.0).round() / 10000.0),
                ecosystem: r.get(7)?,
                name: r.get(8)?,
                installed_version: r.get(9)?,
                fixed_version: r.get(10)?,
                direct: r.get(11)?,
                dev: r.get(12)?,
                project_path: r.get(13)?,
                fix_command: r.get(14)?,
                url: r.get(15)?,
                muted: r.get(17)?,
                estimated: r.get(18)?,
            })
        })
        .map_err(e)?;
    rows.collect::<Result<_, _>>().map_err(e)
}

/// Absolute forms of a user-given path: as typed (made absolute) and with symlinks resolved.
fn path_forms(p: &str) -> Vec<String> {
    let p = Path::new(p);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut v = vec![abs.clone()];
    if let Ok(c) = abs.canonicalize() {
        v.push(c);
    }
    v.into_iter()
        .map(|p| p.to_string_lossy().trim_end_matches('/').to_string())
        .collect()
}

fn inside(path: &str, dir: &str) -> bool {
    path == dir || path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

/// Open, unmuted findings, most urgent first. Returns (total matching, rows after `limit`).
fn select(conn: &Connection, q: &Query) -> Result<(usize, Vec<Row>), String> {
    let dirs: Vec<String> = q.projects.iter().flat_map(|p| path_forms(p)).collect();
    let mut rows: Vec<Row> = load(conn, None)?
        .into_iter()
        .filter(|r| !r.muted)
        .filter(|r| q.min.is_none_or(|m| r.priority <= m))
        .filter(|r| {
            r.priority == Priority::Malicious
                || (r.priority == Priority::Exploited || q.include_dev || !r.dev) && (q.include_estimated || !r.estimated)
        })
        .filter(|r| q.kinds.is_empty() || q.kinds.contains(&r.kind))
        .filter(|r| {
            dirs.is_empty() && q.projects.is_empty()
                || dirs.iter().any(|d| {
                    // Either the lockfile is inside the given dir, or the agent works in a
                    // subfolder of the project whose lockfile sits higher up.
                    inside(&r.project_path, d)
                        || r.kind == "package"
                            && r.project_path.rsplit_once('/').is_some_and(|(lock_dir, _)| inside(d, lock_dir))
                })
        })
        .collect();
    let by = |x: &Option<f64>| x.unwrap_or(0.0);
    rows.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then(by(&b.epss).total_cmp(&by(&a.epss)))
            .then(by(&b.score).total_cmp(&by(&a.score)))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.project_path.cmp(&b.project_path))
    });
    let total = rows.len();
    rows.truncate(q.limit.unwrap_or(usize::MAX));
    Ok((total, rows))
}

/// (total matching, findings as JSON objects)
pub fn findings_json(db: &Path, q: &Query) -> Result<(usize, Vec<Value>), String> {
    let (total, rows) = select(&open_ro(db)?, q)?;
    Ok((total, rows.iter().map(Row::json).collect()))
}

pub fn finding_json(db: &Path, id: i64) -> Result<Value, String> {
    load(&open_ro(db)?, Some(id))?
        .first()
        .map(Row::json)
        .ok_or(format!(
            "no open finding with id {id} (it may have been fixed and rescanned)"
        ))
}

pub fn projects_json(db: &Path) -> Result<Vec<Value>, String> {
    let conn = open_ro(db)?;
    let (_, rows) = select(&conn, &Query::default())?;
    let mut counts: HashMap<String, HashMap<&str, usize>> = HashMap::new();
    for r in &rows {
        *counts
            .entry(r.project_path.clone())
            .or_default()
            .entry(r.priority.as_str())
            .or_default() += 1;
    }
    let e = |e: rusqlite::Error| format!("database error: {e}");
    let mut stmt = conn
        .prepare("SELECT lockfile_path, root, ecosystem, last_scanned_at FROM project ORDER BY root, lockfile_path")
        .map_err(e)?;
    let mut out: Vec<Value> = stmt
        .query_map([], |r| {
            let lockfile: String = r.get(0)?;
            let c = counts.get(&lockfile);
            let n = |p: &str| c.and_then(|c| c.get(p)).copied().unwrap_or(0);
            let total: usize = c.map(|c| c.values().sum()).unwrap_or(0);
            Ok(json!({
                "path": r.get::<_, String>(1)?, "lockfile": lockfile, "ecosystem": r.get::<_, String>(2)?,
                "last_scanned_at": r.get::<_, i64>(3)?, "total": total,
                "counts": {
                    "malicious": n("malicious"), "exploited": n("exploited"), "critical": n("critical"),
                    "high": n("high"), "medium": n("medium"), "low": n("low"), "unrated": n("unrated"),
                },
            }))
        })
        .map_err(e)?
        .flatten()
        .collect();
    let worst = |v: &Value| {
        PRIORITIES
            .iter()
            .position(|p| v["counts"][p].as_u64() > Some(0))
            .unwrap_or(99)
    };
    out.sort_by_key(worst); // stable: keeps path order within a priority
    Ok(out)
}

fn absolute(p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    }
}

/// Lockfile paths for files and directories (directories are searched like the app does).
pub fn resolve_lockfiles(args: &[String]) -> Result<Vec<String>, String> {
    let mut out = vec![];
    for a in args {
        let p = absolute(a);
        if p.is_file() {
            if ecosystem_for(&p.file_name().unwrap_or_default().to_string_lossy()).is_none() {
                return Err(format!("{a} is not a lockfile NoVul knows"));
            }
            out.push(p.to_string_lossy().into_owned());
        } else if p.is_dir() {
            let found = discover(&[p], &Settings::default().exclusions);
            if found.is_empty() {
                return Err(format!("no lockfiles found in {a}"));
            }
            out.extend(
                found
                    .into_iter()
                    .map(|l| l.path.to_string_lossy().into_owned()),
            );
        } else {
            return Err(format!("{a} does not exist"));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Rescan lockfiles with the worker job (same code path as the app's `--worker rescan`).
/// Returns the lockfiles scanned and the scan error text, if any.
pub fn rescan(db: &Path, args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    if !db.exists() {
        return Err(MISSING_DB.into());
    }
    let lockfiles = resolve_lockfiles(args)?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let status = std::process::Command::new(exe)
        .args(["--worker", "rescan", "--db"])
        .arg(db)
        .arg("--lockfiles")
        .args(&lockfiles)
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("cannot start scan: {e}"))?;
    if !status.success() {
        return Err(format!("scan failed ({status})"));
    }
    let err = open_ro(db)
        .ok()
        .and_then(|c| {
            c.query_row("SELECT value FROM meta WHERE key='last_error'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
        })
        .filter(|e| !e.is_empty());
    Ok((lockfiles, err))
}

/// A full scan the way the app runs one: the `full` worker job, then `secrets`. Progress goes to
/// stderr when it is a terminal. Returns the scan error text, if any.
pub fn full_scan(db: &Path) -> Result<Option<String>, String> {
    use std::io::{BufRead, IsTerminal, Write};
    let conn = open_ro(db)?;
    let roots: Vec<String> = conn
        .query_row("SELECT value FROM meta WHERE key='settings'", [], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| serde_json::from_value(v["roots"].clone()).ok())
        .unwrap_or_default();
    drop(conn);
    if roots.is_empty() {
        return Err("No folders to scan yet: choose them in NoVul (Settings > Folders to watch).".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let tty = std::io::stderr().is_terminal();
    for job in ["full", "secrets"] {
        let mut child = std::process::Command::new(&exe)
            .args(["--worker", job, "--db"])
            .arg(db)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start scan: {e}"))?;
        let stdout = child.stdout.take().ok_or("no scan output")?;
        for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
            if let (true, Some(crate::worker::Event::Progress(p, phase))) = (tty, crate::worker::Event::parse(&line)) {
                let mut err = std::io::stderr();
                let _ = write!(err, "\r\x1b[2K{}", progress_line(phase.as_deref(), p));
                let _ = err.flush();
            }
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        if tty {
            eprint!("\r\x1b[2K");
        }
        if !status.success() {
            return Err(format!("{job} scan failed ({status})"));
        }
    }
    Ok(open_ro(db)?
        .query_row("SELECT value FROM meta WHERE key='last_error'", [], |r| r.get::<_, String>(0))
        .ok()
        .filter(|e| !e.is_empty()))
}

fn progress_line(phase: Option<&str>, p: Option<(usize, usize)>) -> String {
    match (phase, p) {
        (Some("machine"), _) => "Checking this Mac (Homebrew, runtimes, tools)…".into(),
        (Some("secrets"), Some((d, t))) if t > 0 => format!("Looking for exposed secrets: {d} of {t} folders…"),
        (Some("secrets"), _) => "Looking for exposed secrets…".into(),
        (_, Some((d, t))) if t > 0 => format!("Checking {d} of {t} lockfiles…"),
        _ => "Looking for lockfiles…".into(),
    }
}

// ---------- human output ----------

fn tilde(p: &str) -> String {
    match dirs::home_dir() {
        Some(h) if inside(p, &h.to_string_lossy()) => {
            format!("~{}", &p[h.to_string_lossy().len()..])
        }
        _ => p.to_string(),
    }
}

fn location(r: &Row) -> String {
    if r.kind == "package" {
        tilde(
            Path::new(&r.project_path)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .as_deref()
                .unwrap_or(&r.project_path),
        )
    } else {
        r.project_path.clone()
    }
}

fn package_cell(r: &Row) -> String {
    let fix = r.fixed_version.as_deref().unwrap_or("no fix");
    let who = match (r.kind.as_str(), r.direct) {
        ("secret", _) => "secret, value not shown".to_string(),
        (_, Some(true)) => "direct".into(),
        (_, Some(false)) => "transitive".into(),
        _ => r.kind.clone(),
    };
    let dev = if r.dev { ", dev" } else { "" };
    let what = if r.kind == "secret" {
        format!("[secret] {} {}", r.name, r.installed_version)
    } else {
        format!("{}@{}", r.name, r.installed_version)
    };
    format!("{what} → {fix} ({who}{dev})")
}

fn table(rows: &[Row]) -> String {
    let cells: Vec<[String; 5]> = rows
        .iter()
        .map(|r| {
            [
                r.priority.as_str().to_string(),
                package_cell(r),
                r.group_id.clone(),
                format!("#{}", r.id),
                location(r),
            ]
        })
        .collect();
    let width = |i: usize| {
        cells
            .iter()
            .map(|c| c[i].chars().count())
            .max()
            .unwrap_or(0)
            .max(["PRIORITY", "PACKAGE → FIXED", "ADVISORY", "ID", "PROJECT"][i].len())
    };
    let w: Vec<usize> = (0..4).map(width).collect();
    let line = |c: [&str; 5]| {
        format!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {}",
            c[0],
            c[1],
            c[2],
            c[3],
            c[4],
            w0 = w[0],
            w1 = w[1],
            w2 = w[2],
            w3 = w[3]
        )
    };
    let mut out = vec![line([
        "PRIORITY",
        "PACKAGE → FIXED",
        "ADVISORY",
        "ID",
        "PROJECT",
    ])];
    out.extend(
        cells
            .iter()
            .map(|c| line([&c[0], &c[1], &c[2], &c[3], &c[4]])),
    );
    out.join("\n")
}

fn print_findings(total: usize, rows: &[Row], json: bool) {
    if json {
        out!("{}", Value::Array(rows.iter().map(Row::json).collect()));
    } else if rows.is_empty() {
        out!("No known vulnerabilities found (in what NoVul has scanned).");
    } else {
        out!("{}", table(rows));
        if total > rows.len() {
            out!(
                "\n{} of {total} shown; use --limit to see more.",
                rows.len()
            );
        }
    }
}

fn print_detail(r: &Row) {
    out!(
        "#{} {} {}  {}",
        r.id,
        r.priority.as_str().to_uppercase(),
        r.group_id,
        r.summary
    );
    out!("  {}", package_cell(r));
    out!("  project: {}", r.project_path);
    if r.kev {
        out!("  actively exploited (CISA KEV)");
    }
    if r.estimated {
        out!("  version estimated from requirements.txt; the installed version may differ (pin with a lockfile)");
    }
    if let Some(s) = r.score {
        out!(
            "  score:   {s}{}",
            r.epss
                .map(|e| format!("  epss: {e:.3}"))
                .unwrap_or_default()
        );
    }
    if !r.aliases.is_empty() {
        out!("  aliases: {}", r.aliases.join(", "));
    }
    out!("  advisory: {}", r.url);
    match &r.fix_command {
        Some(c) => out!("  fix (review first, run in the project folder): {c}"),
        None => out!("  fix: none suggested"),
    }
}

fn scan_scope(lockfiles: &[String]) -> Query {
    Query {
        projects: lockfiles.to_vec(),
        ..Default::default()
    }
}

fn run(cmd: Cmd) -> Result<(), String> {
    let db = db_path();
    match cmd {
        Cmd::Help => out!("{HELP}"),
        Cmd::Version => out!("novul {}", env!("CARGO_PKG_VERSION")),
        Cmd::Mcp => unreachable!(),
        Cmd::Findings { json, q } => {
            let (total, rows) = select(&open_ro(&db)?, &q)?;
            print_findings(total, &rows, json);
        }
        Cmd::Finding { id, json } => {
            let rows = load(&open_ro(&db)?, Some(id))?;
            let r = rows.first().ok_or(format!(
                "no open finding with id {id} (it may have been fixed and rescanned)"
            ))?;
            if json {
                out!("{}", r.json());
            } else {
                print_detail(r);
            }
        }
        Cmd::Projects { json } => {
            let projects = projects_json(&db)?;
            if json {
                out!("{}", Value::Array(projects));
            } else {
                let with: Vec<_> = projects.iter().filter(|p| p["total"] != 0).collect();
                for p in &with {
                    let c = &p["counts"];
                    let parts: Vec<String> = PRIORITIES
                        .iter()
                        .filter(|k| c[**k].as_u64() > Some(0))
                        .map(|k| format!("{} {k}", c[*k]))
                        .collect();
                    out!(
                        "{}  {}",
                        tilde(p["path"].as_str().unwrap_or("")),
                        parts.join(", ")
                    );
                }
                out!(
                    "{} projects scanned, {} with open findings.",
                    projects.len(),
                    with.len()
                );
            }
        }
        Cmd::Scan { json, all: true, .. } => {
            if let Some(e) = full_scan(&db)? {
                eout!("warning: {e}");
            }
            let limit = if json { None } else { Some(20) };
            let (total, rows) = select(&open_ro(&db)?, &Query { limit, ..Query::default() })?;
            if json || rows.is_empty() {
                print_findings(total, &rows, json);
            } else {
                out!("{}\n\n{} of {total} shown; run `novul findings` for the rest.", table(&rows), rows.len());
            }
        }
        Cmd::Scan { json, paths, .. } => {
            let paths = if paths.is_empty() {
                vec![".".to_string()]
            } else {
                paths
            };
            let (lockfiles, err) = rescan(&db, &paths)?;
            if let Some(e) = err {
                eout!("warning: {e}");
            }
            let (total, rows) = select(&open_ro(&db)?, &scan_scope(&lockfiles))?;
            if !json {
                out!("Scanned {} lockfile(s).", lockfiles.len());
            }
            print_findings(total, &rows, json);
        }
    }
    Ok(())
}

/// `args[0]` is the subcommand. Returns the exit code.
pub fn main(args: Vec<String>) -> i32 {
    let cmd = match parse(&args) {
        Ok(c) => c,
        Err(e) => {
            eout!("novul: {e}\nTry `novul help`.");
            return 2;
        }
    };
    if cmd == Cmd::Mcp {
        return crate::mcp::main();
    }
    match run(cmd) {
        Ok(()) => 0,
        Err(e) => {
            eout!("{e}");
            if e == MISSING_DB {
                2
            } else {
                1
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::model::Lockfile;
    use crate::store::{FindingInput, Store};

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    pub fn input(dir: &str, name: &str, group: &str, score: f32, dev: bool) -> FindingInput {
        FindingInput {
            kind: "package",
            group_id: group.into(),
            project_name: dir.into(),
            project_path: format!("/w/{dir}/package-lock.json"),
            ecosystem: "npm".into(),
            name: name.into(),
            installed_version: "1.0.0".into(),
            fixed_version: Some("1.0.1".into()),
            direct: Some(true),
            dev,
            inferred: false,
            fix_command: Some(format!("npm install {name}@1.0.1")),
            aliases: vec![],
            summary: "bad".into(),
            score: Some(score),
            malicious: false,
            url: "https://osv.dev/x".into(),
        }
    }

    /// Projects /w/app (critical lodash, high minimist, dev jest) and /w/app2 (critical ws).
    pub fn temp_db() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("novul.db");
        let s = Store::open(&db).unwrap();
        for (d, f) in [
            (
                "app",
                vec![
                    input("app", "lodash", "CVE-1", 9.8, false),
                    input("app", "minimist", "CVE-2", 7.5, false),
                    input("app", "jest", "CVE-3", 9.0, true),
                ],
            ),
            ("app2", vec![input("app2", "ws", "CVE-4", 9.1, false)]),
        ] {
            let lf = Lockfile {
                path: format!("/w/{d}/package-lock.json").into(),
                root: format!("/w/{d}").into(),
                ecosystem: "npm".into(),
                manifest: None,
            };
            s.write_project(&lf, &[], &f, 100).unwrap();
        }
        let id = load(&open_ro(&db).unwrap(), None)
            .unwrap()
            .iter()
            .find(|r| r.name == "minimist")
            .unwrap()
            .id;
        s.set_muted(id, true).unwrap();
        (dir, db)
    }

    #[test]
    fn parses_findings_flags() {
        let c = parse(&args("findings --json --project /w/app --min=high --include-dev --kind package,brew --limit 5")).unwrap();
        let Cmd::Findings { json, q } = c else {
            panic!()
        };
        assert!(json);
        assert_eq!(q.projects, ["/w/app"]);
        assert_eq!(q.min, Some(Priority::High));
        assert!(q.include_dev);
        assert!(!q.include_estimated);
        assert_eq!(q.kinds, ["package", "brew"]);
        assert_eq!(q.limit, Some(5));
    }

    #[test]
    fn parses_other_commands_and_rejects_junk() {
        assert_eq!(
            parse(&args("finding #12 --json")).unwrap(),
            Cmd::Finding { id: 12, json: true }
        );
        assert_eq!(
            parse(&args("scan a b")).unwrap(),
            Cmd::Scan {
                json: false,
                paths: args("a b"),
                all: false
            }
        );
        assert_eq!(parse(&args("scan --all --json")).unwrap(), Cmd::Scan { json: true, paths: vec![], all: true });
        assert!(parse(&args("scan --all ./app")).is_err(), "--all scans the configured folders, not paths");
        assert!(parse(&args("findings --all")).is_err());
        assert_eq!(parse(&args("--version")).unwrap(), Cmd::Version);
        assert!(parse(&args("findings --min urgent")).is_err());
        assert!(parse(&args("findings --limit")).is_err());
        assert!(parse(&args("findings --bogus")).is_err());
        assert!(parse(&args("finding abc")).is_err());
        assert!(parse(&args("nope")).is_err());
    }

    #[test]
    fn full_scan_needs_folders_and_a_database() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(full_scan(&dir.path().join("none.db")).unwrap_err(), MISSING_DB);
        let db = dir.path().join("novul.db");
        crate::store::Store::open(&db).unwrap();
        assert!(full_scan(&db).unwrap_err().starts_with("No folders to scan yet"));
    }

    #[test]
    fn findings_filter_by_project_dir_not_prefix_sibling() {
        let (_d, db) = temp_db();
        let q = |p: &str| Query {
            projects: vec![p.into()],
            ..Default::default()
        };
        let (total, rows) = findings_json(&db, &q("/w/app")).unwrap();
        assert_eq!(
            (total, rows.len()),
            (1, 1),
            "muted minimist and dev jest are hidden; app2 is a different dir"
        );
        assert_eq!(rows[0]["name"], "lodash");
        assert_eq!(
            findings_json(&db, &q("/w/app/package-lock.json"))
                .unwrap()
                .0,
            1
        );
        assert_eq!(findings_json(&db, &q("/w")).unwrap().0, 2);
        assert_eq!(findings_json(&db, &q("/w/app/src/components")).unwrap().0, 1, "agent in a subfolder");
        assert_eq!(findings_json(&db, &q("/nowhere")).unwrap().0, 0);
    }

    #[test]
    fn dev_min_limit_and_order() {
        let (_d, db) = temp_db();
        let all = Query {
            include_dev: true,
            ..Default::default()
        };
        let (_, rows) = findings_json(&db, &all).unwrap();
        let names: Vec<_> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            ["lodash", "ws", "jest"],
            "critical by score, muted minimist excluded"
        );
        let (total, rows) = findings_json(
            &db,
            &Query {
                limit: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!((total, rows.len()), (2, 1));
        let m = Query {
            min: Some(Priority::Malicious),
            ..Default::default()
        };
        assert_eq!(findings_json(&db, &m).unwrap().0, 0);
    }

    #[test]
    fn estimated_findings_hidden_unless_included_but_malicious_always_show() {
        let (_d, db) = temp_db();
        let s = Store::open(&db).unwrap();
        let mut est = input("est", "requests", "CVE-10", 9.8, false);
        est.inferred = true;
        let mut mal = input("est", "evil", "MAL-1", 9.8, false);
        mal.inferred = true;
        mal.malicious = true;
        let lf = Lockfile {
            path: "/w/est/requirements.txt".into(),
            root: "/w/est".into(),
            ecosystem: "PyPI".into(),
            manifest: None,
        };
        s.write_project(&lf, &[], &[est, mal], 100).unwrap();
        let q = |include_estimated| Query {
            projects: vec!["/w/est".into()],
            include_estimated,
            ..Default::default()
        };
        let (total, rows) = findings_json(&db, &q(false)).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0]["name"], "evil");
        assert_eq!(rows[0]["estimated"], true);
        let (total, rows) = findings_json(&db, &q(true)).unwrap();
        assert_eq!(total, 2);
        assert!(rows.iter().all(|r| r["estimated"] == true));
        let (_, rows) = findings_json(&db, &Query::default()).unwrap();
        assert!(rows.iter().filter(|r| r["name"] != "evil").all(|r| r["estimated"] == false));
    }

    #[test]
    fn finding_by_id_and_projects() {
        let (_d, db) = temp_db();
        let (_, rows) = findings_json(&db, &Query::default()).unwrap();
        let id = rows[0]["id"].as_i64().unwrap();
        assert_eq!(
            finding_json(&db, id).unwrap()["fix_command"],
            "npm install lodash@1.0.1"
        );
        assert!(finding_json(&db, 9999).is_err());
        let p = projects_json(&db).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0]["counts"]["critical"], 1);
    }

    #[test]
    fn missing_db_message() {
        assert_eq!(
            findings_json(Path::new("/nonexistent/novul.db"), &Query::default()).unwrap_err(),
            MISSING_DB
        );
    }
}
