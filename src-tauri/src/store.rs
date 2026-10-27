// SQLite persistence. Everything is read on demand; nothing is cached in memory.

use crate::model::*;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

pub type R<T> = rusqlite::Result<T>;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS project (
  id INTEGER PRIMARY KEY,
  lockfile_path TEXT NOT NULL UNIQUE,
  root TEXT NOT NULL,
  manifest_path TEXT,
  ecosystem TEXT NOT NULL,
  last_scanned_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS location (
  project_id INTEGER NOT NULL,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  direct INTEGER,
  dev INTEGER NOT NULL,
  inferred INTEGER NOT NULL,
  PRIMARY KEY (project_id, ecosystem, name, version)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS location_key ON location (ecosystem, name, version);
CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  group_id TEXT NOT NULL,
  project_id INTEGER,
  project_name TEXT NOT NULL,
  project_path TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  installed_version TEXT NOT NULL,
  fixed_version TEXT,
  direct INTEGER,
  dev INTEGER NOT NULL,
  inferred INTEGER NOT NULL,
  fix_command TEXT,
  aliases TEXT NOT NULL,
  summary TEXT NOT NULL,
  score REAL,
  malicious INTEGER NOT NULL,
  url TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  resolved_at INTEGER,
  notified_at INTEGER,
  UNIQUE (kind, group_id, project_path, ecosystem, name)
);
CREATE INDEX IF NOT EXISTS finding_project ON finding (project_id);
CREATE TABLE IF NOT EXISTS package_ids (
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  ids TEXT NOT NULL,
  PRIMARY KEY (ecosystem, name, version)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mute (
  group_id TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (group_id, ecosystem, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
";

pub struct Store {
    conn: Mutex<Connection>,
}

/// A package row of one lockfile.
pub struct LocationRow {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub direct: Option<bool>,
    pub dev: bool,
    pub inferred: bool,
}

/// What a scan found; `kind`, project and identity columns make up the finding's identity.
#[derive(Clone)]
pub struct FindingInput {
    pub kind: &'static str,
    pub group_id: String,
    pub project_name: String,
    pub project_path: String,
    pub ecosystem: String,
    pub name: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub direct: Option<bool>,
    pub dev: bool,
    pub inferred: bool,
    pub fix_command: Option<String>,
    pub aliases: Vec<String>,
    pub summary: String,
    pub score: Option<f32>,
    pub malicious: bool,
    pub url: String,
}

/// Malicious > actively exploited (KEV) > CVSS band.
pub fn priority_of(malicious: bool, kev: bool, score: Option<f32>) -> Priority {
    if malicious {
        Priority::Malicious
    } else if kev {
        Priority::Exploited
    } else {
        Priority::from_score(score)
    }
}

/// Counts exclude muted, (unless `show_dev`) dev and (unless `show_estimated`) estimated-version
/// findings. Malicious ones always count; actively exploited ones count even when dev-only, but an
/// estimated version is often wrong, so an estimated exploited finding stays hidden. Resolved ones are never loaded.
pub fn counts_of(findings: &[FindingView], show_dev: bool, show_estimated: bool) -> Counts {
    let mut c = Counts::default();
    for f in findings.iter().filter(|f| countable(f, show_dev, show_estimated)) {
        match f.priority {
            Priority::Malicious => c.malicious += 1,
            Priority::Exploited => c.exploited += 1,
            Priority::Critical => c.critical += 1,
            Priority::High => c.high += 1,
            Priority::Medium => c.medium += 1,
            Priority::Low => c.low += 1,
            Priority::Unrated => c.unrated += 1,
        }
    }
    c
}

pub fn countable(f: &FindingView, show_dev: bool, show_estimated: bool) -> bool {
    !f.muted
        && (f.priority == Priority::Malicious
            || ((f.priority == Priority::Exploited || show_dev || !f.dev) && (show_estimated || !f.inferred)))
}

/// Columns added after the first release; `CREATE TABLE IF NOT EXISTS` doesn't touch existing DBs.
fn migrate(conn: &Connection) -> R<()> {
    let has_epss = conn
        .prepare("PRAGMA table_info(finding)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .any(|n| n.is_ok_and(|n| n == "epss"));
    if !has_epss {
        conn.execute_batch("ALTER TABLE finding ADD COLUMN epss REAL")?;
    }
    Ok(())
}

fn cve_ids(group_id: &str, aliases_json: &str) -> Vec<String> {
    let aliases: Vec<String> = serde_json::from_str(aliases_json).unwrap_or_default();
    std::iter::once(group_id.to_string())
        .chain(aliases)
        .filter(|a| a.starts_with("CVE-") && a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .collect()
}

fn scope_ids(tx: &rusqlite::Transaction, sql: &str, p: impl rusqlite::Params) -> R<HashSet<i64>> {
    tx.prepare_cached(sql)?
        .query_map(p, |r| r.get(0))?
        .collect()
}

impl Store {
    pub fn open(path: &Path) -> R<Store> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA cache_size=-2000; PRAGMA temp_store=FILE;",
        )?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---------- meta / settings ----------

    pub fn meta(&self, key: &str) -> Option<String> {
        self.db()
            .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    pub fn meta_i64(&self, key: &str) -> Option<i64> {
        self.meta(key)?.parse().ok()
    }

    /// Drop SQLite's page cache so an idle app doesn't hold scan-time memory.
    pub fn shrink_memory(&self) {
        let _ = self.db().execute_batch("PRAGMA shrink_memory");
    }

    pub fn set_meta(&self, key: &str, value: &str) -> R<()> {
        self.db().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [key, value],
        )?;
        Ok(())
    }

    pub fn clear_meta(&self, key: &str) -> R<()> {
        self.db().execute("DELETE FROM meta WHERE key=?1", [key])?;
        Ok(())
    }

    /// Defaults have no folders: onboarding asks. An install that predates that (projects but no
    /// saved settings) keeps the folder it was scanning, saved once.
    pub fn settings(&self) -> Settings {
        if let Some(s) = self.meta("settings").and_then(|s| serde_json::from_str(&s).ok()) {
            return s;
        }
        let mut s = Settings::default();
        if self.project_count() > 0 {
            if let Some(home) = dirs::home_dir() {
                s.roots = vec![home.join("Workspace").to_string_lossy().into_owned()];
                let _ = self.set_settings(&s);
            }
        }
        s
    }

    pub fn set_settings(&self, s: &Settings) -> R<()> {
        let json = serde_json::to_string(s).unwrap_or_default();
        self.set_meta("settings", &json)
    }

    pub fn runtimes(&self) -> Vec<RuntimeStatus> {
        self.meta("runtimes")
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn set_runtimes(&self, r: &[RuntimeStatus]) -> R<()> {
        self.set_meta("runtimes", &serde_json::to_string(r).unwrap_or_default())
    }

    // ---------- projects / findings (writes) ----------

    pub fn project_count(&self) -> usize {
        self.db()
            .query_row("SELECT COUNT(*) FROM project", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    fn upsert_findings(
        tx: &rusqlite::Transaction,
        project_id: Option<i64>,
        inputs: &[FindingInput],
        now: i64,
    ) -> R<HashSet<i64>> {
        let mut seen = HashSet::new();
        let mut stmt = tx.prepare_cached(
            "INSERT INTO finding (kind, group_id, project_id, project_name, project_path, ecosystem, name,
               installed_version, fixed_version, direct, dev, inferred, fix_command, aliases, summary, score,
               malicious, url, first_seen_at, last_seen_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?19)
             ON CONFLICT(kind, group_id, project_path, ecosystem, name) DO UPDATE SET
               project_id=excluded.project_id, project_name=excluded.project_name,
               installed_version=excluded.installed_version, fixed_version=excluded.fixed_version,
               direct=excluded.direct, dev=excluded.dev, inferred=excluded.inferred,
               fix_command=excluded.fix_command, aliases=excluded.aliases, summary=excluded.summary,
               score=excluded.score, malicious=excluded.malicious, url=excluded.url,
               last_seen_at=excluded.last_seen_at, resolved_at=NULL
             RETURNING id",
        )?;
        // An advisory's main id can change (a GHSA gets a CVE id), so a row stored under one of the
        // new aliases is the same finding: keep its id, first-seen time and mute.
        let mut rekey = tx.prepare_cached(
            "UPDATE finding SET group_id=?1 WHERE id = (
               SELECT id FROM finding WHERE kind=?2 AND project_path=?3 AND ecosystem=?4 AND name=?5
                 AND group_id IN (SELECT value FROM json_each(?6))
                 AND NOT EXISTS (SELECT 1 FROM finding g WHERE g.kind=?2 AND g.group_id=?1 AND g.project_path=?3 AND g.ecosystem=?4 AND g.name=?5)
               ORDER BY resolved_at IS NOT NULL, id LIMIT 1)",
        )?;
        let mut rekey_mute = tx.prepare_cached(
            "UPDATE OR IGNORE mute SET group_id=?1 WHERE ecosystem=?2 AND name=?3 AND group_id IN (SELECT value FROM json_each(?4))",
        )?;
        for f in inputs {
            let aliases = serde_json::to_string(&f.aliases).unwrap_or_else(|_| "[]".into());
            rekey.execute(params![f.group_id, f.kind, f.project_path, f.ecosystem, f.name, aliases])?;
            rekey_mute.execute(params![f.group_id, f.ecosystem, f.name, aliases])?;
            let id: i64 = stmt.query_row(
                params![
                    f.kind,
                    f.group_id,
                    project_id,
                    f.project_name,
                    f.project_path,
                    f.ecosystem,
                    f.name,
                    f.installed_version,
                    f.fixed_version,
                    f.direct,
                    f.dev,
                    f.inferred,
                    f.fix_command,
                    aliases,
                    f.summary,
                    f.score,
                    f.malicious,
                    f.url,
                    now
                ],
                |r| r.get(0),
            )?;
            seen.insert(id);
        }
        Ok(seen)
    }

    fn resolve(tx: &rusqlite::Transaction, ids: impl Iterator<Item = i64>, now: i64) -> R<()> {
        let mut stmt = tx.prepare_cached("UPDATE finding SET resolved_at=?1 WHERE id=?2")?;
        for id in ids {
            stmt.execute(params![now, id])?;
        }
        Ok(())
    }

    /// Replace one lockfile's locations, upsert its findings, resolve its findings not seen now.
    pub fn write_project(
        &self,
        lf: &Lockfile,
        locations: &[LocationRow],
        findings: &[FindingInput],
        now: i64,
    ) -> R<()> {
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let path = lf.path.to_string_lossy();
        let manifest = lf
            .manifest
            .as_ref()
            .map(|m| m.to_string_lossy().into_owned());
        let project_id: i64 = tx.query_row(
            "INSERT INTO project (lockfile_path, root, manifest_path, ecosystem, last_scanned_at)
             VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(lockfile_path) DO UPDATE SET root=excluded.root, manifest_path=excluded.manifest_path,
               ecosystem=excluded.ecosystem, last_scanned_at=excluded.last_scanned_at
             RETURNING id",
            params![path, lf.root.to_string_lossy(), manifest, lf.ecosystem, now],
            |r| r.get(0),
        )?;
        tx.execute("DELETE FROM location WHERE project_id=?1", [project_id])?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO location (project_id, ecosystem, name, version, direct, dev, inferred)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
            )?;
            for l in locations {
                stmt.execute(params![
                    project_id,
                    l.ecosystem,
                    l.name,
                    l.version,
                    l.direct,
                    l.dev,
                    l.inferred
                ])?;
            }
        }
        let seen = Self::upsert_findings(&tx, Some(project_id), findings, now)?;
        let open = scope_ids(
            &tx,
            "SELECT id FROM finding WHERE project_id=?1 AND resolved_at IS NULL",
            [project_id],
        )?;
        Self::resolve(&tx, open.difference(&seen).copied(), now)?;
        tx.commit()
    }

    /// Findings of a non-lockfile kind ('brew' | 'runtime'): upsert, resolve the rest of that kind.
    pub fn sync_kind(&self, kind: &str, findings: &[FindingInput], now: i64) -> R<()> {
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let seen = Self::upsert_findings(&tx, None, findings, now)?;
        let open = scope_ids(
            &tx,
            "SELECT id FROM finding WHERE kind=?1 AND resolved_at IS NULL",
            [kind],
        )?;
        Self::resolve(&tx, open.difference(&seen).copied(), now)?;
        tx.commit()
    }

    /// Drop projects whose lockfile is gone and resolve their findings.
    pub fn remove_projects(&self, paths: &[String], now: i64) -> R<()> {
        let mut conn = self.db();
        let tx = conn.transaction()?;
        for p in paths {
            let id: Option<i64> = tx
                .query_row("SELECT id FROM project WHERE lockfile_path=?1", [p], |r| {
                    r.get(0)
                })
                .optional()?;
            let Some(id) = id else { continue };
            tx.execute(
                "UPDATE finding SET resolved_at=?2 WHERE project_id=?1 AND resolved_at IS NULL",
                params![id, now],
            )?;
            tx.execute("DELETE FROM location WHERE project_id=?1", [id])?;
            tx.execute("DELETE FROM project WHERE id=?1", [id])?;
        }
        tx.commit()
    }

    pub fn project_paths(&self) -> Vec<String> {
        let conn = self.db();
        let Ok(mut stmt) = conn.prepare("SELECT lockfile_path FROM project") else {
            return vec![];
        };
        stmt.query_map([], |r| r.get(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    pub fn lockfile(&self, path: &str) -> Option<Lockfile> {
        self.db()
            .query_row(
                "SELECT lockfile_path, root, ecosystem, manifest_path FROM project WHERE lockfile_path=?1",
                [path],
                |r| {
                    Ok(Lockfile {
                        path: PathBuf::from(r.get::<_, String>(0)?),
                        root: PathBuf::from(r.get::<_, String>(1)?),
                        ecosystem: r.get(2)?,
                        manifest: r.get::<_, Option<String>>(3)?.map(PathBuf::from),
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    // ---------- OSV baseline ----------

    /// Next page of distinct installed package keys, after `after` in sort order.
    pub fn keys_after(&self, after: Option<&PackageKey>, limit: usize) -> R<Vec<PackageKey>> {
        let conn = self.db();
        let (e, n, v) = after
            .map(|k| (k.ecosystem.as_str(), k.name.as_str(), k.version.as_str()))
            .unwrap_or(("", "", ""));
        let mut stmt = conn.prepare_cached(
            "SELECT DISTINCT ecosystem, name, version FROM location
             WHERE (ecosystem, name, version) > (?1, ?2, ?3)
             ORDER BY ecosystem, name, version LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![e, n, v, limit as i64], |r| {
            Ok(PackageKey {
                ecosystem: r.get(0)?,
                name: r.get(1)?,
                version: r.get(2)?,
            })
        })?;
        rows.collect()
    }

    pub fn package_ids_count(&self) -> usize {
        self.db()
            .query_row("SELECT COUNT(*) FROM package_ids", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize
    }

    pub fn package_ids(&self, k: &PackageKey) -> Option<Vec<String>> {
        let json: Option<String> = self
            .db()
            .query_row(
                "SELECT ids FROM package_ids WHERE ecosystem=?1 AND name=?2 AND version=?3",
                [&k.ecosystem, &k.name, &k.version],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        json.and_then(|j| serde_json::from_str(&j).ok())
    }

    pub fn set_package_ids<'a>(
        &self,
        items: impl Iterator<Item = (&'a PackageKey, &'a Vec<String>)>,
    ) -> R<()> {
        let mut conn = self.db();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO package_ids (ecosystem, name, version, ids) VALUES (?1,?2,?3,?4)",
            )?;
            for (k, ids) in items {
                let json = serde_json::to_string(ids).unwrap_or_else(|_| "[]".into());
                stmt.execute(params![k.ecosystem, k.name, k.version, json])?;
            }
        }
        tx.commit()
    }

    pub fn prune_package_ids(&self) -> R<()> {
        self.db().execute(
            "DELETE FROM package_ids WHERE NOT EXISTS (SELECT 1 FROM location l
               WHERE l.ecosystem=package_ids.ecosystem AND l.name=package_ids.name AND l.version=package_ids.version)",
            [],
        )?;
        Ok(())
    }

    /// Lockfiles that contain this exact package version.
    pub fn lockfiles_with(&self, k: &PackageKey) -> Vec<String> {
        let conn = self.db();
        let Ok(mut stmt) = conn.prepare_cached(
            "SELECT p.lockfile_path FROM location l JOIN project p ON p.id = l.project_id
             WHERE l.ecosystem=?1 AND l.name=?2 AND l.version=?3",
        ) else {
            return vec![];
        };
        stmt.query_map([&k.ecosystem, &k.name, &k.version], |r| r.get(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    // ---------- KEV ----------

    pub fn replace_kev(&self, cves: &HashSet<String>) -> R<()> {
        let mut conn = self.db();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM kev", [])?;
        {
            let mut stmt = tx.prepare_cached("INSERT OR IGNORE INTO kev (cve) VALUES (?1)")?;
            for c in cves {
                stmt.execute([c])?;
            }
        }
        tx.commit()
    }

    fn kev_set(conn: &Connection) -> HashSet<String> {
        let Ok(mut stmt) = conn.prepare_cached("SELECT cve FROM kev") else {
            return HashSet::new();
        };
        stmt.query_map([], |r| r.get(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    // ---------- EPSS ----------

    /// Distinct CVE ids (group id or alias) of open findings.
    pub fn open_cves(&self) -> Vec<String> {
        let conn = self.db();
        let Ok(mut stmt) = conn.prepare_cached("SELECT group_id, aliases FROM finding WHERE resolved_at IS NULL") else {
            return vec![];
        };
        let rows: Vec<(String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default();
        let set: std::collections::BTreeSet<String> = rows.iter().flat_map(|(g, a)| cve_ids(g, a)).collect();
        set.into_iter().collect()
    }

    /// Store the highest EPSS among each finding's CVEs; findings with no CVE in `epss` keep their value.
    pub fn set_epss(&self, epss: &std::collections::HashMap<String, f32>) -> R<()> {
        let mut conn = self.db();
        let tx = conn.transaction()?;
        let rows: Vec<(i64, String, String)> = tx
            .prepare_cached("SELECT id, group_id, aliases FROM finding")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<R<_>>()?;
        {
            let mut stmt = tx.prepare_cached("UPDATE finding SET epss=?1 WHERE id=?2")?;
            for (id, group_id, aliases) in rows {
                let best = cve_ids(&group_id, &aliases).iter().filter_map(|c| epss.get(c)).copied().reduce(f32::max);
                if let Some(e) = best {
                    stmt.execute(params![e, id])?;
                }
            }
        }
        tx.commit()
    }

    // ---------- reads ----------

    fn query_findings(&self, extra: &str) -> R<Vec<FindingView>> {
        let conn = self.db();
        let kev = Self::kev_set(&conn);
        let sql = format!(
            "SELECT f.id, f.kind, f.group_id, f.aliases, f.summary, f.score, f.malicious, f.ecosystem, f.name,
                    f.installed_version, f.fixed_version, f.direct, f.dev, f.inferred, f.project_path,
                    f.project_name, f.fix_command, f.url, f.first_seen_at,
                    EXISTS (SELECT 1 FROM mute m WHERE m.group_id=f.group_id AND m.ecosystem=f.ecosystem AND m.name=f.name),
                    f.epss
             FROM finding f WHERE f.resolved_at IS NULL {extra}"
        );
        let mut stmt = conn.prepare_cached(&sql)?;
        let rows = stmt.query_map([], |r| {
            let group_id: String = r.get(2)?;
            let aliases: Vec<String> =
                serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default();
            let score: Option<f32> = r.get::<_, Option<f64>>(5)?.map(|s| s as f32);
            let is_kev = kev.contains(&group_id) || aliases.iter().any(|a| kev.contains(a));
            Ok(FindingView {
                id: r.get(0)?,
                kind: r.get(1)?,
                priority: priority_of(r.get(6)?, is_kev, score),
                kev: is_kev,
                group_id,
                aliases,
                summary: r.get(4)?,
                score,
                ecosystem: r.get(7)?,
                name: r.get(8)?,
                installed_version: r.get(9)?,
                fixed_version: r.get(10)?,
                direct: r.get(11)?,
                dev: r.get(12)?,
                inferred: r.get(13)?,
                project_path: r.get(14)?,
                project_name: r.get(15)?,
                fix_command: r.get(16)?,
                url: r.get(17)?,
                first_seen_at: r.get(18)?,
                muted: r.get(19)?,
                epss: r.get::<_, Option<f64>>(20)?.map(|e| e as f32),
            })
        })?;
        let mut v: Vec<FindingView> = rows.collect::<R<_>>()?;
        v.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| b.epss.partial_cmp(&a.epss).unwrap_or(std::cmp::Ordering::Equal))
                .then(
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.project_name.cmp(&b.project_name))
        });
        Ok(v)
    }

    /// All unresolved findings (muted ones included), most urgent first.
    pub fn open_findings(&self) -> R<Vec<FindingView>> {
        self.query_findings("")
    }

    /// One open finding by id (for apply-fix).
    pub fn finding(&self, id: i64) -> R<Option<FindingView>> {
        Ok(self.query_findings(&format!("AND f.id={id}"))?.into_iter().next())
    }

    pub fn unnotified(&self) -> R<Vec<FindingView>> {
        self.query_findings("AND f.notified_at IS NULL")
    }

    pub fn mark_notified(&self, ids: &[i64], now: i64) -> R<()> {
        let mut conn = self.db();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("UPDATE finding SET notified_at=?1 WHERE id=?2")?;
            for id in ids {
                stmt.execute(params![now, id])?;
            }
        }
        tx.commit()
    }

    pub fn set_muted(&self, finding_id: i64, muted: bool) -> R<()> {
        let conn = self.db();
        let sql = if muted {
            "INSERT OR IGNORE INTO mute (group_id, ecosystem, name) SELECT group_id, ecosystem, name FROM finding WHERE id=?1"
        } else {
            "DELETE FROM mute WHERE (group_id, ecosystem, name) = (SELECT group_id, ecosystem, name FROM finding WHERE id=?1)"
        };
        conn.execute(sql, [finding_id])?;
        Ok(())
    }

    pub fn package_count(&self) -> usize {
        self.db()
            .query_row(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ecosystem, name, version FROM location)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize
    }

    pub fn state(&self, scanning: bool, progress: Option<(usize, usize)>, now: i64) -> R<AppState> {
        let settings = self.settings();
        let findings = self.open_findings()?;
        let paused_until = self.meta_i64("paused_until").filter(|&t| t > now);
        Ok(AppState {
            overview: Overview {
                last_check_at: self.meta_i64("last_check_at"),
                scanning,
                progress,
                phase: None,
                paused_until,
                projects: self.project_count(),
                packages: self.package_count(),
                counts: counts_of(&findings, settings.show_dev, settings.show_estimated),
                last_error: self.meta("last_error").filter(|e| !e.is_empty()),
            },
            findings,
            runtimes: self.runtimes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("novul.db")).unwrap();
        (dir, s)
    }

    fn lockfile(dir: &str) -> Lockfile {
        Lockfile {
            path: PathBuf::from(format!("/w/{dir}/package-lock.json")),
            root: PathBuf::from(format!("/w/{dir}")),
            ecosystem: "npm".into(),
            manifest: None,
        }
    }

    fn input(dir: &str, name: &str, version: &str, group: &str) -> FindingInput {
        FindingInput {
            kind: "package",
            group_id: group.into(),
            project_name: dir.into(),
            project_path: format!("/w/{dir}/package-lock.json"),
            ecosystem: "npm".into(),
            name: name.into(),
            installed_version: version.into(),
            fixed_version: Some("9.9.9".into()),
            direct: Some(true),
            dev: false,
            inferred: false,
            fix_command: None,
            aliases: vec![],
            summary: "s".into(),
            score: Some(9.8),
            malicious: false,
            url: "u".into(),
        }
    }

    fn write(s: &Store, dir: &str, findings: &[FindingInput], now: i64) {
        s.write_project(&lockfile(dir), &[], findings, now).unwrap();
    }

    #[test]
    fn settings_migrate_old_default_root_only_for_existing_installs() {
        let (_d, fresh) = store();
        assert!(fresh.settings().roots.is_empty());

        let (_d, old) = store();
        write(&old, "a", &[], 100);
        let workspace = dirs::home_dir().unwrap().join("Workspace").to_string_lossy().into_owned();
        assert_eq!(old.settings().roots, vec![workspace.clone()]);
        assert!(old.meta("settings").is_some(), "migration is persisted");

        let mut chosen = old.settings();
        chosen.roots.clear();
        old.set_settings(&chosen).unwrap();
        assert!(old.settings().roots.is_empty(), "an explicit empty choice is not migrated again");
    }

    #[test]
    fn version_bump_updates_in_place_and_keeps_notified() {
        let (_d, s) = store();
        write(&s, "a", &[input("a", "lodash", "4.17.20", "CVE-1")], 100);
        let first = s.open_findings().unwrap();
        s.mark_notified(&[first[0].id], 150).unwrap();

        write(&s, "a", &[input("a", "lodash", "4.17.21", "CVE-1")], 200);
        let all = s.open_findings().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, first[0].id);
        assert_eq!(all[0].installed_version, "4.17.21");
        assert_eq!(all[0].first_seen_at, 100);
        assert!(s.unnotified().unwrap().is_empty());
    }

    #[test]
    fn resolve_missing_only_touches_that_project() {
        let (_d, s) = store();
        write(&s, "a", &[input("a", "lodash", "4.17.20", "CVE-1")], 100);
        write(&s, "b", &[input("b", "lodash", "4.17.20", "CVE-1")], 100);
        write(&s, "a", &[], 200);
        let open = s.open_findings().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].project_name, "b");

        // reappearing clears resolved_at and keeps the identity
        write(&s, "a", &[input("a", "lodash", "4.17.20", "CVE-1")], 300);
        assert_eq!(s.open_findings().unwrap().len(), 2);
    }

    #[test]
    fn brew_sync_resolves_only_its_kind() {
        let (_d, s) = store();
        write(&s, "a", &[input("a", "lodash", "4.17.20", "CVE-1")], 100);
        let mut b = input("a", "openssl", "3.0.0", "CVE-2");
        b.kind = "brew";
        b.project_path = "homebrew".into();
        s.sync_kind("brew", &[b], 100).unwrap();
        assert_eq!(s.open_findings().unwrap().len(), 2);
        s.sync_kind("brew", &[], 200).unwrap();
        let open = s.open_findings().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].kind, "package");
    }

    #[test]
    fn advisory_that_gains_a_cve_id_keeps_its_finding_id_and_mute() {
        let (_d, s) = store();
        write(&s, "a", &[input("a", "dompurify", "3.0.0", "GHSA-aaaa")], 100);
        let old = s.open_findings().unwrap()[0].clone();
        s.set_muted(old.id, true).unwrap();
        let mut renamed = input("a", "dompurify", "3.0.0", "CVE-2026-1");
        renamed.aliases = vec!["GHSA-aaaa".into()];
        write(&s, "a", &[renamed], 200);
        let all = s.open_findings().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].id, all[0].group_id.as_str(), all[0].muted), (old.id, "CVE-2026-1", true));
    }

    #[test]
    fn mute_hides_from_counts_but_still_lists() {
        let (_d, s) = store();
        write(&s, "a", &[input("a", "lodash", "4.17.20", "CVE-1")], 100);
        write(
            &s,
            "b",
            &[
                input("b", "lodash", "4.17.20", "CVE-1"),
                input("b", "minimist", "1.0.0", "CVE-3"),
            ],
            100,
        );
        let id = s
            .open_findings()
            .unwrap()
            .iter()
            .find(|f| f.name == "lodash")
            .unwrap()
            .id;
        s.set_muted(id, true).unwrap();

        let all = s.open_findings().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all.iter().filter(|f| f.muted).count(),
            2,
            "mute is by group+package, so it covers both projects"
        );
        let c = counts_of(&all, false, false);
        assert_eq!(c.critical, 1);

        s.set_muted(id, false).unwrap();
        assert_eq!(counts_of(&s.open_findings().unwrap(), false, false).critical, 3);
    }

    #[test]
    fn estimated_findings_only_count_with_show_estimated_unless_malicious() {
        let (_d, s) = store();
        let mut est = input("a", "requests", "1.0.0", "CVE-5");
        est.inferred = true;
        let mut mal = input("a", "evil", "1.0.0", "MAL-1");
        mal.inferred = true;
        mal.malicious = true;
        let mut dev_est = input("a", "jest", "1.0.0", "CVE-6");
        dev_est.inferred = true;
        dev_est.dev = true;
        write(&s, "a", &[est, mal, dev_est], 100);
        let all = s.open_findings().unwrap();
        let c = counts_of(&all, false, false);
        assert_eq!((c.critical, c.malicious), (0, 1));
        assert_eq!(counts_of(&all, false, true).critical, 1, "dev + estimated stays hidden");
        assert_eq!(counts_of(&all, true, false).critical, 0);
        assert_eq!(counts_of(&all, true, true).critical, 2);
        // an estimated version is often wrong (pillow 9.5.0 guessed, 12.1.0 installed): exploited doesn't override it
        let exploited = FindingView { kev: true, priority: Priority::Exploited, ..all.iter().find(|f| f.name == "requests").unwrap().clone() };
        assert!(!countable(&exploited, false, false));
        assert!(countable(&exploited, false, true));
        assert!(countable(&FindingView { inferred: false, dev: true, ..exploited }, false, false), "exploited dev-only still counts");
    }

    #[test]
    fn old_settings_json_without_show_estimated_loads() {
        let (_d, s) = store();
        let mut v = serde_json::to_value(Settings::default()).unwrap();
        v.as_object_mut().unwrap().remove("show_estimated");
        v["interval_minutes"] = 15.into();
        s.set_meta("settings", &v.to_string()).unwrap();
        let loaded = s.settings();
        assert_eq!(loaded.interval_minutes, 15, "old JSON must parse, not fall back to defaults");
        assert!(!loaded.show_estimated);
    }

    #[test]
    fn dev_findings_only_count_with_show_dev() {
        let (_d, s) = store();
        let mut dev = input("a", "jest", "1.0.0", "CVE-4");
        dev.dev = true;
        write(&s, "a", &[dev], 100);
        let all = s.open_findings().unwrap();
        assert_eq!(counts_of(&all, false, false).critical, 0);
        assert_eq!(counts_of(&all, true, false).critical, 1);
    }

    #[test]
    fn malicious_dev_package_counts_even_when_dev_is_hidden() {
        let (_d, s) = store();
        let mut dev = input("a", "evil-lint", "1.0.0", "MAL-2026-1");
        dev.dev = true;
        dev.malicious = true;
        write(&s, "a", &[dev], 100);
        assert_eq!(counts_of(&s.open_findings().unwrap(), false, false).malicious, 1);
    }

    #[test]
    fn priority_order_is_malicious_then_kev_then_score() {
        assert_eq!(priority_of(true, true, Some(9.9)), Priority::Malicious);
        assert_eq!(priority_of(false, true, Some(2.0)), Priority::Exploited);
        assert_eq!(priority_of(false, true, None), Priority::Exploited);
        assert_eq!(priority_of(false, false, Some(9.1)), Priority::Critical);
        assert_eq!(priority_of(false, false, Some(7.5)), Priority::High);
        assert_eq!(priority_of(false, false, None), Priority::Unrated);
    }

    #[test]
    fn kev_alias_makes_finding_exploited() {
        let (_d, s) = store();
        let mut f = input("a", "lodash", "4.17.20", "GHSA-x");
        f.aliases = vec!["CVE-2024-1".into()];
        f.score = Some(5.0);
        write(&s, "a", &[f], 100);
        assert_eq!(s.open_findings().unwrap()[0].priority, Priority::Medium);
        s.replace_kev(&["CVE-2024-1".to_string()].into_iter().collect())
            .unwrap();
        let f = &s.open_findings().unwrap()[0];
        assert_eq!(f.priority, Priority::Exploited);
        assert!(f.kev);
    }

    #[test]
    fn package_keys_paginate_and_baseline_roundtrips() {
        let (_d, s) = store();
        let loc = |n: &str| LocationRow {
            ecosystem: "npm".into(),
            name: n.into(),
            version: "1".into(),
            direct: None,
            dev: false,
            inferred: false,
        };
        s.write_project(&lockfile("a"), &[loc("a"), loc("b"), loc("c")], &[], 1)
            .unwrap();
        s.write_project(&lockfile("b"), &[loc("b")], &[], 1)
            .unwrap();
        let page1 = s.keys_after(None, 2).unwrap();
        assert_eq!(
            page1.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        let page2 = s.keys_after(page1.last(), 2).unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(s.lockfiles_with(&page1[1]).len(), 2);

        let ids = vec!["GHSA-1".to_string()];
        s.set_package_ids([(&page1[0], &ids)].into_iter()).unwrap();
        assert_eq!(s.package_ids(&page1[0]), Some(ids));
        assert_eq!(s.package_ids(&page1[1]), None);
    }

    #[test]
    fn epss_lands_via_group_or_alias_takes_max_and_sorts_within_priority() {
        let (_d, s) = store();
        let mut a = input("a", "alpha", "1", "GHSA-a");
        a.aliases = vec!["CVE-2024-1".into(), "CVE-2024-2".into(), "PYSEC-1".into()];
        let b = input("a", "beta", "1", "CVE-2024-3");
        let c = input("a", "gamma", "1", "GHSA-c");
        write(&s, "a", &[a, b, c], 100);
        assert_eq!(s.open_cves(), ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]);

        let m = [("CVE-2024-1", 0.1), ("CVE-2024-2", 0.7), ("CVE-2024-3", 0.3)]
            .map(|(k, v)| (k.to_string(), v))
            .into_iter()
            .collect();
        s.set_epss(&m).unwrap();
        let all = s.open_findings().unwrap();
        let names: Vec<_> = all.iter().map(|f| (f.name.as_str(), f.epss)).collect();
        assert_eq!(names, [("alpha", Some(0.7)), ("beta", Some(0.3)), ("gamma", None)]);

        // a later partial fetch doesn't erase known values
        s.set_epss(&Default::default()).unwrap();
        assert_eq!(s.open_findings().unwrap()[0].epss, Some(0.7));
    }

    #[test]
    fn epss_does_not_outrank_a_higher_priority() {
        let (_d, s) = store();
        let mut low = input("a", "low", "1", "CVE-2024-9");
        low.score = Some(5.0);
        let crit = input("a", "crit", "1", "CVE-2024-8");
        write(&s, "a", &[low, crit], 100);
        s.set_epss(&[("CVE-2024-9".to_string(), 0.99)].into_iter().collect()).unwrap();
        assert_eq!(s.open_findings().unwrap()[0].name, "crit");
    }

    #[test]
    fn migrates_db_created_without_epss_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(&SCHEMA.replace("CREATE TABLE IF NOT EXISTS", "CREATE TABLE")).unwrap();
            c.execute(
                "INSERT INTO finding (kind, group_id, project_name, project_path, ecosystem, name, installed_version,
                   dev, inferred, aliases, summary, malicious, url, first_seen_at, last_seen_at)
                 VALUES ('package','CVE-2024-1','p','/p/package-lock.json','npm','x','1',0,0,'[]','s',0,'u',1,1)",
                [],
            )
            .unwrap();
        }
        let s = Store::open(&path).unwrap();
        let f = &s.open_findings().unwrap()[0];
        assert_eq!(f.epss, None);
        s.set_epss(&[("CVE-2024-1".to_string(), 0.5)].into_iter().collect()).unwrap();
        assert_eq!(s.open_findings().unwrap()[0].epss, Some(0.5));
        drop(s);
        Store::open(&path).unwrap(); // re-open is idempotent
    }
}
