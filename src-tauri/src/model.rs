// Shared types between scanners, store, engine and the UI.
// Scanner modules produce these plain values and never touch the database.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Most urgent first; `Ord` follows declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Malicious,
    Exploited,
    Critical,
    High,
    Medium,
    Low,
    Unrated,
}

impl Priority {
    /// From a CVSS base score (osv-scanner's `groups[].max_severity`).
    pub fn from_score(score: Option<f32>) -> Priority {
        match score {
            Some(s) if s >= 9.0 => Priority::Critical,
            Some(s) if s >= 7.0 => Priority::High,
            Some(s) if s >= 4.0 => Priority::Medium,
            Some(s) if s > 0.0 => Priority::Low,
            _ => Priority::Unrated,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::Malicious => "malicious",
            Priority::Exploited => "exploited",
            Priority::Critical => "critical",
            Priority::High => "high",
            Priority::Medium => "medium",
            Priority::Low => "low",
            Priority::Unrated => "unrated",
        }
    }

    pub fn parse(s: &str) -> Priority {
        match s {
            "malicious" => Priority::Malicious,
            "exploited" => Priority::Exploited,
            "critical" => Priority::Critical,
            "high" => Priority::High,
            "medium" => Priority::Medium,
            "low" => Priority::Low,
            _ => Priority::Unrated,
        }
    }
}

/// A lockfile found by discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    pub path: PathBuf,
    /// Project root (the lockfile's directory).
    pub root: PathBuf,
    /// "npm" | "PyPI" | "Packagist" | "Go" | "crates.io" | "RubyGems" | ...
    pub ecosystem: String,
    /// Manifest next to the lockfile used for direct-dependency detection, if any.
    pub manifest: Option<PathBuf>,
}

/// One advisory group (aliases merged) as it applies to one installed package version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnGroup {
    /// Canonical id: CVE > GHSA > first ecosystem id.
    pub id: String,
    /// All OSV ids in the group (e.g. ["PYSEC-2023-62", "GHSA-m2qf-hxjv-5gpq"]).
    pub ids: Vec<String>,
    pub aliases: Vec<String>,
    pub score: Option<f32>,
    pub summary: String,
    /// Any id starts with "MAL-".
    pub malicious: bool,
    /// Lowest fixed version above the installed version, if one exists.
    pub fixed_version: Option<String>,
    /// Advisory URL to show the user (osv.dev/vulnerability/<first id>).
    pub url: String,
    /// Latest `modified` timestamp across the group's records (RFC 3339).
    pub modified: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScannedPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// `dependency_groups` contains "dev".
    pub dev: bool,
    /// Not read from the lockfile itself but resolved by osv-scanner
    /// (e.g. transitive deps of requirements.txt; source.type != "lockfile").
    pub inferred: bool,
    pub vulns: Vec<VulnGroup>,
}

/// Result of scanning one lockfile.
#[derive(Debug, Clone, PartialEq)]
pub struct LockfileScan {
    pub lockfile: PathBuf,
    pub packages: Vec<ScannedPackage>,
}

/// Key used for OSV querybatch and package identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageKey {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeStatus {
    /// "node" | "python" | "php" | "go" | "ruby" | "java"
    pub kind: String,
    pub version: String,
    pub path: String,
    /// Release cycle per endoflife.date, e.g. "8.3".
    pub cycle: Option<String>,
    pub latest_in_cycle: Option<String>,
    pub latest_date: Option<String>,
    pub is_eol: bool,
    /// Installed version is older than latest_in_cycle.
    pub behind: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrewVuln {
    pub formula: String,
    pub version: String,
    pub group: VulnGroup,
}

// ---------- UI-facing views (serialized to the webview) ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingView {
    pub id: i64,
    /// "package" | "brew" | "runtime"
    pub kind: String,
    pub group_id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub priority: Priority,
    pub score: Option<f32>,
    pub kev: bool,
    pub ecosystem: String,
    pub name: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    /// None when no manifest could be read.
    pub direct: Option<bool>,
    pub dev: bool,
    pub inferred: bool,
    pub project_path: String,
    pub project_name: String,
    pub fix_command: Option<String>,
    pub url: String,
    pub first_seen_at: i64,
    pub muted: bool,
    /// EPSS exploit probability 0..1 for the finding's CVEs (max), when known.
    pub epss: Option<f32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Counts {
    pub malicious: usize,
    pub exploited: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unrated: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Overview {
    pub last_check_at: Option<i64>,
    pub scanning: bool,
    /// (done, total) lockfiles during a scan.
    pub progress: Option<(usize, usize)>,
    /// "packages" | "machine" | "secrets" while a full scan runs.
    #[serde(default)]
    pub phase: Option<String>,
    pub paused_until: Option<i64>,
    pub projects: usize,
    pub packages: usize,
    /// Open, unmuted, non-dev findings by priority.
    pub counts: Counts,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    pub overview: Overview,
    pub findings: Vec<FindingView>,
    pub runtimes: Vec<RuntimeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub roots: Vec<String>,
    pub exclusions: Vec<String>,
    pub interval_minutes: u64,
    /// Lowest priority that triggers a notification.
    pub notify_threshold: Priority,
    pub show_dev: bool,
    /// Include findings whose version osv-scanner guessed (e.g. requirements.txt).
    #[serde(default)]
    pub show_estimated: bool,
    pub launch_at_login: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            roots: vec![],
            exclusions: [
                "node_modules",
                ".git",
                ".venv",
                "venv",
                "vendor",
                "target",
                "dist",
                "build",
                ".next",
                "archive*",
                "Library",
                "fixtures",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            interval_minutes: 30,
            notify_threshold: Priority::High,
            show_dev: false,
            show_estimated: false,
            launch_at_login: false,
        }
    }
}
