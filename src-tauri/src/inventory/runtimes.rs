// Owner: feeds agent.
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CELLARS: [&str; 2] = ["/opt/homebrew/Cellar", "/usr/local/Cellar"];

/// (kind, binary on PATH, Homebrew formula prefix, args that print the version)
const RUNTIMES: [(&str, &str, &str, &[&str]); 5] = [
    ("node", "node", "node", &["-v"]),
    ("python", "python3", "python", &["-c", "import platform;print(platform.python_version())"]),
    ("php", "php", "php", &["-r", "echo PHP_VERSION;"]),
    ("go", "go", "go", &["env", "GOVERSION"]),
    ("ruby", "ruby", "ruby", &["-e", "print RUBY_VERSION"]),
];

/// Installed runtimes found via PATH (`which`) and the Homebrew Cellar:
/// node, python3, php, go, ruby. Returns (kind, version, path), deduplicated by path.
pub fn detect_runtimes() -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for (kind, bin, formula, args) in RUNTIMES {
        let candidates = which_all(bin).into_iter().chain(cellar_bins(formula, bin));
        for path in candidates {
            let Ok(real) = path.canonicalize() else { continue };
            if !seen.insert(real.clone()) {
                continue;
            }
            let version = run_version(&path, args).or_else(|| cellar_version(&real));
            if let Some(version) = version {
                found.push((kind.to_string(), version, path.to_string_lossy().into_owned()));
            }
        }
    }
    found
}

fn which_all(bin: &str) -> Vec<PathBuf> {
    // A menubar app launched from Finder has a minimal PATH without Homebrew.
    let path = format!("{}:/opt/homebrew/bin:/usr/local/bin", std::env::var("PATH").unwrap_or_default());
    let Ok(out) = Command::new("which").args(["-a", bin]).env("PATH", path).output() else { return vec![] };
    String::from_utf8_lossy(&out.stdout).lines().map(PathBuf::from).filter(|p| p.is_absolute()).collect()
}

/// <Cellar>/<formula>/<version>/bin/<bin> for formula, formula@*. A version dir whose binary
/// is missing is returned as the dir itself so its version still shows up.
fn cellar_bins(formula: &str, bin: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for cellar in CELLARS {
        let Ok(dirs) = std::fs::read_dir(cellar) else { continue };
        let mut dirs: Vec<_> = dirs.flatten().collect();
        dirs.sort_by_key(|d| d.file_name());
        for d in dirs {
            let name = d.file_name().to_string_lossy().into_owned();
            if name != formula && !name.starts_with(&format!("{formula}@")) {
                continue;
            }
            let Ok(versions) = std::fs::read_dir(d.path()) else { continue };
            let mut versions: Vec<_> = versions.flatten().map(|v| v.path()).filter(|p| p.is_dir()).collect();
            versions.sort();
            for v in versions {
                // python@3.13 ships only bin/python3.13
                let candidates = [v.join("bin").join(bin), v.join("bin").join(name.replace('@', ""))];
                out.push(candidates.into_iter().find(|c| c.exists()).unwrap_or(v));
            }
        }
    }
    out
}

/// Version from `<...>/Cellar/<formula>/<version>/...`, minus Homebrew's `_<revision>` suffix.
fn cellar_version(real: &Path) -> Option<String> {
    let parts: Vec<_> = real.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let i = parts.iter().position(|p| p == "Cellar")?;
    let v = parts.get(i + 2)?;
    let v = match v.rsplit_once('_') {
        Some((base, rev)) if rev.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => v,
    };
    v.starts_with(|c: char| c.is_ascii_digit()).then(|| v.to_string())
}

fn run_version(path: &Path, args: &[&str]) -> Option<String> {
    // /usr/bin/python3 is a stub that pops up the Command Line Tools installer when they are missing.
    if path == Path::new("/usr/bin/python3") && !Command::new("xcode-select").arg("-p").output().ok()?.status.success() {
        return None;
    }
    let out = run_with_timeout(path, args, Duration::from_secs(5))?;
    let v = out.trim().trim_start_matches("go").trim_start_matches('v');
    (v.len() < 40 && v.starts_with(|c: char| c.is_ascii_digit())).then(|| v.to_string())
}

fn run_with_timeout(path: &Path, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new(path).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().ok()? {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if !status.success() {
        return None;
    }
    let mut s = String::new();
    child.stdout.take()?.read_to_string(&mut s).ok()?;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cellar_version_strips_revision() {
        let p = Path::new("/opt/homebrew/Cellar/python@3.13/3.13.12_1/bin/python3.13");
        assert_eq!(cellar_version(p).as_deref(), Some("3.13.12"));
        let p = Path::new("/opt/homebrew/Cellar/node/25.6.1/bin/node");
        assert_eq!(cellar_version(p).as_deref(), Some("25.6.1"));
        assert_eq!(cellar_version(Path::new("/usr/bin/ruby")), None);
    }

    #[test]
    fn timeout_kills_and_failure_is_none() {
        let t = Instant::now();
        assert_eq!(run_with_timeout(Path::new("/bin/sleep"), &["10"], Duration::from_millis(200)), None);
        assert!(t.elapsed() < Duration::from_secs(3));
        assert_eq!(run_with_timeout(Path::new("/usr/bin/false"), &[], Duration::from_secs(1)), None);
        assert_eq!(run_with_timeout(Path::new("/bin/echo"), &["1.2.3"], Duration::from_secs(1)).as_deref(), Some("1.2.3\n"));
    }

    /// Runs against whatever is installed; every entry must carry a numeric version and an existing path.
    #[test]
    fn detected_runtimes_are_well_formed_and_unique() {
        let found = detect_runtimes();
        let mut real = HashSet::new();
        for (kind, version, path) in &found {
            assert!(["node", "python", "php", "go", "ruby"].contains(&kind.as_str()));
            assert!(version.starts_with(|c: char| c.is_ascii_digit()), "{kind} {version}");
            let p = Path::new(path);
            assert!(p.exists(), "{path}");
            assert!(real.insert(p.canonicalize().unwrap()), "duplicate {path}");
        }
    }
}
