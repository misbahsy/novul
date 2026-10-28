use crate::inventory::manifest;
use crate::model::Lockfile;
use ignore::WalkBuilder;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Lockfile basename -> OSV ecosystem. `requirements*.txt` maps to "PyPI".
pub fn ecosystem_for(file_name: &str) -> Option<&'static str> {
    match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" | "pnpm-lock.yaml" | "yarn.lock" | "bun.lock" => Some("npm"),
        "poetry.lock" | "uv.lock" | "Pipfile.lock" | "pdm.lock" | "pylock.toml" => Some("PyPI"),
        "composer.lock" => Some("Packagist"),
        "go.mod" => Some("Go"),
        "Cargo.lock" => Some("crates.io"),
        "Gemfile.lock" => Some("RubyGems"),
        "pubspec.lock" => Some("Pub"),
        "mix.lock" => Some("Hex"),
        n if n.starts_with("requirements") && n.ends_with(".txt") => Some("PyPI"),
        _ => None,
    }
}

fn manifest_name(lockfile_name: &str) -> Option<&'static str> {
    match lockfile_name {
        "package-lock.json" | "npm-shrinkwrap.json" | "pnpm-lock.yaml" | "yarn.lock" | "bun.lock" => Some("package.json"),
        "poetry.lock" | "uv.lock" | "pdm.lock" | "pylock.toml" => Some("pyproject.toml"),
        "Pipfile.lock" => Some("Pipfile"),
        "composer.lock" => Some("composer.json"),
        "Cargo.lock" => Some("Cargo.toml"),
        "Gemfile.lock" => Some("Gemfile"),
        _ => None,
    }
}

fn excluded(name: &str, exclusions: &[String]) -> bool {
    exclusions.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == p,
    })
}

/// Walk `roots` (gitignore-aware, skipping hidden dirs and any dir whose name matches an
/// exclusion glob such as "node_modules" or "archive*", max depth 8) and return every lockfile.
pub fn discover(roots: &[PathBuf], exclusions: &[String]) -> Vec<Lockfile> {
    let mut found: BTreeMap<PathBuf, Lockfile> = BTreeMap::new();
    for root in roots {
        let exclusions = exclusions.to_vec();
        let walker = WalkBuilder::new(root)
            .max_depth(Some(8))
            .require_git(false)
            .git_global(false)
            .filter_entry(move |e| {
                // depth 0 is the root itself, which the user chose explicitly
                e.depth() == 0
                    || !e.file_type().is_some_and(|t| t.is_dir())
                    || !excluded(&e.file_name().to_string_lossy(), &exclusions)
            })
            .build();
        for entry in walker.flatten() {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            let Some(ecosystem) = ecosystem_for(&name) else { continue };
            let path = entry.path().to_path_buf();
            let root_dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
            let manifest = if name.starts_with("requirements") || name == "go.mod" {
                Some(path.clone())
            } else {
                manifest_name(&name).map(|m| root_dir.join(m)).filter(|m| m.is_file())
            };
            found.insert(path.clone(), Lockfile { path, root: root_dir, ecosystem: ecosystem.to_string(), manifest });
        }
    }
    // A requirements*.txt next to a Python lockfile only repeats it with less exact versions. It
    // is skipped only when it names packages and nothing else, and a lockfile installs all of them,
    // so a decoy lockfile can't hide a package.
    let locks: Vec<&Lockfile> = found.values().filter(|l| l.ecosystem == "PyPI" && !is_requirements(&l.path)).collect();
    let covered: Vec<PathBuf> = found
        .values()
        .filter(|r| is_requirements(&r.path))
        .filter(|r| {
            let Ok(text) = std::fs::read_to_string(&r.path) else { return false };
            let (pins, includes) = manifest::requirement_pins(&text);
            if pins.is_empty() || !includes.is_empty() || !manifest::requirements_fully_named(&text) {
                return false;
            }
            locks
                .iter()
                .filter(|l| l.root == r.root)
                .filter_map(|l| manifest::lock_packages(&l.path))
                .any(|installed| {
                    // an exact pin the lock doesn't match installs another version: scan it
                    pins.iter().all(|(n, pin)| installed.get(n).is_some_and(|vs| pin.as_ref().is_none_or(|p| vs.contains(p))))
                })
        })
        .map(|r| r.path.clone())
        .collect();
    found.into_values().filter(|l| !covered.contains(&l.path)).collect()
}

/// The files `discover` finds directly in `dir`: same ignore rules, and a symlink is not a file.
pub fn visible_files(dir: &Path) -> Vec<PathBuf> {
    WalkBuilder::new(dir)
        .max_depth(Some(1))
        .require_git(false)
        .git_global(false)
        .build()
        .flatten()
        .filter(|e| e.depth() == 1 && e.file_type().is_some_and(|t| t.is_file()))
        .map(|e| e.into_path())
        .collect()
}

fn is_requirements(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("requirements") && n.ends_with(".txt"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(root: &Path, rel: &str) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, "").unwrap();
    }

    #[test]
    fn ecosystems() {
        assert_eq!(ecosystem_for("package-lock.json"), Some("npm"));
        assert_eq!(ecosystem_for("requirements-dev.txt"), Some("PyPI"));
        assert_eq!(ecosystem_for("requirements.txt"), Some("PyPI"));
        assert_eq!(ecosystem_for("Cargo.lock"), Some("crates.io"));
        assert_eq!(ecosystem_for("go.mod"), Some("Go"));
        assert_eq!(ecosystem_for("Cargo.toml"), None);
        assert_eq!(ecosystem_for("package.json"), None);
        assert_eq!(ecosystem_for("my-requirements.txt"), None);
    }

    #[test]
    fn discovers_prunes_and_fills_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        touch(r, "a/package-lock.json");
        touch(r, "a/package.json");
        touch(r, "a/node_modules/dep/package-lock.json");
        touch(r, "archive-old/b/yarn.lock");
        touch(r, "archive/yarn.lock");
        touch(r, ".hidden/c/Cargo.lock");
        touch(r, "d/requirements-dev.txt");
        touch(r, "e/go.mod");
        touch(r, "f/Cargo.lock"); // no Cargo.toml: manifest stays None
        touch(r, "g/.gitignore");
        fs::write(r.join("g/.gitignore"), "ignored/\n").unwrap();
        touch(r, "g/ignored/uv.lock");
        touch(r, "g/kept/uv.lock");
        touch(r, "g/kept/pyproject.toml");
        // a mention of evil-pkg outside a [[package]] entry doesn't make it installed
        fs::write(r.join("g/kept/uv.lock"), "# \"evil-pkg\"\n[[package]]\nname = \"pillow\"\nversion = \"12.1.0\"\n").unwrap();
        fs::write(r.join("g/kept/requirements.txt"), "Pillow>=10.0\n").unwrap(); // repeats uv.lock
        fs::write(r.join("g/kept/requirements-same.txt"), "pillow==12.1.0\n").unwrap(); // same pin as uv.lock
        fs::write(r.join("g/kept/requirements-old.txt"), "pillow==9.0.0\n").unwrap(); // installs another version
        fs::write(r.join("g/kept/requirements-gpu.txt"), "pillow\nevil-pkg==1.0\n").unwrap(); // not in uv.lock
        fs::write(r.join("g/kept/requirements-git.txt"), "pillow\n-e git+https://example.com/x.git#egg=x\n").unwrap();
        fs::write(r.join("g/kept/requirements-inc.txt"), "pillow\n-r ../other.txt\n").unwrap();
        fs::write(r.join("g/kept/requirements-empty.txt"), "# nothing\n").unwrap();

        let excl: Vec<String> = ["node_modules", "archive*"].iter().map(|s| s.to_string()).collect();
        let found = discover(&[r.to_path_buf()], &excl);
        let rel: Vec<_> = found.iter().map(|l| l.path.strip_prefix(r).unwrap().to_str().unwrap().to_string()).collect();
        assert_eq!(
            rel,
            [
                "a/package-lock.json",
                "d/requirements-dev.txt",
                "e/go.mod",
                "f/Cargo.lock",
                "g/kept/requirements-empty.txt",
                "g/kept/requirements-git.txt",
                "g/kept/requirements-gpu.txt",
                "g/kept/requirements-inc.txt",
                "g/kept/requirements-old.txt",
                "g/kept/uv.lock"
            ]
        );
        assert_eq!(found[0].ecosystem, "npm");
        assert_eq!(found[0].manifest, Some(r.join("a/package.json")));
        assert_eq!(found[0].root, r.join("a"));
        assert_eq!(found[1].manifest, Some(r.join("d/requirements-dev.txt")));
        assert_eq!(found[2].manifest, Some(r.join("e/go.mod")));
        assert_eq!(found[3].manifest, None);
        assert_eq!(found[9].manifest, Some(r.join("g/kept/pyproject.toml")));
    }

    #[test]
    fn root_named_like_an_exclusion_is_still_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("build");
        touch(&root, "x/uv.lock");
        let found = discover(&[root], &["build".to_string()]);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn depth_is_limited() {
        let dir = tempfile::tempdir().unwrap();
        touch(dir.path(), "1/2/3/4/5/6/7/yarn.lock"); // depth 8
        touch(dir.path(), "1/2/3/4/5/6/7/8/yarn.lock"); // depth 9
        assert_eq!(discover(&[dir.path().to_path_buf()], &[]).len(), 1);
    }
}
