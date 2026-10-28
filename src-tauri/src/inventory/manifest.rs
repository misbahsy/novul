use crate::model::Lockfile;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// PEP 503: lowercase, runs of `-_.` become `-`.
pub fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !prev_sep {
                out.push('-');
            }
            prev_sep = true;
        } else {
            out.extend(c.to_lowercase());
            prev_sep = false;
        }
    }
    out
}

/// Package name at the start of a PEP 508 requirement / requirements.txt line.
fn requirement_name(line: &str) -> Option<&str> {
    let line = line.trim();
    if let Some(i) = line.find("://") {
        // a bare URL; `pkg @ https://...` has whitespace or `@` before the scheme
        if !line[..i].contains(|c: char| c.is_whitespace() || c == '@') {
            return None;
        }
    }
    if !line.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return None;
    }
    let end = line.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))).unwrap_or(line.len());
    Some(&line[..end])
}

fn table_keys(v: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(o) = v.and_then(|v| v.as_object()) {
        out.extend(o.keys().cloned());
    }
}

// `str::parse::<toml::Value>` parses a single value, not a document.
fn parse_toml(text: &str) -> Option<toml::Value> {
    toml::from_str::<toml::Table>(text).ok().map(toml::Value::Table)
}

fn at<'a>(v: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
    path.split('.').try_fold(v, |v, k| v.get(k))
}

fn toml_keys(v: Option<&toml::Value>, out: &mut Vec<String>) {
    if let Some(t) = v.and_then(|v| v.as_table()) {
        out.extend(t.keys().cloned());
    }
}

fn toml_requirements(v: Option<&toml::Value>, out: &mut Vec<String>) {
    for s in v.and_then(|v| v.as_array()).into_iter().flatten().filter_map(|s| s.as_str()) {
        out.extend(requirement_name(s).map(str::to_string));
    }
}

fn package_json(text: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    for k in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
        table_keys(v.get(k), &mut out);
    }
    Some(out)
}

fn composer_json(text: &str) -> Option<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let mut out = Vec::new();
    table_keys(v.get("require"), &mut out);
    table_keys(v.get("require-dev"), &mut out);
    out.retain(|n| n != "php" && !n.starts_with("ext-"));
    Some(out)
}

/// A requirements file's own lines: PEP 503 name -> pinned to one exact version (`==x` or `===x`,
/// no wildcard), and the files it includes with `-r`.
pub fn requirement_pins(text: &str) -> (HashMap<String, bool>, Vec<String>) {
    let mut pins = HashMap::new();
    let mut includes = Vec::new();
    for line in text.lines() {
        let line = line.split(" #").next().unwrap_or("").trim();
        if let Some(rest) = line.strip_prefix("--requirement").or_else(|| line.strip_prefix("-r")) {
            let f = rest.trim_start_matches('=').trim();
            if !f.is_empty() {
                includes.push(f.to_string());
            }
            continue;
        }
        let Some(name) = requirement_name(line) else { continue };
        let mut spec = line[name.len()..].split(';').next().unwrap_or("").trim();
        if spec.starts_with('[') {
            spec = spec.split_once(']').map_or("", |(_, s)| s.trim());
        }
        let exact = spec.starts_with("==") && !spec.contains([',', '*']);
        pins.insert(normalize_pypi(name), exact);
    }
    (pins, includes)
}

/// pip options that choose where packages come from, not which ones are installed.
const INDEX_OPTIONS: [&str; 9] =
    ["--index-url", "--extra-index-url", "-i ", "--find-links", "-f ", "--trusted-host", "--pre", "--prefer-binary", "--only-binary"];

/// Whether every requirement line of a requirements file names a package. Options, includes,
/// editable and bare-URL lines can install packages that the names don't show.
pub fn requirements_fully_named(text: &str) -> bool {
    text.lines()
        .map(|l| l.split(" #").next().unwrap_or("").trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !INDEX_OPTIONS.iter().any(|o| l.starts_with(o)))
        .all(|l| requirement_name(l).is_some())
}

/// PEP 503 names of the packages a uv/poetry/pdm lock (`[[package]]`), pylock.toml
/// (`[[packages]]`) or Pipfile.lock (`default`/`develop` keys) installs. None when unreadable.
pub fn lock_package_names(lock: &Path) -> Option<HashSet<String>> {
    let text = std::fs::read_to_string(lock).ok()?;
    let names: Vec<String> = if lock.file_name().is_some_and(|n| n == "Pipfile.lock") {
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        ["default", "develop"].iter().filter_map(|k| v[*k].as_object()).flat_map(|o| o.keys().cloned()).collect()
    } else {
        let v = parse_toml(&text)?;
        ["package", "packages"]
            .iter()
            .filter_map(|k| v.get(*k).and_then(|p| p.as_array()))
            .flatten()
            .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect()
    };
    Some(names.iter().map(|n| normalize_pypi(n)).collect())
}

fn requirements_txt(text: &str) -> Vec<String> {
    text.lines().filter_map(requirement_name).map(str::to_string).collect()
}

fn pyproject(text: &str) -> Option<Vec<String>> {
    let v = parse_toml(text)?;
    let mut out = Vec::new();
    toml_requirements(at(&v, "project.dependencies"), &mut out);
    for deps in at(&v, "project.optional-dependencies").and_then(|v| v.as_table()).into_iter().flat_map(|t| t.values()) {
        toml_requirements(Some(deps), &mut out);
    }
    for deps in v.get("dependency-groups").and_then(|v| v.as_table()).into_iter().flat_map(|t| t.values()) {
        toml_requirements(Some(deps), &mut out);
    }
    toml_requirements(at(&v, "tool.uv.dev-dependencies"), &mut out);
    toml_keys(at(&v, "tool.poetry.dependencies"), &mut out);
    toml_keys(at(&v, "tool.poetry.dev-dependencies"), &mut out);
    for g in at(&v, "tool.poetry.group").and_then(|v| v.as_table()).into_iter().flat_map(|t| t.values()) {
        toml_keys(g.get("dependencies"), &mut out);
    }
    out.retain(|n| !n.eq_ignore_ascii_case("python"));
    Some(out)
}

fn pipfile(text: &str) -> Option<Vec<String>> {
    let v = parse_toml(text)?;
    let mut out = Vec::new();
    toml_keys(v.get("packages"), &mut out);
    toml_keys(v.get("dev-packages"), &mut out);
    Some(out)
}

fn cargo_toml(text: &str) -> Option<Vec<String>> {
    let v = parse_toml(text)?;
    let mut tables: Vec<&toml::Value> = Vec::new();
    let sections = ["dependencies", "dev-dependencies", "build-dependencies"];
    for k in sections {
        tables.extend(v.get(k));
    }
    tables.extend(at(&v, "workspace.dependencies"));
    for target in v.get("target").and_then(|t| t.as_table()).into_iter().flat_map(|t| t.values()) {
        for k in sections {
            tables.extend(target.get(k));
        }
    }
    let mut out = Vec::new();
    for (key, dep) in tables.into_iter().filter_map(|t| t.as_table()).flatten() {
        // `foo = { package = "real-name" }` renames the crate
        out.push(dep.get("package").and_then(|p| p.as_str()).unwrap_or(key).to_string());
    }
    Some(out)
}

fn go_mod(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut entry = |line: &str| {
        if line.contains("// indirect") {
            return;
        }
        let line = line.split("//").next().unwrap_or("");
        out.extend(line.split_whitespace().next().map(str::to_string));
    };
    for line in text.lines().map(str::trim) {
        if in_block {
            if line.starts_with(')') {
                in_block = false;
            } else {
                entry(line);
            }
        } else if line.strip_prefix("require").is_some_and(|r| r.trim_start().starts_with('(')) {
            in_block = true;
        } else if let Some(rest) = line.strip_prefix("require ") {
            entry(rest);
        }
    }
    out
}

fn gemfile(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim_start().strip_prefix("gem ")?.trim_start().strip_prefix(['"', '\'']))
        .filter_map(|rest| Some(&rest[..rest.find(['"', '\''])?]))
        .map(str::to_string)
        .collect()
}

/// Names of direct dependencies declared in the lockfile's manifest
/// (package.json deps + devDeps, requirements*.txt lines, pyproject.toml, composer.json,
/// go.mod without `// indirect`, Cargo.toml, Gemfile). Names normalized like OSV does
/// (PyPI: PEP 503). None when no manifest is readable.
pub fn direct_deps(lockfile: &Lockfile) -> Option<HashSet<String>> {
    let path = lockfile.manifest.as_ref()?;
    let file = path.file_name()?.to_str()?;
    let text = std::fs::read_to_string(path).ok()?;
    let names = match file {
        "package.json" => package_json(&text)?,
        "composer.json" => composer_json(&text)?,
        "pyproject.toml" => pyproject(&text)?,
        "Pipfile" => pipfile(&text)?,
        "Cargo.toml" => cargo_toml(&text)?,
        "go.mod" => go_mod(&text),
        "Gemfile" => gemfile(&text),
        f if f.starts_with("requirements") && f.ends_with(".txt") => requirements_txt(&text),
        _ => return None,
    };
    let pypi = lockfile.ecosystem == "PyPI";
    Some(names.into_iter().map(|n| if pypi { normalize_pypi(&n) } else { n }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn deps(ecosystem: &str, file: &str, content: &str) -> Option<Vec<String>> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(file);
        std::fs::write(&path, content).unwrap();
        let lf = Lockfile {
            path: dir.path().join("lock"),
            root: dir.path().to_path_buf(),
            ecosystem: ecosystem.to_string(),
            manifest: Some(path),
        };
        direct_deps(&lf).map(|s| {
            let mut v: Vec<_> = s.into_iter().collect();
            v.sort();
            v
        })
    }

    #[test]
    fn requirements_that_only_name_packages() {
        assert!(requirements_fully_named("# torch\n--extra-index-url https://download.pytorch.org/whl/cu128\ntorch==2.7 ; sys_platform == 'linux'\nPillow>=10\n"));
        assert!(!requirements_fully_named("pillow\n-e git+https://example.com/x.git#egg=x\n"));
        assert!(!requirements_fully_named("pillow\nhttps://example.com/x-1.0.whl\n"));
        assert!(!requirements_fully_named("pillow\n-r other.txt\n"));
    }

    #[test]
    fn lock_names_come_from_package_entries_only() {
        let dir = tempfile::tempdir().unwrap();
        let uv = dir.path().join("uv.lock");
        std::fs::write(&uv, "# \"evil\"\n[[package]]\nname = \"Pillow\"\nversion = \"12.1.0\"\n[package.metadata]\nrequires-dist = [{ name = \"evil\" }]\n").unwrap();
        assert_eq!(lock_package_names(&uv).unwrap(), HashSet::from(["pillow".to_string()]));
        let pipfile = dir.path().join("Pipfile.lock");
        std::fs::write(&pipfile, r#"{"_meta":{"evil":1},"default":{"requests":{}},"develop":{"Py_Test":{}}}"#).unwrap();
        assert_eq!(lock_package_names(&pipfile).unwrap(), HashSet::from(["requests".to_string(), "py-test".to_string()]));
    }

    #[test]
    fn pypi_normalization() {
        assert_eq!(normalize_pypi("Foo_Bar.baz--Qux"), "foo-bar-baz-qux");
        assert_eq!(normalize_pypi("zope.interface"), "zope-interface");
    }

    #[test]
    fn package_json_all_sections() {
        let j = r#"{"dependencies":{"a":"1"},"devDependencies":{"b":"1"},"optionalDependencies":{"c":"1"},"peerDependencies":{"@s/d":"1"},"scripts":{"x":"y"}}"#;
        assert_eq!(deps("npm", "package.json", j).unwrap(), ["@s/d", "a", "b", "c"]);
        assert_eq!(deps("npm", "package.json", "{not json"), None);
    }

    #[test]
    fn requirements_lines() {
        let t = "# comment\n\nRequests[security]>=2.0 ; python_version > '3'\nFlask_SQLAlchemy==3.0  # inline\n-r base.txt\n-e .\n-c cons.txt\n--index-url https://x/simple\nhttps://example.com/pkg.whl\ngit+https://github.com/o/r.git#egg=r\nmypkg @ https://example.com/mypkg.zip\nzope.interface\n./local\n";
        assert_eq!(
            deps("PyPI", "requirements-dev.txt", t).unwrap(),
            ["flask-sqlalchemy", "mypkg", "requests", "zope-interface"]
        );
    }

    #[test]
    fn pyproject_pep621_and_poetry() {
        let t = r#"
[project]
name = "x"
dependencies = ["Requests>=2", "typing_extensions; python_version<'3.11'"]
[project.optional-dependencies]
web = ["Flask[async]==2.0"]
[dependency-groups]
dev = ["pytest", {include-group = "lint"}]
lint = ["ruff"]
[tool.poetry.dependencies]
python = "^3.11"
django = "^4"
[tool.poetry.group.test.dependencies]
Hypothesis = "*"
"#;
        assert_eq!(
            deps("PyPI", "pyproject.toml", t).unwrap(),
            ["django", "flask", "hypothesis", "pytest", "requests", "ruff", "typing-extensions"]
        );
        assert_eq!(deps("PyPI", "pyproject.toml", "[broken"), None);
    }

    #[test]
    fn pipfile() {
        let t = "[packages]\nRequests = \"*\"\n[dev-packages]\npytest = \"*\"\n";
        assert_eq!(deps("PyPI", "Pipfile", t).unwrap(), ["pytest", "requests"]);
    }

    #[test]
    fn composer() {
        let j = r#"{"require":{"php":">=8","ext-json":"*","laravel/framework":"^10"},"require-dev":{"phpunit/phpunit":"^10"}}"#;
        assert_eq!(deps("Packagist", "composer.json", j).unwrap(), ["laravel/framework", "phpunit/phpunit"]);
    }

    #[test]
    fn go_mod_skips_indirect_and_other_blocks() {
        let t = "module m\n\ngo 1.21\n\nrequire github.com/a/single v1.0.0\nrequire github.com/b/ind v1.0.0 // indirect\n\nrequire (\n\tgithub.com/c/direct v1.2.3\n\tgithub.com/d/ind v0.1.0 // indirect\n\tgithub.com/e/direct v2.0.0 // pinned\n)\n\nreplace (\n\tgithub.com/f/rep => ../rep\n)\n";
        assert_eq!(
            deps("Go", "go.mod", t).unwrap(),
            ["github.com/a/single", "github.com/c/direct", "github.com/e/direct"]
        );
    }

    #[test]
    fn cargo_toml_targets_and_renames() {
        let t = r#"
[dependencies]
serde = "1"
tk = { package = "tokio", version = "1" }
[dev-dependencies]
tempfile = "3"
[build-dependencies]
cc = "1"
[target.'cfg(unix)'.dependencies]
libc = "0.2"
"#;
        assert_eq!(deps("crates.io", "Cargo.toml", t).unwrap(), ["cc", "libc", "serde", "tempfile", "tokio"]);
    }

    #[test]
    fn gemfile() {
        let t = "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n  gem \"pg\"\n# gem 'nope'\ngroup :test do\n  gem 'rspec'\nend\n";
        assert_eq!(deps("RubyGems", "Gemfile", t).unwrap(), ["pg", "rails", "rspec"]);
    }

    #[test]
    fn no_manifest_or_missing_file() {
        let mut lf = Lockfile {
            path: "/x/lock".into(),
            root: "/x".into(),
            ecosystem: "npm".into(),
            manifest: None,
        };
        assert_eq!(direct_deps(&lf), None);
        lf.manifest = Some(Path::new("/nonexistent/package.json").to_path_buf());
        assert_eq!(direct_deps(&lf), None);
    }
}
