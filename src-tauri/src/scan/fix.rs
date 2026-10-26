use crate::inventory::manifest::normalize_pypi;
use serde_json::Value;
use std::cmp::Ordering;
use std::path::Path;
use std::str::FromStr;

/// Canonical id for a group: first CVE alias, else first GHSA, else first id.
pub fn canonical_id(ids: &[String], aliases: &[String]) -> String {
    let all = || ids.iter().chain(aliases);
    all()
        .find(|i| i.starts_with("CVE-"))
        .or_else(|| all().find(|i| i.starts_with("GHSA-")))
        .or_else(|| ids.first())
        .cloned()
        .unwrap_or_default()
}

/// Same package name under the ecosystem's normalization rules.
pub fn names_match(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem == "PyPI" {
        normalize_pypi(a) == normalize_pypi(b)
    } else {
        a == b
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Ver {
    Semver(semver::Version),
    Pep440(pep440_rs::Version),
    Dotted(Vec<u64>),
}

// Accepts "v1.2", "1.2", "1.2.3-rc.1+b": pads the numeric core to three parts.
fn lenient_semver(s: &str) -> Option<semver::Version> {
    let s = s.trim().trim_start_matches('v');
    let (core, rest) = s.split_at(s.find(['-', '+']).unwrap_or(s.len()));
    let mut parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    while parts.len() < 3 {
        parts.push("0");
    }
    semver::Version::parse(&format!("{}{rest}", parts.join("."))).ok()
}

fn dotted(s: &str) -> Option<Vec<u64>> {
    let mut v = s
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<Vec<u64>>>()?;
    while v.last() == Some(&0) {
        v.pop();
    }
    Some(v)
}

fn parse_version(ecosystem: &str, s: &str) -> Option<Ver> {
    match ecosystem {
        "npm" | "crates.io" | "Go" => lenient_semver(s).map(Ver::Semver),
        "PyPI" => pep440_rs::Version::from_str(s.trim()).ok().map(Ver::Pep440),
        _ => dotted(s).map(Ver::Dotted),
    }
}

/// Lowest `fixed` event above `installed` across the ECOSYSTEM/SEMVER ranges of the
/// record's `affected` entries for this package (ignore GIT ranges). Uses semver for
/// npm/crates.io/Go, pep440 for PyPI, and a lenient dotted-number compare otherwise.
///
/// `affected` is the record's `affected` array, already narrowed to this package's entries
/// (see `fixed_version_for_package`).
pub fn fixed_version(ecosystem: &str, installed: &str, affected: &Value) -> Option<String> {
    let entries: Vec<&Value> = match affected {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => vec![affected],
        _ => return None,
    };
    fixed_in(ecosystem, installed, entries)
}

/// Like `fixed_version` but takes a record's full `affected` array and only considers
/// entries whose `package.name` is `name`.
pub fn fixed_version_for_package(
    ecosystem: &str,
    name: &str,
    installed: &str,
    affected: &Value,
) -> Option<String> {
    let entries: Vec<&Value> = affected
        .as_array()?
        .iter()
        .filter(|e| {
            e.pointer("/package/name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| names_match(ecosystem, n, name))
        })
        .collect();
    fixed_in(ecosystem, installed, entries)
}

fn fixed_in(ecosystem: &str, installed: &str, entries: Vec<&Value>) -> Option<String> {
    let installed = parse_version(ecosystem, installed)?;
    let mut best: Option<(Ver, &str)> = None;
    let ranges = entries
        .iter()
        .filter_map(|e| e.get("ranges")?.as_array())
        .flatten();
    for range in ranges.filter(|r| {
        matches!(
            r.get("type").and_then(|t| t.as_str()),
            Some("ECOSYSTEM" | "SEMVER")
        )
    }) {
        let mut introduced: Option<Ver> = None;
        for event in range
            .get("events")
            .and_then(|e| e.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(i) = event.get("introduced").and_then(|v| v.as_str()) {
                introduced = parse_version(ecosystem, i);
            } else if let Some(f) = event.get("fixed").and_then(|v| v.as_str()) {
                let intro = introduced.take();
                let (Some(intro), Some(fv)) = (intro, parse_version(ecosystem, f)) else {
                    continue;
                };
                if intro <= installed
                    && fv > installed
                    && best.as_ref().is_none_or(|(b, _)| fv < *b)
                {
                    best = Some((fv, f));
                }
            } else {
                // last_affected / limit end the open range without a fix
                introduced = None;
            }
        }
    }
    best.map(|(_, s)| s.to_string())
}

/// Ordering of two versions in an ecosystem; None if either is unparsable.
pub fn compare_versions(ecosystem: &str, a: &str, b: &str) -> Option<Ordering> {
    Some(parse_version(ecosystem, a)?.cmp(&parse_version(ecosystem, b)?))
}

fn shell_quote_dir(dir: &Path) -> String {
    let mut out = String::from("\"");
    for c in dir.to_string_lossy().chars() {
        if matches!(c, '"' | '\\' | '$' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Exact command for a direct dependency, run in the lockfile's directory; for transitive
/// deps, the override mechanism as a short instruction. None if the ecosystem is unknown.
pub fn fix_command(
    lockfile: &Path,
    _ecosystem: &str,
    name: &str,
    fixed: &str,
    direct: Option<bool>,
) -> Option<String> {
    let file = lockfile.file_name()?.to_str()?;
    let transitive = direct == Some(false);
    // `npm pkg set a.b=…` treats dots as nesting, so dotted names get an instruction instead.
    let npm_family = matches!(
        file,
        "package-lock.json" | "npm-shrinkwrap.json" | "pnpm-lock.yaml" | "yarn.lock" | "bun.lock"
    );
    if transitive && npm_family && name.contains('.') {
        let key = match file {
            "pnpm-lock.yaml" => "pnpm.overrides",
            "yarn.lock" => "resolutions",
            _ => "overrides",
        };
        return Some(format!(
            "Add \"{name}\": \"{fixed}\" to \"{key}\" in package.json, then reinstall"
        ));
    }
    let cmd = match file {
        "package-lock.json" | "npm-shrinkwrap.json" if transitive => {
            format!("npm pkg set overrides.{name}={fixed} && npm install")
        }
        "package-lock.json" | "npm-shrinkwrap.json" => format!("npm install {name}@{fixed}"),
        "pnpm-lock.yaml" if transitive => {
            format!("pnpm pkg set pnpm.overrides.{name}={fixed} && pnpm install")
        }
        "pnpm-lock.yaml" => format!("pnpm add {name}@{fixed}"),
        "yarn.lock" if transitive => {
            format!("npm pkg set resolutions.{name}={fixed} && yarn install")
        }
        "yarn.lock" => format!("yarn add {name}@{fixed}"),
        "bun.lock" if transitive => format!("npm pkg set overrides.{name}={fixed} && bun install"),
        "bun.lock" => format!("bun add {name}@{fixed}"),
        "uv.lock" if transitive => format!("uv lock --upgrade-package {name}"),
        "uv.lock" => format!("uv add '{name}>={fixed}'"),
        "poetry.lock" if transitive => format!("poetry update {name}"),
        "poetry.lock" => format!("poetry add '{name}>={fixed}'"),
        "pdm.lock" => format!("pdm add '{name}>={fixed}'"),
        "Pipfile.lock" => format!("pipenv install '{name}>={fixed}'"),
        f if f.starts_with("requirements") && f.ends_with(".txt") => {
            format!("pip install '{name}>={fixed}'")
        }
        "composer.lock" => format!("composer require '{name}:^{fixed}'"),
        "go.mod" => format!("go get {name}@v{}", fixed.trim_start_matches('v')),
        "Cargo.lock" => format!("cargo update -p {name} --precise {fixed}"),
        "Gemfile.lock" => format!("bundle update {name}"),
        _ => return None,
    };
    let dir = lockfile.parent().unwrap_or(Path::new("."));
    Some(format!("cd {} && {cmd}", shell_quote_dir(dir)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn affected(ranges: Value) -> Value {
        json!([{ "package": {"name": "x", "ecosystem": "any"}, "ranges": ranges }])
    }

    #[test]
    fn canonical_prefers_cve_then_ghsa() {
        assert_eq!(
            canonical_id(
                &s(&["PYSEC-2023-62", "GHSA-m2qf-hxjv-5gpq"]),
                &s(&["CVE-2023-30861", "GHSA-m2qf-hxjv-5gpq"])
            ),
            "CVE-2023-30861"
        );
        assert_eq!(
            canonical_id(&s(&["PYSEC-1", "GHSA-a"]), &s(&["GHSA-a"])),
            "GHSA-a"
        );
        assert_eq!(canonical_id(&s(&["RUSTSEC-1"]), &[]), "RUSTSEC-1");
        assert_eq!(canonical_id(&[], &[]), "");
    }

    #[test]
    fn fixed_picks_range_containing_installed() {
        let a = affected(json!([{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "2.2.5"}, {"introduced": "2.3.0"}, {"fixed": "2.3.2"}]}]));
        assert_eq!(fixed_version("PyPI", "2.0.0", &a).as_deref(), Some("2.2.5"));
        assert_eq!(fixed_version("PyPI", "2.3.1", &a).as_deref(), Some("2.3.2"));
        // between the ranges: not affected, no fix to suggest
        assert_eq!(fixed_version("PyPI", "2.2.5", &a), None);
        assert_eq!(fixed_version("PyPI", "2.2.9", &a), None);
        // above every fix
        assert_eq!(fixed_version("PyPI", "3.0.0", &a), None);
    }

    #[test]
    fn fixed_ignores_git_ranges_and_takes_lowest_across_entries() {
        let a = json!([
            {"package": {"name": "x"}, "ranges": [
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "70f906c51ce49c485f1d355703e9cc3386b1cc2b"}]},
                {"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.23"}]}]},
            {"package": {"name": "x"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}
        ]);
        assert_eq!(
            fixed_version("npm", "4.17.20", &a).as_deref(),
            Some("4.17.21")
        );
    }

    #[test]
    fn fixed_introduced_after_installed_is_not_affected() {
        let a = affected(
            json!([{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]),
        );
        assert_eq!(fixed_version("npm", "1.5.0", &a), None);
    }

    #[test]
    fn fixed_semver_prerelease_and_padding() {
        let a = affected(
            json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}]),
        );
        assert_eq!(fixed_version("npm", "1.1.9", &a).as_deref(), Some("1.2"));
        assert_eq!(
            fixed_version("npm", "1.2.0-rc.1", &a).as_deref(),
            Some("1.2")
        );
        assert_eq!(fixed_version("npm", "1.2.0", &a), None);
    }

    #[test]
    fn fixed_go_v_prefix() {
        let a = affected(
            json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]),
        );
        assert_eq!(fixed_version("Go", "v1.2.0", &a).as_deref(), Some("1.2.3"));
        assert_eq!(fixed_version("Go", "v1.10.0", &a), None);
        let b = affected(
            json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "v1.2.3"}]}]),
        );
        assert_eq!(fixed_version("Go", "v1.2.0", &b).as_deref(), Some("v1.2.3"));
    }

    #[test]
    fn fixed_pep440_ordering() {
        // 2.0.0rc1 < 2.0.0, and 1.10 > 1.9 numerically
        let a = affected(
            json!([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]),
        );
        assert_eq!(
            fixed_version("PyPI", "2.0.0rc1", &a).as_deref(),
            Some("2.0.0")
        );
        let b = affected(
            json!([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.10"}]}]),
        );
        assert_eq!(fixed_version("PyPI", "1.9", &b).as_deref(), Some("1.10"));
        assert_eq!(fixed_version("PyPI", "1.10.1", &b), None);
    }

    #[test]
    fn fixed_dotted_fallback() {
        let a = affected(
            json!([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.0.10"}]}]),
        );
        assert_eq!(
            fixed_version("RubyGems", "7.0.9", &a).as_deref(),
            Some("7.0.10")
        );
        assert_eq!(fixed_version("RubyGems", "7.0.10", &a), None);
    }

    #[test]
    fn garbage_never_panics() {
        let a = affected(
            json!([{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]),
        );
        assert_eq!(fixed_version("npm", "not-a-version", &a), None);
        assert_eq!(fixed_version("npm", "", &a), None);
        assert_eq!(fixed_version("PyPI", "???", &a), None);
        assert_eq!(fixed_version("Go", "master", &a), None);
        let bad = affected(
            json!([{"type": "SEMVER", "events": [{"introduced": "zzz"}, {"fixed": "1.0.0"}, {"introduced": "0"}, {"fixed": "oops"}]}]),
        );
        assert_eq!(fixed_version("npm", "0.5.0", &bad), None);
        assert_eq!(fixed_version("npm", "0.5.0", &Value::Null), None);
        assert_eq!(
            fixed_version(
                "npm",
                "0.5.0",
                &json!([{"no": "ranges"}, 7, {"ranges": [{"type": "SEMVER"}]}])
            ),
            None
        );
    }

    #[test]
    fn for_package_filters_by_name() {
        let a = json!([
            {"package": {"name": "lodash-es"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]},
            {"package": {"name": "Foo_Bar"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.5"}]}]}
        ]);
        assert_eq!(
            fixed_version_for_package("npm", "lodash", "4.17.20", &a),
            None
        );
        assert_eq!(
            fixed_version_for_package("PyPI", "foo-bar", "1.0", &a).as_deref(),
            Some("1.2.5")
        );
    }

    fn cmd(file: &str, name: &str, fixed: &str, direct: Option<bool>) -> String {
        fix_command(
            Path::new("/p/app").join(file).as_path(),
            "x",
            name,
            fixed,
            direct,
        )
        .unwrap()
    }

    #[test]
    fn commands_direct() {
        assert_eq!(
            cmd("package-lock.json", "lodash", "4.17.21", Some(true)),
            r#"cd "/p/app" && npm install lodash@4.17.21"#
        );
        assert_eq!(
            cmd("package-lock.json", "lodash", "4.17.21", None),
            r#"cd "/p/app" && npm install lodash@4.17.21"#
        );
        assert_eq!(
            cmd("pnpm-lock.yaml", "a", "1.0.0", Some(true)),
            r#"cd "/p/app" && pnpm add a@1.0.0"#
        );
        assert_eq!(
            cmd("yarn.lock", "a", "1.0.0", Some(true)),
            r#"cd "/p/app" && yarn add a@1.0.0"#
        );
        assert_eq!(
            cmd("bun.lock", "a", "1.0.0", Some(true)),
            r#"cd "/p/app" && bun add a@1.0.0"#
        );
        assert_eq!(
            cmd("uv.lock", "flask", "2.2.5", Some(true)),
            r#"cd "/p/app" && uv add 'flask>=2.2.5'"#
        );
        assert_eq!(
            cmd("poetry.lock", "flask", "2.2.5", Some(true)),
            r#"cd "/p/app" && poetry add 'flask>=2.2.5'"#
        );
        assert_eq!(
            cmd("pdm.lock", "flask", "2.2.5", Some(true)),
            r#"cd "/p/app" && pdm add 'flask>=2.2.5'"#
        );
        assert_eq!(
            cmd("Pipfile.lock", "flask", "2.2.5", Some(true)),
            r#"cd "/p/app" && pipenv install 'flask>=2.2.5'"#
        );
        assert_eq!(
            cmd("requirements-dev.txt", "flask", "2.2.5", Some(true)),
            r#"cd "/p/app" && pip install 'flask>=2.2.5'"#
        );
        assert_eq!(
            cmd("composer.lock", "a/b", "1.2.3", Some(true)),
            r#"cd "/p/app" && composer require 'a/b:^1.2.3'"#
        );
        assert_eq!(
            cmd("go.mod", "github.com/a/b", "1.2.3", Some(true)),
            r#"cd "/p/app" && go get github.com/a/b@v1.2.3"#
        );
        assert_eq!(
            cmd("go.mod", "github.com/a/b", "v1.2.3", Some(true)),
            r#"cd "/p/app" && go get github.com/a/b@v1.2.3"#
        );
        assert_eq!(
            cmd("Cargo.lock", "time", "0.3.36", Some(true)),
            r#"cd "/p/app" && cargo update -p time --precise 0.3.36"#
        );
        assert_eq!(
            cmd("Gemfile.lock", "rails", "7.0.1", Some(true)),
            r#"cd "/p/app" && bundle update rails"#
        );
    }

    #[test]
    fn commands_transitive() {
        assert_eq!(
            cmd("package-lock.json", "minimist", "1.2.6", Some(false)),
            r#"cd "/p/app" && npm pkg set overrides.minimist=1.2.6 && npm install"#
        );
        assert_eq!(
            cmd("pnpm-lock.yaml", "a", "1.0.0", Some(false)),
            r#"cd "/p/app" && pnpm pkg set pnpm.overrides.a=1.0.0 && pnpm install"#
        );
        assert_eq!(
            cmd("yarn.lock", "a", "1.0.0", Some(false)),
            r#"cd "/p/app" && npm pkg set resolutions.a=1.0.0 && yarn install"#
        );
        assert_eq!(
            cmd("bun.lock", "a", "1.0.0", Some(false)),
            r#"cd "/p/app" && npm pkg set overrides.a=1.0.0 && bun install"#
        );
        assert_eq!(
            cmd("uv.lock", "urllib3", "1.26.5", Some(false)),
            r#"cd "/p/app" && uv lock --upgrade-package urllib3"#
        );
        assert_eq!(
            cmd("poetry.lock", "urllib3", "1.26.5", Some(false)),
            r#"cd "/p/app" && poetry update urllib3"#
        );
        assert_eq!(
            cmd("Cargo.lock", "time", "0.3.36", Some(false)),
            r#"cd "/p/app" && cargo update -p time --precise 0.3.36"#
        );
    }

    #[test]
    fn command_dir_is_quoted_and_unknown_is_none() {
        let c = fix_command(Path::new("/p/my $app/yarn.lock"), "npm", "a", "1.0.0", None).unwrap();
        assert_eq!(c, r#"cd "/p/my \$app" && yarn add a@1.0.0"#);
        assert_eq!(
            fix_command(Path::new("/p/mix.lock"), "Hex", "a", "1.0.0", None),
            None
        );
    }
}

#[cfg(test)]
mod dotted_name_tests {
    use super::fix_command;
    use std::path::Path;

    #[test]
    fn dotted_npm_name_gets_instruction_not_nested_key() {
        let c = fix_command(Path::new("/p/app/package-lock.json"), "npm", "lodash.merge", "4.6.2", Some(false)).unwrap();
        assert_eq!(c, r#"Add "lodash.merge": "4.6.2" to "overrides" in package.json, then reinstall"#);
    }
}
