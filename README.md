# NoVul

A menu bar app that keeps an eye on everything you've installed on your Mac and tells you what to fix.

NoVul finds the projects on your Mac and checks every locked dependency against public vulnerability
data. It also covers your Homebrew packages, language runtimes, global packages and AI coding tools,
and looks for API keys left in plain-text files. It checks again every 30 minutes and as soon as a
lockfile changes, and notifies you only when something matters.

Everything runs locally. Nothing about your code or your keys leaves your Mac (see [Privacy](#privacy)).

![NoVul: a radar of open issues by project and severity, next to a fix plan ranked by what to fix first](docs/screenshots/main.webp)

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/fix-with-agent.webp" alt="Fix with agent menu: copy a prompt for Claude Code or Codex, or open one in Terminal"></td>
    <td width="50%"><img src="docs/screenshots/this-mac.webp" alt="This Mac tab: runtimes past end of life and their advisories"></td>
  </tr>
  <tr>
    <td><b>Fix with agent.</b> Hand the findings to Claude Code or Codex with one prompt.</td>
    <td><b>This Mac.</b> Runtimes, Homebrew, global installs and AI tools.</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/secrets.webp" alt="Secrets tab: exposed keys with file, line and a one-click permission fix, never the value"></td>
    <td><img src="docs/screenshots/onboarding.webp" alt="First run: NoVul suggests the folders where your code lives"></td>
  </tr>
  <tr>
    <td><b>Exposed secrets.</b> Where each key is and how to lock it down, never the value.</td>
    <td><b>First run.</b> Pick the folders where your code lives.</td>
  </tr>
</table>

<sub>Screenshots use NoVul's built-in demo data.</sub>

## What it checks

- **Project dependencies.** Lockfiles for npm, pnpm, Yarn, Bun, uv, Poetry, Pipenv, PDM,
  `requirements*.txt`, Composer, Go, Cargo, Bundler, Dart/Flutter and Mix, matched against
  [OSV.dev](https://osv.dev).
- **Homebrew packages** and **global installs** (npm/pnpm/Bun globals, pipx and uv tools,
  `cargo install`, Go binaries, gems).
- **Runtimes** (Node, Python, PHP, Go, Ruby, Java), including versions past end of life.
- **AI coding tools.** Claude Code, Codex and Ollama, and the runtimes bundled inside them.
- **Exposed secrets.** API keys and tokens in project folders and common config files, found with
  [gitleaks](https://github.com/gitleaks/gitleaks). NoVul never stores or shows the key itself, only
  where it is and how to move it somewhere safer. Keys for services that had a recent public breach
  are ranked higher.

Findings are ranked by what to fix first: **malicious** packages, then vulnerabilities **actively
exploited** in the wild ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)),
then by severity, with [EPSS](https://www.first.org/epss) exploit likelihood as a tiebreaker. Each
finding comes with the command that fixes it for that project's package manager.

## Install

Requires a Mac with Apple Silicon and macOS 13 or later.

1. Download `NoVul_<version>_aarch64.dmg` from [Releases](../../releases) and drag NoVul to Applications.
2. Open it. NoVul asks where your code lives, suggests folders it found, and starts the first scan.
   Package results arrive in a minute or two; the check for exposed secrets runs right after.

NoVul lives in the menu bar (no Dock icon) and uses about 20 MB of memory while idle. Scans run in a
separate low-priority process that exits when it's done.

## Use it from your coding agent

NoVul includes a CLI and an MCP server, so Claude Code, Codex or another agent can read the
findings for the repo it's working in, fix them and ask NoVul to rescan. The app itself has no AI
features and needs no API keys.

The quickest way: click **Fix with agent** above the chart. It copies a prompt for Claude Code or
Codex (or opens one in Terminal) that tells the agent how to read NoVul's findings, fix them project
by project, run your tests and rescan. Pick a project in the chart first to focus on just that one.

To connect an agent permanently:

```bash
claude mcp add novul -- /Applications/NoVul.app/Contents/MacOS/novul mcp
```

```bash
/Applications/NoVul.app/Contents/MacOS/novul findings --project "$PWD"
```

`novul scan --all` runs a full scan from the terminal (projects, this Mac, then secrets), the same
as **Scan Now** in the menu bar.

See [agent/setup.md](agent/setup.md) for Codex, OpenCode, the Claude Code skill and an AGENTS.md
snippet.

## Privacy

NoVul has no account, no telemetry and no server of its own. It makes these requests:

| Service | What is sent | Why |
|---|---|---|
| [OSV.dev](https://osv.dev) | package names and versions | find known vulnerabilities |
| [deps.dev](https://deps.dev) | package names and versions from `requirements.txt` files | estimate versions that aren't pinned |
| [FIRST EPSS](https://www.first.org/epss) | CVE ids | exploit likelihood |
| [endoflife.date](https://endoflife.date) | runtime names (e.g. `nodejs`) | end-of-life dates |
| GitHub API | names of public tool repositories | advisories for AI coding tools |
| CISA, Have I Been Pwned | nothing (public lists are downloaded) | exploited vulnerabilities, recent breaches |

Your source code, file contents, file paths and secrets are never sent. Results are stored in a local
SQLite database in `~/Library/Application Support/dev.novul.app/`.

## Build from source

You need [Rust](https://rustup.rs) and [Bun](https://bun.sh).

```bash
bun install
scripts/fetch-sidecars.sh
bun run tauri dev
```

`fetch-sidecars.sh` downloads the pinned osv-scanner and gitleaks releases and verifies them against
`sidecars/SHA256SUMS`. `bun run tauri build` builds the app and DMG; `scripts/release.sh` also signs
and notarizes them (needs an Apple Developer ID). Run the tests with `cargo test --lib` in `src-tauri`.

## License

NoVul is licensed under the [Apache License 2.0](LICENSE). It bundles osv-scanner (Apache 2.0) and
gitleaks (MIT), and uses data from OSV.dev, CISA, FIRST, Have I Been Pwned (CC BY 4.0) and
endoflife.date. See [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
