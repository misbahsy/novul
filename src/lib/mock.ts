import type { AppState, Counts, FindingView, Overview, Priority, RootSuggestion, RuntimeStatus, Settings } from "./types";

/** `?mock=real|empty|scanning`; anything else is the small realistic set. */
const scenario = new URLSearchParams(location.search).get("mock");

const HOME = "/Users/dev/Workspace";
const PRI = { M: "malicious", x: "exploited", c: "critical", h: "high", m: "medium", l: "low", u: "unrated" } as const;
type Code = keyof typeof PRI;
// id, priority, score, fixed, summary
type Adv = [string, Code, number | null, string | null, string];
interface Pkg { eco: string; name: string; ver: string[]; p: number; dev?: boolean; advs: Adv[] }

const lodash: Adv[] = [
  ["CVE-2021-23337", "h", 7.2, "4.17.21", "Command injection in lodash template"],
  ["CVE-2020-8203", "h", 7.4, "4.17.21", "Prototype pollution in zipObjectDeep"],
  ["CVE-2019-10744", "c", 9.1, "4.17.21", "Prototype pollution in defaultsDeep"],
  ["CVE-2020-28500", "m", 5.3, "4.17.21", "Regular expression denial of service in toNumber, trim and trimEnd"],
  ["CVE-2018-16487", "h", 8.1, "4.17.21", "Prototype pollution in merge, mergeWith and defaultsDeep"],
];
const axios: Adv[] = [
  ["CVE-2023-45857", "m", 6.5, "1.6.0", "Axios leaks the XSRF-TOKEN cookie to third-party hosts"],
  ["CVE-2024-39338", "h", 7.5, "1.7.4", "SSRF via path-relative URLs in axios"],
  ["CVE-2025-27152", "h", 7.7, "1.8.2", "Absolute URLs bypass baseURL and leak credentials"],
];

// ---------- small default scenario ----------
const L = (d: string, f: string) => `${HOME}/${d}/${f}`;
const P = {
  site: ["portfolio-site", L("Development/Web/portfolio-site", "package-lock.json")],
  dash: ["client-dashboard", L("Development/Web/client-dashboard", "bun.lock")],
  docs: ["docs-site", L("Development/Web/docs-site", "pnpm-lock.yaml")],
  takes: ["notes-app", L("Development/Desktop-Tools/notes-app", "Cargo.lock")],
  takesui: ["notes-app", L("Development/Desktop-Tools/notes-app", "bun.lock")],
  tts: ["voice-tts", L("Tools/AI/voice-tts", "uv.lock")],
  gate: ["api-gateway", L("Development/Backend/api-gateway", "go.sum")],
  nb: ["ml-notebooks", L("Research/ml-notebooks", "poetry.lock")],
  bill: ["billing-service", L("Development/Backend/billing-service", "composer.lock")],
  rt: ["Runtimes", "/usr/local/bin"],
  brew: ["Homebrew", "/opt/homebrew"],
} as const;

type Row = [keyof typeof P, string, string, string, string | null, string, Priority, number | null, boolean | null, boolean, string];
const rows: Row[] = [
  ["site", "npm", "next", "14.1.0", "14.2.10", "CVE-2024-46982", "high", 7.5, true, false, "Cache poisoning in Next.js pages router data requests"],
  ["site", "npm", "next", "14.1.0", "14.1.1", "CVE-2024-34351", "high", 7.5, true, false, "Server-Side Request Forgery in Server Actions"],
  ["site", "npm", "next", "14.1.0", "14.2.25", "CVE-2025-29927", "exploited", 9.1, true, false, "Authorization bypass in Next.js middleware"],
  ["dash", "npm", "next", "13.4.2", "14.2.25", "CVE-2025-29927", "exploited", 9.1, true, false, "Authorization bypass in Next.js middleware"],
  ["site", "npm", "postcss", "8.4.31", "8.4.38", "CVE-2023-44270", "medium", 5.3, false, true, "Line return parsing error in PostCSS"],
  ["site", "npm", "braces", "3.0.2", "3.0.3", "CVE-2024-4068", "high", 7.5, false, true, "Uncontrolled resource consumption in braces"],
  ["site", "npm", "ws", "8.13.0", "8.17.1", "CVE-2024-37890", "high", 7.5, false, true, "DoS when handling a request with many HTTP headers"],
  ["site", "npm", "cross-spawn", "7.0.3", "7.0.5", "CVE-2024-21538", "high", 7.5, false, false, "Regular Expression Denial of Service in cross-spawn"],
  ["dash", "npm", "cross-spawn", "7.0.3", "7.0.5", "CVE-2024-21538", "high", 7.5, false, false, "Regular Expression Denial of Service in cross-spawn"],
  ["site", "npm", "micromatch", "4.0.5", "4.0.8", "CVE-2024-4067", "medium", 5.3, false, true, "Regular Expression Denial of Service in micromatch"],
  ["site", "npm", "colors-utils-pro", "2.3.1", null, "MAL-2025-4731", "malicious", null, false, false, "Malicious code in colors-utils-pro: exfiltrates environment variables and SSH keys on install"],
  ["site", "npm", "nanoid", "3.3.4", "3.3.8", "CVE-2024-55565", "medium", 4.3, false, false, "Predictable results in nanoid generation when given non-integer values"],
  ["dash", "npm", "nanoid", "3.3.4", "3.3.8", "CVE-2024-55565", "medium", 4.3, false, false, "Predictable results in nanoid generation when given non-integer values"],
  ["docs", "npm", "nanoid", "3.3.6", "3.3.8", "CVE-2024-55565", "medium", 4.3, false, false, "Predictable results in nanoid generation when given non-integer values"],
  ["site", "npm", "vite", "5.0.2", "5.0.12", "CVE-2024-23331", "high", 7.5, true, true, "Vite dev server bypasses server.fs.deny on case-insensitive filesystems"],
  ["docs", "npm", "vite", "5.0.2", "5.0.12", "CVE-2024-23331", "high", 7.5, true, true, "Vite dev server bypasses server.fs.deny on case-insensitive filesystems"],
  ["site", "npm", "esbuild", "0.19.5", "0.25.0", "GHSA-67mh-4wv8-2f99", "medium", 5.3, false, true, "esbuild dev server allows any website to send requests and read the response"],
  ["takes", "crates.io", "tokio", "1.28.0", "1.38.2", "RUSTSEC-2025-0023", "medium", 5.9, true, false, "Broadcast channel calls clone in parallel but not drop"],
  ["takes", "crates.io", "rustls", "0.21.6", "0.21.11", "RUSTSEC-2024-0336", "high", 7.5, false, false, "rustls::ConnectionCommon::complete_io could fall into an infinite loop"],
  ["takes", "crates.io", "h2", "0.3.20", "0.3.26", "RUSTSEC-2024-0332", "medium", 5.3, false, false, "Degradation of service in h2 via CONTINUATION frames"],
  ["takes", "crates.io", "time", "0.3.20", "0.3.35", "RUSTSEC-2026-0009", "low", 3.3, false, false, "Stack exhaustion when parsing deeply nested input"],
  ["takesui", "npm", "tar", "6.1.11", "6.2.1", "CVE-2024-28863", "medium", 6.5, false, true, "Denial of service while parsing a tar file due to lack of folders count validation"],
  ["takesui", "npm", "@tauri-apps/api", "2.0.0", "2.0.3", "GHSA-8rmx-8f9j-c3fc", "low", 3.1, true, false, "Tauri IPC origin check can be bypassed from nested iframes"],
  ["takesui", "npm", "d3-color", "2.0.0", "3.1.0", "CVE-2022-31129", "high", 7.5, false, false, "Regular expression denial of service in d3-color"],
  ["tts", "PyPI", "pillow", "10.0.1", "10.3.0", "CVE-2024-28219", "high", 8.8, true, false, "Buffer overflow in _imagingcms.c"],
  ["tts", "PyPI", "numpy", "1.24.1", "1.26.0", "PYSEC-2021-856", "unrated", null, true, false, "Buffer overflow in numpy.f2py"],
  ["tts", "PyPI", "requests", "2.28.2", "2.32.0", "CVE-2024-35195", "medium", 5.6, true, false, "Requests Session object does not verify requests after making first request with verify=False"],
  ["nb", "PyPI", "requests", "2.28.1", "2.32.0", "CVE-2024-35195", "medium", 5.6, true, false, "Requests Session object does not verify requests after making first request with verify=False"],
  ["tts", "PyPI", "urllib3", "1.26.15", "1.26.19", "CVE-2024-37891", "medium", 4.4, false, false, "Proxy-Authorization header not stripped on cross-origin redirects"],
  ["tts", "PyPI", "jinja2", "3.1.2", "3.1.5", "CVE-2024-56326", "high", 7.8, false, false, "Jinja has a sandbox breakout through indirect reference to format method"],
  ["tts", "PyPI", "transformers", "4.30.2", "4.38.0", "CVE-2024-3568", "critical", 9.6, true, false, "Deserialization of untrusted data in the Transformers TensorFlow loader"],
  ["tts", "PyPI", "gradio", "3.50.2", "4.44.1", "CVE-2024-47867", "critical", 9.1, true, false, "Gradio lacks integrity checking on the downloaded FRP client"],
  ["tts", "PyPI", "aiohttp", "3.8.4", "3.9.4", "CVE-2024-30251", "high", 7.5, false, false, "aiohttp vulnerable to Denial of Service when trying to parse malformed POST requests"],
  ["tts", "PyPI", "setuptools", "65.5.0", "70.0.0", "CVE-2024-6345", "high", 8.8, false, true, "Remote code execution via download functions in package_index"],
  ["gate", "Go", "golang.org/x/net", "v0.17.0", "v0.23.0", "CVE-2023-45288", "high", 7.5, true, false, "HTTP/2 CONTINUATION flood in net/http"],
  ["gate", "Go", "golang.org/x/crypto", "v0.14.0", "v0.31.0", "CVE-2024-45337", "critical", 9.1, true, false, "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in x/crypto"],
  ["gate", "Go", "github.com/gin-gonic/gin", "v1.9.0", "v1.9.1", "CVE-2023-29401", "medium", 5.3, true, false, "Gin Web Framework does not properly sanitize filename parameter of Context.FileAttachment"],
  ["gate", "Go", "github.com/golang-jwt/jwt/v4", "v4.4.2", "v4.5.1", "CVE-2024-51744", "low", 3.1, false, false, "Bad documentation of error handling in ParseWithClaims can lead to potentially dangerous situations"],
  ["gate", "Go", "google.golang.org/grpc", "v1.56.0", "v1.56.3", "CVE-2023-44487", "high", 7.5, false, false, "HTTP/2 rapid reset can cause excessive resource consumption"],
  ["gate", "Go", "github.com/docker/docker", "v24.0.5", "v25.0.6", "CVE-2024-41110", "critical", 9.9, false, false, "Authz zero length regression"],
  ["nb", "PyPI", "scikit-learn", "1.1.3", "1.5.0", "CVE-2024-5206", "medium", 5.3, true, false, "Sensitive data leakage in TfidfVectorizer"],
  ["nb", "PyPI", "jupyterlab", "3.6.1", "3.6.7", "CVE-2024-22421", "high", 7.6, true, false, "JupyterLab XSS via malicious notebook rendering"],
  ["nb", "PyPI", "notebook", "6.5.2", "6.5.7", "CVE-2024-35179", "low", 3.5, false, false, "Jupyter Notebook open redirect in the login page"],
  ["nb", "PyPI", "pandas", "1.5.3", null, "PYSEC-2023-217", "unrated", null, true, false, "Possible memory disclosure in pandas.read_sas"],
  ["nb", "PyPI", "tornado", "6.2", "6.4.1", "CVE-2024-52804", "high", 7.5, false, false, "Tornado vulnerable to DoS due to too many multipart/form-data parts"],
  ["nb", "PyPI", "ipython", "8.8.0", "8.10.0", "CVE-2023-24816", "high", 7.8, false, true, "IPython vulnerable to command injection through the ipython_cve_2023_24816 path"],
  ["nb", "PyPI", "matplotlib", "3.6.2", null, "GHSA-3x8f-q6fc-hq3p", "low", 2.5, true, false, "Insecure temporary directory permissions in matplotlib cache"],
  ["bill", "Packagist", "symfony/http-kernel", "5.4.20", "5.4.46", "CVE-2024-50340", "medium", 5.3, true, false, "Symfony HttpKernel trusts the _controller query parameter"],
  ["bill", "Packagist", "guzzlehttp/guzzle", "7.4.5", "7.9.2", "CVE-2022-31091", "high", 7.7, true, false, "Guzzle failure to strip Authorization header on HTTP downgrade"],
  ["bill", "Packagist", "laravel/framework", "9.52.4", "9.52.16", "CVE-2024-13919", "critical", 9.8, true, false, "Laravel framework XSS in the debug-mode error page"],
  ["bill", "Packagist", "league/commonmark", "2.3.8", "2.4.0", "CVE-2024-24807", "low", 3.7, false, false, "CommonMark allows loading unsafe attribute names via the Attributes extension"],
  ["bill", "Packagist", "phpunit/phpunit", "9.5.28", "9.6.19", "GHSA-vv7q-hmfp-8m4c", "unrated", null, true, true, "PHPUnit unsafe deserialization in PHPT code coverage handling"],
  ["rt", "Runtime", "node", "20.11.0", "20.18.1", "CVE-2024-36137", "high", 7.5, null, false, "Node.js permission model bypass via path traversal"],
  ["rt", "Runtime", "node", "20.11.0", "20.12.1", "CVE-2024-27983", "high", 8.2, null, false, "Node.js HTTP/2 server crash via a continuation frame flood"],
  ["rt", "Runtime", "python", "3.9.6", "3.9.20", "CVE-2024-6232", "medium", 7.5, null, false, "Regular expression denial of service when parsing tarfile headers"],
  ["rt", "Runtime", "python", "3.9.6", "3.9.19", "CVE-2023-6597", "medium", 6.5, null, false, "Symlink bypass in tempfile.TemporaryDirectory cleanup"],
  ["rt", "Runtime", "go", "1.21.5", "1.21.9", "CVE-2024-24790", "critical", 9.8, null, false, "net/netip Is methods return incorrect results for IPv4-mapped IPv6 addresses"],
  ["rt", "Runtime", "ruby", "2.6.10", null, "CVE-2023-36617", "medium", 5.3, null, false, "Ruby URI regular expression denial of service"],
  ["brew", "Homebrew", "openssl@3", "3.1.2", "3.1.8", "CVE-2024-5535", "medium", 9.1, null, false, "SSL_select_next_proto buffer overread"],
  ["brew", "Homebrew", "curl", "8.4.0", "8.4.1", "CVE-2023-46218", "medium", 6.5, null, false, "Cookie mixed case PSL bypass in curl"],
  ["brew", "Homebrew", "webp", "1.3.1", "1.3.2", "CVE-2023-4863", "exploited", 8.8, null, false, "Heap buffer overflow in libwebp BuildHuffmanTable"],
  ["brew", "Homebrew", "sqlite", "3.43.1", "3.44.0", "CVE-2023-7104", "high", 7.3, null, false, "Heap-based buffer overflow in SQLite sessionReadRecord"],
  ["brew", "Homebrew", "git", "2.42.0", "2.43.5", "CVE-2024-32002", "critical", 9.0, null, false, "Remote code execution while cloning repositories with submodules"],
  ["brew", "Homebrew", "ffmpeg", "6.0", "6.1.2", "CVE-2024-32230", "low", 3.3, null, false, "FFmpeg h264 parsing issue in the decoder"],
  ["brew", "Homebrew", "libxml2", "2.11.5", "2.12.7", "CVE-2024-25062", "medium", 7.5, null, false, "libxml2 use-after-free in xmlReader"],
  ["brew", "Homebrew", "imagemagick", "7.1.1-15", null, "CVE-2023-34152", "unrated", null, null, false, "ImageMagick remote shell injection via pipe filenames"],
];
for (const pk of ["site", "dash", "docs", "takesui"] as const)
  for (const [id, c, score, fixed, summary] of lodash)
    rows.push([pk, "npm", "lodash", "4.17.15", fixed, id, PRI[c], score, pk === "dash", false, summary]);
for (const pk of ["site", "dash", "takesui"] as const)
  for (const [id, c, score, fixed, summary] of axios)
    rows.push([pk, "npm", "axios", "1.5.0", fixed, id, PRI[c], score, true, false, summary]);

const npmCommand = (lock: string, name: string, fixed: string) =>
  lock.endsWith("bun.lock") ? `bun add ${name}@${fixed}` : lock.endsWith("pnpm-lock.yaml") ? `pnpm add ${name}@${fixed}`
    : lock.endsWith("yarn.lock") ? `yarn add ${name}@${fixed}` : `npm install ${name}@${fixed}`;

function fixCommand(ecosystem: string, lock: string, name: string, fixed: string | null, malicious: boolean) {
  if (malicious) return `npm uninstall ${name}`;
  if (!fixed) return null;
  if (ecosystem === "Homebrew" || ecosystem === "Runtime") return `brew upgrade ${name.split("@")[0]}`;
  if (ecosystem === "npm") return npmCommand(lock, name, fixed);
  if (ecosystem === "PyPI") return `uv add '${name}>=${fixed}'`;
  if (ecosystem === "Go") return `go get ${name}@${fixed}`;
  if (ecosystem === "crates.io") return `cargo update -p ${name} --precise ${fixed}`;
  return `composer require ${name}:^${fixed}`;
}

/** Package fixes run inside their project folder, so the backend hands them over as `cd '<dir>' && ...`. */
const inFolder = (kind: FindingView["kind"], path: string, cmd: string | null) =>
  cmd && kind === "package" ? `cd '${path.replace(/\/[^/]*$/, "")}' && ${cmd}` : cmd;

const NOW = Math.floor(Date.now() / 1000);
const alias = (gid: string, i: number) =>
  gid.startsWith("CVE") ? `GHSA-${(i * 7919 + 3).toString(36).slice(0, 4)}-${(i * 104729 + 7).toString(36).slice(0, 4)}-${(i * 13 + 5).toString(36).slice(0, 4)}` : `CVE-2025-${30000 + (i % 900) * 13}`;

/** Stable per advisory id, shaped like real EPSS: exploited bugs score high, most others near zero. */
function epssFor(gid: string, priority: Priority): number | null {
  let h = 2166136261;
  for (const ch of gid) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
  const u = (h >>> 0) / 4294967296;
  if (priority === "malicious" || priority === "unrated" || u < 0.08) return null;
  const v = { exploited: 0.55 + 0.4 * u, critical: 0.03 + 0.6 * u * u, high: 0.002 + 0.3 * u * u, medium: 0.001 + 0.08 * u * u, low: 0.0004 + 0.02 * u * u }[priority];
  return Math.round(v * 10000) / 10000;
}

function make(i: number, kind: FindingView["kind"], eco: string, name: string, installed: string, fixed: string | null, gid: string,
  priority: Priority, score: number | null, direct: boolean | null, dev: boolean, summary: string, project: string, path: string): FindingView {
  return {
    id: i + 1, kind, group_id: gid, aliases: [alias(gid, i)], summary, priority, score, kev: priority === "exploited",
    ecosystem: eco, name, installed_version: installed, fixed_version: fixed, direct, dev, inferred: path.endsWith("requirements.txt"),
    project_path: path, project_name: project, fix_command: inFolder(kind, path, fixCommand(eco, path, name, fixed, priority === "malicious")),
    url: `https://osv.dev/vulnerability/${gid}`, first_seen_at: NOW - 86400 * (i % 9), muted: false, epss: epssFor(gid, priority),
  };
}

function small(): FindingView[] {
  return rows.map((r, i) => {
    const [pk, eco, name, installed, fixed, gid, priority, score, direct, dev, summary] = r;
    const kind = pk === "rt" ? "runtime" : pk === "brew" ? "brew" : "package";
    return make(i, kind, eco, name, installed, fixed, gid, priority, score, direct, dev, summary, P[pk][0], P[pk][1]);
  }).concat(extras(rows.length));
}

const runtimes: RuntimeStatus[] = [
  { kind: "node", version: "20.11.0", path: "/usr/local/bin/node", cycle: "20", latest_in_cycle: "20.18.1", latest_date: "2024-11-20", is_eol: false, behind: true },
  { kind: "python", version: "3.9.6", path: "/usr/bin/python3", cycle: "3.9", latest_in_cycle: "3.9.20", latest_date: "2024-09-06", is_eol: true, behind: true },
  { kind: "ruby", version: "2.6.10", path: "/usr/bin/ruby", cycle: "2.6", latest_in_cycle: "2.6.10", latest_date: "2022-04-12", is_eol: true, behind: false },
  { kind: "go", version: "1.21.5", path: "/usr/local/go/bin/go", cycle: "1.21", latest_in_cycle: "1.21.13", latest_date: "2024-08-06", is_eol: true, behind: true },
];

// ---------- v2 kinds: global packages, AI tools, secrets ----------
function extras(base: number): FindingView[] {
  const out: FindingView[] = [];
  const add = (...a: Parameters<typeof make> extends [number, ...infer R] ? R : never) => out.push(make(base + out.length, ...a));
  const G = "/opt/homebrew/lib/node_modules";
  add("global", "npm", "cross-spawn", "7.0.3", "7.0.5", "CVE-2024-21538", "high", 7.5, null, false, "Regular Expression Denial of Service in cross-spawn", "npm (global)", G);
  add("global", "npm", "tar", "6.1.11", "6.2.1", "CVE-2024-28863", "medium", 6.5, null, false, "Denial of service while parsing a tar file due to lack of folders count validation", "npm (global)", G);
  add("global", "npm", "tar", "6.1.11", "6.1.7", "CVE-2021-37701", "high", 8.6, null, false, "Arbitrary file creation/overwrite via insufficient symlink protection", "npm (global)", G);
  add("global", "npm", "semver", "7.3.8", "7.5.2", "CVE-2022-25883", "high", 7.5, null, false, "semver vulnerable to regular expression denial of service", "npm (global)", G);
  add("global", "PyPI", "requests", "2.25.1", "2.32.0", "CVE-2024-35195", "medium", 5.6, null, false, "Requests Session object does not verify requests after making first request with verify=False", "pipx", "/Users/dev/.local/pipx/venvs/httpie");
  add("global", "PyPI", "urllib3", "1.26.5", "1.26.19", "CVE-2024-37891", "medium", 4.4, null, false, "Proxy-Authorization header not stripped on cross-origin redirects", "pipx", "/Users/dev/.local/pipx/venvs/httpie");
  add("global", "crates.io", "time", "0.3.20", "0.3.35", "RUSTSEC-2026-0009", "low", 3.3, null, false, "Stack exhaustion when parsing deeply nested input", "cargo install", "/Users/dev/.cargo/bin");
  const CC = ["Claude Code 2.1.299", "/Users/dev/.local/bin/claude"] as const;
  add("tool", "Bundled", "bun", "1.4.3", "1.4.5", "GHSA-q8w4-hx6m-2c5f", "high", 7.8, null, false, "Bun: path traversal when extracting a crafted tarball during bun install (bundled with Claude Code)", ...CC);
  add("tool", "Bundled", "bun", "1.4.3", "1.4.4", "CVE-2026-31207", "medium", 5.3, null, false, "Bun: HTTP client forwards the Authorization header across redirects to other hosts", ...CC);
  add("tool", "AI tool", "codex", "0.160.0", "0.161.2", "GHSA-4m7r-p9xj-w2hc", "medium", 6.1, null, false, "Codex CLI: sandbox allows writes outside the workspace through a symlinked path", "Codex 0.160.0", "/opt/homebrew/bin/codex");
  out[out.length - 3].fix_command = "claude update";
  out[out.length - 2].fix_command = "claude update";
  out[out.length - 1].fix_command = "brew upgrade codex";

  const H = "/Users/dev";
  const secret = (det: string, path: string, line: number, what: string, priority: Priority, fp: string, chmod: boolean) => {
    const f = make(base + out.length, "secret", "Secret", det, fp, null, `SECRET-${det}-${fp}`, priority, null, null, false, `Line ${line}: ${what}`, path.split("/").pop()!, path);
    f.aliases = [];
    f.kev = false;
    f.url = "";
    f.epss = null;
    f.fix_command = chmod ? `chmod 600 '${path}'` : null;
    out.push(f);
  };
  secret("aws-access-token", `${H}/.aws/credentials`, 3, "AWS access key ID in a file other users on this Mac can read", "critical", "9f3a21c7", true);
  secret("github-pat", `${H}/.config/gh/hosts.yml`, 6, "GitHub personal access token in a file other users on this Mac can read", "critical", "b71e04d2", true);
  secret("openai-api-key", `${H}/.zshrc`, 41, "OpenAI API key exported in your shell profile", "high", "04c9e6aa", false);
  secret("stripe-access-token", `${HOME}/Development/Web/client-dashboard/.env`, 12, "Stripe live secret key in a project .env file", "high", "d2087b53", false);
  secret("npm-access-token", `${H}/.npmrc`, 2, "npm publish token in a file other users on this Mac can read", "high", "6ac15f90", true);
  secret("generic-api-key", `${HOME}/Development/Backend/billing-service/.env`, 8, "API key assigned to a variable named SECRET_KEY", "medium", "e8b3d71f", false);
  return out;
}

// ---------- `?mock=real`: ~4,300 findings, ~430 lockfiles, ~300 folders ----------
function rng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const catalogue: Pkg[] = [
  { eco: "npm", name: "lodash", ver: ["4.17.15", "4.17.19", "4.17.20"], p: 0.24, advs: lodash },
  { eco: "npm", name: "axios", ver: ["0.21.1", "1.4.0", "1.5.1", "1.6.2"], p: 0.3, advs: axios },
  { eco: "npm", name: "minimist", ver: ["1.2.0", "1.2.5"], p: 0.2, advs: [["CVE-2021-44906", "c", 9.8, "1.2.6", "Prototype pollution in minimist"], ["CVE-2020-7598", "m", 5.6, "1.2.3", "Prototype pollution in minimist"]] },
  { eco: "npm", name: "semver", ver: ["5.7.1", "6.3.0", "7.3.8"], p: 0.3, advs: [["CVE-2022-25883", "h", 7.5, "7.5.2", "semver vulnerable to regular expression denial of service"]] },
  { eco: "npm", name: "json5", ver: ["1.0.1", "2.2.1"], p: 0.25, advs: [["CVE-2022-46175", "h", 7.1, "2.2.2", "Prototype pollution in JSON5 via parse method"]] },
  { eco: "npm", name: "word-wrap", ver: ["1.2.3"], p: 0.2, advs: [["CVE-2023-26115", "m", 5.3, "1.2.4", "word-wrap vulnerable to regular expression denial of service"]] },
  { eco: "npm", name: "ws", ver: ["7.5.9", "8.13.0"], p: 0.25, dev: true, advs: [["CVE-2024-37890", "h", 7.5, "8.17.1", "DoS when handling a request with many HTTP headers"]] },
  { eco: "npm", name: "tar", ver: ["6.1.11", "6.1.15"], p: 0.2, advs: [["CVE-2024-28863", "m", 6.5, "6.2.1", "Denial of service while parsing a tar file due to lack of folders count validation"], ["CVE-2021-37701", "h", 8.6, "6.1.7", "Arbitrary file creation/overwrite via insufficient symlink protection"]] },
  { eco: "npm", name: "braces", ver: ["3.0.2"], p: 0.3, dev: true, advs: [["CVE-2024-4068", "h", 7.5, "3.0.3", "Uncontrolled resource consumption in braces"]] },
  { eco: "npm", name: "micromatch", ver: ["4.0.5"], p: 0.28, dev: true, advs: [["CVE-2024-4067", "m", 5.3, "4.0.8", "Regular Expression Denial of Service in micromatch"]] },
  { eco: "npm", name: "postcss", ver: ["8.4.21", "8.4.31"], p: 0.3, dev: true, advs: [["CVE-2023-44270", "m", 5.3, "8.4.31", "Line return parsing error in PostCSS"]] },
  { eco: "npm", name: "nanoid", ver: ["3.3.4", "3.3.6"], p: 0.2, advs: [["CVE-2024-55565", "m", 4.3, "3.3.8", "Predictable results in nanoid generation when given non-integer values"]] },
  { eco: "npm", name: "cross-spawn", ver: ["7.0.3"], p: 0.28, advs: [["CVE-2024-21538", "h", 7.5, "7.0.5", "Regular Expression Denial of Service in cross-spawn"]] },
  { eco: "npm", name: "path-to-regexp", ver: ["0.1.7", "6.2.1"], p: 0.2, advs: [["CVE-2024-45296", "h", 7.5, "0.1.10", "path-to-regexp outputs backtracking regular expressions"], ["CVE-2024-52798", "h", 7.5, "0.1.12", "path-to-regexp unpatched ReDoS in 0.1.x"]] },
  { eco: "npm", name: "express", ver: ["4.18.1", "4.18.2"], p: 0.15, advs: [["CVE-2024-29041", "m", 6.1, "4.19.2", "Express open redirect in malformed URLs"], ["CVE-2024-43796", "m", 5, "4.20.0", "Express XSS via response.redirect()"]] },
  { eco: "npm", name: "qs", ver: ["6.5.2", "6.10.3"], p: 0.18, advs: [["CVE-2022-24999", "h", 7.5, "6.2.4", "qs vulnerable to prototype pollution"]] },
  { eco: "npm", name: "follow-redirects", ver: ["1.14.9", "1.15.2"], p: 0.2, advs: [["CVE-2024-28849", "m", 6.5, "1.15.6", "Proxy-Authorization header kept across hosts"], ["CVE-2023-26159", "m", 6.1, "1.15.4", "Improper input validation of URLs"]] },
  { eco: "npm", name: "glob-parent", ver: ["3.1.0", "5.1.1"], p: 0.15, dev: true, advs: [["CVE-2020-28469", "h", 7.5, "5.1.2", "Regular expression denial of service in glob-parent"]] },
  { eco: "npm", name: "ansi-regex", ver: ["4.1.0", "5.0.0"], p: 0.15, advs: [["CVE-2021-3807", "h", 7.5, "5.0.1", "Inefficient regular expression complexity in ansi-regex"]] },
  { eco: "npm", name: "node-fetch", ver: ["2.6.1", "2.6.5"], p: 0.15, advs: [["CVE-2022-0235", "h", 8.8, "2.6.7", "node-fetch forwards secure headers to untrusted sites"]] },
  { eco: "npm", name: "tough-cookie", ver: ["2.5.0", "4.0.0"], p: 0.15, advs: [["CVE-2023-26136", "m", 6.5, "4.1.3", "Prototype pollution in tough-cookie"]] },
  { eco: "npm", name: "jsonwebtoken", ver: ["8.5.1"], p: 0.08, advs: [["CVE-2022-23529", "c", 9.8, "9.0.0", "jsonwebtoken insecure input validation in secretOrPublicKey"], ["CVE-2022-23540", "m", 6.4, "9.0.0", "jsonwebtoken allows insecure default algorithm"]] },
  { eco: "npm", name: "moment", ver: ["2.29.1"], p: 0.12, advs: [["CVE-2022-24785", "h", 7.5, "2.29.2", "Path traversal in moment.locale"], ["CVE-2022-31129", "h", 7.5, "2.29.4", "Inefficient parsing algorithm in moment"]] },
  { eco: "npm", name: "serialize-javascript", ver: ["5.0.1"], p: 0.12, advs: [["CVE-2024-11831", "m", 5.4, "6.0.2", "Cross-site scripting in serialize-javascript"]] },
  { eco: "npm", name: "webpack-dev-middleware", ver: ["5.3.3"], p: 0.1, dev: true, advs: [["CVE-2024-29180", "h", 7.4, "5.3.4", "Path traversal in webpack-dev-middleware"]] },
  { eco: "npm", name: "vite", ver: ["4.4.9", "5.0.2"], p: 0.14, dev: true, advs: [["CVE-2024-23331", "h", 7.5, "5.0.12", "Vite dev server bypasses server.fs.deny on case-insensitive filesystems"], ["GHSA-vg6x-rcgg-rjx6", "m", 5.3, "5.0.13", "Vite allows any website to send requests to the dev server"]] },
  { eco: "npm", name: "esbuild", ver: ["0.18.20", "0.19.5"], p: 0.25, dev: true, advs: [["GHSA-67mh-4wv8-2f99", "m", 5.3, "0.25.0", "esbuild dev server allows any website to send requests and read the response"]] },
  { eco: "npm", name: "rollup", ver: ["3.29.0"], p: 0.12, dev: true, advs: [["CVE-2024-47068", "h", 7.5, "3.29.5", "DOM clobbering gadget in bundled scripts"]] },
  { eco: "npm", name: "next", ver: ["13.4.2", "14.1.0"], p: 0.05, advs: [["CVE-2024-34351", "h", 7.5, "14.1.1", "Server-Side Request Forgery in Server Actions"], ["CVE-2024-46982", "h", 7.5, "14.2.10", "Cache poisoning in Next.js pages router data requests"], ["CVE-2025-29927", "x", 9.1, "14.2.25", "Authorization bypass in Next.js middleware"]] },
  { eco: "npm", name: "@babel/traverse", ver: ["7.20.0"], p: 0.1, dev: true, advs: [["CVE-2023-45133", "c", 9.3, "7.23.2", "Babel arbitrary code execution when compiling malicious code"]] },
  { eco: "npm", name: "cookie", ver: ["0.4.2", "0.5.0"], p: 0.12, advs: [["CVE-2024-47764", "m", 5.3, "0.7.0", "cookie accepts cookie name, path and domain with out of bounds characters"]] },
  { eco: "npm", name: "ejs", ver: ["3.1.6"], p: 0.1, advs: [["CVE-2022-29078", "c", 9.8, "3.1.7", "ejs template injection vulnerability"], ["CVE-2024-33883", "m", 4.8, "3.1.10", "ejs lacks certain pollution protection"]] },
  { eco: "npm", name: "webpack", ver: ["5.75.0"], p: 0.1, dev: true, advs: [["CVE-2023-28154", "c", 9.8, "5.76.0", "Cross-realm object access in webpack 5"]] },
  { eco: "npm", name: "vm2", ver: ["3.9.11"], p: 0.04, advs: [["CVE-2023-37466", "c", 9.8, null, "vm2 sandbox escape; the project is discontinued"]] },
  { eco: "npm", name: "request", ver: ["2.88.2"], p: 0.15, advs: [["GHSA-p8p7-x288-28g6", "m", 6.1, null, "Server-side request forgery in request; deprecated, no patch"]] },
  { eco: "npm", name: "minimatch", ver: ["3.0.4"], p: 0.25, dev: true, advs: [["CVE-2022-3517", "h", 7.5, "3.0.5", "minimatch ReDoS via the braceExpand function"]] },
  { eco: "npm", name: "brace-expansion", ver: ["1.1.11", "2.0.1"], p: 0.3, dev: true, advs: [["CVE-2025-5889", "l", 1.3, "2.0.2", "brace-expansion regular expression denial of service"]] },
  { eco: "npm", name: "form-data", ver: ["2.3.3", "4.0.0"], p: 0.2, advs: [["CVE-2025-7783", "c", 9.4, "4.0.4", "form-data uses unsafe random for boundary values"]] },
  { eco: "npm", name: "socket.io-parser", ver: ["4.0.4"], p: 0.08, advs: [["CVE-2022-2421", "c", 9.8, "4.0.5", "Insufficient validation when decoding a Socket.IO packet"]] },
  { eco: "PyPI", name: "urllib3", ver: ["1.26.5", "1.26.15"], p: 0.32, advs: [["CVE-2024-37891", "m", 4.4, "1.26.19", "Proxy-Authorization header not stripped on cross-origin redirects"], ["CVE-2023-45803", "m", 4.2, "1.26.18", "Request body not stripped after redirect from 303 status"]] },
  { eco: "PyPI", name: "requests", ver: ["2.25.1", "2.28.2"], p: 0.36, advs: [["CVE-2024-35195", "m", 5.6, "2.32.0", "Requests Session object does not verify requests after verify=False"], ["CVE-2023-32681", "m", 6.1, "2.31.0", "Unintended leak of Proxy-Authorization header"]] },
  { eco: "PyPI", name: "jinja2", ver: ["3.0.3", "3.1.2"], p: 0.25, advs: [["CVE-2024-56326", "h", 7.8, "3.1.5", "Jinja sandbox breakout through indirect reference to format method"], ["CVE-2024-34064", "m", 5.4, "3.1.4", "Jinja accepts keys containing non-attribute characters"]] },
  { eco: "PyPI", name: "werkzeug", ver: ["2.2.2"], p: 0.15, advs: [["CVE-2024-34069", "h", 7.5, "3.0.3", "Werkzeug debugger vulnerable to remote execution"]] },
  { eco: "PyPI", name: "django", ver: ["3.2.9", "4.2.1"], p: 0.1, advs: [["CVE-2024-42005", "c", 9.8, "4.2.15", "SQL injection in QuerySet.values() on JSONField"], ["CVE-2024-45231", "m", 5.3, "4.2.16", "User enumeration via password reset form"]] },
  { eco: "PyPI", name: "pillow", ver: ["9.5.0", "10.0.1"], p: 0.2, advs: [["CVE-2024-28219", "h", 8.8, "10.3.0", "Buffer overflow in _imagingcms.c"], ["CVE-2023-44271", "h", 7.5, "10.0.0", "Uncontrolled resource consumption in ImageFont"]] },
  { eco: "PyPI", name: "numpy", ver: ["1.21.0", "1.24.1"], p: 0.25, advs: [["PYSEC-2021-856", "u", null, "1.22.0", "Buffer overflow in numpy.f2py"]] },
  { eco: "PyPI", name: "cryptography", ver: ["41.0.3"], p: 0.2, advs: [["CVE-2024-26130", "h", 7.5, "42.0.4", "NULL pointer dereference in pkcs12 serialization"], ["CVE-2023-50782", "h", 7.5, "42.0.0", "Bleichenbacher timing oracle attack in RSA decryption"]] },
  { eco: "PyPI", name: "certifi", ver: ["2022.12.7"], p: 0.25, advs: [["CVE-2023-37920", "c", 9.8, "2023.7.22", "Removal of e-Tugra root certificate"]] },
  { eco: "PyPI", name: "idna", ver: ["3.4"], p: 0.25, advs: [["CVE-2024-3651", "m", 6.2, "3.7", "Quadratic complexity in idna.encode"]] },
  { eco: "PyPI", name: "aiohttp", ver: ["3.8.4"], p: 0.12, advs: [["CVE-2024-30251", "h", 7.5, "3.9.4", "Denial of Service when parsing malformed POST requests"], ["CVE-2023-47627", "m", 5.3, "3.8.5", "HTTP request smuggling via llhttp"]] },
  { eco: "PyPI", name: "setuptools", ver: ["65.5.0"], p: 0.3, dev: true, advs: [["CVE-2024-6345", "h", 8.8, "70.0.0", "Remote code execution via download functions in package_index"]] },
  { eco: "PyPI", name: "transformers", ver: ["4.30.2"], p: 0.08, advs: [["CVE-2024-3568", "c", 9.6, "4.38.0", "Deserialization of untrusted data in the TensorFlow loader"]] },
  { eco: "PyPI", name: "tornado", ver: ["6.2"], p: 0.1, advs: [["CVE-2024-52804", "h", 7.5, "6.4.1", "DoS due to too many multipart/form-data parts"]] },
  { eco: "PyPI", name: "pyyaml", ver: ["5.3.1"], p: 0.1, advs: [["CVE-2020-14343", "c", 9.8, "5.4", "Arbitrary code execution in full_load"]] },
  { eco: "PyPI", name: "pandas", ver: ["1.5.3"], p: 0.1, advs: [["PYSEC-2023-217", "u", null, null, "Possible memory disclosure in pandas.read_sas"]] },
  { eco: "Go", name: "golang.org/x/net", ver: ["v0.10.0", "v0.17.0"], p: 0.32, advs: [["CVE-2023-45288", "h", 7.5, "v0.23.0", "HTTP/2 CONTINUATION flood in net/http"], ["CVE-2023-39325", "h", 7.5, "v0.17.0", "HTTP/2 rapid reset can cause excessive resource consumption"]] },
  { eco: "Go", name: "golang.org/x/crypto", ver: ["v0.9.0", "v0.14.0"], p: 0.3, advs: [["CVE-2024-45337", "c", 9.1, "v0.31.0", "Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass"], ["CVE-2023-48795", "m", 5.9, "v0.17.0", "Prefix truncation attack against SSH (Terrapin)"]] },
  { eco: "Go", name: "github.com/gin-gonic/gin", ver: ["v1.9.0"], p: 0.15, advs: [["CVE-2023-29401", "m", 5.3, "v1.9.1", "Gin does not properly sanitize filename parameter of FileAttachment"]] },
  { eco: "Go", name: "google.golang.org/grpc", ver: ["v1.56.0"], p: 0.15, advs: [["CVE-2023-44487", "h", 7.5, "v1.56.3", "HTTP/2 rapid reset can cause excessive resource consumption"]] },
  { eco: "Go", name: "github.com/docker/docker", ver: ["v24.0.5"], p: 0.05, advs: [["CVE-2024-41110", "c", 9.9, "v25.0.6", "Authz zero length regression"]] },
  { eco: "crates.io", name: "tokio", ver: ["1.28.0"], p: 0.3, advs: [["RUSTSEC-2025-0023", "m", 5.9, "1.38.2", "Broadcast channel calls clone in parallel but not drop"]] },
  { eco: "crates.io", name: "rustls", ver: ["0.21.6"], p: 0.2, advs: [["RUSTSEC-2024-0336", "h", 7.5, "0.21.11", "ConnectionCommon::complete_io could fall into an infinite loop"]] },
  { eco: "crates.io", name: "h2", ver: ["0.3.20"], p: 0.25, advs: [["RUSTSEC-2024-0332", "m", 5.3, "0.3.26", "Degradation of service in h2 via CONTINUATION frames"]] },
  { eco: "crates.io", name: "time", ver: ["0.3.20"], p: 0.3, advs: [["RUSTSEC-2026-0009", "l", 3.3, "0.3.35", "Stack exhaustion when parsing deeply nested input"]] },
  { eco: "Packagist", name: "guzzlehttp/guzzle", ver: ["7.4.5"], p: 0.3, advs: [["CVE-2022-31091", "h", 7.7, "7.9.2", "Failure to strip Authorization header on HTTP downgrade"]] },
  { eco: "Packagist", name: "laravel/framework", ver: ["9.52.4"], p: 0.2, advs: [["CVE-2024-13919", "c", 9.8, "9.52.16", "XSS in the debug-mode error page"]] },
  { eco: "Packagist", name: "symfony/http-kernel", ver: ["5.4.20"], p: 0.25, advs: [["CVE-2024-50340", "m", 5.3, "5.4.46", "HttpKernel trusts the _controller query parameter"]] },
];

const LOCK: Record<string, string[]> = {
  npm: ["package-lock.json", "package-lock.json", "bun.lock", "pnpm-lock.yaml", "yarn.lock"],
  PyPI: ["uv.lock", "poetry.lock", "requirements.txt", "requirements.txt"], Go: ["go.sum"], "crates.io": ["Cargo.lock"], Packagist: ["composer.lock"],
};
const BASES = ["portfolio-site", "api-gateway", "billing-service", "ml-notebooks", "notes-app", "voice-tts", "client-dashboard", "docs-site", "landing", "admin-panel", "worker", "scraper", "dashboard", "sdk", "mobile-web", "auth-service", "search-api", "etl-jobs", "blog", "shop", "analytics", "bot", "extension", "playground", "cli-tool"];
const SUFFIX = ["", "-v2", "-old", "-copy", "-2024", "-next", "-staging", "-2", "-demo", "-fork", ""];
const PARENTS = ["Development/Web", "Development/Backend", "Development/Desktop-Tools", "Research", "Tools/AI", "Clients/acme", "Clients/globex", "Archive/2023", "Experiments"];
const FORMULAE = ["openssl@3", "curl", "webp", "sqlite", "git", "ffmpeg", "libxml2", "imagemagick", "python@3.12", "node", "libpng", "nginx", "postgresql@14", "redis", "wget", "openssh", "gnupg", "libssh2", "libtiff", "freetype", "jpeg-turbo", "ghostscript", "poppler", "protobuf", "pcre2", "expat", "bash", "vim", "tmux", "rsync", "cmake", "qemu", "gcc", "llvm", "lua", "php", "mysql", "mariadb", "subversion", "unbound", "nmap", "sox", "libtool", "ruby", "zstd"];
const FLAWS = ["Heap buffer overflow", "Use-after-free", "Out-of-bounds read", "Integer overflow", "Denial of service via crafted input", "Improper certificate validation", "Path traversal on extract", "NULL pointer dereference"];

function realSet(): { findings: FindingView[]; folders: number } {
  const rand = rng(42);
  const pick = <T,>(a: T[]) => a[Math.floor(rand() * a.length)];
  const used = new Set<string>();
  const dirs: { dir: string; name: string }[] = [];
  while (dirs.length < 300) {
    const name = pick(BASES) + pick(SUFFIX) + (rand() < 0.3 ? `-${Math.floor(rand() * 9) + 1}` : "");
    const dir = `${HOME}/${pick(PARENTS)}/${name}`;
    if (!used.has(dir)) (used.add(dir), dirs.push({ dir, name }));
  }
  const lockfiles: { dir: string; name: string; eco: string; lock: string }[] = [];
  const ecoFor = () => { const r = rand(); return r < 0.62 ? "npm" : r < 0.8 ? "PyPI" : r < 0.88 ? "Go" : r < 0.95 ? "crates.io" : "Packagist"; };
  for (const d of dirs) lockfiles.push({ ...d, eco: ecoFor(), lock: "" });
  for (let i = 0; i < 260; i++) {
    const d = dirs[Math.floor(rand() * dirs.length)];
    const eco = pick(["npm", "PyPI", "npm", "crates.io"]);
    if (!lockfiles.some((l) => l.dir === d.dir && l.eco === eco)) lockfiles.push({ ...d, eco, lock: "" });
  }
  for (const l of lockfiles) l.lock = `${l.dir}/${pick(LOCK[l.eco])}`;

  // scale inclusion probabilities so the totals land near the target
  const perEco = (eco: string) => lockfiles.filter((l) => l.eco === eco).length;
  const expected = catalogue.reduce((n, c) => n + c.p * c.advs.length * perEco(c.eco), 0);
  const scale = 4750 / expected;

  const out: FindingView[] = [];
  const push = (kind: FindingView["kind"], eco: string, name: string, ver: string, a: Adv, direct: boolean | null, dev: boolean, project: string, path: string) =>
    out.push(make(out.length, kind, eco, name, ver, a[3], a[0], PRI[a[1]], a[2], direct, dev, a[4], project, path));

  for (const l of lockfiles) {
    for (const c of catalogue) {
      if (c.eco !== l.eco || rand() > Math.min(0.9, c.p * scale * (c.advs.some((a) => a[1] === "c") ? 0.5 : 1))) continue;
      const ver = pick(c.ver);
      const direct = rand() < 0.35;
      const dev = !!c.dev && rand() < 0.8;
      for (const a of c.advs) push("package", c.eco, c.name, ver, a, direct, dev, l.name, l.lock);
    }
  }
  const mal = ["colors-utils-pro", "event-stream-lite", "reqeusts"];
  [0, 90, 210].forEach((di, i) => {
    const l = lockfiles.filter((x) => x.eco === (i === 2 ? "PyPI" : "npm"))[di % 40];
    push("package", l.eco, mal[i], "2.3.1", [`MAL-2025-${4731 + i}`, "M", null, null, `Malicious code in ${mal[i]}: exfiltrates environment variables on install`], false, false, l.name, l.lock);
  });
  for (const name of FORMULAE) {
    const fixed = `${1 + Math.floor(rand() * 3)}.${Math.floor(rand() * 20)}.${Math.floor(rand() * 9)}`;
    const n = 1 + Math.floor(rand() * 5);
    for (let k = 0; k < n && out.length < 4400; k++) {
      const r = rand();
      const code: Code = r < 0.12 ? "c" : r < 0.4 ? "h" : r < 0.78 ? "m" : r < 0.9 ? "l" : "u";
      const id = `CVE-2024-${20000 + Math.floor(rand() * 40000)}`;
      push("brew", "Homebrew", name, `${fixed.slice(0, -1)}0`, [id, code, code === "u" ? null : Math.round(rand() * 60 + 30) / 10, k === 4 ? null : fixed, `${name}: ${pick(FLAWS).toLowerCase()}`], null, false, "Homebrew", "/opt/homebrew");
    }
  }
  const sx = out.filter((f) => f.kind === "brew").slice(0, 3);
  for (const f of sx) { f.priority = "exploited"; f.kev = true; }
  for (const r of rows.filter((x) => x[0] === "rt"))
    out.push(make(out.length, "runtime", r[1], r[2], r[3], r[4], r[5], r[6], r[7], null, false, r[10], "Runtimes", "/usr/local/bin"));
  out.push(...extras(out.length));
  return { findings: out, folders: new Set(lockfiles.map((l) => l.dir)).size };
}

// ---------- state ----------
const real = scenario === "real" ? realSet() : null;
let findings: FindingView[] = scenario === "empty" || scenario === "scanning" ? [] : real ? real.findings : small();
let scanning = scenario === "scanning";
let progress: [number, number] | null = scanning ? [120, 445] : null;
let lastCheck: number | null = scanning ? null : Math.floor(Date.now() / 1000) - 120;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((cb) => cb());

let settings: Settings = {
  roots: new URLSearchParams(location.search).get("onboarding") ? [] : [HOME],
  exclusions: ["node_modules", ".venv", "vendor", "archive*", ".git"],
  interval_minutes: 30,
  notify_threshold: "high",
  show_dev: false,
  show_estimated: false,
  launch_at_login: true,
};

const count = (fs: FindingView[]): Counts => {
  const c: Counts = { malicious: 0, exploited: 0, critical: 0, high: 0, medium: 0, low: 0, unrated: 0 };
  for (const f of fs) {
    const always = f.priority === "malicious" || f.priority === "exploited";
    if (!f.muted && (always || ((settings.show_dev || !f.dev) && (settings.show_estimated || !f.inferred)))) c[f.priority]++;
  }
  return c;
};

export const mock = {
  getState(): AppState {
    const overview: Overview = {
      last_check_at: lastCheck,
      scanning,
      progress,
      paused_until: null,
      projects: real ? real.folders : scenario === "empty" ? 312 : 9,
      packages: real ? 41230 : scenario === "empty" ? 38412 : 445,
      counts: count(findings),
      last_error: null,
    };
    return { overview, findings, runtimes: scenario === "empty" || scenario === "scanning" ? [] : runtimes };
  },
  scanNow() {
    if (scanning) return;
    scanning = true;
    const total = 445;
    let done = 0;
    const step = () => {
      done += 55;
      if (done >= total) {
        scanning = false;
        progress = null;
        lastCheck = Math.floor(Date.now() / 1000);
      } else progress = [done, total];
      emit();
      if (scanning) setTimeout(step, 300);
    };
    progress = [0, total];
    emit();
    setTimeout(step, 300);
  },
  setMuted(id: number, muted: boolean) {
    findings = findings.map((f) => (f.id === id ? { ...f, muted } : f));
    emit();
  },
  async applyFix(id: number): Promise<{ ok: boolean; output: string }> {
    const f = findings.find((x) => x.id === id);
    await new Promise((r) => setTimeout(r, 1500));
    if (!f?.fix_command) return { ok: false, output: "No fix command for this finding." };
    if (f.name === "openssl@3")
      return { ok: false, output: `==> Upgrading openssl@3\nError: openssl@3: the bottle needs the Apple Command Line Tools to be installed.\nYou can install them with: xcode-select --install` };
    const lines =
      f.kind === "package"
        ? [`$ ${f.fix_command.replace(/^cd '[^']*' && /, "")}`, "", `added 1 package, changed 1 package, and audited 612 packages in 3s`, "", "found 0 vulnerabilities"]
        : [`==> Upgrading 1 outdated package:`, `${f.name} ${f.installed_version} -> ${f.fixed_version}`, ...Array.from({ length: 22 }, (_, i) => `==> Pouring ${f.name}--${f.fixed_version}.arm64_sequoia.bottle.${i + 1}.tar.gz`), `🍺  /opt/homebrew/Cellar/${f.name}/${f.fixed_version}: 214 files, 12.4MB`];
    findings = findings.filter((x) => !(x.project_path === f.project_path && x.name === f.name && x.ecosystem === f.ecosystem));
    emit();
    return { ok: true, output: lines.join("\n") };
  },
  getSettings: (): Settings => ({ ...settings, roots: [...settings.roots], exclusions: [...settings.exclusions] }),
  setSettings(s: Settings) {
    settings = s;
    emit();
  },
  suggestRoots: (): Promise<RootSuggestion[]> =>
    new Promise((r) =>
      setTimeout(() => r([
        { path: "/Users/dev/Workspace", projects: 41 },
        { path: "/Users/dev/Documents/GitHub", projects: 7 },
        { path: "/Users/dev/Developer", projects: 3 },
      ]), 400),
    ),
  pickFolders: async (): Promise<string[]> => ["/Users/dev/Code/side-projects"],
  subscribe(cb: () => void) {
    listeners.add(cb);
    return () => listeners.delete(cb);
  },
};
