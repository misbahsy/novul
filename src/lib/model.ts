import type { FindingView, Overview, Priority } from "./types";

export const PRIORITIES: Priority[] = ["malicious", "exploited", "critical", "high", "medium", "low", "unrated"];
export const RANK: Record<Priority, number> = {
  malicious: 0, exploited: 1, critical: 2, high: 3, medium: 4, low: 5, unrated: 6,
};
export const WEIGHT: Record<Priority, number> = {
  malicious: 16, exploited: 12, critical: 8, high: 4, medium: 2, low: 1, unrated: 1,
};
export const COLOR = Object.fromEntries(PRIORITIES.map((p) => [p, `var(--s-${p})`])) as Record<Priority, string>;
export const LABEL: Record<Priority, string> = {
  malicious: "malicious", exploited: "exploited", critical: "critical", high: "high",
  medium: "medium", low: "low", unrated: "unrated",
};

export type Band = 0 | 1 | 2 | 3;
export const BAND_NAME = ["Act now", "Critical", "High", "Later"] as const;
export const bandOf = (p: Priority): Band => {
  const r = RANK[p];
  return r <= 1 ? 0 : r === 2 ? 1 : r === 3 ? 2 : 3;
};

export type Tab = "fix" | "projects" | "system" | "secrets";
export const BREW = "__brew";
export const RUNTIME = "__runtime";
export const GLOBAL = "__global";
export const TOOL = "__tool";
export const SECRET = "__secret";
export const OTHER = "__other";
export const TOP_PROJECTS = 24;

export const fmt = (n: number) => n.toLocaleString("en-US");
export const plural = (n: number, one: string, many = one + "s") => `${fmt(n)} ${n === 1 ? one : many}`;
export const shortPath = (p: string) => p.replace(/^\/Users\/[^/]+/, "~");
const dirOf = (p: string) => p.replace(/\/[^/]*$/, "");
export const epssLabel = (p: number) => (p < 0.01 ? "<1%" : `${Math.round(p * 100)}%`);
export const ESTIMATED_TIP = "Version estimated from requirements.txt; the installed version may differ. Pin versions with a lockfile (uv, poetry, pip-tools) for exact results.";
export const EPSS_TIP = "Chance this vulnerability is exploited in the next 30 days (EPSS)";

export function relativeTime(ts: number | null, now: number): string {
  if (ts == null) return "never checked";
  const ms = ts > 1e12 ? ts : ts * 1000;
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 45) return "checked just now";
  const m = Math.round(s / 60);
  if (m < 60) return `checked ${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `checked ${h} h ago`;
  return `checked ${Math.round(h / 24)} d ago`;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// ---------- derived structures (computed once per state change) ----------

export interface Item {
  f: FindingView;
  /** project key: the lockfile folder, or BREW / RUNTIME */
  pk: string;
  /** radar sector: pk for the top projects, OTHER for the rest */
  sk: string;
  band: Band;
  hay: string;
}

export interface Scope {
  sk: string;
  pk?: string;
  band?: Band;
  label: string;
}

export interface Cell { count: number; pkgs: number; worst: number }
export interface Sector { key: string; label: string; path: string; cells: (Cell | null)[]; total: number }

export interface Project {
  pk: string;
  name: string;
  path: string;
  counts: number[];
  total: number;
  risk: number;
  worst: number;
}

export interface Advisory { id: string; aliases: string[]; summary: string; priority: Priority; score: number | null; kev: boolean; epss: number | null; url: string; sample: FindingView }
export interface Target { path: string; dir: string; name: string; installed: string[]; command: string | null; /** finding whose command this is; what applyFix takes */ fid: number }
export interface Fix {
  key: string;
  eco: string;
  name: string;
  fixed: string | null;
  kind: FindingView["kind"];
  verb: "upgrade" | "remove" | "none";
  /** every affected version is a guess (requirements.txt), none read from a lockfile */
  estimated: boolean;
  risk: number;
  worst: number;
  /** highest EPSS among the advisories, when any is known */
  epss: number | null;
  advisories: Advisory[];
  targets: Target[];
}

export interface Model {
  items: Item[];
  sectors: Sector[];
  projects: Project[];
  fixes: Fix[];
  /** counts per priority rank, after muted and dev filtering */
  counts: number[];
  total: number;
  hiddenDev: number;
  hiddenEstimated: number;
  sysCount: number;
  secrets: number;
}

const SECTOR_OF: Partial<Record<FindingView["kind"], string>> = { brew: BREW, runtime: RUNTIME, global: GLOBAL, tool: TOOL, secret: SECRET };
const keyOf = (f: FindingView) => SECTOR_OF[f.kind] ?? dirOf(f.project_path);
const bandPkgs = (f: FindingView) => `${f.ecosystem}:${f.name}`;

export function groupProjects(items: Item[]): Project[] {
  const m = new Map<string, Project>();
  for (const { f, pk } of items) {
    if (f.kind !== "package") continue;
    let p = m.get(pk);
    if (!p) m.set(pk, (p = { pk, name: f.project_name, path: pk, counts: [0, 0, 0, 0, 0, 0, 0], total: 0, risk: 0, worst: 6 }));
    const r = RANK[f.priority];
    p.counts[r]++;
    p.total++;
    p.risk += WEIGHT[f.priority];
    if (r < p.worst) p.worst = r;
  }
  return [...m.values()].sort((a, b) => b.risk - a.risk || a.name.localeCompare(b.name));
}

export function groupFixes(items: Item[]): Fix[] {
  const groups = new Map<string, { fix: Fix; adv: Map<string, Advisory>; tgt: Map<string, Target & { inst: Set<string> }> }>();
  for (const { f } of items) {
    if (f.kind === "secret") continue;
    const key = `${f.ecosystem}|${f.name}|${f.fixed_version ?? ""}`;
    let g = groups.get(key);
    if (!g) {
      const fix: Fix = { key, eco: f.ecosystem, name: f.name, fixed: f.fixed_version, kind: f.kind, verb: "none", estimated: true, risk: 0, worst: 6, epss: null, advisories: [], targets: [] };
      groups.set(key, (g = { fix, adv: new Map(), tgt: new Map() }));
    }
    g.fix.risk += WEIGHT[f.priority];
    if (!f.inferred) g.fix.estimated = false;
    g.fix.worst = Math.min(g.fix.worst, RANK[f.priority]);
    if (f.epss != null) g.fix.epss = Math.max(g.fix.epss ?? 0, f.epss);
    if (!g.adv.has(f.group_id))
      g.adv.set(f.group_id, { id: f.group_id, aliases: f.aliases, summary: f.summary, priority: f.priority, score: f.score, kev: f.kev, epss: f.epss, url: f.url, sample: f });
    let t = g.tgt.get(f.project_path);
    if (!t) g.tgt.set(f.project_path, (t = { path: f.project_path, dir: dirOf(f.project_path), name: f.project_name, installed: [], command: null, fid: f.id, inst: new Set() }));
    t.inst.add(f.installed_version);
    if (t.command == null && f.fix_command) (t.command = f.fix_command), (t.fid = f.id);
  }
  const out: Fix[] = [];
  for (const { fix, adv, tgt } of groups.values()) {
    fix.advisories = [...adv.values()].sort((a, b) => RANK[a.priority] - RANK[b.priority] || (b.score ?? 0) - (a.score ?? 0));
    fix.targets = [...tgt.values()].map(({ inst, ...t }) => ({ ...t, installed: [...inst] }));
    fix.targets.sort((a, b) => a.name.localeCompare(b.name));
    fix.verb = fix.fixed ? "upgrade" : fix.worst === 0 && fix.targets.some((t) => t.command) ? "remove" : "none";
    out.push(fix);
  }
  const first = (x: Fix) => (x.verb === "none" ? 2 : x.worst === 0 ? 0 : 1);
  // Same priority: likelier to be exploited first (EPSS), then the most risk removed.
  return out.sort((a, b) => first(a) - first(b) || a.worst - b.worst || (b.epss ?? -1) - (a.epss ?? -1) || b.risk - a.risk || a.name.localeCompare(b.name));
}

export function view(items: Item[], scope: Scope | null, q: string): Item[] {
  const terms = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!scope && !terms.length) return items;
  return items.filter(
    (it) =>
      (!scope || (it.sk === scope.sk && (!scope.pk || it.pk === scope.pk) && (scope.band == null || it.band === scope.band))) &&
      terms.every((t) => it.hay.includes(t)),
  );
}

export const EMPTY: Model = { items: [], sectors: [], projects: [], fixes: [], counts: [0, 0, 0, 0, 0, 0, 0], total: 0, hiddenDev: 0, hiddenEstimated: 0, sysCount: 0, secrets: 0 };

export function derive(findings: FindingView[], showDev: boolean, showEstimated: boolean): Model {
  const items: Item[] = [];
  const counts = [0, 0, 0, 0, 0, 0, 0];
  let hiddenDev = 0;
  let hiddenEstimated = 0;
  for (const f of findings) {
    if (f.muted) continue;
    // Malicious or actively exploited dev packages run on this machine: never hide them.
    if (RANK[f.priority] > RANK.exploited) {
      if (f.dev && !showDev) {
        hiddenDev++;
        continue;
      }
      if (f.inferred && !showEstimated) {
        hiddenEstimated++;
        continue;
      }
    }
    counts[RANK[f.priority]]++;
    items.push({
      f, pk: keyOf(f), sk: "", band: bandOf(f.priority),
      hay: `${f.name} ${f.project_name} ${f.project_path} ${f.group_id} ${f.aliases.join(" ")}`.toLowerCase(),
    });
  }

  const projects = groupProjects(items);
  const sectorOf = new Map(projects.map((p, i) => [p.pk, i < TOP_PROJECTS ? p.pk : OTHER]));
  const acc = new Map<string, { total: number; cells: ({ count: number; pkgs: Set<string>; worst: number } | null)[] }>();
  for (const it of items) {
    it.sk = it.f.kind === "package" ? sectorOf.get(it.pk)! : it.pk;
    let s = acc.get(it.sk);
    if (!s) acc.set(it.sk, (s = { total: 0, cells: [null, null, null, null] }));
    const c = (s.cells[it.band] ??= { count: 0, pkgs: new Set(), worst: 6 });
    c.count++;
    c.pkgs.add(bandPkgs(it.f));
    c.worst = Math.min(c.worst, RANK[it.f.priority]);
    s.total++;
  }
  const mk = (key: string, label: string, path: string): Sector => {
    const s = acc.get(key);
    return { key, label, path, total: s?.total ?? 0, cells: (s?.cells ?? [null, null, null, null]).map((c) => (c ? { count: c.count, pkgs: c.pkgs.size, worst: c.worst } : null)) };
  };
  const sectors = projects.slice(0, TOP_PROJECTS).map((p) => mk(p.pk, p.name, p.path));
  if (projects.length > TOP_PROJECTS) sectors.push(mk(OTHER, "Other projects", `${projects.length - TOP_PROJECTS} more projects`));
  sectors.push(mk(BREW, "Homebrew", "/opt/homebrew"), mk(RUNTIME, "Runtimes", "Node, Python, Ruby, Go…"));
  if (acc.has(GLOBAL)) sectors.push(mk(GLOBAL, "Global packages", "npm, pip, cargo and gem installs"));
  if (acc.has(TOOL)) sectors.push(mk(TOOL, "AI tools", "Claude Code, Codex and other agents"));
  if (acc.has(SECRET)) sectors.push(mk(SECRET, "Secrets", "Plaintext keys and tokens in files"));
  const n = (k: string) => acc.get(k)?.total ?? 0;

  return {
    items, sectors, projects, fixes: groupFixes(items), counts, total: items.length, hiddenDev, hiddenEstimated,
    sysCount: n(BREW) + n(RUNTIME) + n(GLOBAL) + n(TOOL), secrets: n(SECRET),
  };
}

// ---------- headline + radar centre ----------

export const bandTotals = (c: number[]) => [c[0] + c[1], c[2], c[3], c[4] + c[5] + c[6]];

export function centerOf(c: number[], total: number): { big: string; label: string; color: string } | null {
  const [m, x, cr, h] = c;
  if (!total) return null;
  if (m + x) return { big: fmt(m + x), label: "Act now", color: m ? "var(--s-malicious)" : "var(--s-exploited)" };
  if (cr) return { big: fmt(cr), label: "Critical", color: "var(--s-critical)" };
  if (h) return { big: fmt(h), label: "High", color: "var(--s-high)" };
  return { big: fmt(total), label: "Issues", color: "var(--text)" };
}

export interface Part { t: string; c?: string }
export interface Headline {
  /** lines of coloured parts; the app joins them with a space, the share card stacks them */
  title: Part[][];
  sub: string[];
  checking: boolean;
}

/** A subline part with its numbers picked out: red for exploited, purple for malicious, amber for secrets. */
export function emphasize(s: string): Part[] {
  const c = /exploited/.test(s) ? COLOR.exploited : /malicious/.test(s) ? COLOR.malicious : /secret/.test(s) ? COLOR.high : "var(--text)";
  return s.split(/(\d[\d,.]*)/).filter(Boolean).map((t) => (/^\d/.test(t) ? { t, c } : { t }));
}

export function headline(m: Model, ov: Overview | null): Headline {
  const [mal, exp, crit] = m.counts;
  const act = mal + exp;
  if (!ov || (m.total === 0 && ov.last_check_at == null)) {
    const p = ov?.progress;
    return {
      title: [[{ t: "Checking this Mac…" }]],
      sub: [p ? `Scanning ${fmt(p[0])} of ${fmt(p[1])} lockfiles` : "Looking for lockfiles, runtimes and Homebrew formulae"],
      checking: true,
    };
  }
  const vulns = m.total - m.secrets;
  const sub: string[] = [];
  if (vulns > 0) sub.push(plural(vulns, "known vulnerability", "known vulnerabilities") + (ov.projects ? ` across ${plural(ov.projects, "project")}` : ""));
  if (exp) sub.push(`${fmt(exp)} actively exploited`);
  if (m.secrets) sub.push(plural(m.secrets, "exposed secret"));
  if (!sub.length) sub.push(m.hiddenDev ? `${plural(m.hiddenDev, "dev-only issue")} hidden` : `Checked ${plural(ov.projects, "project")} and ${plural(ov.packages, "package")}`);

  const title: Part[][] = act
    ? [[{ t: fmt(act), c: mal ? "var(--s-malicious)" : "var(--s-exploited)" }, { t: ` ${act === 1 ? "issue" : "issues"} on this Mac` }], [{ t: act === 1 ? "needs attention now" : "need attention now" }]]
    : crit
      ? [[{ t: fmt(crit), c: "var(--s-critical)" }, { t: ` critical ${crit === 1 ? "issue" : "issues"}` }], [{ t: "on this Mac" }]]
      : m.total || m.hiddenDev
        ? [[{ t: "Nothing urgent" }], [{ t: "on this Mac" }]]
        : [[{ t: "No known vulnerabilities" }], [{ t: "on this Mac" }]];
  return { title, sub, checking: false };
}

// ---------- copy output ----------

/** Package fixes only make sense inside their project folder; prefix one unless the backend already did. */
const runnable = (g: Fix, t: Target) =>
  !t.command ? null : g.kind === "package" && !t.command.startsWith("cd ") ? `cd '${t.dir}' && ${t.command}` : t.command;

export function commandsFor(fixes: Fix[]): string {
  const out = new Set<string>();
  for (const g of fixes) for (const t of g.targets) {
    const c = runnable(g, t);
    if (c) out.add(c);
  }
  return [...out].join("\n");
}

export function briefFor(fixes: Fix[]): string {
  const L = [
    `# Fix ${plural(fixes.length, "vulnerable dependency", "vulnerable dependencies")}`,
    "",
    "NoVul found these known vulnerabilities on this Mac.",
    "",
  ];
  fixes.forEach((g, i) => {
    const installed = [...new Set(g.targets.flatMap((t) => t.installed))].join(", ");
    L.push(`## ${i + 1}. ${g.verb === "remove" ? "Remove" : "Upgrade"} \`${g.name}\`${g.fixed ? ` to ${g.fixed}` : ""} (${g.eco})`);
    L.push(`- Installed: ${installed}${g.fixed ? `, fixed in ${g.fixed}` : ""}`);
    L.push(`- Advisories: ${g.advisories.map((a) => `[${a.id}](${a.url})`).join(", ")}`);
    L.push("- Affected:");
    for (const t of g.targets) L.push(`  - \`${t.path}\`${t.command ? ` — run \`${t.command}\`${g.kind === "package" ? ` in \`${t.dir}\`` : ""}` : ""}`);
    L.push("");
  });
  L.push("Apply these fixes, run each project's tests, and report what changed.");
  return L.join("\n");
}
