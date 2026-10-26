<script lang="ts">
  import type { FindingView, RuntimeStatus } from "../lib/types";
  import { COLOR, PRIORITIES, RANK, plural, shortPath, type Item } from "../lib/model";
  import FindingRow from "./FindingRow.svelte";

  let { items, runtimes, showRuntimes, searching, ondetail }: {
    items: Item[];
    runtimes: RuntimeStatus[];
    showRuntimes: boolean;
    searching: boolean;
    ondetail: (f: FindingView) => void;
  } = $props();

  const LIMIT = 200;
  let limit = $state({ brew: LIMIT, global: LIMIT });
  const worst = (fs: FindingView[]) => Math.min(6, ...fs.map((f) => RANK[f.priority]));
  const byRank = (a: FindingView, b: FindingView) => RANK[a.priority] - RANK[b.priority] || (b.score ?? 0) - (a.score ?? 0);

  const rt = $derived.by(() => {
    const m = new Map<string, { name: string; version: string; st?: RuntimeStatus; fs: FindingView[] }>();
    for (const st of runtimes) m.set(`${st.kind}@${st.version}`, { name: st.kind, version: st.version, st, fs: [] });
    for (const { f } of items) {
      if (f.kind !== "runtime") continue;
      const k = `${f.name}@${f.installed_version}`;
      (m.get(k) ?? m.set(k, { name: f.name, version: f.installed_version, fs: [] }).get(k)!).fs.push(f);
    }
    return [...m.values()]
      .filter((g) => !searching || g.fs.length)
      .sort((a, b) => worst(a.fs) - worst(b.fs) || a.name.localeCompare(b.name));
  });

  /** Findings of one kind grouped by package name, worst first. */
  function byName(kind: FindingView["kind"]) {
    const m = new Map<string, FindingView[]>();
    for (const { f } of items) if (f.kind === kind) (m.get(f.name) ?? m.set(f.name, []).get(f.name)!).push(f);
    return [...m.entries()]
      .map(([name, fs]) => ({ name, fs: fs.sort(byRank) }))
      .sort((a, b) => worst(a.fs) - worst(b.fs) || b.fs.length - a.fs.length || a.name.localeCompare(b.name));
  }
  function capped<T extends { fs: unknown[] }>(gs: T[], n: number): T[] {
    const out: T[] = [];
    for (const g of gs) {
      if (n <= 0) break;
      out.push({ ...g, fs: g.fs.slice(0, n) });
      n -= g.fs.length;
    }
    return out;
  }
  const rows = (gs: { fs: unknown[] }[]) => gs.reduce((n, g) => n + g.fs.length, 0);

  const brew = $derived(byName("brew"));
  const globalPkgs = $derived(byName("global"));
  const brewShown = $derived(capped(brew, limit.brew));
  const globalShown = $derived(capped(globalPkgs, limit.global));

  /** AI tools: one block per tool, its advisories (the tool itself or a bundled component) listed under it. */
  const tools = $derived.by(() => {
    const m = new Map<string, { name: string; path: string; fs: FindingView[] }>();
    for (const { f } of items) {
      if (f.kind !== "tool") continue;
      (m.get(f.project_name) ?? m.set(f.project_name, { name: f.project_name, path: f.project_path, fs: [] }).get(f.project_name)!).fs.push(f);
    }
    return [...m.values()].map((g) => ({ ...g, fs: g.fs.sort(byRank) })).sort((a, b) => worst(a.fs) - worst(b.fs) || a.name.localeCompare(b.name));
  });
</script>

{#if showRuntimes && rt.length}
  <h3>Runtimes</h3>
  {#each rt as g (g.name + g.version)}
    <section style="--c:{COLOR[PRIORITIES[worst(g.fs)]]}">
      <div class="head">
        <b class="mono">{g.name}</b><span class="mono ver">{g.version}</span>
        {#if g.st?.is_eol}<span class="tag eol">EOL</span>{/if}
        {#if g.st?.behind}<span class="tag late">outdated → {g.st.latest_in_cycle}</span>{/if}
        {#if g.st && !g.st.is_eol && !g.st.behind && !g.fs.length}<span class="ok small">up to date</span>{/if}
        <span class="grow"></span>
        {#if g.fs.length}<span class="muted small">{plural(g.fs.length, "advisory", "advisories")}</span>{/if}
      </div>
      {#if g.st}<div class="path mono">{g.st.path}</div>{/if}
      {#each g.fs.sort(byRank) as f (f.id)}<FindingRow {f} onclick={() => ondetail(f)} />{/each}
    </section>
  {/each}
{/if}

{#snippet named(title: string, all: { name: string; fs: FindingView[] }[], shown: { name: string; fs: FindingView[] }[], key: "brew" | "global", noun: string)}
  {@const n = rows(all)}
  <h3>{title} <em>{plural(n, "advisory", "advisories")} · {plural(all.length, noun, noun === "formula" ? "formulae" : noun + "s")}</em></h3>
  {#each shown as g (g.name)}
    <section style="--c:{COLOR[PRIORITIES[worst(g.fs)]]}">
      <div class="head">
        <i class="dot"></i><b class="mono">{g.name}</b><span class="mono ver">{g.fs[0].installed_version}</span>
        <span class="grow"></span><span class="muted small">{g.fs.length}</span>
      </div>
      {#each g.fs as f (f.id)}<FindingRow {f} onclick={() => ondetail(f)} />{/each}
    </section>
  {/each}
  {#if n > limit[key]}<button class="more" onclick={() => (limit[key] += LIMIT)}>Show more ({n - limit[key]} left)</button>{/if}
{/snippet}

{#if brew.length}{@render named("Homebrew", brew, brewShown, "brew", "formula")}{/if}
{#if globalPkgs.length}{@render named("Global packages", globalPkgs, globalShown, "global", "package")}{/if}

{#if tools.length}
  <h3>AI tools</h3>
  {#each tools as g (g.name)}
    <section style="--c:{COLOR[PRIORITIES[worst(g.fs)]]}">
      <div class="head">
        <i class="dot"></i><b>{g.name}</b>
        <span class="grow"></span><span class="muted small">{plural(g.fs.length, "advisory", "advisories")}</span>
      </div>
      <div class="path mono" title={g.path}>{shortPath(g.path)}</div>
      {#each g.fs as f (f.id)}<FindingRow {f} onclick={() => ondetail(f)} />{/each}
    </section>
  {/each}
{/if}

{#if !(showRuntimes && rt.length) && !brew.length && !globalPkgs.length && !tools.length}
  <div class="empty"><b>Nothing here</b>No runtime, Homebrew, global package or AI tool advisories match.</div>
{/if}

<style>
  h3 { margin: 0; padding: 14px 16px 6px; font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  h3 em { font-style: normal; text-transform: none; letter-spacing: 0; opacity: 0.8; margin-left: 6px; }
  section { margin-bottom: 4px; }
  .head { display: flex; align-items: center; gap: 8px; padding: 8px 16px 2px; }
  .head b { font-size: 13px; }
  .ver { color: var(--muted); font-size: 11.5px; }
  .grow { flex: 1; }
  .small { font-size: 11.5px; }
  .path { padding: 0 16px 6px; font-size: 10.5px; color: var(--muted); }
  .tag.eol { background: color-mix(in srgb, var(--s-exploited) 18%, transparent); color: var(--s-exploited); }
  .tag.late { background: color-mix(in srgb, var(--s-high) 18%, transparent); color: var(--s-high); }
</style>
