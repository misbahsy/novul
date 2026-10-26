<script lang="ts">
  import { untrack } from "svelte";
  import { getSettings, pickFolders, setSettings, suggestRoots } from "../lib/backend";
  import type { RootSuggestion } from "../lib/types";

  let { ondone, needRoots, onroots }: { ondone: () => void; needRoots: boolean; onroots: () => void } = $props();

  // The folder step comes first until roots are saved; the three cards follow while the scan runs.
  const startWithFolders = untrack(() => needRoots);
  let folders = $state(startWithFolders);
  let found = $state<RootSuggestion[] | null>(null);
  let extra = $state<string[]>([]);
  let chosen = $state(new Set<string>());
  let saving = $state(false);
  let failed = $state(false);
  if (startWithFolders) {
    suggestRoots()
      .then((r) => {
        found = r;
        if (r[0] && r[0].projects !== 0) chosen = new Set([r[0].path]);
      })
      .catch(() => (found = []));
  }
  const rows = $derived([...(found ?? []), ...extra.filter((p) => !found?.some((f) => f.path === p)).map((path) => ({ path, projects: undefined as number | null | undefined }))]);
  const short = (p: string) => p.replace(/^\/Users\/[^/]+/, "~");
  function toggle(path: string) {
    const next = new Set(chosen);
    if (!next.delete(path)) next.add(path);
    chosen = next;
  }
  async function add() {
    const picked = await pickFolders();
    for (const p of picked) if (!extra.includes(p)) extra.push(p);
    chosen = new Set([...chosen, ...picked]);
  }
  async function start() {
    saving = true;
    failed = false;
    try {
      const s = await getSettings();
      s.roots = [...chosen];
      await setSettings(s);
      onroots();
      folders = false;
    } catch {
      failed = true;
    } finally {
      saving = false;
    }
  }

  const cards = [
    { t: "Everything you've installed", d: "Projects, runtimes and Homebrew formulae, found automatically. Nothing to set up." },
    { t: "Checked every 30 minutes against OSV", d: "Only package names and versions leave your Mac. Your code and paths stay here." },
    { t: "Lives in your menu bar", d: "About 20 MB, quiet until something new actually matters." },
  ];
  let i = $state(0);
  let auto = $state(true);
  const last = cards.length - 1;

  $effect(() => {
    if (!auto || folders) return;
    const t = setInterval(() => (i < last ? i++ : (auto = false)), 4000);
    return () => clearInterval(t);
  });
  const go = (n: number) => ((auto = false), (i = Math.max(0, Math.min(last, n))));
</script>

<div class="ob" role="dialog" aria-label="Welcome to NoVul">
  {#if folders}
    <div class="card pick">
      <h2>Where's your code?</h2>
      <p>NoVul checks the projects inside these folders.</p>
      <div class="rows">
        {#if !found}
          <div class="note">Looking for your code folders…</div>
        {:else if !rows.length}
          <div class="note">No usual folders found. Add the one where you keep code.</div>
        {/if}
        {#each rows as r (r.path)}
          <label class="row" class:on={chosen.has(r.path)}>
            <input type="checkbox" checked={chosen.has(r.path)} onchange={() => toggle(r.path)} />
            <span class="path mono" title={r.path}>{short(r.path)}</span>
            {#if r.projects === null}<span class="n">many projects</span>{:else if r.projects !== undefined}<span class="n">{r.projects} {r.projects === 1 ? "project" : "projects"}</span>{/if}
          </label>
        {/each}
      </div>
      <button class="btn" onclick={add}>Add folder…</button>
      <p class="priv">NoVul reads lockfiles in these folders. Nothing leaves your Mac except package names and versions.</p>
      {#if failed}<p class="err">Couldn't save. Try again.</p>{/if}
    </div>
    <div class="nav one">
      <button class="btn primary" disabled={!chosen.size || saving} onclick={start}>Start scanning</button>
    </div>
  {:else}
  <button class="skip link" onclick={ondone}>Skip</button>
  {#key i}
    <div class="card">
      <svg viewBox="0 0 220 120" width="220" height="120" fill="none" stroke-linecap="round" aria-hidden="true">
        {#if i === 0}
          {#each [20, 38, 56] as r}<circle cx="110" cy="60" {r} stroke="#232b42" />{/each}
          <path d="M110 60 150 28" stroke="#3ee6c4" stroke-width="1.5" /><path d="M110 60 140 20 168 50Z" fill="#3ee6c4" opacity=".1" stroke="none" />
          <circle cx="82" cy="45" r="5" fill="#ff9f5a" /><circle cx="82" cy="45" r="11" fill="#ff9f5a" opacity=".15" />
          <circle cx="140" cy="78" r="4" fill="#f2cf5b" /><circle cx="116" cy="22" r="3.5" fill="#8aa4c8" /><circle cx="110" cy="60" r="3" fill="#3ee6c4" />
        {:else if i === 1}
          <rect x="16" y="26" width="76" height="52" rx="7" stroke="#2b3552" stroke-width="1.5" /><path d="M8 88h92" stroke="#2b3552" stroke-width="1.5" />
          <path d="M28 42h30M28 52h46M28 62h22" stroke="#232b42" stroke-width="3" />
          <rect x="102" y="46" width="62" height="18" rx="9" fill="#3ee6c4" fill-opacity=".14" stroke="#3ee6c4" />
          <text x="133" y="58" text-anchor="middle" font-size="8" fill="#3ee6c4" stroke="none" font-family="ui-monospace,monospace">name@1.2.3</text>
          <path d="M168 55h14" stroke="#3ee6c4" stroke-dasharray="3 3" /><circle cx="198" cy="55" r="14" stroke="#7d879e" /><circle cx="198" cy="55" r="7" stroke="#232b42" />
        {:else}
          <rect x="14" y="20" width="192" height="16" rx="5" fill="#1b2338" stroke="#232b42" />
          <circle cx="30" cy="28" r="2.6" fill="#7d879e" /><circle cx="42" cy="28" r="2.6" fill="#7d879e" />
          <circle cx="164" cy="28" r="2.6" fill="#7d879e" /><circle cx="176" cy="28" r="2.6" fill="#7d879e" />
          <circle cx="192" cy="28" r="6" stroke="#3ee6c4" /><path d="M192 28 196 24" stroke="#3ee6c4" />
          <rect x="132" y="42" width="74" height="58" rx="7" fill="#151b2d" stroke="#2b3552" />
          <path d="M142 54h54M142 66h40M142 78h48" stroke="#232b42" stroke-width="3" /><circle cx="198" cy="54" r="2.6" fill="#ff9f5a" stroke="none" />
        {/if}
      </svg>
      <h2>{cards[i].t}</h2>
      <p>{cards[i].d}</p>
    </div>
  {/key}
  <div class="nav">
    <button class="btn" style:visibility={i ? "visible" : "hidden"} onclick={() => go(i - 1)}>Back</button>
    <div class="dots">{#each cards as _, n}<button aria-label="Card {n + 1}" class:on={n === i} onclick={() => go(n)}></button>{/each}</div>
    {#if i < last}<button class="btn" onclick={() => go(i + 1)}>Next</button>{:else}<button class="btn primary" onclick={ondone}>Show my results</button>{/if}
  </div>
  {/if}
</div>

<style>
  .ob { position: absolute; inset: 0; z-index: 6; background: var(--panel); display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 28px; padding: 24px; }
  .skip { position: absolute; top: 14px; right: 16px; color: var(--muted); }
  .card { display: grid; justify-items: center; gap: 10px; text-align: center; max-width: 340px; animation: rise 0.3s ease; }
  h2 { margin: 8px 0 0; font-size: 18px; font-weight: 600; letter-spacing: -0.01em; }
  p { margin: 0; color: var(--muted); line-height: 1.5; min-height: 3em; }
  .nav { width: 100%; max-width: 320px; display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; gap: 16px; }
  .nav > :first-child { justify-self: start; }
  .nav > :last-child { justify-self: end; }
  .pick { max-width: 420px; width: 100%; }
  .rows { width: 100%; display: grid; gap: 6px; margin: 6px 0 4px; }
  .row { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 8px; background: var(--ink); border: 1px solid var(--hair); text-align: left; cursor: pointer; }
  .row.on { border-color: var(--teal); }
  .row input { accent-color: var(--teal); width: 15px; height: 15px; margin: 0; flex: none; }
  .path { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12.5px; }
  .n { color: var(--muted); font-size: 11.5px; flex: none; }
  .note { color: var(--muted); font-size: 12.5px; padding: 8px 0; }
  .priv { font-size: 11.5px; min-height: 0; margin-top: 4px; }
  .err { color: var(--s-critical); font-size: 12px; min-height: 0; }
  .nav.one { display: flex; justify-content: center; }
  .dots { display: flex; gap: 8px; }
  .dots button { width: 7px; height: 7px; padding: 0; border: 0; border-radius: 50%; background: var(--hair); }
  .dots button.on { background: var(--teal); box-shadow: 0 0 8px var(--teal); }
</style>
