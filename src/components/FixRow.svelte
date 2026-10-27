<script lang="ts">
  import type { FindingView } from "../lib/types";
  import { COLOR, EPSS_TIP, ESTIMATED_TIP, LABEL, PRIORITIES, epssLabel, plural, shortPath, type Fix, type Target } from "../lib/model";
  import { openUrl, revealPath } from "../lib/backend";
  import CopyBtn from "./CopyBtn.svelte";
  import Info from "./Info.svelte";

  let { g, open, checked, maxRisk, ontoggle, onexpand, ondetail, onrun }: {
    g: Fix;
    open: boolean;
    checked: boolean;
    maxRisk: number;
    ontoggle: () => void;
    onexpand: () => void;
    ondetail: (f: FindingView) => void;
    onrun: (t: Target) => void;
  } = $props();

  let tmore = $state(false);
  let amore = $state(false);
  const worst = $derived(PRIORITIES[g.worst]);
  const tshow = $derived(tmore ? g.targets : g.targets.slice(0, 6));
  const runnable = (t: Target) => !!t.command && (t.command.startsWith("cd ") || t.command.startsWith("brew "));
  const ashow = $derived(amore ? g.advisories : g.advisories.slice(0, 5));
</script>

<article class:open style="--c:{COLOR[worst]}">
  <div class="row">
    <input type="checkbox" {checked} disabled={g.verb === "none"} onchange={ontoggle} aria-label="Select fix for {g.name}" />
    <button class="main" aria-expanded={open} onclick={onexpand}>
      <span class="title">
        {#if g.verb === "none"}<b class="mono">{g.name}</b> <span class="muted">has no patched release</span>
        {:else if g.verb === "remove"}Remove <b class="mono">{g.name}</b>
        {:else}Upgrade <b class="mono">{g.name}</b> to <b class="mono to">{g.fixed}</b>{/if}
      </span>
      <span class="meta">
        {g.verb === "upgrade" || g.verb === "remove" ? "fixes " : ""}{plural(g.advisories.length, "advisory", "advisories")} · {plural(g.targets.length, "project")} · worst: <span class="w">{LABEL[worst]}</span>
      </span>
    </button>
    {#if g.estimated}<span class="chip">estimated<Info text={ESTIMATED_TIP} /></span>{/if}
    {#if g.epss != null}<span class="chip epss" title={EPSS_TIP}>EPSS {epssLabel(g.epss)}</span>{/if}
    <span class="risk" title="Risk removed: {g.risk}"><i style="width:{Math.max(6, (g.risk / maxRisk) * 100)}%"></i></span>
    <svg class="chev" width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="m3 4.5 3 3 3-3" /></svg>
  </div>

  {#if open}
    <div class="body">
      {#if g.worst === 0}
        <div class="banner"><b>Malicious package</b><span>Remove it and rotate any secrets this machine holds</span></div>
      {/if}

      <h4>{g.verb === "none" ? "Affected" : "Apply in"}</h4>
      {#each tshow as t (t.path)}
        <div class="tgt">
          <div class="tline">
            <b>{t.name}</b>
            <span class="mono ver">{t.installed.join(", ")}{g.fixed ? ` → ${g.fixed}` : ""}</span>
            <button class="link" onclick={() => revealPath(t.path)}>Reveal</button>
          </div>
          <div class="path mono" title={t.path}>{shortPath(t.path)}</div>
          {#if t.command}
            <div class="cmd">
              <code class="sel">{t.command}</code><CopyBtn text={() => t.command!} />
              {#if runnable(t)}<button class="run" onclick={() => onrun(t)}>Run fix</button>{/if}
            </div>
          {/if}
        </div>
      {/each}
      {#if g.targets.length > tshow.length}<button class="more" onclick={() => (tmore = true)}>Show {g.targets.length - tshow.length} more projects</button>{/if}

      <h4>Advisories</h4>
      {#each ashow as a (a.id)}
        <div class="adv" style="--c:{COLOR[a.priority]}">
          <button class="advmain" onclick={() => ondetail(a.sample)}>
            <i class="dot"></i>
            <span class="mono id">{a.id}</span>
            {#if a.score != null}<span class="score">{a.score.toFixed(1)}</span>{/if}
            {#if a.kev}<span class="tag">Actively exploited</span>{/if}
            <span class="sum">{a.summary}</span>
          </button>
          <button class="link" onclick={() => openUrl(a.url)}>Open</button>
        </div>
        {#if a.aliases.length}<div class="alias mono">{a.aliases.slice(0, 3).join("  ")}</div>{/if}
      {/each}
      {#if g.advisories.length > ashow.length}<button class="more" onclick={() => (amore = true)}>Show {g.advisories.length - ashow.length} more advisories</button>{/if}
    </div>
  {/if}
</article>

<style>
  article { border-bottom: 1px solid var(--hair); border-left: 3px solid var(--c); }
  article.open { background: color-mix(in srgb, var(--raised) 55%, transparent); }
  .row { position: relative; display: flex; align-items: center; gap: 10px; padding: 9px 12px 9px 11px; }
  .row:hover { background: var(--raised); }
  input[type="checkbox"] { accent-color: var(--teal); width: 15px; height: 15px; margin: 0; flex: none; }
  .main { flex: 1; min-width: 0; display: grid; gap: 1px; border: 0; background: none; text-align: left; padding: 0; }
  .title { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .title b { font-weight: 600; }
  .to { color: var(--teal); }
  .meta { font-size: 11.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .w { color: var(--c); }
  .risk { width: 40px; height: 4px; border-radius: 2px; background: var(--hair); flex: none; overflow: hidden; }
  @media (max-width: 820px) { .risk { display: none; } }
  .risk i { display: block; height: 100%; background: var(--c); border-radius: 2px; }
  .chev { color: var(--muted); flex: none; transition: transform 0.15s; }
  .open .chev { transform: rotate(180deg); }

  .body { padding: 2px 14px 12px 38px; display: grid; grid-template-columns: minmax(0, 1fr); gap: 6px; animation: rise 0.15s ease; }
  h4 { margin: 8px 0 0; font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  .tgt { display: grid; grid-template-columns: minmax(0, 1fr); gap: 3px; padding: 7px 10px; background: var(--ink); border: 1px solid var(--hair); border-radius: 8px; }
  .tline { display: flex; align-items: baseline; gap: 10px; }
  .tline b { font-weight: 600; font-size: 12.5px; }
  .ver { flex: 1; min-width: 0; color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .path { color: var(--muted); font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .cmd { display: flex; align-items: flex-start; gap: 10px; margin-top: 2px; }
  /* the whole command stays readable: it wraps instead of running out of the box */
  code { flex: 1; min-width: 0; font-size: 11.5px; line-height: 1.45; color: var(--teal); white-space: pre-wrap; overflow-wrap: anywhere; }

  .run { height: 22px; padding: 0 9px; border: 1px solid color-mix(in srgb, var(--teal) 55%, var(--line)); border-radius: 6px; background: none; color: var(--teal); font-size: 11.5px; white-space: nowrap; }
  .run:hover { background: color-mix(in srgb, var(--teal) 14%, transparent); }
  .adv { display: flex; align-items: center; gap: 8px; }
  .advmain { flex: 1; min-width: 0; display: flex; align-items: center; gap: 7px; border: 0; background: none; text-align: left; padding: 3px 0; }
  .advmain:hover .id { text-decoration: underline; }
  .id { font-size: 12px; flex: none; }
  .sum { color: var(--muted); font-size: 11.5px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .alias { margin: -4px 0 2px 15px; font-size: 10.5px; color: var(--muted); opacity: 0.8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
