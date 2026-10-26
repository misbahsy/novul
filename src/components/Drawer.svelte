<script lang="ts">
  import type { FindingView } from "../lib/types";
  import { COLOR, EPSS_TIP, ESTIMATED_TIP, LABEL, epssLabel, shortPath } from "../lib/model";
  import { openUrl, revealPath } from "../lib/backend";
  import CopyBtn from "./CopyBtn.svelte";
  import Info from "./Info.svelte";

  let { f, onclose, onmute }: { f: FindingView; onclose: () => void; onmute: () => void } = $props();
  let closeBtn: HTMLButtonElement;
  $effect(() => closeBtn.focus());
  const KIND = { package: "", brew: "Homebrew", runtime: "Runtime", global: "Global package", tool: "AI tool", secret: "Secret" } as const;
  const secret = $derived(f.kind === "secret");
</script>

<aside style="--c:{COLOR[f.priority]}" aria-label="Advisory detail">
  <div class="top">
    <button bind:this={closeBtn} class="back" onclick={onclose} aria-label="Close detail">‹ Back</button>
    <span class="muted">{KIND[f.kind] || f.ecosystem}</span>
  </div>
  <div class="body scroll">
    <h2 class="mono sel">{secret ? f.name : f.group_id}</h2>
    {#if f.aliases.length}<div class="aliases">{#each f.aliases as a}<span class="chip mono sel">{a}</span>{/each}</div>{/if}

    <div class="badges">
      <span class="score" style="font-family:inherit;height:22px;padding:0 10px;border-radius:11px">{LABEL[f.priority]}</span>
      {#if f.score != null}<span class="score" style="height:22px;padding:0 10px;border-radius:11px">CVSS {f.score.toFixed(1)}</span>{/if}
      {#if f.kev}<span class="tag" style="height:22px;padding:0 10px;border-radius:11px">Actively exploited</span>{/if}
      {#if f.epss != null}<span class="chip epss" title={EPSS_TIP} style="height:22px;padding:0 10px;border-radius:11px;font-size:11.5px">EPSS {epssLabel(f.epss)}</span>{/if}
    </div>

    {#if f.priority === "malicious"}
      <div class="banner"><b>Malicious package</b><span>Remove it and rotate any secrets this machine holds</span></div>
    {/if}

    <p class="sel">{f.summary}</p>

    <dl>
      <dt>{secret ? "Detector" : "Package"}</dt><dd class="mono">{f.name}</dd>
      {#if secret}
        <dt>Fingerprint</dt><dd class="mono sel">{f.installed_version}</dd>
      {:else}
        <dt>Version</dt>
        <dd class="mono">
          {f.installed_version}
          {#if f.fixed_version}<span class="muted">→</span> <span class="ok">{f.fixed_version}</span>{:else}<span class="muted nofix">no fix yet</span>{/if}
        </dd>
      {/if}
      <dt>Found in</dt>
      <dd class="path"><span class="mono sel" title={f.project_path}>{shortPath(f.project_path)}</span><button class="link" onclick={() => revealPath(f.project_path)}>Reveal</button></dd>
    </dl>

    <div class="chips">
      {#if f.direct === true}<span class="chip">direct</span>{:else if f.direct === false}<span class="chip">transitive</span>{/if}
      {#if f.dev}<span class="chip">dev</span>{/if}
      {#if f.inferred}<span class="chip">estimated<Info text={ESTIMATED_TIP} /></span>{/if}
    </div>

    {#if f.fix_command}
      <div class="fix">
        <div class="fh"><span class="muted">{f.priority === "malicious" ? "Remove" : secret ? "Tighten permissions" : "Fix"}</span><CopyBtn text={() => f.fix_command!} /></div>
        <code class="sel">{f.fix_command}</code>
      </div>
    {/if}

    <div class="actions">
      {#if f.url}<button class="btn primary" onclick={() => openUrl(f.url)}>Open advisory</button>{/if}
      <button class="btn" onclick={onmute}>Mute</button>
    </div>
  </div>
</aside>

<style>
  aside { position: absolute; inset: 0; z-index: 4; background: var(--panel); display: flex; flex-direction: column; animation: slide 0.2s ease; box-shadow: -14px 0 30px rgba(0, 0, 0, 0.25); }
  .top { display: flex; justify-content: space-between; align-items: center; padding: 0 16px; height: 40px; border-bottom: 1px solid var(--hair); flex: none; }
  .back { border: 0; background: none; color: var(--teal); padding: 4px 0; }
  .body { flex: 1; min-height: 0; padding: 16px 18px 20px; display: flex; flex-direction: column; gap: 13px; }
  h2 { margin: 0; font-size: 17px; font-weight: 600; word-break: break-all; }
  .aliases, .badges, .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .badges .score { text-transform: capitalize; font-size: 11.5px; }
  .chips:empty { display: none; }
  p { margin: 0; line-height: 1.5; }
  dl { margin: 0; display: grid; grid-template-columns: 78px 1fr; gap: 8px 12px; font-size: 12.5px; }
  dt { color: var(--muted); }
  dd { margin: 0; min-width: 0; }
  .nofix { margin-left: 8px; font-family: -apple-system, system-ui, sans-serif; }
  .path { display: flex; align-items: baseline; gap: 10px; }
  .path .mono { font-size: 11.5px; word-break: break-all; min-width: 0; }
  .fix { background: var(--ink); border: 1px solid var(--hair); border-radius: 9px; padding: 8px 12px 10px; }
  .fh { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 4px; }
  code { display: block; font-size: 12px; color: var(--teal); white-space: pre-wrap; word-break: break-all; }
  .actions { display: flex; gap: 8px; margin-top: auto; padding-top: 6px; }
</style>
