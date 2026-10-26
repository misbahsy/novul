<script lang="ts">
  import { emphasize, type Headline } from "../lib/model";
  import type { Overview } from "../lib/types";
  import { progressText } from "../lib/progress";
  import { AGENT_NAME, type Agent } from "../lib/agent";

  let {
    h, busy, onshare, ov = null, agents = [], oncopy, onopen,
  }: {
    h: Headline; busy: boolean; onshare: () => void; ov?: Overview | null;
    agents?: Agent[]; oncopy: (a: Agent) => void; onopen: (a: Agent) => void;
  } = $props();
  const sub = $derived(h.checking && ov?.scanning ? [progressText(ov)] : h.sub);
  let open = $state(false);
  let menuEl = $state<HTMLElement>();
  const pick = (fn: () => void) => () => ((open = false), fn());
  function outside(e: PointerEvent) {
    if (open && menuEl && !menuEl.contains(e.target as Node)) open = false;
  }
</script>

<svelte:window onpointerdown={outside} onkeydown={(e) => e.key === "Escape" && open && ((open = false), e.stopPropagation())} />

<div class="hl" data-tauri-drag-region>
  <div class="txt" data-tauri-drag-region>
    <h1 data-tauri-drag-region>
      {#each h.title as line, i}{#if i}{" "}{/if}{#each line as p}<span data-tauri-drag-region style:color={p.c}>{p.t}</span>{/each}{/each}
    </h1>
    <p data-tauri-drag-region>{#each sub as part, i}<span class="part" data-tauri-drag-region>{#each emphasize(part) as seg}{#if seg.c}<b data-tauri-drag-region style:color={seg.c}>{seg.t}</b>{:else}{seg.t}{/if}{/each}{i < sub.length - 1 ? " ·" : ""}</span>{" "}{/each}</p>
  </div>
  {#if !h.checking}
    <div class="menu" bind:this={menuEl}>
      <button class="share" aria-haspopup="menu" aria-expanded={open} onclick={() => (open = !open)} title="Hand these findings to your coding agent, or save a shareable image">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m14.7 6.3 3 3M4 20l4.5-1 10.8-10.8a2.1 2.1 0 0 0-3-3L5.5 16 4 20z" /></svg>
        Fix with agent
        <svg class="chev" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6" /></svg>
      </button>
      {#if open}
        <div class="pop" role="menu">
          <p class="note">A prompt that tells your agent how to read NoVul's findings and fix them, project by project.</p>
          {#each ["claude", "codex"] as const as a (a)}
            <button role="menuitem" onclick={pick(() => oncopy(a))}>Copy prompt for {AGENT_NAME[a]}</button>
          {/each}
          {#each agents as a (a)}
            {#if a === "claude" || a === "codex"}
              <button role="menuitem" onclick={pick(() => onopen(a))}>Open in {AGENT_NAME[a]} <span class="dim">Terminal</span></button>
            {/if}
          {/each}
          <hr />
          <button role="menuitem" disabled={busy} onclick={pick(onshare)}>{busy ? "Saving…" : "Save as image"} <span class="dim">no project names</span></button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .hl { flex: none; display: flex; align-items: flex-start; gap: 12px; padding: 14px 16px 0; }
  .txt { flex: 1; min-width: 0; }
  h1 { margin: 0; font-size: 21px; line-height: 1.2; font-weight: 600; letter-spacing: -0.01em; text-wrap: balance; }
  p { margin: 4px 0 0; font-size: 12.5px; line-height: 1.4; color: var(--muted); text-wrap: pretty; }
  .part { white-space: nowrap; }
  b { font-weight: 600; font-variant-numeric: tabular-nums; }
  .share {
    flex: none; height: 26px; padding: 0 10px 0 8px; display: inline-flex; align-items: center; gap: 6px;
    border: 1px solid var(--line); border-radius: 7px; background: var(--raised); color: var(--text); font-size: 12px;
  }
  .share:hover:not(:disabled) { border-color: #34405f; background: #212b45; }
  .share:disabled { opacity: 0.6; }
  .chev { opacity: 0.7; margin-left: -1px; }
  .menu { position: relative; flex: none; }
  .pop {
    position: absolute; right: 0; top: calc(100% + 6px); z-index: 30; width: 270px; padding: 6px; display: flex; flex-direction: column;
    background: var(--raised); border: 1px solid #2b3552; border-radius: 10px; box-shadow: 0 14px 34px rgba(0, 0, 0, 0.5); animation: rise 0.12s ease;
  }
  .pop button {
    display: flex; justify-content: space-between; align-items: baseline; gap: 8px; width: 100%; padding: 7px 9px; border: 0; border-radius: 6px;
    background: none; color: var(--text); font-size: 12.5px; text-align: left;
  }
  .pop button:hover:not(:disabled), .pop button:focus-visible { background: #24304d; }
  .pop button:disabled { opacity: 0.6; }
  .dim { color: var(--muted); font-size: 11px; }
  .note { margin: 2px 9px 6px; font-size: 11.5px; line-height: 1.4; color: var(--muted); }
  hr { width: 100%; margin: 5px 0; border: 0; border-top: 1px solid var(--hair); }
</style>
