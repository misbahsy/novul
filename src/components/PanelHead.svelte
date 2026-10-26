<script lang="ts">
  import { ESTIMATED_TIP, type Tab } from "../lib/model";

  let { tab = $bindable(), q = $bindable(), showDev = $bindable(), showEstimated = $bindable(), searchEl = $bindable(), counts, label, pinned, onclear }: {
    tab: Tab;
    q: string;
    showDev: boolean;
    showEstimated: boolean;
    searchEl: HTMLInputElement | undefined;
    counts: Record<Tab, number>;
    label: string;
    pinned: boolean;
    onclear: () => void;
  } = $props();

  const tabs: [Tab, string][] = [["fix", "Fix plan"], ["projects", "Projects"], ["system", "This Mac"], ["secrets", "Secrets"]];
</script>

<div class="head">
  <div class="tabs" role="tablist">
    {#each tabs.filter(([id]) => id !== "secrets" || counts.secrets > 0) as [id, name]}
      <button role="tab" aria-selected={tab === id} class:on={tab === id} onclick={() => (tab = id)}>
        {name}<em>{counts[id].toLocaleString("en-US")}</em>
      </button>
    {/each}
  </div>
  <div class="find">
    <label class="search">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></svg>
      <input bind:this={searchEl} bind:value={q} placeholder="Search package, project or CVE" spellcheck="false" autocomplete="off" />
      {#if q}<button class="x" aria-label="Clear search" onclick={() => (q = "")}>×</button>{/if}
    </label>
    <button class="dev" class:on={showDev} aria-pressed={showDev} onclick={() => (showDev = !showDev)} title="Show development dependencies">
      <i></i>Dev
    </button>
    <button class="dev" class:on={showEstimated} aria-pressed={showEstimated} onclick={() => (showEstimated = !showEstimated)} title={ESTIMATED_TIP}>
      <i></i>Estimated
    </button>
  </div>
  <div class="ctx">
    <span class="lbl" class:pinned>{label}</span>
    {#if pinned}<button class="x" aria-label="Clear filter" onclick={onclear}>×</button>{/if}
  </div>
</div>

<style>
  .head { flex: none; }
  .tabs { display: flex; gap: 2px; padding: 0 12px; border-bottom: 1px solid var(--hair); }
  .tabs button {
    height: 36px; padding: 0 10px; border: 0; background: none; color: var(--muted); font-size: 12.5px;
    border-bottom: 2px solid transparent; margin-bottom: -1px; white-space: nowrap;
  }
  .tabs button:hover { color: var(--text); }
  .tabs button.on { color: var(--text); border-bottom-color: var(--teal); }
  .tabs em { font-style: normal; font-size: 11px; margin-left: 6px; opacity: 0.6; }
  .find { display: flex; gap: 8px; padding: 10px 12px 6px; }
  .search {
    flex: 1; min-width: 0; height: 28px; display: flex; align-items: center; gap: 7px; padding: 0 8px;
    background: var(--ink); border: 1px solid var(--hair); border-radius: 7px; color: var(--muted);
  }
  .search:focus-within { border-color: var(--teal); }
  .search input { flex: 1; min-width: 0; border: 0; outline: 0; background: none; color: var(--text); -webkit-user-select: text; user-select: text; }
  .search input::placeholder { color: var(--muted); }
  .x { border: 0; background: none; color: var(--muted); font-size: 15px; line-height: 1; padding: 0 2px; }
  .x:hover { color: var(--text); }
  .dev {
    height: 28px; padding: 0 10px 0 8px; display: flex; align-items: center; gap: 6px; border: 1px solid var(--hair);
    background: none; border-radius: 7px; color: var(--muted); font-size: 12px;
  }
  .dev i { width: 8px; height: 8px; border-radius: 50%; border: 1.5px solid var(--muted); }
  .dev.on { color: var(--text); border-color: color-mix(in srgb, var(--teal) 50%, var(--hair)); }
  .dev.on i { background: var(--teal); border-color: var(--teal); }
  .ctx { height: 24px; padding: 0 12px; display: flex; align-items: center; gap: 4px; font-size: 11.5px; color: var(--muted); }
  .lbl { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .lbl.pinned { color: var(--teal); }
</style>
