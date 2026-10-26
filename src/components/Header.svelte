<script lang="ts">
  import type { Overview } from "../lib/types";
  import { fmt, relativeTime } from "../lib/model";
  import { progressText } from "../lib/progress";

  let { ov, counts, total, now, onscan, onsettings }: {
    ov: Overview | null;
    counts: number[];
    total: number;
    now: number;
    onscan: () => void;
    onsettings: () => void;
  } = $props();

  const scanning = $derived(ov?.scanning ?? false);
  const pct = $derived(ov?.progress?.[1] ? (ov.progress[0] / ov.progress[1]) * 100 : 100);
  const checked = $derived(relativeTime(ov?.last_check_at ?? null, now));
</script>

<header data-tauri-drag-region>
  <svg class="glyph" data-tauri-drag-region width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
    <circle cx="12" cy="12" r="9.5" opacity=".55" /><circle cx="12" cy="12" r="5.2" opacity=".55" /><path d="M12 12 19 6.2" /><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
  </svg>
  <p class="status" data-tauri-drag-region>
    {#if !ov}
      &nbsp;
    {:else if scanning}
      <span data-tauri-drag-region>{progressText(ov)}</span>
    {:else if total === 0}
      <b data-tauri-drag-region class="ok">All clear</b><i data-tauri-drag-region>·</i><span data-tauri-drag-region>{checked}</span>
    {:else}
      <b data-tauri-drag-region>{fmt(total)}</b> issues
      {#if counts[0]}<i data-tauri-drag-region>·</i><b data-tauri-drag-region style="color:var(--s-malicious)">{fmt(counts[0])}</b> malicious{/if}
      {#if counts[1]}<i data-tauri-drag-region>·</i><b data-tauri-drag-region style="color:var(--s-exploited)">{fmt(counts[1])}</b> actively exploited{/if}
      <i data-tauri-drag-region>·</i><span data-tauri-drag-region>{checked}</span>
    {/if}
    {#if ov?.last_error && !scanning}<i data-tauri-drag-region>·</i><span data-tauri-drag-region class="err" title={ov.last_error}>last check failed</span>{/if}
  </p>
  <span class="grow" data-tauri-drag-region></span>
  <button class="btn primary" disabled={scanning} onclick={onscan} title="Scan now (⌘R)">{scanning ? "Scanning" : "Scan"}</button>
  <button class="gear" aria-label="Settings" onclick={onsettings}>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </svg>
  </button>
  {#if scanning}<div class="prog" data-tauri-drag-region style="width:{pct}%"></div>{/if}
</header>

<style>
  header {
    position: relative; height: 44px; padding: 0 12px 0 80px; display: flex; align-items: center; gap: 10px;
    border-bottom: 1px solid var(--hair); flex: none;
  }
  .glyph { color: var(--teal); flex: none; pointer-events: none; }
  .status { margin: 0; font-size: 12.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; }
  .status b { color: var(--text); font-weight: 600; }
  .status i { font-style: normal; margin: 0 7px; opacity: 0.5; }
  .err { color: var(--s-critical); }
  .grow { flex: 1; align-self: stretch; }
  .gear { width: 28px; height: 28px; display: grid; place-items: center; border: 0; border-radius: 7px; background: transparent; color: var(--muted); }
  .gear:hover { background: var(--raised); color: var(--text); }
  .prog { position: absolute; left: 0; bottom: -1px; height: 2px; background: var(--teal); box-shadow: 0 0 8px var(--teal); transition: width 0.3s ease; }
</style>
