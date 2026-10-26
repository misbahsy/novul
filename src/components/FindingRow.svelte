<script lang="ts">
  import type { FindingView } from "../lib/types";
  import { COLOR, ESTIMATED_TIP } from "../lib/model";

  let { f, onclick }: { f: FindingView; onclick: () => void } = $props();
</script>

<button class="row" style="--c:{COLOR[f.priority]}" {onclick}>
  <i class="dot"></i>
  <span class="main">
    <span class="top mono">{f.name}<em>{f.installed_version}{f.fixed_version ? ` → ${f.fixed_version}` : ""}</em></span>
    <span class="sub"><span class="mono">{f.group_id}</span> {f.summary}</span>
  </span>
  {#if f.dev}<span class="chip">dev</span>{/if}
  {#if f.inferred}<span class="chip" title={ESTIMATED_TIP}>estimated</span>{/if}
  {#if f.kev}<span class="tag">KEV</span>{/if}
  {#if f.score != null}<span class="score">{f.score.toFixed(1)}</span>{/if}
</button>

<style>
  .row {
    display: flex; align-items: center; gap: 10px; width: 100%; padding: 8px 16px; border: 0;
    background: none; text-align: left; border-bottom: 1px solid var(--hair);
  }
  .row:hover { background: var(--raised); }
  .main { flex: 1; min-width: 0; display: grid; gap: 1px; }
  .top { font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .top em { font-style: normal; color: var(--muted); margin-left: 8px; font-size: 11.5px; }
  .sub { font-size: 11.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sub .mono { color: var(--text); opacity: 0.7; margin-right: 4px; }
</style>
