<script lang="ts">
  import type { FindingView } from "../lib/types";
  import { COLOR, RANK, shortPath, type Item } from "../lib/model";
  import { revealPath } from "../lib/backend";
  import CopyBtn from "./CopyBtn.svelte";

  let { items, ondetail }: { items: Item[]; ondetail: (f: FindingView) => void } = $props();

  const list = $derived(items.map((i) => i.f).filter((f) => f.kind === "secret").sort((a, b) => RANK[a.priority] - RANK[b.priority] || a.project_path.localeCompare(b.project_path)));

  const ADD = `security add-generic-password -a "$USER" -s NAME -w`;
  const READ = `$(security find-generic-password -a "$USER" -s NAME -w)`;
  const OP_REF = "op://Vault/Item/field";
  const OP_RUN = "op run --env-file .env -- <cmd>";
</script>

{#each list as f (f.id)}
  <article style="--c:{COLOR[f.priority]}">
    <div class="top">
      <button class="name" onclick={() => ondetail(f)}>
        <i class="dot"></i><b class="mono">{f.name}</b>
        <span class="fp mono" title="First 8 hex characters of a hash of the value. The value itself is never stored.">fingerprint {f.installed_version}</span>
      </button>
      {#if f.fix_command}<CopyBtn cls="chip act" label="chmod 600" text={() => f.fix_command!} />{/if}
    </div>
    <div class="file">
      <span class="mono sel" title={f.project_path}>{shortPath(f.project_path)}</span>
      <button class="link" onclick={() => revealPath(f.project_path)}>Reveal</button>
    </div>
    <p class="sum sel">{f.summary}</p>
  </article>
{:else}
  <div class="empty"><b>No secrets found</b>Nothing matches.</div>
{/each}

<section class="help">
  <h3>How to move a secret</h3>
  <p class="muted">NoVul never reads out or stores the value. Move it out of the file, then reference it.</p>

  <h4>macOS Keychain</h4>
  <div class="cmd"><code class="sel">{ADD}</code><CopyBtn text={() => ADD} /></div>
  <p class="muted small">Then read it back where the app needs it:</p>
  <div class="cmd"><code class="sel">{READ}</code><CopyBtn text={() => READ} /></div>

  <h4>1Password</h4>
  <p class="muted small">Put a reference in your .env instead of the value:</p>
  <div class="cmd"><code class="sel">{OP_REF}</code><CopyBtn text={() => OP_REF} /></div>
  <p class="muted small">and run your command through the CLI:</p>
  <div class="cmd"><code class="sel">{OP_RUN}</code><CopyBtn text={() => OP_RUN} /></div>
</section>

<style>
  article { padding: 9px 14px 10px 13px; border-bottom: 1px solid var(--hair); border-left: 3px solid var(--c); display: grid; gap: 3px; }
  .top { display: flex; align-items: center; gap: 10px; }
  .name { flex: 1; min-width: 0; display: flex; align-items: center; gap: 8px; border: 0; background: none; padding: 0; text-align: left; }
  .name:hover b { text-decoration: underline; }
  .name b { font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .fp { color: var(--muted); font-size: 10.5px; white-space: nowrap; }
  :global(.chip.act) { cursor: pointer; color: var(--teal); border-color: color-mix(in srgb, var(--teal) 45%, var(--hair)); font-family: var(--mono); }
  :global(.chip.act:hover) { background: color-mix(in srgb, var(--teal) 14%, var(--raised)); }
  .file { display: flex; align-items: baseline; gap: 10px; }
  .file .mono { flex: 1; min-width: 0; color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sum { margin: 0; font-size: 12px; line-height: 1.45; }

  .help { padding: 16px 16px 20px; display: grid; gap: 6px; }
  h3 { margin: 0; font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
  h4 { margin: 10px 0 0; font-size: 12.5px; font-weight: 600; }
  .help p { margin: 0; font-size: 12px; }
  .small { font-size: 11.5px; }
  .cmd { display: flex; align-items: flex-start; gap: 10px; padding: 7px 10px; border-radius: 8px; background: var(--ink); border: 1px solid var(--hair); }
  code { flex: 1; min-width: 0; font-size: 11.5px; color: var(--teal); white-space: pre-wrap; word-break: break-all; }
</style>
