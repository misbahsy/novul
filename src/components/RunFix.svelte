<script lang="ts">
  import type { Target } from "../lib/model";
  import { shortPath } from "../lib/model";
  import { applyFix } from "../lib/backend";

  let { t, name, onclose }: { t: Target; name: string; onclose: () => void } = $props();

  let phase = $state<"confirm" | "running" | "done">("confirm");
  let result = $state<{ ok: boolean; output: string } | null>(null);
  let cancelBtn = $state<HTMLButtonElement>();
  let closeBtn = $state<HTMLButtonElement>();
  const folder = $derived(t.command?.startsWith("cd ") ? shortPath(t.dir) : "None (Homebrew, system-wide)");

  $effect(() => (phase === "confirm" ? cancelBtn : closeBtn)?.focus());

  async function run() {
    phase = "running";
    try {
      result = await applyFix(t.fid);
    } catch (e) {
      result = { ok: false, output: String(e) };
    }
    phase = "done";
  }
  function onkey(e: KeyboardEvent) {
    if (e.key === "Escape" && phase !== "running") {
      e.preventDefault();
      onclose();
    }
  }
</script>

<svelte:window onkeydown={onkey} />

<div class="scrim">
  <div class="dlg" role="dialog" aria-modal="true" aria-labelledby="rf-title">
    <h2 id="rf-title">{phase === "confirm" ? "Run this fix?" : phase === "running" ? "Running…" : result?.ok ? "Fix applied" : "Fix failed"}</h2>
    <p class="who muted">{t.name} · <span class="mono">{name}</span></p>

    <dl>
      <dt>Command</dt><dd><code class="sel">{t.command}</code></dd>
      <dt>Folder</dt><dd class="mono sel" title={t.dir}>{folder}</dd>
    </dl>

    {#if phase === "confirm"}
      <p class="warn">Runs in your login shell. Review it first.</p>
      <div class="btns">
        <button bind:this={cancelBtn} class="btn" onclick={onclose}>Cancel</button>
        <button class="btn primary" onclick={run}>Run</button>
      </div>
    {:else if phase === "running"}
      <div class="status"><i class="spinner"></i><span>Running the command. This can take a minute.</span></div>
    {:else if result}
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <pre class="out sel" role="region" aria-label="Command output" tabindex="0">{result.output.trim() || "(no output)"}</pre>
      <p class="line" class:ok={result.ok} class:bad={!result.ok}>
        {result.ok ? "Done. NoVul is rechecking this project." : "The command failed. Nothing else was changed by NoVul."}
      </p>
      <div class="btns"><button bind:this={closeBtn} class="btn primary" onclick={onclose}>Close</button></div>
    {/if}
  </div>
</div>

<style>
  .scrim { position: absolute; inset: 0; z-index: 8; display: grid; place-items: center; padding: 16px; background: rgba(8, 11, 20, 0.66); animation: rise 0.12s ease; }
  .dlg { width: min(420px, 100%); max-height: 100%; overflow: auto; padding: 16px 18px 14px; border-radius: 12px; background: var(--panel); border: 1px solid var(--line); box-shadow: 0 18px 50px rgba(0, 0, 0, 0.5); display: flex; flex-direction: column; gap: 10px; }
  h2 { margin: 0; font-size: 15px; font-weight: 600; }
  .who { margin: -6px 0 0; font-size: 12px; }
  dl { margin: 0; display: grid; grid-template-columns: 58px minmax(0, 1fr); gap: 6px 10px; font-size: 12px; }
  dt { color: var(--muted); }
  dd { margin: 0; min-width: 0; }
  code { display: block; padding: 7px 9px; border-radius: 7px; background: var(--ink); border: 1px solid var(--hair); color: var(--teal); font-size: 11.5px; white-space: pre-wrap; word-break: break-all; }
  dd.mono { font-size: 11.5px; word-break: break-all; }
  .warn { margin: 0; font-size: 12px; }
  .btns { display: flex; justify-content: flex-end; gap: 8px; padding-top: 2px; }
  .status { display: flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--muted); padding: 4px 0; }
  .out { margin: 0; max-height: 240px; overflow: auto; padding: 8px 10px; border-radius: 7px; background: var(--ink); border: 1px solid var(--hair); font: 11px/1.45 var(--mono); white-space: pre-wrap; word-break: break-word; }
  .line { margin: 0; font-size: 12.5px; font-weight: 600; }
  .line.bad { color: var(--s-critical); }
</style>
