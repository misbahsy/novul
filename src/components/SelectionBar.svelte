<script lang="ts">
  import { plural } from "../lib/model";
  import CopyBtn from "./CopyBtn.svelte";

  let { count, commands, brief, onclear }: { count: number; commands: () => string; brief: () => string; onclear: () => void } = $props();
</script>

<footer>
  <span class="n"><b>{plural(count, "fix", "fixes")}</b> selected</span>
  <button class="link" onclick={onclear}>Clear</button>
  <div class="btns">
    <CopyBtn cls="btn" label="Copy commands" text={commands} />
    <CopyBtn cls="btn primary" label="Copy for my agent" text={brief} />
  </div>
</footer>

<style>
  footer {
    position: absolute; left: 0; right: 0; bottom: 0; z-index: 2; display: flex; flex-wrap: wrap; align-items: center; gap: 8px 10px;
    padding: 10px 14px; background: var(--raised); border-top: 1px solid #2b3552; box-shadow: 0 -10px 24px rgba(0, 0, 0, 0.3);
    animation: rise 0.15s ease;
  }
  .n { font-size: 12.5px; }
  .btns { display: flex; gap: 8px; margin-left: auto; }
</style>
