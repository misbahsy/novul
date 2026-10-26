<script lang="ts">
  import { copyText } from "../lib/model";

  let { text, label = "Copy", cls = "link" }: { text: () => string; label?: string; cls?: string } = $props();
  let done = $state(false);

  async function go(e: MouseEvent) {
    e.stopPropagation();
    if (!(await copyText(text()))) return;
    done = true;
    setTimeout(() => (done = false), 1500);
  }
</script>

<button class={cls} onclick={go}>{done ? "Copied" : label}</button>
