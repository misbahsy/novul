<script lang="ts">
  let { text, tip }: { text: string; tip?: string } = $props();
  const id = `tip-${Math.random().toString(36).slice(2, 8)}`;
</script>

<span class="info">
  <button type="button" aria-label="More about this setting" aria-describedby={id}>i</button>
  <span class="tip" role="tooltip" {id}>
    {text}
    {#if tip}<em>Recommended: {tip}</em>{/if}
  </span>
</span>

<style>
  .info { display: inline-flex; vertical-align: middle; margin-left: 6px; }
  button {
    width: 15px; height: 15px; padding: 0; border-radius: 50%;
    border: 1px solid var(--muted); background: none; color: var(--muted);
    font: italic 600 9.5px/13px Georgia, serif; text-transform: none; cursor: help;
  }
  button:hover, button:focus-visible { border-color: var(--teal); color: var(--teal); outline: 0; }
  .tip {
    /* anchored to the setting row (the nearest positioned ancestor), full width, below the icon */
    position: absolute; left: 0; right: 0; margin-top: 22px; z-index: 10;
    padding: 10px 12px; border-radius: 9px; background: var(--raised); border: 1px solid var(--hair);
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4);
    color: var(--text); font-size: 12px; font-weight: 400; line-height: 1.5;
    letter-spacing: 0; text-transform: none;
    opacity: 0; visibility: hidden; transform: translateY(-3px);
    transition: opacity 0.12s, transform 0.12s, visibility 0.12s;
  }
  .tip em { display: block; margin-top: 6px; font-style: normal; color: var(--teal); }
  .info:hover .tip, .info:focus-within .tip { opacity: 1; visibility: visible; transform: none; }
</style>
