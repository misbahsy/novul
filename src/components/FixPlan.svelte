<script lang="ts">
  import type { FindingView } from "../lib/types";
  import type { Fix, Target } from "../lib/model";
  import FixRow from "./FixRow.svelte";

  let { fixes, checked, ontoggle, ondetail, onrun, filtered }: {
    fixes: Fix[];
    checked: Set<string>;
    ontoggle: (key: string) => void;
    ondetail: (f: FindingView) => void;
    onrun: (g: Fix, t: Target) => void;
    filtered: boolean;
  } = $props();

  const LIMIT = 200;
  let open = $state.raw(new Set<string>());
  let limit = $state(LIMIT);
  let nolimit = $state(LIMIT);

  const main = $derived(fixes.filter((g) => g.verb !== "none"));
  const nofix = $derived(fixes.filter((g) => g.verb === "none"));
  const maxRisk = $derived(Math.max(1, ...fixes.map((g) => g.risk)));

  function expand(key: string) {
    const next = new Set(open);
    if (!next.delete(key)) next.add(key);
    open = next;
  }
</script>

{#if !fixes.length}
  <div class="empty"><b>{filtered ? "Nothing matches" : "Nothing to fix"}</b>{filtered ? "Try a different search or clear the filter." : "No known vulnerabilities in what NoVul can see."}</div>
{:else}
  {#each main.slice(0, limit) as g (g.key)}
    <FixRow {g} open={open.has(g.key)} checked={checked.has(g.key)} {maxRisk} ontoggle={() => ontoggle(g.key)} onexpand={() => expand(g.key)} {ondetail} onrun={(t) => onrun(g, t)} />
  {/each}
  {#if main.length > limit}<button class="more" onclick={() => (limit += LIMIT)}>Show {Math.min(LIMIT, main.length - limit)} more of {main.length - limit}</button>{/if}

  {#if nofix.length}
    <h3>No fix yet <em>{nofix.length}</em></h3>
    {#each nofix.slice(0, nolimit) as g (g.key)}
      <FixRow {g} open={open.has(g.key)} checked={false} {maxRisk} ontoggle={() => {}} onexpand={() => expand(g.key)} {ondetail} onrun={(t) => onrun(g, t)} />
    {/each}
    {#if nofix.length > nolimit}<button class="more" onclick={() => (nolimit += LIMIT)}>Show more</button>{/if}
  {/if}
{/if}

<style>
  h3 { margin: 0; padding: 14px 14px 6px; font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--hair); }
  h3 em { font-style: normal; opacity: 0.7; margin-left: 4px; }
</style>
