<script lang="ts">
  import type { FindingView } from "../lib/types";
  import { COLOR, LABEL, PRIORITIES, RANK, fmt, groupProjects, plural, shortPath, type Item, type Scope } from "../lib/model";
  import FindingRow from "./FindingRow.svelte";

  let { items, scope, hoverKey, onpick, onback, ondetail, filtered }: {
    items: Item[];
    scope: Scope | null;
    hoverKey: string | null;
    onpick: (s: Scope) => void;
    onback: () => void;
    ondetail: (f: FindingView) => void;
    filtered: boolean;
  } = $props();

  const LIMIT = 200;
  let limit = $state(LIMIT);
  const projects = $derived(groupProjects(items));
  const maxTotal = $derived(Math.max(1, ...projects.map((p) => p.total)));
  const list = $derived(
    scope?.pk ? [...items].sort((a, b) => RANK[a.f.priority] - RANK[b.f.priority] || (b.f.score ?? 0) - (a.f.score ?? 0)) : [],
  );
  $effect(() => {
    scope;
    limit = LIMIT;
  });
</script>

{#if scope?.pk}
  <div class="bar">
    <button class="link" onclick={onback}>‹ All projects</button>
    <b>{scope.label}</b>
    <span class="muted">{plural(list.length, "issue")}</span>
  </div>
  {#each list.slice(0, limit) as it (it.f.id)}
    <FindingRow f={it.f} onclick={() => ondetail(it.f)} />
  {/each}
  {#if list.length > limit}<button class="more" onclick={() => (limit += LIMIT)}>Show more ({list.length - limit} left)</button>{/if}
  {#if !list.length}<div class="empty"><b>Nothing matches</b>Try a different search.</div>{/if}
{:else if !projects.length}
  <div class="empty"><b>{filtered ? "Nothing matches" : "No vulnerable projects"}</b>{filtered ? "Try a different search or clear the filter." : "Every lockfile NoVul checked is clean."}</div>
{:else}
  {#each projects.slice(0, limit) as p (p.pk)}
    <button class="prow" class:hot={hoverKey === p.pk} onclick={() => onpick({ sk: p.pk, pk: p.pk, label: p.name })}>
      <span class="name">
        <b>{p.name}</b>
        <span class="path mono" title={p.path}>{shortPath(p.path.replace(/\/[^/]*$/, ""))}</span>
      </span>
      <span class="bars" style="width:{28 + 84 * Math.sqrt(p.total / maxTotal)}px">
        {#each PRIORITIES as pr, r}
          {#if p.counts[r]}<i style="flex:{p.counts[r]} 1 3px;background:{COLOR[pr]}" title="{fmt(p.counts[r])} {LABEL[pr]}"></i>{/if}
        {/each}
      </span>
      <span class="n">{fmt(p.total)}</span>
    </button>
  {/each}
  {#if projects.length > limit}<button class="more" onclick={() => (limit += LIMIT)}>Show more ({projects.length - limit} left)</button>{/if}
{/if}

<style>
  .bar { display: flex; align-items: baseline; gap: 10px; padding: 10px 16px; border-bottom: 1px solid var(--hair); }
  .bar b { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .prow {
    display: flex; align-items: center; gap: 14px; width: 100%; padding: 8px 16px; border: 0; background: none;
    text-align: left; border-bottom: 1px solid var(--hair);
  }
  .prow:hover, .prow.hot { background: var(--raised); }
  .name { flex: 1; min-width: 0; display: grid; }
  .name b { font-weight: 600; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .path { font-size: 10.5px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bars { display: flex; gap: 1px; height: 6px; flex: none; }
  .bars i { border-radius: 1.5px; min-width: 3px; }
  .n { width: 38px; text-align: right; color: var(--muted); flex: none; }
</style>
