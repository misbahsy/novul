<script lang="ts">
  import { BAND_NAME, COLOR, OTHER, PRIORITIES, bandTotals, centerOf, fmt, shortPath, type Band, type Scope, type Sector } from "../lib/model";
  import { BW, C, R, R0, TAU, VB, annular, dotsOf, pt, spokesPath, ticksPath } from "../lib/radar";
  import { progressText } from "../lib/progress";
  import type { Overview } from "../lib/types";

  let { sectors, counts, total, ov, scope, onhover, onselect }: {
    sectors: Sector[];
    counts: number[];
    total: number;
    ov: Overview | null;
    scope: Scope | null;
    onhover: (s: Scope | null) => void;
    onselect: (s: Scope | null) => void;
  } = $props();

  const n = $derived(Math.max(1, sectors.length));
  const w = $derived(TAU / n);
  const scanning = $derived(ov?.scanning ?? false);
  const spokes = $derived(spokesPath(sectors.length));
  const ticks = ticksPath();
  const dots = $derived(dotsOf(sectors));

  let hoverI = $state<number | null>(null);
  let hoverB = $state(0);
  let tipX = $state(0);
  let tipY = $state(0);
  let stageW = $state(0);
  let svg: SVGSVGElement;

  const selI = $derived(scope ? sectors.findIndex((s) => s.key === scope.sk) : -1);
  const active = $derived(hoverI ?? (selI >= 0 ? selI : null));
  const hot = $derived(hoverI != null ? sectors[hoverI] : null);

  function locate(e: PointerEvent) {
    const r = svg.getBoundingClientRect();
    const k = Math.min(r.width, r.height) / VB;
    const x = (e.clientX - r.left - (r.width - VB * k) / 2) / k - C;
    const y = (e.clientY - r.top - (r.height - VB * k) / 2) / k - C;
    const rho = Math.hypot(x, y);
    if (rho < R0 || rho > R || !sectors.length) return null;
    const a = (Math.atan2(x, -y) + TAU) % TAU;
    const i = Math.min(sectors.length - 1, Math.floor(a / w));
    const b = Math.min(3, Math.floor((rho - R0) / BW));
    const d = dots.find((q) => q.i === i && q.b === b);
    const onDot = !!d && Math.hypot(x + C - d.x, y + C - d.y) <= d.r + 5;
    return { i, b: b as Band, onDot };
  }
  const scopeOf = (i: number, band?: Band): Scope => {
    const s = sectors[i];
    return { sk: s.key, pk: s.key === OTHER ? undefined : s.key, band, label: band == null ? s.label : `${s.label} · ${BAND_NAME[band]}` };
  };

  function move(e: PointerEvent) {
    const l = locate(e);
    const i = l && sectors[l.i].total > 0 ? l.i : null;
    if (i !== hoverI) onhover(i == null ? null : scopeOf(i));
    hoverI = i;
    if (l) hoverB = l.b;
    const r = svg.parentElement!.getBoundingClientRect();
    tipX = e.clientX - r.left;
    tipY = e.clientY - r.top;
  }
  function leave() {
    hoverI = null;
    onhover(null);
  }
  function click(e: PointerEvent | MouseEvent) {
    const l = locate(e as PointerEvent);
    if (!l) return onselect(null);
    if (sectors[l.i].total > 0) onselect(scopeOf(l.i, l.onDot ? l.b : undefined));
  }

  const center = $derived.by(() => {
    if (scanning && !total) return { big: ov?.progress ? fmt(ov.progress[0]) : "…", label: ov?.progress ? `of ${fmt(ov.progress[1])}` : "scanning", color: "var(--teal)" };
    return centerOf(counts, total);
  });
  const bands = $derived(bandTotals(counts));
</script>

<figure class="radar">
  <div class="stage" bind:clientWidth={stageW}>
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions, a11y_click_events_have_key_events -->
    <svg bind:this={svg} viewBox="0 0 {VB} {VB}" role="img" aria-label="Threat radar: projects as sectors, severity as rings" onpointermove={move} onpointerleave={leave} onclick={click} style:cursor={hot ? "pointer" : "default"}>
      <defs>
        {#each PRIORITIES as p}
          <radialGradient id="glow-{p}">
            <stop offset="0" style="stop-color:var(--s-{p})" />
            <stop offset="0.36" style="stop-color:var(--s-{p})" />
            <stop offset="0.4" style="stop-color:var(--s-{p});stop-opacity:0.5" />
            <stop offset="0.7" style="stop-color:var(--s-{p});stop-opacity:0.12" />
            <stop offset="1" style="stop-color:var(--s-{p});stop-opacity:0" />
          </radialGradient>
        {/each}
        <radialGradient id="wash"><stop offset="0" stop-color="#3ee6c4" stop-opacity="0.09" /><stop offset="1" stop-color="#3ee6c4" stop-opacity="0.01" /></radialGradient>
        <linearGradient id="trail" gradientUnits="userSpaceOnUse" x1={C} y1="0" x2={C - 100} y2="0"><stop offset="0" stop-color="#3ee6c4" stop-opacity="0.32" /><stop offset="1" stop-color="#3ee6c4" stop-opacity="0" /></linearGradient>
      </defs>

      <circle cx={C} cy={C} r={R} fill="url(#wash)" />
      {#each [1, 2, 3] as k}<circle class="ring" cx={C} cy={C} r={R0 + BW * k} />{/each}
      <circle class="ring edge" cx={C} cy={C} r={R} />
      <circle class="ring edge" cx={C} cy={C} r={R0} />
      <path class="ticks" d={ticks} />
      <path class="spoke" d={spokes} />

      {#if selI >= 0}
        <path class="sel" d={annular(R0, R, selI * w, (selI + 1) * w)} />
        {#if scope?.band != null}<path class="selcell" d={annular(R0 + BW * scope.band, R0 + BW * (scope.band + 1), selI * w, (selI + 1) * w)} />{/if}
      {/if}
      {#if hoverI != null}
        <path class="hov" d={annular(R0, R, hoverI * w, (hoverI + 1) * w)} />
        <path class="hovcell" d={annular(R0 + BW * hoverB, R0 + BW * (hoverB + 1), hoverI * w, (hoverI + 1) * w)} />
      {/if}

      {#each dots as d (d.i * 4 + d.b)}
        {#if d.mal}<circle class="pulse" cx={d.x} cy={d.y} r={d.r + 1} style="stroke:var(--s-malicious)" />{/if}
        <circle class="glow" class:dim={active != null && active !== d.i} cx={d.x} cy={d.y} r={d.r / 0.38} style="fill:url(#glow-{d.p})" />
      {/each}

      {#if scanning}
        <g class="sweep">
          <path d="M{C} {C}L{C} {C - R}A{R} {R} 0 0 0 {pt(R, -0.42)}Z" fill="url(#trail)" />
          <path d="M{C} {C - R0}L{C} {C - R}" stroke="#3ee6c4" stroke-width="1.5" />
        </g>
      {/if}

      {#if center}
        <text class="big" x={C} y={C + 6} text-anchor="middle" style="fill:{center.color};font-size:{center.big.length > 4 ? 36 : 46}px">{center.big}</text>
        <text class="lab" x={C} y={C + 28} text-anchor="middle">{center.label}</text>
      {:else}
        <path d="M{C - 14} {C - 12}l9 9l19 -19" fill="none" stroke="#3ee6c4" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" />
        <text class="lab ok" x={C} y={C + 24} text-anchor="middle" style="font-size:19px">All clear</text>
      {/if}
    </svg>

    {#if hot}
      <div class="tip" style="left:{tipX}px;top:{tipY}px;transform:translate({tipX > stageW / 2 ? 'calc(-100% - 14px)' : '14px'}, 14px)">
        <b>{hot.label}</b>
        <span class="path mono">{hot.key === OTHER ? hot.path : shortPath(hot.path)}</span>
        {#each hot.cells as c, b}
          <div class="trow" class:on={b === hoverB} class:zero={!c}>
            <i class="dot" style="--c:{c ? COLOR[PRIORITIES[c.worst]] : 'var(--hair)'}"></i>
            <span>{BAND_NAME[b]}</span>
            <em>{c ? fmt(c.count) : "–"}</em>
            <small>{c ? `${fmt(c.pkgs)} pkg${c.pkgs === 1 ? "" : "s"}` : ""}</small>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <figcaption>
    {#if total}
      <span class="from">centre → edge</span>
      {#each bands as n, b}<span class="band"><b>{fmt(n)}</b> {BAND_NAME[b]}</span>{/each}
    {:else if scanning}
      <span>{ov ? progressText(ov) : "Looking for lockfiles…"}</span>
    {:else if ov}
      <span>Checked <b>{fmt(ov.projects)}</b> projects · <b>{fmt(ov.packages)}</b> packages</span>
    {/if}
  </figcaption>
</figure>

<style>
  .radar { margin: 0; flex: 1; min-height: 0; display: flex; flex-direction: column; padding: 14px 10px 10px; min-width: 0; }
  .stage { position: relative; flex: 1; min-height: 0; }
  svg { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; }
  .ring { fill: none; stroke: var(--hair); stroke-width: 1; }
  .ring.edge { stroke: color-mix(in srgb, var(--teal) 32%, var(--hair)); }
  .ticks { stroke: color-mix(in srgb, var(--teal) 30%, var(--hair)); stroke-width: 1; fill: none; }
  .spoke { stroke: var(--hair); stroke-width: 1; opacity: 0.7; fill: none; }
  .hov { fill: rgba(62, 230, 196, 0.06); }
  .hovcell { fill: rgba(232, 236, 246, 0.07); }
  .sel { fill: rgba(62, 230, 196, 0.09); stroke: rgba(62, 230, 196, 0.5); stroke-width: 1; }
  .selcell { fill: rgba(62, 230, 196, 0.12); stroke: var(--teal); stroke-width: 1; }
  .glow { pointer-events: none; transition: opacity 0.15s; }
  .glow.dim { opacity: 0.22; }
  .pulse { fill: none; stroke-width: 1.5; pointer-events: none; transform-box: fill-box; transform-origin: center; animation: pulse 3.4s ease-out infinite; }
  @keyframes pulse { from { transform: scale(1); opacity: 0.8; } to { transform: scale(2.8); opacity: 0; } }
  .sweep { transform-box: view-box; transform-origin: 50% 50%; animation: spin 4.5s linear infinite; pointer-events: none; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .pulse { animation: none; opacity: 0.4; } }
  .big { font-weight: 600; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
  .lab { fill: var(--muted); font-size: 13px; letter-spacing: 0.1em; text-transform: uppercase; }
  .lab.ok { fill: var(--teal); text-transform: none; letter-spacing: 0; font-weight: 600; }

  figcaption { flex: none; display: flex; flex-wrap: wrap; justify-content: center; gap: 2px 14px; padding-top: 8px; font-size: 11.5px; color: var(--muted); }
  figcaption b { color: var(--text); font-weight: 600; }
  .from { opacity: 0.7; }
  @media (max-width: 900px) { .from { display: none; } }

  .tip {
    position: absolute; z-index: 3; pointer-events: none; min-width: 170px; max-width: 230px; padding: 9px 11px;
    background: var(--raised); border: 1px solid #2b3552; border-radius: 9px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    display: grid; gap: 1px; font-size: 12px;
  }
  .tip b { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .path { color: var(--muted); font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-bottom: 4px; }
  .trow { display: grid; grid-template-columns: 8px 1fr auto 52px; gap: 7px; align-items: center; color: var(--muted); }
  .trow.on { color: var(--text); }
  .trow em { font-style: normal; text-align: right; color: var(--text); }
  .trow small { color: var(--muted); font-size: 10.5px; }
  .trow.zero em { color: var(--muted); }
</style>
