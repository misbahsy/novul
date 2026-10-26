<script lang="ts">
  import { onMount } from "svelte";
  import {
    agentInfo, getSettings, getState, isTauri, openInAgent, onFocusFinding, onStateChanged, scanNow, setMuted, setSettings, takeFocusRequest,
  } from "./lib/backend";
  import type { AppState, FindingView, Settings } from "./lib/types";
  import { EMPTY, GLOBAL, SECRET, TOOL, BREW, RUNTIME, briefFor, commandsFor, copyText, derive, fmt, groupFixes, headline, plural, view, type Fix, type Scope, type Tab, type Target } from "./lib/model";
  import { cardSvg, shareCard } from "./lib/share";
  import { AGENT_NAME, agentPrompt, type Agent } from "./lib/agent";
  import Header from "./components/Header.svelte";
  import HeadlineBlock from "./components/Headline.svelte";
  import Secrets from "./components/Secrets.svelte";
  import RunFix from "./components/RunFix.svelte";
  import Radar from "./components/Radar.svelte";
  import PanelHead from "./components/PanelHead.svelte";
  import FixPlan from "./components/FixPlan.svelte";
  import Projects from "./components/Projects.svelte";
  import System from "./components/System.svelte";
  import SelectionBar from "./components/SelectionBar.svelte";
  import Drawer from "./components/Drawer.svelte";
  import SettingsSheet from "./components/SettingsSheet.svelte";
  import Onboarding from "./components/Onboarding.svelte";

  function shouldOnboard() {
    const forced = new URLSearchParams(location.search).get("onboarding");
    if (forced != null) return forced !== "0";
    if (!isTauri) return false;
    try {
      return localStorage.getItem("vs.onboarded") !== "1";
    } catch {
      return true;
    }
  }

  let app = $state.raw<AppState | null>(null);
  let showDev = $state(false);
  let showEstimated = $state(false);
  let tab = $state<Tab>("fix");
  let q = $state("");
  let scope = $state.raw<Scope | null>(null);
  let hover = $state.raw<Scope | null>(null);
  let picked = $state.raw(new Set<string>());
  let detailId = $state<number | null>(null);
  let settingsOpen = $state(false);
  let onboarding = $state(shouldOnboard());
  // Known once settings load: with no folders chosen, onboarding asks for them first.
  let needRoots = $state(false);
  let settingsReady = $state(false);
  let now = $state(Date.now());
  let searchEl = $state<HTMLInputElement>();
  let listEl = $state<HTMLDivElement>();

  // Everything below is derived once per state change (or per filter change), never per render.
  const model = $derived(app ? derive(app.findings, showDev, showEstimated) : EMPTY);
  const searching = $derived(q.trim() !== "");
  const scoped = $derived(view(model.items, scope, q));
  const fixes = $derived(!scope && !searching ? model.fixes : groupFixes(scoped));
  const hoverOn = $derived(!!hover && tab === "fix" && hover.sk !== scope?.sk);
  const shownFixes = $derived(hoverOn ? groupFixes(view(model.items, hover, q)) : fixes);
  const selected = $derived(fixes.filter((g) => picked.has(g.key)));
  const detail = $derived(detailId != null ? (app?.findings.find((f) => f.id === detailId) ?? null) : null);
  const ov = $derived(app?.overview ?? null);
  const scanning = $derived(ov?.scanning ?? false);
  const tabCounts = $derived({ fix: model.fixes.length, projects: model.projects.length, system: model.sysCount, secrets: model.secrets });
  const hl = $derived(headline(model, ov));

  const SYSTEM = new Set([BREW, RUNTIME, GLOBAL, TOOL]);

  let fetching = false;
  let again = false;
  async function refetch() {
    if (fetching) return void (again = true);
    fetching = true;
    try {
      app = await getState();
    } finally {
      fetching = false;
      if (again) {
        again = false;
        refetch();
      }
    }
  }

  let hoverTimer: ReturnType<typeof setTimeout>;
  function onhover(s: Scope | null) {
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(() => (hover = s), s ? 70 : 120);
  }
  function select(s: Scope | null) {
    const same = s && scope && s.sk === scope.sk && s.pk === scope.pk && s.band === scope.band;
    scope = same ? null : s;
    if (s && !same && split === 1) setSplit(SPLIT);
    if (s && !same) tab = s.sk === SECRET ? "secrets" : SYSTEM.has(s.sk) ? "system" : tab === "system" || tab === "secrets" ? "fix" : tab;
  }
  function toggle(key: string) {
    const next = new Set(picked);
    if (!next.delete(key)) next.add(key);
    picked = next;
  }
  let runFor = $state.raw<{ name: string; t: Target } | null>(null);

  // Chart/list split: the fraction of the width the chart gets; 0 hides the chart, 1 hides the list.
  const SPLIT = 0.48;
  function storedSplit() {
    try {
      const v = localStorage.getItem("nv.split");
      return v != null && Number(v) >= 0 && Number(v) <= 1 ? Number(v) : SPLIT;
    } catch {
      return SPLIT;
    }
  }
  let split = $state(storedSplit());
  let dragging = $state(false);
  let mainEl = $state<HTMLElement>();
  // the drawer, settings, onboarding and fix sheets live in the list panel, so they bring it back
  const needsList = $derived(settingsOpen || !!detail || !!runFor || (onboarding && settingsReady) || selected.length > 0);
  const shown = $derived(needsList && split === 1 ? SPLIT : split);
  function setSplit(v: number) {
    split = v;
    try {
      localStorage.setItem("nv.split", String(v));
    } catch {}
  }
  // the list needs 400px for its tabs and search, the chart 320px; past half of that a side hides
  function fit(f: number) {
    const w = mainEl?.getBoundingClientRect().width || 980;
    const lo = 320 / w, hi = 1 - 400 / w;
    return f < lo / 2 ? 0 : f > 1 - (1 - hi) / 2 ? 1 : Math.min(hi, Math.max(lo, f));
  }
  function dragTo(e: PointerEvent) {
    if (!dragging || !mainEl) return;
    const r = mainEl.getBoundingClientRect();
    split = fit((e.clientX - r.left) / r.width);
  }
  function sepKey(e: KeyboardEvent) {
    const d = e.key === "ArrowLeft" ? -0.04 : e.key === "ArrowRight" ? 0.04 : 0;
    if (!d) return;
    e.preventDefault();
    setSplit(split === 0 || split === 1 ? SPLIT : fit(split + d));
  }
  let toast = $state.raw<{ text: string; sub?: string } | null>(null);
  let toastTimer: ReturnType<typeof setTimeout>;
  let sharing = $state(false);
  function say(text: string, sub?: string) {
    toast = { text, sub };
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = null), 4500);
  }
  async function share() {
    if (sharing) return;
    sharing = true;
    try {
      const date = new Date().toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
      const r = await shareCard(cardSvg(model, hl, date));
      if (r.file) say(r.copied ? "Saved to Desktop and copied" : "Saved to Desktop", r.file);
      else say("Opened the snapshot in a new tab");
    } catch {
      say("Couldn't create the snapshot");
    } finally {
      sharing = false;
    }
  }
  // "Fix with agent": a prompt that tells Claude Code or Codex how to read and fix these findings
  let agents = $state.raw<{ bin: string; agents: string[] }>({ bin: "/Applications/NoVul.app/Contents/MacOS/novul", agents: [] });
  agentInfo().then((a) => (agents = a)).catch(() => {});
  const scopedProject = () => (scope?.pk?.startsWith("/") ? scope.pk : undefined);
  const promptFor = (a: Agent) =>
    agentPrompt(a, agents.bin, {
      vulns: model.total - model.secrets, projects: ov?.projects ?? 0, exploited: model.counts[1], malicious: model.counts[0],
      secrets: model.secrets, project: scopedProject(),
    });
  async function copyPrompt(a: Agent) {
    say((await copyText(promptFor(a))) ? `Prompt copied. Paste it into ${AGENT_NAME[a]}.` : "Couldn't copy the prompt");
  }
  async function openAgent(a: Agent) {
    try {
      const cwd = scopedProject() ?? (await getSettings()).roots[0] ?? null;
      await openInAgent(a, promptFor(a), cwd);
      say(`Opening ${AGENT_NAME[a]} in Terminal`, cwd ?? undefined);
    } catch (e) {
      say(`Couldn't open ${AGENT_NAME[a]}`, String(e));
    }
  }
  const showDetail = (f: FindingView) => (detailId = f.id);

  function focusFinding(id: number) {
    const f = app?.findings.find((x) => x.id === id);
    if (!f) return;
    if (f.dev) showDev = true;
    if (f.inferred) showEstimated = true;
    settingsOpen = false;
    detailId = id;
  }
  async function mute(f: FindingView) {
    await setMuted(f.id, true);
    detailId = null;
    refetch();
  }
  async function save(s: Settings) {
    await setSettings(s);
    showDev = s.show_dev;
    showEstimated = s.show_estimated;
    settingsOpen = false;
    refetch();
  }
  function finishOnboarding() {
    if (needRoots) return;
    onboarding = false;
    try {
      localStorage.setItem("vs.onboarded", "1");
    } catch {}
  }

  function onkey(e: KeyboardEvent) {
    if (runFor) return;
    if (e.key === "Escape") {
      if (detailId != null) detailId = null;
      else if (settingsOpen) settingsOpen = false;
      else if (onboarding && !needRoots) finishOnboarding();
      else if (document.activeElement === searchEl && q) q = "";
      else if (scope) scope = null;
    } else if (e.metaKey && e.key.toLowerCase() === "r") {
      e.preventDefault();
      scanNow();
    } else if (e.metaKey && e.key.toLowerCase() === "f") {
      e.preventDefault();
      searchEl?.focus();
      searchEl?.select();
    }
  }

  $effect(() => {
    if (tab === "secrets" && !model.secrets) tab = "fix";
  });
  $effect(() => {
    tab; scope; q;
    if (listEl) listEl.scrollTop = 0;
  });

  onMount(() => {
    const unsubs: (() => void)[] = [];
    let dead = false;
    const tick = setInterval(() => (now = Date.now()), 20_000);
    (async () => {
      getSettings()
        .then((s) => {
          showDev = s.show_dev;
          showEstimated = s.show_estimated;
          if (s.roots.length === 0) needRoots = onboarding = true;
        })
        .finally(() => (settingsReady = true));
      await refetch();
      const id = await takeFocusRequest();
      if (id != null) focusFinding(id);
      const a = await onStateChanged(refetch);
      const b = await onFocusFinding(async (fid) => {
        await refetch();
        focusFinding(fid);
      });
      if (dead) { a(); b(); } else unsubs.push(a, b);
    })();
    return () => {
      dead = true;
      clearInterval(tick);
      unsubs.forEach((u) => u());
    };
  });
</script>

<svelte:window onkeydown={onkey} />

<div class="shell">
  <Header {ov} counts={model.counts} total={model.total} {now} onscan={() => scanNow()} onsettings={() => (settingsOpen = true)} />

  <main bind:this={mainEl} class:dragging style:--basis={shown === 0 ? "22px" : shown === 1 ? "calc(100% - 22px)" : `${shown * 100}%`}>
    <section class="left" class:gone={shown === 0}>
      <HeadlineBlock h={hl} busy={sharing} onshare={share} {ov} agents={agents.agents as Agent[]} oncopy={copyPrompt} onopen={openAgent} />
      <Radar sectors={model.sectors} counts={model.counts} total={model.total} {ov} {scope} {onhover} onselect={select} />
    </section>

    {#if shown > 0 && shown < 1}
    <!-- a focusable separator is the ARIA window-splitter pattern -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <div
      class="sep"
      role="separator" aria-orientation="vertical" aria-label="Resize chart and list" tabindex="0"
      aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(shown * 100)}
      title="Drag to resize. Drag to an edge to hide a side; double-click to reset."
      onpointerdown={(e) => { (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId); dragging = true; }}
      onpointermove={dragTo}
      onpointerup={() => { dragging = false; setSplit(split); }}
      ondblclick={() => setSplit(SPLIT)}
      onkeydown={sepKey}
    ></div>
    {:else if shown === 0}
      <button class="edge start" onclick={() => setSplit(SPLIT)} title="Show the chart">Show chart</button>
    {:else if shown === 1}
      <button class="edge end" onclick={() => setSplit(SPLIT)} title="Show the list">Show list</button>
    {/if}

    <section class="panel" class:gone={shown === 1}>
      <PanelHead
        bind:tab bind:q bind:showDev bind:showEstimated bind:searchEl counts={tabCounts}
        label={hoverOn ? hover!.label : (scope?.label ?? "Everything on this Mac")}
        pinned={!!scope && !hoverOn}
        onclear={() => (scope = null)}
      />
      <div class="list scroll" class:pad={selected.length > 0} bind:this={listEl}>
        {#if !app}
          <!-- loading -->
        {:else if model.total === 0}
          <div class="empty">
            {#if scanning}
              <b>Scanning</b>Looking for lockfiles, runtimes and Homebrew formulae. Results appear here as they are found.
            {:else if model.hiddenDev > 0}
              <b>Nothing outside dev dependencies</b>{plural(model.hiddenDev, "dev-only issue")} hidden.
              <button class="link" onclick={() => (showDev = true)}>Show dev</button>
            {:else if model.hiddenEstimated > 0}
              <b>Nothing with exact versions</b>{plural(model.hiddenEstimated, "estimated issue")} hidden.
              <button class="link" onclick={() => (showEstimated = true)}>Show estimated</button>
            {:else}
              <b>All clear</b>No known vulnerabilities in {fmt(ov?.packages ?? 0)} packages.
            {/if}
          </div>
        {:else if tab === "fix"}
          <FixPlan fixes={shownFixes} checked={picked} ontoggle={toggle} ondetail={showDetail} onrun={(g: Fix, t: Target) => (runFor = { name: g.name, t })} filtered={!!scope || searching} />
        {:else if tab === "projects"}
          <Projects items={scoped} {scope} hoverKey={hover?.pk ?? null} onpick={(s) => (scope = s)} onback={() => (scope = null)} ondetail={showDetail} filtered={!!scope || searching} />
        {:else if tab === "secrets"}
          <Secrets items={scoped} ondetail={showDetail} />
        {:else}
          <System
            items={scoped} runtimes={app.runtimes} {searching}
            showRuntimes={!scope || scope.sk === RUNTIME || !SYSTEM.has(scope.sk)}
            ondetail={showDetail}
          />
        {/if}
      </div>

      {#if selected.length}
        <SelectionBar count={selected.length} commands={() => commandsFor(selected)} brief={() => briefFor(selected)} onclear={() => (picked = new Set())} />
      {/if}
      {#if detail}<Drawer f={detail} onclose={() => (detailId = null)} onmute={() => mute(detail)} />{/if}
      {#if settingsOpen}<SettingsSheet onsave={save} oncancel={() => (settingsOpen = false)} />{/if}
      {#if runFor}<RunFix t={runFor.t} name={runFor.name} onclose={() => (runFor = null)} />{/if}
      {#if onboarding && settingsReady}<Onboarding {needRoots} ondone={finishOnboarding} onroots={() => ((needRoots = false), refetch())} />{/if}
    </section>
  </main>
</div>

{#if toast}
  <div class="toast" role="status"><b>{toast.text}</b>{#if toast.sub}<span class="mono">{toast.sub}</span>{/if}</div>
{/if}

<style>
  .shell { height: 100%; display: flex; flex-direction: column; }
  main { position: relative; flex: 1; min-height: 0; display: flex; }
  .left { flex: 0 0 var(--basis); min-width: 0; min-height: 0; display: flex; flex-direction: column; overflow: hidden; transition: flex-basis 0.18s ease; }
  .panel { position: relative; flex: 1 1 0; min-width: 0; min-height: 0; display: flex; flex-direction: column; overflow: hidden; background: var(--panel); border-left: 1px solid var(--hair); }
  main.dragging .left { transition: none; }
  main.dragging { cursor: col-resize; user-select: none; }
  .gone { visibility: hidden; }
  .panel.gone { border: 0; }
  .sep { position: absolute; top: 0; bottom: 0; left: calc(var(--basis) - 4px); width: 8px; z-index: 6; cursor: col-resize; touch-action: none; transition: left 0.18s ease; }
  main.dragging .sep { transition: none; }
  .sep::after { content: ""; position: absolute; top: 0; bottom: 0; left: 3px; width: 2px; background: var(--teal); opacity: 0; transition: opacity 0.12s; }
  .sep:hover::after, .sep:focus-visible::after, main.dragging .sep::after { opacity: 0.7; }
  .sep:focus-visible { outline: none; }
  .edge {
    position: absolute; top: 0; bottom: 0; z-index: 7; width: 22px; padding: 0; border: 0; border-radius: 0;
    writing-mode: vertical-rl; font-size: 11px; letter-spacing: 0.04em; color: var(--muted); background: var(--panel);
  }
  .edge:hover { color: var(--teal); background: var(--raised); }
  .edge.start { left: 0; border-right: 1px solid var(--hair); }
  .edge.end { right: 0; border-left: 1px solid var(--hair); }
  .list { flex: 1; min-height: 0; }
  .toast {
    position: fixed; left: 0; right: 0; bottom: 18px; margin: 0 auto; width: fit-content; z-index: 20; max-width: calc(100% - 32px);
    display: flex; align-items: baseline; gap: 10px; padding: 9px 14px; border-radius: 10px; font-size: 12.5px;
    background: var(--raised); border: 1px solid #2b3552; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45); animation: rise 0.15s ease;
  }
  .toast span { color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .list.pad { padding-bottom: 76px; }
</style>
