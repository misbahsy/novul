<script lang="ts">
  import { getSettings, openUrl, pickFolders } from "../lib/backend";
  import type { Priority, Settings } from "../lib/types";
  import Info from "./Info.svelte";
  import CopyBtn from "./CopyBtn.svelte";

  let { onsave, oncancel }: { onsave: (s: Settings) => void; oncancel: () => void } = $props();

  let draft = $state<Settings | null>(null);
  let newRoot = $state("");
  let newExcl = $state("");
  getSettings().then((s) => (draft = s));

  function add(list: "roots" | "exclusions", v: string) {
    v = v.trim();
    if (draft && v && !draft[list].includes(v)) draft[list].push(v);
  }
  async function addFolders() {
    for (const p of await pickFolders()) add("roots", p);
  }
  const BIN = "/Applications/NoVul.app/Contents/MacOS/novul";
  const agents = [
    ["Claude Code", `claude mcp add novul -- ${BIN} mcp`],
    ["Codex", `codex mcp add novul -- ${BIN} mcp`],
  ];
  const findings = `${BIN} findings --project "$PWD"`;
  const intervals = [15, 30, 60];
  const thresholds: [Priority, string][] = [["critical", "Critical"], ["high", "High +"], ["medium", "Medium +"]];
  const credits = [
    ["OSV.dev", "https://osv.dev"],
    ["CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
    ["FIRST EPSS", "https://www.first.org/epss"],
    ["Have I Been Pwned (CC BY 4.0)", "https://haveibeenpwned.com"],
    ["endoflife.date", "https://endoflife.date"],
    ["osv-scanner", "https://github.com/google/osv-scanner"],
    ["gitleaks", "https://github.com/gitleaks/gitleaks"],
  ];
</script>

<aside aria-label="Settings">
  <div class="body scroll">
    <h2>Settings</h2>
    {#if draft}
      <section>
        <h3>Folders to watch<Info
          text="NoVul looks inside these folders for projects: it reads lockfiles such as package-lock.json, uv.lock or Cargo.lock to learn the exact versions you use, and rescans a project as soon as its lockfile changes. Your whole home folder works too, but it is slower and finds more old copies."
          tip="the folder(s) where you keep code, e.g. ~/Workspace" /></h3>
        <p class="hint">Where your projects live.</p>
        <ul>
          {#each draft.roots as r (r)}
            <li><span class="mono" title={r}>{r}</span><button aria-label="Remove {r}" onclick={() => (draft!.roots = draft!.roots.filter((x) => x !== r))}>×</button></li>
          {/each}
        </ul>
        <form onsubmit={(e) => { e.preventDefault(); add("roots", newRoot); newRoot = ""; }}>
          <input bind:value={newRoot} placeholder="/path/to/folder" spellcheck="false" />
          <button class="btn" type="submit">Add</button>
          <button class="btn" type="button" onclick={addFolders}>Add folder…</button>
        </form>
      </section>

      <section>
        <h3>Skip folders named<Info
          text="Any folder with one of these names is never searched. node_modules, .venv and vendor hold installed copies of packages your lockfile already lists; dist, build and target are build output. End a name with * to match a prefix: archive* also skips archive-2024."
          tip="keep the defaults; add folders of old or third-party code" /></h3>
        <p class="hint">Saves time and cuts duplicate results.</p>
        <div class="chips">
          {#each draft.exclusions as x (x)}
            <span class="chip mono">{x}<button aria-label="Remove {x}" onclick={() => (draft!.exclusions = draft!.exclusions.filter((y) => y !== x))}>×</button></span>
          {/each}
        </div>
        <form onsubmit={(e) => { e.preventDefault(); add("exclusions", newExcl); newExcl = ""; }}>
          <input bind:value={newExcl} placeholder="node_modules" spellcheck="false" />
          <button class="btn" type="submit">Add</button>
        </form>
      </section>

      <section class="inline">
        <div>
          <h3>Check for new advisories<Info
            text="How often NoVul asks OSV.dev whether a newly published vulnerability affects your packages. Only package names and versions are sent; it takes a few seconds. Changed lockfiles are rescanned immediately anyway, and a full rescan runs once a day."
            tip="30 min" /></h3>
          <p class="hint">Only names and versions leave your Mac.</p>
        </div>
        <div class="seg">{#each intervals as m}<button class:on={draft.interval_minutes === m} onclick={() => (draft!.interval_minutes = m)}>{m} min</button>{/each}</div>
      </section>
      <section class="inline">
        <div>
          <h3>Notify me about<Info
            text="The lowest severity that sends a macOS notification. Malicious packages and actively exploited bugs always notify. Everything still appears in the app; this only controls interruptions."
            tip="High +" /></h3>
          <p class="hint">Severity that's worth an interruption.</p>
        </div>
        <div class="seg">{#each thresholds as [t, label]}<button class:on={draft.notify_threshold === t} onclick={() => (draft!.notify_threshold = t)}>{label}</button>{/each}</div>
      </section>

      <div class="check">
        <label><input type="checkbox" bind:checked={draft.show_dev} /> Include development-only packages</label>
        <Info
          text="Test runners, bundlers, linters and other tools listed as devDependencies (or a dev group in Python). They run on your machine but don't ship to your users, so a vulnerable one is usually lower risk. Malicious or actively exploited ones are always shown, because they can still steal secrets from this Mac."
          tip="off, to keep the list focused" />
      </div>
      <div class="check">
        <label><input type="checkbox" bind:checked={draft.show_estimated} /> Include estimated versions</label>
        <Info
          text="Python projects that only have a requirements.txt don't record every package version, so NoVul estimates the rest, and the installed version may differ. Estimated findings are hidden from counts, the menu bar and notifications unless this is on. Malicious or actively exploited ones always show. Pin versions with a lockfile (uv, poetry, pip-tools) for exact results."
          tip="off, until you pin versions with a lockfile" />
      </div>
      <div class="check">
        <label><input type="checkbox" bind:checked={draft.launch_at_login} /> Start NoVul when I log in</label>
        <Info
          text="Keeps checks running after a restart. NoVul sits in the menu bar at about 20 MB and scans in a separate low-priority process that exits when it's done."
          tip="on" />
      </div>

      <section>
        <h3>Connect your coding agent<Info
          text="Lets Claude Code, Codex or another agent read these results, fix the repo it's working in, and ask NoVul to rescan. Nothing is sent anywhere; it reads the local results." /></h3>
        <p class="hint">Run one of these in a terminal.</p>
        {#each agents as [label, cmd] (label)}
          <div class="cmd">
            <div class="ctext"><span class="lbl">{label}</span><code class="sel">{cmd}</code></div>
            <CopyBtn text={() => cmd} />
          </div>
        {/each}
        <p class="hint or">Or ask it to run:</p>
        <div class="cmd"><div class="ctext"><code class="sel">{findings}</code></div><CopyBtn text={() => findings} /></div>
      </section>

      <section>
        <h3>About</h3>
        <p class="hint">NoVul is free and open source under the Apache 2.0 license. Data and tools by:</p>
        <p class="credits">
          {#each credits as [label, url], i (url)}{#if i}<span>·</span>{/if}<button class="link" onclick={() => openUrl(url)}>{label}</button>{/each}
        </p>
      </section>
    {/if}
  </div>
  <div class="foot">
    <button class="btn" onclick={oncancel}>Cancel</button>
    <button class="btn primary" disabled={!draft} onclick={() => draft && onsave($state.snapshot(draft) as Settings)}>Save</button>
  </div>
</aside>

<style>
  aside { position: absolute; inset: 0; z-index: 5; background: var(--panel); display: flex; flex-direction: column; animation: slide 0.2s ease; box-shadow: -14px 0 30px rgba(0, 0, 0, 0.25); }
  .body { flex: 1; min-height: 0; overflow-x: hidden; padding: 18px 20px; display: flex; flex-direction: column; gap: 18px; }
  h2 { margin: 0; font-size: 17px; font-weight: 600; }
  h3 { margin: 0 0 8px; font-size: 10.5px; font-weight: 600; color: var(--muted); letter-spacing: 0.06em; text-transform: uppercase; }
  .inline { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .inline h3 { margin: 0; }
  ul { list-style: none; margin: 0 0 8px; padding: 0; display: grid; gap: 4px; }
  li { display: flex; align-items: center; gap: 8px; padding: 5px 10px; background: var(--ink); border-radius: 7px; font-size: 12px; }
  li span { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  li button, .chip button { border: 0; background: none; color: var(--muted); padding: 0 0 0 6px; font-size: 14px; line-height: 1; }
  li button:hover, .chip button:hover { color: var(--s-critical); }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
  form { display: flex; gap: 8px; }
  form input { flex: 1; min-width: 0; height: 28px; padding: 0 10px; border: 1px solid var(--hair); border-radius: 7px; background: var(--ink); -webkit-user-select: text; user-select: text; }
  form input:focus { outline: 0; border-color: var(--teal); }
  .seg { display: flex; background: var(--ink); border-radius: 8px; padding: 2px; }
  .seg button { border: 0; background: none; color: var(--muted); height: 24px; padding: 0 12px; border-radius: 6px; font-size: 12px; }
  .seg button.on { background: var(--teal); color: var(--teal-ink); font-weight: 600; }
  section, .check { position: relative; }
  .hint { margin: -4px 0 8px; font-size: 11.5px; color: var(--muted); }
  .inline .hint { margin: 3px 0 0; }
  .check { display: flex; align-items: center; }
  .check label { display: flex; align-items: center; gap: 10px; }
  .check input { accent-color: var(--teal); width: 15px; height: 15px; margin: 0; }
  .cmd { display: flex; align-items: flex-start; gap: 10px; padding: 7px 10px; margin-bottom: 6px; border-radius: 8px; background: var(--ink); border: 1px solid var(--hair); }
  .ctext { flex: 1; min-width: 0; display: grid; gap: 2px; }
  .lbl { font-size: 11px; color: var(--muted); }
  code { font-size: 11.5px; color: var(--teal); white-space: pre-wrap; word-break: break-all; }
  .hint.or { margin: 8px 0 6px; }
  .credits { margin: 0; display: flex; flex-wrap: wrap; gap: 4px 6px; font-size: 11.5px; color: var(--muted); }
  .credits .link { border: 0; background: none; padding: 0; font: inherit; color: var(--teal); cursor: pointer; }
  .credits .link:hover { text-decoration: underline; }
  .foot { padding: 12px 20px; border-top: 1px solid var(--hair); display: flex; justify-content: flex-end; gap: 8px; }
</style>
