import * as real from "./api";
import { mock } from "./mock";
import type { AppState, RootSuggestion, Settings } from "./types";

/** In a plain browser (no Tauri) every call is served by src/lib/mock.ts. */
export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export const getState = (): Promise<AppState> => (isTauri ? real.getState() : Promise.resolve(mock.getState()));
export const scanNow = (): Promise<void> => (isTauri ? real.scanNow() : Promise.resolve(mock.scanNow()));
export const setMuted = (id: number, muted: boolean): Promise<void> =>
  isTauri ? real.setMuted(id, muted) : Promise.resolve(mock.setMuted(id, muted));
export const getSettings = (): Promise<Settings> => (isTauri ? real.getSettings() : Promise.resolve(mock.getSettings()));
export const setSettings = (s: Settings): Promise<void> =>
  isTauri ? real.setSettings(s) : Promise.resolve(mock.setSettings(s));
export const openUrl = (url: string): Promise<void> =>
  isTauri ? real.openUrl(url) : Promise.resolve(void window.open(url, "_blank", "noopener"));
export const revealPath = (path: string): Promise<void> =>
  isTauri ? real.revealPath(path) : Promise.resolve(void console.info("reveal", path));
export const takeFocusRequest = (): Promise<number | null> => (isTauri ? real.takeFocusRequest() : Promise.resolve(null));

export const onStateChanged = async (cb: () => void): Promise<() => void> =>
  isTauri ? real.onStateChanged(cb) : mock.subscribe(cb);
export const onFocusFinding = async (cb: (id: number) => void): Promise<() => void> =>
  isTauri ? real.onFocusFinding(cb) : () => {};

export const applyFix = (findingId: number): Promise<{ ok: boolean; output: string }> =>
  isTauri ? real.applyFix(findingId) : mock.applyFix(findingId);
export const saveImage = (dataUrl: string): Promise<string> => (isTauri ? real.saveImage(dataUrl) : Promise.resolve(""));
export const suggestRoots = (): Promise<RootSuggestion[]> => (isTauri ? real.suggestRoots() : mock.suggestRoots());
export const agentInfo = (): Promise<{ bin: string; agents: string[] }> =>
  isTauri ? real.agentInfo() : Promise.resolve({ bin: "/Applications/NoVul.app/Contents/MacOS/novul", agents: ["claude", "codex"] });
export const openInAgent = (agent: string, prompt: string, cwd: string | null): Promise<void> =>
  isTauri ? real.openInAgent(agent, prompt, cwd) : Promise.resolve();
/** Native folder picker (several folders at once); [] when cancelled. */
export async function pickFolders(): Promise<string[]> {
  if (!isTauri) return mock.pickFolders();
  const { open } = await import("@tauri-apps/plugin-dialog");
  const r = await open({ directory: true, multiple: true });
  return r == null ? [] : Array.isArray(r) ? r : [r];
}
