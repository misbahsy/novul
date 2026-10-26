import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AppState, RootSuggestion, Settings } from "./types";

export const getState = () => invoke<AppState>("get_state");
export const scanNow = () => invoke<void>("scan_now");
export const setMuted = (findingId: number, muted: boolean) => invoke<void>("set_muted", { findingId, muted });
export const getSettings = () => invoke<Settings>("get_settings");
export const setSettings = (settings: Settings) => invoke<void>("set_settings", { settings });
export const openUrl = (url: string) => invoke<void>("open_url", { url });
export const revealPath = (path: string) => invoke<void>("reveal_path", { path });

/** Backend emits "state-changed" (no payload) whenever findings or overview change. */
export const onStateChanged = (cb: () => void): Promise<UnlistenFn> => listen("state-changed", cb);
/** Backend emits "focus-finding" with a finding id when the user picks one from the tray menu. */
export const onFocusFinding = (cb: (id: number) => void): Promise<UnlistenFn> =>
  listen<number>("focus-finding", (e) => cb(e.payload));
/** Finding id the user picked in the tray menu before the window existed; cleared on read. */
export const takeFocusRequest = () => invoke<number | null>("take_focus_request");

/** Runs the finding's fix command in its project folder (after the user confirmed it). */
export const applyFix = (findingId: number) => invoke<{ ok: boolean; output: string }>("apply_fix", { findingId });
/** Saves a PNG data URL to the Desktop, reveals it in Finder, returns the path. */
export const saveImage = (dataUrl: string) => invoke<string>("save_image", { dataUrl });
/** Folders where code seems to live, most projects first. Takes up to ~1.5 s per folder. */
export const suggestRoots = () => invoke<RootSuggestion[]>("suggest_roots");
/** The app's own executable (the `novul` CLI) and the coding agent CLIs found on PATH. */
export const agentInfo = () => invoke<{ bin: string; agents: string[] }>("agent_info");
/** Opens Terminal with Claude Code or Codex started on the given prompt. */
export const openInAgent = (agent: string, prompt: string, cwd: string | null) => invoke<void>("open_in_agent", { agent, prompt, cwd });
