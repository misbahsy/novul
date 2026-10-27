// Mirrors src-tauri/src/model.rs. Keep in sync.

export type Priority = "malicious" | "exploited" | "critical" | "high" | "medium" | "low" | "unrated";

export interface FindingView {
  id: number;
  kind: "package" | "brew" | "runtime" | "global" | "tool" | "secret";
  group_id: string;
  aliases: string[];
  summary: string;
  priority: Priority;
  score: number | null;
  kev: boolean;
  ecosystem: string;
  name: string;
  installed_version: string;
  fixed_version: string | null;
  direct: boolean | null;
  dev: boolean;
  inferred: boolean;
  project_path: string;
  project_name: string;
  fix_command: string | null;
  url: string;
  first_seen_at: number;
  muted: boolean;
  /** EPSS exploit probability 0..1 for the canonical CVE, when known. */
  epss: number | null;
}

export interface Counts {
  malicious: number;
  exploited: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unrated: number;
}

export interface Overview {
  last_check_at: number | null;
  scanning: boolean;
  progress: [number, number] | null;
  /** "packages" | "machine" | "secrets" during a full scan */
  phase?: "packages" | "machine" | "secrets" | null;
  paused_until: number | null;
  projects: number;
  packages: number;
  counts: Counts;
  last_error: string | null;
}

export interface RuntimeStatus {
  kind: string;
  version: string;
  path: string;
  cycle: string | null;
  latest_in_cycle: string | null;
  latest_date: string | null;
  is_eol: boolean;
  behind: boolean;
}

export interface AppState {
  overview: Overview;
  findings: FindingView[];
  runtimes: RuntimeStatus[];
}

export interface RootSuggestion {
  path: string;
  projects: number | null;
}

export interface Settings {
  roots: string[];
  exclusions: string[];
  interval_minutes: number;
  notify_threshold: Priority;
  show_dev: boolean;
  show_estimated: boolean;
  private_mode: boolean;
  launch_at_login: boolean;
}
