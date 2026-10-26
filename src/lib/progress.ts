import type { Overview } from "./types";

const n = (x: number) => x.toLocaleString("en-US");

export function progressText(ov: Overview): string {
  const [done, total] = ov.progress ?? [0, 0];
  switch (ov.phase) {
    case "machine":
      return "Checking this Mac (Homebrew, runtimes, tools)";
    case "secrets":
      return total ? `Looking for exposed secrets: ${n(done)} of ${n(total)} folders` : "Looking for exposed secrets…";
    case "packages":
      return total ? `Checking ${n(done)} of ${n(total)} lockfiles` : "Looking for lockfiles…";
    default:
      return total ? `Scanning ${n(done)} of ${n(total)} lockfiles` : "Scanning lockfiles…";
  }
}
