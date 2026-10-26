// Prompts that hand NoVul's findings to a coding agent (Claude Code, Codex) to fix.
// The agent reads results through the CLI, which needs no setup; MCP is offered as an extra.

export type Agent = "claude" | "codex";
export const AGENT_NAME: Record<Agent, string> = { claude: "Claude Code", codex: "Codex" };

export interface PromptFacts {
  vulns: number;
  projects: number;
  exploited: number;
  malicious: number;
  secrets: number;
  /** Narrow the work to one project folder. */
  project?: string;
}

const n = (x: number) => x.toLocaleString("en-US");
const plural = (x: number, one: string, many = one + "s") => `${n(x)} ${x === 1 ? one : many}`;
const sh = (s: string) => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

export function agentPrompt(agent: Agent, bin: string, f: PromptFacts): string {
  const b = sh(bin);
  const found = [
    f.malicious ? plural(f.malicious, "malicious package") : "",
    f.vulns ? plural(f.vulns, "known vulnerability", "known vulnerabilities") + (f.exploited ? ` (${n(f.exploited)} actively exploited)` : "") : "",
    f.secrets ? plural(f.secrets, "exposed secret") : "",
  ].filter(Boolean);
  const what = found.length > 1 ? `${found.slice(0, -1).join(", ")} and ${found[found.length - 1]}` : (found[0] ?? "nothing open right now");
  const where = f.project ? ` in ${f.project}` : f.projects ? ` across ${plural(f.projects, "project")}` : "";
  const dir = f.project ? sh(f.project) : "<project dir>";
  const mcp = `${agent === "claude" ? "claude" : "codex"} mcp add novul -- ${b} mcp`;

  return `NoVul, the vulnerability scanner on this Mac, found ${what}${where}. Please help me fix them.

Read the findings with NoVul's CLI. It only reads local scan results:
${f.project ? "" : `  ${b} projects
      every project with open issues, most urgent first
`}  ${b} findings --json --project ${dir} --min high
      that project's malicious, actively exploited, critical and high findings, each with fix_command
      (drop --min high for medium and low; add --limit N to page through long lists)
  ${b} findings --json --kind secret${f.project ? ` --project ${dir}` : ""}
      exposed secrets (where they are, never the value)
${f.project ? "" : `  ${b} findings --json --kind brew,runtime,global,tool --min high
      Homebrew packages, language runtimes, global installs and AI tools
`}  ${b} finding <id> --json
      details for one finding
  ${b} scan ${dir}
      rescan a project after fixing it
(Optional, once: \`${mcp}\` gives you the same as MCP tools.)

How to work:
1. Start with malicious packages and actively exploited vulnerabilities, then critical, then high. Work one project at a time.
2. In each project, apply the finding's fix_command or the equivalent upgrade for its package manager. Prefer upgrading direct dependencies, keep the lockfile consistent and the change minimal.${agent === "codex" ? " Package installs need network access; ask me to approve it if the sandbox blocks it." : ""}
3. Run the project's tests or build. If an upgrade breaks something, undo it and tell me instead of forcing it.
4. Rescan the project with \`${b} scan ${dir}\` and check that the findings are gone.
5. Malicious package: remove it, look at what it could have accessed, and tell me which credentials to rotate.
6. Exposed secrets: never print, copy or log a secret value. Move it into the macOS Keychain or a gitignored .env file, restrict the file with chmod 600, and tell me which keys to rotate, especially any that were committed to git.
7. Homebrew packages, language runtimes and global installs affect the whole Mac: show me the commands and ask before running them.
8. Don't commit or push. Finish with a short summary: what you fixed, what you skipped and why, and what I still need to do.`;
}
