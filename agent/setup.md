# Connect your coding agent to NoVul

The app has to have run at least once (it creates the database). The binary is the app's own executable:
`/Applications/NoVul.app/Contents/MacOS/novul`

## MCP server (read-only except rescan)

Claude Code:

    claude mcp add novul -- /Applications/NoVul.app/Contents/MacOS/novul mcp

Codex (syntax checked against codex 0.160.0, `codex mcp add --help`):

    codex mcp add novul -- /Applications/NoVul.app/Contents/MacOS/novul mcp

OpenCode (`opencode.json`):

    { "mcp": { "novul": { "type": "local", "command": ["/Applications/NoVul.app/Contents/MacOS/novul", "mcp"] } } }

pi has no MCP client: use the CLI plus the AGENTS.md snippet.

## Skill (Claude Code)

    mkdir -p ~/.claude/skills && cp -R agent/skills/novul ~/.claude/skills/

## AGENTS.md (Codex, OpenCode, pi)

Append `agent/AGENTS-snippet.md` to the project's `AGENTS.md` (or the agent's global AGENTS.md).

## CLI quick check

    /Applications/NoVul.app/Contents/MacOS/novul findings --project "$PWD"
