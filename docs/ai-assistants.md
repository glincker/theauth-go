# Using theauth-go with AI coding assistants

Copy the rule file for your tool into your project, then point the assistant at the docs.

```sh
cp docs/ai-rules/AGENTS.md AGENTS.md
```

| Tool | Copy |
|---|---|
| Codex, Cursor, Copilot coding agent, Gemini CLI | `AGENTS.md` to the project root |
| Cursor | `.cursor/rules/theauth.mdc` to `.cursor/rules/theauth.mdc` |
| Claude Code | `CLAUDE.md`, appended to your own |
| GitHub Copilot | `copilot-instructions.md` to `.github/copilot-instructions.md` |

`CLAUDE.md` and `copilot-instructions.md` point to `AGENTS.md`, so copy that too. Gemini CLI reads `GEMINI.md` by default: copy `AGENTS.md` to `GEMINI.md`, or set `context.fileName` to `AGENTS.md` in `.gemini/settings.json`.

Docs for the assistant:

1. [`llms.txt`](../llms.txt) in this repository: a short overview with links.
2. Full Go docs: https://docs.theauth.dev/go
3. [AGENTS.md](AGENTS.md): what the library does, a working example and a "what not to do" list.
4. The TypeScript `llms.txt` and `llms-full.txt` do not cover Go.

The rules cover wiring (`theauth.New`, `a.Mount`, `a.RequireAuth()`, `policy/toolguard`, `mcpresource`) and forbid:

- Logging or committing tokens, secrets or `Authorization` headers.
- Trusting an agent's claim to act for a user without checking delegation.
- Allowing policy errors, or wrapping agent tools outside `toolguard.Tool`.
- Sending non-DPoP MCP tokens across your trust boundary, or non-exact redirect matching.

## Limits

- The hosted docs MCP server (`https://docs.theauth.dev/mcp`) indexes the TypeScript docs only. No Go docs MCP server is published, so it is not recommended here.
- The rule files say how to wire the library and what to avoid. Read the Go docs for options.
