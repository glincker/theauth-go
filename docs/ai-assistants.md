# Using theauth-go with AI coding assistants

If an assistant writes your auth code, give it the real docs and a short list of rules. This page covers Cursor, Claude Code, Codex, GitHub Copilot and Gemini CLI. For the library's own agent notes, see [AGENTS.md](AGENTS.md).

## Docs as context

- [`llms.txt`](../llms.txt) in this repository (raw: `https://raw.githubusercontent.com/glincker/theauth-go/main/llms.txt`): a short overview with links.
- Full Go docs: https://docs.theauth.dev/go
- The TypeScript SDK publishes `https://docs.theauth.dev/llms.txt` and `https://docs.theauth.dev/llms-full.txt`. Those cover the TypeScript docs, not the Go docs.
- [AGENTS.md](AGENTS.md): what the library does, a working example and a "what not to do" list.

Most tools let you paste a URL into the chat or add it as a doc source (Cursor: `@Docs`). Otherwise point the assistant at the files above.

## Docs MCP server

A hosted docs MCP server exists for the TypeScript docs site (`https://docs.theauth.dev/mcp`), but it does not index the Go docs, so it is not recommended here. No Go-specific docs MCP server is published.

## Rule files to copy

Ready-made files live in [`ai-rules/`](ai-rules/). Copy the one for your tool into your own project:

| File | Copy to | Tool |
|---|---|---|
| `AGENTS.md` | `AGENTS.md` in your project root | Codex, Cursor, Copilot coding agent, Gemini CLI |
| `.cursor/rules/theauth.mdc` | `.cursor/rules/theauth.mdc` | Cursor |
| `CLAUDE.md` | append to your `CLAUDE.md` | Claude Code |
| `copilot-instructions.md` | `.github/copilot-instructions.md` | GitHub Copilot |

Gemini CLI reads `GEMINI.md` by default. Copy `AGENTS.md` to `GEMINI.md`, or set `context.fileName` to `AGENTS.md` in `.gemini/settings.json`.

The rules say how to wire the library (`theauth.New`, `a.Mount`, `a.RequireAuth()`, `policy/toolguard`, the `mcpresource` module) and what an assistant must not do:

- Never log or commit tokens, secrets or `Authorization` headers.
- Always verify delegation. Read the `Principal` from `mcpresource` instead of trusting a claim.
- Keep policy deny by default. Treat deny, escalation and errors as "do not run".
- Wrap every agent tool with `toolguard.Tool`.
- Use DPoP-bound tokens for MCP access tokens that leave your trust boundary.
- Match redirect URIs exactly.
