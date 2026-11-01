# About theauth-go

## What it is

theauth-go is the Go library for [theAuth](https://theauth.dev). It handles sign-in for people (passwords, magic links, social login, passkeys, TOTP, SAML SSO, SCIM provisioning) and for software (an OAuth 2.1 authorization server with PKCE, DPoP, device login, token exchange and agent identities, plus a resource server module for MCP).

It runs inside your process as an `http.Handler`. You keep your users, sessions and tokens in your own database. The root module is Go 1.25, MIT licensed, and every release is signed and ships an SBOM. The TypeScript library is [glincker/theauth](https://github.com/glincker/theauth).

**Verify it yourself.** This project is about four months old, so we point to things you can check instead of asking for trust: signed releases, test counts you can reproduce with `find`, and the exact benchmark statements we stand behind. See [docs/PROOF.md](./PROOF.md).

## Links

- [Documentation](https://docs.theauth.dev/go) and [API reference on pkg.go.dev](https://pkg.go.dev/github.com/glincker/theauth-go/v2)
- [CHANGELOG](../CHANGELOG.md), [STABILITY](https://docs.theauth.dev/go/reference/stability), [ROADMAP](./ROADMAP.md)
- [Security policy](../.github/SECURITY.md): report vulnerabilities privately to support@glinr.com or through GitHub advisories, not in public issues
- [Contributing](../.github/CONTRIBUTING.md), [Discussions](https://github.com/glincker/theauth-go/discussions), [GLINR Discord](https://discord.gg/Ar5pcaZB99)
- [AGENTS.md](./AGENTS.md) and [llms.txt](../llms.txt) for AI coding assistants
- [License: MIT](../LICENSE)

## Made by GLINCKER, a GLINR STUDIOS company

theAuth is built and maintained in the open by [GLINCKER](https://glincker.com), the open-source division of [GLINR STUDIOS](https://glinr.com). Founder: [thegdsks.com](https://thegdsks.com). The TypeScript library is [glincker/theauth](https://github.com/glincker/theauth).

| Partner project | What it is | Site | Source |
|---|---|---|---|
| **LevelRail** | Self-hosted deployment platform: push to git, get a running app. | [levelrail.com](https://levelrail.com) | [glincker/levelrail](https://github.com/glincker/levelrail) |
| **theSVG** | Open-source brand SVG icons. | [thesvg.org](https://thesvg.org) | [glincker/thesvg](https://github.com/glincker/thesvg) |
| **GLINUI** | Open-source liquid glass UI components for React. theauth.dev is designed with it. | [glinui.com](https://glinui.com) | [glincker/glinui](https://github.com/glincker/glinui) |
