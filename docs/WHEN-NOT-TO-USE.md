# When not to use theauth-go

I would rather you pick the right tool than a wrong one from me. theauth-go is young (first commit 2026-06-20) and has one maintainer, so for several jobs something older is the safer choice. Facts about other projects come from their own READMEs and the GitHub API, read on 2026-10-31, and are listed under Sources. I state what those pages say and nothing more. Check them before you decide, because they change.

## Pick something else if

**You want a low-level OAuth 2.0 or OpenID Connect server toolkit with a long track record.** Look at [ory/fosite](https://github.com/ory/fosite). Its README calls it "the security first OAuth2 & OpenID Connect framework for Go" and it has been around since 2015. Its README also says the core API is "almost stable". Its RFC list there names PAR (RFC 9126) but not DPoP, RFC 9728 or CIMD, so if you need those, check its docs. theauth-go adds sign-in, sessions and agent identity on top of the server, which you may not want.

**You need an OpenID-certified relying party or provider library.** Look at [zitadel/oidc](https://github.com/zitadel/oidc). Its README says the RP is certified for the basic and config profiles and describes a client (RP) and server (OP) implementation. I have no OpenID certification to point to.

**You need just "Sign in with X" in a Go web app.** Look at [goth](https://github.com/markbates/goth). Its README describes a way to write authentication packages for Go web apps and lists a long set of providers. It does one job. theauth-go also ships users, sessions and an authorization server, which is more surface than you need for social login alone.

**You want a modular, web-focused auth system with a long history.** Look at [authboss](https://github.com/aarondl/authboss). Its README describes a "modular authentication system for the web" where you enable the modules you need. The repository dates from 2015-01.

**You want a separate identity service with an admin UI, not a library.** Look at [Keycloak](https://github.com/keycloak/keycloak) or the Ory projects. Keycloak's README describes identity and access management with user federation, strong authentication and user management. [Ory Hydra](https://github.com/ory/hydra) describes itself as an OpenID Certified OAuth 2.0 server and OpenID Connect provider that connects to your identity provider through a login and consent app, and [Ory Kratos](https://github.com/ory/kratos) as an API first identity and user management system. theauth-go is a library, not a separate service, and has no hosted login UI.

**You need a vendor you can call.** theauth-go is MIT licensed with community support through GitHub Discussions. There is no support contract.

## Where theauth-go does fit

You want the authorization server inside your own Go process and database, for MCP clients and agents (RFC 9728 metadata, CIMD, DPoP, agent delegation), and you also want ordinary sign-in from the same module. Levelrail, another product I build, imports it, pinned at v2.12.0.

## Known limits of this project

- Age: the first commit is 2026-06-20, and the repo had 8 stars on 2026-10-31.
- Maintainers: two contributors on GitHub, one of them Dependabot.
- Coverage: Codecov reported 45.69 percent on 2026-10-31.
- No OpenID certification and no independent security audit.
- Parts of the code were built with AI assistance. See the README note.
- Postgres and MySQL pass the new storage suites, but the full shared contract suite still fails on constraint edge cases. See [ROADMAP](./ROADMAP.md).
- Several areas are Experimental. See the status table in the [README](../README.md#status).

## Snapshot

| Project | Stars | Created | What its README says |
|---|---|---|---|
| theauth-go | 8 | 2026-06 | n/a |
| [ory/fosite](https://github.com/ory/fosite) | 2,631 | 2015-12 | Security first OAuth2 and OpenID Connect framework for Go |
| [zitadel/oidc](https://github.com/zitadel/oidc) | 1,919 | 2019-11 | Client (RP) and server (OP) OIDC implementation for Go |
| [markbates/goth](https://github.com/markbates/goth) | 6,620 | 2014-10 | Authentication packages for Go web applications |
| [aarondl/authboss](https://github.com/aarondl/authboss) | 4,201 | 2015-01 | Modular authentication system for the web |
| [ory/hydra](https://github.com/ory/hydra) | 17,640 | n/a | OAuth 2.0 server and OpenID Connect provider |
| [keycloak/keycloak](https://github.com/keycloak/keycloak) | 37,621 | n/a | Identity and access management |

Stars are a size signal, not a quality ranking.

## Sources

All read on 2026-10-31.

- README text: `gh api repos/<owner>/<repo>/readme` for ory/fosite, zitadel/oidc, markbates/goth, aarondl/authboss, ory/hydra, ory/kratos and keycloak/keycloak.
- Stars, creation date: `gh api repos/<owner>/<repo>` for each repo above.
- theauth-go coverage: `https://api.codecov.io/api/v2/github/glincker/repos/theauth-go`, `totals.coverage`.
- Contributor count: `gh api repos/glincker/theauth-go/contributors`.
