// Package theauth is auth for AI agents and humans in Go. It embeds into a
// net/http or chi server and keeps all data in your own database (memory,
// SQLite, Postgres or MySQL).
//
// For agents it provides an OAuth 2.1 authorization server (PKCE-mandatory
// authorization code, client_credentials, refresh token rotation, RFC 8693
// token exchange, CIBA, PAR, JAR, DPoP-bound tokens), MCP authorization with
// RFC 9728 protected resource metadata, and agent identities with revocable
// delegation chains. Per-client token policy, RFC 9396 rich authorization
// requests and ID-JAG are supported on top of token exchange.
//
// For humans it provides email and password, magic links, email and SMS
// one-time codes, WebAuthn passkeys, TOTP, OAuth and OIDC login providers,
// RFC 8628 device login for CLIs, SAML SSO, SCIM, organizations with RBAC,
// and an async audit log.
//
// Quick start:
//
//	a, err := theauth.New(theauth.Config{Storage: memory.New(), BaseURL: "http://localhost:8080"})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer a.Close()
//	mux := http.NewServeMux()
//	mux.Handle("/auth/", a.Handler())
//
// Here memory is github.com/glincker/theauth-go/v2/storage/memory. See
// docs/AGENTS.md or https://docs.theauth.dev/go for the full feature list
// and guides.
package theauth
