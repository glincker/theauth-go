// Package theauth is auth for AI agents and humans in Go. It embeds into a net/http or chi server and keeps all data in
// your own database (memory, SQLite, Postgres or MySQL). It provides an OAuth 2.1 authorization server with agent identities
// and delegation, and human login with passwords, passkeys, TOTP, OAuth, SAML, SCIM and RBAC.
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
// See docs/AGENTS.md or https://docs.theauth.dev/go for the full feature list.
package theauth
