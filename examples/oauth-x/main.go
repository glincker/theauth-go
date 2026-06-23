// Example oauth-x demonstrates Sign in with X (formerly Twitter) using
// OAuth 2.0 with PKCE. PKCE is mandatory for all X OAuth 2.0 flows.
//
// Note: X does not expose email via the standard /2/users/me endpoint
// without elevated API access. This example shows the user's display name.
//
// Run:
//
//	X_CLIENT_ID=xxx X_CLIENT_SECRET=yyy go run .
//
// For public client apps (no client secret), set X_CLIENT_SECRET to empty.
//
// Then visit http://localhost:8091 and click "Sign in with X".
//
// Prerequisites: create a project and app at https://developer.x.com/en/portal.
// Set the callback URL to http://localhost:8091/auth/providers/x/callback.
// Enable OAuth 2.0 under User authentication settings. PKCE must be enabled.
package main

import (
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	xprov "github.com/glincker/theauth-go/provider/x"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8091")
	addr := envOr("ADDR", ":8091")

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		log.Fatal(err)
	}

	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           baseURL,
		EncryptionKey:     encKey,
		PostLoginRedirect: "/me",
		SecureCookie:      false,
		Providers: []theauth.Provider{
			xprov.New(xprov.Config{
				ClientID:     os.Getenv("X_CLIENT_ID"),
				ClientSecret: os.Getenv("X_CLIENT_SECRET"), // may be empty for public clients
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)

	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body>
<h1>theauth-go X (Twitter) example</h1>
<p>Note: PKCE is mandatory for X OAuth 2.0 flows.</p>
<ul>
  <li><a href="/auth/providers/x/start">Sign in with X</a></li>
</ul>
</body></html>`))
	})

	authn := a.Authn()
	r.With(authn).Get("/me", func(w http.ResponseWriter, req *http.Request) {
		if u, ok := theauth.UserFromContext(req.Context()); ok {
			name := u.Name
			if name == "" {
				name = u.ID
			}
			_, _ = w.Write([]byte("hello, @" + name))
			return
		}
		http.Error(w, "anonymous", http.StatusUnauthorized)
	})

	slog.Info("listening", "addr", addr, "baseURL", baseURL)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
