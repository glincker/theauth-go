// Command oauth-x shows Sign in with X (formerly Twitter) via OAuth 2.0 with PKCE, which X requires.
// X does not expose email on /2/users/me without elevated access, so this shows the display name.
// Run: X_CLIENT_ID=xxx X_CLIENT_SECRET=yyy go run . (leave the secret empty for public clients),
// then open http://localhost:8091. The X app needs callback http://localhost:8091/auth/providers/x/callback.
package main

import (
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go/v2"
	xprov "github.com/glincker/theauth-go/v2/provider/x"
	"github.com/glincker/theauth-go/v2/storage/memory"
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
				name = u.ID.String()
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
