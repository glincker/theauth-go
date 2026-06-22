// Example oauth-linkedin demonstrates Sign in with LinkedIn (OIDC via /v2/userinfo).
//
// Run:
//
//	LINKEDIN_CLIENT_ID=xxx LINKEDIN_CLIENT_SECRET=yyy go run .
//
// Then visit http://localhost:8090 and click "Sign in with LinkedIn".
//
// Prerequisites: create a LinkedIn app at https://www.linkedin.com/developers/apps.
// Add the "Sign In with LinkedIn using OpenID Connect" product to your app.
// Set authorized redirect URL to http://localhost:8090/auth/providers/linkedin/callback.
package main

import (
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/provider/linkedin"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8090")
	addr := envOr("ADDR", ":8090")

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
			linkedin.New(linkedin.Config{
				ClientID:     os.Getenv("LINKEDIN_CLIENT_ID"),
				ClientSecret: os.Getenv("LINKEDIN_CLIENT_SECRET"),
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
<h1>theauth-go LinkedIn example</h1>
<ul>
  <li><a href="/auth/providers/linkedin/start">Sign in with LinkedIn</a></li>
</ul>
</body></html>`))
	})

	authn := a.Authn()
	r.With(authn).Get("/me", func(w http.ResponseWriter, req *http.Request) {
		if u, ok := theauth.UserFromContext(req.Context()); ok {
			_, _ = w.Write([]byte("hello, " + u.Email))
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
