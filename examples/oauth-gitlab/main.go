// Example oauth-gitlab demonstrates Sign in with GitLab (OIDC).
//
// Run (gitlab.com):
//
//	GITLAB_CLIENT_ID=xxx GITLAB_CLIENT_SECRET=yyy go run .
//
// Self-hosted GitLab:
//
//	GITLAB_BASE_URL=https://git.example.com GITLAB_CLIENT_ID=xxx GITLAB_CLIENT_SECRET=yyy go run .
//
// Then visit http://localhost:8087 and click "Sign in with GitLab".
//
// Prerequisites: create an OAuth application in your GitLab instance under
// User Settings > Applications. Set redirect URI to
// http://localhost:8087/auth/providers/gitlab/callback.
// Required scopes: openid, email, profile.
package main

import (
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/provider/gitlab"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8087")
	addr := envOr("ADDR", ":8087")

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
			gitlab.New(gitlab.Config{
				ClientID:     os.Getenv("GITLAB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITLAB_CLIENT_SECRET"),
				BaseURL:      os.Getenv("GITLAB_BASE_URL"), // empty = gitlab.com
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
<h1>theauth-go GitLab example</h1>
<ul>
  <li><a href="/auth/providers/gitlab/start">Sign in with GitLab</a></li>
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
