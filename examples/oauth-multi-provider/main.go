package main

import (
	"crypto/rand"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/provider/discord"
	"github.com/glincker/theauth-go/provider/github"
	"github.com/glincker/theauth-go/provider/google"
	"github.com/glincker/theauth-go/provider/microsoft"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8084")
	addr := envOr("ADDR", ":8084")

	// Encryption key for OAuth tokens at rest. In production load this
	// from a secrets manager; here we generate a random one per run.
	encKey := loadKey()

	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           baseURL,
		EncryptionKey:     encKey,
		PostLoginRedirect: "/me",
		SecureCookie:      false,
		Providers: []theauth.Provider{
			github.New(github.Config{
				ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
				ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			}),
			google.New(google.Config{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			}),
			microsoft.New(microsoft.Config{
				ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
				ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
				Tenant:       envOr("MICROSOFT_TENANT", "common"),
			}),
			discord.New(discord.Config{
				ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
				ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
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
<h1>theauth-go multi provider example</h1>
<p>Pick a provider:</p>
<ul>
  <li><a href="/auth/providers/github/start">Sign in with GitHub</a></li>
  <li><a href="/auth/providers/google/start">Sign in with Google</a></li>
  <li><a href="/auth/providers/microsoft/start">Sign in with Microsoft</a></li>
  <li><a href="/auth/providers/discord/start">Sign in with Discord</a></li>
</ul>
<p>After signing in, visit <a href="/me">/me</a>.</p>
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

func loadKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		log.Fatal(err)
	}
	return k
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
