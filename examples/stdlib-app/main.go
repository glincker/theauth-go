package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8083")
	addr := envOr("ADDR", ":8083")

	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      baseURL,
		SecureCookie: false,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// theauth-go's Mount writes onto a chi.Router. Mount onto a chi
	// subrouter and then expose it under /auth/ via a plain
	// http.ServeMux. The point of this example is that no framework is
	// required: chi is only used to satisfy the Mount signature.
	authRouter := chi.NewRouter()
	a.Mount(authRouter)

	mux := http.NewServeMux()
	mux.Handle("/auth/", authRouter)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("open /auth/me after signing in via /auth/magic-link"))
	})

	authn := a.Authn()
	mux.Handle("GET /me", authn(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, ok := theauth.UserFromContext(req.Context()); ok {
			_, _ = w.Write([]byte("hello, " + u.Email))
			return
		}
		http.Error(w, "anonymous", http.StatusUnauthorized)
	})))

	slog.Info("listening", "addr", addr, "baseURL", baseURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
