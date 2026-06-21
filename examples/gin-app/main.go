package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8081")
	addr := envOr("ADDR", ":8081")

	a, err := theauth.New(theauth.Config{
		Storage:      memory.New(),
		BaseURL:      baseURL,
		SecureCookie: false,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	// theauth-go's Mount writes onto a chi.Router. Mount the auth subroutes
	// onto a dedicated chi router, then wrap the resulting handler so the
	// gin engine can serve it under /auth/*.
	authRouter := chi.NewRouter()
	a.Mount(authRouter)

	r := gin.Default()
	r.Any("/auth/*any", gin.WrapH(authRouter))
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "open /auth/me after signing in via /auth/magic-link")
	})

	// /me passes through the theauth Authn middleware and returns the user.
	authn := a.Authn()
	r.GET("/me", gin.WrapH(authn(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, ok := theauth.UserFromContext(req.Context()); ok {
			_, _ = w.Write([]byte("hello, " + u.Email))
			return
		}
		http.Error(w, "anonymous", http.StatusUnauthorized)
	}))))

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
