package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
	"github.com/labstack/echo/v4"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8082")
	addr := envOr("ADDR", ":8082")

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
	// subrouter, then expose it through echo.WrapHandler.
	authRouter := chi.NewRouter()
	a.Mount(authRouter)

	e := echo.New()
	e.HideBanner = true
	e.Any("/auth/*", echo.WrapHandler(authRouter))
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "open /auth/me after signing in via /auth/magic-link")
	})

	authn := a.Authn()
	e.GET("/me", echo.WrapHandler(authn(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if u, ok := theauth.UserFromContext(req.Context()); ok {
			_, _ = w.Write([]byte("hello, " + u.Email))
			return
		}
		http.Error(w, "anonymous", http.StatusUnauthorized)
	}))))

	slog.Info("listening", "addr", addr, "baseURL", baseURL)
	if err := e.Start(addr); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
