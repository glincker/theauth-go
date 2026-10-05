// Command single-binary-sqlite is a complete app with auth: one static binary, one SQLite file.
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	a, err := newApp(ctx, options{
		baseURL:      envOr("BASE_URL", "http://localhost:8080"),
		dbPath:       envOr("DB_PATH", "app.db"),
		setupToken:   os.Getenv("SETUP_TOKEN"),
		pollInterval: 5 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.close()

	srv := &http.Server{Addr: envOr("ADDR", ":8080"), Handler: a.handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	slog.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
