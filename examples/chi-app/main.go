package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/glincker/theauth-go/storage/postgres"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8080")
	dbURL := os.Getenv("DATABASE_URL")

	a, err := theauth.New(theauth.Config{
		Storage:      newStorage(dbURL),
		BaseURL:      baseURL,
		SecureCookie: false, // localhost
	})
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	a.Mount(r)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>
			<h1>TheAuth Example</h1>
			<form id="f">
				<input name="email" placeholder="you@example.com" required>
				<button type="submit">Send magic link</button>
			</form>
			<script>
				document.getElementById('f').addEventListener('submit', async (e) => {
					e.preventDefault();
					const email = e.target.email.value;
					const res = await fetch('/auth/magic-link', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ email })
					});
					alert(res.ok ? 'Check your console (noop email sender prints the link)' : 'Error');
				});
			</script>
			<p><a href="/auth/me">/auth/me</a></p>
		</body></html>`))
	})

	slog.Info("listening", "addr", ":8080", "baseURL", baseURL)
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

// newStorage returns either an in-memory or Postgres storage backend.
// Returns theauth.Storage (the interface) so both implementations work.
func newStorage(dbURL string) theauth.Storage {
	if dbURL == "" {
		slog.Info("using in-memory storage (set DATABASE_URL to use Postgres)")
		return memory.New()
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatal(err)
	}
	return postgres.New(pool)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
