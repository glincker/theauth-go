// doctor-admin serves /healthz publicly and a root-only /admin/security page
// that renders the theauth-go security report next to it.
package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/glincker/theauth-go"
	"github.com/glincker/theauth-go/storage/memory"
	"github.com/go-chi/chi/v5"
)

var page = template.Must(template.New("p").Parse(`<!doctype html><title>Security</title>
<h1>Security posture</h1>
<table border=1 cellpadding=4>
{{range .Findings}}<tr><td>{{.Severity}}</td><td>{{.ID}}</td><td>{{.Title}}<br><small>{{.Remediation}}</small></td></tr>
{{else}}<tr><td>No findings</td></tr>{{end}}
</table>`))

func main() {
	a, err := theauth.New(theauth.Config{
		Storage:    memory.New(),
		BaseURL:    envOr("BASE_URL", "http://localhost:8080"),
		APITokens:  &theauth.APITokensConfig{},
		Bootstrap:  &theauth.BootstrapConfig{},
		SessionTTL: 24 * time.Hour,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	r.With(a.RequireAbility(theauth.AbilityRoot)).Get("/admin/security", func(w http.ResponseWriter, req *http.Request) {
		if err := page.Execute(w, a.Doctor(req.Context())); err != nil {
			http.Error(w, "render failed", http.StatusInternalServerError)
		}
	})
	log.Fatal(http.ListenAndServe(":8080", r))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
