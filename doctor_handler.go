package theauth

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// mountDoctor serves GET /auth/admin/doctor for callers holding the root
// ability, via session or API bearer token.
func (a *TheAuth) mountDoctor(r chi.Router, ipLimit func(http.Handler) http.Handler) {
	r.With(ipLimit, a.RequireAbility(AbilityRoot)).Get("/admin/doctor", a.handleDoctor)
}

func (a *TheAuth) handleDoctor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(a.Doctor(r.Context()))
}
