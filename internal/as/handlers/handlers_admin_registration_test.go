package handlers_test

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/as/handlers"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

func newAdminServer(t *testing.T) (*httptest.Server, string, *internalas.Service) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg := internalas.Config{
		Issuer:          "https://auth.example.com",
		Resources:       []models.ProtectedResource{{Identifier: "https://files.example.com/mcp"}},
		DisableRotation: true,
	}
	if err := internalas.Validate(&cfg, key); err != nil {
		t.Fatal(err)
	}
	svc := internalas.New(internalas.Deps{Cfg: cfg, Storage: memory.New(), EncryptionKey: key})
	admin := handlers.NewAdmin(svc, func(*http.Request) (*models.User, bool) {
		return &models.User{ID: ulid.New()}, true
	})
	var gated []string
	gate := func(perm string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			gated = append(gated, perm)
			return next
		}
	}
	r := chi.NewRouter()
	r.Route("/admin/v1/organizations/{orgID}", func(r chi.Router) { admin.Mount(r, gate) })
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	if len(gated) == 0 || gated[0] != models.PermissionAgentsAdmin {
		t.Fatalf("routes must sit behind %s, gated: %v", models.PermissionAgentsAdmin, gated)
	}
	return srv, srv.URL + "/admin/v1/organizations/" + ulid.New().String() + "/registration-tokens", svc
}

func call(t *testing.T, method, url, body string) (int, map[string]any, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var m map[string]any
	var raw strings.Builder
	dec := json.NewDecoder(resp.Body)
	_ = dec.Decode(&m)
	b, _ := json.Marshal(m)
	raw.Write(b)
	return resp.StatusCode, m, raw.String()
}

func TestRegistrationTokenAdminAPI(t *testing.T) {
	_, base, _ := newAdminServer(t)

	code, created, _ := call(t, http.MethodPost, base, `{"label":"agent fleet","scopes":["files.read"],"grant_types":["client_credentials"],"max_uses":2,"ttl_seconds":3600}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, created)
	}
	token, _ := created["token"].(string)
	id, _ := created["id"].(string)
	if !strings.HasPrefix(token, "rt_") || id == "" || created["max_uses"] != float64(2) || created["active"] != true {
		t.Fatalf("create body: %v", created)
	}

	t.Run("list is scoped to the organization and hides the secret", func(t *testing.T) {
		code, list, raw := call(t, http.MethodGet, base, "")
		data, _ := list["data"].([]any)
		if code != http.StatusOK || len(data) != 1 || strings.Contains(raw, token) {
			t.Fatalf("own org: %d %s", code, raw)
		}
		otherOrg := base[:strings.Index(base, "/organizations/")] + "/organizations/" + ulid.New().String() + "/registration-tokens"
		_, other, _ := call(t, http.MethodGet, otherOrg, "")
		if rows, _ := other["data"].([]any); len(rows) != 0 {
			t.Fatalf("another org sees %d tokens", len(rows))
		}
		if code, _, _ := call(t, http.MethodDelete, otherOrg+"/"+id, ""); code != http.StatusNotFound {
			t.Fatalf("another org revoked our token: %d", code)
		}
	})

	t.Run("bad input is a 400", func(t *testing.T) {
		for _, body := range []string{`{"max_uses":-3}`, `{"grant_types":["password"]}`, `{"ttl_seconds":-5}`, `not json`} {
			if code, _, _ := call(t, http.MethodPost, base, body); code != http.StatusBadRequest {
				t.Errorf("%s: status %d", body, code)
			}
		}
	})

	t.Run("revoking an unknown token is a 404", func(t *testing.T) {
		if code, _, _ := call(t, http.MethodDelete, base+"/"+ulid.New().String(), ""); code != http.StatusNotFound {
			t.Fatalf("status %d", code)
		}
	})
}

func TestRegistrationTokenAdminLifecycleWithinOneOrg(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	base := srv.URL + "/admin/v1/organizations/" + ulid.New().String() + "/registration-tokens"

	code, created, _ := call(t, http.MethodPost, base, `{"label":"one"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	id := created["id"].(string)
	secret := created["token"].(string)

	code, list, raw := call(t, http.MethodGet, base, "")
	data, _ := list["data"].([]any)
	if code != http.StatusOK || len(data) != 1 {
		t.Fatalf("list: %d %s", code, raw)
	}
	if strings.Contains(raw, secret) || strings.Contains(raw, "token_hash") {
		t.Fatalf("list leaks secret material: %s", raw)
	}
	if code, _, _ := call(t, http.MethodDelete, base+"/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	_, list, _ = call(t, http.MethodGet, base, "")
	row := list["data"].([]any)[0].(map[string]any)
	if row["active"] != false || row["revoked_at"] == nil {
		t.Fatalf("not revoked: %v", row)
	}
}
