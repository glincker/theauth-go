package handlers_test

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
	"github.com/glincker/theauth-go/v2/internal/as/handlers"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

func newDeviceAdminServer(t *testing.T, enable bool) (string, *memory.Store) {
	t.Helper()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cfg := internalas.Config{
		Issuer:          "https://auth.example.com",
		Resources:       []models.ProtectedResource{{Identifier: "https://iot.example.com/api"}},
		DisableRotation: true,
	}
	if enable {
		cfg.DeviceTokens = &internalas.DeviceTokensConfig{}
	}
	if err := internalas.Validate(&cfg, key); err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	svc := internalas.New(internalas.Deps{Cfg: cfg, Storage: store, EncryptionKey: key})
	admin := handlers.NewAdmin(svc, func(*http.Request) (*models.User, bool) {
		return &models.User{ID: ulid.New()}, true
	})
	gate := func(string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler { return next }
	}
	r := chi.NewRouter()
	r.Route("/admin/v1/organizations/{orgID}", func(r chi.Router) { admin.Mount(r, gate) })
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv.URL + "/admin/v1/organizations/", store
}

func TestDeviceAdminAPI(t *testing.T) {
	base, store := newDeviceAdminServer(t, true)
	org := ulid.New().String()
	orgURL := base + org

	code, created, raw := call(t, http.MethodPost, orgURL+"/devices/join-tokens",
		`{"name":"gate sensor","spiffe_id":"spiffe://example.org/gate","scopes":["telemetry:write"],"ttl_seconds":600}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	secret, _ := created["token"].(string)
	tokenID, _ := created["id"].(string)
	if !strings.HasPrefix(secret, "dj_") || tokenID == "" || created["spiffe_id"] != "spiffe://example.org/gate" {
		t.Fatalf("create body: %v", created)
	}

	t.Run("bad input is a 400", func(t *testing.T) {
		for _, body := range []string{`{"name":"x"}`, `{"scopes":["a"],"ttl_seconds":-1}`, `not json`} {
			if code, _, _ := call(t, http.MethodPost, orgURL+"/devices/join-tokens", body); code != http.StatusBadRequest {
				t.Errorf("%s: status %d", body, code)
			}
		}
	})

	t.Run("join token revoke is scoped to the organization", func(t *testing.T) {
		other := base + ulid.New().String()
		if code, _, _ := call(t, http.MethodDelete, other+"/devices/join-tokens/"+tokenID, ""); code != http.StatusNotFound {
			t.Fatalf("another org revoked our token: %d", code)
		}
		if code, _, _ := call(t, http.MethodDelete, orgURL+"/devices/join-tokens/"+tokenID, ""); code != http.StatusNoContent {
			t.Fatalf("revoke: %d", code)
		}
		if code, _, _ := call(t, http.MethodDelete, orgURL+"/devices/join-tokens/"+ulid.New().String(), ""); code != http.StatusNotFound {
			t.Fatalf("unknown token: %d", code)
		}
	})

	t.Run("list and revoke devices", func(t *testing.T) {
		var orgID models.ULID
		if err := orgID.UnmarshalText([]byte(org)); err != nil {
			t.Fatal(err)
		}
		dev := models.Device{
			ID: ulid.New(), OrganizationID: &orgID, Name: "gate sensor", SPIFFEID: "spiffe://example.org/gate",
			PublicKeyJWK: []byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`), KeyThumbprint: "tp",
			Attestation: models.DeviceAttestationJoinToken, Scopes: []string{"telemetry:write"},
			Status: models.DeviceStatusActive, CreatedAt: time.Now(),
		}
		if err := store.InsertDevice(t.Context(), dev); err != nil {
			t.Fatal(err)
		}
		code, list, raw := call(t, http.MethodGet, orgURL+"/devices", "")
		rows, _ := list["data"].([]any)
		if code != http.StatusOK || len(rows) != 1 || strings.Contains(raw, "public_key") {
			t.Fatalf("list: %d %s", code, raw)
		}
		other := base + ulid.New().String()
		if code, _, _ := call(t, http.MethodPost, other+"/devices/"+dev.ID.String()+"/revoke", ""); code != http.StatusNotFound {
			t.Fatalf("another org revoked our device: %d", code)
		}
		if code, _, _ := call(t, http.MethodPost, orgURL+"/devices/"+dev.ID.String()+"/revoke", ""); code != http.StatusNoContent {
			t.Fatalf("revoke: %d", code)
		}
		got, _ := store.DeviceByID(t.Context(), dev.ID)
		if got.Active() {
			t.Fatalf("device still active: %+v", got)
		}
	})
}

func TestDeviceAdminRoutesAbsentWhenDisabled(t *testing.T) {
	base, _ := newDeviceAdminServer(t, false)
	code, _, _ := call(t, http.MethodGet, base+ulid.New().String()+"/devices", "")
	if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want the routes unmounted", code)
	}
}

func TestDeviceAdminSuspendResumeAndTokenKinds(t *testing.T) {
	base, store := newDeviceAdminServer(t, true)
	org := ulid.New().String()
	orgURL := base + org

	t.Run("claim and bulk tokens", func(t *testing.T) {
		code, claim, raw := call(t, http.MethodPost, orgURL+"/devices/join-tokens",
			`{"kind":"claim","scopes":["telemetry:write"]}`)
		secret, _ := claim["token"].(string)
		if code != http.StatusCreated || len(secret) != 11 || secret[5] != '-' || claim["kind"] != "claim" || claim["max_uses"] != float64(1) {
			t.Fatalf("claim: %d %s", code, raw)
		}
		code, bulk, raw := call(t, http.MethodPost, orgURL+"/devices/join-tokens",
			`{"kind":"bulk","max_uses":50,"scopes":["telemetry:write"],"ttl_seconds":3600}`)
		if code != http.StatusCreated || !strings.HasPrefix(bulk["token"].(string), "dj_") || bulk["max_uses"] != float64(50) {
			t.Fatalf("bulk: %d %s", code, raw)
		}
		for _, body := range []string{
			`{"kind":"bulk","scopes":["a"]}`,
			`{"kind":"bulk","max_uses":2,"spiffe_id":"spiffe://example.org/x","scopes":["a"]}`,
			`{"kind":"claim","max_uses":3,"scopes":["a"]}`,
			`{"kind":"nope","scopes":["a"]}`,
			`{"kind":"claim","scopes":["a"],"ttl_seconds":99999999}`,
		} {
			if code, _, _ := call(t, http.MethodPost, orgURL+"/devices/join-tokens", body); code != http.StatusBadRequest {
				t.Errorf("%s: status %d, want 400", body, code)
			}
		}
	})

	t.Run("suspend and resume", func(t *testing.T) {
		var orgID models.ULID
		if err := orgID.UnmarshalText([]byte(org)); err != nil {
			t.Fatal(err)
		}
		dev := models.Device{
			ID: ulid.New(), OrganizationID: &orgID, Name: "door", PublicKeyJWK: []byte(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`),
			KeyThumbprint: "tp2", Attestation: models.DeviceAttestationJoinToken, Scopes: []string{"telemetry:write"},
			Status: models.DeviceStatusActive, CreatedAt: time.Now(),
		}
		if err := store.InsertDevice(t.Context(), dev); err != nil {
			t.Fatal(err)
		}
		path := "/devices/" + dev.ID.String()
		other := base + ulid.New().String()
		if code, _, _ := call(t, http.MethodPost, other+path+"/suspend", ""); code != http.StatusNotFound {
			t.Fatalf("another org suspended our device: %d", code)
		}
		if code, _, _ := call(t, http.MethodPost, orgURL+path+"/suspend", ""); code != http.StatusNoContent {
			t.Fatalf("suspend: %d", code)
		}
		if code, _, _ := call(t, http.MethodPost, orgURL+path+"/suspend", ""); code != http.StatusNoContent {
			t.Fatalf("suspend twice: %d", code)
		}
		if got, _ := store.DeviceByID(t.Context(), dev.ID); got.Status != models.DeviceStatusSuspended {
			t.Fatalf("after suspend: %+v", got)
		}
		_, list, _ := call(t, http.MethodGet, orgURL+"/devices", "")
		if rows, _ := list["data"].([]any); len(rows) != 1 || rows[0].(map[string]any)["status"] != "suspended" {
			t.Fatalf("list shows %v", list)
		}
		if code, _, _ := call(t, http.MethodPost, orgURL+path+"/resume", ""); code != http.StatusNoContent {
			t.Fatalf("resume: %d", code)
		}
		if got, _ := store.DeviceByID(t.Context(), dev.ID); !got.Active() {
			t.Fatalf("after resume: %+v", got)
		}
		if code, _, _ := call(t, http.MethodPost, orgURL+path+"/revoke", ""); code != http.StatusNoContent {
			t.Fatalf("revoke: %d", code)
		}
		for _, verb := range []string{"/resume", "/suspend"} {
			if code, _, _ := call(t, http.MethodPost, orgURL+path+verb, ""); code != http.StatusConflict {
				t.Fatalf("%s a revoked device: %d, want 409", verb, code)
			}
		}
		if code, _, _ := call(t, http.MethodPost, orgURL+"/devices/"+ulid.New().String()+"/suspend", ""); code != http.StatusNotFound {
			t.Fatalf("unknown device: %d", code)
		}
	})
}
