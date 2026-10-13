package cimd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

const authMethodDocID = "https://app.example.com/client.json"

func authMethodDoc(extra string) []byte {
	return []byte(fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://app.example.com/cb"]%s}`, authMethodDocID, extra))
}

func TestParseAndValidateAuthMethodAllowlist(t *testing.T) {
	const inlineJWKS = `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`
	tests := []struct {
		name    string
		extra   string
		wantErr bool
		method  string
	}{
		{"omitted defaults to none", ``, false, "none"},
		{"none", `,"token_endpoint_auth_method":"none"`, false, "none"},
		{"private_key_jwt inline jwks", `,"token_endpoint_auth_method":"private_key_jwt","jwks":` + inlineJWKS, false, "private_key_jwt"},
		{"private_key_jwt jwks_uri", `,"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://app.example.com/jwks.json"`, false, "private_key_jwt"},
		{"private_key_jwt no keys", `,"token_endpoint_auth_method":"private_key_jwt"`, true, ""},
		{"private_key_jwt both", `,"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://app.example.com/jwks.json","jwks":` + inlineJWKS, true, ""},
		{"private_key_jwt http jwks_uri", `,"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"http://app.example.com/jwks.json"`, true, ""},
		{"private_key_jwt empty key set", `,"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[]}`, true, ""},
		{"client_secret_basic", `,"token_endpoint_auth_method":"client_secret_basic"`, true, ""},
		{"client_secret_post", `,"token_endpoint_auth_method":"client_secret_post"`, true, ""},
		{"client_secret_jwt", `,"token_endpoint_auth_method":"client_secret_jwt"`, true, ""},
		{"unknown method", `,"token_endpoint_auth_method":"tls_client_auth"`, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parseAndValidate(authMethodDoc(tc.extra), authMethodDocID)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidDocument) {
					t.Fatalf("err = %v, want ErrInvalidDocument", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAndValidate: %v", err)
			}
			if doc.TokenEndpointAuthMethod != tc.method {
				t.Fatalf("method = %q, want %q", doc.TokenEndpointAuthMethod, tc.method)
			}
		})
	}
}

func TestParseAndValidateIgnoresUnknownFields(t *testing.T) {
	raw := authMethodDoc(`,"dpop_bound_access_tokens":true,"x_vendor":{"nested":[1,2]},"client_uri":"https://app.example.com","frobnicate":"yes"`)
	doc, err := parseAndValidate(raw, authMethodDocID)
	if err != nil {
		t.Fatalf("unknown fields must be tolerated: %v", err)
	}
	if doc.ClientID != authMethodDocID || doc.ClientURI != "https://app.example.com" {
		t.Fatalf("known fields lost: %+v", doc)
	}
}

func TestResolvePrivateKeyJWTCopiesJWKS(t *testing.T) {
	t.Parallel()
	ts := newTestServer(t, nil)
	ts.setHandler(serveDoc(map[string]any{
		"client_id":                  ts.URL(),
		"redirect_uris":              []string{"https://example.org/cb"},
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks_uri":                   "https://example.org/jwks.json",
	}))
	svc := NewService(Config{TrustPolicy: AllowAnyHTTPS(), HTTPClient: trustingClient(2 * time.Second)}, nil)
	got, err := svc.Resolve(context.Background(), ts.URL())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.JwksURI != "https://example.org/jwks.json" || got.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Fatalf("client = %+v", got)
	}
}

func TestCacheControlTTL(t *testing.T) {
	s := NewService(Config{CacheTTL: time.Hour, HonorCacheControl: true}, nil)
	tests := []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"public", 0},
		{"max-age=60", time.Minute},
		{"public, max-age=120", 2 * time.Minute},
		{"max-age=999999", time.Hour},
		{"max-age=0", MinCacheTTL},
		{"no-store", MinCacheTTL},
		{"no-cache, max-age=600", MinCacheTTL},
		{"max-age=abc", 0},
		{"max-age=-5", 0},
	}
	for _, tc := range tests {
		if got := s.cacheControlTTL(tc.header); got != tc.want {
			t.Errorf("cacheControlTTL(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

func TestResolveHonorsCacheControl(t *testing.T) {
	t.Parallel()
	for _, honor := range []bool{false, true} {
		t.Run(fmt.Sprintf("honor=%v", honor), func(t *testing.T) {
			t.Parallel()
			ts := newTestServer(t, nil)
			ts.setHandler(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "max-age=0")
				serveDoc(Document{ClientID: ts.URL(), RedirectURIs: []string{"https://example.org/cb"}})(w, r)
			})
			svc := NewService(Config{
				TrustPolicy:       AllowAnyHTTPS(),
				HTTPClient:        trustingClient(2 * time.Second),
				HonorCacheControl: honor,
			}, nil)
			for i := 0; i < 2; i++ {
				if _, err := svc.Resolve(context.Background(), ts.URL()); err != nil {
					t.Fatalf("Resolve: %v", err)
				}
			}
			// max-age=0 clamps to MinCacheTTL (10s), so a second call inside
			// that window is still a cache hit either way.
			if got := ts.hits.Load(); got != 1 {
				t.Fatalf("hits = %d, want 1", got)
			}
			v, ok := svc.cache.Load(cacheKey(ts.URL()))
			if !ok {
				t.Fatal("entry not cached")
			}
			entry, _ := v.(*cacheEntry)
			want := time.Duration(0)
			if honor {
				want = MinCacheTTL
			}
			if entry == nil || entry.ttl != want {
				t.Fatalf("entry ttl = %v, want %v", entry, want)
			}
		})
	}
}
