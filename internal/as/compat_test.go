package as

import (
	"errors"
	"reflect"
	"testing"

	"github.com/glincker/theauth-go/v2/internal/models"
)

// compat_test.go: unit vectors for Config.ClientCompat. The tables are
// deliberately plain data so the TypeScript library can mirror them.

const (
	compatRes  = "https://files.example.com/mcp"
	compatRes2 = "https://notes.example.com/mcp"
)

func compatSvc(c ClientCompat, resources ...string) *Service {
	var rs []models.ProtectedResource
	for _, id := range resources {
		rs = append(rs, models.ProtectedResource{Identifier: id, Scopes: []string{"files.read", "files.write"}})
	}
	return &Service{Cfg: Config{Resources: rs, ClientCompat: c}}
}

func TestCompatResolveResource(t *testing.T) {
	tests := []struct {
		name      string
		compat    ClientCompat
		resources []string
		raw       string
		wantAud   string
		wantErr   bool
	}{
		{"strict exact", ClientCompat{}, []string{compatRes}, compatRes, compatRes, false},
		{"strict trailing slash keeps caller spelling", ClientCompat{}, []string{compatRes}, compatRes + "/", compatRes + "/", false},
		{"strict absent", ClientCompat{}, []string{compatRes}, "", "", true},
		{"strict sub path", ClientCompat{}, []string{compatRes}, compatRes + "/sse", "", true},
		{"optional absent single", ClientCompat{OptionalResource: true}, []string{compatRes}, "", compatRes, false},
		{"optional absent several", ClientCompat{OptionalResource: true}, []string{compatRes, compatRes2}, "", "", true},
		{"optional unknown still rejected", ClientCompat{OptionalResource: true}, []string{compatRes}, "https://evil.example.com/mcp", "", true},
		{"path audience sub path", ClientCompat{PathAudience: true}, []string{compatRes}, compatRes + "/sse", compatRes, false},
		{"path audience deep sub path", ClientCompat{PathAudience: true}, []string{compatRes}, compatRes + "/v1/tools/", compatRes, false},
		{"path audience sibling prefix", ClientCompat{PathAudience: true}, []string{compatRes}, compatRes + "-admin", "", true},
		{"path audience other host", ClientCompat{PathAudience: true}, []string{compatRes}, "https://files.example.com.evil.test/mcp/x", "", true},
		{"path audience dot dot", ClientCompat{PathAudience: true}, []string{compatRes}, compatRes + "/../admin", "", true},
		{"path audience encoded dot", ClientCompat{PathAudience: true}, []string{compatRes}, compatRes + "/%2e%2e/admin", "", true},
		{"path audience query", ClientCompat{PathAudience: true}, []string{compatRes}, compatRes + "/sse?x=1", "", true},
		{"path audience fragment", ClientCompat{PathAudience: true}, []string{compatRes}, compatRes + "/sse#f", "", true},
		{"path audience picks longest", ClientCompat{PathAudience: true}, []string{"https://files.example.com", compatRes}, compatRes + "/sse", compatRes, false},
		{"path audience off by default", ClientCompat{OptionalResource: true}, []string{compatRes}, compatRes + "/sse", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, aud, err := compatSvc(tc.compat, tc.resources...).resolveResource(tc.raw)
			if tc.wantErr {
				if !errors.Is(err, models.ErrOAuthInvalidResource) {
					t.Fatalf("err = %v, want invalid_target", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveResource: %v", err)
			}
			if aud != tc.wantAud {
				t.Fatalf("audience = %q, want %q", aud, tc.wantAud)
			}
		})
	}
}

func TestCompatNarrowScopes(t *testing.T) {
	res := models.ProtectedResource{Identifier: compatRes, Scopes: []string{"files.read", "files.write"}}
	client := &models.OAuthClient{Scope: "files.read claudeai"}
	open := &models.OAuthClient{}
	tests := []struct {
		name    string
		compat  ClientCompat
		req     []string
		client  *models.OAuthClient
		want    []string
		wantErr error
	}{
		{"strict unknown rejected", ClientCompat{}, []string{"files.read", "claudeai"}, open, nil, models.ErrOAuthInvalidScope},
		{"drop unknown from catalog", ClientCompat{DropUnknownScopes: true}, []string{"files.read", "claudeai"}, open, []string{"files.read"}, nil},
		{"drop outside client set", ClientCompat{DropUnknownScopes: true}, []string{"files.read", "files.write"}, client, []string{"files.read"}, nil},
		{"catalog and client both exclude claudeai", ClientCompat{DropUnknownScopes: true}, []string{"claudeai"}, client, nil, models.ErrOAuthInvalidScope},
		{"nothing left", ClientCompat{DropUnknownScopes: true}, []string{"bogus", "other"}, open, nil, models.ErrOAuthInvalidScope},
		{"order preserved", ClientCompat{DropUnknownScopes: true}, []string{"files.write", "x", "files.read"}, open, []string{"files.write", "files.read"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compatSvc(tc.compat, compatRes).narrowScopes(tc.req, res, tc.client)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("narrowScopes: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("scope = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompatNarrowRefreshScopes(t *testing.T) {
	granted := []string{"files.read", "files.write"}
	strict := compatSvc(ClientCompat{}, compatRes)
	lenient := compatSvc(ClientCompat{DropUnknownScopes: true}, compatRes)
	if got, err := strict.narrowRefreshScopes(nil, granted); err != nil || !reflect.DeepEqual(got, granted) {
		t.Fatalf("empty request = %v, %v", got, err)
	}
	if _, err := strict.narrowRefreshScopes([]string{"files.read", "admin"}, granted); !errors.Is(err, models.ErrOAuthInvalidScope) {
		t.Fatalf("strict widening err = %v", err)
	}
	got, err := lenient.narrowRefreshScopes([]string{"files.read", "admin"}, granted)
	if err != nil || !reflect.DeepEqual(got, []string{"files.read"}) {
		t.Fatalf("lenient = %v, %v", got, err)
	}
	if _, err := lenient.narrowRefreshScopes([]string{"admin"}, granted); !errors.Is(err, models.ErrOAuthInvalidScope) {
		t.Fatalf("lenient none left err = %v", err)
	}
}

func TestCompatRedirectURIMatching(t *testing.T) {
	any := ClientCompat{LoopbackAnyPort: true}
	withLocalhost := ClientCompat{LoopbackAnyPort: true, LoopbackAllowLocalhost: true}
	tests := []struct {
		name       string
		compat     ClientCompat
		registered string
		uri        string
		want       bool
	}{
		{"strict exact", ClientCompat{}, "http://127.0.0.1/cb", "http://127.0.0.1/cb", true},
		{"strict different port", ClientCompat{}, "http://127.0.0.1/cb", "http://127.0.0.1:5000/cb", false},
		{"any port v4", any, "http://127.0.0.1/cb", "http://127.0.0.1:54321/cb", true},
		{"any port v4 registered with port", any, "http://127.0.0.1:3000/cb", "http://127.0.0.1:54321/cb", true},
		{"any port v6", any, "http://[::1]/cb", "http://[::1]:54321/cb", true},
		{"v4 does not match v6", any, "http://127.0.0.1/cb", "http://[::1]:54321/cb", false},
		{"different path", any, "http://127.0.0.1/cb", "http://127.0.0.1:5000/other", false},
		{"path prefix not enough", any, "http://127.0.0.1/cb", "http://127.0.0.1:5000/cb/x", false},
		{"different query", any, "http://127.0.0.1/cb?a=1", "http://127.0.0.1:5000/cb?a=2", false},
		{"https scheme never port-agnostic", any, "https://127.0.0.1/cb", "https://127.0.0.1:5000/cb", false},
		{"non loopback host", any, "http://app.example.com/cb", "http://app.example.com:5000/cb", false},
		{"localhost off by default", any, "http://localhost/cb", "http://localhost:5000/cb", false},
		{"localhost opt in", withLocalhost, "http://localhost/cb", "http://localhost:5000/cb", true},
		{"localhost does not match 127", withLocalhost, "http://localhost/cb", "http://127.0.0.1:5000/cb", false},
		{"userinfo rejected", any, "http://127.0.0.1/cb", "http://u@127.0.0.1:5000/cb", false},
		{"bad port", any, "http://127.0.0.1/cb", "http://127.0.0.1:99999/cb", false},
		{"empty uri", any, "http://127.0.0.1/cb", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := compatSvc(tc.compat, compatRes).redirectURIRegistered([]string{tc.registered}, tc.uri)
			if got != tc.want {
				t.Fatalf("match = %v, want %v", got, tc.want)
			}
		})
	}
}
