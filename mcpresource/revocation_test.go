package mcpresource

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func deviceToken(t *testing.T, f *fakeAS, extra map[string]any) string {
	t.Helper()
	c := map[string]any{
		"iss": testResource, "sub": "spiffe://example.org/sensor", "aud": testResource,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"jti": "jti-dev", "client_id": "dev-1", "scope": "telemetry:write",
	}
	for k, v := range extra {
		c[k] = v
	}
	return signToken(t, f.kid, f.priv, c)
}

func TestRevocationCheckerDeniesRevokedToken(t *testing.T) {
	f := newFakeAS(t)
	var revoked atomic.Bool
	var seen atomic.Value
	v := New(testResource, WithJWKS(f.jwksServer.URL), WithRevocationChecker(
		RevocationCheckerFunc(func(_ context.Context, _ string, p *Principal) (bool, error) {
			seen.Store(p.JWTID)
			return revoked.Load(), nil
		})))
	tok := deviceToken(t, f, map[string]any{"device_id": "01DEV"})

	if rec := runMiddleware(v, "Bearer "+tok); rec.Code != http.StatusOK {
		t.Fatalf("before revocation: %d %s", rec.Code, rec.Body.String())
	}
	revoked.Store(true)
	if rec := runMiddleware(v, "Bearer "+tok); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after revocation: %d", rec.Code)
	}
	if seen.Load() != "jti-dev" {
		t.Fatalf("checker saw %v", seen.Load())
	}
}

func TestRevocationCheckerSkippedForInvalidTokens(t *testing.T) {
	f := newFakeAS(t)
	var calls atomic.Int64
	v := New(testResource, WithJWKS(f.jwksServer.URL), WithRevocationChecker(
		RevocationCheckerFunc(func(context.Context, string, *Principal) (bool, error) {
			calls.Add(1)
			return false, nil
		})))
	expired := deviceToken(t, f, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	if rec := runMiddleware(v, "Bearer "+expired); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired: %d", rec.Code)
	}
	if calls.Load() != 0 {
		t.Fatalf("checker ran %d times for an invalid token", calls.Load())
	}
}

func TestRevocationCheckerErrorFailsClosedUnlessFailOpen(t *testing.T) {
	f := newFakeAS(t)
	boom := RevocationCheckerFunc(func(context.Context, string, *Principal) (bool, error) {
		return false, errors.New("denylist unreachable")
	})
	tok := deviceToken(t, f, nil)

	closed := New(testResource, WithJWKS(f.jwksServer.URL), WithRevocationChecker(boom))
	if rec := runMiddleware(closed, "Bearer "+tok); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fail closed: %d", rec.Code)
	}
	open := New(testResource, WithJWKS(f.jwksServer.URL), WithRevocationChecker(boom), WithRevocationFailOpen())
	if rec := runMiddleware(open, "Bearer "+tok); rec.Code != http.StatusOK {
		t.Fatalf("fail open: %d", rec.Code)
	}
}

func TestNoRevocationCheckerByDefault(t *testing.T) {
	f := newFakeAS(t)
	v := New(testResource, WithJWKS(f.jwksServer.URL))
	if rec := runMiddleware(v, "Bearer "+deviceToken(t, f, map[string]any{"device_id": "01DEV"})); rec.Code != http.StatusOK {
		t.Fatalf("default: %d", rec.Code)
	}
}

func TestDeviceRevocationIntrospection(t *testing.T) {
	f := newFakeAS(t)
	v := New(testResource,
		WithJWKS(f.jwksServer.URL),
		WithIntrospection(f.introspectServer.URL, "client-1", "secret-1"),
		WithDeviceRevocationIntrospection(),
		WithCacheTTL(time.Minute),
	)
	dev := deviceToken(t, f, map[string]any{"device_id": "01DEV"})
	user := deviceToken(t, f, map[string]any{"jti": "jti-user"})

	if rec := runMiddleware(v, "Bearer "+dev); rec.Code != http.StatusOK {
		t.Fatalf("active device: %d %s", rec.Code, rec.Body.String())
	}
	callsAfterDevice := f.introspectCalls.Load()
	if callsAfterDevice == 0 {
		t.Fatal("device token was not introspected")
	}
	// Non device tokens never reach the AS.
	if rec := runMiddleware(v, "Bearer "+user); rec.Code != http.StatusOK {
		t.Fatalf("user token: %d", rec.Code)
	}
	if f.introspectCalls.Load() != callsAfterDevice {
		t.Fatal("non device token was introspected")
	}

	f.introspectActive.Store(false)
	v2 := New(testResource,
		WithJWKS(f.jwksServer.URL),
		WithIntrospection(f.introspectServer.URL, "client-1", "secret-1"),
		WithDeviceRevocationIntrospection(),
	)
	if rec := runMiddleware(v2, "Bearer "+dev); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked device: %d", rec.Code)
	}
	if rec := runMiddleware(v2, "Bearer "+user); rec.Code != http.StatusOK {
		t.Fatalf("user token must not depend on device revocation: %d", rec.Code)
	}
}

func TestDeviceRevocationIntrospectionWithoutURIWarns(t *testing.T) {
	v := New(testResource, WithJWKS("https://as.example.com/jwks"), WithDeviceRevocationIntrospection())
	var found bool
	for _, d := range v.Diagnostics() {
		if d.Code == "revocation-no-introspection" {
			found = true
		}
	}
	if !found {
		t.Fatalf("diagnostics: %+v", v.Diagnostics())
	}
}
