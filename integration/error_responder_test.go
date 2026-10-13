package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func newResponderAuth(t *testing.T, resp func(http.ResponseWriter, *http.Request, int, string, string)) *theauth.TheAuth {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage: memory.New(), BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		APITokens:      &theauth.APITokensConfig{Prefix: "tk"},
		ErrorResponder: resp,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func serve(h http.Handler, method, target string, hdr map[string]string) (*http.Response, string) {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func TestErrorResponderNilKeepsDefaultBytes(t *testing.T) {
	a := newResponderAuth(t, nil)

	res, body := serve(a.RequireAuth()(okHandler()), "GET", "/x", nil)
	want := `{"type":"https://theauth.dev/problems/auth.unauthenticated","title":"Unauthorized","status":401,"detail":"Missing or invalid session","code":"auth.unauthenticated"}`
	if res.StatusCode != 401 || body != want {
		t.Fatalf("RequireAuth default changed: %d %s", res.StatusCode, body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	if got := res.Header.Get("WWW-Authenticate"); got != `Session realm="theauth", error="auth.unauthenticated"` {
		t.Fatalf("WWW-Authenticate %q", got)
	}

	res, body = serve(a.RequireAbility("deploy")(okHandler()), "GET", "/x", map[string]string{"Authorization": "Bearer tk_nope"})
	want = `{"type":"https://theauth.dev/problems/auth.unauthenticated","title":"Unauthorized","status":401,"detail":"Invalid API token","code":"auth.unauthenticated"}`
	if res.StatusCode != 401 || body != want {
		t.Fatalf("RequireAbility default changed: %d %s", res.StatusCode, body)
	}
}

func TestErrorResponderReceivesMiddlewareErrors(t *testing.T) {
	type call struct {
		status        int
		code, message string
	}
	var got []call
	a := newResponderAuth(t, func(w http.ResponseWriter, _ *http.Request, status int, code, message string) {
		got = append(got, call{status, code, message})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"error":{"code":%q}}`, code)
	})

	res, body := serve(a.RequireAuth()(okHandler()), "GET", "/x", nil)
	if res.StatusCode != 401 || body != `{"error":{"code":"auth.unauthenticated"}}` {
		t.Fatalf("RequireAuth: %d %s", res.StatusCode, body)
	}
	if res.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("401 must keep the WWW-Authenticate challenge")
	}
	serve(a.RequireAbility("deploy")(okHandler()), "GET", "/x", nil)
	serve(a.RequirePermission("p")(okHandler()), "GET", "/x", nil)
	serve(a.Handler(), "POST", "/auth/signin", map[string]string{"Origin": "http://evil.test", "Cookie": "theauth_session=x"})

	want := []call{
		{401, "auth.unauthenticated", "Missing or invalid session"},
		{401, "auth.unauthenticated", "Missing credentials"},
		{500, "rbac.disabled", "RBAC is not enabled in Config"},
		{403, "csrf_origin_rejected", "request origin is not trusted"},
	}
	if len(got) != len(want) {
		t.Fatalf("calls %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("call %d: %+v want %+v", i, got[i], want[i])
		}
	}
}
