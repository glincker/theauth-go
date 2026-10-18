package device

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newKeys(t *testing.T) map[string]*Signer {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	out := map[string]*Signer{}
	for name, k := range map[string]any{"EdDSA": edPriv, "ES256": p256, "ES384": p384} {
		s, err := NewSigner(k, nil)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = s
	}
	return out
}

func TestAssertionRoundTrip(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	for name, s := range newKeys(t) {
		t.Run(name, func(t *testing.T) {
			if string(s.Alg()) != name {
				t.Fatalf("alg %s", s.Alg())
			}
			for i := 0; i < 50; i++ { // exercises ECDSA r/s with leading zero bytes
				tok, err := s.SignAssertion("dev-1", now, AssertionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyAssertion(tok, s.Public(), "dev-1", "theauth", now); err != nil {
					t.Fatalf("round trip: %v", err)
				}
				if err := VerifyAssertion(tok, s.Public(), "dev-2", "theauth", now); err == nil {
					t.Fatal("accepted for another device")
				}
				if err := VerifyAssertion(tok, s.Public(), "dev-1", "other", now); err == nil {
					t.Fatal("accepted for another audience")
				}
				if err := VerifyAssertion(tok, s.Public(), "dev-1", "theauth", now.Add(2*time.Minute)); err == nil {
					t.Fatal("accepted after expiry")
				}
			}
		})
	}
}

func TestAssertionTTLAndJTI(t *testing.T) {
	s := newKeys(t)["EdDSA"]
	now := time.Now()
	for _, ttl := range []time.Duration{time.Millisecond, 301 * time.Second, -time.Second} {
		if _, err := s.SignAssertion("d", now, AssertionOptions{TTL: ttl}); err == nil {
			t.Errorf("ttl %v accepted", ttl)
		}
	}
	if _, err := s.SignAssertion("", now, AssertionOptions{}); err == nil {
		t.Error("empty device id accepted")
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, _ := s.SignAssertion("d", now, AssertionOptions{TTL: 300 * time.Second})
		p, _ := parseJWS(tok)
		pv, _ := parseJSON(p.payload)
		jti := pv.(map[string]any)["jti"].(string)
		if len(jti) < 16 || seen[jti] {
			t.Fatalf("weak or repeated jti %q", jti)
		}
		seen[jti] = true
	}
	if _, err := s.SignAssertion("d", now, AssertionOptions{Rand: strings.NewReader("short")}); err == nil {
		t.Error("short entropy source accepted")
	}
}

func testClaims(deviceID string, now time.Time, perms ...Permission) Claims {
	return Claims{
		Issuer: DefaultIssuer, Subject: deviceID, Audience: deviceID, IssuedAt: now.Unix(), NotBefore: now.Unix(),
		Exp: now.Unix() + 3600, JTI: "j", Seq: now.UnixMilli(), Owner: "o", Groups: []string{"g"}, Perms: perms,
	}
}

func TestBundleSignVerifyEvaluate(t *testing.T) {
	now := time.Unix(1_760_000_000, 0)
	calls := 3.0
	for name, s := range newKeys(t) {
		if name == "ES384" {
			if _, err := s.SignBundle("k", Claims{}); err == nil {
				t.Fatal("ES384 bundle signing accepted")
			}
			continue
		}
		t.Run(name, func(t *testing.T) {
			c := testClaims("dev-1", now,
				Permission{Resource: "mqtt:a:*", Actions: []string{"publish"}},
				Permission{Resource: "mqtt:b", Actions: []string{"publish"}, Constraints: &Constraints{MaxCallsPerHour: &calls}},
			)
			tok, err := s.SignBundle("k1", c)
			if err != nil {
				t.Fatal(err)
			}
			pub := s.Public()
			pub.KID = "k1"
			got, err := VerifyBundle(tok, VerifyOptions{Keys: NewKeySet(pub), DeviceID: "dev-1", Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if got.Seq != c.Seq || got.Owner != "o" || len(got.Groups) != 1 || len(got.Perms) != 2 {
				t.Fatalf("claims lost in transit: %+v", got)
			}
			if d := Evaluate(got, "publish", "mqtt:a:x", WithNow(now)); !d.Allowed {
				t.Fatalf("denied: %+v", d)
			}
			if d := Evaluate(got, "publish", "mqtt:b", WithNow(now)); d.Code != CodeRateLimited {
				t.Fatalf("want rate_limited without count, got %+v", d)
			}
			if d := Evaluate(got, "publish", "mqtt:b", WithNow(now), WithCallsInLastHour(2)); !d.Allowed {
				t.Fatalf("denied under budget: %+v", d)
			}
			if d := Evaluate(got, "publish", "mqtt:a:x", WithNow(now.Add(2*time.Hour))); d.Code != CodeDeviceExpired {
				t.Fatalf("want device_expired, got %+v", d)
			}
			_, err = VerifyBundle(tok, VerifyOptions{Keys: NewKeySet(pub), DeviceID: "dev-1", Now: now, LastSeq: c.Seq + 1})
			var ve *VerifyError
			if !errors.As(err, &ve) || ve.Reason != ReasonRollback {
				t.Fatalf("want rollback, got %v", err)
			}
		})
	}
}

func TestBundleRefusesWithoutKeys(t *testing.T) {
	s := newKeys(t)["EdDSA"]
	now := time.Unix(1_760_000_000, 0)
	tok, _ := s.SignBundle("k1", testClaims("d", now))
	if _, err := VerifyBundle(tok, VerifyOptions{DeviceID: "d", Now: now}); err == nil {
		t.Fatal("verified with a nil key set")
	}
	if _, err := VerifyBundle("", VerifyOptions{DeviceID: "d", Now: now}); err == nil {
		t.Fatal("verified an empty token")
	}
}

func TestEvaluateMalformedPermissionsFailClosed(t *testing.T) {
	if _, ok := parsePermission(map[string]any{"resource": 5.0, "actions": []any{"x"}}); ok {
		t.Error("numeric resource accepted")
	}
	if _, ok := parsePermission(map[string]any{"resource": "r", "actions": "publish"}); ok {
		t.Error("string actions accepted")
	}
	if _, ok := parsePermission(map[string]any{"resource": "r", "actions": []any{"x"}, "constraints": "none"}); ok {
		t.Error("string constraints accepted")
	}
	c := &Claims{Exp: time.Now().Unix() + 100, Perms: []Permission{{
		Resource: "r", Actions: []string{"a"}, Constraints: &Constraints{AllowedArgPatterns: []string{"(?=x)"}},
	}}}
	if d := Evaluate(c, "a", "r", WithArguments(map[string]any{"k": "x"})); d.Allowed || d.Code != CodeArgumentRejected {
		t.Errorf("pattern RE2 cannot compile must deny, got %+v", d)
	}
	deep := map[string]any{}
	cur := deep
	for i := 0; i < 40; i++ {
		next := map[string]any{}
		cur["n"] = next
		cur = next
	}
	c.Perms[0].Constraints.AllowedArgPatterns = []string{"."}
	if d := Evaluate(c, "a", "r", WithArguments(deep)); d.Allowed {
		t.Error("deeply nested arguments were not refused")
	}
}

func TestEvaluateTimeWindowLocation(t *testing.T) {
	loc := time.FixedZone("x", 2*3600)
	c := &Claims{Exp: 1 << 40, Perms: []Permission{{
		Resource: "r", Actions: []string{"a"}, Constraints: &Constraints{TimeWindow: &TimeWindow{Start: "09:00", End: "17:00"}},
	}}}
	utc8 := time.Date(2025, 1, 1, 8, 0, 0, 0, time.UTC) // 10:00 in the +02:00 zone
	if d := Evaluate(c, "a", "r", WithNow(utc8)); d.Allowed {
		t.Error("08:00 UTC is outside 09:00 to 17:00")
	}
	if d := Evaluate(c, "a", "r", WithNow(utc8), WithLocation(loc)); !d.Allowed {
		t.Errorf("10:00 local is inside: %+v", d)
	}
}

func TestSyncedClock(t *testing.T) {
	var tick time.Duration
	c := NewSyncedClock(func() time.Duration { return tick })
	if _, ok := c.Now(); ok {
		t.Fatal("Now reported ok before any sync")
	}
	t0 := time.Unix(1_760_000_000, 0)
	if !c.Sync(t0) {
		t.Fatal("first sync refused")
	}
	tick = 90 * time.Second
	if now, _ := c.Now(); !now.Equal(t0.Add(90 * time.Second)) {
		t.Fatalf("now %v", now)
	}
	if c.Sync(t0) {
		t.Fatal("a stale replay moved the clock back")
	}
	if now, _ := c.Now(); !now.Equal(t0.Add(90 * time.Second)) {
		t.Fatal("refused sync changed the clock")
	}
	if !c.Sync(t0.Add(80 * time.Second)) { // small step back is drift correction
		t.Fatal("drift correction refused")
	}
	if !c.Sync(t0.Add(500 * time.Second)) {
		t.Fatal("forward sync refused")
	}
}

func TestJSONReader(t *testing.T) {
	good := `{"a":[1,2.5e3,-0.5,true,false,null,"xé😀\n"],"b":{}}`
	v, err := parseJSON([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	var std any
	if err := json.Unmarshal([]byte(good), &std); err != nil {
		t.Fatal(err)
	}
	if string(appendJSON(nil, v)) != mustMarshal(t, std) {
		t.Errorf("mine %s, std %s", appendJSON(nil, v), mustMarshal(t, std))
	}
	for _, bad := range []string{``, `{`, `{"a":}`, `[1,]`, `01`, `1.`, `-`, `"\x"`, "\"a\nb\"", `{"a":1} x`, `nul`, `{1:2}`, strings.Repeat("[", 100)} {
		if _, err := parseJSON([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func FuzzVerifyBundle(f *testing.F) {
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJFZERTQSJ9.e30.AAAA")
	f.Fuzz(func(t *testing.T, tok string) {
		_, _ = VerifyBundle(tok, VerifyOptions{Keys: NewKeySet(), DeviceID: "d", Now: time.Unix(1, 0)})
	})
}

func FuzzParseJSON(f *testing.F) {
	f.Add(`{"a":[1,"x"]}`)
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseJSON([]byte(s)) })
}

// The verify path must stay light enough for TinyGo: no reflection based packages are
// imported directly by this package.
func TestNoHeavyImports(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			switch p := strings.Trim(imp.Path.Value, `"`); p {
			case "encoding/json", "reflect", "fmt", "os", "net/http", "sort", "encoding/asn1", "encoding/gob":
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}

func TestWriteInterop(t *testing.T) {
	out := os.Getenv("GO_DEVICE_INTEROP_OUT")
	if out == "" {
		t.Skip("set GO_DEVICE_INTEROP_OUT to write the Go to TS interop file")
	}
	now := time.Now()
	type item = map[string]any
	doc := item{"deviceId": "dev-go", "audience": "theauth", "now": now.Unix()}
	var assertions, bundles []item
	var keys []any
	for name, s := range newKeys(t) {
		tok, err := s.SignAssertion("dev-go", now, AssertionOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assertions = append(assertions, item{"name": name, "token": tok, "jwk": s.Public().JWK()})
		if name == "ES384" {
			continue
		}
		pub := s.Public()
		pub.KID = "go-" + name
		keys = append(keys, pub.JWK())
		c := testClaims("dev-go", now, Permission{Resource: "mqtt:a:*", Actions: []string{"publish"}})
		btok, err := s.SignBundle(pub.KID, c)
		if err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, item{"name": name, "token": btok})
	}
	doc["assertions"], doc["bundles"], doc["jwks"] = assertions, bundles, item{"keys": keys}
	b, _ := json.MarshalIndent(doc, "", " ")
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
