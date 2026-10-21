package mqttauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	brokerSecret = "broker-secret-0123456789"
	purgeSecret  = "purge-secret-0123456789"
	testFP       = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type memAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *memAudit) Record(_ context.Context, e AuditEvent) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}

type fixture struct {
	h     *Handler
	store *MemoryStore
	clock *fakeClock
	audit *memAudit
}

func newFixture(t *testing.T, mut func(*Config)) *fixture {
	t.Helper()
	store := NewMemoryStore()
	put := func(d Device) {
		if err := store.PutDevice(context.Background(), d); err != nil {
			t.Fatal(err)
		}
	}
	put(Device{
		ID: "dev1", OrgID: "org9", Status: StatusActive, Subject: "spiffe://example.org/dev1",
		CertFingerprints: []string{testFP}, TokenHashes: []string{HashToken("tok-1"), HashToken("tok-1b")},
		Rules: []Rule{
			{Allow, ActionPublish, "devices/{device_id}/telemetry/#"},
			{Allow, ActionSubscribe, "devices/{device_id}/cmd/+"},
			{Allow, ActionSubscribe, "fleet/{org_id}/#"},
			{Deny, ActionAll, "fleet/{org_id}/secret/#"},
			{Allow, ActionAll, "shared/#"},
		},
	})
	put(Device{ID: "dev2", Status: StatusActive, TokenHashes: []string{HashToken("tok-2")}, Rules: []Rule{{Allow, ActionAll, "#"}}})
	put(Device{ID: "revoked", Status: StatusRevoked, TokenHashes: []string{HashToken("tok-r")}})
	put(Device{ID: "susp", Status: StatusSuspended, TokenHashes: []string{HashToken("tok-s")}})
	put(Device{ID: "short", Status: StatusActive, TokenHashes: []string{HashToken("tok-x")}, ExpiresAt: t0.Add(time.Minute)})
	clock := &fakeClock{t: t0}
	audit := &memAudit{}
	cfg := Config{
		Store: store, BrokerSecret: brokerSecret, PurgeSecret: purgeSecret, Audit: audit, Mosquitto: true,
		Now: clock.Now, AllowSampleRate: 1, CacheTTL: 5 * time.Second,
		JWT: &JWTConfig{
			Keyfunc: func(*jwt.Token) (any, error) { return []byte("jwt-key-0123456789"), nil },
			Methods: []string{"HS256"}, Issuer: "https://auth.example.com", Audience: "mqtt",
		},
	}
	if mut != nil {
		mut(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{h: h, store: store, clock: clock, audit: audit}
}

func (f *fixture) post(path string, body any, hdr map[string]string) (int, map[string]any) {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if _, ok := hdr["Authorization"]; !ok {
		r.Header.Set("Authorization", "Bearer "+brokerSecret)
	}
	for k, v := range hdr {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *fixture) jwt(sub, aud string, exp time.Time) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: sub, Issuer: "https://auth.example.com", Audience: jwt.ClaimStrings{aud}, ExpiresAt: jwt.NewNumericDate(exp),
	})
	s, err := tok.SignedString([]byte("jwt-key-0123456789"))
	if err != nil {
		panic(err)
	}
	return s
}

func TestNewFailsClosedWithoutBrokerAuth(t *testing.T) {
	if _, err := New(Config{Store: NewMemoryStore()}); err == nil {
		t.Fatal("New accepted a config with no broker secret")
	}
	if _, err := New(Config{Store: NewMemoryStore(), AllowUnauthenticatedBroker: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BrokerSecret: "x"}); err == nil {
		t.Fatal("New accepted a nil store")
	}
	if _, err := New(Config{Store: NewMemoryStore(), BrokerSecret: "x", JWT: &JWTConfig{}}); err == nil {
		t.Fatal("New accepted an empty JWT config")
	}
}

func TestAuthn(t *testing.T) {
	f := newFixture(t, nil)
	exp := f.clock.Now().Add(time.Hour)
	cases := []struct {
		name string
		body map[string]any
		hdr  map[string]string
		want string
	}{
		{"token ok", map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev1"}, nil, "allow"},
		{"second token ok", map[string]any{"username": "dev1", "password": "tok-1b", "clientid": "dev1-a"}, nil, "allow"},
		{"wrong token", map[string]any{"username": "dev1", "password": "nope", "clientid": "dev1"}, nil, "deny"},
		{"token of another device", map[string]any{"username": "dev1", "password": "tok-2", "clientid": "dev1"}, nil, "deny"},
		{"unknown device", map[string]any{"username": "ghost", "password": "tok-1", "clientid": "ghost"}, nil, "deny"},
		{"empty password", map[string]any{"username": "dev1", "password": "", "clientid": "dev1"}, nil, "deny"},
		{"empty username", map[string]any{"username": "", "password": "tok-1", "clientid": "dev1"}, nil, "deny"},
		{"revoked", map[string]any{"username": "revoked", "password": "tok-r", "clientid": "revoked"}, nil, "deny"},
		{"suspended", map[string]any{"username": "susp", "password": "tok-s", "clientid": "susp"}, nil, "deny"},
		{"device not yet expired", map[string]any{"username": "short", "password": "tok-x", "clientid": "short"}, nil, "allow"},
		{"clientid takeover attempt", map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev2"}, nil, "deny"},
		{"clientid prefix without separator", map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev1x"}, nil, "deny"},
		{"empty clientid", map[string]any{"username": "dev1", "password": "tok-1", "clientid": ""}, nil, "deny"},
		{"cert header ok", map[string]any{"clientid": "dev1"}, map[string]string{DefaultCertHeader: "SHA256:" + strings.ToUpper(testFP)}, "allow"},
		{"cert body ok", map[string]any{"clientid": "dev1", "cert_fingerprint": testFP}, nil, "allow"},
		{"cert unknown", map[string]any{"clientid": "dev1"}, map[string]string{DefaultCertHeader: strings.Repeat("ab", 32)}, "deny"},
		{"cert malformed does not fall back to token", map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev1"}, map[string]string{DefaultCertHeader: "zzz"}, "deny"},
		{"cert conflict", map[string]any{"clientid": "dev1", "cert_fingerprint": strings.Repeat("ab", 32)}, map[string]string{DefaultCertHeader: testFP}, "deny"},
		{"cert wrong clientid", map[string]any{"clientid": "dev2"}, map[string]string{DefaultCertHeader: testFP}, "deny"},
		{"jwt by subject", map[string]any{"password": f.jwt("spiffe://example.org/dev1", "mqtt", exp), "clientid": "dev1"}, nil, "allow"},
		{"jwt by device id", map[string]any{"password": f.jwt("dev2", "mqtt", exp), "clientid": "dev2"}, nil, "allow"},
		{"jwt expired", map[string]any{"password": f.jwt("dev1", "mqtt", f.clock.Now().Add(-time.Minute)), "clientid": "dev1"}, nil, "deny"},
		{"jwt wrong audience", map[string]any{"password": f.jwt("dev1", "other", exp), "clientid": "dev1"}, nil, "deny"},
		{"jwt unknown subject", map[string]any{"password": f.jwt("ghost", "mqtt", exp), "clientid": "ghost"}, nil, "deny"},
		{"jwt revoked device", map[string]any{"password": f.jwt("revoked", "mqtt", exp), "clientid": "revoked"}, nil, "deny"},
		{"jwt garbage", map[string]any{"password": "eyJ.eyJ.sig", "clientid": "dev1"}, nil, "deny"},
		{"no credential", map[string]any{"clientid": "dev1"}, nil, "deny"},
		{"wrong broker secret", map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev1"}, map[string]string{"Authorization": "Bearer nope"}, "deny"},
		{"no broker secret", map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev1"}, map[string]string{"Authorization": ""}, "deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := f.post("/authn", c.body, c.hdr)
			if code != http.StatusOK {
				t.Fatalf("status %d, EMQX needs 200 for a decision", code)
			}
			if out["result"] != c.want {
				t.Fatalf("result %v, want %s", out["result"], c.want)
			}
			if c.want == "allow" {
				if out["is_superuser"] != false {
					t.Fatalf("is_superuser = %v", out["is_superuser"])
				}
				if _, ok := out["client_attrs"].(map[string]any)["device_id"]; !ok {
					t.Fatal("client_attrs.device_id missing")
				}
			} else if len(out) != 1 {
				t.Fatalf("deny leaked fields: %v", out)
			}
		})
	}
}

func TestAuthnExpireAt(t *testing.T) {
	f := newFixture(t, nil)
	_, out := f.post("/authn", map[string]any{"username": "short", "password": "tok-x", "clientid": "short"}, nil)
	if got := int64(out["expire_at"].(float64)); got != t0.Add(time.Minute).Unix() {
		t.Fatalf("expire_at %d", got)
	}
	jexp := t0.Add(30 * time.Second)
	_, out = f.post("/authn", map[string]any{"password": f.jwt("dev2", "mqtt", jexp), "clientid": "dev2"}, nil)
	if got := int64(out["expire_at"].(float64)); got != jexp.Unix() {
		t.Fatalf("jwt expire_at %d", got)
	}
	f.clock.Advance(2 * time.Minute)
	_, out = f.post("/authn", map[string]any{"username": "short", "password": "tok-x", "clientid": "short"}, nil)
	if out["result"] != "deny" {
		t.Fatal("expired device authenticated")
	}
}

func TestAuthz(t *testing.T) {
	f := newFixture(t, nil)
	cases := []struct {
		name, action, topic string
		want                string
	}{
		{"publish own telemetry", "publish", "devices/dev1/telemetry/temp", "allow"},
		{"publish telemetry root", "publish", "devices/dev1/telemetry", "allow"},
		{"publish another device telemetry", "publish", "devices/dev2/telemetry/temp", "deny"},
		{"publish to wildcard name", "publish", "devices/dev1/telemetry/+", "deny"},
		{"publish to hash", "publish", "#", "deny"},
		{"publish empty", "publish", "", "deny"},
		{"publish $SYS even with shared grant", "publish", "$SYS/broker/x", "deny"},
		{"publish $share name", "publish", "$share/g/shared/x", "deny"},
		{"publish where only subscribe granted", "publish", "devices/dev1/cmd/reboot", "deny"},
		{"subscribe own cmd", "subscribe", "devices/dev1/cmd/reboot", "allow"},
		{"subscribe cmd plus", "subscribe", "devices/dev1/cmd/+", "allow"},
		{"subscribe cmd hash too wide", "subscribe", "devices/dev1/cmd/#", "deny"},
		{"subscribe other device cmd", "subscribe", "devices/dev2/cmd/x", "deny"},
		{"subscribe plus device cmd", "subscribe", "devices/+/cmd/x", "deny"},
		{"subscribe hash", "subscribe", "#", "deny"},
		{"subscribe org tree", "subscribe", "fleet/org9/telemetry/#", "allow"},
		{"subscribe other org tree", "subscribe", "fleet/org1/#", "deny"},
		{"subscribe org root wildcard hits deny", "subscribe", "fleet/org9/#", "deny"},
		{"subscribe org plus wildcard hits deny", "subscribe", "fleet/org9/+/x", "deny"},
		{"subscribe org plus clear of deny", "subscribe", "fleet/org9/telemetry/+", "allow"},
		{"subscribe denied subtree", "subscribe", "fleet/org9/secret/key", "deny"},
		{"subscribe shared group", "subscribe", "$share/workers/devices/dev1/cmd/+", "allow"},
		{"subscribe shared group ungranted", "subscribe", "$share/workers/devices/dev2/cmd/+", "deny"},
		{"subscribe malformed shared", "subscribe", "$share/workers", "deny"},
		{"subscribe $SYS", "subscribe", "$SYS/#", "deny"},
		{"subscribe via shared hash", "subscribe", "$share/g/#", "deny"},
		{"subscribe granted all", "subscribe", "shared/a/b", "allow"},
		{"bad filter", "subscribe", "a/#/b", "deny"},
		{"unknown action", "all", "shared/a", "deny"},
		{"empty action", "", "shared/a", "deny"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out := f.post("/authz", map[string]any{"username": "dev1", "clientid": "dev1-x", "action": c.action, "topic": c.topic}, nil)
			if code != http.StatusOK || out["result"] != c.want {
				t.Fatalf("status %d result %v, want %s", code, out["result"], c.want)
			}
		})
	}
}

func TestAuthzIdentity(t *testing.T) {
	f := newFixture(t, nil)
	check := func(name string, body map[string]any, want string) {
		t.Helper()
		_, out := f.post("/authz", body, nil)
		if out["result"] != want {
			t.Errorf("%s: result %v, want %s", name, out["result"], want)
		}
	}
	pub := func(extra map[string]any) map[string]any {
		m := map[string]any{"action": "publish", "topic": "devices/dev1/telemetry/t"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	check("client_attrs device id", pub(map[string]any{"device_id": "dev1"}), "allow")
	check("username with bound clientid", pub(map[string]any{"username": "dev1", "clientid": "dev1"}), "allow")
	check("username with foreign clientid", pub(map[string]any{"username": "dev1", "clientid": "dev2"}), "deny")
	check("no identity", pub(nil), "deny")
	check("unknown device", pub(map[string]any{"device_id": "ghost"}), "deny")
	check("revoked device", pub(map[string]any{"device_id": "revoked"}), "deny")
	check("suspended device", pub(map[string]any{"device_id": "susp"}), "deny")
	check("cert CN username does not grant", pub(map[string]any{"username": "CN=dev1", "clientid": "dev1"}), "deny")
}

func TestAuthzMalformedAndWrongCaller(t *testing.T) {
	f := newFixture(t, nil)
	r := httptest.NewRequest(http.MethodPost, "/authz", strings.NewReader("{not json"))
	r.Header.Set("Authorization", "Bearer "+brokerSecret)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deny"`) {
		t.Fatalf("malformed: %d %s", w.Code, w.Body.String())
	}
	code, out := f.post("/authz", map[string]any{"device_id": "dev2", "action": "publish", "topic": "x"}, map[string]string{"Authorization": "Bearer wrong"})
	if code != 200 || out["result"] != "deny" {
		t.Fatalf("wrong caller: %d %v", code, out)
	}
}

type errStore struct{ DeviceStore }

func (errStore) DeviceByID(context.Context, string) (*Device, error) {
	return nil, errors.New("db down")
}
func (errStore) DeviceByCertFingerprint(context.Context, string) (*Device, error) {
	return nil, errors.New("db down")
}

func TestStoreErrorFailsClosed(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Store = errStore{c.Store} })
	code, out := f.post("/authz", map[string]any{"device_id": "dev2", "action": "publish", "topic": "x"}, nil)
	if code != 200 || out["result"] != "deny" {
		t.Fatalf("authz: %d %v", code, out)
	}
	code, out = f.post("/authn", map[string]any{"username": "dev2", "password": "tok-2", "clientid": "dev2"}, nil)
	if code != 200 || out["result"] != "deny" {
		t.Fatalf("authn: %d %v", code, out)
	}
	if f.h.Metrics()[`theauth_mqtt_errors_total{result="store"}`] == 0 {
		t.Fatal("store error not counted")
	}
}

func TestRevocationLatencyAndPurge(t *testing.T) {
	f := newFixture(t, nil)
	req := map[string]any{"device_id": "dev2", "action": "publish", "topic": "x/y"}
	if _, out := f.post("/authz", req, nil); out["result"] != "allow" {
		t.Fatal("setup")
	}
	if ok, _ := f.store.SetStatus(context.Background(), "dev2", StatusRevoked); !ok {
		t.Fatal("revoke")
	}
	if _, out := f.post("/authz", req, nil); out["result"] != "allow" {
		t.Fatal("expected the cached allow to stand within the TTL")
	}
	if f.h.Metrics()[`theauth_mqtt_cache_hits_total{result="decision"}`] == 0 {
		t.Fatal("cache hit not counted")
	}
	// Purge endpoint: wrong secret, missing secret, bad body, then success.
	if code, _ := f.post("/purge", map[string]any{"device_id": "dev2"}, map[string]string{"Authorization": "Bearer " + brokerSecret}); code != 401 {
		t.Fatalf("broker secret must not purge, got %d", code)
	}
	if code, _ := f.post("/purge", map[string]any{}, map[string]string{"Authorization": "Bearer " + purgeSecret}); code != 400 {
		t.Fatalf("empty purge body got %d", code)
	}
	if code, out := f.post("/purge", map[string]any{"device_id": "dev2"}, map[string]string{"Authorization": "Bearer " + purgeSecret}); code != 200 || out["purged"].(float64) < 1 {
		t.Fatalf("purge: %d %v", code, out)
	}
	if _, out := f.post("/authz", req, nil); out["result"] != "deny" {
		t.Fatal("revoked device still allowed after purge")
	}
}

func TestRevocationWithoutPurgeAfterTTL(t *testing.T) {
	f := newFixture(t, nil)
	req := map[string]any{"device_id": "dev2", "action": "publish", "topic": "x/y"}
	f.post("/authz", req, nil)
	_, _ = f.store.SetStatus(context.Background(), "dev2", StatusRevoked)
	f.clock.Advance(6 * time.Second)
	if _, out := f.post("/authz", req, nil); out["result"] != "deny" {
		t.Fatal("allow outlived the cache TTL")
	}
}

func TestCacheDisabledAndPurgeDisabled(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.CacheTTL = -1; c.PurgeSecret = "" })
	req := map[string]any{"device_id": "dev2", "action": "publish", "topic": "x/y"}
	f.post("/authz", req, nil)
	_, _ = f.store.SetStatus(context.Background(), "dev2", StatusRevoked)
	if _, out := f.post("/authz", req, nil); out["result"] != "deny" {
		t.Fatal("revocation not immediate without cache")
	}
	if code, _ := f.post("/purge", map[string]any{"all": true}, map[string]string{"Authorization": "Bearer "}); code != 404 {
		t.Fatalf("purge should be disabled, got %d", code)
	}
}

func TestAuditSamplingAndAlwaysDeny(t *testing.T) {
	var roll float64
	f := newFixture(t, func(c *Config) { c.AllowSampleRate = 0.25; c.Rand = func() float64 { return roll } })
	allow := map[string]any{"device_id": "dev2", "action": "publish", "topic": "x"}
	roll = 0.9
	f.post("/authz", allow, nil)
	if len(f.audit.events) != 0 {
		t.Fatal("allow recorded outside the sample")
	}
	roll = 0.1
	f.post("/authz", allow, nil)
	if len(f.audit.events) != 1 || !f.audit.events[0].Allowed || f.audit.events[0].DeviceID != "dev2" {
		t.Fatalf("sampled allow missing: %+v", f.audit.events)
	}
	roll = 0.99
	f.post("/authz", map[string]any{"device_id": "dev2", "action": "publish", "topic": ""}, nil)
	f.post("/authn", map[string]any{"username": "dev1", "password": "s3cr3t-pw", "clientid": "dev1"}, nil)
	if len(f.audit.events) != 3 || f.audit.events[1].Allowed || f.audit.events[2].Allowed {
		t.Fatalf("denies must always be recorded: %+v", f.audit.events)
	}
	for _, e := range f.audit.events {
		if strings.Contains(e.Reason, "s3cr3t-pw") {
			t.Fatal("secret in audit reason")
		}
	}
}

func TestAuditNegativeRateKeepsDenies(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.AllowSampleRate = -1 })
	f.post("/authz", map[string]any{"device_id": "dev2", "action": "publish", "topic": "x"}, nil)
	f.post("/authz", map[string]any{"device_id": "ghost", "action": "publish", "topic": "x"}, nil)
	if len(f.audit.events) != 1 || f.audit.events[0].Allowed {
		t.Fatalf("%+v", f.audit.events)
	}
}

func TestMetricsHandler(t *testing.T) {
	f := newFixture(t, nil)
	f.post("/authz", map[string]any{"device_id": "dev2", "action": "publish", "topic": "x"}, nil)
	f.post("/authz", map[string]any{"device_id": "ghost", "action": "publish", "topic": "x"}, nil)
	w := httptest.NewRecorder()
	f.h.MetricsHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{`theauth_mqtt_authz_total{result="allow"} 1`, `theauth_mqtt_authz_total{result="deny"} 1`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q in:\n%s", want, body)
		}
	}
}

func TestMosquitto(t *testing.T) {
	f := newFixture(t, nil)
	do := func(path string, body map[string]any) int {
		code, _ := f.post(path, body, nil)
		return code
	}
	if c := do("/mosquitto/user", map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev1"}); c != 200 {
		t.Fatalf("user ok: %d", c)
	}
	if c := do("/mosquitto/user", map[string]any{"username": "dev1", "password": "bad", "clientid": "dev1"}); c != 403 {
		t.Fatalf("user bad: %d", c)
	}
	if c := do("/mosquitto/superuser", map[string]any{"username": "dev2"}); c != 403 {
		t.Fatalf("superuser: %d", c)
	}
	acl := func(topic string, acc any) int {
		return do("/mosquitto/acl", map[string]any{"username": "dev1", "clientid": "dev1", "topic": topic, "acc": acc})
	}
	if c := acl("devices/dev1/telemetry/t", 2); c != 200 {
		t.Fatalf("write ok: %d", c)
	}
	if c := acl("devices/dev2/telemetry/t", 2); c != 403 {
		t.Fatalf("write other: %d", c)
	}
	if c := acl("devices/dev1/cmd/x", 1); c != 200 {
		t.Fatalf("read ok: %d", c)
	}
	if c := acl("devices/dev1/cmd/+", "4"); c != 200 {
		t.Fatalf("subscribe string acc: %d", c)
	}
	if c := acl("devices/dev1/cmd/#", 4); c != 403 {
		t.Fatalf("subscribe too wide: %d", c)
	}
	if c := acl("shared/x", 3); c != 403 {
		t.Fatalf("readwrite must fail closed: %d", c)
	}
	if c := acl("shared/x", nil); c != 403 {
		t.Fatalf("missing acc must fail closed: %d", c)
	}
	// A client supplied device_id is ignored on this contract.
	if c := do("/mosquitto/acl", map[string]any{"username": "dev1", "clientid": "dev1", "device_id": "dev2", "topic": "devices/dev2/telemetry/t", "acc": 2}); c != 403 {
		t.Fatalf("device_id attribute trusted: %d", c)
	}
	// Form encoded mode.
	r := httptest.NewRequest(http.MethodPost, "/mosquitto/acl", strings.NewReader("username=dev1&clientid=dev1&topic=devices%2Fdev1%2Ftelemetry%2Ft&acc=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer "+brokerSecret)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("form acl: %d", w.Code)
	}
}

func TestMosquittoDisabledByDefault(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.Mosquitto = false })
	if c, _ := f.post("/mosquitto/user", map[string]any{"username": "dev1", "password": "tok-1"}, nil); c != http.StatusNotFound {
		t.Fatalf("got %d", c)
	}
}

func TestRuleValidation(t *testing.T) {
	bad := []Rule{
		{Allow, ActionPublish, "a/{unknown}"},
		{Allow, ActionPublish, "a/#/b"},
		{Allow, ActionSubscribe, "$share/g/a"},
		{"maybe", ActionPublish, "a"},
		{Allow, "delete", "a"},
		{Allow, ActionPublish, ""},
	}
	for _, r := range bad {
		d := Device{ID: "d", Status: StatusActive, Rules: []Rule{r}}
		if d.Validate() == nil {
			t.Errorf("rule %+v accepted", r)
		}
	}
	for _, id := range []string{"", "a/b", "a+b", "a#", "{x}", "a b", "$x"} {
		if (&Device{ID: id, Status: StatusActive}).Validate() == nil {
			t.Errorf("device id %q accepted", id)
		}
	}
	d := Device{ID: "d", Status: StatusActive, CertFingerprints: []string{"AB"}}
	if d.Validate() == nil {
		t.Error("unnormalized fingerprint accepted")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	colon := strings.ToUpper(strings.Join(splitN(testFP, 2), ":"))
	for _, in := range []string{testFP, strings.ToUpper(testFP), "sha256:" + testFP, "SHA256:" + colon, colon, " " + testFP + " "} {
		if got, ok := NormalizeFingerprint(in); !ok || got != testFP {
			t.Errorf("NormalizeFingerprint(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "abcd", testFP + "00", "md5:" + testFP[:32], strings.Repeat("zz", 32)} {
		if _, ok := NormalizeFingerprint(in); ok {
			t.Errorf("NormalizeFingerprint(%q) accepted", in)
		}
	}
}

func splitN(s string, n int) []string {
	var out []string
	for i := 0; i < len(s); i += n {
		out = append(out, s[i:i+n])
	}
	return out
}

func TestMemoryStoreConflicts(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.PutDevice(ctx, Device{ID: "a", Status: StatusActive, Subject: "s", CertFingerprints: []string{testFP}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutDevice(ctx, Device{ID: "b", Status: StatusActive, Subject: "s"}); err == nil {
		t.Fatal("duplicate subject accepted")
	}
	if err := s.PutDevice(ctx, Device{ID: "b", Status: StatusActive, CertFingerprints: []string{testFP}}); err == nil {
		t.Fatal("duplicate fingerprint accepted")
	}
	if _, err := s.DeviceBySubject(ctx, ""); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatal("empty subject matched a device")
	}
	if ok, err := s.SetStatus(ctx, "zzz", StatusRevoked); ok || err != nil {
		t.Fatal("SetStatus on a missing device")
	}
}

// mosquitto-go-auth cannot send request headers, so the secret may ride in the URI query.
func TestMosquittoSecretQuery(t *testing.T) {
	f := newFixture(t, nil)
	body := map[string]any{"username": "dev1", "password": "tok-1", "clientid": "dev1"}
	noHeader := map[string]string{"Authorization": ""}
	for _, c := range []struct {
		name, path string
		want       int
	}{
		{"correct query secret", "/mosquitto/user?secret=" + brokerSecret, 200},
		{"wrong query secret", "/mosquitto/user?secret=nope", 403},
		{"no secret", "/mosquitto/user", 403},
	} {
		if got, _ := f.post(c.path, body, noHeader); got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
	// The query secret is for the mosquitto routes only, the EMQX routes still need the header.
	if _, res := f.post("/authn?secret="+brokerSecret, body, noHeader); res["result"] != "deny" {
		t.Errorf("EMQX route accepted the query secret: %v", res)
	}
}
