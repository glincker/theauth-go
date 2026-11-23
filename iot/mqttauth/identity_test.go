package mqttauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

func TestScopeRules(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		want   []Rule
	}{
		{"publish with star", []string{"mqtt:publish:sensors:temp:*"}, []Rule{{Allow, ActionPublish, "sensors/temp/#"}}},
		{"exact topic", []string{"mqtt:subscribe:cmd:boiler"}, []Rule{{Allow, ActionSubscribe, "cmd/boiler"}}},
		{"both actions", []string{"mqtt:*:shared:*"}, []Rule{{Allow, ActionAll, "shared/#"}}},
		{"placeholder", []string{"mqtt:publish:devices:{device_id}:telemetry:*"}, []Rule{{Allow, ActionPublish, "devices/{device_id}/telemetry/#"}}},
		{"star ends the filter", []string{"mqtt:publish:a:*:c"}, []Rule{{Allow, ActionPublish, "a/#"}}},
		{"bare star", []string{"mqtt:publish:*"}, []Rule{{Allow, ActionPublish, "#"}}},
		{"other scopes ignored", []string{"telemetry:write", "openid"}, nil},
		{"unknown action grants nothing", []string{"mqtt:read:a:b"}, nil},
		{"missing path grants nothing", []string{"mqtt:publish", "mqtt:publish:"}, nil},
		{"slash in level grants nothing", []string{"mqtt:publish:a/b"}, nil},
		{"plus grants nothing", []string{"mqtt:subscribe:a:+"}, nil},
		{"partial star grants nothing", []string{"mqtt:publish:a*"}, nil},
		{"empty level grants nothing", []string{"mqtt:publish:a::b"}, nil},
		{"unknown placeholder grants nothing", []string{"mqtt:publish:{tenant}:x"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ScopeRules(c.scopes); !reflect.DeepEqual(got, c.want) {
				t.Errorf("ScopeRules(%v) = %v, want %v", c.scopes, got, c.want)
			}
		})
	}
}

func newRegistryDevice(t *testing.T, st *memory.Store, mut func(*theauth.Device)) theauth.Device {
	t.Helper()
	org := ulid.New()
	d := theauth.Device{
		ID: ulid.New(), OrganizationID: &org, Name: "boiler", Status: "active", CreatedAt: time.Now().UTC(),
		Scopes: []string{"telemetry:write", "mqtt:publish:devices:{device_id}:telemetry:*", "mqtt:subscribe:devices:{device_id}:cmd:*"},
	}
	if mut != nil {
		mut(&d)
	}
	if err := st.InsertDevice(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestIdentityStoreMapping(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	d := newRegistryDevice(t, st, nil)
	spiffe := newRegistryDevice(t, st, func(d *theauth.Device) { d.SPIFFEID = "spiffe://example.org/gw/1" })
	is := NewIdentityStore(st)

	got, err := is.DeviceByID(ctx, d.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != d.ID.String() || got.OrgID != d.OrganizationID.String() || got.Status != StatusActive || got.Subject != "device:"+d.ID.String() {
		t.Errorf("mapped device = %+v", got)
	}
	if len(got.Rules) != 2 {
		t.Errorf("rules = %v, want 2 from scopes", got.Rules)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("mapped device does not validate: %v", err)
	}

	for _, id := range []string{"", "nope", ulid.New().String(), d.ID.String() + "x"} {
		if _, err := is.DeviceByID(ctx, id); err != ErrDeviceNotFound {
			t.Errorf("DeviceByID(%q) err = %v, want ErrDeviceNotFound", id, err)
		}
	}

	bySub, err := is.DeviceBySubject(ctx, "device:"+d.ID.String())
	if err != nil || bySub.ID != d.ID.String() {
		t.Errorf("DeviceBySubject(device:id) = %v, %v", bySub, err)
	}
	bySpiffe, err := is.DeviceBySubject(ctx, "spiffe://example.org/gw/1")
	if err != nil || bySpiffe.ID != spiffe.ID.String() {
		t.Errorf("DeviceBySubject(spiffe) = %v, %v", bySpiffe, err)
	}
	// A device with a SPIFFE ID has that as its subject, so the device: form does not resolve it.
	for _, sub := range []string{"device:" + spiffe.ID.String(), "spiffe://example.org/other", "", "device:"} {
		if _, err := is.DeviceBySubject(ctx, sub); err != ErrDeviceNotFound {
			t.Errorf("DeviceBySubject(%q) err = %v, want ErrDeviceNotFound", sub, err)
		}
	}
	if _, err := is.DeviceByCertFingerprint(ctx, testFP); err != ErrDeviceNotFound {
		t.Errorf("DeviceByCertFingerprint err = %v", err)
	}

	if _, err := st.RevokeDevice(ctx, d.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err = is.DeviceByID(ctx, d.ID.String())
	if err != nil || got.Status != StatusRevoked || got.Active(time.Now()) {
		t.Errorf("revoked device = %+v, %v", got, err)
	}
}

// TestIdentityStoreRevokePurgesCache runs the whole path: registry device, JWT password, rules from
// scopes, a cached allow, then TheAuth.RevokeDevice, which must end the allow at once.
func TestIdentityStoreRevokePurgesCache(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	d := newRegistryDevice(t, st, nil)

	var purge Purger
	enc := make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		t.Fatal(err)
	}
	a, err := theauth.New(theauth.Config{
		Storage: st, BaseURL: "https://auth.example.com", EncryptionKey: enc,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:       "https://auth.example.com",
			Resources:    []theauth.ProtectedResource{{Identifier: "https://iot.example.com/api", Scopes: []string{"telemetry:write"}}},
			DeviceTokens: &theauth.DeviceTokensConfig{OnRevoke: purge.OnRevoke},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	audit := &memAudit{}
	key := []byte("jwt-key-0123456789")
	h, err := New(Config{
		Store: NewIdentityStore(st), BrokerSecret: brokerSecret, Audit: audit, AllowSampleRate: 1, CacheTTL: time.Hour,
		JWT: &JWTConfig{
			Keyfunc: func(*jwt.Token) (any, error) { return key, nil },
			Methods: []string{"HS256"}, Issuer: "https://auth.example.com", Audience: "mqtt",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	purge.Bind(h)

	post := func(path string, body any) map[string]any {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+brokerSecret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: d.Subject(), Issuer: "https://auth.example.com", Audience: jwt.ClaimStrings{"mqtt"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	id := d.ID.String()

	authn := post("/authn", map[string]string{"username": "x", "password": tok, "clientid": id})
	if authn["result"] != "allow" {
		t.Fatalf("authn = %v", authn)
	}
	pub := map[string]string{"device_id": id, "clientid": id, "action": "publish", "topic": "devices/" + id + "/telemetry/t"}
	if r := post("/authz", pub); r["result"] != "allow" {
		t.Fatalf("authz before revoke = %v", r)
	}
	other := map[string]string{"device_id": id, "clientid": id, "action": "publish", "topic": "devices/other/telemetry/t"}
	if r := post("/authz", other); r["result"] != "deny" {
		t.Fatalf("authz for another device's topic = %v", r)
	}

	if err := a.RevokeDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	// The cache TTL is an hour, so only the purge can explain an immediate deny.
	if r := post("/authz", pub); r["result"] != "deny" {
		t.Fatalf("authz after revoke = %v, want deny without waiting for the cache TTL", r)
	}
	if r := post("/authn", map[string]string{"username": "x", "password": tok, "clientid": id}); r["result"] != "deny" {
		t.Fatalf("authn after revoke = %v", r)
	}
	last := audit.events[len(audit.events)-1]
	if last.Code != CodeDeviceRevoked || last.Allowed {
		t.Errorf("last audit event = %+v, want code %s", last, CodeDeviceRevoked)
	}
}

func TestPurgerBeforeBindIsSafe(t *testing.T) {
	var p Purger
	p.OnRevoke(context.Background(), "x")
	p.Bind(nil)
}

func TestDecisionCodes(t *testing.T) {
	f := newFixture(t, nil)
	f.post("/authz", map[string]string{"device_id": "dev1", "clientid": "dev1", "action": "publish", "topic": "devices/dev1/telemetry/a"}, nil)
	f.post("/authz", map[string]string{"device_id": "dev1", "clientid": "dev1", "action": "publish", "topic": "nowhere"}, nil)
	f.post("/authz", map[string]string{"device_id": "ghost", "clientid": "ghost", "action": "publish", "topic": "a"}, nil)
	f.post("/authz", map[string]string{"device_id": "susp", "clientid": "susp", "action": "publish", "topic": "a"}, nil)
	f.post("/authz", map[string]string{"device_id": "revoked", "clientid": "revoked", "action": "publish", "topic": "a"}, nil)
	f.clock.Advance(time.Hour)
	f.post("/authz", map[string]string{"device_id": "short", "clientid": "short", "action": "publish", "topic": "a"}, nil)
	f.post("/authn", map[string]string{"username": "dev1", "password": "wrong", "clientid": "dev1"}, nil)
	f.post("/authn", map[string]string{"username": "susp", "password": "tok-s", "clientid": "susp"}, nil)
	var got []string
	for _, e := range f.audit.events {
		got = append(got, e.Kind+":"+e.Code)
	}
	want := []string{
		"authz:" + CodeAllowed, "authz:" + CodeNoPermission, "authz:" + CodeDeviceNotFound,
		"authz:" + CodeDeviceSuspended, "authz:" + CodeDeviceRevoked, "authz:" + CodeDeviceExpired,
		"authn:" + CodeInvalidCredential, "authn:" + CodeDeviceSuspended,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("codes = %v\nwant    %v", got, want)
	}
	for _, c := range []string{CodeAllowed, CodeNoPermission, CodeIndeterminate, CodeDeviceNotFound, CodeDeviceSuspended, CodeDeviceRevoked, CodeDeviceExpired} {
		if !policy.DecisionCode(c).Valid() {
			t.Errorf("%q is not a policy decision code", c)
		}
	}
}
