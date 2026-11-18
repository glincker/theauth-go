package mqttauth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/policy"
)

// These benchmarks cover what the broker hits on every publish and subscribe: topic matching,
// rule authorization, the decision cache, the device lookup and the HTTP wrapper around them.

func benchDevice() *Device {
	return &Device{
		ID: "dev1", OrgID: "org9", Status: StatusActive,
		Rules: []Rule{
			{Allow, ActionPublish, "devices/{device_id}/telemetry/#"},
			{Allow, ActionSubscribe, "devices/{device_id}/cmd/+"},
			{Allow, ActionSubscribe, "fleet/{org_id}/#"},
			{Deny, ActionAll, "fleet/{org_id}/secret/#"},
			{Allow, ActionAll, "shared/#"},
		},
	}
}

func BenchmarkMatchTopic(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !MatchTopic("devices/dev1/telemetry/#", "devices/dev1/telemetry/temp/42") {
			b.Fatal("want match")
		}
	}
}

func BenchmarkMatchTopicMiss(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if MatchTopic("devices/dev1/telemetry/#", "devices/dev2/telemetry/temp/42") {
			b.Fatal("want miss")
		}
	}
}

func BenchmarkFilterCovers(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !FilterCovers("fleet/org9/#", "fleet/org9/+/status") {
			b.Fatal("want cover")
		}
	}
}

func BenchmarkFiltersOverlap(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !FiltersOverlap("fleet/org9/secret/#", "fleet/+/secret/x") {
			b.Fatal("want overlap")
		}
	}
}

func BenchmarkValidateTopicName(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if ValidateTopicName("devices/dev1/telemetry/temp/42") != nil {
			b.Fatal("want valid")
		}
	}
}

func BenchmarkParseSubscription(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseSubscription("$share/group1/devices/dev1/cmd/+"); err != nil {
			b.Fatal(err)
		}
	}
}

func benchAuthorizer(b *testing.B, a Authorizer, action Action, topic string, want bool) {
	b.Helper()
	d := benchDevice()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if a.Authorize(ctx, d, action, topic).Allowed != want {
			b.Fatal("unexpected decision")
		}
	}
}

func BenchmarkRulePublishAllow(b *testing.B) {
	benchAuthorizer(b, RuleAuthorizer{}, ActionPublish, "devices/dev1/telemetry/temp/42", true)
}

func BenchmarkRulePublishDeny(b *testing.B) {
	benchAuthorizer(b, RuleAuthorizer{}, ActionPublish, "devices/dev2/telemetry/temp", false)
}

func BenchmarkRuleSubscribeWildcard(b *testing.B) {
	benchAuthorizer(b, RuleAuthorizer{}, ActionSubscribe, "fleet/org9/ops/+", true)
}

func benchPolicyAuthorizer() PolicyAuthorizer {
	pol := &policy.Policy{Version: policy.Version, Statements: []policy.Statement{
		{Effect: policy.Allow, Actions: []string{"publish"}, Resources: []string{"mqtt:devices:{device_id}:telemetry:*"}},
		{Effect: policy.Allow, Actions: []string{"subscribe"}, Resources: []string{"mqtt:devices:{device_id}:cmd:*", "mqtt:fleet:{org_id}:*"}},
		{Effect: policy.Deny, Actions: []string{"*"}, Resources: []string{"mqtt:fleet:{org_id}:secret:*"}},
	}}
	pols := []*policy.Policy{pol}
	return PolicyAuthorizer{Policies: func(context.Context, *Device) ([]*policy.Policy, error) { return pols, nil }}
}

func BenchmarkPolicyPublishAllow(b *testing.B) {
	benchAuthorizer(b, benchPolicyAuthorizer(), ActionPublish, "devices/dev1/telemetry/temp/42", true)
}

func BenchmarkPolicySubscribeWildcard(b *testing.B) {
	benchAuthorizer(b, benchPolicyAuthorizer(), ActionSubscribe, "fleet/org9/ops/+", true)
}

func BenchmarkPolicyPublishDeny(b *testing.B) {
	benchAuthorizer(b, benchPolicyAuthorizer(), ActionPublish, "devices/dev2/telemetry/temp", false)
}

// BenchmarkCacheDecisionHit is the warm cache lookup on one goroutine.
func BenchmarkCacheDecisionHit(b *testing.B) {
	c := newCache(time.Minute, 10000, time.Now)
	c.putDecision("dev1", "publish\x00devices/dev1/telemetry/temp", Decision{Allowed: true}, c.token("dev1"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.decision("dev1", "publish\x00devices/dev1/telemetry/temp"); !ok {
			b.Fatal("want hit")
		}
	}
}

// BenchmarkCacheParallel mixes device and decision lookups across many device IDs from every
// core, the shape a busy broker produces. It exposes lock contention.
func BenchmarkCacheParallel(b *testing.B) {
	c := newCache(time.Minute, 100000, time.Now)
	const n = 1000
	keys := make([]string, n)
	for i := range keys {
		id := "dev" + strconv.Itoa(i)
		keys[i] = id
		c.putDevice(&Device{ID: id, Status: StatusActive}, c.token(id))
		c.putDecision(id, "publish\x00t/"+id, Decision{Allowed: true}, c.token(id))
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			id := keys[i%n]
			i++
			if _, ok := c.device(id); !ok {
				b.Fatal("device miss")
			}
			if _, ok := c.decision(id, "publish\x00t/"+id); !ok {
				b.Fatal("decision miss")
			}
		}
	})
}

func benchHandler(b *testing.B, devices int, mut func(*Config)) (*Handler, *MemoryStore) {
	b.Helper()
	store := NewMemoryStore()
	for i := 0; i < devices; i++ {
		d := *benchDevice()
		d.ID = "dev" + strconv.Itoa(i)
		d.Subject = "spiffe://example.org/" + d.ID
		d.TokenHashes = []string{HashToken("tok-" + d.ID)}
		if err := store.PutDevice(context.Background(), d); err != nil {
			b.Fatal(err)
		}
	}
	cfg := Config{Store: store, BrokerSecret: "broker-secret-0123456789", AllowSampleRate: -1}
	if mut != nil {
		mut(&cfg)
	}
	h, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	return h, store
}

// authzBody is the JSON the broker posts for a publish check.
func authzBody(id, topic string) []byte {
	return []byte(fmt.Sprintf(`{"username":%q,"clientid":%q,"action":"publish","topic":%q,"peerhost":"10.0.0.1"}`, id, id, topic))
}

// authzRequest builds one reusable request; call resetBody before each use.
func authzRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/authz", nil)
	r.Header.Set("Authorization", "Bearer broker-secret-0123456789")
	r.Header.Set("Content-Type", "application/json")
	return r
}

func resetBody(r *http.Request, body []byte) { r.Body = io.NopCloser(bytes.NewReader(body)) }

// BenchmarkAuthorizeCached is Handler.authorize with a warm device and decision cache.
func BenchmarkAuthorizeCached(b *testing.B) {
	h, _ := benchHandler(b, 100, nil)
	req := brokerRequest{Username: "dev1", ClientID: "dev1"}
	ctx := context.Background()
	h.authorize(ctx, req, ActionPublish, "devices/dev1/telemetry/temp")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d, _, _ := h.authorize(ctx, req, ActionPublish, "devices/dev1/telemetry/temp"); !d.Allowed {
			b.Fatal("want allow")
		}
	}
}

// BenchmarkAuthorizeUncached disables the cache, so every call loads the device and evaluates.
func BenchmarkAuthorizeUncached(b *testing.B) {
	h, _ := benchHandler(b, 100, func(c *Config) { c.CacheTTL = -1 })
	req := brokerRequest{Username: "dev1", ClientID: "dev1"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d, _, _ := h.authorize(ctx, req, ActionPublish, "devices/dev1/telemetry/temp"); !d.Allowed {
			b.Fatal("want allow")
		}
	}
}

// BenchmarkAuthorizeUncachedBigRegistry is the same against 10000 devices in the memory store.
func BenchmarkAuthorizeUncachedBigRegistry(b *testing.B) {
	h, _ := benchHandler(b, 10000, func(c *Config) { c.CacheTTL = -1 })
	req := brokerRequest{Username: "dev1", ClientID: "dev1"}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if d, _, _ := h.authorize(ctx, req, ActionPublish, "devices/dev1/telemetry/temp"); !d.Allowed {
			b.Fatal("want allow")
		}
	}
}

// BenchmarkServeAuthzHTTP is the full POST /authz handler without a network: JSON decode, broker
// auth, authorize, counters, JSON encode. The request is built once, only the body is reset.
func BenchmarkServeAuthzHTTP(b *testing.B) {
	h, _ := benchHandler(b, 100, nil)
	body := authzBody("dev1", "devices/dev1/telemetry/temp")
	r := authzRequest()
	w := httptest.NewRecorder()
	resetBody(r, body)
	h.ServeHTTP(w, r)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		resetBody(r, body)
		h.ServeHTTP(w, r)
	}
}

// BenchmarkServeAuthzHTTPParallel runs the handler from every core against 1000 devices.
func BenchmarkServeAuthzHTTPParallel(b *testing.B) {
	h, _ := benchHandler(b, 1000, nil)
	bodies := make([][]byte, 1000)
	for i := range bodies {
		id := "dev" + strconv.Itoa(i)
		bodies[i] = authzBody(id, "devices/"+id+"/telemetry/temp")
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := httptest.NewRecorder()
		r := authzRequest()
		i := 0
		for pb.Next() {
			w.Body.Reset()
			resetBody(r, bodies[i%1000])
			i++
			h.ServeHTTP(w, r)
		}
	})
}

// BenchmarkMemoryStoreDeviceByID is the registry lookup the cache falls back to.
func BenchmarkMemoryStoreDeviceByID(b *testing.B) {
	for _, n := range []int{10, 1000, 10000} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			_, store := benchHandler(b, n, nil)
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := store.DeviceByID(ctx, "dev"+strconv.Itoa(n/2)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMemoryStoreDeviceBySubject(b *testing.B) {
	_, store := benchHandler(b, 1000, nil)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.DeviceBySubject(ctx, "spiffe://example.org/dev500"); err != nil {
			b.Fatal(err)
		}
	}
}
