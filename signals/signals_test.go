package signals

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testKeys struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	sig  Signer
}

func newKeys(t *testing.T) testKeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKeys{pub: pub, priv: priv, sig: NewKeySigner("k1", "EdDSA", priv)}
}

func (k testKeys) resolve(kid string) (string, crypto.PublicKey, bool) {
	if kid != "k1" {
		return "", nil, false
	}
	return "EdDSA", k.pub, true
}

func (k testKeys) jwks() map[string]any {
	return map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(k.pub),
	}}}
}

func sampleSET(iss, aud string) *SET {
	return &SET{Issuer: iss, Audience: []string{aud}, IssuedAt: time.Now(), JTI: newID(),
		Events: []Event{NewSessionRevoked(IssSub(iss, "user-1"), time.Now(), "admin", "policy")}}
}

func TestSETRoundTrip(t *testing.T) {
	k := newKeys(t)
	set := sampleSET("https://idp.example", "https://rp.example")
	set.TransactionID = "txn-1"
	tok, err := set.Sign(k.sig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(tok, k.resolve, VerifyOptions{Issuer: "https://idp.example", Audience: "https://rp.example"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.JTI != set.JTI || got.TransactionID != "txn-1" || len(got.Events) != 1 {
		t.Fatalf("unexpected SET: %+v", got)
	}
	ev := got.Events[0]
	if ev.Type != EventSessionRevoked || ev.Subject.Sub != "user-1" || ev.Subject.Format != FormatIssSub {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Properties["initiating_entity"] != "admin" {
		t.Fatalf("lost property: %+v", ev.Properties)
	}
	// No exp claim is required or emitted.
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if strings.Contains(string(payload), `"exp"`) {
		t.Fatal("SET must not carry exp")
	}
}

func TestSETRejections(t *testing.T) {
	k := newKeys(t)
	other := newKeys(t)
	tok, err := sampleSET("https://idp.example", "rp").Sign(k.sig)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	forged, _ := json.Marshal(map[string]any{"iss": "https://idp.example", "aud": "rp", "iat": time.Now().Unix(), "jti": "x",
		"events": map[string]any{EventAccountDisabled: map[string]any{}}})
	otherTok, _ := sampleSET("https://idp.example", "rp").Sign(other.sig)
	cases := map[string]struct {
		token string
		opts  VerifyOptions
	}{
		"tampered payload": {parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2], VerifyOptions{}},
		"wrong key":        {otherTok, VerifyOptions{}},
		"garbage":          {"not-a-jwt", VerifyOptions{}},
		"wrong issuer":     {tok, VerifyOptions{Issuer: "https://evil.example"}},
		"wrong audience":   {tok, VerifyOptions{Audience: "someone-else"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(c.token, k.resolve, c.opts); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	t.Run("wrong typ", func(t *testing.T) {
		wrong := SignerFunc(func(p map[string]any) (string, error) { return signWithTyp(t, k, p, "JWT") })
		set := sampleSET("https://idp.example", "rp")
		tok, err := set.Sign(wrong)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(tok, k.resolve, VerifyOptions{}); err == nil {
			t.Fatal("typ JWT must be rejected")
		}
	})
	t.Run("future iat", func(t *testing.T) {
		s := sampleSET("https://idp.example", "rp")
		s.IssuedAt = time.Now().Add(time.Hour)
		tok, _ := s.Sign(k.sig)
		if _, err := Verify(tok, k.resolve, VerifyOptions{}); err == nil {
			t.Fatal("future iat must be rejected")
		}
	})
}

func signWithTyp(t *testing.T, k testKeys, payload map[string]any, typ string) (string, error) {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": typ, "kid": "k1"})
	body, _ := json.Marshal(payload)
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(in))), nil
}

func TestSubjectFormats(t *testing.T) {
	subjects := []Subject{
		IssSub("https://i", "s"), EmailSubject("a@b.c"), Opaque("o1"),
		{Format: FormatPhoneNumber, PhoneNumber: "+15555550100"},
		{Format: FormatAccount, URI: "acct:a@b.c"},
		ComplexSubject(map[string]Subject{"user": EmailSubject("a@b.c"), "device": Opaque("d1")}),
	}
	for _, s := range subjects {
		if err := s.Validate(); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var back Subject
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Key() != s.Key() {
			t.Fatalf("round trip mismatch: %s vs %s", back.Key(), s.Key())
		}
	}
	if err := (Subject{Format: FormatEmail, Email: "nope"}).Validate(); err == nil {
		t.Fatal("bad email must fail validation")
	}
	if EmailSubject("A@B.c").Key() != EmailSubject("a@b.C").Key() {
		t.Fatal("email keys must be case-insensitive")
	}
}

func TestEventBuilders(t *testing.T) {
	s := Opaque("x")
	at := time.Unix(1700000000, 0)
	evs := []Event{
		NewSessionRevoked(s, at, "admin", ""), NewCredentialChange(s, at, "password", "update"),
		NewTokenClaimsChange(s, at, map[string]any{"role": "admin"}),
		NewAssuranceLevelChange(s, at, "AAL1", "AAL2", "increase"),
		NewDeviceComplianceChange(s, at, "compliant", "not-compliant"),
		NewAccountDisabled(s, "hijacking"), NewAccountEnabled(s),
		NewCredentialCompromise(s, at, "password", ""), NewSessionsRevoked(s),
	}
	for _, e := range evs {
		if !isSupported(e.Type) {
			t.Errorf("%s not in SupportedEvents", e.Type)
		}
		if e.Payload()["subject"] == nil {
			t.Errorf("%s lost subject", e.Type)
		}
	}
}

// --- transmitter ---

type fixture struct {
	tx   *Transmitter
	keys testKeys
	srv  *httptest.Server
	now  *fakeClock
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newFixture(t *testing.T, mutate func(*TransmitterConfig)) *fixture {
	t.Helper()
	keys := newKeys(t)
	clk := &fakeClock{t: time.Now()}
	f := &fixture{keys: keys, now: clk}
	mux := http.NewServeMux()
	cfg := TransmitterConfig{
		Signer:               keys.sig,
		Authenticate:         StaticBearerAuth(map[string]string{"tok-a": "recv-a", "tok-b": "recv-b"}),
		AllowPrivateNetworks: true, AllowInsecureHTTP: true,
		Clock: clk.Now, BackoffBase: time.Second, BackoffMax: time.Minute, MaxAttempts: 3, MaxPollWait: -1,
	}
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	cfg.Issuer, cfg.BaseURL, cfg.JWKSURI = f.srv.URL, f.srv.URL, f.srv.URL+"/jwks"
	if mutate != nil {
		mutate(&cfg)
	}
	tx, err := NewTransmitter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.tx = tx
	mux.Handle("/", tx.Handler())
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(keys.jwks()) })
	return f
}

func (f *fixture) call(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestMetadata(t *testing.T) {
	f := newFixture(t, nil)
	code, m := f.call(t, "GET", "/.well-known/ssf-configuration", "", nil)
	if code != 200 || m["issuer"] != f.srv.URL || m["spec_version"] != "1_0" || m["jwks_uri"] == "" {
		t.Fatalf("metadata: %d %v", code, m)
	}
	for _, k := range []string{"configuration_endpoint", "status_endpoint", "add_subject_endpoint", "remove_subject_endpoint", "verification_endpoint", "delivery_methods_supported"} {
		if m[k] == nil {
			t.Errorf("metadata missing %s", k)
		}
	}
}

func TestStreamManagementAndAuth(t *testing.T) {
	f := newFixture(t, nil)
	if code, _ := f.call(t, "POST", "/ssf/stream", "", map[string]any{}); code != 401 {
		t.Fatalf("unauthenticated create: %d", code)
	}
	code, s := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{
		"delivery":         map[string]any{"method": MethodPush, "endpoint_url": "http://example.test/push", "authorization_header": "Bearer secret"},
		"events_requested": []string{EventSessionRevoked, "https://unknown/event"},
	})
	if code != 201 {
		t.Fatalf("create: %d %v", code, s)
	}
	id := s["stream_id"].(string)
	if d := s["delivery"].(map[string]any); d["authorization_header"] != nil {
		t.Fatal("authorization_header must not be echoed")
	}
	if del := s["events_delivered"].([]any); len(del) != 1 || del[0] != EventSessionRevoked {
		t.Fatalf("events_delivered: %v", del)
	}
	// other receiver cannot see it
	if code, _ := f.call(t, "GET", "/ssf/stream?stream_id="+id, "tok-b", nil); code != 404 {
		t.Fatalf("cross receiver read: %d", code)
	}
	if code, _ := f.call(t, "GET", "/ssf/stream?stream_id="+id, "tok-a", nil); code != 200 {
		t.Fatalf("read: %d", code)
	}
	code, s = f.call(t, "PATCH", "/ssf/stream", "tok-a", map[string]any{"stream_id": id, "description": "hello"})
	if code != 200 || s["description"] != "hello" {
		t.Fatalf("patch: %d %v", code, s)
	}
	code, st := f.call(t, "POST", "/ssf/status", "tok-a", map[string]any{"stream_id": id, "status": "paused"})
	if code != 200 || st["status"] != "paused" {
		t.Fatalf("status: %d %v", code, st)
	}
	if code, _ := f.call(t, "POST", "/ssf/status", "tok-a", map[string]any{"stream_id": id, "status": "bogus"}); code != 400 {
		t.Fatalf("bad status: %d", code)
	}
	if code, _ := f.call(t, "POST", "/ssf/subjects/add", "tok-a", map[string]any{"stream_id": id, "subject": map[string]any{"format": "email", "email": "a@b.c"}}); code != 200 {
		t.Fatalf("add subject: %d", code)
	}
	if code, _ := f.call(t, "POST", "/ssf/subjects/add", "tok-a", map[string]any{"stream_id": id, "subject": map[string]any{"format": "email"}}); code != 400 {
		t.Fatalf("invalid subject: %d", code)
	}
	if n, _ := f.tx.Store().CountSubjects(context.Background(), id); n != 1 {
		t.Fatalf("subjects: %d", n)
	}
	if code, _ := f.call(t, "POST", "/ssf/subjects/remove", "tok-a", map[string]any{"stream_id": id, "subject": map[string]any{"format": "email", "email": "A@B.c"}}); code != 200 {
		t.Fatalf("remove subject: %d", code)
	}
	if n, _ := f.tx.Store().CountSubjects(context.Background(), id); n != 0 {
		t.Fatalf("subjects after remove: %d", n)
	}
	if code, _ := f.call(t, "DELETE", "/ssf/stream?stream_id="+id, "tok-a", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := f.call(t, "GET", "/ssf/stream?stream_id="+id, "tok-a", nil); code != 404 {
		t.Fatalf("read after delete: %d", code)
	}
}

func TestSSRFRejection(t *testing.T) {
	f := newFixture(t, func(c *TransmitterConfig) {
		c.AllowPrivateNetworks, c.AllowInsecureHTTP = false, false
		c.Lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "rebind.example":
				return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
			case "ok.example":
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}
			return nil, errors.New("nxdomain")
		}
	})
	bad := []string{
		"http://ok.example/push",          // plain http
		"https://127.0.0.1/push",          // loopback literal
		"https://169.254.169.254/latest",  // cloud metadata
		"https://[::1]/push",              // v6 loopback
		"https://10.1.2.3/push",           // private
		"https://100.64.0.1/push",         // CGNAT
		"https://localhost/push",          // name
		"https://rebind.example/push",     // resolves to private
		"https://user:pw@ok.example/push", // credentials
		"https://nxdomain.example/push",   // unresolvable
		"ftp://ok.example/push",           // scheme
		"https://ok.example/push#frag",    // fragment
	}
	for _, u := range bad {
		code, body := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{"delivery": map[string]any{"method": MethodPush, "endpoint_url": u}})
		if code != 400 {
			t.Errorf("%s: want 400 got %d %v", u, code, body)
		}
	}
	code, body := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{"delivery": map[string]any{"method": MethodPush, "endpoint_url": "https://ok.example/push"}})
	if code != 201 {
		t.Fatalf("public https endpoint must be accepted: %d %v", code, body)
	}
}

func TestSSRFDialGuard(t *testing.T) {
	// A stream whose URL passes validation but whose connection lands on
	// loopback (DNS rebinding) must be refused by the dialer.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(202) }))
	defer target.Close()
	f := newFixture(t, func(c *TransmitterConfig) {
		c.AllowPrivateNetworks = false
		c.AllowInsecureHTTP = true
		c.Lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		c.PushTimeout = 2 * time.Second
	})
	ctx := context.Background()
	s := Stream{ID: "s1", ReceiverID: "recv-a", Status: StatusEnabled, EventsDelivered: SupportedEvents(),
		Delivery: DeliveryConfig{Method: MethodPush, EndpointURL: strings.Replace(target.URL, "127.0.0.1", "rebind.example", 1)}}
	_ = f.tx.Store().CreateStream(ctx, s)
	// the dial resolves rebind.example via system DNS and fails: either way nothing is delivered
	if err := f.tx.Emit(ctx, NewAccountEnabled(Opaque("u"))); err != nil {
		t.Fatal(err)
	}
	res, _ := f.tx.DeliverDue(ctx)
	if res.Delivered != 0 {
		t.Fatalf("must not deliver: %+v", res)
	}
}

func TestPushDeliveryRetryAndBackoff(t *testing.T) {
	var hits atomic.Int32
	var gotAuth, gotCT atomic.Value
	var lastBody atomic.Value
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		gotAuth.Store(r.Header.Get("Authorization"))
		gotCT.Store(r.Header.Get("Content-Type"))
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(string(b))
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer recv.Close()
	f := newFixture(t, func(c *TransmitterConfig) { c.MaxAttempts = 5 })
	code, s := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{
		"delivery": map[string]any{"method": MethodPush, "endpoint_url": recv.URL, "authorization_header": "Bearer rcv-secret"},
	})
	if code != 201 {
		t.Fatalf("create: %d %v", code, s)
	}
	ctx := context.Background()
	if err := f.tx.Emit(ctx, NewSessionsRevoked(IssSub(f.srv.URL, "u1"))); err != nil {
		t.Fatal(err)
	}
	res, _ := f.tx.DeliverDue(ctx)
	if res.Retried != 1 || res.Delivered != 0 {
		t.Fatalf("pass 1: %+v", res)
	}
	// not due yet: nothing happens before the backoff elapses
	res, _ = f.tx.DeliverDue(ctx)
	if res != (DeliveryResult{}) || hits.Load() != 1 {
		t.Fatalf("pass 1b should be idle: %+v hits=%d", res, hits.Load())
	}
	f.now.Advance(1100 * time.Millisecond) // base 1s after first failure
	res, _ = f.tx.DeliverDue(ctx)
	if res.Retried != 1 {
		t.Fatalf("pass 2: %+v", res)
	}
	f.now.Advance(1500 * time.Millisecond) // second delay is 2s: still not due
	if res, _ = f.tx.DeliverDue(ctx); res != (DeliveryResult{}) {
		t.Fatalf("backoff must double: %+v", res)
	}
	f.now.Advance(time.Second)
	res, _ = f.tx.DeliverDue(ctx)
	if res.Delivered != 1 {
		t.Fatalf("pass 3: %+v", res)
	}
	if gotAuth.Load() != "Bearer rcv-secret" || gotCT.Load() != "application/secevent+jwt" {
		t.Fatalf("headers: %v %v", gotAuth.Load(), gotCT.Load())
	}
	set, err := Verify(lastBody.Load().(string), f.keys.resolve, VerifyOptions{Issuer: f.srv.URL, Audience: "recv-a"})
	if err != nil || set.Events[0].Type != EventSessionsRevoked {
		t.Fatalf("delivered SET invalid: %v %+v", err, set)
	}
	if n, _ := f.tx.Store().CountPending(ctx, s["stream_id"].(string)); n != 0 {
		t.Fatalf("queue not drained: %d", n)
	}
}

func TestPushPermanentFailureAndMaxAttempts(t *testing.T) {
	status := atomic.Int32{}
	status.Store(400)
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(status.Load())) }))
	defer recv.Close()
	f := newFixture(t, func(c *TransmitterConfig) { c.MaxAttempts = 2 })
	_, s := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{"delivery": map[string]any{"method": MethodPush, "endpoint_url": recv.URL}})
	id := s["stream_id"].(string)
	ctx := context.Background()
	_ = f.tx.Emit(ctx, NewAccountEnabled(Opaque("u")))
	if res, _ := f.tx.DeliverDue(ctx); res.Dropped != 1 {
		t.Fatalf("400 must drop: %+v", res)
	}
	status.Store(500)
	_ = f.tx.Emit(ctx, NewAccountEnabled(Opaque("u")))
	if res, _ := f.tx.DeliverDue(ctx); res.Retried != 1 {
		t.Fatalf("500 must retry: %+v", res)
	}
	f.now.Advance(time.Minute)
	if res, _ := f.tx.DeliverDue(ctx); res.Dropped != 1 {
		t.Fatalf("attempts exhausted must drop: %+v", res)
	}
	if n, _ := f.tx.Store().CountPending(ctx, id); n != 0 {
		t.Fatalf("queue: %d", n)
	}
}

func TestPollDeliveryAckAndMaxEvents(t *testing.T) {
	f := newFixture(t, nil)
	code, s := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{"delivery": map[string]any{"method": MethodPoll}})
	if code != 201 {
		t.Fatalf("create: %d %v", code, s)
	}
	id := s["stream_id"].(string)
	pollURL := s["delivery"].(map[string]any)["endpoint_url"].(string)
	if !strings.HasSuffix(pollURL, "/ssf/poll/"+id) {
		t.Fatalf("poll url: %s", pollURL)
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := f.tx.Emit(ctx, NewSessionRevoked(Opaque("u"), time.Now(), "", "")); err != nil {
			t.Fatal(err)
		}
		f.now.Advance(time.Millisecond)
	}
	path := "/ssf/poll/" + id
	_, r1 := f.call(t, "POST", path, "tok-a", map[string]any{"maxEvents": 2, "returnImmediately": true})
	sets := r1["sets"].(map[string]any)
	if len(sets) != 2 || r1["moreAvailable"] != true {
		t.Fatalf("first poll: %v", r1)
	}
	// without ack the same SETs come back
	_, r2 := f.call(t, "POST", path, "tok-a", map[string]any{"maxEvents": 2, "returnImmediately": true})
	if len(r2["sets"].(map[string]any)) != 2 {
		t.Fatalf("unacked redelivery: %v", r2)
	}
	var acks []string
	for jti, tok := range sets {
		acks = append(acks, jti)
		if _, err := Verify(tok.(string), f.keys.resolve, VerifyOptions{Audience: "recv-a"}); err != nil {
			t.Fatalf("polled SET invalid: %v", err)
		}
	}
	_, r3 := f.call(t, "POST", path, "tok-a", map[string]any{"ack": acks, "returnImmediately": true})
	if len(r3["sets"].(map[string]any)) != 1 || r3["moreAvailable"] != false {
		t.Fatalf("after ack: %v", r3)
	}
	for jti := range r3["sets"].(map[string]any) {
		acks = []string{jti}
	}
	_, r4 := f.call(t, "POST", path, "tok-a", map[string]any{"ack": acks, "returnImmediately": true})
	if len(r4["sets"].(map[string]any)) != 0 {
		t.Fatalf("drained: %v", r4)
	}
	if code, _ := f.call(t, "POST", path, "tok-b", map[string]any{}); code != 404 {
		t.Fatalf("cross receiver poll: %d", code)
	}
}

func TestSubjectFilteringAndEventFiltering(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	_, s := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{
		"delivery":         map[string]any{"method": MethodPoll},
		"events_requested": []string{EventAccountDisabled},
	})
	id := s["stream_id"].(string)
	f.call(t, "POST", "/ssf/subjects/add", "tok-a", map[string]any{"stream_id": id, "subject": map[string]any{"format": "email", "email": "me@x.y"}})
	_ = f.tx.Emit(ctx,
		NewAccountDisabled(EmailSubject("other@x.y"), ""), // wrong subject
		NewSessionsRevoked(EmailSubject("me@x.y")),        // wrong type
		NewAccountDisabled(EmailSubject("ME@x.y"), ""),    // match
	)
	if n, _ := f.tx.Store().CountPending(ctx, id); n != 1 {
		t.Fatalf("want exactly 1 queued, got %d", n)
	}
	// paused streams keep queueing, disabled streams drop
	f.call(t, "POST", "/ssf/status", "tok-a", map[string]any{"stream_id": id, "status": "disabled"})
	_ = f.tx.Emit(ctx, NewAccountDisabled(EmailSubject("me@x.y"), ""))
	if n, _ := f.tx.Store().CountPending(ctx, id); n != 1 {
		t.Fatalf("disabled stream must not queue: %d", n)
	}
}

func TestVerificationEvent(t *testing.T) {
	f := newFixture(t, nil)
	_, s := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{"delivery": map[string]any{"method": MethodPoll}})
	id := s["stream_id"].(string)
	if code, _ := f.call(t, "POST", "/ssf/verify", "tok-a", map[string]any{"stream_id": id, "state": "abc123"}); code != 204 {
		t.Fatalf("verify: %d", code)
	}
	_, r := f.call(t, "POST", "/ssf/poll/"+id, "tok-a", map[string]any{"returnImmediately": true})
	for _, tok := range r["sets"].(map[string]any) {
		set, err := Verify(tok.(string), f.keys.resolve, VerifyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ev := set.Events[0]
		if ev.Type != EventVerification || ev.Properties["state"] != "abc123" {
			t.Fatalf("verification event: %+v", ev)
		}
		return
	}
	t.Fatal("no verification SET delivered")
}

// --- receiver ---

func newReceiverFixture(t *testing.T, f *fixture, h ...Handler) (*Receiver, *httptest.Server) {
	t.Helper()
	rx, err := NewReceiver(ReceiverConfig{
		Audience: "https://rp.example", Issuers: map[string]string{f.srv.URL: ""},
		AllowPrivateNetworks: true, AllowInsecureHTTP: true, Handlers: h,
		Authenticate: func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer push-secret" },
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(rx)
	t.Cleanup(srv.Close)
	return rx, srv
}

func TestReceiverEndToEndPushRevokesSessions(t *testing.T) {
	f := newFixture(t, nil)
	var mu sync.Mutex
	revoked := map[string]int{}
	h := SessionRevocationHandler(SessionRevocationConfig{
		ResolveUser: func(_ context.Context, sub Subject) (string, bool, error) {
			if sub.Format == FormatEmail && sub.Email == "alice@example.com" {
				return "user-alice", true, nil
			}
			return "", false, nil
		},
		RevokeSessions: func(_ context.Context, uid string) error {
			mu.Lock()
			revoked[uid]++
			mu.Unlock()
			return nil
		},
	})
	_, rxSrv := newReceiverFixture(t, f, h)
	code, s := f.call(t, "POST", "/ssf/stream", "tok-a", map[string]any{
		"aud":      "https://rp.example",
		"delivery": map[string]any{"method": MethodPush, "endpoint_url": rxSrv.URL, "authorization_header": "Bearer push-secret"},
	})
	if code != 201 {
		t.Fatalf("create: %d %v", code, s)
	}
	ctx := context.Background()
	for _, ev := range []Event{
		NewSessionsRevoked(EmailSubject("alice@example.com")),
		NewAccountDisabled(ComplexSubject(map[string]Subject{"user": EmailSubject("alice@example.com")}), ""),
		NewSessionsRevoked(EmailSubject("stranger@example.com")),                                 // unknown user: ignored
		NewCredentialChange(EmailSubject("alice@example.com"), time.Now(), "password", "update"), // not a revocation
	} {
		if err := f.tx.Emit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	res, err := f.tx.DeliverDue(ctx)
	if err != nil || res.Delivered != 4 {
		t.Fatalf("deliver: %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if revoked["user-alice"] != 2 || len(revoked) != 1 {
		t.Fatalf("revocations: %v", revoked)
	}
}

func TestReceiverRejections(t *testing.T) {
	f := newFixture(t, nil)
	var calls atomic.Int32
	rx, srv := newReceiverFixture(t, f, HandlerFunc(func(context.Context, *SET, Event) error { calls.Add(1); return nil }))
	ctx := context.Background()
	post := func(tok, auth string) int {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(tok))
		req.Header.Set("Content-Type", "application/secevent+jwt")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	good := sampleSET(f.srv.URL, "https://rp.example")
	tok, _ := good.Sign(f.keys.sig)

	if c := post(tok, ""); c != 401 {
		t.Fatalf("unauthenticated push: %d", c)
	}
	if c := post(tok, "Bearer push-secret"); c != 202 {
		t.Fatalf("good push: %d", c)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls: %d", calls.Load())
	}
	// replay: acknowledged, but handlers do not run again
	if c := post(tok, "Bearer push-secret"); c != 202 {
		t.Fatalf("replay: %d", c)
	}
	if calls.Load() != 1 {
		t.Fatalf("replay re-ran handlers: %d", calls.Load())
	}
	if _, err := rx.Handle(ctx, tok); !errors.Is(err, ErrReplay) {
		t.Fatalf("Handle replay: %v", err)
	}
	// tampered
	parts := strings.Split(mustSign(t, f, sampleSET(f.srv.URL, "https://rp.example")), ".")
	evil, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "aud": "https://rp.example", "iat": time.Now().Unix(), "jti": "evil",
		"events": map[string]any{EventSessionsRevoked: map[string]any{"subject": map[string]any{"format": "opaque", "id": "x"}}}})
	if c := post(parts[0]+"."+base64.RawURLEncoding.EncodeToString(evil)+"."+parts[2], "Bearer push-secret"); c != 400 {
		t.Fatalf("tampered: %d", c)
	}
	// wrong audience
	if c := post(mustSign(t, f, sampleSET(f.srv.URL, "https://other.example")), "Bearer push-secret"); c != 400 {
		t.Fatalf("wrong aud: %d", c)
	}
	// untrusted issuer, even if validly signed by some key
	rogue := newKeys(t)
	rs := sampleSET("https://rogue.example", "https://rp.example")
	rtok, _ := rs.Sign(rogue.sig)
	if c := post(rtok, "Bearer push-secret"); c != 400 {
		t.Fatalf("untrusted issuer: %d", c)
	}
	var re *ReceiveError
	_, err := rx.Handle(ctx, rtok)
	if !errors.As(err, &re) || re.Code != CodeInvalidIssuer {
		t.Fatalf("issuer code: %v", err)
	}
	// signed with an unpublished key but claiming the trusted issuer
	forged := sampleSET(f.srv.URL, "https://rp.example")
	ftok, _ := forged.Sign(rogue.sig)
	if c := post(ftok, "Bearer push-secret"); c != 400 {
		t.Fatalf("forged signature: %d", c)
	}
	// wrong content type
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(tok))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer push-secret")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 400 {
		t.Fatalf("content type: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if calls.Load() != 1 {
		t.Fatalf("rejected SETs reached handlers: %d", calls.Load())
	}
}

func mustSign(t *testing.T, f *fixture, s *SET) string {
	t.Helper()
	tok, err := s.Sign(f.keys.sig)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestReceiverHandlerFailureAllowsRetry(t *testing.T) {
	f := newFixture(t, nil)
	var fail atomic.Bool
	fail.Store(true)
	rx, _ := newReceiverFixture(t, f, HandlerFunc(func(context.Context, *SET, Event) error {
		if fail.Load() {
			return errors.New("boom")
		}
		return nil
	}))
	tok := mustSign(t, f, sampleSET(f.srv.URL, "https://rp.example"))
	if _, err := rx.Handle(context.Background(), tok); err == nil {
		t.Fatal("expected handler failure")
	}
	fail.Store(false)
	if _, err := rx.Handle(context.Background(), tok); err != nil {
		t.Fatalf("retry after handler failure must be processed: %v", err)
	}
}

func TestReceiverRefetchesKeysOnRotation(t *testing.T) {
	k1, k2 := newKeys(t), newKeys(t)
	k2.sig = rekey(t, k2, "k2")
	var current atomic.Value
	current.Store(k1.jwks())
	var fetches atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(current.Load())
	})
	rx, err := NewReceiver(ReceiverConfig{Audience: "rp", Issuers: map[string]string{srv.URL: ""},
		AllowPrivateNetworks: true, AllowInsecureHTTP: true, JWKSRefetchCooldown: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	t1, _ := sampleSET(srv.URL, "rp").Sign(k1.sig)
	if _, err := rx.Handle(ctx, t1); err != nil {
		t.Fatal(err)
	}
	t2, _ := sampleSET(srv.URL, "rp").Sign(k2.sig)
	if _, err := rx.Handle(ctx, t2); err == nil {
		t.Fatal("unknown kid must fail before the JWKS publishes it")
	}
	pubs := k2.jwks()
	pubs["keys"].([]map[string]string)[0]["kid"] = "k2"
	current.Store(pubs)
	if _, err := rx.Handle(ctx, t2); err != nil {
		t.Fatalf("rotated key must be picked up: %v", err)
	}
	if fetches.Load() < 2 {
		t.Fatalf("expected a refetch, got %d", fetches.Load())
	}
}

func rekey(t *testing.T, k testKeys, kid string) Signer {
	t.Helper()
	return SignerFunc(func(p map[string]any) (string, error) {
		hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": TypeSET, "kid": kid})
		body, _ := json.Marshal(p)
		in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, []byte(in))), nil
	})
}

func TestEventsFromAudit(t *testing.T) {
	subj := IssSubSubjects("https://idp")
	ctx := context.Background()
	at := time.Now()
	cases := []struct {
		action, ttype, tid, user string
		want                     string
	}{
		{"session.revoked", "user", "u1", "", EventSessionsRevoked},
		{"session.revoked", "session", "s1", "u1", EventSessionRevoked},
		{"user.logout", "session", "s1", "", EventSessionRevoked},
		{"password.changed", "user", "u1", "", EventCredentialChange},
		{"account.disabled", "user", "u1", "", EventAccountDisabled},
		{"account.enabled", "user", "u1", "", EventAccountEnabled},
	}
	for _, c := range cases {
		evs := EventsFromAudit(ctx, subj, c.action, c.ttype, c.tid, nil, c.user, at)
		if len(evs) != 1 || evs[0].Type != c.want {
			t.Errorf("%s/%s: %+v", c.action, c.ttype, evs)
		}
	}
	if evs := EventsFromAudit(ctx, subj, "login.failed", "user", "u1", nil, "", at); evs != nil {
		t.Errorf("unmapped action produced %+v", evs)
	}
	ev := EventsFromAudit(ctx, subj, "session.revoked", "session", "s1", nil, "u1", at)[0]
	if _, ok := ev.Subject.Complex["session"]; !ok || ev.Subject.Complex["user"].Sub != "u1" {
		t.Errorf("session revoke subject: %+v", ev.Subject)
	}
}
