package tokenvault_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/glincker/theauth-go/v2/tokenvault"
)

type stubRefresher struct {
	calls atomic.Int32
	resp  tokenvault.TokenResponse
	err   error
}

func (s *stubRefresher) Refresh(_ context.Context, rt string) (tokenvault.TokenResponse, error) {
	s.calls.Add(1)
	if rt != "refresh-1" && rt != "refresh-2" {
		return tokenvault.TokenResponse{}, errors.New("unexpected refresh token")
	}
	return s.resp, s.err
}

type auditLog struct {
	mu   sync.Mutex
	evs  []tokenvault.Event
	fail bool
}

func (a *auditLog) Record(_ context.Context, e tokenvault.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail && e.Action == tokenvault.ActionTokenIssued {
		return errors.New("sink down")
	}
	a.evs = append(a.evs, e)
	return nil
}

func (a *auditLog) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.evs {
		out = append(out, e.Action)
	}
	return out
}

type fixture struct {
	v     *tokenvault.Vault
	store *memory.Store
	ring  *tokenvault.KeyRing
	audit *auditLog
	ref   *stubRefresher
	now   *time.Time
	allow *atomic.Bool
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ring, err := tokenvault.NewKeyRing("k1", map[string][]byte{"k1": key(1)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	f := &fixture{store: memory.New(), ring: ring, audit: &auditLog{}, now: &now, allow: &atomic.Bool{}}
	f.allow.Store(true)
	f.ref = &stubRefresher{resp: tokenvault.TokenResponse{AccessToken: "access-2", ExpiresIn: time.Hour}}
	f.v, err = tokenvault.New(tokenvault.Config{
		Store: f.store, Keys: ring, Audit: f.audit,
		Providers: map[string]tokenvault.Refresher{"acme": f.ref},
		Clock:     func() time.Time { return now },
		Delegations: tokenvault.DelegationsFunc(func(_ context.Context, user, agent, _ string, _ []string, _ time.Time) (bool, error) {
			return f.allow.Load() && user == "alice" && agent == "agent-1", nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) connect(t *testing.T, expiresIn time.Duration, refresh string) {
	t.Helper()
	in := tokenvault.ConnectInput{UserID: "alice", Provider: "acme", AccountID: "a1",
		AccessToken: "access-1", RefreshToken: refresh, Scopes: []string{"read", "write"}}
	if expiresIn != 0 {
		in.ExpiresAt = f.now.Add(expiresIn)
	}
	if _, err := f.v.Connect(context.Background(), in); err != nil {
		t.Fatal(err)
	}
}

func req(agent, user string, scopes ...string) tokenvault.Request {
	return tokenvault.Request{AgentID: agent, UserID: user, Provider: "acme", Scopes: scopes}
}

func TestAccessTokenHappyPath(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Hour, "refresh-1")
	got, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read"))
	if err != nil || got.Token != "access-1" || got.TokenType != "Bearer" {
		t.Fatalf("got %v, %v", got, err)
	}
	if s := fmt.Sprintf("%v %+v %#v", got, got, got); strings.Contains(s, "access-1") {
		t.Fatal("AccessToken formatting leaks")
	}
	if f.ref.calls.Load() != 0 {
		t.Fatal("refreshed a fresh token")
	}
	if a := f.audit.actions(); a[len(a)-1] != tokenvault.ActionTokenIssued {
		t.Fatalf("audit = %v", a)
	}
}

func TestAccessTokenDenials(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *fixture)
		req   tokenvault.Request
		want  error
	}{
		{"no scopes", nil, req("agent-1", "alice"), tokenvault.ErrScopesRequired},
		{"wrong user", nil, req("agent-1", "mallory", "read"), tokenvault.ErrNotDelegated},
		{"wrong agent", nil, req("agent-2", "alice", "read"), tokenvault.ErrNotDelegated},
		{"revoked delegation", func(f *fixture) { f.allow.Store(false) }, req("agent-1", "alice", "read"), tokenvault.ErrNotDelegated},
		{"scope not granted", nil, req("agent-1", "alice", "admin"), tokenvault.ErrScopeNotGranted},
		{"not connected", func(f *fixture) { _ = f.v.Disconnect(context.Background(), "alice", "acme") }, req("agent-1", "alice", "read"), tokenvault.ErrNotConnected},
		{"expired without refresh token", func(f *fixture) { *f.now = f.now.Add(2 * time.Hour); f.ref.err = nil }, req("agent-1", "alice", "read"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			norefresh := tc.name == "expired without refresh token"
			if norefresh {
				f.connect(t, time.Hour, "")
				tc.want = tokenvault.ErrTokenExpired
			} else {
				f.connect(t, time.Hour, "refresh-1")
			}
			if tc.setup != nil {
				tc.setup(f)
			}
			got, err := f.v.AccessToken(context.Background(), tc.req)
			if !errors.Is(err, tc.want) || got.Token != "" {
				t.Fatalf("err = %v token = %q, want %v", err, got.Token, tc.want)
			}
			if a := f.audit.actions(); a[len(a)-1] != tokenvault.ActionTokenDenied {
				t.Fatalf("denial not audited: %v", a)
			}
		})
	}
}

func TestRefreshOnExpiry(t *testing.T) {
	f := newFixture(t)
	f.connect(t, 30*time.Second, "refresh-1") // inside the 60s skew
	f.ref.resp.RefreshToken = "refresh-2"
	got, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read"))
	if err != nil || got.Token != "access-2" || f.ref.calls.Load() != 1 {
		t.Fatalf("got %q, %v, calls %d", got.Token, err, f.ref.calls.Load())
	}
	if !got.ExpiresAt.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("expiry = %v", got.ExpiresAt)
	}
	// Second call uses the stored refreshed token.
	if _, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read")); err != nil || f.ref.calls.Load() != 1 {
		t.Fatalf("second call err %v calls %d", err, f.ref.calls.Load())
	}
	// Rotated refresh token is used next time.
	*f.now = f.now.Add(2 * time.Hour)
	f.ref.resp.AccessToken = "access-3"
	if got, err = f.v.AccessToken(context.Background(), req("agent-1", "alice", "read")); err != nil || got.Token != "access-3" {
		t.Fatalf("rotated refresh: %q %v", got.Token, err)
	}
}

func TestRefreshConcurrentSingleFlight(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Second, "refresh-1")
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read")); err != nil || got.Token != "access-2" {
				t.Errorf("got %q, %v", got.Token, err)
			}
		}()
	}
	wg.Wait()
	if n := f.ref.calls.Load(); n != 1 {
		t.Fatalf("refresh called %d times", n)
	}
}

func TestRefreshInvalidGrantNeedsReauth(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Second, "refresh-1")
	f.ref.err = tokenvault.ErrInvalidGrant
	if _, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read")); !errors.Is(err, tokenvault.ErrReauthRequired) {
		t.Fatalf("err = %v", err)
	}
	f.ref.err = nil
	if _, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read")); !errors.Is(err, tokenvault.ErrReauthRequired) {
		t.Fatalf("second err = %v", err)
	}
	if f.ref.calls.Load() != 1 {
		t.Fatal("kept hitting the provider after invalid_grant")
	}
	conns, _ := f.v.Connections(context.Background(), "alice")
	if len(conns) != 1 || conns[0].Status != theauth.VaultStatusNeedsReauth {
		t.Fatalf("conns = %+v", conns)
	}
}

func TestRefreshProviderErrorIsGeneric(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Second, "refresh-1")
	f.ref.err = errors.New("boom refresh-1")
	_, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read"))
	if !errors.Is(err, tokenvault.ErrRefreshFailed) || strings.Contains(err.Error(), "refresh-1") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuditFailureWithholdsToken(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Hour, "refresh-1")
	f.audit.fail = true
	got, err := f.v.AccessToken(context.Background(), req("agent-1", "alice", "read"))
	if !errors.Is(err, tokenvault.ErrAuditFailed) || got.Token != "" {
		t.Fatalf("got %q, %v", got.Token, err)
	}
}

func TestStoredCiphertextIsEncryptedAndBound(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Hour, "refresh-1")
	ctx := context.Background()
	row, _ := f.store.VaultCredentialByUserProvider(ctx, "alice", "acme")
	if bytes.Contains(row.AccessCT, []byte("access-1")) || bytes.Contains(row.RefreshCT, []byte("refresh-1")) {
		t.Fatal("plaintext in storage")
	}

	t.Run("tampered ciphertext", func(t *testing.T) {
		bad := *row
		bad.AccessCT = append([]byte(nil), row.AccessCT...)
		bad.AccessCT[len(bad.AccessCT)-1] ^= 0xff
		if _, err := f.store.PutVaultCredential(ctx, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := f.v.AccessToken(ctx, req("agent-1", "alice", "read")); !errors.Is(err, tokenvault.ErrDecrypt) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("row moved to another user", func(t *testing.T) {
		moved := *row
		moved.UserID = "bob"
		if _, err := f.store.PutVaultCredential(ctx, moved); err != nil {
			t.Fatal(err)
		}
		f.v2Allow(t, "bob")
	})
}

// v2Allow checks a bob-owned copy of alice's row does not decrypt.
func (f *fixture) v2Allow(t *testing.T, user string) {
	t.Helper()
	v, err := tokenvault.New(tokenvault.Config{Store: f.store, Keys: f.ring, Audit: f.audit, Clock: func() time.Time { return *f.now },
		Delegations: tokenvault.DelegationsFunc(func(context.Context, string, string, string, []string, time.Time) (bool, error) { return true, nil })})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.AccessToken(context.Background(), req("agent-1", user, "read")); !errors.Is(err, tokenvault.ErrDecrypt) {
		t.Fatalf("copied row err = %v, want ErrDecrypt", err)
	}
}

func TestUnknownKeyID(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Hour, "refresh-1")
	other, _ := tokenvault.NewKeyRing("k9", map[string][]byte{"k9": key(9)})
	v, _ := tokenvault.New(tokenvault.Config{Store: f.store, Keys: other, Audit: f.audit, Clock: func() time.Time { return *f.now },
		Delegations: tokenvault.DelegationsFunc(func(context.Context, string, string, string, []string, time.Time) (bool, error) { return true, nil })})
	if _, err := v.AccessToken(context.Background(), req("agent-1", "alice", "read")); !errors.Is(err, tokenvault.ErrUnknownKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestRewrapAfterRotation(t *testing.T) {
	f := newFixture(t)
	f.connect(t, time.Hour, "refresh-1")
	ring2, err := tokenvault.NewKeyRing("k2", map[string][]byte{"k1": key(1), "k2": key(2)})
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := tokenvault.New(tokenvault.Config{Store: f.store, Keys: ring2, Audit: f.audit, Clock: func() time.Time { return *f.now },
		Delegations: tokenvault.DelegationsFunc(func(context.Context, string, string, string, []string, time.Time) (bool, error) { return true, nil })})
	n, err := v2.Rewrap(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("rewrap = %d, %v", n, err)
	}
	if n, _ = v2.Rewrap(context.Background()); n != 0 {
		t.Fatalf("second rewrap moved %d", n)
	}
	row, _ := f.store.VaultCredentialByUserProvider(context.Background(), "alice", "acme")
	for _, blob := range [][]byte{row.AccessCT, row.RefreshCT} {
		if id, _ := ring2.KeyID(blob); id != "k2" {
			t.Fatalf("key id = %s", id)
		}
	}
	// Old key is no longer needed.
	only2, _ := tokenvault.NewKeyRing("k2", map[string][]byte{"k2": key(2)})
	v3, _ := tokenvault.New(tokenvault.Config{Store: f.store, Keys: only2, Audit: f.audit, Clock: func() time.Time { return *f.now },
		Delegations: tokenvault.DelegationsFunc(func(context.Context, string, string, string, []string, time.Time) (bool, error) { return true, nil })})
	if got, err := v3.AccessToken(context.Background(), req("agent-1", "alice", "read")); err != nil || got.Token != "access-1" {
		t.Fatalf("after rewrap: %q %v", got.Token, err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := tokenvault.NewKeyRing("a", map[string][]byte{"a": []byte("short")}); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := tokenvault.NewKeyRing("missing", map[string][]byte{"a": key(1)}); err == nil {
		t.Fatal("missing active accepted")
	}
	if _, err := tokenvault.New(tokenvault.Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
	r, _ := tokenvault.NewKeyRing("a", map[string][]byte{"a": key(7)})
	if s := fmt.Sprintf("%v %#v", r, r); strings.Contains(s, "\x07") {
		t.Fatal("key ring leaks key bytes")
	}
}

func TestKeyRingOpenNegative(t *testing.T) {
	r, _ := tokenvault.NewKeyRing("a", map[string][]byte{"a": key(1)})
	blob, _ := r.Seal([]byte("x"), []byte("ctx"))
	tests := []struct {
		name string
		blob []byte
		aad  string
		want error
	}{
		{"ok", blob, "ctx", nil},
		{"wrong aad", blob, "other", tokenvault.ErrDecrypt},
		{"empty", nil, "ctx", tokenvault.ErrMalformed},
		{"bad version", append([]byte{9}, blob[1:]...), "ctx", tokenvault.ErrMalformed},
		{"truncated", blob[:5], "ctx", tokenvault.ErrMalformed},
		{"flipped header id", func() []byte { b := append([]byte(nil), blob...); b[2] = 'b'; return b }(), "ctx", tokenvault.ErrUnknownKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.Open(tc.blob, []byte(tc.aad))
			if !errors.Is(err, tc.want) && (tc.want != nil || err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
