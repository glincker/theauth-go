package as

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/clientauthcache"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// pauser blocks one armed call after the slow lookup has produced its answer and before the
// caller can store it. That is the window between a cache Load and its Store, so a test can run an
// invalidation inside it deterministically.
type pauser struct {
	armed   atomic.Bool
	reached chan struct{}
	release chan struct{}
}

func newPauser() *pauser {
	return &pauser{reached: make(chan struct{}, 1), release: make(chan struct{})}
}

func (p *pauser) pause() {
	if p.armed.CompareAndSwap(true, false) {
		p.reached <- struct{}{}
		<-p.release
	}
}

// runPaused arms p, starts fn, waits until fn is paused, runs during (the revoke), then releases fn
// and waits for it to finish.
func runPaused(t *testing.T, p *pauser, fn func(), during func()) {
	t.Helper()
	p.armed.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-p.reached:
	case <-time.After(5 * time.Second):
		t.Fatal("lookup never reached")
	}
	during()
	close(p.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("paused call never finished")
	}
}

// agentFixture is an agent lookup whose status can be flipped, with a pause hook.
type agentFixture struct {
	id        models.ULID
	suspended atomic.Bool
	p         *pauser
}

func newAgentFixture() *agentFixture { return &agentFixture{id: ulid.New(), p: newPauser()} }

func (f *agentFixture) sub() string { return models.AgentSubjectPrefix + f.id.String() }

func (f *agentFixture) lookup(_ context.Context, _ string) (*models.Agent, error) {
	st := models.AgentStatusActive
	if f.suspended.Load() {
		st = models.AgentStatusSuspended
	}
	ag := &models.Agent{ID: f.id, Status: st}
	f.p.pause()
	return ag, nil
}

func (f *agentFixture) service() *Service {
	return &Service{
		Cfg:         Config{Clock: realClock{}, SubjectActiveCacheTTL: time.Second, IntrospectionCacheTTL: time.Minute},
		AgentLookup: AgentLookupFunc(f.lookup),
	}
}

// A subjectActive that read "active" just before a suspend must not cache that answer when the
// store lands after InvalidateSubject returned.
func TestSubjectActiveStaleStoreAfterInvalidate(t *testing.T) {
	f := newAgentFixture()
	s := f.service()
	ctx := context.Background()
	runPaused(t, f.p, func() { s.subjectActive(ctx, f.sub()) }, func() {
		f.suspended.Store(true)
		s.InvalidateSubject(f.sub())
	})
	if s.subjectActive(ctx, f.sub()) {
		t.Fatal("suspended agent served active from the subject cache after InvalidateSubject")
	}
}

// Same window through the revocation bus path (SubscribeRevocations calls InvalidateSubject).
func TestSubjectActiveStillCachesWithoutRace(t *testing.T) {
	f := newAgentFixture()
	s := f.service()
	ctx := context.Background()
	if !s.subjectActive(ctx, f.sub()) {
		t.Fatal("active agent reported inactive")
	}
	f.suspended.Store(true)
	if !s.subjectActive(ctx, f.sub()) {
		t.Fatal("positive answer should be served from cache inside the TTL")
	}
	s.InvalidateSubject(f.sub())
	if s.subjectActive(ctx, f.sub()) {
		t.Fatal("invalidate did not drop the cached answer")
	}
}

func actChain(f *agentFixture) *IntrospectionResponse {
	return &IntrospectionResponse{Active: true, Act: &models.ActorClaim{Sub: f.sub()}}
}

// A chain walk that saw an active agent just before a suspend must not cache it after
// InvalidateChainCache. The agent service passes the bare agent ID, as production does.
func TestChainStillActiveStaleStoreAfterInvalidate(t *testing.T) {
	f := newAgentFixture()
	s := f.service()
	ctx := context.Background()
	runPaused(t, f.p, func() { s.chainStillActive(ctx, actChain(f)) }, func() {
		f.suspended.Store(true)
		s.InvalidateChainCache(f.id.String())
	})
	if s.chainStillActive(ctx, actChain(f)) {
		t.Fatal("suspended agent served active from the chain cache after InvalidateChainCache")
	}
}

// The chain cache is keyed by the "agent:<id>" actor subject, so InvalidateChainCache(bareID) must
// reach that key without any race.
func TestInvalidateChainCacheReachesCachedEntry(t *testing.T) {
	f := newAgentFixture()
	s := f.service()
	ctx := context.Background()
	if !s.chainStillActive(ctx, actChain(f)) {
		t.Fatal("active agent reported inactive")
	}
	f.suspended.Store(true)
	s.InvalidateChainCache(f.id.String())
	if s.chainStillActive(ctx, actChain(f)) {
		t.Fatal("InvalidateChainCache left the chain entry in place")
	}
}

// An inner actor of a chain is not the cache key. Suspending it must still drop the entry cached
// under the outer actor.
func TestInvalidateChainCacheCoversInnerActors(t *testing.T) {
	inner := newAgentFixture()
	outer := newAgentFixture()
	s := &Service{
		Cfg: Config{Clock: realClock{}},
		AgentLookup: AgentLookupFunc(func(ctx context.Context, sub string) (*models.Agent, error) {
			if sub == inner.sub() {
				return inner.lookup(ctx, sub)
			}
			return outer.lookup(ctx, sub)
		}),
	}
	ctx := context.Background()
	resp := func() *IntrospectionResponse {
		return &IntrospectionResponse{Active: true, Act: &models.ActorClaim{Sub: outer.sub(), Act: &models.ActorClaim{Sub: inner.sub()}}}
	}
	if !s.chainStillActive(ctx, resp()) {
		t.Fatal("active chain reported inactive")
	}
	inner.suspended.Store(true)
	s.InvalidateChainCache(inner.id.String())
	if s.chainStillActive(ctx, resp()) {
		t.Fatal("suspended inner actor still served active from the chain cache")
	}
}

type opaqueStub struct {
	Storage
	revoked atomic.Bool
	claims  []byte
	p       *pauser
}

func (o *opaqueStub) InsertOpaqueAccessToken(context.Context, models.OpaqueAccessToken) error {
	return nil
}

func (o *opaqueStub) OpaqueAccessTokenByHash(context.Context, []byte) (*models.OpaqueAccessToken, error) {
	rec := &models.OpaqueAccessToken{ClientID: "c", Claims: o.claims, ExpiresAt: time.Now().Add(time.Hour)}
	if o.revoked.Load() {
		now := time.Now()
		rec.RevokedAt = &now
	}
	o.p.pause()
	return rec, nil
}

func (o *opaqueStub) RefreshTokenByHash(context.Context, []byte) (*models.RefreshToken, error) {
	return nil, models.ErrStorageNotFound
}

func (o *opaqueStub) RevokeOpaqueAccessToken(context.Context, []byte) error {
	o.revoked.Store(true)
	return nil
}

func newOpaqueStub(t *testing.T) (*Service, *opaqueStub) {
	t.Helper()
	claims, err := json.Marshal(jwt.Claims{Aud: "https://rs.example", Jti: "j1", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	st := &opaqueStub{claims: claims, p: newPauser()}
	return &Service{Cfg: Config{Clock: realClock{}, IntrospectionCacheTTL: time.Minute}, Storage: st}, st
}

// An introspection that read a live opaque token just before the revoke must not leave an active
// body in the introspection cache once the revoke returned.
func TestIntrospectStaleStoreAfterRevoke(t *testing.T) {
	s, st := newOpaqueStub(t)
	ctx := context.Background()
	const tok = "opaque-token-value"
	runPaused(t, st.p, func() { s.introspectFresh(ctx, tok, "") }, func() {
		if !s.revokeOpaqueAccessToken(ctx, crypto.HashToken(tok), "c") {
			t.Fatal("revoke did not find the token")
		}
	})
	if body, ok := s.introspectCacheGet(tok, ""); ok {
		t.Fatalf("active body cached across a revoke: %s", body)
	}
	if resp, _ := s.introspectFresh(ctx, tok, ""); resp.Active {
		t.Fatal("revoked opaque token introspected as active")
	}
}

// Without a race the cache still works and a revoke clears it.
func TestIntrospectCachesAndRevokeClears(t *testing.T) {
	s, _ := newOpaqueStub(t)
	ctx := context.Background()
	const tok = "opaque-token-value"
	if resp, _ := s.introspectFresh(ctx, tok, ""); !resp.Active {
		t.Fatal("live opaque token inactive")
	}
	if _, ok := s.introspectCacheGet(tok, ""); !ok {
		t.Fatal("active body not cached")
	}
	s.revokeOpaqueAccessToken(ctx, crypto.HashToken(tok), "c")
	if _, ok := s.introspectCacheGet(tok, ""); ok {
		t.Fatal("revoke left the body in the cache")
	}
}

type refreshStub struct {
	Storage
	revoked atomic.Bool
}

func (r *refreshStub) RefreshTokenByHash(context.Context, []byte) (*models.RefreshToken, error) {
	rt := &models.RefreshToken{ClientID: "c", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if r.revoked.Load() {
		now := time.Now()
		rt.RevokedAt = &now
	}
	return rt, nil
}

// A rotated or revoked refresh token must introspect as inactive at once. A cache hit does not
// re-read the refresh token row, so these answers are never cached.
func TestIntrospectRefreshTokenAnswerIsNotCached(t *testing.T) {
	st := &refreshStub{}
	s := &Service{Cfg: Config{Clock: realClock{}, IntrospectionCacheTTL: time.Minute}, Storage: st}
	ctx := context.Background()
	const tok = "refresh-token-value"
	if resp, _ := s.introspectFresh(ctx, tok, ""); !resp.Active {
		t.Fatal("live refresh token inactive")
	}
	if _, ok := s.introspectCacheGet(tok, ""); ok {
		t.Fatal("refresh token answer was cached")
	}
	st.revoked.Store(true)
	if resp, _ := s.introspectFresh(ctx, tok, ""); resp.Active {
		t.Fatal("revoked refresh token introspected as active")
	}
}

type clientStub struct {
	Storage
	hash atomic.Value // string
	p    *pauser
}

func (c *clientStub) OAuthClientByClientID(context.Context, string) (*models.OAuthClient, error) {
	cl := &models.OAuthClient{
		ClientID:                "c",
		TokenEndpointAuthMethod: models.ClientAuthSecretBasic,
		ClientSecretHash:        []byte(c.hash.Load().(string)),
	}
	c.p.pause()
	return cl, nil
}

// A client verified against the old secret hash just before a rotation must not be cached once
// InvalidateClientAuthCache returned, or the old secret would authenticate for the cache TTL.
func TestAuthenticateClientStaleStoreAfterRotation(t *testing.T) {
	oldHash, err := crypto.HashPassword("old-secret")
	if err != nil {
		t.Fatal(err)
	}
	newHash, err := crypto.HashPassword("new-secret")
	if err != nil {
		t.Fatal(err)
	}
	st := &clientStub{p: newPauser()}
	st.hash.Store(oldHash)
	s := &Service{
		Cfg:             Config{Clock: realClock{}},
		Storage:         st,
		clientAuthCache: clientauthcache.New[*models.OAuthClient](0, 0),
	}
	ctx := context.Background()
	runPaused(t, st.p, func() { _, _ = s.AuthenticateClient(ctx, "c", "old-secret") }, func() {
		st.hash.Store(newHash)
		s.InvalidateClientAuthCache("c")
	})
	if _, err := s.AuthenticateClient(ctx, "c", "old-secret"); err == nil {
		t.Fatal("rotated-out secret authenticated from the client auth cache")
	}
	if _, err := s.AuthenticateClient(ctx, "c", "new-secret"); err != nil {
		t.Fatalf("new secret rejected: %v", err)
	}
}
