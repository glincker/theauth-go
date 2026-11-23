package dpop

import (
	"container/list"
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

// service.go is the facade that ties proof verification, nonce management and jti replay protection
// together. The AS and the resource-server middleware each embed one *Service per process.

// Service holds DPoP verification state: the policy knobs, the nonce HMAC secret, and the jti
// replay store sized to ProofMaxAge. The replay store is in memory per process, so replay
// protection does not survive a restart. The zero value is unusable; call New.
type Service struct {
	allowedAlgs           map[string]struct{}
	proofMaxAge           time.Duration
	clockSkew             time.Duration
	nonceTTL              time.Duration
	requireNonceForTokens bool
	requireForClients     map[string]struct{}
	nonceSecret           []byte

	replay  kv.ReplayCache
	jtiMu   sync.Mutex
	jtiCap  int
	jtiList *list.List
	jtiSeen map[string]*list.Element
}

type jtiEntry struct {
	jti     string
	expires time.Time
}

// Config mirrors the public theauth.DPoPConfig. The translation happens in theauth.asConfigFromRoot.
type Config struct {
	// AllowedSignAlgs is the whitelist of signing algorithms a proof JWT
	// may use. Empty means DefaultAllowedAlgs.
	AllowedSignAlgs []string

	// ProofMaxAge bounds how far in the past or future the proof's iat
	// claim may be. Defaults to 60 seconds.
	ProofMaxAge time.Duration

	// ClockSkew widens the iat acceptance window on top of ProofMaxAge, to absorb clock drift. Defaults to zero.
	ClockSkew time.Duration

	// NonceTTL bounds how long an issued DPoP-Nonce remains acceptable.
	// Defaults to 10 minutes.
	NonceTTL time.Duration

	// RequireNonceForTokens makes the token endpoint demand a nonce on every proof. The first proof
	// without one gets 400 use_dpop_nonce with a DPoP-Nonce header to retry with. Off by default.
	RequireNonceForTokens bool

	// RequireDPoPForClients lists client IDs that must present a proof on every token request. Other
	// clients may opt in by sending one.
	RequireDPoPForClients []string

	// NonceSecret is the HMAC key for DPoP-Nonce values. Nil lets New generate one; a stable value
	// lets several AS instances share a nonce pool.
	NonceSecret []byte

	// ReplayCache, when set, records proof jti values in a store shared by every replica. Backend
	// errors fail closed. Nil keeps the in-process LRU.
	ReplayCache kv.ReplayCache

	// JTIReplayWindow caps the in-memory jti LRU (default 4096). At that size and a 60 second
	// ProofMaxAge, one AS accepts about 68 proofs per second before eviction weakens replay
	// protection.
	JTIReplayWindow int
}

// New constructs a Service. Returns an error only when NonceSecret is
// neither supplied nor generatable (crypto/rand failure).
func New(cfg Config) (*Service, error) {
	allowed := cfg.AllowedSignAlgs
	if len(allowed) == 0 {
		allowed = DefaultAllowedAlgs
	}
	algSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		algSet[strings.TrimSpace(a)] = struct{}{}
	}
	if cfg.ProofMaxAge <= 0 {
		cfg.ProofMaxAge = 60 * time.Second
	}
	if cfg.NonceTTL <= 0 {
		cfg.NonceTTL = 10 * time.Minute
	}
	if cfg.JTIReplayWindow <= 0 {
		cfg.JTIReplayWindow = 4096
	}
	secret := cfg.NonceSecret
	if len(secret) == 0 {
		s, err := newNonceSecret()
		if err != nil {
			return nil, err
		}
		secret = s
	}
	requireSet := make(map[string]struct{}, len(cfg.RequireDPoPForClients))
	for _, c := range cfg.RequireDPoPForClients {
		requireSet[c] = struct{}{}
	}
	return &Service{
		allowedAlgs:           algSet,
		proofMaxAge:           cfg.ProofMaxAge,
		clockSkew:             cfg.ClockSkew,
		nonceTTL:              cfg.NonceTTL,
		requireNonceForTokens: cfg.RequireNonceForTokens,
		requireForClients:     requireSet,
		nonceSecret:           secret,
		replay:                cfg.ReplayCache,
		jtiCap:                cfg.JTIReplayWindow,
		jtiList:               list.New(),
		jtiSeen:               map[string]*list.Element{},
	}, nil
}

// ProofMaxAge surfaces the configured proof acceptance window for callers
// (the AS handler needs it for the DPoP-Nonce expiry hint header).
func (s *Service) ProofMaxAge() time.Duration { return s.proofMaxAge }

// NonceTTL surfaces the configured nonce acceptance window.
func (s *Service) NonceTTL() time.Duration { return s.nonceTTL }

// RequireNonceForTokens reports whether the token endpoint must demand a
// nonce on every DPoP proof.
func (s *Service) RequireNonceForTokens() bool { return s.requireNonceForTokens }

// ClientRequiresDPoP reports whether the client is on the RequireDPoPForClients list. Token
// endpoints reject a missing proof for such clients.
func (s *Service) ClientRequiresDPoP(clientID string) bool {
	if s == nil {
		return false
	}
	_, ok := s.requireForClients[clientID]
	return ok
}

// IssueNonce mints a fresh DPoP-Nonce string. Safe to call from any
// goroutine; the underlying HMAC is stateless.
func (s *Service) IssueNonce(now time.Time) string {
	if s == nil {
		return ""
	}
	return issueNonce(s.nonceSecret, now)
}

// Verify runs every RFC 9449 section 4.3 check on the proof JWT. On success it returns the parsed
// proof, whose thumbprint goes into cnf.jkt. It never panics on malformed input; each failure is a
// typed error.
func (s *Service) Verify(proofJWT string, params VerifyParams) (*Proof, error) {
	if s == nil {
		return nil, errors.New("dpop: service not configured")
	}
	hdr, claims, sig, signingInput, err := ParseProof(proofJWT)
	if err != nil {
		return nil, err
	}
	// Check 1: typ MUST be dpop+jwt.
	if hdr.Typ != ProofTyp {
		return nil, joinErr(ErrMalformedProof, "typ", hdr.Typ)
	}
	// Check 2: alg in the configured whitelist.
	if _, ok := s.allowedAlgs[hdr.Alg]; !ok {
		return nil, joinErr(ErrUnsupportedAlg, "alg", hdr.Alg)
	}
	// Check 3: jwk present + signature verifies.
	if err := verifySignature(hdr.Alg, hdr.JWK, signingInput, sig); err != nil {
		return nil, err
	}
	// Check 4: htm matches request method (case-insensitive).
	if !strings.EqualFold(claims.HTM, params.Method) {
		return nil, joinErr(ErrMethodMismatch, "htm", claims.HTM, "method", params.Method)
	}
	// Check 5: htu matches request URI without query / fragment.
	wantURI, err := canonicalURI(params.URL)
	if err != nil {
		return nil, err
	}
	gotURI, err := canonicalURI(claims.HTU)
	if err != nil {
		return nil, joinErr(ErrURIMismatch, "htu", claims.HTU)
	}
	if gotURI != wantURI {
		return nil, joinErr(ErrURIMismatch, "htu", gotURI, "want", wantURI)
	}
	// Check 6: iat within ProofMaxAge.
	now := params.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if claims.IAT == 0 {
		return nil, joinErr(ErrProofExpired, "iat", "missing")
	}
	iat := time.Unix(claims.IAT, 0)
	if abs(now.Sub(iat)) > s.proofMaxAge+s.clockSkew {
		return nil, joinErr(ErrProofExpired, "age", now.Sub(iat).String(), "max", s.proofMaxAge.String())
	}
	// Check 7 (nonce): RequireNonce always forces a nonce. A nonce that is present is verified even
	// when not required.
	if params.RequireNonce && claims.Nonce == "" {
		return nil, ErrNonceRequired
	}
	if claims.Nonce != "" {
		if len(s.nonceSecret) == 0 {
			return nil, errNonceSecretRequired
		}
		if err := verifyNonce(s.nonceSecret, claims.Nonce, s.nonceTTL, now); err != nil {
			return nil, err
		}
	}
	// Check 8: jti unique within the replay window. Reject before
	// computing ath so a replayed proof never authorizes a token call.
	if claims.JTI == "" {
		return nil, joinErr(ErrMalformedProof, "jti", "missing")
	}
	// Remember the jti for as long as the proof stays acceptable (ProofMaxAge plus ClockSkew), or a proof
	// inside the skew allowance could be replayed once its entry expired.
	fresh, err := s.checkJTI(claims.JTI, iat.Add(s.proofMaxAge+s.clockSkew))
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, ErrReplay
	}
	// Check 9 (ath): when the caller supplies an access token, the ath claim is required and must
	// match its hash (RFC 9449 section 4.2).
	if params.AccessToken != "" {
		if claims.ATH == "" {
			return nil, ErrATHRequired
		}
		want := AccessTokenHash(params.AccessToken)
		if claims.ATH != want {
			return nil, joinErr(ErrATHMismatch, "got", claims.ATH, "want", want)
		}
	}
	thumb, err := Thumbprint(hdr.JWK)
	if err != nil {
		return nil, err
	}
	return &Proof{Header: hdr, Claims: claims, Thumbprint: thumb}, nil
}

// VerifyAgainstConfirmation runs Verify, then requires the proof's thumbprint to equal the token's
// cnf.jkt. This enforces sender constraint: a valid proof from a different key is still rejected.
func (s *Service) VerifyAgainstConfirmation(proofJWT string, params VerifyParams, jkt string) (*Proof, error) {
	proof, err := s.Verify(proofJWT, params)
	if err != nil {
		return nil, err
	}
	if jkt == "" || proof.Thumbprint != jkt {
		return nil, ErrJKTMismatch
	}
	return proof, nil
}

// checkJTI routes to the shared ReplayCache when configured, otherwise to the
// in-process LRU. It returns true when the jti is new.
func (s *Service) checkJTI(jti string, expires time.Time) (bool, error) {
	if s.replay == nil {
		return s.rememberJTI(jti, expires), nil
	}
	ttl := time.Until(expires)
	if ttl < time.Second {
		ttl = time.Second
	}
	seen, err := s.replay.Seen(context.Background(), "dpop:jti:"+jti, ttl)
	if err != nil {
		return false, joinErr(ErrReplayStore, "err", err.Error())
	}
	return !seen, nil
}

// rememberJTI records jti and returns true when it is new. Expired entries are pruned on insert;
// LRU eviction runs at capacity.
func (s *Service) rememberJTI(jti string, expires time.Time) bool {
	s.jtiMu.Lock()
	defer s.jtiMu.Unlock()
	now := time.Now()
	if el, ok := s.jtiSeen[jti]; ok {
		entry, _ := el.Value.(*jtiEntry)
		if entry != nil && now.Before(entry.expires) {
			return false
		}
		// Expired entry; drop it and treat as new.
		s.jtiList.Remove(el)
		delete(s.jtiSeen, jti)
	}
	// Lazy expiry sweep: walk from oldest until first non-expired.
	for {
		front := s.jtiList.Front()
		if front == nil {
			break
		}
		entry, _ := front.Value.(*jtiEntry)
		if entry == nil || now.Before(entry.expires) {
			break
		}
		s.jtiList.Remove(front)
		delete(s.jtiSeen, entry.jti)
	}
	for s.jtiList.Len() >= s.jtiCap {
		front := s.jtiList.Front()
		if front == nil {
			break
		}
		entry, _ := front.Value.(*jtiEntry)
		s.jtiList.Remove(front)
		if entry != nil {
			delete(s.jtiSeen, entry.jti)
		}
	}
	el := s.jtiList.PushBack(&jtiEntry{jti: jti, expires: expires})
	s.jtiSeen[jti] = el
	return true
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// joinErr wraps a sentinel with key=value context, so errors.Is still matches the sentinel.
func joinErr(sentinel error, kv ...string) error {
	if len(kv) == 0 {
		return sentinel
	}
	var b strings.Builder
	b.WriteString(sentinel.Error())
	b.WriteString(" (")
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(kv[i])
		b.WriteString("=")
		b.WriteString(kv[i+1])
	}
	b.WriteString(")")
	return &dpopErr{sentinel: sentinel, msg: b.String()}
}

type dpopErr struct {
	sentinel error
	msg      string
}

func (e *dpopErr) Error() string { return e.msg }

func (e *dpopErr) Unwrap() error { return e.sentinel }
