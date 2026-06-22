package dpop

import (
	"container/list"
	"errors"
	"strings"
	"sync"
	"time"
)

// service.go: top-level facade that ties proof verification, nonce
// management, and jti replay protection together. Both the authorization
// server (internal/as) and the resource-server middleware (mcpresource)
// embed exactly one *Service per process.

// Service holds the runtime state for DPoP proof verification:
//
//   - operator-configured policy (AllowedSignAlgs, ProofMaxAge, NonceTTL,
//     RequireNonceForTokens, RequireDPoPForClients);
//   - the HMAC secret used to issue + verify DPoP-Nonce headers;
//   - an LRU jti store sized to ProofMaxAge so a replayed proof inside
//     the acceptance window is rejected even when the original AS process
//     has crashed and restarted (the LRU is in-memory only; cross-process
//     replay protection across restarts is out of scope for this PR and
//     called out in the deferred list).
//
// The zero value is not usable; call New.
type Service struct {
	allowedAlgs           map[string]struct{}
	proofMaxAge           time.Duration
	nonceTTL              time.Duration
	requireNonceForTokens bool
	requireForClients     map[string]struct{}
	nonceSecret           []byte

	jtiMu   sync.Mutex
	jtiCap  int
	jtiList *list.List
	jtiSeen map[string]*list.Element
}

type jtiEntry struct {
	jti     string
	expires time.Time
}

// Config bundles the constructor inputs. Mirrors the public
// theauth.DPoPConfig 1:1; the translation happens in
// theauth.asConfigFromRoot when the AS Service is constructed.
type Config struct {
	// AllowedSignAlgs is the whitelist of signing algorithms a proof JWT
	// may use. Empty means DefaultAllowedAlgs.
	AllowedSignAlgs []string

	// ProofMaxAge bounds how far in the past or future the proof's iat
	// claim may be. Defaults to 60 seconds.
	ProofMaxAge time.Duration

	// NonceTTL bounds how long an issued DPoP-Nonce remains acceptable.
	// Defaults to 10 minutes.
	NonceTTL time.Duration

	// RequireNonceForTokens forces the token endpoint to demand a nonce
	// on every DPoP proof. A first-call proof without a nonce returns
	// HTTP 400 with error=use_dpop_nonce and a DPoP-Nonce header for the
	// retry. Off by default; operators serving a public AS may want this
	// on.
	RequireNonceForTokens bool

	// RequireDPoPForClients lists OAuth client IDs that MUST present a
	// DPoP proof on every token request. Token requests from any other
	// client may opt in by sending DPoP voluntarily; for clients in this
	// set, the absence of a proof is a hard failure.
	RequireDPoPForClients []string

	// NonceSecret is the HMAC-SHA256 secret used to mint + verify
	// DPoP-Nonce headers. Operators normally leave this nil and let New
	// generate a fresh 32-byte secret; supplying a stable value here lets
	// multiple AS instances share a nonce pool (sticky sessions not
	// required).
	NonceSecret []byte

	// JTIReplayWindow caps the in-memory jti LRU size. Defaults to 4096.
	// At 4096 entries and ~60-second ProofMaxAge a single AS can accept
	// ~68 RPS of DPoP-protected token mints before LRU eviction starts
	// shadowing the replay protection; that is well above any realistic
	// token-mint rate.
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
		nonceTTL:              cfg.NonceTTL,
		requireNonceForTokens: cfg.RequireNonceForTokens,
		requireForClients:     requireSet,
		nonceSecret:           secret,
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

// ClientRequiresDPoP reports whether the supplied OAuth client ID is on
// the operator-configured RequireDPoPForClients list. Token endpoints
// call this after authenticating the client and reject the request when
// the result is true AND no DPoP header was supplied.
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

// Verify runs every RFC 9449 section 4.3 step against the supplied proof
// JWT. On success the parsed proof (including the canonical JWK
// thumbprint) is returned; callers stamp the thumbprint into cnf.jkt of
// the issued access token.
//
// The function never panics on malformed input; every failure mode is a
// typed error so the handler layer can map onto the right wire response.
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
	if abs(now.Sub(iat)) > s.proofMaxAge {
		return nil, joinErr(ErrProofExpired, "age", now.Sub(iat).String(), "max", s.proofMaxAge.String())
	}
	// Check 7: nonce. RequireNonce ALWAYS forces a nonce. When the
	// proof carries one anyway (without RequireNonce), still verify it
	// so a client cannot pass an arbitrary string.
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
	if !s.rememberJTI(claims.JTI, iat.Add(s.proofMaxAge)) {
		return nil, ErrReplay
	}
	// Check 9: ath equals base64url(SHA-256(access_token)) when the
	// caller supplied an access token. Token endpoints leave AccessToken
	// empty; resource servers always pass it. The ath claim is REQUIRED
	// when AccessToken is non-empty (RFC 9449 section 4.2).
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

// VerifyAgainstConfirmation runs Verify and then enforces that the JWK
// thumbprint of the proof equals the supplied cnf.jkt from a presented
// access token. Used by resource servers to enforce sender constraint:
// even a perfectly valid proof signed by a different key than the one the
// token was minted for is rejected.
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

// rememberJTI records jti and returns true when it is new, false when it
// was already in the window. Expired entries are pruned lazily on every
// insert; the LRU eviction kicks in when jtiCap is reached.
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

// joinErr wraps a sentinel with structured key=value context. Kept here
// instead of using fmt.Errorf("%w: ...") so callers using errors.Is land
// on the sentinel cleanly.
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
