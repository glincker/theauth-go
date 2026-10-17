package as

import (
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/v2/internal/dpop"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// dpop.go is the glue between the token endpoint and the RFC 9449 verifier. It lives here so grants
// can call it without depending on the HTTP layer.

// dpopThumbprintForRequest verifies the DPoP proof on req. It returns ("", nil) when DPoP is off or
// the client sent no proof and is not required to; (jkt, nil) for a valid proof; ErrDPoPRequired,
// ErrDPoPNonceRequired (400 plus a DPoP-Nonce header) or ErrDPoPInvalid otherwise.
func (s *Service) dpopThumbprintForRequest(req TokenRequest) (string, error) {
	if s == nil || s.dpopSvc == nil {
		// With DPoP disabled a proof is ignored and the token is a plain Bearer token (no cnf claim).
		return "", nil
	}
	if req.DPoPProof == "" {
		if s.dpopSvc.ClientRequiresDPoP(req.ClientID) {
			return "", ErrDPoPRequired
		}
		return "", nil
	}
	params := dpop.VerifyParams{
		Method:       req.HTTPMethod,
		URL:          req.HTTPURL,
		Now:          time.Now().UTC(),
		RequireNonce: s.dpopSvc.RequireNonceForTokens(),
	}
	proof, err := s.dpopSvc.Verify(req.DPoPProof, params)
	if err != nil {
		if errors.Is(err, dpop.ErrNonceRequired) || errors.Is(err, dpop.ErrNonceInvalid) {
			return "", ErrDPoPNonceRequired
		}
		return "", fmt.Errorf("%w: %v", ErrDPoPInvalid, err)
	}
	return proof.Thumbprint, nil
}

// IssueDPoPNonce mints a DPoP-Nonce value, or "" when DPoP is disabled.
func (s *Service) IssueDPoPNonce() string {
	if s == nil || s.dpopSvc == nil {
		return ""
	}
	return s.dpopSvc.IssueNonce(time.Now().UTC())
}

// DPoPProofMaxAge is the proof acceptance window, surfaced as a hint on DPoP-Nonce errors. It is 0
// when DPoP is disabled.
func (s *Service) DPoPProofMaxAge() time.Duration {
	if s == nil || s.dpopSvc == nil {
		return 0
	}
	return s.dpopSvc.ProofMaxAge()
}

// Sentinel errors that handlers map onto wire responses.
var (
	// ErrDPoPRequired is returned when the client must present a proof and did not. Maps to 400
	// invalid_dpop_proof.
	ErrDPoPRequired = errors.New("theauth: DPoP proof required")

	// ErrDPoPNonceRequired is returned when the proof lacks the server-issued nonce. Maps to 400 use_dpop_nonce.
	ErrDPoPNonceRequired = errors.New("theauth: DPoP nonce required")

	// ErrDPoPInvalid wraps every other proof verification failure. Maps to 400 invalid_dpop_proof.
	ErrDPoPInvalid = errors.New("theauth: DPoP proof invalid")
)

// Compile-time guard: these sentinels must not be shadowed by a same-named models constant.
var _ = models.ErrOAuthInvalidRequest
