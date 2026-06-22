package as

import (
	"errors"
	"fmt"
	"time"

	"github.com/glincker/theauth-go/internal/dpop"
	"github.com/glincker/theauth-go/internal/models"
)

// dpop.go: glue between the AS token endpoint and the RFC 9449 verifier.
// Lives in this package (not in handlers) so the grant implementations
// can call it without taking a dependency on the HTTP layer.

// dpopThumbprintForRequest extracts and verifies the DPoP proof from
// req. Returns:
//
//   - ("", nil)               when DPoP is disabled OR the client did not
//     present a proof AND is not on the
//     RequireDPoPForClients list.
//   - (jkt, nil)              on a valid proof; jkt is the RFC 7638
//     SHA-256 thumbprint of the proof key.
//   - ("", ErrDPoPRequired)   when the client is on the required list
//     but no proof was supplied.
//   - ("", ErrDPoPNonceRequired) when nonce mode is on and the proof
//     lacked a nonce. Handlers map this to a
//     400 + DPoP-Nonce response header.
//   - ("", ErrDPoPInvalid)    on any other verification failure
//     (signature, htm, htu, iat, jti replay,
//     malformed proof, unsupported alg).
//
// The grant implementations call this helper exactly once and pass the
// resulting jkt through to mintAccessAndRefresh.
func (s *Service) dpopThumbprintForRequest(req TokenRequest) (string, error) {
	if s == nil || s.dpopSvc == nil {
		// DPoP disabled. A client presenting a proof to a DPoP-unaware
		// AS gets a Bearer token (no cnf claim); this is the
		// pre-PR behavior and matches the deployment opt-in
		// model laid out in Cfg.DPoP.
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

// IssueDPoPNonce mints a fresh DPoP-Nonce string when DPoP is enabled.
// Returns "" when DPoP is disabled so handlers can branch with a single
// nil check.
func (s *Service) IssueDPoPNonce() string {
	if s == nil || s.dpopSvc == nil {
		return ""
	}
	return s.dpopSvc.IssueNonce(time.Now().UTC())
}

// DPoPProofMaxAge surfaces the configured proof acceptance window so the
// handler can emit it as a hint on the DPoP-Nonce error response. Returns
// 0 when DPoP is disabled.
func (s *Service) DPoPProofMaxAge() time.Duration {
	if s == nil || s.dpopSvc == nil {
		return 0
	}
	return s.dpopSvc.ProofMaxAge()
}

// Sentinel errors the handler layer maps onto wire responses. Kept in
// this package so handlers (in internal/as/handlers) and any future
// non-HTTP caller share the same vocabulary.
var (
	// ErrDPoPRequired is returned when the AS is configured to require
	// a DPoP proof for the given client and the request did not include
	// one. Maps to HTTP 400 invalid_dpop_proof.
	ErrDPoPRequired = errors.New("theauth: DPoP proof required")

	// ErrDPoPNonceRequired is returned when the proof lacks a server-
	// issued nonce that the server has demanded. Maps to HTTP 400
	// use_dpop_nonce + DPoP-Nonce response header.
	ErrDPoPNonceRequired = errors.New("theauth: DPoP nonce required")

	// ErrDPoPInvalid wraps every other proof verification failure.
	// Maps to HTTP 400 invalid_dpop_proof.
	ErrDPoPInvalid = errors.New("theauth: DPoP proof invalid")
)

// Compile-time guard that ErrDPoPRequired and friends are sentinels the
// models package does not also export. Avoids accidental shadowing by a
// later models constant of the same name.
var _ = models.ErrOAuthInvalidRequest
