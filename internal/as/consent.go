package as

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/cimd"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// consent.go implements host-owned consent. When Config.ConsentHandler is set, the handler is
// called after authentication and validation. The host approves (optionally narrowing scopes and
// setting an expiry), denies, or interacts and resumes through CompleteConsent with a signed
// ticket.

// ConsentAction is the host's answer to a consent question.
type ConsentAction string

const (
	// ConsentApprove issues the authorization code for GrantedScopes.
	ConsentApprove ConsentAction = "approve"
	// ConsentDeny answers the client with access_denied.
	ConsentDeny ConsentAction = "deny"
	// ConsentInteract redirects the user agent to the host's consent page.
	ConsentInteract ConsentAction = "interact"
)

const (
	ConsentSourceRegistered = "registered"
	ConsentSourceCIMD       = "cimd"
)

const (
	defaultConsentTicketTTL = 10 * time.Minute
	consentTicketParam      = "consent_ticket"
	consentTicketVersion    = 1
	// grantExpirySep separates a token's random part from the grant expiry it carries. The stored key
	// hashes the whole string, so the suffix cannot be changed without invalidating the token.
	grantExpirySep = "~"
)

var (
	// ErrConsentTicketInvalid is returned by CompleteConsent for a malformed, forged, expired, reused
	// or foreign ticket.
	ErrConsentTicketInvalid = errors.New("theauth: consent ticket invalid")
	// ErrConsentDecisionInvalid is returned for a decision the library refuses: out-of-request scopes,
	// no scopes, a past expiry or an unusable URL.
	ErrConsentDecisionInvalid = errors.New("theauth: consent decision invalid")
)

// ConsentClient describes the requesting client for the consent screen.
type ConsentClient struct {
	ID          string
	Name        string
	LogoURI     string
	ClientURI   string
	PolicyURI   string
	TosURI      string
	RedirectURI string
	// MetadataSource is ConsentSourceRegistered (stored client) or ConsentSourceCIMD (fetched from the
	// client_id URL).
	MetadataSource string
	// Verified is true for CIMD clients whose metadata was fetched over https from the client_id URL.
	// It does not vouch for the name or logo. Registered clients are self-asserted, so it is false.
	Verified bool
}

// ConsentRequest is the read-only question put to the ConsentHandler.
type ConsentRequest struct {
	User                          models.User
	Client                        ConsentClient
	RequestedScopes               []string
	RequestedResource             string
	RequestedAuthorizationDetails string
	State                         string
	MaxGrantTTL                   time.Duration
}

// ConsentDecision is the host's answer.
type ConsentDecision struct {
	Action        ConsentAction
	GrantedScopes []string
	// ExpiresAt and MaxTTL bound the grant. When both are set the earlier wins; both are clamped to
	// the server maxima.
	ExpiresAt time.Time
	MaxTTL    time.Duration
	// RedirectToConsentURL is where Interact sends the user agent: an absolute path on this origin or
	// an http(s) URL.
	RedirectToConsentURL string
}

// ConsentHandler decides whether to grant, and with which scopes.
type ConsentHandler func(ctx context.Context, req ConsentRequest) (ConsentDecision, error)

// consentTicket is the signed payload binding a pending authorization.
type consentTicket struct {
	V   int              `json:"v"`
	JTI string           `json:"jti"`
	Exp int64            `json:"exp"`
	UID string           `json:"uid"`
	SID string           `json:"sid,omitempty"`
	Req AuthorizeRequest `json:"req"`
}

func (s *Service) consentTicketTTL() time.Duration {
	if s.Cfg.ConsentTicketTTL > 0 {
		return s.Cfg.ConsentTicketTTL
	}
	return defaultConsentTicketTTL
}

func (s *Service) consentKey() ([]byte, error) {
	if len(s.encryptionKey) == 0 {
		return nil, errors.New("theauth: consent tickets need an encryption key")
	}
	m := hmac.New(sha256.New, s.encryptionKey)
	m.Write([]byte("theauth/consent-ticket/v1"))
	return m.Sum(nil), nil
}

func (s *Service) signTicket(t consentTicket) (string, error) {
	key, err := s.consentKey()
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("marshal consent ticket: %w", err)
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(enc))
	return enc + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func (s *Service) parseTicket(raw string) (consentTicket, error) {
	var t consentTicket
	key, err := s.consentKey()
	if err != nil {
		return t, err
	}
	enc, sig, ok := strings.Cut(raw, ".")
	if !ok || enc == "" || sig == "" {
		return t, fmt.Errorf("%w: malformed", ErrConsentTicketInvalid)
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return t, fmt.Errorf("%w: malformed", ErrConsentTicketInvalid)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(enc))
	if subtle.ConstantTimeCompare(got, m.Sum(nil)) != 1 {
		return t, fmt.Errorf("%w: bad signature", ErrConsentTicketInvalid)
	}
	body, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return t, fmt.Errorf("%w: malformed", ErrConsentTicketInvalid)
	}
	if err := json.Unmarshal(body, &t); err != nil || t.V != consentTicketVersion || t.JTI == "" {
		return consentTicket{}, fmt.Errorf("%w: malformed", ErrConsentTicketInvalid)
	}
	if !time.Unix(t.Exp, 0).After(time.Now()) {
		return consentTicket{}, fmt.Errorf("%w: expired", ErrConsentTicketInvalid)
	}
	return t, nil
}

type consentOutcome struct {
	redirect string // set for Interact and Deny: respond with this redirect
	scope    []string
	expiry   time.Time
}

type consentResume struct {
	ticket   consentTicket
	decision ConsentDecision
}

func (s *Service) consentStep(ctx context.Context, req AuthorizeRequest, client *models.OAuthClient, user *models.User, scope []string, resume *consentResume) (consentOutcome, error) {
	var dec ConsentDecision
	if resume != nil {
		dec = resume.decision
		if dec.Action == ConsentInteract {
			return consentOutcome{}, fmt.Errorf("%w: interact is not valid when completing", ErrConsentDecisionInvalid)
		}
	} else {
		var err error
		dec, err = s.Cfg.ConsentHandler(ctx, s.consentRequest(req, client, user, scope))
		if err != nil {
			return consentOutcome{}, fmt.Errorf("consent handler: %w", err)
		}
	}
	switch dec.Action {
	case ConsentDeny:
		if resume != nil {
			if err := s.burnTicket(ctx, resume.ticket); err != nil {
				return consentOutcome{}, err
			}
		}
		return consentOutcome{redirect: buildAuthzErrorRedirect(req.RedirectURI, "access_denied", req.State, s.Cfg.Issuer)}, nil
	case ConsentInteract:
		u, err := s.interactURL(ctx, req, user, dec.RedirectToConsentURL)
		if err != nil {
			return consentOutcome{}, err
		}
		return consentOutcome{redirect: u}, nil
	case ConsentApprove:
		granted, err := subsetScopes(dec.GrantedScopes, scope)
		if err != nil {
			return consentOutcome{}, err
		}
		exp, err := s.clampGrantExpiry(dec, time.Now())
		if err != nil {
			return consentOutcome{}, err
		}
		if resume != nil {
			if err := s.burnTicket(ctx, resume.ticket); err != nil {
				return consentOutcome{}, err
			}
		}
		return consentOutcome{scope: granted, expiry: exp}, nil
	}
	return consentOutcome{}, fmt.Errorf("%w: unknown action %q", ErrConsentDecisionInvalid, dec.Action)
}

func (s *Service) consentRequest(req AuthorizeRequest, client *models.OAuthClient, user *models.User, scope []string) ConsentRequest {
	src := ConsentSourceRegistered
	if cimd.LooksLikeCIMD(client.ClientID) {
		src = ConsentSourceCIMD
	}
	return ConsentRequest{
		User: *user,
		Client: ConsentClient{
			ID:             client.ClientID,
			Name:           client.ClientName,
			LogoURI:        client.LogoURI,
			ClientURI:      client.ClientURI,
			PolicyURI:      client.PolicyURI,
			TosURI:         client.TosURI,
			RedirectURI:    req.RedirectURI,
			MetadataSource: src,
			Verified:       src == ConsentSourceCIMD,
		},
		RequestedScopes:               append([]string(nil), scope...),
		RequestedResource:             req.Resource,
		RequestedAuthorizationDetails: req.AuthorizationDetails,
		State:                         req.State,
		MaxGrantTTL:                   s.Cfg.ConsentMaxGrantTTL,
	}
}

// subsetScopes returns granted, deduplicated, failing unless it is non-empty and every entry is in requested.
func subsetScopes(granted, requested []string) ([]string, error) {
	if len(granted) == 0 {
		return nil, fmt.Errorf("%w: no scopes granted", ErrConsentDecisionInvalid)
	}
	allowed := make(map[string]struct{}, len(requested))
	for _, r := range requested {
		allowed[r] = struct{}{}
	}
	seen := make(map[string]struct{}, len(granted))
	out := make([]string, 0, len(granted))
	for _, g := range granted {
		if _, ok := allowed[g]; !ok {
			return nil, fmt.Errorf("%w: scope %q was not requested", ErrConsentDecisionInvalid, g)
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out, nil
}

// clampGrantExpiry computes the absolute grant expiry, or the zero time when only the token TTLs
// bound the grant.
func (s *Service) clampGrantExpiry(dec ConsentDecision, now time.Time) (time.Time, error) {
	var exp time.Time
	if !dec.ExpiresAt.IsZero() {
		if !dec.ExpiresAt.After(now) {
			return time.Time{}, fmt.Errorf("%w: expiry is in the past", ErrConsentDecisionInvalid)
		}
		exp = dec.ExpiresAt
	}
	if dec.MaxTTL < 0 {
		return time.Time{}, fmt.Errorf("%w: negative ttl", ErrConsentDecisionInvalid)
	}
	if dec.MaxTTL > 0 {
		if t := now.Add(dec.MaxTTL); exp.IsZero() || t.Before(exp) {
			exp = t
		}
	}
	if m := s.Cfg.ConsentMaxGrantTTL; m > 0 {
		if t := now.Add(m); exp.IsZero() || exp.After(t) {
			exp = t
		}
	}
	if !exp.IsZero() {
		exp = exp.UTC().Truncate(time.Second)
		if !exp.After(now) {
			return time.Time{}, fmt.Errorf("%w: expiry is too short", ErrConsentDecisionInvalid)
		}
	}
	return exp, nil
}

func (s *Service) interactURL(ctx context.Context, req AuthorizeRequest, user *models.User, target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil || target == "" {
		return "", fmt.Errorf("%w: bad consent url", ErrConsentDecisionInvalid)
	}
	switch {
	case u.Scheme == "" && u.Host == "" && strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") && !strings.HasPrefix(target, `/\`):
	case (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil:
	default:
		return "", fmt.Errorf("%w: consent url must be an absolute path or http(s) url", ErrConsentDecisionInvalid)
	}
	jti, err := crypto.NewToken()
	if err != nil {
		return "", fmt.Errorf("consent ticket id: %w", err)
	}
	t := consentTicket{
		V:   consentTicketVersion,
		JTI: jti,
		Exp: time.Now().Add(s.consentTicketTTL()).Unix(),
		UID: user.ID.String(),
		Req: req,
	}
	// The pushed-request and JAR handles are resolved already, so they are not carried into a ticket
	// that outlives them.
	t.Req.RequestURI, t.Req.RequestObject = "", ""
	if ac, ok := AuthContextFrom(ctx); ok {
		t.SID = ac.SessionID
	}
	ticket, err := s.signTicket(t)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(consentTicketParam, ticket)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Service) burnTicket(ctx context.Context, t consentTicket) error {
	cache := s.consentReplay
	if cache == nil {
		return errors.New("theauth: consent replay cache unavailable")
	}
	ttl := time.Until(time.Unix(t.Exp, 0)) + time.Minute
	seen, err := cache.Seen(ctx, "consent:"+t.JTI, ttl)
	if err != nil {
		return fmt.Errorf("consent replay cache: %w", err)
	}
	if seen {
		return fmt.Errorf("%w: already used", ErrConsentTicketInvalid)
	}
	return nil
}

// CompleteConsent resumes an authorization the ConsentHandler answered with Interact. user must be
// the user the ticket was issued to. The result is a redirect to the client (a code, or
// access_denied). The host MUST protect the calling endpoint against CSRF, since a forged call
// could approve on the user's behalf.
func (s *Service) CompleteConsent(ctx context.Context, ticket string, dec ConsentDecision, user *models.User) (AuthorizeResult, error) {
	if s == nil || s.Cfg.ConsentHandler == nil {
		return AuthorizeResult{}, errors.New("theauth: consent not configured")
	}
	if user == nil {
		return AuthorizeResult{}, fmt.Errorf("%w: no user", ErrConsentTicketInvalid)
	}
	t, err := s.parseTicket(ticket)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if subtle.ConstantTimeCompare([]byte(t.UID), []byte(user.ID.String())) != 1 {
		return AuthorizeResult{}, fmt.Errorf("%w: user mismatch", ErrConsentTicketInvalid)
	}
	if t.SID != "" {
		ac, ok := AuthContextFrom(ctx)
		if !ok || ac.SessionID != t.SID {
			return AuthorizeResult{}, fmt.Errorf("%w: session mismatch", ErrConsentTicketInvalid)
		}
	}
	return s.startAuthorize(ctx, t.Req, user, &consentResume{ticket: t, decision: dec})
}

// splitGrantExpiry returns the grant expiry carried by a code or refresh token, or the zero time
// when it has none.
func splitGrantExpiry(tok string) time.Time {
	i := strings.LastIndex(tok, grantExpirySep)
	if i < 0 {
		return time.Time{}
	}
	n, err := strconv.ParseInt(tok[i+1:], 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func withGrantExpiry(tok string, exp time.Time) string {
	if exp.IsZero() {
		return tok
	}
	return tok + grantExpirySep + strconv.FormatInt(exp.Unix(), 10)
}

// buildAuthzErrorRedirect appends error and state to a validated redirect URI.
func buildAuthzErrorRedirect(redirectURI, code, state, issuer string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	if issuer != "" {
		q.Set("iss", issuer)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
