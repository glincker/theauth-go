package as

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// authctx.go: the authentication context (OIDC Core auth_time, acr, amr)
// the AS records on codes and refresh families and emits in access tokens
// and introspection responses so resource servers can enforce RFC 9470
// step-up (mcpresource RequireStepUp).

// Default acr values emitted when Config.ACRValues has no entry for the
// authentication method set.
const (
	// ACRSingleFactor is the default acr for a session authenticated with
	// one factor (for example a password, magic link or social login).
	ACRSingleFactor = "urn:theauth:acr:1fa"
	// ACRMultiFactor is the default acr for a session whose amr lists the
	// "mfa" method or two or more distinct methods.
	ACRMultiFactor = "urn:theauth:acr:mfa"
)

// AuthContext describes how and when the user behind a request
// authenticated. The authorize handler builds it from the session; callers
// of StartAuthorize that bypass the handler attach one with WithAuthContext.
type AuthContext struct {
	// AuthTime is when the user last proved identity (login or step-up).
	// The zero time means unknown.
	AuthTime time.Time
	// AMR lists the RFC 8176 authentication method references, for example
	// "pwd", "otp", "hwk", "mfa".
	AMR []string
	// ACR, when non-empty, overrides the value derived from AMR and
	// Config.ACRValues.
	ACR string
	// SessionID identifies the browser session behind the request. OIDC
	// uses it for the sid claim and back-channel logout.
	SessionID string
}

type authContextKey struct{}

// WithAuthContext returns a context carrying ac for StartAuthorize.
func WithAuthContext(ctx context.Context, ac AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey{}, ac)
}

// AuthContextFrom returns the AuthContext attached by WithAuthContext.
func AuthContextFrom(ctx context.Context) (AuthContext, bool) {
	ac, ok := ctx.Value(authContextKey{}).(AuthContext)
	return ac, ok
}

// errAuthorizeReauthRequired is returned by StartAuthorize when the session
// is older than max_age or does not satisfy acr_values. The handler answers
// it like a missing session: a redirect to LoginURL.
var errAuthorizeReauthRequired = errors.New("theauth: authorize requires re-authentication")

// IsReauthRequired reports whether err means the authorize request needs the
// user to authenticate again (max_age exceeded or acr_values unmet).
func IsReauthRequired(err error) bool {
	return errors.Is(err, errAuthorizeReauthRequired)
}

// ACRMethodKey is the lookup key into Config.ACRValues for a method set: the
// distinct, lowercased amr values sorted and joined with "+", for example
// "otp+pwd".
func ACRMethodKey(amr []string) string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(amr))
	for _, m := range amr {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

// acrFor maps an authentication method set to an acr string. An exact entry
// in Config.ACRValues wins; otherwise the documented default applies:
// ACRMultiFactor when amr holds "mfa" or two or more distinct methods, else
// ACRSingleFactor. An empty method set has no acr.
func (s *Service) acrFor(ac AuthContext) string {
	if ac.ACR != "" {
		return ac.ACR
	}
	key := ACRMethodKey(ac.AMR)
	if key == "" {
		return ""
	}
	if v, ok := s.Cfg.ACRValues[key]; ok && v != "" {
		return v
	}
	if strings.Contains(key, "+") || key == "mfa" {
		return ACRMultiFactor
	}
	return ACRSingleFactor
}

// acrValuesSupported lists the configured acr strings, sorted and unique,
// for the acr_values_supported metadata field. Nil when none are configured.
func (s *Service) acrValuesSupported() []string {
	if len(s.Cfg.ACRValues) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(s.Cfg.ACRValues))
	for _, v := range s.Cfg.ACRValues {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// reauthNeeded reports whether the request's max_age or acr_values are not
// met by the session's authentication context. A missing context fails any
// stated requirement (fail closed).
func (s *Service) reauthNeeded(req AuthorizeRequest, ac AuthContext, have bool, now time.Time) bool {
	if req.MaxAge != nil {
		if !have || ac.AuthTime.IsZero() {
			return true
		}
		age := now.Sub(ac.AuthTime)
		if *req.MaxAge <= 0 || age > time.Duration(*req.MaxAge)*time.Second {
			return true
		}
	}
	if len(req.ACRValues) > 0 {
		if !have {
			return true
		}
		got := s.acrFor(ac)
		for _, want := range req.ACRValues {
			if got != "" && got == want {
				return false
			}
		}
		return true
	}
	return false
}

// ParseMaxAge parses an OIDC max_age parameter. An empty string is absent
// (nil). Anything that is not a non-negative integer is invalid_request.
func ParseMaxAge(raw string) (*int64, error) {
	if raw == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return nil, models.ErrOAuthInvalidRequest
	}
	return &n, nil
}

// NormalizeACRValues returns a copy of m with every key rewritten to its
// ACRMethodKey form so operators may write "pwd+otp" in any order. Entries
// with an empty key or value are dropped. Nil for an empty input.
func NormalizeACRValues(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		key := ACRMethodKey(strings.Split(k, "+"))
		if key == "" || v == "" {
			continue
		}
		out[key] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// setAuthContextClaims adds auth_time, acr and amr to claims. Each claim is
// emitted only when the grant recorded a value.
func setAuthContextClaims(claims *jwt.Claims, authTime time.Time, acr string, amr []string) {
	if authTime.IsZero() && acr == "" && len(amr) == 0 {
		return
	}
	if claims.Extra == nil {
		claims.Extra = map[string]any{}
	}
	if !authTime.IsZero() {
		claims.Extra["auth_time"] = authTime.Unix()
	}
	if acr != "" {
		claims.Extra["acr"] = acr
	}
	if len(amr) > 0 {
		claims.Extra["amr"] = append([]string(nil), amr...)
	}
}

// authContextFromExtra reads auth_time, acr and amr back out of a decoded
// claim set (JSON numbers arrive as float64, arrays as []any).
func authContextFromExtra(extra map[string]any) (int64, string, []string) {
	var at int64
	switch v := extra["auth_time"].(type) {
	case float64:
		at = int64(v)
	case int64:
		at = v
	}
	acr, _ := extra["acr"].(string)
	var amr []string
	switch v := extra["amr"].(type) {
	case []string:
		amr = v
	case []any:
		for _, e := range v {
			if str, ok := e.(string); ok {
				amr = append(amr, str)
			}
		}
	}
	return at, acr, amr
}
