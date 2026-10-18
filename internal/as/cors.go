package as

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CORSGroup names one endpoint group of the authorization server that can opt in to CORS.
type CORSGroup int

// The CORS endpoint groups. Discovery and JWKS are public read-only documents; the rest carry
// credentials or mutate state and never accept a wildcard origin.
const (
	CORSDiscovery CORSGroup = iota
	CORSJWKS
	CORSRegister
	CORSToken
	CORSIntrospect
	CORSRevoke
	CORSUserInfo
)

// String returns the config field name of the group, used in validation errors.
func (g CORSGroup) String() string {
	switch g {
	case CORSDiscovery:
		return "Discovery"
	case CORSJWKS:
		return "JWKS"
	case CORSRegister:
		return "Register"
	case CORSToken:
		return "Token"
	case CORSIntrospect:
		return "Introspect"
	case CORSRevoke:
		return "Revoke"
	case CORSUserInfo:
		return "UserInfo"
	default:
		return "Unknown"
	}
}

func (g CORSGroup) public() bool { return g == CORSDiscovery || g == CORSJWKS }

// Methods returns the Access-Control-Allow-Methods value: only what the group's endpoints serve.
func (g CORSGroup) methods() string {
	switch g {
	case CORSDiscovery, CORSJWKS:
		return "GET"
	case CORSUserInfo:
		return "GET, POST"
	default:
		return "POST"
	}
}

// CORSConfig opts the authorization server endpoints in to browser cross-origin access. The zero
// value sends no CORS headers and registers no preflight routes. Enable a group with its switch
// and list the origins that may call it.
type CORSConfig struct {
	// AllowedOrigins lists exact origins (scheme, host and optional port, for example
	// "https://app.example.com") allowed on every enabled group. Matching is exact after
	// lower-casing and dropping a trailing slash or default port. A request origin that is not
	// listed never gets Access-Control-Allow-Origin, and "null" is never allowed. The wildcard "*"
	// is accepted here only when no group other than Discovery and JWKS is enabled.
	AllowedOrigins []string

	// PublicOrigins overrides AllowedOrigins for the public read-only documents (Discovery and
	// JWKS). It is the only list that may hold "*" next to enabled token endpoints. Empty means
	// those groups use AllowedOrigins.
	PublicOrigins []string

	// Per-group switches. All default to off.
	Discovery  bool // authorization server and protected resource metadata documents
	JWKS       bool // GET /oauth/jwks
	Register   bool // POST /oauth/register
	Token      bool // POST /oauth/token
	Introspect bool // POST /oauth/introspect
	Revoke     bool // POST /oauth/revoke
	UserInfo   bool // GET and POST /oauth/userinfo

	// AllowCredentials sends Access-Control-Allow-Credentials: true on the non-public groups, and
	// only for an exactly listed origin. It is refused at startup together with "*" anywhere.
	AllowCredentials bool

	// ExposedHeaders are the response headers scripts may read. Empty means DPoP-Nonce and
	// WWW-Authenticate.
	ExposedHeaders []string

	// MaxAge is how long a browser may cache a preflight answer. Zero means 10 minutes, negative
	// omits the header.
	MaxAge time.Duration
}

// Errors returned by ValidateCORS.
var (
	// ErrCORSWildcardPrivate is returned when "*" is combined with a group that is not a public
	// read-only document.
	ErrCORSWildcardPrivate = errors.New("theauth: AuthorizationServer.CORS: wildcard origin is allowed only for Discovery and JWKS")
	// ErrCORSWildcardCredentials is returned when AllowCredentials is set with a wildcard origin.
	ErrCORSWildcardCredentials = errors.New("theauth: AuthorizationServer.CORS: AllowCredentials cannot be combined with a wildcard origin")
	// ErrCORSInvalidOrigin is returned for an origin that is not scheme://host[:port].
	ErrCORSInvalidOrigin = errors.New("theauth: AuthorizationServer.CORS: invalid origin")
)

const (
	defaultCORSMaxAge  = 10 * time.Minute
	corsAllowedHeaders = "Accept, Content-Type, Authorization, DPoP"
	corsDefaultExposed = "DPoP-Nonce, WWW-Authenticate"
	corsWildcard       = "*"
)

// NormalizeOrigin returns the canonical form of an origin (lower-case scheme and host, default port
// dropped, no trailing slash) or false when s is not a plain http(s) origin. "null" is invalid.
func NormalizeOrigin(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "null") {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", false
	}
	if u.Path != "" && u.Path != "/" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
			return "", false
		}
		host += ":" + port
	}
	return scheme + "://" + host, true
}

func (c *CORSConfig) enabled(g CORSGroup) bool {
	switch g {
	case CORSDiscovery:
		return c.Discovery
	case CORSJWKS:
		return c.JWKS
	case CORSRegister:
		return c.Register
	case CORSToken:
		return c.Token
	case CORSIntrospect:
		return c.Introspect
	case CORSRevoke:
		return c.Revoke
	case CORSUserInfo:
		return c.UserInfo
	default:
		return false
	}
}

// Any reports whether any group is enabled.
func (c *CORSConfig) Any() bool {
	for g := CORSDiscovery; g <= CORSUserInfo; g++ {
		if c.enabled(g) {
			return true
		}
	}
	return false
}

// normalizeOrigins canonicalizes a list in place. The wildcard is kept as "*" and reported.
func normalizeOrigins(list []string, field string) ([]string, bool, error) {
	out := make([]string, 0, len(list))
	wild := false
	for _, o := range list {
		if strings.TrimSpace(o) == corsWildcard {
			wild = true
			out = append(out, corsWildcard)
			continue
		}
		n, ok := NormalizeOrigin(o)
		if !ok {
			return nil, false, fmt.Errorf("%w: %s entry %q must be scheme://host[:port]", ErrCORSInvalidOrigin, field, o)
		}
		out = append(out, n)
	}
	return out, wild, nil
}

// ValidateCORS normalizes the origin lists and refuses unsafe combinations. It runs at startup so a
// bad CORS block fails New instead of weakening an endpoint at request time.
func ValidateCORS(c *CORSConfig) error {
	if c == nil {
		return nil
	}
	allowed, wildAllowed, err := normalizeOrigins(c.AllowedOrigins, "AllowedOrigins")
	if err != nil {
		return err
	}
	public, wildPublic, err := normalizeOrigins(c.PublicOrigins, "PublicOrigins")
	if err != nil {
		return err
	}
	if wildAllowed {
		for g := CORSRegister; g <= CORSUserInfo; g++ {
			if c.enabled(g) {
				return fmt.Errorf("%w (AllowedOrigins has \"*\" and %s is enabled)", ErrCORSWildcardPrivate, g)
			}
		}
	}
	if c.AllowCredentials && (wildAllowed || wildPublic) {
		return ErrCORSWildcardCredentials
	}
	for _, h := range c.ExposedHeaders {
		if !validHeaderName(h) {
			return fmt.Errorf("theauth: AuthorizationServer.CORS: invalid ExposedHeaders entry %q", h)
		}
	}
	c.AllowedOrigins = allowed
	c.PublicOrigins = public
	return nil
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// CORSPolicy applies a validated CORSConfig to requests. A nil policy and the zero config are inert.
type CORSPolicy struct {
	cfg     CORSConfig
	exposed string
	maxAge  string
}

// NewCORSPolicy builds the policy. It re-normalizes the lists so it is safe on an unvalidated
// config: invalid entries are dropped and a wildcard is ignored on non-public groups.
func NewCORSPolicy(cfg CORSConfig) *CORSPolicy {
	p := &CORSPolicy{cfg: cfg, exposed: corsDefaultExposed}
	p.cfg.AllowedOrigins = dropInvalid(cfg.AllowedOrigins)
	p.cfg.PublicOrigins = dropInvalid(cfg.PublicOrigins)
	if len(cfg.ExposedHeaders) > 0 {
		p.exposed = strings.Join(cfg.ExposedHeaders, ", ")
	}
	age := cfg.MaxAge
	if age == 0 {
		age = defaultCORSMaxAge
	}
	if age > 0 {
		p.maxAge = strconv.Itoa(int(age / time.Second))
	}
	return p
}

func dropInvalid(list []string) []string {
	out, _, err := normalizeOrigins(list, "")
	if err == nil {
		return out
	}
	out = out[:0]
	for _, o := range list {
		if strings.TrimSpace(o) == corsWildcard {
			out = append(out, corsWildcard)
		} else if n, ok := NormalizeOrigin(o); ok {
			out = append(out, n)
		}
	}
	return out
}

// Enabled reports whether group g sends CORS headers.
func (p *CORSPolicy) Enabled(g CORSGroup) bool { return p != nil && p.cfg.enabled(g) }

// allow returns the Access-Control-Allow-Origin value for a request origin, or "" when not allowed.
func (p *CORSPolicy) allow(g CORSGroup, origin string) string {
	if origin == "" {
		return ""
	}
	list := p.cfg.AllowedOrigins
	if g.public() && len(p.cfg.PublicOrigins) > 0 {
		list = p.cfg.PublicOrigins
	}
	norm, ok := NormalizeOrigin(origin)
	for _, o := range list {
		if o == corsWildcard {
			if g.public() && !p.cfg.AllowCredentials {
				return corsWildcard
			}
			continue
		}
		if ok && o == norm {
			return norm
		}
	}
	return ""
}

func requestOrigin(r *http.Request) string {
	v := r.Header.Values("Origin")
	if len(v) != 1 {
		return ""
	}
	return v[0]
}

func (p *CORSPolicy) apply(w http.ResponseWriter, g CORSGroup, origin string) bool {
	h := w.Header()
	h.Add("Vary", "Origin")
	acao := p.allow(g, origin)
	if acao == "" {
		return false
	}
	h.Set("Access-Control-Allow-Origin", acao)
	if p.cfg.AllowCredentials && !g.public() {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	return true
}

// Middleware adds CORS headers to the responses of group g, including errors written by inner
// handlers. It is the identity when the group is off.
func (p *CORSPolicy) Middleware(g CORSGroup) func(http.Handler) http.Handler {
	if !p.Enabled(g) {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p.apply(w, g, requestOrigin(r)) {
				w.Header().Set("Access-Control-Expose-Headers", p.exposed)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Preflight answers OPTIONS for group g with 204 before any authentication or rate limiting. A
// disallowed origin or method gets 204 without Access-Control-Allow-Origin, so the browser blocks it.
func (p *CORSPolicy) Preflight(g CORSGroup) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Vary", "Access-Control-Request-Method")
		h.Add("Vary", "Access-Control-Request-Headers")
		if p.apply(w, g, requestOrigin(r)) && methodListed(g.methods(), r.Header.Get("Access-Control-Request-Method")) {
			h.Set("Access-Control-Allow-Methods", g.methods())
			h.Set("Access-Control-Allow-Headers", corsAllowedHeaders)
			if p.maxAge != "" {
				h.Set("Access-Control-Max-Age", p.maxAge)
			}
		} else {
			h.Del("Access-Control-Allow-Origin")
			h.Del("Access-Control-Allow-Credentials")
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func methodListed(list, m string) bool {
	for _, x := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(x), m) {
			return true
		}
	}
	return false
}
