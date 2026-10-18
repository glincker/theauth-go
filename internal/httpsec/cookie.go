package httpsec

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Cookie name prefixes defined by RFC 6265bis.
const (
	// HostPrefix marks a cookie browsers accept only when Secure, Path=/ and without Domain.
	HostPrefix = "__Host-"
	// SecurePrefix marks a cookie browsers accept only when Secure.
	SecurePrefix = "__Secure-"
)

// CookiePolicy is the one attribute set every Set-Cookie the library writes goes through. HttpOnly
// is always on. The zero value reproduces the historic behavior: SameSite=Lax, no Domain, not
// Partitioned, and Secure only as far as Secure says.
type CookiePolicy struct {
	// Secure is the static Secure flag. The per-request upgrade in CookieWriter can still add
	// Secure on a TLS request, but prefix, SameSite=None and Partitioned rules look at this value.
	Secure bool
	// Domain, when set, shares the cookie with every subdomain. Empty keeps it host only.
	Domain string
	// SameSite is Lax, Strict or None. The zero value means Lax.
	SameSite http.SameSite
	// Partitioned adds the CHIPS Partitioned attribute. It requires Secure.
	Partitioned bool
}

// ParseSameSite maps the Config string form ("", "lax", "strict", "none") to http.SameSite.
func ParseSameSite(s string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	}
	return 0, fmt.Errorf("SameSite %q is not one of lax, strict, none", s)
}

func (p CookiePolicy) sameSite() http.SameSite {
	if p.SameSite == 0 || p.SameSite == http.SameSiteDefaultMode {
		return http.SameSiteLaxMode
	}
	return p.SameSite
}

// Validate rejects attribute combinations browsers drop or that weaken a prefix guarantee. name and
// path are the cookie being written. It is cheap, so Config validation runs it at startup for the
// session cookie and the builder runs it again on every write.
func (p CookiePolicy) Validate(name, path string) error {
	ss := p.sameSite()
	if ss != http.SameSiteLaxMode && ss != http.SameSiteStrictMode && ss != http.SameSiteNoneMode {
		return errors.New("SameSite must be Lax, Strict or None")
	}
	if strings.ContainsAny(p.Domain, "/:; ,") {
		return fmt.Errorf("cookie domain %q must be a bare host name", p.Domain)
	}
	if ss == http.SameSiteNoneMode && !p.Secure {
		return fmt.Errorf("cookie %q: SameSite=None requires Secure", name)
	}
	if p.Partitioned && !p.Secure {
		return fmt.Errorf("cookie %q: a Partitioned cookie requires Secure", name)
	}
	switch {
	case strings.HasPrefix(name, HostPrefix):
		if !p.Secure {
			return fmt.Errorf("cookie %q: a __Host- cookie must be Secure", name)
		}
		if path != "/" {
			return fmt.Errorf("cookie %q: a __Host- cookie must have Path=/", name)
		}
		if p.Domain != "" {
			return fmt.Errorf("cookie %q: a __Host- cookie must not set Domain", name)
		}
	case strings.HasPrefix(name, SecurePrefix):
		if !p.Secure {
			return fmt.Errorf("cookie %q: a __Secure- cookie must be Secure", name)
		}
	}
	return nil
}

// New builds a cookie with value, valid until expires (zero means a session cookie), after
// validating the policy against name and path. It sets both Expires and Max-Age.
func (p CookiePolicy) New(name, value, path string, expires time.Time) (*http.Cookie, error) {
	if err := p.Validate(name, path); err != nil {
		return nil, err
	}
	c := p.base(name, value, path)
	if !expires.IsZero() {
		c.Expires = expires
		secs := int(time.Until(expires).Round(time.Second) / time.Second)
		if secs < 1 {
			secs = 1
		}
		c.MaxAge = secs
	}
	return c, nil
}

// NewClear builds the expiring counterpart of a cookie. It repeats Domain, Path, Secure and
// Partitioned, which browsers require to match before they delete the stored cookie.
func (p CookiePolicy) NewClear(name, path string) (*http.Cookie, error) {
	if err := p.Validate(name, path); err != nil {
		return nil, err
	}
	c := p.base(name, "", path)
	c.MaxAge = -1
	return c, nil
}

func (p CookiePolicy) base(name, value, path string) *http.Cookie {
	return &http.Cookie{
		Name:        name,
		Value:       value,
		Path:        path,
		Domain:      p.Domain,
		HttpOnly:    true,
		Secure:      p.Secure,
		SameSite:    p.sameSite(),
		Partitioned: p.Partitioned,
	}
}

// Set writes the cookie. An invalid policy is rejected at startup, so a failure here is a bug: it
// is logged and the cookie is not written, never written with weaker attributes.
func (p CookiePolicy) Set(w http.ResponseWriter, name, value, path string, expires time.Time) {
	c, err := p.New(name, value, path, expires)
	if err != nil {
		slog.Error("theauth: refusing to write cookie", "error", err)
		return
	}
	http.SetCookie(w, c)
}

// Clear writes the expiring counterpart of a cookie, see NewClear.
func (p CookiePolicy) Clear(w http.ResponseWriter, name, path string) {
	c, err := p.NewClear(name, path)
	if err != nil {
		slog.Error("theauth: refusing to clear cookie", "error", err)
		return
	}
	http.SetCookie(w, c)
}

// WithSecure returns p with Secure turned on when secure is true. It never turns Secure off.
func (p CookiePolicy) WithSecure(secure bool) CookiePolicy {
	p.Secure = p.Secure || secure
	return p
}

// ForCrossSiteReturn returns p with SameSite=Strict relaxed to Lax. Cookies read on a top-level
// cross-site redirect back (the OAuth state cookie) are not sent under Strict.
func (p CookiePolicy) ForCrossSiteReturn() CookiePolicy {
	if p.SameSite == http.SameSiteStrictMode {
		p.SameSite = http.SameSiteLaxMode
	}
	return p
}
