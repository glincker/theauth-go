package doctor

import "strings"

// Finding IDs for the cookie attribute and response header checks.
const (
	DoctorCookieDomain       = "cookie.domain_no_prefix"
	DoctorCookieNoneOpen     = "cookie.samesite_none_unpartitioned"
	DoctorSecurityHeadersOff = "headers.security_off_https"
)

// cookieFindingIDs lists the IDs checkCookies and checkSecurityHeaders can emit.
func cookieFindingIDs() []string {
	return []string{DoctorCookieDomain, DoctorCookieNoneOpen, DoctorSecurityHeadersOff}
}

func checkCookies(in Input) []Finding {
	var out []Finding
	if in.CookieDomain != "" && !strings.HasPrefix(in.CookieName, "__Secure-") && !strings.HasPrefix(in.CookieName, "__Host-") {
		out = append(out, fnd(DoctorCookieDomain, SeverityMedium,
			"Session cookie is shared across subdomains without a name prefix",
			"Config.Cookies.Domain is "+in.CookieDomain+", so every subdomain can read the session cookie and a sibling can overwrite it. A __Host- cookie cannot carry Domain, so the strongest available guard is the __Secure- prefix.",
			"Leave Config.Cookies.Domain empty if one host serves the app, or set Config.Cookies.Prefix to \"secure\" and keep every subdomain under your control."))
	}
	if in.CookieSameSite == "none" && !in.CookiePartitioned {
		out = append(out, fnd(DoctorCookieNoneOpen, SeverityLow,
			"SameSite=None session cookie is not Partitioned",
			"The cookie is sent on every cross-site request, which removes the SameSite CSRF defense, and browsers that block third-party cookies drop it unless it is Partitioned.",
			"Set Config.Cookies.Partitioned to true for embedded use, or use SameSite lax or strict when the app is not embedded."))
	}
	return out
}

func checkSecurityHeaders(in Input) []Finding {
	_, https := baseHost(in.BaseURL)
	if in.SecurityHeaders || !https {
		return nil
	}
	return []Finding{fnd(DoctorSecurityHeadersOff, SeverityInfo,
		"Security response headers are off on an https deployment",
		"Config.SecurityHeaders is false, so the library sends no Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy or X-Frame-Options.",
		"Set Config.SecurityHeaders to true, or send equivalent headers from your reverse proxy and ignore this hint.")}
}
