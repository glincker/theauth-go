package theauth

import (
	"net/http"
	"time"
)

// setSessionCookie writes the standard session cookie used by every
// successful signin path that still lives on *TheAuth (oauth, totp,
// webauthn). The password endpoints (extracted to internal/password/
// handlers in PR E) use an equivalent cookie writer on the Handler
// type that takes a CookieConfig value, so the cookie semantics stay
// identical regardless of which signin path was used.
func (a *TheAuth) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.sessionTTL),
	})
}
