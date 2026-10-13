package theauth

import (
	"net/http"

	"github.com/glincker/theauth-go/v2/internal/httpx"
)

// problem writes an RFC 7807 middleware error, or hands it to
// Config.ErrorResponder when one is set.
func (a *TheAuth) problem(w http.ResponseWriter, r *http.Request, status int, code, detail, instance string) {
	if a.errorResponder != nil {
		a.errorResponder(w, r, status, code, detail)
		return
	}
	httpx.WriteProblemJSON(w, status, code, detail, instance)
}

// unauthenticated writes a 401 with the WWW-Authenticate challenge. The
// header is set before a custom responder runs so RFC 7235 holds either way.
func (a *TheAuth) unauthenticated(w http.ResponseWriter, r *http.Request, code, detail string) {
	if a.errorResponder != nil {
		w.Header().Set("WWW-Authenticate", `Session realm="theauth", error="`+code+`"`)
		a.errorResponder(w, r, http.StatusUnauthorized, code, detail)
		return
	}
	httpx.WriteUnauthenticated(w, code, detail)
}

// jsonError writes the {"code","message"} body, or hands it to
// Config.ErrorResponder when one is set.
func (a *TheAuth) jsonError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	if a.errorResponder != nil {
		a.errorResponder(w, r, status, code, message)
		return
	}
	writeJSONError(w, status, code, message)
}
