package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	internalas "github.com/glincker/theauth-go/v2/internal/as"
)

// handlers_authctx.go plumbs the authentication context into /oauth/authorize (auth_time, acr, amr,
// max_age, acr_values, prompt=none).

// errLoginRequired is the prompt=none outcome when the user must sign in or re-authenticate.
var errLoginRequired = errors.New("login_required")

// SetAuthContext installs the function that reports how the session authenticated. Without it,
// tokens carry no auth_time, acr or amr, and max_age or acr_values can never be met.
func (h *Handler) SetAuthContext(fn func(r *http.Request) (internalas.AuthContext, bool)) {
	h.authContext = fn
}

// loginRedirect builds the LoginURL redirect. The original authorize URL travels in next, and
// re-authentication adds the max_age and acr_values hints. The login flow must create or step up a
// session, or the user loops back here.
func (h *Handler) loginRedirect(r *http.Request, req internalas.AuthorizeRequest, reauth bool) string {
	target := h.svc.Cfg.LoginURL
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	v := url.Values{"next": {r.URL.String()}}
	if reauth {
		v.Set("reauth", "1")
		if req.MaxAge != nil {
			v.Set("max_age", strconv.FormatInt(*req.MaxAge, 10))
		}
		if len(req.ACRValues) > 0 {
			v.Set("acr_values", strings.Join(req.ACRValues, " "))
		}
	}
	return target + sep + strings.ReplaceAll(v.Encode(), "+", "%20")
}
