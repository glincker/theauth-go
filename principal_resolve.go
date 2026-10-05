package theauth

import (
	"context"
	"net/http"
)

// AuthenticatePrincipal resolves the request's session or API bearer token
// into a Principal with its current abilities, writing the 401 or 500
// response itself when it cannot. The returned request carries the Principal
// and user in its context. Needs Config.APITokens.
func (a *TheAuth) AuthenticatePrincipal(w http.ResponseWriter, r *http.Request) (*http.Request, *Principal, bool) {
	s, err := a.apiSvc()
	if err != nil {
		writeProblemJSON(w, http.StatusInternalServerError, "apitokens.disabled", "API tokens are not enabled in Config", "")
		return r, nil, false
	}
	p, ok := s.principalFromRequest(w, r)
	if !ok {
		return r, nil, false
	}
	ctx := context.WithValue(r.Context(), principalCtxKey{}, p)
	if p.user != nil {
		ctx = context.WithValue(ctx, userKey, p.user)
	}
	return r.WithContext(ctx), p, true
}
