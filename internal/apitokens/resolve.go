package apitokens

import (
	"net/http"
)

// AuthenticatePrincipal resolves the request's session or API bearer token
// into a Principal with its current abilities, writing the 401 or 500
// response itself when it cannot. The returned request carries the Principal
// and user in its context. Needs Config.APITokens.
func (s *Service) AuthenticatePrincipal(w http.ResponseWriter, r *http.Request) (*http.Request, *Principal, bool) {
	p, ok := s.principalFromRequest(w, r)
	if !ok {
		return r, nil, false
	}
	return r.WithContext(s.withPrincipal(r.Context(), p)), p, true
}
