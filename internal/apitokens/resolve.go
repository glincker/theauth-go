package apitokens

import (
	"net/http"
)

// AuthenticatePrincipal resolves the session or bearer token into a Principal with current
// abilities. It writes the 401 or 500 itself on failure.
func (s *Service) AuthenticatePrincipal(w http.ResponseWriter, r *http.Request) (*http.Request, *Principal, bool) {
	p, ok := s.principalFromRequest(w, r)
	if !ok {
		return r, nil, false
	}
	return r.WithContext(s.withPrincipal(r.Context(), p)), p, true
}
