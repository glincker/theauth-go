package as

import (
	"encoding/json"
	"strings"
)

// par_serialise.go: JSON serialisation helpers for pushed authorization
// request payloads. Using encoding/json keeps the payload human-readable
// in storage and avoids a dependency on any binary format.

type serializedAuthorizeRequest struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scope               []string `json:"scope"`
	State               string   `json:"state,omitempty"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	Resource            string   `json:"resource"`
	Nonce               string   `json:"nonce,omitempty"`
}

func serializeAuthorizeRequest(req AuthorizeRequest) ([]byte, error) {
	return json.Marshal(serializedAuthorizeRequest{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		ResponseType:        req.ResponseType,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Resource:            req.Resource,
		Nonce:               req.Nonce,
	})
}

func deserializeAuthorizeRequest(payload []byte) (AuthorizeRequest, error) {
	var s serializedAuthorizeRequest
	if err := json.Unmarshal(payload, &s); err != nil {
		return AuthorizeRequest{}, err
	}
	return AuthorizeRequest{
		ClientID:            s.ClientID,
		RedirectURI:         s.RedirectURI,
		ResponseType:        s.ResponseType,
		Scope:               s.Scope,
		State:               s.State,
		CodeChallenge:       s.CodeChallenge,
		CodeChallengeMethod: s.CodeChallengeMethod,
		Resource:            s.Resource,
		Nonce:               s.Nonce,
	}, nil
}

// scopeSplitIntoSlice is a thin wrapper so par.go can use scope normalization.
// Mirrors internal/as.scopeSplit.
func scopeSplitIntoSlice(s string) []string {
	parts := strings.Fields(s)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
