package as

import (
	"encoding/json"
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
