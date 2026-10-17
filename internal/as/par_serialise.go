package as

import (
	"encoding/json"
)

// par_serialise.go holds JSON serialization for pushed request payloads, kept human readable in storage.

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
	MaxAge              *int64   `json:"max_age,omitempty"`
	ACRValues           []string `json:"acr_values,omitempty"`
	Prompt              string   `json:"prompt,omitempty"`

	AuthorizationDetails string `json:"authorization_details,omitempty"`
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
		MaxAge:              req.MaxAge,
		ACRValues:           req.ACRValues,
		Prompt:              req.Prompt,

		AuthorizationDetails: req.AuthorizationDetails,
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
		MaxAge:              s.MaxAge,
		ACRValues:           s.ACRValues,
		Prompt:              s.Prompt,

		AuthorizationDetails: s.AuthorizationDetails,
	}, nil
}
