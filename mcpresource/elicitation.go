package mcpresource

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// URLElicitationRequiredCode is the JSON-RPC error code an MCP server returns
// when a request cannot proceed until the user completes an out-of-band
// interaction (MCP URL mode elicitation).
const URLElicitationRequiredCode = -32042

// URLElicitation is an MCP URL mode elicitation: it sends the user to a
// browser page (for example an authorization or consent page) instead of
// collecting data through the MCP client. It is the params object of an
// elicitation/create request and the element type of the data.elicitations
// list in a URLElicitationRequiredError.
type URLElicitation struct {
	Mode          string `json:"mode"`
	ElicitationID string `json:"elicitationId"`
	URL           string `json:"url"`
	Message       string `json:"message"`
}

// NewURLElicitation builds a URL mode elicitation. An empty id gets a random
// 128 bit hex id. The URL must be absolute https (http is accepted only for a
// loopback host) and must not embed credentials. The URL must not carry
// secrets or tokens: clients show it to the user and may log it.
func NewURLElicitation(id, rawURL, message string) (URLElicitation, error) {
	if message == "" {
		return URLElicitation{}, errors.New("mcpresource: elicitation message required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return URLElicitation{}, fmt.Errorf("mcpresource: elicitation url must be absolute: %q", rawURL)
	}
	if u.User != nil {
		return URLElicitation{}, errors.New("mcpresource: elicitation url must not embed credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return URLElicitation{}, errors.New("mcpresource: elicitation url must be https")
		}
	default:
		return URLElicitation{}, fmt.Errorf("mcpresource: elicitation url scheme %q not allowed", u.Scheme)
	}
	if id == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return URLElicitation{}, fmt.Errorf("mcpresource: elicitation id: %w", err)
		}
		id = hex.EncodeToString(b[:])
	}
	return URLElicitation{Mode: "url", ElicitationID: id, URL: rawURL, Message: message}, nil
}

// JSONRPCError is a JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// URLElicitationRequiredData is the data member of a URL elicitation
// required error.
type URLElicitationRequiredData struct {
	Elicitations []URLElicitation `json:"elicitations"`
}

// URLElicitationRequiredError builds the JSON-RPC error (code -32042) a tool
// call returns to tell the client the user must visit one or more URLs
// before the request can succeed, for example to authorize a downstream
// service.
func URLElicitationRequiredError(elicitations ...URLElicitation) JSONRPCError {
	return JSONRPCError{
		Code:    URLElicitationRequiredCode,
		Message: "URL elicitation required",
		Data:    URLElicitationRequiredData{Elicitations: elicitations},
	}
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
