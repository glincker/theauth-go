package device

import (
	"errors"
	"strings"
)

var errToken = errors.New("device: malformed token")

// jws is a parsed compact JWS (RFC 7515 section 7.1) whose signature is not yet checked.
type jws struct {
	header  map[string]any
	payload []byte
	input   []byte
	sig     []byte
}

func parseJWS(tok string) (*jws, error) {
	h, rest, ok := strings.Cut(tok, ".")
	if !ok {
		return nil, errToken
	}
	p, s, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(s, ".") {
		return nil, errToken
	}
	hb, err := b64.DecodeString(h)
	if err != nil {
		return nil, errToken
	}
	pb, err := b64.DecodeString(p)
	if err != nil {
		return nil, errToken
	}
	sb, err := b64.DecodeString(s)
	if err != nil {
		return nil, errToken
	}
	hv, err := parseJSON(hb)
	if err != nil {
		return nil, errToken
	}
	hm, ok := hv.(map[string]any)
	if !ok {
		return nil, errToken
	}
	if _, crit := hm["crit"]; crit {
		return nil, errToken // no critical extensions are understood (RFC 7515 section 4.1.11)
	}
	return &jws{header: hm, payload: pb, input: []byte(h + "." + p), sig: sb}, nil
}

// typMatches compares typ the way RFC 7515 section 4.1.9 allows: case insensitive, with
// an optional "application/" prefix.
func typMatches(got any, want string) bool {
	s, ok := got.(string)
	if !ok {
		return false
	}
	norm := func(v string) string {
		v = strings.ToLower(v)
		if !strings.Contains(v, "/") {
			v = "application/" + v
		}
		return v
	}
	return norm(s) == norm(want)
}

func signJWS(s *Signer, header, payload map[string]any) (string, error) {
	hb := appendJSON(nil, header)
	pb := appendJSON(nil, payload)
	input := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	sig, err := s.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}
