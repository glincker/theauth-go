package cimd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Document is the JSON shape the AS expects when it fetches a CIMD URL.
// Field names mirror RFC 7591 client metadata exactly so a client that
// already publishes an RFC 7591 registration response can serve the same
// document via CIMD with no transformation.
//
// The MCP authorization spec section on CIMD (2025-11-25) adds one
// invariant on top of RFC 7591: the document's client_id field MUST equal
// the URL the AS fetched it from. Without this check a malicious host
// could publish a document claiming to be a different client_id and
// impersonate it at /oauth/authorize.
type Document struct {
	// ClientID is the URL the AS fetched this document from. MUST equal
	// the fetch URL byte-for-byte (after trailing-slash normalization);
	// the impersonation guard rejects documents where it does not.
	ClientID string `json:"client_id"`

	// ClientName is the human-readable name shown on consent screens. May
	// be empty; the AS falls back to ClientID in that case.
	ClientName string `json:"client_name,omitempty"`

	// RedirectURIs is the registered set of redirect URIs. MUST be present
	// and non-empty; OAuth 2.1 requires exact-match redirect URI
	// validation and there must be at least one URI to match against.
	RedirectURIs []string `json:"redirect_uris"`

	// GrantTypes is the set of OAuth grant types the client is allowed
	// to use. Defaults to ["authorization_code", "refresh_token"] when
	// omitted, matching the RFC 7591 default.
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes is the set of OAuth response types the client may
	// request. Defaults to ["code"] when omitted; OAuth 2.1 only
	// supports "code".
	ResponseTypes []string `json:"response_types,omitempty"`

	// TokenEndpointAuthMethod is "none" for public clients (the common
	// MCP case) or "private_key_jwt" for confidential clients that publish
	// their verification keys in Jwks or JwksURI. The client_secret_*
	// methods are rejected: a CIMD document has no place for a secret.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// JwksURI is the https URL of the client's JWK Set (RFC 7591). Required
	// (or Jwks) when TokenEndpointAuthMethod is private_key_jwt. Mutually
	// exclusive with Jwks.
	JwksURI string `json:"jwks_uri,omitempty"`

	// Jwks is the client's inline JWK Set (RFC 7591). Required (or JwksURI)
	// when TokenEndpointAuthMethod is private_key_jwt.
	Jwks json.RawMessage `json:"jwks,omitempty"`

	// cacheTTL is the freshness hint derived from the HTTP Cache-Control
	// header when Config.HonorCacheControl is on. Zero means no hint. It is
	// unexported so it never reaches the shared cache or the wire.
	cacheTTL time.Duration

	// Scope is the space-separated set of scopes the client may request.
	// The AS still narrows against the resource catalog on every grant.
	Scope string `json:"scope,omitempty"`

	// ApplicationType is "web" or "native". Defaults to "web" when
	// omitted.
	ApplicationType string `json:"application_type,omitempty"`

	// ClientURI is the client's homepage URL. Surfaced on consent screens.
	ClientURI string `json:"client_uri,omitempty"`

	// LogoURI is a URL pointing to the client's logo image. Surfaced on
	// consent screens.
	LogoURI string `json:"logo_uri,omitempty"`

	// TosURI is the client's Terms of Service URL.
	TosURI string `json:"tos_uri,omitempty"`

	// PolicyURI is the client's privacy policy URL.
	PolicyURI string `json:"policy_uri,omitempty"`

	// Contacts are the email addresses of people responsible for the
	// client. Optional, surfaced on admin tooling.
	Contacts []string `json:"contacts,omitempty"`

	// SoftwareID + SoftwareVersion are opaque vendor identifiers.
	SoftwareID      string `json:"software_id,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`
}

// ErrInvalidDocument is the sentinel returned by parseAndValidate when
// the document fails any CIMD invariant. The AS maps this to
// invalid_client at the wire.
var ErrInvalidDocument = errors.New("cimd: invalid client metadata document")

// parseAndValidate decodes raw JSON, applies CIMD invariants, and
// returns the validated document. fetchURL is the URL the AS used to
// retrieve the bytes; the document's client_id MUST equal it.
func parseAndValidate(raw []byte, fetchURL string, extraSchemes ...string) (Document, error) {
	if len(raw) == 0 {
		return Document{}, fmt.Errorf("%w: empty body", ErrInvalidDocument)
	}
	var doc Document
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		// Tolerate unknown fields (RFC 7591 explicitly allows extensions).
		// Retry without strict mode rather than rejecting documents that
		// carry vendor extensions like Bluesky's "dpop_bound_access_tokens".
		if uerr := json.Unmarshal(raw, &doc); uerr != nil {
			return Document{}, fmt.Errorf("%w: %v", ErrInvalidDocument, uerr)
		}
	}
	// Impersonation guard: the URL the AS fetched MUST equal the
	// document's claimed client_id. Allow a single trailing slash
	// difference; everything else is rejected as a forgery attempt.
	if !sameURL(doc.ClientID, fetchURL) {
		return Document{}, fmt.Errorf("%w: client_id %q does not match fetch URL %q",
			ErrInvalidDocument, doc.ClientID, fetchURL)
	}
	if len(doc.RedirectURIs) == 0 {
		return Document{}, fmt.Errorf("%w: redirect_uris is required", ErrInvalidDocument)
	}
	for _, u := range doc.RedirectURIs {
		if err := validateRedirectURIWith(u, extraSchemes); err != nil {
			return Document{}, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
		}
	}
	// Defaults that mirror RFC 7591 + OAuth 2.1.
	if len(doc.GrantTypes) == 0 {
		doc.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(doc.ResponseTypes) == 0 {
		doc.ResponseTypes = []string{"code"}
	}
	if doc.TokenEndpointAuthMethod == "" {
		doc.TokenEndpointAuthMethod = "none"
	}
	if doc.ApplicationType == "" {
		doc.ApplicationType = "web"
	}
	if err := validateAuthMethod(doc); err != nil {
		return Document{}, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return doc, nil
}

// validateAuthMethod enforces the token_endpoint_auth_method allowlist.
// "none" and "private_key_jwt" are the only methods a metadata document can
// express safely: there is nowhere to publish a client secret, so the
// client_secret_* family (and anything unrecognised) is refused instead of
// being copied through to a client row that could never authenticate.
func validateAuthMethod(doc Document) error {
	switch doc.TokenEndpointAuthMethod {
	case "none":
		return nil
	case "private_key_jwt":
		hasJWKS := len(doc.Jwks) > 0
		hasURI := doc.JwksURI != ""
		if hasJWKS == hasURI {
			return errors.New("private_key_jwt requires exactly one of jwks or jwks_uri")
		}
		if hasURI {
			u, err := url.Parse(doc.JwksURI)
			if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" {
				return errors.New("jwks_uri must be an absolute https URL")
			}
			return nil
		}
		var set struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(doc.Jwks, &set); err != nil || len(set.Keys) == 0 {
			return errors.New("jwks must be a JWK Set with at least one key")
		}
		return nil
	}
	return fmt.Errorf("token_endpoint_auth_method %q is not allowed in a client metadata document", doc.TokenEndpointAuthMethod)
}

// sameURL compares two URLs ignoring a single trailing slash. Both
// strings are lowercased on the scheme + host segment so case
// differences in the host (RFC 3986 allows them) do not trip the
// impersonation guard.
func sameURL(a, b string) bool {
	return canonicalURL(a) == canonicalURL(b)
}

// canonicalURL trims one trailing slash from the path segment and
// lowercases the scheme + host. Returns the input unchanged on parse
// failure so the equality test still fires and rejects.
func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimRight(u.Path, "/")
	}
	return u.String()
}

// ValidateRedirectURI applies the redirect URI allowlist shared with the
// DCR path: https, loopback http (any port, RFC 8252 section 7.3), or a
// reverse-DNS private-use scheme (RFC 8252 section 7.1). javascript:, data:,
// file: and dotless custom schemes are refused. No fragment, no userinfo.
func ValidateRedirectURI(raw string) error { return validateRedirectURIWith(raw, nil) }

// validateRedirectURIWith is ValidateRedirectURI plus operator-listed
// private-use schemes that skip the reverse-DNS rule. Everything else (no
// fragment, no userinfo, absolute, forbidden schemes) still applies.
func validateRedirectURIWith(raw string, extraSchemes []string) error {
	if raw == "" {
		return errors.New("empty redirect_uri")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("redirect_uri is not a valid URI")
	}
	if u.Scheme == "" {
		return errors.New("redirect_uri must be absolute")
	}
	if u.Fragment != "" {
		return errors.New("redirect_uri must not contain a fragment")
	}
	if u.User != nil {
		return errors.New("redirect_uri must not contain userinfo")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		if u.Hostname() == "" {
			return errors.New("https redirect_uri requires a host")
		}
		return nil
	case "http":
		switch strings.ToLower(u.Hostname()) {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return errors.New("http redirect_uri is only allowed for loopback hosts")
	case "javascript", "data", "file", "vbscript", "blob", "about", "ftp":
		return errors.New("redirect_uri scheme is not allowed")
	}
	for _, allowed := range extraSchemes {
		if scheme == allowed {
			return nil
		}
	}
	labels := strings.Split(scheme, ".")
	if len(labels) < 2 {
		return errors.New("native redirect_uri scheme must be reverse-DNS")
	}
	for _, l := range labels {
		if l == "" {
			return errors.New("native redirect_uri scheme must be reverse-DNS")
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("native redirect_uri scheme must be reverse-DNS")
			}
		}
	}
	return nil
}
