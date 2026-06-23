// Package cimd implements RFC draft "Client ID Metadata Documents" (CIMD)
// per the MCP Authorization specification 2025-11-25. CIMD lets an OAuth
// client publish its RFC 7591 client metadata at a stable https URL whose
// value IS the client_id; the authorization server fetches the document,
// validates it, and uses the resulting metadata in place of a local
// registration row.
//
// CIMD demotes the RFC 7591 Dynamic Client Registration (DCR) flow this
// library has shipped since v2.0 phase 1. DCR remains supported (no
// breaking change) but CIMD is now the preferred client identification
// mechanism. When the AS receives a token-endpoint or authorize-endpoint
// request whose client_id parses as an https URL, the AS routes through
// this package instead of consulting OAuthServerStorage.
//
// Security model: CIMD is open by default in the wild but this library
// fails closed. The default TrustPolicy is DenyAll; operators must opt in
// with AllowAnyHTTPS or AllowHTTPSHosts. This mirrors the H4 audit
// finding (2026-06-20) for X-Forwarded-For: trust is explicit, never
// implicit.
package cimd

import (
	"net/url"
	"strings"
)

// TrustPolicy decides whether an https URL is allowed to be fetched as a
// client metadata document. Returning false rejects the URL before any
// network IO; the AS responds with invalid_client.
//
// Implementations MUST treat the input as untrusted user data: parse with
// net/url, lowercase the host for comparison, and reject anything that
// does not start with "https://" (the cimd.Service short-circuits the
// non-https case before calling Allow but a defensive policy MAY recheck).
type TrustPolicy interface {
	// Allow reports whether rawURL is permitted. The Service guarantees
	// rawURL is a well-formed absolute https URL with no fragment by the
	// time Allow is called; policies should not need to re-parse for
	// scheme correctness.
	Allow(rawURL string) bool
}

// denyAllPolicy rejects every URL. It is the default returned by
// theauth.DenyAll and the implicit default when Config.CIMD.TrustPolicy
// is left nil at construction time. Fail-closed mirrors the security
// audit H4 default for trusted proxies.
type denyAllPolicy struct{}

// Allow on denyAllPolicy always returns false.
func (denyAllPolicy) Allow(string) bool { return false }

// DenyAll returns the fail-closed default policy. Every URL is rejected;
// CIMD resolution falls through to invalid_client without any network IO.
func DenyAll() TrustPolicy { return denyAllPolicy{} }

// allowAnyHTTPSPolicy permits every absolute https URL the Service hands
// it. The Service already enforces scheme=="https" before calling Allow,
// so this is effectively "trust every CIMD document the world publishes",
// which matches the Bluesky / ATProto baseline. Operators that want
// stricter posture should prefer AllowHTTPSHost or AllowHTTPSHosts.
type allowAnyHTTPSPolicy struct{}

// Allow on allowAnyHTTPSPolicy returns true for every non-empty input.
// The Service has already validated the URL shape; we trust that here.
func (allowAnyHTTPSPolicy) Allow(raw string) bool { return raw != "" }

// AllowAnyHTTPS returns a policy that accepts every https URL. Use only
// in deployments that intentionally federate with an open ecosystem of
// MCP clients (the public MCP profile). Production deployments that know
// their clients ahead of time should prefer AllowHTTPSHost.
func AllowAnyHTTPS() TrustPolicy { return allowAnyHTTPSPolicy{} }

// allowHostsPolicy permits an explicit allowlist of hostnames. Host
// comparison is case-insensitive and exact (no suffix wildcards in v1);
// operators that need wildcards can implement TrustPolicy themselves.
type allowHostsPolicy struct {
	hosts map[string]struct{}
}

// Allow checks the parsed host against the allowlist. Returns false on
// parse failure, missing scheme, or unknown host.
func (p allowHostsPolicy) Allow(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	_, ok := p.hosts[host]
	return ok
}

// AllowHTTPSHost returns a TrustPolicy that permits one specific host
// (case-insensitive, exact match). Convenience wrapper around
// AllowHTTPSHosts for the single-host case.
func AllowHTTPSHost(host string) TrustPolicy {
	return AllowHTTPSHosts(host)
}

// AllowHTTPSHosts returns a TrustPolicy that permits any of the supplied
// hosts (case-insensitive, exact match). An empty list produces a
// permanently-deny policy (a typo by the operator must not silently
// allow every host).
func AllowHTTPSHosts(hosts ...string) TrustPolicy {
	set := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		set[h] = struct{}{}
	}
	return allowHostsPolicy{hosts: set}
}
