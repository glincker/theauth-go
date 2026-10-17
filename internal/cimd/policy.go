// Package cimd implements Client ID Metadata Documents per the MCP Authorization specification
// 2025-11-25. CIMD lets a client publish its metadata at an https URL that is also its client_id.
// The default TrustPolicy is DenyAll, so operators opt in explicitly.
package cimd

import (
	"net/url"
	"strings"
)

// TrustPolicy decides whether an https URL may be fetched as a metadata document. Returning false
// rejects it before any network IO. Implementations must treat the input as untrusted.
type TrustPolicy interface {
	// Allow reports whether rawURL is permitted. The Service has already checked that it is a
	// well-formed https URL.
	Allow(rawURL string) bool
}

// denyAllPolicy rejects every URL. It is the default, and matches the trusted-proxy fail-closed
// default (security audit H4).
type denyAllPolicy struct{}

// Allow on denyAllPolicy always returns false.
func (denyAllPolicy) Allow(string) bool { return false }

// DenyAll returns the fail-closed default policy. Every URL is rejected;
// CIMD resolution falls through to invalid_client without any network IO.
func DenyAll() TrustPolicy { return denyAllPolicy{} }

// allowAnyHTTPSPolicy permits every https URL the Service hands it, which matches the open
// ecosystem baseline. Stricter deployments should prefer AllowHTTPSHost or AllowHTTPSHosts.
type allowAnyHTTPSPolicy struct{}

// Allow on allowAnyHTTPSPolicy returns true for every non-empty input.
// The Service has already validated the URL shape; we trust that here.
func (allowAnyHTTPSPolicy) Allow(raw string) bool { return raw != "" }

// AllowAnyHTTPS accepts every https URL. Use it only when federating with the open MCP ecosystem.
func AllowAnyHTTPS() TrustPolicy { return allowAnyHTTPSPolicy{} }

// allowHostsPolicy permits an exact, case-insensitive host allowlist. Wildcards are not supported;
// implement TrustPolicy for those.
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

// AllowHTTPSHost permits one host, case-insensitively.
func AllowHTTPSHost(host string) TrustPolicy {
	return AllowHTTPSHosts(host)
}

// AllowHTTPSHosts permits any listed host, case-insensitively. An empty list denies everything, so
// a typo cannot allow every host.
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
