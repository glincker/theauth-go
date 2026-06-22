package theauth

import (
	"github.com/glincker/theauth-go/internal/cimd"
)

// cimd.go: public CIMD (Client ID Metadata Documents) surface, per the
// MCP authorization specification 2025-11-25.
//
// CIMD lets an OAuth client publish its RFC 7591 client metadata at a
// stable https URL whose value IS the client_id. The AS fetches the
// URL, validates the document, and uses the metadata in place of a
// locally stored DCR registration. The MCP spec demoted RFC 7591 DCR
// (still supported) in favor of CIMD as the preferred client
// identification mechanism because CIMD eliminates the server-side
// registration step entirely.
//
// Wire CIMD on Config.AuthorizationServer.CIMD; the field is optional
// and additive. When nil, theauth-go behaves exactly as it did pre-CIMD
// (every client_id consults OAuthServerStorage).

// CIMDConfig wires the CIMD service onto the AS. Set on
// AuthorizationServerConfig.CIMD to enable https-URL client_id
// resolution. Defaults to DenyAll (fail-closed); operators must opt in
// to a permissive policy explicitly.
//
// Aliased from internal/cimd so consumers can wire CIMDConfig{...} at
// the public surface without importing the internal package.
type CIMDConfig = cimd.Config

// CIMDTrustPolicy decides which https client_id URLs the AS is allowed
// to fetch as CIMD documents. Aliased from internal/cimd.TrustPolicy.
type CIMDTrustPolicy = cimd.TrustPolicy

// DenyAll returns a CIMDTrustPolicy that rejects every URL. This is the
// fail-closed default applied when CIMDConfig.TrustPolicy is nil and is
// the default returned here so operator code reads naturally:
//
//	cfg.AuthorizationServer.CIMD = &theauth.CIMDConfig{
//	    TrustPolicy: theauth.DenyAll(), // explicit acknowledgement
//	}
//
// DenyAll mirrors the security audit H4 default for TrustedProxies:
// trust must be explicit, never implicit.
func DenyAll() CIMDTrustPolicy { return cimd.DenyAll() }

// AllowAnyHTTPS returns a CIMDTrustPolicy that permits every absolute
// https URL. Use only in deployments that intentionally federate with
// the open MCP ecosystem; production deployments that know their
// clients ahead of time should prefer AllowHTTPSHost.
func AllowAnyHTTPS() CIMDTrustPolicy { return cimd.AllowAnyHTTPS() }

// AllowHTTPSHost returns a CIMDTrustPolicy that permits one specific
// host (case-insensitive, exact match).
func AllowHTTPSHost(host string) CIMDTrustPolicy { return cimd.AllowHTTPSHost(host) }

// AllowHTTPSHosts returns a CIMDTrustPolicy that permits any of the
// supplied hosts (case-insensitive, exact match). An empty list
// produces a permanently-deny policy so a typo cannot silently allow
// every host.
func AllowHTTPSHosts(hosts ...string) CIMDTrustPolicy { return cimd.AllowHTTPSHosts(hosts...) }
