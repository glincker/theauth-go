// Package oidc implements theauth.Provider (and theauth.NonceProvider) for
// any OpenID Connect issuer using discovery. It verifies the ID token
// signature, issuer, audience, expiry and nonce, and always sends PKCE.
//
// Multi-tenant issuers: an Issuer containing "{tenantid}" (Microsoft Entra
// common, organizations and consumers) is validated by rebuilding the issuer
// from the token's tid claim. Set AllowedTenants to limit which tenants may
// sign in.
//
// Presets (Entra, Okta, Keycloak, Authentik, Auth0) return a Config with the
// discovery URL, scopes and claim mapping filled in.
//
// Every failure after construction is an *Error carrying the provider id, the
// stage (discovery, exchange, verify, userinfo, refresh) and the upstream HTTP
// status; messages never include response bodies or secrets.
package oidc
