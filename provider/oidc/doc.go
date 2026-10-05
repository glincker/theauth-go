// Package oidc implements theauth.Provider (and theauth.NonceProvider) for
// any OpenID Connect issuer using discovery. It verifies the ID token
// signature, issuer, audience, expiry and nonce, and always sends PKCE.
package oidc
