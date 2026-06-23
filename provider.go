package theauth

import internaloauth "github.com/glincker/theauth-go/internal/oauth"

// Provider is the contract every OAuth 2.0 / OIDC provider implements. Each
// concrete provider lives in its own sub-package under provider/<name>/ so
// consumers can pick what to import (avoids dragging in HTTP clients for
// providers they will never use).
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type Provider = internaloauth.Provider

// ProviderToken is the normalized shape of an OAuth token exchange response.
// Providers vary in which fields they populate (e.g. GitHub typically omits
// RefreshToken and ExpiresAt for "no-expiry" tokens). Storage encrypts the
// access/refresh tokens at rest via crypto.Encrypt.
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type ProviderToken = internaloauth.ProviderToken

// ProviderUser is the normalized shape of a provider's userinfo response.
// ID is the provider-stable user identifier (e.g. GitHub numeric id as a
// string) and is what oauth_accounts.provider_user_id stores. Email may be
// empty when the user denied the email scope or has no public email on the
// provider; EmailVerified is true only when the provider attests to it.
//
// The type moved to internal/oauth in PR H (2026-06-22); this alias keeps
// the v0.3+ public surface byte-stable.
type ProviderUser = internaloauth.ProviderUser
