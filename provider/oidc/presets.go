package oidc

import "strings"

// presets.go: ready-made Config values for common identity providers. Each
// returns a Config you can adjust before passing to New, for example to add
// scopes, AllowedTenants or an HTTPClient.

// Entra returns a Config for Microsoft Entra ID (v2.0 endpoints). tenant is a
// tenant GUID or verified domain for a single-tenant app, or one of
// "common", "organizations" or "consumers" for a multi-tenant app. Multi
// tenant issuers are validated against the token's tid claim; set
// AllowedTenants to limit which tenants may sign in, because "common" admits
// every Entra tenant. The preset reads the email claim (often absent from
// Entra ID tokens; add it as an optional claim) and treats the optional
// xms_edov claim as email verification, so an unverified Entra email is never
// trusted for account linking.
func Entra(tenant, clientID, clientSecret string) Config {
	const base = "https://login.microsoftonline.com/"
	issuer := base + tenant + "/v2.0"
	for _, alias := range multiTenantAliases {
		if tenant == alias {
			issuer = base + tenantPlaceholder + "/v2.0"
		}
	}
	return Config{
		Name:         "entra",
		Issuer:       issuer,
		DiscoveryURL: base + tenant + "/v2.0/.well-known/openid-configuration",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Claims:       ClaimMapping{Subject: "sub", Email: "email", EmailVerified: "xms_edov", Name: "name"},
	}
}

// Okta returns a Config for an Okta org or custom authorization server.
// domain is the host, optionally with an authorization server path:
// "dev-123456.okta.com" or "dev-123456.okta.com/oauth2/default".
func Okta(domain, clientID, clientSecret string) Config {
	issuer := "https://" + trimHostPath(domain)
	return Config{
		Name:         "okta",
		Issuer:       issuer,
		DiscoveryURL: issuer + "/.well-known/openid-configuration",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Claims:       ClaimMapping{Subject: "sub", Email: "email", EmailVerified: "email_verified", Name: "name", Picture: "picture"},
	}
}

// Keycloak returns a Config for a Keycloak realm. baseURL is the server root
// (for example "https://sso.example.com", plus "/auth" on legacy
// distributions).
func Keycloak(baseURL, realm, clientID, clientSecret string) Config {
	issuer := strings.TrimRight(baseURL, "/") + "/realms/" + realm
	return Config{
		Name:         "keycloak",
		Issuer:       issuer,
		DiscoveryURL: issuer + "/.well-known/openid-configuration",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Claims:       ClaimMapping{Subject: "sub", Email: "email", EmailVerified: "email_verified", Name: "name", Picture: "picture"},
	}
}

// Authentik returns a Config for an authentik OAuth2/OpenID provider.
// baseURL is the authentik server root and slug the application slug. The
// issuer carries a trailing slash, as authentik publishes it.
func Authentik(baseURL, slug, clientID, clientSecret string) Config {
	issuer := strings.TrimRight(baseURL, "/") + "/application/o/" + slug + "/"
	return Config{
		Name:         "authentik",
		Issuer:       issuer,
		DiscoveryURL: issuer + ".well-known/openid-configuration",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Claims:       ClaimMapping{Subject: "sub", Email: "email", EmailVerified: "email_verified", Name: "name", Picture: "picture"},
	}
}

// Auth0 returns a Config for an Auth0 tenant. domain is the tenant or custom
// domain host, for example "example.us.auth0.com". The issuer carries a
// trailing slash, as Auth0 publishes it.
func Auth0(domain, clientID, clientSecret string) Config {
	issuer := "https://" + trimHostPath(domain) + "/"
	return Config{
		Name:         "auth0",
		Issuer:       issuer,
		DiscoveryURL: issuer + ".well-known/openid-configuration",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Claims:       ClaimMapping{Subject: "sub", Email: "email", EmailVerified: "email_verified", Name: "name", Picture: "picture"},
	}
}

// Cognito returns a Config for an Amazon Cognito user pool. region is the
// AWS region ("us-east-1") and userPoolID the pool id ("us-east-1_AbCdEfGhI").
// The issuer is the original per-region form
// https://cognito-idp.{region}.amazonaws.com/{userPoolID}, which is the one
// Cognito puts in ID tokens by default. Pools configured with the updated
// issuer (issuer-cognito-idp) need Issuer and DiscoveryURL overridden.
// Docs: https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html
// Cognito answers PKCE and accepts client credentials in the body or a Basic
// header. email_verified is a string in the userInfo response and a boolean in
// the ID token; both read as verified when "true".
func Cognito(region, userPoolID, clientID, clientSecret string) Config {
	issuer := "https://cognito-idp." + region + ".amazonaws.com/" + userPoolID
	return Config{
		Name:         "cognito",
		Issuer:       issuer,
		DiscoveryURL: issuer + "/.well-known/openid-configuration",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Claims:       ClaimMapping{Subject: "sub", Email: "email", EmailVerified: "email_verified", Name: "name", Picture: "picture"},
	}
}

// trimHostPath drops a scheme and trailing slashes from a host (and optional
// path) so callers may paste either form.
func trimHostPath(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	return strings.TrimRight(s, "/")
}
