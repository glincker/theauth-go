package tokenvault

import (
	"fmt"
	"net/http"
	"net/url"
)

// AuthStyle is how the token request carries the client credentials.
type AuthStyle int

const (
	// AuthBasic sends HTTP Basic auth (client_secret_basic). The zero value.
	AuthBasic AuthStyle = iota
	// AuthPost sends client_id and client_secret in the form body (client_secret_post).
	AuthPost
)

// RefreshKind says when a provider issues refresh tokens.
type RefreshKind string

const (
	RefreshAlways         RefreshKind = "always"
	RefreshOptIn          RefreshKind = "opt_in"          // only after a provider setting is enabled
	RefreshAuthorizeParam RefreshKind = "authorize_param" // needs extra authorize query params
	RefreshScope          RefreshKind = "scope"           // needs the offline_access scope
)

// Preset is static data about one provider. Scopes are chosen by the caller.
type Preset struct {
	ID               string
	Name             string
	AuthorizationURL string
	TokenURL         string
	Refresh          RefreshKind
	RefreshNote      string
	// AuthorizeParams are extra authorize query params needed for a refresh token.
	AuthorizeParams map[string]string
	ExampleScopes   []string
	AuthStyle       AuthStyle
	DocsURL         string
}

// Presets maps preset id to its data. Treat it as read only.
var Presets = map[string]Preset{
	"github": {
		ID: "github", Name: "GitHub",
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		Refresh:          RefreshOptIn,
		RefreshNote:      "OAuth app tokens do not expire unless token expiration is enabled; then access tokens last 8 hours and refresh tokens rotate (6 months idle).",
		ExampleScopes:    []string{"repo", "read:user", "gist"},
		AuthStyle:        AuthPost,
		DocsURL:          "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps",
	},
	"google": {
		ID: "google", Name: "Google",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token",
		Refresh:          RefreshAuthorizeParam,
		RefreshNote:      "Refresh token is returned only with access_type=offline, usually on the first consent; add prompt=consent to get a new one.",
		AuthorizeParams:  map[string]string{"access_type": "offline", "prompt": "consent"},
		ExampleScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
			"https://www.googleapis.com/auth/calendar.readonly",
			"https://www.googleapis.com/auth/drive.file",
		},
		AuthStyle: AuthPost,
		DocsURL:   "https://developers.google.com/identity/protocols/oauth2/web-server",
	},
	"slack": {
		ID: "slack", Name: "Slack",
		AuthorizationURL: "https://slack.com/oauth/v2/authorize",
		TokenURL:         "https://slack.com/api/oauth.v2.access",
		Refresh:          RefreshOptIn,
		RefreshNote:      "Tokens do not expire unless token rotation is enabled for the app (cannot be turned off); then access tokens last 12 hours and refresh tokens are single use.",
		ExampleScopes:    []string{"channels:read", "chat:write", "channels:history"},
		AuthStyle:        AuthPost,
		DocsURL:          "https://docs.slack.dev/authentication/using-token-rotation",
	},
	"linear": {
		ID: "linear", Name: "Linear",
		AuthorizationURL: "https://linear.app/oauth/authorize",
		TokenURL:         "https://api.linear.app/oauth/token",
		Refresh:          RefreshAlways,
		RefreshNote:      "Access tokens last 24 hours; each refresh returns a new refresh token (30 minute replay grace).",
		ExampleScopes:    []string{"read", "issues:create", "comments:create"},
		AuthStyle:        AuthPost,
		DocsURL:          "https://linear.app/developers/oauth-2-0-authentication",
	},
	"microsoft": {
		ID: "microsoft", Name: "Microsoft (Entra v2, common)",
		AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		Refresh:          RefreshScope,
		RefreshNote:      "Refresh token is returned only when the offline_access scope is requested.",
		ExampleScopes:    []string{"offline_access", "https://graph.microsoft.com/mail.read", "openid"},
		AuthStyle:        AuthPost,
		DocsURL:          "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow",
	},
	"discord": {
		ID: "discord", Name: "Discord",
		AuthorizationURL: "https://discord.com/oauth2/authorize",
		TokenURL:         "https://discord.com/api/oauth2/token",
		Refresh:          RefreshAlways,
		RefreshNote:      "Authorization code grant returns a refresh token; the implicit and client credentials grants do not.",
		ExampleScopes:    []string{"identify", "email", "guilds"},
		AuthStyle:        AuthBasic,
		DocsURL:          "https://docs.discord.com/developers/topics/oauth2",
	},
}

// RefresherFromPreset builds an OAuthRefresher for a preset id. It makes no
// network call and refuses a preset whose token URL is not https.
func RefresherFromPreset(id, clientID, clientSecret string, httpClient *http.Client) (OAuthRefresher, error) {
	p, ok := Presets[id]
	if !ok {
		return OAuthRefresher{}, fmt.Errorf("tokenvault: unknown provider preset %q", id)
	}
	if u, err := url.Parse(p.TokenURL); err != nil || u.Scheme != "https" {
		return OAuthRefresher{}, fmt.Errorf("tokenvault: preset %q token URL must be https", id)
	}
	return OAuthRefresher{
		TokenURL:     p.TokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		HTTPClient:   httpClient,
		AuthStyle:    p.AuthStyle,
	}, nil
}
