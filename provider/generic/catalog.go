package generic

import (
	"fmt"
	"sort"

	"github.com/glincker/theauth-go/v2"
)

// catalog is the built-in provider table. Only providers whose token
// response is JSON and whose profile arrives in one userinfo call belong
// here. EmailVerified is mapped only where the provider states it; the
// rest report false, so account linking will not trust their emails.
var catalog = map[string]Spec{
	"spotify": {
		Name: "spotify", AuthURL: "https://accounts.spotify.com/authorize",
		TokenURL: "https://accounts.spotify.com/api/token", UserURL: "https://api.spotify.com/v1/me",
		Scopes: []string{"user-read-email"}, TokenBasicAuth: true,
		Fields: Fields{ID: []string{"id"}, Email: []string{"email"}, Name: []string{"display_name"}, AvatarURL: []string{"images.0.url"}},
	},
	"dropbox": {
		Name: "dropbox", AuthURL: "https://www.dropbox.com/oauth2/authorize",
		TokenURL: "https://api.dropboxapi.com/oauth2/token", UserURL: "https://api.dropboxapi.com/2/users/get_current_account",
		Scopes: []string{"account_info.read"}, UserMethod: "POST",
		AuthParams: map[string]string{"token_access_type": "online"},
		Fields: Fields{ID: []string{"account_id"}, Email: []string{"email"}, EmailVerified: []string{"email_verified"},
			Name: []string{"name.display_name"}, AvatarURL: []string{"profile_photo_url"}},
	},
	"zoom": {
		Name: "zoom", AuthURL: "https://zoom.us/oauth/authorize",
		TokenURL: "https://zoom.us/oauth/token", UserURL: "https://api.zoom.us/v2/users/me",
		TokenBasicAuth: true,
		Fields:         Fields{ID: []string{"id"}, Email: []string{"email"}, Name: []string{"display_name"}, AvatarURL: []string{"pic_url"}},
	},
	"kakao": {
		Name: "kakao", AuthURL: "https://kauth.kakao.com/oauth/authorize",
		TokenURL: "https://kauth.kakao.com/oauth/token", UserURL: "https://kapi.kakao.com/v2/user/me",
		Scopes: []string{"account_email", "profile_nickname", "profile_image"},
		Fields: Fields{ID: []string{"id"}, Email: []string{"kakao_account.email"}, EmailVerified: []string{"kakao_account.is_email_verified"},
			Name: []string{"kakao_account.profile.nickname"}, AvatarURL: []string{"kakao_account.profile.profile_image_url"}},
	},
	"naver": {
		Name: "naver", AuthURL: "https://nid.naver.com/oauth2.0/authorize",
		TokenURL: "https://nid.naver.com/oauth2.0/token", UserURL: "https://openapi.naver.com/v1/nid/me",
		Fields: Fields{ID: []string{"response.id"}, Email: []string{"response.email"}, Name: []string{"response.name", "response.nickname"},
			AvatarURL: []string{"response.profile_image"}},
	},
	"patreon": {
		Name: "patreon", AuthURL: "https://www.patreon.com/oauth2/authorize",
		TokenURL: "https://www.patreon.com/api/oauth2/token", UserURL: "https://www.patreon.com/api/oauth2/v2/identity",
		UserQuery: "fields%5Buser%5D=email,full_name,image_url,is_email_verified",
		Scopes:    []string{"identity", "identity[email]"},
		Fields: Fields{ID: []string{"data.id"}, Email: []string{"data.attributes.email"}, EmailVerified: []string{"data.attributes.is_email_verified"},
			Name: []string{"data.attributes.full_name"}, AvatarURL: []string{"data.attributes.image_url"}},
	},
	"box": {
		Name: "box", AuthURL: "https://account.box.com/api/oauth2/authorize",
		TokenURL: "https://api.box.com/oauth2/token", UserURL: "https://api.box.com/2.0/users/me",
		Fields: Fields{ID: []string{"id"}, Email: []string{"login"}, Name: []string{"name"}, AvatarURL: []string{"avatar_url"}},
	},
	"salesforce": {
		Name: "salesforce", AuthURL: "https://login.salesforce.com/services/oauth2/authorize",
		TokenURL: "https://login.salesforce.com/services/oauth2/token", UserURL: "https://login.salesforce.com/services/oauth2/userinfo",
		Scopes: []string{"openid", "email", "profile"},
		Fields: Fields{ID: []string{"user_id"}, Email: []string{"email"}, EmailVerified: []string{"email_verified"},
			Name: []string{"name"}, AvatarURL: []string{"picture"}},
	},
	"figma": {
		Name: "figma", AuthURL: "https://www.figma.com/oauth",
		TokenURL: "https://api.figma.com/v1/oauth/token", UserURL: "https://api.figma.com/v1/me",
		Scopes: []string{"current_user:read"}, TokenBasicAuth: true, ScopeSeparator: ",",
		Fields: Fields{ID: []string{"id"}, Email: []string{"email"}, Name: []string{"handle"}, AvatarURL: []string{"img_url"}},
	},
	// linear: https://linear.app/developers/oauth-2-0-authentication
	// Scopes are comma separated. The profile is a GraphQL viewer query; the
	// OAuth guide shows id and name and the GraphQL guide adds email. The
	// avatar field is not documented there, so it is not requested. Linear
	// does not state email verification, so EmailVerified is unmapped.
	"linear": {
		Name: "linear", AuthURL: "https://linear.app/oauth/authorize",
		TokenURL: "https://api.linear.app/oauth/token", UserURL: "https://api.linear.app/graphql",
		Scopes: []string{"read"}, ScopeSeparator: ",", UserMethod: "POST",
		UserBody: `{"query":"{ viewer { id name email } }"}`,
		Fields: Fields{ID: []string{"data.viewer.id"}, Email: []string{"data.viewer.email"},
			Name: []string{"data.viewer.name"}},
	},
	// paypal: https://developer.paypal.com/docs/log-in-with-paypal/integrate/
	// Client credentials go in a Basic header. PayPal's guides do not
	// describe PKCE, so none is sent. The login URL carries flowEntry=static.
	// The field names come from the Identity API reference; the response per
	// schema value is not spelled out, so the email falls back to emails.0.
	// EmailVerified is unmapped on purpose.
	"paypal": {
		Name: "paypal", AuthURL: "https://www.paypal.com/connect",
		TokenURL: "https://api-m.paypal.com/v1/oauth2/token",
		UserURL:  "https://api-m.paypal.com/v1/identity/openidconnect/userinfo", UserQuery: "schema=openid",
		Scopes: []string{"openid", "email", "profile"}, TokenBasicAuth: true, NoPKCE: true,
		AuthParams: map[string]string{"flowEntry": "static"},
		Fields: Fields{ID: []string{"user_id", "sub"}, Email: []string{"email", "emails.0.value"},
			Name: []string{"name"}, AvatarURL: []string{"picture"}},
	},
	// kick: https://docs.kick.com/getting-started/generating-tokens-oauth2-flow
	// and https://docs.kick.com/apis/users. PKCE S256 is required. The
	// profile call lives on api.kick.com and answers {"data":[{...}]}.
	"kick": {
		Name: "kick", AuthURL: "https://id.kick.com/oauth/authorize",
		TokenURL: "https://id.kick.com/oauth/token", UserURL: "https://api.kick.com/public/v1/users",
		Scopes: []string{"user:read"},
		Fields: Fields{ID: []string{"data.0.user_id"}, Email: []string{"data.0.email"},
			Name: []string{"data.0.name"}, AvatarURL: []string{"data.0.profile_picture"}},
	},
	// huggingface: https://huggingface.co/docs/hub/en/oauth and the
	// discovery document at https://huggingface.co/.well-known/openid-configuration.
	// PKCE S256; client credentials in the body or a Basic header.
	"huggingface": {
		Name: "huggingface", AuthURL: "https://huggingface.co/oauth/authorize",
		TokenURL: "https://huggingface.co/oauth/token", UserURL: "https://huggingface.co/oauth/userinfo",
		Scopes: []string{"openid", "profile", "email"},
		Fields: Fields{ID: []string{"sub"}, Email: []string{"email"}, EmailVerified: []string{"email_verified"},
			Name: []string{"name", "preferred_username"}, AvatarURL: []string{"picture"}},
	},
	// vercel: https://vercel.com/docs/sign-in-with-vercel/authorization-server-api
	// PKCE S256 is required and userinfo is a POST. A refresh token needs the
	// offline_access scope. Names the "Sign in with Vercel" app flow, not
	// the marketplace integration OAuth.
	"vercel": {
		Name: "vercel", AuthURL: "https://vercel.com/oauth/authorize",
		TokenURL: "https://api.vercel.com/login/oauth/token", UserURL: "https://api.vercel.com/login/oauth/userinfo",
		Scopes: []string{"openid", "email", "profile"}, UserMethod: "POST",
		Fields: Fields{ID: []string{"sub"}, Email: []string{"email"}, EmailVerified: []string{"email_verified"},
			Name: []string{"name", "preferred_username"}, AvatarURL: []string{"picture"}},
	},
	// yandex: https://yandex.com/dev/id/doc/en/codes/code-url and
	// https://yandex.com/dev/id/doc/en/user-information. Scopes are comma
	// separated, userinfo uses the OAuth scheme, and the avatar is an id that
	// expands to an avatars.yandex.net URL.
	"yandex": {
		Name: "yandex", AuthURL: "https://oauth.yandex.com/authorize",
		TokenURL: "https://oauth.yandex.com/token", UserURL: "https://login.yandex.ru/info", UserQuery: "format=json",
		Scopes: []string{"login:email", "login:info", "login:avatar"}, ScopeSeparator: ",", UserAuthScheme: "OAuth",
		Fields: Fields{ID: []string{"id"}, Email: []string{"default_email"},
			Name: []string{"real_name", "display_name"}, AvatarURL: []string{"default_avatar_id"},
			AvatarURLFormat: "https://avatars.yandex.net/get-yapic/%s/islands-200"},
	},
	"codeberg": {
		Name: "codeberg", AuthURL: "https://codeberg.org/login/oauth/authorize",
		TokenURL: "https://codeberg.org/login/oauth/access_token", UserURL: "https://codeberg.org/api/v1/user",
		Fields: Fields{ID: []string{"id"}, Email: []string{"email"}, Name: []string{"full_name", "login"}, AvatarURL: []string{"avatar_url"}},
	},
}

// Names lists the built-in provider names in sorted order.
func Names() []string {
	out := make([]string, 0, len(catalog))
	for n := range catalog {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup returns a copy of the built-in Spec for name.
func Lookup(name string) (Spec, bool) {
	s, ok := catalog[name]
	if !ok {
		return Spec{}, false
	}
	s.Scopes = append([]string(nil), s.Scopes...)
	return s, true
}

// NewByName builds a built-in provider, for example NewByName("spotify", cfg).
func NewByName(name string, cfg Config) (theauth.Provider, error) {
	s, ok := Lookup(name)
	if !ok {
		return nil, fmt.Errorf("generic: unknown provider %q", name)
	}
	return New(s, cfg)
}
