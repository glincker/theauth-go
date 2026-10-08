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
