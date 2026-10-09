// Package keycloak reads a Keycloak realm export and converts it to the
// migration Bundle format.
//
// Input is the JSON from Realm settings, Action, Partial export (or
// kc.sh export), which has a "users" array. Keycloak's pbkdf2 password hashes
// are converted to theauth's legacy "$pbkdf2-sha256$..." form and verified
// with Config.PasswordPolicy.AllowLegacyBcrypt on, then replaced with Argon2id
// on each user's first successful login, the same path Auth0 bcrypt takes.
// Users whose credential uses another algorithm get a password reset. OTP
// secrets are not migrated; those users re-enroll.
package keycloak

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/cmd/theauth-migrate/internal"
	"github.com/glincker/theauth-go/v2/crypto"
)

// User is one entry of a realm export's "users" array.
type User struct {
	ID               string `json:"id"`
	Username         string `json:"username"`
	Email            string `json:"email"`
	EmailVerified    bool   `json:"emailVerified"`
	Enabled          *bool  `json:"enabled"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	CreatedTimestamp int64  `json:"createdTimestamp"`
	Credentials      []struct {
		Type           string `json:"type"`
		SecretData     string `json:"secretData"`
		CredentialData string `json:"credentialData"`
	} `json:"credentials"`
	FederatedIdentities []struct {
		IdentityProvider string `json:"identityProvider"`
		UserID           string `json:"userId"`
	} `json:"federatedIdentities"`
	Attributes map[string][]string `json:"attributes"`
}

// ReadJSON converts a realm export (an object with "users", or a bare users
// array) into a Bundle. forcePasswordReset drops every password hash.
func ReadJSON(r io.Reader, forcePasswordReset bool) (*internal.Bundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("keycloak json: read: %w", err)
	}
	var users []User
	var wrapper struct {
		Users []User `json:"users"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && wrapper.Users != nil {
		users = wrapper.Users
	} else if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("keycloak json: expected a realm export with a users array: %w", err)
	}

	b := &internal.Bundle{SchemaVersion: internal.SchemaVersion, Source: "keycloak", ExportedAt: time.Now().UTC()}
	b.Notes = append(b.Notes,
		"Keycloak pbkdf2 password hashes are preserved as $pbkdf2-sha256$ or $pbkdf2-sha512$ strings (algo=pbkdf2-sha256 or pbkdf2-sha512).",
		"Enable Config.PasswordPolicy.AllowLegacyBcrypt=true in theauth-go during the migration window; it covers bcrypt and PBKDF2.",
		"On first successful login the hash is re-hashed with Argon2id and the row updated. Disable AllowLegacyBcrypt once active users have logged in.",
		"Keycloak OTP secrets are not migrated; users with OTP are flagged requires_mfa_reenroll=true.",
		"Realm roles, groups, client scopes and required actions are out of scope; recreate them with theauth-go organizations and RBAC.",
	)
	skippedDisabled := 0
	for _, u := range users {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		switch {
		case u.ID == "":
			b.Notes = append(b.Notes, "WARN: user with no id skipped")
			continue
		case email == "":
			b.Notes = append(b.Notes, fmt.Sprintf("WARN: user %q has no email; skipped", u.Username))
			continue
		case u.Enabled != nil && !*u.Enabled:
			skippedDisabled++
			continue
		}
		convert(b, u, email, forcePasswordReset)
	}
	if skippedDisabled > 0 {
		b.Notes = append(b.Notes, fmt.Sprintf("%d disabled Keycloak users were skipped.", skippedDisabled))
	}
	return b, nil
}

func convert(b *internal.Bundle, u User, email string, forceReset bool) {
	created := time.Time{}
	if u.CreatedTimestamp > 0 {
		created = time.UnixMilli(u.CreatedTimestamp).UTC()
	}
	rec := internal.UserRecord{
		SourceID: u.ID, Email: email, Name: strings.TrimSpace(u.FirstName + " " + u.LastName),
		EmailVerified: u.EmailVerified, CreatedAt: created, UpdatedAt: created,
	}
	if len(u.Attributes) > 0 {
		rec.Metadata = make(map[string]string, len(u.Attributes))
		for k, v := range u.Attributes {
			rec.Metadata["attr:"+k] = strings.Join(v, ",")
		}
	}

	hashed := false
	for _, c := range u.Credentials {
		switch c.Type {
		case "password":
			hash, algo, note := convertPassword(c.SecretData, c.CredentialData)
			if hash != "" && !forceReset {
				b.Passwords = append(b.Passwords, internal.PasswordRecord{SourceUserID: u.ID, Hash: hash, Algo: algo})
				hashed = true
			} else if note != "" {
				b.Notes = append(b.Notes, fmt.Sprintf("WARN: user %q: %s", email, note))
			}
		case "otp":
			rec.RequiresMFAReenroll = true
			b.MFAEnrolled = append(b.MFAEnrolled, internal.MFARecord{
				SourceUserID: u.ID, Type: "totp",
				Note: "User had OTP in Keycloak; must re-enroll TOTP on first login.",
			})
		}
	}
	rec.RequiresPasswordReset = !hashed && len(federatedOnly(u)) == 0
	b.Users = append(b.Users, rec)
	for _, fi := range u.FederatedIdentities {
		b.OAuthAccounts = append(b.OAuthAccounts, internal.OAuthAccount{
			SourceUserID: u.ID, Provider: normalizeProvider(fi.IdentityProvider), ProviderUserID: fi.UserID,
		})
	}
}

// federatedOnly returns the user's federated identities when they have no
// password credential at all, so a social-only user is not forced to reset.
func federatedOnly(u User) []string {
	for _, c := range u.Credentials {
		if c.Type == "password" {
			return nil
		}
	}
	var out []string
	for _, fi := range u.FederatedIdentities {
		out = append(out, fi.IdentityProvider)
	}
	return out
}

func convertPassword(secretJSON, credJSON string) (hash, algo, note string) {
	var secret struct {
		Value string `json:"value"`
		Salt  string `json:"salt"`
	}
	var cred struct {
		Algorithm      string `json:"algorithm"`
		HashIterations int    `json:"hashIterations"`
	}
	if json.Unmarshal([]byte(secretJSON), &secret) != nil || json.Unmarshal([]byte(credJSON), &cred) != nil {
		return "", "", "unreadable password credential, password reset required"
	}
	if cred.Algorithm != "pbkdf2-sha256" && cred.Algorithm != "pbkdf2-sha512" {
		return "", "", fmt.Sprintf("password algorithm %q is not supported, password reset required", cred.Algorithm)
	}
	salt, err1 := base64.StdEncoding.DecodeString(secret.Salt)
	key, err2 := base64.StdEncoding.DecodeString(secret.Value)
	if err1 != nil || err2 != nil || len(key) == 0 || cred.HashIterations < 1 {
		return "", "", "malformed pbkdf2 credential, password reset required"
	}
	return crypto.FormatPBKDF2Hash(cred.Algorithm, cred.HashIterations, salt, key), cred.Algorithm, ""
}

var providerMap = map[string]string{"google": "google", "github": "github", "facebook": "facebook", "microsoft": "microsoft", "twitter": "twitter", "linkedin": "linkedin", "apple": "apple"}

func normalizeProvider(p string) string {
	if n, ok := providerMap[strings.ToLower(p)]; ok {
		return n
	}
	return p
}
