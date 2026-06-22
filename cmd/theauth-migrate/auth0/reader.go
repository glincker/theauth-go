// Package auth0 reads Auth0 user-pool exports and converts them to the
// migration Bundle format.
//
// Two input formats are supported:
//
//  1. Auth0 Management API user export JSON - the array of user objects from
//     GET /api/v2/users, or the output from the Export Users extension.
//
//  2. Auth0 connection export - an identities array nested inside the user
//     object (the "identities" field from the Management API).
//
// Auth0 bcrypt password hashes ARE exported for database connections. They
// are preserved in the Bundle's Passwords slice with algo="bcrypt". The
// theauth-go library will verify them via the legacy-bcrypt fallback (enabled
// with Config.PasswordPolicy.AllowLegacyBcrypt=true) and transparently
// re-hash with Argon2id on first successful login.
//
// TOTP (Guardian MFA) secrets cannot be exported from Auth0; users with MFA
// are flagged requires_mfa_reenroll=true.
//
// Auth0 rules and hooks are out of scope; a note is added to the bundle.
package auth0

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/glincker/theauth-go/cmd/theauth-migrate/internal"
)

// Auth0User matches the shape of a user object from the Auth0 Management API
// GET /api/v2/users response.
type Auth0User struct {
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	LastLogin     string `json:"last_login"`
	// PasswordHash is only present for database connection users when exported
	// via the bulk export job with password_hash included.
	PasswordHash string `json:"password_hash,omitempty"`
	// Identities lists all social/enterprise connections for the user.
	Identities []Auth0Identity `json:"identities"`
	// AppMetadata contains operator-defined metadata.
	AppMetadata map[string]interface{} `json:"app_metadata,omitempty"`
	// UserMetadata contains user-editable metadata.
	UserMetadata map[string]interface{} `json:"user_metadata,omitempty"`
	// Multifactor lists enrolled MFA providers.
	Multifactor []string `json:"multifactor,omitempty"`
	// Blocked indicates the account is blocked.
	Blocked bool `json:"blocked,omitempty"`
}

// Auth0Identity represents one connected identity provider for a user.
type Auth0Identity struct {
	// Connection is the Auth0 connection name.
	Connection string `json:"connection"`
	// Provider is "auth0", "google-oauth2", "github", "facebook", etc.
	Provider string `json:"provider"`
	// UserID is the provider-scoped identifier (without the "provider|" prefix).
	UserID string `json:"user_id"`
	// IsSocial indicates the identity comes from a social connection.
	IsSocial bool `json:"isSocial"`
	// ProfileData contains provider-fetched profile data.
	ProfileData map[string]interface{} `json:"profileData,omitempty"`
}

// ReadJSON reads an Auth0 user export from r. The input may be:
//   - A JSON array of Auth0User objects.
//   - A single Auth0User object (AdminGetUser style).
//   - A JSON object with a "users" key (Management API list response).
func ReadJSON(r io.Reader, forcePasswordReset bool) (*internal.Bundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("auth0 json: read: %w", err)
	}

	var rawUsers []Auth0User

	// Try JSON array first.
	if err := json.Unmarshal(data, &rawUsers); err != nil {
		// Try single-object.
		var single Auth0User
		if err2 := json.Unmarshal(data, &single); err2 == nil && single.UserID != "" {
			rawUsers = []Auth0User{single}
		} else {
			// Try Management API pagination wrapper: {"users":[...], "total":...}
			var wrapper struct {
				Users []Auth0User `json:"users"`
			}
			if err3 := json.Unmarshal(data, &wrapper); err3 != nil {
				return nil, fmt.Errorf("auth0 json: cannot parse as array, single object, or pagination wrapper: %v", err)
			}
			rawUsers = wrapper.Users
		}
	}

	bundle := &internal.Bundle{
		SchemaVersion: internal.SchemaVersion,
		Source:        "auth0",
		ExportedAt:    time.Now().UTC(),
	}
	bundle.Notes = append(bundle.Notes,
		"Auth0 bcrypt password hashes are preserved in the passwords array (algo=bcrypt).",
		"Enable Config.PasswordPolicy.AllowLegacyBcrypt=true in theauth-go during the migration window.",
		"On first successful login the hash is transparently re-hashed with Argon2id and the row is updated.",
		"Disable AllowLegacyBcrypt once all active users have logged in (typically 30-90 days post-migration).",
		"Auth0 Guardian MFA secrets cannot be exported; users with MFA are flagged requires_mfa_reenroll=true.",
		"Auth0 rules and hooks are out of scope; re-implement them as theauth-go middleware or lifecycle hooks.",
	)

	for _, au := range rawUsers {
		if au.UserID == "" {
			bundle.Notes = append(bundle.Notes, "WARN: user with no user_id found in export; skipped")
			continue
		}
		email := strings.ToLower(au.Email)
		if email == "" {
			bundle.Notes = append(bundle.Notes,
				fmt.Sprintf("WARN: user %q has no email; skipped", au.UserID),
			)
			continue
		}

		name := au.Name
		if name == "" {
			name = strings.TrimSpace(au.GivenName + " " + au.FamilyName)
		}

		createdAt := parseAuth0Time(au.CreatedAt)
		updatedAt := parseAuth0Time(au.UpdatedAt)
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}

		hasMFA := len(au.Multifactor) > 0

		requiresReset := forcePasswordReset
		// If no hash is available and the primary identity is database, user
		// must reset.
		if au.PasswordHash == "" && isPrimaryDatabaseUser(au) {
			requiresReset = true
		}

		// Flatten app_metadata + user_metadata to string map.
		meta := make(map[string]string)
		for k, v := range au.AppMetadata {
			meta["app:"+k] = fmt.Sprintf("%v", v)
		}
		for k, v := range au.UserMetadata {
			meta["user:"+k] = fmt.Sprintf("%v", v)
		}

		ur := internal.UserRecord{
			SourceID:              au.UserID,
			Email:                 email,
			Name:                  name,
			EmailVerified:         au.EmailVerified,
			RequiresPasswordReset: requiresReset,
			RequiresMFAReenroll:   hasMFA,
			CreatedAt:             createdAt,
			UpdatedAt:             updatedAt,
		}
		if len(meta) > 0 {
			ur.Metadata = meta
		}
		bundle.Users = append(bundle.Users, ur)

		// Password record (bcrypt hash from database connection).
		if au.PasswordHash != "" && !forcePasswordReset {
			bundle.Passwords = append(bundle.Passwords, internal.PasswordRecord{
				SourceUserID: au.UserID,
				Hash:         au.PasswordHash,
				Algo:         "bcrypt",
			})
		}

		// OAuth/social identity connections.
		for _, id := range au.Identities {
			if !id.IsSocial {
				continue
			}
			provider := normalizeProvider(id.Provider)
			bundle.OAuthAccounts = append(bundle.OAuthAccounts, internal.OAuthAccount{
				SourceUserID:   au.UserID,
				Provider:       provider,
				ProviderUserID: id.UserID,
			})
		}

		// MFA records.
		if hasMFA {
			for _, mfaName := range au.Multifactor {
				mtype := "totp"
				note := fmt.Sprintf("User had %s MFA via Auth0 Guardian; must re-enroll TOTP on first login.", mfaName)
				bundle.MFAEnrolled = append(bundle.MFAEnrolled, internal.MFARecord{
					SourceUserID: au.UserID,
					Type:         mtype,
					Note:         note,
				})
			}
		}
	}

	return bundle, nil
}

// ---- helpers ----

// parseAuth0Time handles the ISO-8601 timestamps Auth0 uses.
func parseAuth0Time(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// isPrimaryDatabaseUser returns true when the user's primary identity is an
// Auth0 "auth0" (database) connection, meaning a password is expected.
func isPrimaryDatabaseUser(au Auth0User) bool {
	for _, id := range au.Identities {
		if id.Provider == "auth0" && !id.IsSocial {
			return true
		}
	}
	// Fall back to inspecting the user_id prefix.
	return strings.HasPrefix(au.UserID, "auth0|")
}

// normalizeProvider maps Auth0 provider names to the conventional lowercase
// names used by theauth-go OAuth accounts.
var providerMap = map[string]string{
	"google-oauth2": "google",
	"github":        "github",
	"facebook":      "facebook",
	"twitter":       "twitter",
	"linkedin":      "linkedin",
	"apple":         "apple",
	"microsoft":     "microsoft",
	"windowslive":   "microsoft",
}

func normalizeProvider(p string) string {
	if n, ok := providerMap[p]; ok {
		return n
	}
	return p
}
