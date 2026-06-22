// Package internal defines the shared migration bundle format, applier, and
// validator used by both the cognito and auth0 sub-commands.
package internal

import "time"

// SchemaVersion is the current bundle schema version. Bump when the shape
// changes in a backward-incompatible way.
const SchemaVersion = "1"

// Bundle is the intermediate normalized representation produced by a reader
// (cognito or auth0) and consumed by the applier. Operators can inspect and
// edit this JSON before running --apply.
type Bundle struct {
	SchemaVersion string           `json:"schema_version"`
	Source        string           `json:"source"` // "cognito" or "auth0"
	ExportedAt    time.Time        `json:"exported_at"`
	Users         []UserRecord     `json:"users"`
	OAuthAccounts []OAuthAccount   `json:"oauth_accounts"`
	Passwords     []PasswordRecord `json:"passwords"`
	MFAEnrolled   []MFARecord      `json:"mfa_enrolled"`
	Sessions      []SessionRecord  `json:"sessions"`
	Notes         []string         `json:"notes"`
}

// UserRecord is a normalized user row.
type UserRecord struct {
	// SourceID is the vendor-assigned identifier (Cognito Sub UUID, Auth0 user_id).
	SourceID string `json:"source_id"`
	// Email is always lower-cased.
	Email         string            `json:"email"`
	Name          string            `json:"name,omitempty"`
	EmailVerified bool              `json:"email_verified"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	// RequiresPasswordReset is set when the vendor cannot export the password
	// hash (Cognito) or when --force-password-reset is active.
	RequiresPasswordReset bool `json:"requires_password_reset,omitempty"`
	// RequiresMFAReenroll is set when the user had MFA but the secret cannot
	// be migrated (all Cognito + Auth0 cases).
	RequiresMFAReenroll bool      `json:"requires_mfa_reenroll,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// OAuthAccount is a normalized OAuth connection row.
type OAuthAccount struct {
	SourceUserID   string `json:"source_user_id"`
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
}

// PasswordRecord holds a password hash from the vendor export.
// For Cognito this is always empty because Cognito does not export hashes.
// For Auth0 this may contain a bcrypt hash.
type PasswordRecord struct {
	SourceUserID string `json:"source_user_id"`
	// Hash is the raw vendor hash string. For Auth0 bcrypt this starts with
	// "$2a$" or "$2b$". Empty means no hash available.
	Hash string `json:"hash,omitempty"`
	// Algo is "bcrypt" or "argon2id".
	Algo string `json:"algo,omitempty"`
}

// MFARecord records that a user had MFA enrolled. Because vendor keys are
// not exportable, these records only trigger re-enrollment flows.
type MFARecord struct {
	SourceUserID string `json:"source_user_id"`
	// Type is "totp", "sms", or "webauthn".
	Type string `json:"type"`
	// Note contains a human-readable explanation of what action is needed.
	Note string `json:"note,omitempty"`
}

// SessionRecord holds an active session to import. Session import is
// best-effort; sessions that cannot be mapped to a user are skipped.
type SessionRecord struct {
	SourceUserID string    `json:"source_user_id"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}
