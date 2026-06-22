package auth0_test

import (
	"strings"
	"testing"

	auth0pkg "github.com/glincker/theauth-go/cmd/theauth-migrate/auth0"
)

// sampleAuth0JSON is a minimal Auth0 Management API export with three users:
// - eve: database user with bcrypt hash
// - frank: Google social user
// - grace: database user with Guardian MFA enrolled
const sampleAuth0JSON = `[
  {
    "user_id": "auth0|eve",
    "email": "eve@example.com",
    "email_verified": true,
    "name": "Eve Adams",
    "created_at": "2024-02-10T09:00:00.000Z",
    "updated_at": "2024-05-01T11:00:00.000Z",
    "password_hash": "$2b$10$abcdefghijklmnopqrstuuVGmtU0Oy2P5FIlkTGYhN7wTEQpI3qFi",
    "identities": [
      {
        "provider": "auth0",
        "user_id": "eve",
        "isSocial": false,
        "connection": "Username-Password-Authentication"
      }
    ]
  },
  {
    "user_id": "google-oauth2|12345",
    "email": "frank@example.com",
    "email_verified": true,
    "name": "Frank Booth",
    "created_at": "2024-03-05T14:00:00Z",
    "updated_at": "2024-03-05T14:00:00Z",
    "identities": [
      {
        "provider": "google-oauth2",
        "user_id": "12345",
        "isSocial": true,
        "connection": "google-oauth2"
      }
    ]
  },
  {
    "user_id": "auth0|grace",
    "email": "Grace@example.com",
    "email_verified": false,
    "name": "Grace Hopper",
    "created_at": "2023-11-20T08:00:00Z",
    "updated_at": "2024-01-10T10:00:00Z",
    "multifactor": ["guardian"],
    "identities": [
      {
        "provider": "auth0",
        "user_id": "grace",
        "isSocial": false,
        "connection": "Username-Password-Authentication"
      }
    ]
  }
]`

func TestAuth0JSONReader(t *testing.T) {
	bundle, err := auth0pkg.ReadJSON(strings.NewReader(sampleAuth0JSON), false)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}

	if bundle.Source != "auth0" {
		t.Errorf("Source=%q; want auth0", bundle.Source)
	}
	if bundle.SchemaVersion != "1" {
		t.Errorf("SchemaVersion=%q; want 1", bundle.SchemaVersion)
	}
	if got, want := len(bundle.Users), 3; got != want {
		t.Fatalf("len(Users)=%d; want %d", got, want)
	}

	// Eve: database user with bcrypt hash.
	eve := bundle.Users[0]
	if eve.Email != "eve@example.com" {
		t.Errorf("eve.Email=%q; want eve@example.com", eve.Email)
	}
	if !eve.EmailVerified {
		t.Errorf("eve.EmailVerified=false; want true")
	}
	if eve.RequiresPasswordReset {
		t.Errorf("eve.RequiresPasswordReset=true; she has a bcrypt hash so should not need reset")
	}

	// Frank: social user (no password).
	frank := bundle.Users[1]
	if frank.Email != "frank@example.com" {
		t.Errorf("frank.Email=%q; want frank@example.com", frank.Email)
	}

	// Grace: email must be lower-cased, MFA flag set.
	grace := bundle.Users[2]
	if grace.Email != "grace@example.com" {
		t.Errorf("grace.Email=%q; want grace@example.com", grace.Email)
	}
	if !grace.RequiresMFAReenroll {
		t.Errorf("grace.RequiresMFAReenroll=false; she had Guardian MFA")
	}

	// Passwords: only Eve has a bcrypt hash.
	if got, want := len(bundle.Passwords), 1; got != want {
		t.Fatalf("len(Passwords)=%d; want %d", got, want)
	}
	pw := bundle.Passwords[0]
	if pw.SourceUserID != "auth0|eve" {
		t.Errorf("password source_user_id=%q; want auth0|eve", pw.SourceUserID)
	}
	if !strings.HasPrefix(pw.Hash, "$2b$") {
		t.Errorf("password hash=%q; expected bcrypt ($2b$ prefix)", pw.Hash)
	}
	if pw.Algo != "bcrypt" {
		t.Errorf("password algo=%q; want bcrypt", pw.Algo)
	}

	// OAuth accounts: Frank has a Google identity.
	if got, want := len(bundle.OAuthAccounts), 1; got != want {
		t.Fatalf("len(OAuthAccounts)=%d; want %d", got, want)
	}
	oa := bundle.OAuthAccounts[0]
	if oa.Provider != "google" {
		t.Errorf("oauth_account provider=%q; want google (normalized from google-oauth2)", oa.Provider)
	}
	if oa.ProviderUserID != "12345" {
		t.Errorf("oauth_account provider_user_id=%q; want 12345", oa.ProviderUserID)
	}

	// MFA records: Grace has one.
	if got, want := len(bundle.MFAEnrolled), 1; got != want {
		t.Fatalf("len(MFAEnrolled)=%d; want %d", got, want)
	}
}

func TestAuth0JSONReaderForcePasswordReset(t *testing.T) {
	bundle, err := auth0pkg.ReadJSON(strings.NewReader(sampleAuth0JSON), true)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	for _, u := range bundle.Users {
		if !u.RequiresPasswordReset {
			t.Errorf("user %q: RequiresPasswordReset=false with --force-password-reset", u.Email)
		}
	}
	// With forceReset=true, passwords should NOT be written to the bundle
	// because the hashes will not be used.
	if len(bundle.Passwords) != 0 {
		t.Errorf("Passwords=%d; expected 0 when --force-password-reset", len(bundle.Passwords))
	}
}
