package cognito_test

import (
	"strings"
	"testing"

	"github.com/glincker/theauth-go/cmd/theauth-migrate/cognito"
)

// sampleCognitoCSV is a minimal Cognito user export CSV with two users.
// One user has MFA enabled; the other does not.
const sampleCognitoCSV = `name,given_name,family_name,email,email_verified,cognito:username,sub,cognito:mfa_enabled,cognito:status,custom:tier
Alice Smith,Alice,Smith,alice@example.com,true,alice,aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa,true,CONFIRMED,pro
Bob Jones,Bob,Jones,bob@example.com,false,bob,bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb,false,CONFIRMED,free
`

func TestCognitoCSVReader(t *testing.T) {
	bundle, err := cognito.ReadCSV(strings.NewReader(sampleCognitoCSV))
	if err != nil {
		t.Fatalf("ReadCSV: %v", err)
	}

	if bundle.Source != "cognito" {
		t.Errorf("Source=%q; want cognito", bundle.Source)
	}
	if bundle.SchemaVersion != "1" {
		t.Errorf("SchemaVersion=%q; want 1", bundle.SchemaVersion)
	}
	if got, want := len(bundle.Users), 2; got != want {
		t.Fatalf("len(Users)=%d; want %d", got, want)
	}

	alice := bundle.Users[0]
	if alice.Email != "alice@example.com" {
		t.Errorf("alice.Email=%q; want alice@example.com", alice.Email)
	}
	if !alice.EmailVerified {
		t.Errorf("alice.EmailVerified=false; want true")
	}
	if !alice.RequiresPasswordReset {
		t.Errorf("alice.RequiresPasswordReset=false; Cognito never exports hashes so must be true")
	}
	if !alice.RequiresMFAReenroll {
		t.Errorf("alice.RequiresMFAReenroll=false; alice had mfa enabled")
	}
	if got := alice.Metadata["custom:tier"]; got != "pro" {
		t.Errorf("alice Metadata[custom:tier]=%q; want pro", got)
	}

	bob := bundle.Users[1]
	if bob.Email != "bob@example.com" {
		t.Errorf("bob.Email=%q; want bob@example.com", bob.Email)
	}
	if bob.RequiresMFAReenroll {
		t.Errorf("bob.RequiresMFAReenroll=true; bob had no MFA")
	}

	// Expect at least one MFA record (for Alice).
	found := false
	for _, m := range bundle.MFAEnrolled {
		if m.SourceUserID == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" {
			found = true
		}
	}
	if !found {
		t.Errorf("no MFA record found for alice's sub")
	}

	// All users should have RequiresPasswordReset because Cognito never exports hashes.
	for _, u := range bundle.Users {
		if !u.RequiresPasswordReset {
			t.Errorf("user %q: RequiresPasswordReset=false; expected true for all Cognito users", u.Email)
		}
	}

	// Notes must contain the password caveat.
	foundNote := false
	for _, n := range bundle.Notes {
		if strings.Contains(n, "password") {
			foundNote = true
			break
		}
	}
	if !foundNote {
		t.Errorf("bundle.Notes does not contain password-reset caveat")
	}
}

// sampleCognitoJSON is a minimal Cognito list-users JSON response.
const sampleCognitoJSON = `{
  "Users": [
    {
      "Username": "carol",
      "UserStatus": "CONFIRMED",
      "Enabled": true,
      "UserCreateDate": "2024-01-15T10:00:00Z",
      "UserLastModifiedDate": "2024-06-01T12:00:00Z",
      "UserMFASettingList": ["SOFTWARE_TOKEN_MFA"],
      "UserAttributes": [
        {"Name": "sub",            "Value": "cccccccc-cccc-cccc-cccc-cccccccccccc"},
        {"Name": "email",          "Value": "carol@example.com"},
        {"Name": "email_verified", "Value": "true"},
        {"Name": "name",           "Value": "Carol Danvers"},
        {"Name": "custom:plan",    "Value": "enterprise"}
      ]
    },
    {
      "Username": "dave",
      "UserStatus": "CONFIRMED",
      "Enabled": true,
      "UserCreateDate": "2024-03-20T08:30:00Z",
      "UserLastModifiedDate": "2024-05-10T09:00:00Z",
      "UserAttributes": [
        {"Name": "sub",            "Value": "dddddddd-dddd-dddd-dddd-dddddddddddd"},
        {"Name": "email",          "Value": "Dave@Example.com"},
        {"Name": "email_verified", "Value": "false"},
        {"Name": "name",           "Value": "Dave Rogers"}
      ]
    }
  ]
}`

func TestCognitoJSONReader(t *testing.T) {
	bundle, err := cognito.ReadJSON(strings.NewReader(sampleCognitoJSON))
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}

	if got, want := len(bundle.Users), 2; got != want {
		t.Fatalf("len(Users)=%d; want %d", got, want)
	}

	carol := bundle.Users[0]
	if carol.Email != "carol@example.com" {
		t.Errorf("carol.Email=%q; want carol@example.com", carol.Email)
	}
	if !carol.RequiresMFAReenroll {
		t.Errorf("carol.RequiresMFAReenroll=false; carol has SOFTWARE_TOKEN_MFA")
	}
	if got := carol.Metadata["custom:plan"]; got != "enterprise" {
		t.Errorf("carol Metadata[custom:plan]=%q; want enterprise", got)
	}

	dave := bundle.Users[1]
	// Email should be lower-cased.
	if dave.Email != "dave@example.com" {
		t.Errorf("dave.Email=%q; want dave@example.com", dave.Email)
	}
	if dave.RequiresMFAReenroll {
		t.Errorf("dave.RequiresMFAReenroll=true; dave has no MFA")
	}

	// All Cognito users need password reset.
	for _, u := range bundle.Users {
		if !u.RequiresPasswordReset {
			t.Errorf("user %q: RequiresPasswordReset=false; expected true", u.Email)
		}
	}
}
