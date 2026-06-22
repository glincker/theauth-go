// Package cognito reads AWS Cognito user-pool exports and converts them to
// the migration Bundle format.
//
// Two input formats are supported:
//
//  1. Cognito User Export CSV - produced by the "Export users" button in the
//     Cognito console or via `aws cognito-idp list-users --output csv`.
//
//  2. Cognito JSON - a newline-delimited array of AdminGetUser / list-users
//     JSON responses that each contain a UserAttributes slice.
//
// Cognito does NOT export password hashes; all migrated users will have
// RequiresPasswordReset=true. See docs/MIGRATING-FROM-COGNITO.md for the
// recommended operator workflow.
package cognito

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/glincker/theauth-go/cmd/theauth-migrate/internal"
)

// ReadCSV reads a Cognito user export CSV from r and returns a Bundle.
// The standard Cognito CSV columns are:
//
//	name, given_name, family_name, middle_name, nickname, preferred_username,
//	profile, picture, website, email, email_verified, gender, birthdate,
//	zoneinfo, locale, phone_number, phone_number_verified, address, updated_at,
//	cognito:username, cognito:status, cognito:mfa_enabled, cognito:user_status,
//	custom:*
func ReadCSV(r io.Reader) (*internal.Bundle, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true

	headers, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("cognito csv: read headers: %w", err)
	}
	idx := headerIndex(headers)

	bundle := &internal.Bundle{
		SchemaVersion: internal.SchemaVersion,
		Source:        "cognito",
		ExportedAt:    time.Now().UTC(),
	}
	bundle.Notes = append(bundle.Notes,
		"Cognito does not export password hashes. All users have requires_password_reset=true.",
		"Send password-reset emails via POST /auth/email-password/forgot, or use the --enable-password-reset-on-import flag when wiring to an email service.",
		"TOTP (SOFTWARE_TOKEN_MFA) users are flagged requires_mfa_reenroll=true; they must re-enroll TOTP on first login.",
		"SMS_MFA users are flagged requires_mfa_reenroll=true. theauth-go does not support SMS MFA; coordinate an alternative second-factor flow.",
	)

	lineNum := 1
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("cognito csv: line %d: %w", lineNum, err)
		}
		lineNum++

		get := func(name string) string {
			i, ok := idx[name]
			if !ok || i >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[i])
		}

		// Cognito Sub (UUID) is the stable identity.
		sub := get("sub")
		if sub == "" {
			sub = get("cognito:username")
		}
		if sub == "" {
			return nil, fmt.Errorf("cognito csv: line %d: cannot determine user id (no 'sub' or 'cognito:username' column)", lineNum)
		}

		email := strings.ToLower(get("email"))
		if email == "" {
			bundle.Notes = append(bundle.Notes,
				fmt.Sprintf("WARN: user %q has no email; skipped", sub),
			)
			continue
		}

		emailVerified := strings.EqualFold(get("email_verified"), "true")

		name := get("name")
		if name == "" {
			given := get("given_name")
			family := get("family_name")
			name = strings.TrimSpace(given + " " + family)
		}

		updatedAt := parseUnixOrRFC3339(get("updated_at"))
		createdAt := updatedAt // Cognito CSV doesn't expose created_at reliably

		// Collect custom attributes as metadata.
		meta := make(map[string]string)
		for header, i := range idx {
			if strings.HasPrefix(header, "custom:") && i < len(row) && row[i] != "" {
				meta[header] = row[i]
			}
		}

		mfaEnabled := strings.EqualFold(get("cognito:mfa_enabled"), "true")

		ur := internal.UserRecord{
			SourceID:              sub,
			Email:                 email,
			Name:                  name,
			EmailVerified:         emailVerified,
			RequiresPasswordReset: true,
			RequiresMFAReenroll:   mfaEnabled,
			CreatedAt:             createdAt,
			UpdatedAt:             updatedAt,
		}
		if len(meta) > 0 {
			ur.Metadata = meta
		}
		bundle.Users = append(bundle.Users, ur)

		if mfaEnabled {
			mfaType := get("cognito:mfa_enabled")
			note := "User had TOTP (SOFTWARE_TOKEN_MFA) enrolled; must re-enroll on first login."
			recordType := "totp"
			if strings.EqualFold(get("cognito:preferred_mfa_setting"), "SMS_MFA") ||
				strings.Contains(strings.ToLower(mfaType), "sms") {
				recordType = "sms"
				note = "User had SMS MFA enrolled; theauth-go does not support SMS MFA. Coordinate an alternative."
			}
			bundle.MFAEnrolled = append(bundle.MFAEnrolled, internal.MFARecord{
				SourceUserID: sub,
				Type:         recordType,
				Note:         note,
			})
		}
	}

	return bundle, nil
}

// CognitoUser matches the shape returned by aws cognito-idp list-users
// or AdminGetUser (both use the same UserType JSON structure).
type CognitoUser struct {
	Username             string `json:"Username"`
	UserStatus           string `json:"UserStatus"`
	Enabled              bool   `json:"Enabled"`
	UserCreateDate       string `json:"UserCreateDate"`
	UserLastModifiedDate string `json:"UserLastModifiedDate"`
	MFAOptions           []struct {
		DeliveryMedium string `json:"DeliveryMedium"`
		AttributeName  string `json:"AttributeName"`
	} `json:"MFAOptions"`
	PreferredMfaSetting string   `json:"PreferredMfaSetting"`
	UserMFASettingList  []string `json:"UserMFASettingList"`
	UserAttributes      []struct {
		Name  string `json:"Name"`
		Value string `json:"Value"`
	} `json:"UserAttributes"`
	// Some AdminGetUser responses use Attributes instead of UserAttributes.
	Attributes []struct {
		Name  string `json:"Name"`
		Value string `json:"Value"`
	} `json:"Attributes"`
}

// ReadJSON reads a Cognito JSON export from r. The input may be either:
//   - A JSON array: [ { "Username": "...", ... }, ... ]
//   - A newline-delimited JSON object wrapping a "Users" array
//     (output of `aws cognito-idp list-users`)
func ReadJSON(r io.Reader) (*internal.Bundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cognito json: read: %w", err)
	}

	var users []CognitoUser

	// Try array first.
	if err := json.Unmarshal(data, &users); err != nil {
		// Try the list-users wrapper: {"Users": [...], "PaginationToken": "..."}
		var wrapper struct {
			Users []CognitoUser `json:"Users"`
		}
		if err2 := json.Unmarshal(data, &wrapper); err2 != nil {
			return nil, fmt.Errorf("cognito json: cannot parse as array or list-users response: %v", err)
		}
		users = wrapper.Users
	}

	bundle := &internal.Bundle{
		SchemaVersion: internal.SchemaVersion,
		Source:        "cognito",
		ExportedAt:    time.Now().UTC(),
	}
	bundle.Notes = append(bundle.Notes,
		"Cognito does not export password hashes. All users have requires_password_reset=true.",
		"Send password-reset emails via POST /auth/email-password/forgot, or use --enable-password-reset-on-import.",
		"TOTP (SOFTWARE_TOKEN_MFA) users are flagged requires_mfa_reenroll=true; they must re-enroll TOTP on first login.",
		"SMS_MFA users are flagged requires_mfa_reenroll=true. theauth-go does not support SMS MFA.",
	)

	for _, cu := range users {
		attrs := mergeAttributes(cu.UserAttributes, cu.Attributes)

		sub := attrValue(attrs, "sub")
		if sub == "" {
			sub = cu.Username
		}

		email := strings.ToLower(attrValue(attrs, "email"))
		if email == "" {
			bundle.Notes = append(bundle.Notes,
				fmt.Sprintf("WARN: user %q has no email attribute; skipped", sub),
			)
			continue
		}

		emailVerified := strings.EqualFold(attrValue(attrs, "email_verified"), "true")

		name := attrValue(attrs, "name")
		if name == "" {
			given := attrValue(attrs, "given_name")
			family := attrValue(attrs, "family_name")
			name = strings.TrimSpace(given + " " + family)
		}

		createdAt := parseUnixOrRFC3339(cu.UserCreateDate)
		updatedAt := parseUnixOrRFC3339(cu.UserLastModifiedDate)
		if updatedAt.IsZero() {
			updatedAt = createdAt
		}

		meta := make(map[string]string)
		for k, v := range attrs {
			if strings.HasPrefix(k, "custom:") {
				meta[k] = v
			}
		}

		hasTOTP := false
		hasSMS := false
		for _, setting := range cu.UserMFASettingList {
			switch setting {
			case "SOFTWARE_TOKEN_MFA":
				hasTOTP = true
			case "SMS_MFA":
				hasSMS = true
			}
		}
		if len(cu.MFAOptions) > 0 {
			hasSMS = true
		}

		requiresMFA := hasTOTP || hasSMS
		ur := internal.UserRecord{
			SourceID:              sub,
			Email:                 email,
			Name:                  name,
			EmailVerified:         emailVerified,
			RequiresPasswordReset: true,
			RequiresMFAReenroll:   requiresMFA,
			CreatedAt:             createdAt,
			UpdatedAt:             updatedAt,
		}
		if len(meta) > 0 {
			ur.Metadata = meta
		}
		bundle.Users = append(bundle.Users, ur)

		if hasTOTP {
			bundle.MFAEnrolled = append(bundle.MFAEnrolled, internal.MFARecord{
				SourceUserID: sub,
				Type:         "totp",
				Note:         "User had SOFTWARE_TOKEN_MFA; must re-enroll TOTP on first login.",
			})
		}
		if hasSMS {
			bundle.MFAEnrolled = append(bundle.MFAEnrolled, internal.MFARecord{
				SourceUserID: sub,
				Type:         "sms",
				Note:         "User had SMS_MFA; theauth-go does not support SMS MFA. Coordinate an alternative second factor.",
			})
		}
	}

	return bundle, nil
}

// ---- helpers ----

func headerIndex(headers []string) map[string]int {
	m := make(map[string]int, len(headers))
	for i, h := range headers {
		m[strings.TrimSpace(h)] = i
	}
	return m
}

// mergeAttributes merges two attribute slices (UserAttributes / Attributes)
// into a single name->value map.
func mergeAttributes(a, b []struct {
	Name  string `json:"Name"`
	Value string `json:"Value"`
}) map[string]string {
	m := make(map[string]string)
	for _, attr := range a {
		m[attr.Name] = attr.Value
	}
	for _, attr := range b {
		m[attr.Name] = attr.Value
	}
	return m
}

func attrValue(attrs map[string]string, name string) string {
	return attrs[name]
}

// parseUnixOrRFC3339 tries several common Cognito timestamp formats and
// returns the zero time on failure.
func parseUnixOrRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
