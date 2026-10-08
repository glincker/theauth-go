package cimd

import (
	"fmt"
	"reflect"
	"testing"
)

// Regression for pocket-id#1677: documents that list grant_types beyond
// authorization_code (refresh_token, client_credentials, vendor URNs) must
// be accepted and preserved, not rejected.
func TestParseAndValidateGrantTypes(t *testing.T) {
	const id = "https://app.example.com/client.json"
	tests := []struct {
		name   string
		grants string
		want   []string
	}{
		{"omitted defaults", ``, []string{"authorization_code", "refresh_token"}},
		{"code only", `"grant_types":["authorization_code"],`, []string{"authorization_code"}},
		{"code and refresh", `"grant_types":["authorization_code","refresh_token"],`, []string{"authorization_code", "refresh_token"}},
		{"extra grants", `"grant_types":["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:device_code"],`,
			[]string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"client_id":%q,%s"redirect_uris":["https://app.example.com/cb"]}`, id, tc.grants)
			doc, err := parseAndValidate([]byte(raw), id)
			if err != nil {
				t.Fatalf("parseAndValidate: %v", err)
			}
			if !reflect.DeepEqual(doc.GrantTypes, tc.want) {
				t.Fatalf("grant_types = %v, want %v", doc.GrantTypes, tc.want)
			}
		})
	}
}
