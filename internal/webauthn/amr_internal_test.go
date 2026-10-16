package webauthn

import (
	"reflect"
	"testing"
)

func TestPasskeyAMR(t *testing.T) {
	for _, tc := range []struct {
		name   string
		be, uv bool
		want   []string
	}{
		{"device bound, no UV", false, false, []string{"hwk"}},
		{"device bound, UV", false, true, []string{"hwk", "user"}},
		{"synced passkey, no UV", true, false, []string{"swk"}},
		{"synced passkey, UV", true, true, []string{"swk", "user"}},
	} {
		if got := passkeyAMR(tc.be, tc.uv); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.name, got, tc.want)
		}
	}
}
