package as

import "testing"

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		uri     string
		wantErr bool
	}{
		{"https://app.example.com/cb", false},
		{"http://localhost:8123/cb", false},
		{"http://127.0.0.1:5555/cb", false},
		{"http://[::1]:9/cb", false},
		{"com.example.app:/oauth2redirect", false},
		{"com.example.app://cb", false},
		{"javascript:alert(1)", true},
		{"JavaScript:alert(1)", true},
		{"data:text/html,<script>x</script>", true},
		{"file:///etc/passwd", true},
		{"vbscript:msgbox", true},
		{"myapp://cb", true},
		{"http://app.example.com/cb", true},
		{"https:///nohost", true},
		{"https://user:pw@app.example.com/cb", true},
		{"https://app.example.com/cb#frag", true},
		{"/relative", true},
		{"", true},
		{"java.script.:x", true},
	}
	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			err := validateRedirectURI(tc.uri)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateRedirectURI(%q) err=%v wantErr=%v", tc.uri, err, tc.wantErr)
			}
		})
	}
}
