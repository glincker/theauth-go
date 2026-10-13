package mcpresource

import (
	"encoding/json"
	"testing"
)

func TestNewURLElicitation(t *testing.T) {
	e, err := NewURLElicitation("el-1", "https://as.example.com/consent?x=1", "Authorize access")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e)
	const want = `{"mode":"url","elicitationId":"el-1","url":"https://as.example.com/consent?x=1","message":"Authorize access"}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}

func TestNewURLElicitationGeneratesID(t *testing.T) {
	a, err := NewURLElicitation("", "https://as.example.com/c", "m")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewURLElicitation("", "https://as.example.com/c", "m")
	if len(a.ElicitationID) < 16 || a.ElicitationID == b.ElicitationID {
		t.Fatalf("ids %q %q", a.ElicitationID, b.ElicitationID)
	}
}

func TestNewURLElicitationRejects(t *testing.T) {
	tests := []struct{ name, url, msg string }{
		{"empty url", "", "m"},
		{"relative", "/consent", "m"},
		{"http remote", "http://as.example.com/c", "m"},
		{"userinfo", "https://u:p@as.example.com/c", "m"},
		{"javascript", "javascript:alert(1)", "m"},
		{"empty message", "https://as.example.com/c", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewURLElicitation("id", tc.url, tc.msg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := NewURLElicitation("id", "http://localhost:8080/c", "m"); err != nil {
		t.Fatalf("loopback http allowed: %v", err)
	}
}

func TestURLElicitationRequiredError(t *testing.T) {
	e, _ := NewURLElicitation("el-1", "https://as.example.com/c", "Go")
	b, err := json.Marshal(URLElicitationRequiredError(e))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Elicitations []URLElicitation `json:"elicitations"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Code != -32042 || len(m.Data.Elicitations) != 1 || m.Data.Elicitations[0].ElicitationID != "el-1" {
		t.Fatalf("got %s", b)
	}
}
