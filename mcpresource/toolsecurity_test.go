package mcpresource

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSecuritySchemes(t *testing.T) {
	got := SecuritySchemes("files:read", "files:write", "files:read")
	want := []SecurityScheme{{Type: "oauth2", Scopes: []string{"files:read", "files:write"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := SecuritySchemes(); len(got) != 1 || got[0].Type != "oauth2" || len(got[0].Scopes) != 0 {
		t.Fatalf("no scopes: %+v", got)
	}
}

func TestToolSecurityJSONShape(t *testing.T) {
	b, err := json.Marshal(ToolSecurity("files:read"))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"securitySchemes":[{"type":"oauth2","scopes":["files:read"]}],"_meta":{"securitySchemes":[{"type":"oauth2","scopes":["files:read"]}]}}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}

func TestToolSecurityApplyPreservesMeta(t *testing.T) {
	tool := map[string]any{"name": "search", "_meta": map[string]any{"ui": "x"}}
	ToolSecurity("a").Apply(tool)
	meta := tool["_meta"].(map[string]any)
	if meta["ui"] != "x" || meta["securitySchemes"] == nil || tool["securitySchemes"] == nil {
		t.Fatalf("tool %+v", tool)
	}
}

func TestNoAuthToolSecurity(t *testing.T) {
	b, _ := json.Marshal(PublicToolSecurity())
	const want = `{"securitySchemes":[{"type":"noauth"}],"_meta":{"securitySchemes":[{"type":"noauth"}]}}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
}
