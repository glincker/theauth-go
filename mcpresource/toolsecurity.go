package mcpresource

// SecurityScheme is one entry of a tool's securitySchemes list. Type is
// "oauth2" (a token is required, optionally with scopes) or "noauth"
// (callable anonymously).
type SecurityScheme struct {
	Type   string   `json:"type"`
	Scopes []string `json:"scopes,omitempty"`
}

// ToolSecurityInfo is the security metadata for one tool in a tools/list
// result. It marshals to both places clients look for it: the top level
// securitySchemes member and the same list mirrored under _meta.
type ToolSecurityInfo struct {
	SecuritySchemes []SecurityScheme `json:"securitySchemes"`
	Meta            ToolSecurityMeta `json:"_meta"`
}

// ToolSecurityMeta is the _meta object of a ToolSecurityInfo.
type ToolSecurityMeta struct {
	SecuritySchemes []SecurityScheme `json:"securitySchemes"`
}

// SecuritySchemes returns the securitySchemes list for a tool that needs an
// OAuth token carrying scopes (duplicates dropped, order kept). With no
// scopes it still declares oauth2, meaning "any valid token".
func SecuritySchemes(scopes ...string) []SecurityScheme {
	seen := make(map[string]struct{}, len(scopes))
	var out []string
	for _, s := range scopes {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return []SecurityScheme{{Type: "oauth2", Scopes: out}}
}

// ToolSecurity builds the MCP tool security metadata for a tool that needs the given scopes. Merge it into each tool descriptor returned from tools/list so clients can plan authorization before calling the tool.
//
// Wire shape for ToolSecurity('files:read') is '{"securitySchemes": [{"type": "oauth2", "scopes": ["files:read"]}], "_meta": {...}}'.
//
// Example: tool := map[string]any{'name': 'read_file', 'inputSchema': schema}; mcpresource.ToolSecurity('files:read').Apply(tool)
//
// The metadata is advisory; enforcement still happens in RequireScope.
func ToolSecurity(scopes ...string) ToolSecurityInfo {
	return newToolSecurity(SecuritySchemes(scopes...))
}

// PublicToolSecurity is the metadata for a tool callable without a token.
func PublicToolSecurity() ToolSecurityInfo {
	return newToolSecurity([]SecurityScheme{{Type: "noauth"}})
}

func newToolSecurity(s []SecurityScheme) ToolSecurityInfo {
	return ToolSecurityInfo{SecuritySchemes: s, Meta: ToolSecurityMeta{SecuritySchemes: s}}
}

// Apply writes the metadata into a tool descriptor map: securitySchemes at
// the top level and under _meta. Other _meta members already present are
// preserved.
func (t ToolSecurityInfo) Apply(tool map[string]any) {
	tool["securitySchemes"] = t.SecuritySchemes
	meta, ok := tool["_meta"].(map[string]any)
	if !ok {
		meta = map[string]any{}
	}
	meta["securitySchemes"] = t.Meta.SecuritySchemes
	tool["_meta"] = meta
}
