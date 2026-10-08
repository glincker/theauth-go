// Package openapi derives an OpenAPI 3.1 document from a mounted chi router.
//
// The route list is read with chi.Walk, so the document always matches what
// is actually mounted, including optional features switched on in Config.
// A small table adds summaries, tags and security for the well-known auth
// routes; any other route is still listed with a generated summary.
package openapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Info is the document header.
type Info struct {
	Title       string
	Version     string
	Description string
	// ServerURL is added as the single server entry when non-empty.
	ServerURL string
}

type op struct {
	Summary string
	Tag     string
	Secured bool
	Body    bool
}

// known describes routes by "METHOD path-suffix". The suffix match lets the
// table work under any Config.PathPrefix.
var known = map[string]op{
	"POST /magic-link":                            {"Request a magic link", "magic-link", false, true},
	"GET /magic-link/verify":                      {"Consume a magic link", "magic-link", false, false},
	"POST /email-password/signup":                 {"Create an account with email and password", "password", false, true},
	"POST /email-password/signin":                 {"Sign in with email and password", "password", false, true},
	"POST /email-password/forgot":                 {"Request a password reset", "password", false, true},
	"POST /email-password/reset":                  {"Reset a password with a token", "password", false, true},
	"GET /me":                                     {"Return the signed-in user", "session", true, false},
	"DELETE /sessions/current":                    {"Revoke the current session", "session", true, false},
	"GET /sessions":                               {"List the caller's sessions", "session", true, false},
	"DELETE /sessions/{id}":                       {"Revoke one session", "session", true, false},
	"POST /sessions/revoke-others":                {"Revoke all other sessions", "session", true, false},
	"POST /step-up":                               {"Elevate the current session", "session", true, true},
	"POST /password/change":                       {"Change the password", "password", true, true},
	"POST /oauth/token":                           {"OAuth token endpoint", "oauth", false, true},
	"POST /oauth/revoke":                          {"Revoke a token (RFC 7009)", "oauth", false, true},
	"POST /oauth/introspect":                      {"Introspect a token (RFC 7662)", "oauth", false, true},
	"POST /oauth/par":                             {"Pushed authorization request (RFC 9126)", "oauth", false, true},
	"GET /oauth/authorize":                        {"OAuth authorization endpoint", "oauth", false, false},
	"POST /oauth/device_authorization":            {"Start a device authorization (RFC 8628)", "oauth", false, true},
	"GET /.well-known/jwks.json":                  {"JSON Web Key Set", "discovery", false, false},
	"GET /.well-known/oauth-authorization-server": {"Authorization server metadata (RFC 8414)", "discovery", false, false},
}

// Generate walks r and returns the OpenAPI document as indented JSON.
func Generate(r chi.Routes, info Info) ([]byte, error) {
	if info.Title == "" {
		info.Title = "theauth-go"
	}
	if info.Version == "" {
		info.Version = "0.0.0"
	}
	paths := map[string]map[string]any{}
	tags := map[string]bool{}
	err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = normalize(route)
		m := strings.ToLower(method)
		if m == "connect" || m == "trace" {
			return nil
		}
		o := lookup(method, route)
		item := map[string]any{
			"summary":     o.Summary,
			"operationId": operationID(method, route),
			"tags":        []string{o.Tag},
			"responses":   responses(o),
		}
		if o.Body {
			item["requestBody"] = map[string]any{
				"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}}},
			}
		}
		if o.Secured {
			item["security"] = []map[string][]string{{"session": {}}, {"bearer": {}}}
		}
		if params := pathParams(route); len(params) > 0 {
			item["parameters"] = params
		}
		if paths[route] == nil {
			paths[route] = map[string]any{}
		}
		paths[route][m] = item
		tags[o.Tag] = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("openapi: walk: %w", err)
	}
	tagList := make([]map[string]string, 0, len(tags))
	names := make([]string, 0, len(tags))
	for t := range tags {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, n := range names {
		tagList = append(tagList, map[string]string{"name": n})
	}
	doc := map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]string{"title": info.Title, "version": info.Version, "description": info.Description},
		"paths":   paths,
		"tags":    tagList,
		"components": map[string]any{"securitySchemes": map[string]any{
			"session": map[string]any{"type": "apiKey", "in": "cookie", "name": "theauth_session"},
			"bearer":  map[string]any{"type": "http", "scheme": "bearer"},
		}},
	}
	if info.ServerURL != "" {
		doc["servers"] = []map[string]string{{"url": info.ServerURL}}
	}
	return json.MarshalIndent(doc, "", "  ")
}

func normalize(route string) string {
	route = strings.ReplaceAll(route, "/*", "/{wildcard}")
	if len(route) > 1 {
		route = strings.TrimSuffix(route, "/")
	}
	return route
}

func lookup(method, route string) op {
	for key, o := range known {
		m, suffix, _ := strings.Cut(key, " ")
		if m == method && strings.HasSuffix(route, suffix) {
			return o
		}
	}
	return op{Summary: method + " " + route, Tag: tagFor(route)}
}

func tagFor(route string) string {
	parts := strings.Split(strings.Trim(route, "/"), "/")
	for _, p := range parts {
		if p != "" && !strings.HasPrefix(p, "{") && p != "auth" {
			return strings.TrimPrefix(p, ".")
		}
	}
	return "default"
}

func responses(o op) map[string]any {
	r := map[string]any{"200": map[string]string{"description": "Success"}}
	if o.Body {
		r["400"] = map[string]string{"description": "Invalid request"}
	}
	if o.Secured {
		r["401"] = map[string]string{"description": "Not authenticated"}
	}
	return r
}

func operationID(method, route string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	underscore := false
	for _, r := range "/" + route {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			if underscore {
				b.WriteByte('_')
				underscore = false
			}
			b.WriteRune(r)
		default:
			underscore = true
		}
	}
	return b.String()
}

func pathParams(route string) []map[string]any {
	var out []map[string]any
	for _, seg := range strings.Split(route, "/") {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			out = append(out, map[string]any{
				"name": strings.Trim(seg, "{}"), "in": "path", "required": true,
				"schema": map[string]string{"type": "string"},
			})
		}
	}
	return out
}
