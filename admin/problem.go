// Package admin holds shared helpers for the /admin/v1 HTTP surface:
// RFC 7807 problem+json marshalling and keyset cursor encoding.
package admin

import (
	"encoding/json"
	"net/http"
)

// ProblemTypeBase is the URI prefix for problem types per RFC 7807. Each
// problem code is appended to form the canonical type URI. Consumers may
// host their own equivalent page; the URI is informational only.
const ProblemTypeBase = "https://theauth.dev/problems/"

// Problem is the RFC 7807 application/problem+json document shape, plus the
// "code" extension this library uses for machine-readable error matching.
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Code     string `json:"code"`
}

// Write emits a single problem+json response. status drives both the HTTP
// status code and the body's "status" field so the two cannot drift.
func Write(w http.ResponseWriter, status int, code, detail, instance string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{
		Type:     ProblemTypeBase + code,
		Title:    http.StatusText(status),
		Status:   status,
		Detail:   detail,
		Instance: instance,
		Code:     code,
	})
}

// Reserved problem codes. Listed here so the admin handlers and the
// middleware both pull from the same source of truth.
const (
	CodeForbidden         = "rbac.forbidden"
	CodeOrgMismatch       = "rbac.org_mismatch"
	CodeNoActiveOrg       = "rbac.no_active_org"
	CodeRoleInUse         = "rbac.role_in_use"
	CodeUnknownPermission = "rbac.unknown_permission"
	CodeBadCursor         = "pagination.bad_cursor"
	CodeUserNotInOrg      = "admin.user_not_in_org"
	CodeValidationInvalid = "validation.invalid"
	CodeNotFound          = "admin.not_found"
	CodeInternal          = "admin.internal"
	CodeUnauthorized      = "auth.unauthorized"
	CodeUnsupportedAction = "admin.unsupported_action"
)
