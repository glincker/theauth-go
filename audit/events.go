// Package audit exposes the audit event vocabulary, the write-order cursor and the write-order
// stamp so storage backends in other modules (storage/sqlite) and custom backends share one
// implementation with the built-in stores. The checkpoint and sinks subpackages are separate.
package audit

import (
	iaudit "github.com/glincker/theauth-go/v2/internal/audit"
	"github.com/glincker/theauth-go/v2/internal/models"
)

// Shared event names, identical to the TypeScript SDK where the concept exists.
const (
	EventAuthorize        = iaudit.EventAuthorize
	EventAuthorizeToken   = iaudit.EventAuthorizeToken
	EventPolicyEvaluate   = iaudit.EventPolicyEvaluate
	EventMCPToolCall      = iaudit.EventMCPToolCall
	EventDelegationCreate = iaudit.EventDelegationCreate
	EventDelegationRevoke = iaudit.EventDelegationRevoke
	EventAgentCreate      = iaudit.EventAgentCreate
	EventAgentRevoke      = iaudit.EventAgentRevoke
	EventAgentCascade     = iaudit.EventAgentCascade
	EventApprovalRequest  = iaudit.EventApprovalRequest
	EventApprovalApprove  = iaudit.EventApprovalApprove
	EventApprovalDeny     = iaudit.EventApprovalDeny
	EventVaultRead        = iaudit.EventVaultRead
	EventAuditCheckpoint  = iaudit.EventAuditCheckpoint
	EventAuditWriteFailed = iaudit.EventAuditWriteFailed
	EventAuditErasure     = iaudit.EventAuditErasure
)

// CursorPrefix versions the write-order cursor.
const CursorPrefix = iaudit.CursorPrefix

// Cursor is a decoded write-order keyset position.
type Cursor = iaudit.Cursor

// Events returns the closed event vocabulary, sorted.
func Events() []string { return iaudit.Events() }

// ValidEvent reports whether e is in the closed vocabulary.
func ValidEvent(e string) bool { return iaudit.ValidEvent(e) }

// ValidateEvent returns nil for "" and for vocabulary names, an error otherwise.
func ValidateEvent(e string) error { return iaudit.ValidateEvent(e) }

// EventForAction maps an existing Go action string to its shared event, or "".
func EventForAction(action string) string { return iaudit.EventForAction(action) }

// ActionEvents returns a copy of the action to event table used by the migrations backfill.
func ActionEvents() map[string]string { return iaudit.ActionEvents() }

// EncodeCursor returns the opaque write-order cursor.
func EncodeCursor(c Cursor) string { return iaudit.EncodeCursor(c) }

// DecodeCursor parses a cursor for the given order. Failures wrap theauth.ErrBadCursor.
func DecodeCursor(s, wantOrder string) (Cursor, error) { return iaudit.DecodeCursor(s, wantOrder) }

// IsLegacyCursor reports whether s is a pre write order cursor.
func IsLegacyCursor(s string) bool { return iaudit.IsLegacyCursor(s) }

// NormalizeOrder maps "" to "desc" and reports false for an invalid order.
func NormalizeOrder(o string) (string, bool) { return iaudit.NormalizeOrder(o) }

// NextRecordedAtUs returns the next strictly increasing write-order stamp in microseconds, above
// floor (the chain head's stamp).
func NextRecordedAtUs(floor int64) int64 { return iaudit.NextRecordedAtUs(floor) }

// ErrBadAuditOrder is returned for an invalid AuditQuery.Order.
var ErrBadAuditOrder = models.ErrBadAuditOrder
