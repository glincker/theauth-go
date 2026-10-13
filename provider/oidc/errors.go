package oidc

import (
	"errors"
	"fmt"
	"net/url"
)

// Stage names the step of an OIDC login that failed.
type Stage string

// Stages reported by Error.
const (
	StageDiscovery Stage = "discovery"
	StageExchange  Stage = "exchange"
	StageVerify    Stage = "verify"
	StageUserinfo  Stage = "userinfo"
	StageRefresh   Stage = "refresh"
)

// Error is the typed failure every provider operation returns after
// construction. Use errors.As to branch on Stage or Status:
//
//	var oe *oidc.Error
//	if errors.As(err, &oe) && oe.Stage == oidc.StageExchange && oe.Status == 400 { ... }
//
// The message carries the provider id, the stage and, for HTTP failures, the
// status. It never includes response bodies, request parameters, tokens or
// client secrets, so it is safe to log.
type Error struct {
	// Provider is Config.Name (for example "entra" or "oidc").
	Provider string
	// Stage is the step that failed.
	Stage Stage
	// Status is the upstream HTTP status, or 0 when none applied.
	Status int
	// Err is the underlying cause, with request URLs stripped from
	// transport errors.
	Err error
}

func (e *Error) Error() string {
	msg := "failed"
	if e.Err != nil {
		msg = e.Err.Error()
	}
	if e.Status != 0 {
		return fmt.Sprintf("oidc: %s: %s: %s (status %d)", e.Provider, e.Stage, msg, e.Status)
	}
	return fmt.Sprintf("oidc: %s: %s: %s", e.Provider, e.Stage, msg)
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// fail builds an *Error. A *url.Error (which embeds the request URL) is
// reduced to its inner error so query strings never reach logs.
func (p *provider) fail(stage Stage, status int, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return &Error{Provider: p.cfg.Name, Stage: stage, Status: status, Err: err}
}
