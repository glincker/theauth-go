package models

import "errors"

// ErrOAuthServerBusy is returned when the authorization server sheds load
// because too many client-secret verifications are already running. Handlers
// map it to HTTP 503 with error=temporarily_unavailable.
var ErrOAuthServerBusy = errors.New("theauth: temporarily_unavailable")
