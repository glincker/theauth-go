package theauth

import "errors"

var (
	ErrInvalidToken     = errors.New("theauth: invalid token")
	ErrSessionExpired   = errors.New("theauth: session expired")
	ErrUserNotFound     = errors.New("theauth: user not found")
	ErrMagicLinkExpired = errors.New("theauth: magic link expired")
	ErrMagicLinkUsed    = errors.New("theauth: magic link already used")
	ErrEmailNotVerified = errors.New("theauth: email not verified")
)
