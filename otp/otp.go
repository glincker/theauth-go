// Package otp issues and verifies one-time numeric codes delivered over a
// pluggable channel (email, SMS, or anything else a Sender can reach).
//
// The service keeps no database table. State lives in a kv.Cache, so the
// same code runs on the in-memory store, Redis or SQL adapters. Codes are
// stored as an HMAC under a server secret, compared in constant time, and
// guarded by a resend cooldown, an attempt counter and a lockout window.
//
// The package proves control of a destination. It does not create sessions:
// after Verify returns nil, hand the destination to your own sign-in path.
package otp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/kv"
)

// Channel names the delivery medium. It selects destination normalization.
type Channel string

const (
	// ChannelEmail normalizes destinations by trimming and lower-casing.
	ChannelEmail Channel = "email"
	// ChannelSMS normalizes destinations by dropping spaces, dashes and parentheses.
	ChannelSMS Channel = "sms"
)

// Errors returned by the Service. ErrInvalid covers wrong, expired and
// unknown codes alike so callers cannot tell them apart.
var (
	ErrInvalid  = errors.New("otp: invalid or expired code")
	ErrCooldown = errors.New("otp: resend cooldown active")
	ErrLocked   = errors.New("otp: too many attempts, destination locked")
)

// Message is what a Sender delivers.
type Message struct {
	Channel   Channel
	To        string
	Code      string
	Purpose   string
	ExpiresIn time.Duration
}

// Sender delivers a Message. Implementations must be safe for concurrent use.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SenderFunc adapts a function to Sender.
type SenderFunc func(ctx context.Context, m Message) error

// Send calls f.
func (f SenderFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

// Config wires a Service. Cache, Sender and Secret are required.
type Config struct {
	Channel Channel
	Cache   kv.Cache
	Sender  Sender
	// Secret keys the code HMAC and the cache key derivation. At least 32 bytes.
	Secret []byte
	// Length is the number of digits. Default 6, range 4 to 10.
	Length int
	// TTL is how long a code stays valid. Default 10 minutes.
	TTL time.Duration
	// Cooldown is the minimum gap between two sends to one destination.
	// Default 60 seconds.
	Cooldown time.Duration
	// MaxAttempts is the number of wrong guesses allowed per issued code
	// window before lockout. Default 5.
	MaxAttempts int
	// LockoutDuration is how long a destination stays locked. Default 15 minutes.
	LockoutDuration time.Duration
	// Rand is the entropy source. Defaults to crypto/rand.
	Rand io.Reader
}

// Service issues and verifies codes.
type Service struct {
	cfg Config
}

// New validates cfg and applies defaults.
func New(cfg Config) (*Service, error) {
	if cfg.Cache == nil || cfg.Sender == nil {
		return nil, errors.New("otp: Cache and Sender are required")
	}
	if len(cfg.Secret) < 32 {
		return nil, errors.New("otp: Secret must be at least 32 bytes")
	}
	if cfg.Channel == "" {
		cfg.Channel = ChannelEmail
	}
	if cfg.Length == 0 {
		cfg.Length = 6
	}
	if cfg.Length < 4 || cfg.Length > 10 {
		return nil, errors.New("otp: Length must be between 4 and 10")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 60 * time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.LockoutDuration <= 0 {
		cfg.LockoutDuration = 15 * time.Minute
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	cfg.Secret = append([]byte(nil), cfg.Secret...)
	return &Service{cfg: cfg}, nil
}

// Issue generates a code for purpose and to, and sends it. It returns
// ErrCooldown when a code was sent too recently and ErrLocked while the
// destination is locked. If delivery fails the cooldown is released so the
// caller can retry.
func (s *Service) Issue(ctx context.Context, purpose, to string) error {
	to = s.normalize(to)
	if to == "" {
		return errors.New("otp: empty destination")
	}
	id := s.id(purpose, to)
	if locked, err := s.locked(ctx, id); err != nil {
		return err
	} else if locked {
		return ErrLocked
	}
	stored, err := s.cfg.Cache.SetNX(ctx, "otp:cd:"+id, []byte{1}, s.cfg.Cooldown)
	if err != nil {
		return err
	}
	if !stored {
		return ErrCooldown
	}
	code, err := s.generate()
	if err != nil {
		_ = s.cfg.Cache.Delete(ctx, "otp:cd:"+id)
		return err
	}
	if err := s.cfg.Cache.Set(ctx, "otp:code:"+id, []byte(s.mac(id, code)), s.cfg.TTL); err != nil {
		_ = s.cfg.Cache.Delete(ctx, "otp:cd:"+id)
		return err
	}
	_ = s.cfg.Cache.Delete(ctx, "otp:att:"+id)
	msg := Message{Channel: s.cfg.Channel, To: to, Code: code, Purpose: purpose, ExpiresIn: s.cfg.TTL}
	if err := s.cfg.Sender.Send(ctx, msg); err != nil {
		_ = s.cfg.Cache.Delete(ctx, "otp:code:"+id)
		_ = s.cfg.Cache.Delete(ctx, "otp:cd:"+id)
		return fmt.Errorf("otp: send: %w", err)
	}
	return nil
}

// Verify checks code and consumes it on success. A wrong guess counts
// against MaxAttempts; the guess that exceeds it locks the destination and
// discards the pending code.
func (s *Service) Verify(ctx context.Context, purpose, to, code string) error {
	to = s.normalize(to)
	id := s.id(purpose, to)
	if locked, err := s.locked(ctx, id); err != nil {
		return err
	} else if locked {
		return ErrLocked
	}
	n, err := s.cfg.Cache.Incr(ctx, "otp:att:"+id, s.cfg.LockoutDuration)
	if err != nil {
		return err
	}
	if n > int64(s.cfg.MaxAttempts) {
		_ = s.cfg.Cache.Set(ctx, "otp:lock:"+id, []byte{1}, s.cfg.LockoutDuration)
		_ = s.cfg.Cache.Delete(ctx, "otp:code:"+id)
		return ErrLocked
	}
	want, ok, err := s.cfg.Cache.Get(ctx, "otp:code:"+id)
	if err != nil {
		return err
	}
	if !ok {
		// Compare against a dummy so absent and wrong codes cost the same.
		want = []byte(s.mac(id, "absent"))
	}
	got := s.mac(id, strings.TrimSpace(code))
	match := subtle.ConstantTimeCompare([]byte(got), want) == 1
	if !ok || !match {
		return ErrInvalid
	}
	_ = s.cfg.Cache.Delete(ctx, "otp:code:"+id)
	_ = s.cfg.Cache.Delete(ctx, "otp:att:"+id)
	return nil
}

func (s *Service) locked(ctx context.Context, id string) (bool, error) {
	_, ok, err := s.cfg.Cache.Get(ctx, "otp:lock:"+id)
	return ok, err
}

func (s *Service) normalize(to string) string {
	to = strings.TrimSpace(to)
	if s.cfg.Channel == ChannelSMS {
		return strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(to)
	}
	return strings.ToLower(to)
}

// id derives an opaque cache identifier so destinations never appear in keys.
func (s *Service) id(purpose, to string) string {
	m := hmac.New(sha256.New, s.cfg.Secret)
	m.Write([]byte("id\x00" + string(s.cfg.Channel) + "\x00" + purpose + "\x00" + to))
	return hex.EncodeToString(m.Sum(nil))[:40]
}

func (s *Service) mac(id, code string) string {
	m := hmac.New(sha256.New, s.cfg.Secret)
	m.Write([]byte("code\x00" + id + "\x00" + code))
	return hex.EncodeToString(m.Sum(nil))
}

// generate returns a uniformly distributed Length-digit string using
// rejection sampling to avoid modulo bias.
func (s *Service) generate() (string, error) {
	out := make([]byte, s.cfg.Length)
	buf := make([]byte, 1)
	for i := 0; i < len(out); {
		if _, err := io.ReadFull(s.cfg.Rand, buf); err != nil {
			return "", fmt.Errorf("otp: entropy: %w", err)
		}
		if buf[0] >= 250 {
			continue
		}
		out[i] = '0' + buf[0]%10
		i++
	}
	return string(out), nil
}
