package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rotating pseudonyms.
//
// The stable pseudonym (Pseudonym) is keyed by one installation secret, so whoever holds it can
// link a subject across all time. With rotation each period (a whole number of days since the Unix
// epoch) has its own random secret, and a subject's pseudonym is keyed by the secret of the period
// the row was written in. One subject has a different pseudonym in every period. Once the secret of
// an old period is deleted ("shredded") no key remains that links that period to any other, the
// operator included. The chain hash covers the stored pseudonyms, not the secrets, so shredding
// keeps the chain verifiable. The cost: a raw id still present on a row of a shredded period can
// no longer be checked against its pseudonym.
//
// A rotated pseudonym is tagged so the verifier knows which key to use and old rows keep working:
//
//	r1:<period>:<hex>   HMAC-SHA256(periodSecret, "theauth.audit.pseudonym.v2:p<period>:" + id)
//	<hex>               the stable pseudonym of rows written before rotation was turned on
//
// "r1" is the scheme version. The hashed field set of the row is unchanged, so ChainHashVersion
// stays 1 and rows of both forms verify together. The period secret is independent of any other
// key on purpose: deriving it from the installation secret would let its holder recompute every
// period.

const (
	rotatedPrefix = "r1:"
	rotatedDomain = "theauth.audit.pseudonym.v2:p"
	dayMillis     = int64(24 * 60 * 60 * 1000)
)

// Rotation is the rotation policy.
type Rotation struct {
	// PeriodDays is the length of one period in days, at least 1.
	PeriodDays int
	// RetainPeriods is how many periods older than the current one keep their secret. Zero means the
	// default of 1. A negative value keeps only the current period. Older secrets are shredded the
	// first time a new period starts.
	RetainPeriods int
}

// Normalize validates r and applies the retention default.
func (r Rotation) Normalize() (Rotation, error) {
	if r.PeriodDays < 1 {
		return Rotation{}, errors.New("theauth: audit pseudonym rotation period must be a whole number of days, at least 1")
	}
	switch {
	case r.RetainPeriods == 0:
		r.RetainPeriods = 1
	case r.RetainPeriods < 0:
		r.RetainPeriods = 0
	}
	return r, nil
}

// PeriodOf returns the period number of t: floor(unix milliseconds / period length).
func PeriodOf(t time.Time, periodDays int) int64 {
	span := int64(periodDays) * dayMillis
	ms := t.UnixMilli()
	q := ms / span
	if ms%span < 0 {
		q--
	}
	return q
}

// RotatingPseudonym is the tagged pseudonym of id under the secret of period. Empty ids stay empty.
func RotatingPseudonym(secret []byte, period int64, id string) string {
	if id == "" {
		return ""
	}
	p := strconv.FormatInt(period, 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(rotatedDomain + p + ":" + id))
	return rotatedPrefix + p + ":" + hex.EncodeToString(m.Sum(nil))
}

// PseudonymPeriod returns the period a pseudonym was written under, or false for a stable pseudonym
// or a malformed tag.
func PseudonymPeriod(p string) (int64, bool) {
	rest, ok := strings.CutPrefix(p, rotatedPrefix)
	if !ok {
		return 0, false
	}
	num, _, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(num, 10, 64)
	return n, err == nil
}

// PseudonymKeys is what the verifier holds: the stable secret and the secrets of every period that
// has not been shredded. Either may be absent.
type PseudonymKeys struct {
	Stable  []byte
	Periods map[int64][]byte
}

// StableKeys wraps a lone installation secret.
func StableKeys(secret []byte) PseudonymKeys { return PseudonymKeys{Stable: secret} }

// Check reports whether pseudo is consistent with the raw id still on the row. It is true when the
// pseudonym cannot be checked: no key (a store that never wrote a chained row) or a shredded
// period. A rotated pseudonym is never compared under the stable secret.
func (k PseudonymKeys) Check(raw, pseudo string) bool {
	if period, rotated := PseudonymPeriod(pseudo); rotated {
		secret, ok := k.Periods[period]
		if !ok {
			return true
		}
		return hmac.Equal([]byte(RotatingPseudonym(secret, period, raw)), []byte(pseudo))
	}
	if k.Stable == nil {
		return true
	}
	return hmac.Equal([]byte(Pseudonym(k.Stable, raw)), []byte(pseudo))
}

// Pseudonymizer makes the pseudonyms of one row at write time.
type Pseudonymizer struct {
	Stable []byte
	// Rotation, when set, switches to rotating pseudonyms. Periods must then hold the secret of every
	// period a row in the batch falls in (see RotationState.Resolve).
	Rotation *Rotation
	Periods  map[int64][]byte
}

// Of returns the pseudonym of id for a row created at t. It fails closed: with rotation on and no
// secret for the period it returns an error instead of falling back to the stable form.
func (p Pseudonymizer) Of(t time.Time, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	if p.Rotation == nil {
		return Pseudonym(p.Stable, id), nil
	}
	period := PeriodOf(t, p.Rotation.PeriodDays)
	secret, ok := p.Periods[period]
	if !ok {
		return "", fmt.Errorf("theauth: no audit pseudonym secret for period %d", period)
	}
	return RotatingPseudonym(secret, period, id), nil
}

// PeriodSecretStore is the storage a backend gives the rotation logic. Implementations bind it to
// the transaction the batch writes in, when the backend has one.
type PeriodSecretStore interface {
	// GetOrCreate returns the secret of period, creating it when absent. Two writers racing on the
	// same period must end up with the same secret.
	GetOrCreate(ctx context.Context, period int64) ([]byte, error)
	// Periods lists the periods that have a secret.
	Periods(ctx context.Context) ([]int64, error)
	// Delete removes the secrets of the given periods.
	Delete(ctx context.Context, periods []int64) error
}

// NewPeriodSecret returns a fresh random 32 byte period secret.
func NewPeriodSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate audit period secret: %w", err)
	}
	return b, nil
}

// RotationState holds a store's rotation policy and remembers the last period it swept. The zero
// value means rotation is off. It is safe for concurrent use.
type RotationState struct {
	mu    sync.Mutex
	rot   *Rotation
	last  int64
	swept bool
}

// Set turns rotation on with r, or off when r is nil.
func (s *RotationState) Set(r *Rotation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r == nil {
		s.rot, s.swept = nil, false
		return nil
	}
	n, err := r.Normalize()
	if err != nil {
		return err
	}
	s.rot, s.swept = &n, false
	return nil
}

// Get returns the active policy, or nil when rotation is off.
func (s *RotationState) Get() *Rotation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rot == nil {
		return nil
	}
	c := *s.rot
	return &c
}

// Resolve returns a Pseudonymizer for a batch of rows created at times. With rotation off it is the
// stable one. With rotation on it reads or creates the secret of every period in the batch, and
// the first batch of a new period also shreds the secrets that fell out of the retention window.
func (s *RotationState) Resolve(ctx context.Context, stable []byte, st PeriodSecretStore, times []time.Time) (Pseudonymizer, error) {
	rot := s.Get()
	if rot == nil {
		return Pseudonymizer{Stable: stable}, nil
	}
	periods := map[int64][]byte{}
	var newest int64
	for i, t := range times {
		p := PeriodOf(t, rot.PeriodDays)
		if i == 0 || p > newest {
			newest = p
		}
		if _, ok := periods[p]; ok {
			continue
		}
		secret, err := st.GetOrCreate(ctx, p)
		if err != nil {
			return Pseudonymizer{}, err
		}
		periods[p] = secret
	}
	if len(times) > 0 && s.needsSweep(newest) {
		if _, err := ShredStalePeriods(ctx, st, newest, rot.RetainPeriods); err != nil {
			return Pseudonymizer{}, err
		}
		s.markSwept(newest)
	}
	return Pseudonymizer{Stable: stable, Rotation: rot, Periods: periods}, nil
}

func (s *RotationState) needsSweep(period int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.swept || period > s.last
}

func (s *RotationState) markSwept(period int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.swept || period > s.last {
		s.last, s.swept = period, true
	}
}

// ShredStalePeriods deletes the secrets of periods older than current-retain and returns the
// periods removed, ascending. After this nobody can recompute the pseudonyms of those periods.
func ShredStalePeriods(ctx context.Context, st PeriodSecretStore, current int64, retain int) ([]int64, error) {
	all, err := st.Periods(ctx)
	if err != nil {
		return nil, err
	}
	var stale []int64
	for _, p := range all {
		if p < current-int64(retain) {
			stale = append(stale, p)
		}
	}
	if len(stale) == 0 {
		return nil, nil
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i] < stale[j] })
	if err := st.Delete(ctx, stale); err != nil {
		return nil, err
	}
	return stale, nil
}
