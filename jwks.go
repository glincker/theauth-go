package theauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/glincker/theauth-go/crypto"
	"github.com/glincker/theauth-go/internal/ulid"
)

// jwks.go: JWKS state machine, Ed25519 keypair lifecycle, rotation goroutine.
//
// State transitions (driven by the rotation loop and bootstrap):
//   (empty)            -> mint two keys, mark first `current`, second `next`.
//   current + next     -> on tick: previous = current; current = next;
//                         next = generate fresh.
//   With previous      -> on tick: retire previous; promote as above.
//
// All three live states (current, next, previous) appear in /oauth/jwks so
// verifiers can validate tokens minted under the prior key during the
// rotation window. Retired keys are pruned after KeyRetention.

// jwk is the JSON Web Key encoding for an Ed25519 public key (RFC 8037).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

// jwksDoc is the public document served at /oauth/jwks.
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// generateEd25519Keypair mints a fresh Ed25519 keypair, encrypts the seed
// with the AS encryption key, and returns a populated JWKSKey ready to be
// inserted at state = next.
func (a *TheAuth) generateEd25519Keypair(state string) (JWKSKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return JWKSKey{}, nil, fmt.Errorf("ed25519 generate: %w", err)
	}
	publicJWK := jwk{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Alg: "EdDSA",
		Use: "sig",
		Kid: ulid.New().String(),
	}
	pubBytes, err := json.Marshal(publicJWK)
	if err != nil {
		return JWKSKey{}, nil, err
	}
	// Persist the seed (32 bytes), AES-GCM encrypted. ed25519.PrivateKey is
	// 64 bytes (seed || pub); the seed alone is the canonical secret per
	// RFC 8032 and rederives the public half deterministically.
	seed := priv.Seed()
	enc, err := crypto.Encrypt(a.encryptionKey, seed)
	if err != nil {
		return JWKSKey{}, nil, fmt.Errorf("encrypt jwks private: %w", err)
	}
	now := time.Now().UTC()
	k := JWKSKey{
		KID:        publicJWK.Kid,
		Alg:        "EdDSA",
		Use:        "sig",
		PublicJWK:  pubBytes,
		PrivateEnc: enc,
		State:      state,
		CreatedAt:  now,
	}
	if state == JWKSStateCurrent {
		t := now
		k.PromotedAt = &t
	}
	return k, priv, nil
}

// loadPrivateKey decrypts a JWKSKey row back into an ed25519.PrivateKey.
func (a *TheAuth) loadPrivateKey(k JWKSKey) (ed25519.PrivateKey, error) {
	seed, err := crypto.Decrypt(a.encryptionKey, k.PrivateEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt jwks private: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("theauth: jwks key seed has wrong length")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// bootstrapJWKS loads existing keys from storage, mints fresh ones if the
// table is empty, and populates the in-memory snapshot.
func (a *TheAuth) bootstrapJWKS(ctx context.Context) error {
	if a.as == nil {
		return nil
	}
	existing, err := a.as.storage.JWKSKeysAll(ctx)
	if err != nil {
		return fmt.Errorf("jwks load: %w", err)
	}
	if len(existing) == 0 {
		// First boot: mint current + next.
		curr, _, err := a.generateEd25519Keypair(JWKSStateCurrent)
		if err != nil {
			return err
		}
		if err := a.as.storage.InsertJWKSKey(ctx, curr); err != nil {
			return fmt.Errorf("jwks insert current: %w", err)
		}
		next, _, err := a.generateEd25519Keypair(JWKSStateNext)
		if err != nil {
			return err
		}
		if err := a.as.storage.InsertJWKSKey(ctx, next); err != nil {
			return fmt.Errorf("jwks insert next: %w", err)
		}
		existing = []JWKSKey{curr, next}
	}
	a.refreshJWKSSnapshot(existing)
	return nil
}

// refreshJWKSSnapshot rewrites the in-memory key snapshot under the AS lock.
func (a *TheAuth) refreshJWKSSnapshot(keys []JWKSKey) {
	a.as.mu.Lock()
	defer a.as.mu.Unlock()
	// Order: current, next, previous, retired. Retired keys are not served
	// in JWKS but are kept in the map briefly for verifier lookups during
	// the KeyRetention window.
	order := map[string]int{
		JWKSStateCurrent:  0,
		JWKSStateNext:     1,
		JWKSStatePrevious: 2,
		JWKSStateRetired:  3,
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return order[keys[i].State] < order[keys[j].State]
	})
	a.as.keys = keys
	a.as.keyMap = map[string]JWKSKey{}
	for _, k := range keys {
		a.as.keyMap[k.KID] = k
	}
}

// currentSigningKey returns the active (state = current) JWKS row and the
// decrypted private key. Used at every JWT mint.
func (a *TheAuth) currentSigningKey() (JWKSKey, ed25519.PrivateKey, error) {
	if a.as == nil {
		return JWKSKey{}, nil, errors.New("theauth: authorization server not configured")
	}
	a.as.mu.RLock()
	defer a.as.mu.RUnlock()
	for _, k := range a.as.keys {
		if k.State == JWKSStateCurrent {
			priv, err := a.loadPrivateKey(k)
			if err != nil {
				return JWKSKey{}, nil, err
			}
			return k, priv, nil
		}
	}
	return JWKSKey{}, nil, errors.New("theauth: no current JWKS key")
}

// publicKeyByKID returns the Ed25519 public key for the supplied kid, used at
// verify time. Returns false when the kid is unknown or retired.
func (a *TheAuth) publicKeyByKID(kid string) (ed25519.PublicKey, bool) {
	if a.as == nil {
		return nil, false
	}
	a.as.mu.RLock()
	defer a.as.mu.RUnlock()
	k, ok := a.as.keyMap[kid]
	if !ok || k.State == JWKSStateRetired {
		return nil, false
	}
	var pub jwk
	if err := json.Unmarshal(k.PublicJWK, &pub); err != nil {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(pub.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// renderJWKSDoc serializes the current JWKS document. Current + next +
// previous keys are exposed; retired keys are omitted.
func (a *TheAuth) renderJWKSDoc() ([]byte, error) {
	if a.as == nil {
		return nil, errors.New("theauth: authorization server not configured")
	}
	a.as.mu.RLock()
	defer a.as.mu.RUnlock()
	doc := jwksDoc{Keys: make([]jwk, 0, len(a.as.keys))}
	for _, k := range a.as.keys {
		if k.State == JWKSStateRetired {
			continue
		}
		var j jwk
		if err := json.Unmarshal(k.PublicJWK, &j); err != nil {
			continue
		}
		doc.Keys = append(doc.Keys, j)
	}
	return json.Marshal(doc)
}

// jwksRotationLoop runs in the background and rotates the signing keys at the
// configured cadence. Exits when rotationStop closes.
func (a *TheAuth) jwksRotationLoop() {
	defer close(a.as.rotationDone)
	period := a.as.cfg.KeyRotationPeriod
	if period <= 0 {
		period = 30 * 24 * time.Hour
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-a.as.rotationStop:
			return
		case <-ticker.C:
			if err := a.RotateSigningKey(context.Background()); err != nil {
				slog.Error("theauth: jwks rotation failed", "err", err.Error())
			}
		}
	}
}

// RotateSigningKey advances the JWKS state machine one step: previous (if
// any) is retired, current becomes previous, next becomes current, and a
// fresh next is minted. Idempotent under concurrent callers (each call mints
// one fresh next). Operators can invoke this on emergency without waiting
// for the scheduled tick.
func (a *TheAuth) RotateSigningKey(ctx context.Context) error {
	if a.as == nil {
		return errors.New("theauth: authorization server not configured")
	}
	a.as.mu.Lock()
	snapshot := append([]JWKSKey(nil), a.as.keys...)
	a.as.mu.Unlock()
	now := time.Now().UTC()
	var current, next JWKSKey
	for _, k := range snapshot {
		switch k.State {
		case JWKSStateCurrent:
			current = k
		case JWKSStateNext:
			next = k
		case JWKSStatePrevious:
			// Retire any previous (only the most recent prior key is kept).
			if err := a.as.storage.UpdateJWKSKeyState(ctx, k.KID, JWKSStateRetired, now); err != nil {
				return fmt.Errorf("retire previous: %w", err)
			}
		}
	}
	if current.KID == "" || next.KID == "" {
		return errors.New("theauth: cannot rotate without current + next keys")
	}
	if err := a.as.storage.UpdateJWKSKeyState(ctx, current.KID, JWKSStatePrevious, now); err != nil {
		return fmt.Errorf("demote current: %w", err)
	}
	if err := a.as.storage.UpdateJWKSKeyState(ctx, next.KID, JWKSStateCurrent, now); err != nil {
		return fmt.Errorf("promote next: %w", err)
	}
	fresh, _, err := a.generateEd25519Keypair(JWKSStateNext)
	if err != nil {
		return err
	}
	if err := a.as.storage.InsertJWKSKey(ctx, fresh); err != nil {
		return fmt.Errorf("insert fresh next: %w", err)
	}
	updated, err := a.as.storage.JWKSKeysAll(ctx)
	if err != nil {
		return fmt.Errorf("reload jwks: %w", err)
	}
	// Drop retired keys older than KeyRetention.
	cutoff := now.Add(-a.as.cfg.KeyRetention)
	filtered := make([]JWKSKey, 0, len(updated))
	for _, k := range updated {
		if k.State == JWKSStateRetired && k.RetiredAt != nil && k.RetiredAt.Before(cutoff) {
			continue
		}
		filtered = append(filtered, k)
	}
	a.refreshJWKSSnapshot(filtered)
	return nil
}
