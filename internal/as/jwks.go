package as

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
	"github.com/glincker/theauth-go/internal/models"
	"github.com/glincker/theauth-go/internal/ulid"
)

// jwks.go: JWKS state machine, Ed25519 keypair lifecycle, rotation
// goroutine.
//
// State transitions (driven by the rotation loop and bootstrap):
//
//	(empty)            -> mint two keys, mark first `current`, second `next`.
//	current + next     -> on tick: previous = current; current = next;
//	                      next = generate fresh.
//	With previous      -> on tick: retire previous; promote as above.
//
// All three live states (current, next, previous) appear in /oauth/jwks
// so verifiers can validate tokens minted under the prior key during the
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
func (s *Service) generateEd25519Keypair(state string) (models.JWKSKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return models.JWKSKey{}, nil, fmt.Errorf("ed25519 generate: %w", err)
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
		return models.JWKSKey{}, nil, err
	}
	// Persist the seed (32 bytes), AES-GCM encrypted. ed25519.PrivateKey
	// is 64 bytes (seed || pub); the seed alone is the canonical secret
	// per RFC 8032 and rederives the public half deterministically.
	seed := priv.Seed()
	enc, err := crypto.Encrypt(s.encryptionKey, seed)
	if err != nil {
		return models.JWKSKey{}, nil, fmt.Errorf("encrypt jwks private: %w", err)
	}
	now := time.Now().UTC()
	k := models.JWKSKey{
		KID:        publicJWK.Kid,
		Alg:        "EdDSA",
		Use:        "sig",
		PublicJWK:  pubBytes,
		PrivateEnc: enc,
		State:      state,
		CreatedAt:  now,
	}
	if state == models.JWKSStateCurrent {
		t := now
		k.PromotedAt = &t
	}
	return k, priv, nil
}

// loadPrivateKey decrypts a JWKSKey row back into an ed25519.PrivateKey.
func (s *Service) loadPrivateKey(k models.JWKSKey) (ed25519.PrivateKey, error) {
	seed, err := crypto.Decrypt(s.encryptionKey, k.PrivateEnc)
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
func (s *Service) bootstrapJWKS(ctx context.Context) error {
	if s == nil {
		return nil
	}
	existing, err := s.Storage.JWKSKeysAll(ctx)
	if err != nil {
		return fmt.Errorf("jwks load: %w", err)
	}
	if len(existing) == 0 {
		// First boot: mint current + next.
		curr, _, err := s.generateEd25519Keypair(models.JWKSStateCurrent)
		if err != nil {
			return err
		}
		if err := s.Storage.InsertJWKSKey(ctx, curr); err != nil {
			return fmt.Errorf("jwks insert current: %w", err)
		}
		next, _, err := s.generateEd25519Keypair(models.JWKSStateNext)
		if err != nil {
			return err
		}
		if err := s.Storage.InsertJWKSKey(ctx, next); err != nil {
			return fmt.Errorf("jwks insert next: %w", err)
		}
		existing = []models.JWKSKey{curr, next}
	}
	s.refreshJWKSSnapshot(existing)
	return nil
}

// refreshJWKSSnapshot rewrites the in-memory key snapshot under the AS
// lock. The AES-GCM-encrypted private seed on every active key is
// decrypted ONCE and stashed in s.privKeyByKID; currentSigningKey serves
// JWT mints out of that map so the hot path never re-runs
// aes.NewCipher + cipher.NewGCM. Retired keys are kept in keyMap for the
// KeyRetention window but their private halves are NOT cached because
// retired keys are never used to sign.
//
// Cache invalidation contract: privKeyByKID is replaced wholesale here.
// Every state transition (bootstrap, scheduled rotation, manual
// RotateSigningKey) routes through this function, so a rotated KID's
// private key disappears from the cache the same moment its public form
// changes state.
func (s *Service) refreshJWKSSnapshot(keys []models.JWKSKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Order: current, next, previous, retired. Retired keys are not
	// served in JWKS but are kept in the map briefly for verifier lookups
	// during the KeyRetention window.
	order := map[string]int{
		models.JWKSStateCurrent:  0,
		models.JWKSStateNext:     1,
		models.JWKSStatePrevious: 2,
		models.JWKSStateRetired:  3,
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return order[keys[i].State] < order[keys[j].State]
	})
	s.keys = keys
	s.keyMap = map[string]models.JWKSKey{}
	s.privKeyByKID = make(map[string]ed25519.PrivateKey, len(keys))
	for _, k := range keys {
		s.keyMap[k.KID] = k
		if k.State == models.JWKSStateRetired {
			continue
		}
		priv, err := s.loadPrivateKey(k)
		if err != nil {
			// A single bad row should not poison the whole snapshot. Skip
			// it; currentSigningKey will surface the absence of a
			// decrypted current key as a typed error to the caller.
			slog.Warn("theauth: jwks key decrypt failed during snapshot refresh", "kid", k.KID, "err", err.Error())
			continue
		}
		s.privKeyByKID[k.KID] = priv
	}
}

// CurrentSigningKey returns the active (state = current) JWKS row and the
// decrypted private key. Used at every JWT mint.
//
// The private key is served from s.privKeyByKID, which refreshJWKSSnapshot
// populates by decrypting each key exactly once at snapshot build time.
// The hot path therefore never executes aes.NewCipher + cipher.NewGCM and
// never allocates the seed buffer; it returns a pointer to the cached
// ed25519 private key under the same RLock that already guards the keys
// slice.
func (s *Service) CurrentSigningKey() (models.JWKSKey, ed25519.PrivateKey, error) {
	if s == nil {
		return models.JWKSKey{}, nil, errors.New("theauth: authorization server not configured")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if k.State == models.JWKSStateCurrent {
			if priv, ok := s.privKeyByKID[k.KID]; ok && priv != nil {
				return k, priv, nil
			}
			// Defensive fallback: the cache should always carry the
			// current key (refreshJWKSSnapshot populates it for every
			// non-retired row). If a bootstrap race or storage
			// corruption leaves it empty, fall back to the slow decrypt
			// path so the request still succeeds.
			fallback, err := s.loadPrivateKey(k)
			if err != nil {
				return models.JWKSKey{}, nil, err
			}
			return k, fallback, nil
		}
	}
	return models.JWKSKey{}, nil, errors.New("theauth: no current JWKS key")
}

// PublicKeyByKID returns the Ed25519 public key for the supplied kid,
// used at verify time. Returns false when the kid is unknown or retired.
func (s *Service) PublicKeyByKID(kid string) (ed25519.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keyMap[kid]
	if !ok || k.State == models.JWKSStateRetired {
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

// RenderJWKSDoc serializes the current JWKS document. Current + next +
// previous keys are exposed; retired keys are omitted.
func (s *Service) RenderJWKSDoc() ([]byte, error) {
	if s == nil {
		return nil, errors.New("theauth: authorization server not configured")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc := jwksDoc{Keys: make([]jwk, 0, len(s.keys))}
	for _, k := range s.keys {
		if k.State == models.JWKSStateRetired {
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

// jwksRotationLoop runs in the background and rotates the signing keys
// at the configured cadence. Exits when rotationStop closes.
func (s *Service) jwksRotationLoop() {
	defer close(s.rotationDone)
	period := s.Cfg.KeyRotationPeriod
	if period <= 0 {
		period = 30 * 24 * time.Hour
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-s.rotationStop:
			return
		case <-ticker.C:
			if err := s.RotateSigningKey(context.Background()); err != nil {
				slog.Error("theauth: jwks rotation failed", "err", err.Error())
			}
		}
	}
}

// RotateSigningKey advances the JWKS state machine one step: previous
// (if any) is retired, current becomes previous, next becomes current,
// and a fresh next is minted. Concurrent callers are serialized via
// rotationMu so that two goroutines cannot both read the same snapshot
// and independently issue conflicting state updates, which could leave two
// rows with state = current.
//
// When the underlying Storage also implements JWKSAtomicRotator the entire
// state transition is issued as a single database transaction, providing
// an additional DB-level guard against concurrent callers on separate
// process instances.
func (s *Service) RotateSigningKey(ctx context.Context) error {
	if s == nil {
		return errors.New("theauth: authorization server not configured")
	}
	// Serialise concurrent callers at the process level so that two goroutines
	// cannot both observe the same snapshot and produce two current rows.
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	s.mu.Lock()
	snapshot := append([]models.JWKSKey(nil), s.keys...)
	s.mu.Unlock()
	now := time.Now().UTC()
	var current, next models.JWKSKey
	var retireKIDs []string
	for _, k := range snapshot {
		switch k.State {
		case models.JWKSStateCurrent:
			current = k
		case models.JWKSStateNext:
			next = k
		case models.JWKSStatePrevious:
			retireKIDs = append(retireKIDs, k.KID)
		}
	}
	if current.KID == "" || next.KID == "" {
		return errors.New("theauth: cannot rotate without current + next keys")
	}
	fresh, _, err := s.generateEd25519Keypair(models.JWKSStateNext)
	if err != nil {
		return err
	}
	if ar, ok := s.Storage.(JWKSAtomicRotator); ok {
		// Fast path: issue all state changes in a single transaction so no
		// concurrent rotation can interleave and produce two current rows.
		if err := ar.AtomicRotateJWKS(ctx, retireKIDs, current.KID, next.KID, fresh, now); err != nil {
			return fmt.Errorf("atomic jwks rotate: %w", err)
		}
	} else {
		// Fallback path for storage backends that do not implement
		// JWKSAtomicRotator (e.g. in-memory store for unit tests).
		for _, kid := range retireKIDs {
			if err := s.Storage.UpdateJWKSKeyState(ctx, kid, models.JWKSStateRetired, now); err != nil {
				return fmt.Errorf("retire previous: %w", err)
			}
		}
		if err := s.Storage.UpdateJWKSKeyState(ctx, current.KID, models.JWKSStatePrevious, now); err != nil {
			return fmt.Errorf("demote current: %w", err)
		}
		if err := s.Storage.UpdateJWKSKeyState(ctx, next.KID, models.JWKSStateCurrent, now); err != nil {
			return fmt.Errorf("promote next: %w", err)
		}
		if err := s.Storage.InsertJWKSKey(ctx, fresh); err != nil {
			return fmt.Errorf("insert fresh next: %w", err)
		}
	}
	updated, err := s.Storage.JWKSKeysAll(ctx)
	if err != nil {
		return fmt.Errorf("reload jwks: %w", err)
	}
	// Drop retired keys older than KeyRetention.
	cutoff := now.Add(-s.Cfg.KeyRetention)
	filtered := make([]models.JWKSKey, 0, len(updated))
	for _, k := range updated {
		if k.State == models.JWKSStateRetired && k.RetiredAt != nil && k.RetiredAt.Before(cutoff) {
			continue
		}
		filtered = append(filtered, k)
	}
	s.refreshJWKSSnapshot(filtered)
	return nil
}
