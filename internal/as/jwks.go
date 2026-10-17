package as

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
	"time"

	authcrypto "github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/jwt"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// jwks.go is the JWKS state machine, the Ed25519 keypair lifecycle and the rotation goroutine. Keys
// move from next to current to previous and then retire. All three live states appear in
// /oauth/jwks so tokens minted under the prior key still verify during the rotation window; retired
// keys are pruned after KeyRetention.

// jwk is the JSON Web Key encoding of a public signing key: Ed25519 (RFC 8037), P-256 (RFC 7518) or RSA.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// generateKeypair mints a keypair for alg and encrypts the private half with the AS encryption key.
// Ed25519 stores the 32-byte seed; the other algorithms store PKCS#8 DER.
func (s *Service) generateKeypair(alg, state string) (models.JWKSKey, error) {
	kid := ulid.New().String()
	var (
		public jwk
		secret []byte
	)
	switch alg {
	case jwt.AlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return models.JWKSKey{}, fmt.Errorf("ed25519 generate: %w", err)
		}
		public = jwk{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}
		secret = priv.Seed()
	case jwt.AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return models.JWKSKey{}, fmt.Errorf("ecdsa generate: %w", err)
		}
		public = jwk{
			Kty: "EC", Crv: "P-256",
			X: base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32))),
			Y: base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32))),
		}
		if secret, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
			return models.JWKSKey{}, fmt.Errorf("marshal ecdsa key: %w", err)
		}
	case jwt.AlgRS256:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return models.JWKSKey{}, fmt.Errorf("rsa generate: %w", err)
		}
		public = jwk{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		}
		if secret, err = x509.MarshalPKCS8PrivateKey(priv); err != nil {
			return models.JWKSKey{}, fmt.Errorf("marshal rsa key: %w", err)
		}
	default:
		return models.JWKSKey{}, fmt.Errorf("theauth: unsupported signing alg %q", alg)
	}
	public.Alg, public.Use, public.Kid = alg, "sig", kid
	pubBytes, err := json.Marshal(public)
	if err != nil {
		return models.JWKSKey{}, err
	}
	enc, err := authcrypto.Encrypt(s.encryptionKey, secret)
	if err != nil {
		return models.JWKSKey{}, fmt.Errorf("encrypt jwks private: %w", err)
	}
	now := time.Now().UTC()
	k := models.JWKSKey{
		KID:        kid,
		Alg:        alg,
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
	return k, nil
}

// loadPrivateKey decrypts a JWKSKey row back into a crypto.Signer.
func (s *Service) loadPrivateKey(k models.JWKSKey) (crypto.Signer, error) {
	raw, err := authcrypto.Decrypt(s.encryptionKey, k.PrivateEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt jwks private: %w", err)
	}
	if k.Alg == jwt.AlgEdDSA || k.Alg == "" {
		if len(raw) != ed25519.SeedSize {
			return nil, errors.New("theauth: jwks key seed has wrong length")
		}
		return ed25519.NewKeyFromSeed(raw), nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse jwks private: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("theauth: jwks private key cannot sign")
	}
	return signer, nil
}

func parsePublicJWK(raw []byte) (string, crypto.PublicKey, bool) {
	var j jwk
	if err := json.Unmarshal(raw, &j); err != nil {
		return "", nil, false
	}
	dec := func(v string) ([]byte, bool) {
		b, err := base64.RawURLEncoding.DecodeString(v)
		return b, err == nil && len(b) > 0
	}
	switch j.Kty {
	case "OKP":
		x, ok := dec(j.X)
		if !ok || len(x) != ed25519.PublicKeySize {
			return "", nil, false
		}
		return jwt.AlgEdDSA, ed25519.PublicKey(x), true
	case "EC":
		x, okx := dec(j.X)
		y, oky := dec(j.Y)
		if !okx || !oky || j.Crv != "P-256" {
			return "", nil, false
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if len(x) > 32 || len(y) > 32 {
			return "", nil, false
		}
		point := make([]byte, 65)
		point[0] = 4
		pub.X.FillBytes(point[1:33])
		pub.Y.FillBytes(point[33:65])
		if _, err := ecdh.P256().NewPublicKey(point); err != nil {
			return "", nil, false
		}
		return jwt.AlgES256, pub, true
	case "RSA":
		n, okn := dec(j.N)
		e, oke := dec(j.E)
		if !okn || !oke {
			return "", nil, false
		}
		return jwt.AlgRS256, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, true
	}
	return "", nil, false
}

// bootstrapJWKS loads stored keys and mints a current and next pair for the default algorithm when
// none exist. Other algorithms are minted lazily by SigningKeyFor.
func (s *Service) bootstrapJWKS(ctx context.Context) error {
	if s == nil {
		return nil
	}
	existing, err := s.Storage.JWKSKeysAll(ctx)
	if err != nil {
		return fmt.Errorf("jwks load: %w", err)
	}
	s.refreshJWKSSnapshot(existing)
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()
	return s.ensureKeysetLocked(ctx, s.defaultSigningAlg())
}

func (s *Service) defaultSigningAlg() string {
	if s.Cfg.SigningAlg == "" {
		return jwt.AlgEdDSA
	}
	return s.Cfg.SigningAlg
}

func (s *Service) hasCurrentKey(alg string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if k.State == models.JWKSStateCurrent && k.Alg == alg {
			return true
		}
	}
	return false
}

// ensureKeysetLocked mints a current and next pair for alg when the snapshot lacks a current key.
// The caller holds rotationMu. If another instance wins the insert race, the snapshot reloads.
func (s *Service) ensureKeysetLocked(ctx context.Context, alg string) error {
	if s.hasCurrentKey(alg) {
		return nil
	}
	curr, err := s.generateKeypair(alg, models.JWKSStateCurrent)
	if err != nil {
		return err
	}
	if err := s.Storage.InsertJWKSKey(ctx, curr); err != nil {
		return s.adoptConcurrentKeyset(ctx, alg, fmt.Errorf("jwks insert current: %w", err))
	}
	next, err := s.generateKeypair(alg, models.JWKSStateNext)
	if err != nil {
		return err
	}
	if err := s.Storage.InsertJWKSKey(ctx, next); err != nil {
		return fmt.Errorf("jwks insert next: %w", err)
	}
	all, err := s.Storage.JWKSKeysAll(ctx)
	if err != nil {
		return fmt.Errorf("jwks reload: %w", err)
	}
	s.refreshJWKSSnapshot(all)
	return nil
}

func (s *Service) adoptConcurrentKeyset(ctx context.Context, alg string, cause error) error {
	all, err := s.Storage.JWKSKeysAll(ctx)
	if err != nil {
		return cause
	}
	s.refreshJWKSSnapshot(all)
	if s.hasCurrentKey(alg) {
		return nil
	}
	return cause
}

// refreshJWKSSnapshot rebuilds the in-memory key snapshot. Private halves of active keys are
// decrypted once and cached, so signing never re-runs the cipher setup. Every state transition
// routes through here, so a rotated key leaves the cache at the same moment its state changes.
func (s *Service) refreshJWKSSnapshot(keys []models.JWKSKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Order is current, next, previous, then retired. Retired keys stay briefly for verifier lookups.
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
	s.privKeyByKID = make(map[string]crypto.Signer, len(keys))
	s.pubByKID = make(map[string]verifyKey, len(keys))
	for _, k := range keys {
		s.keyMap[k.KID] = k
		if alg, pub, ok := parsePublicJWK(k.PublicJWK); ok {
			s.pubByKID[k.KID] = verifyKey{alg: alg, pub: pub}
		}
		if k.State == models.JWKSStateRetired {
			continue
		}
		priv, err := s.loadPrivateKey(k)
		if err != nil {
			// A bad row must not poison the snapshot. It is skipped, and signing surfaces the missing
			// current key as a typed error.
			slog.Warn("theauth: jwks key decrypt failed during snapshot refresh", "kid", k.KID, "err", err.Error())
			continue
		}
		s.privKeyByKID[k.KID] = priv
	}
}

type verifyKey struct {
	alg string
	pub crypto.PublicKey
}

// CurrentSigningKey returns the current key for the default algorithm, with its private half.
func (s *Service) CurrentSigningKey() (models.JWKSKey, crypto.Signer, error) {
	if s == nil {
		return models.JWKSKey{}, nil, errors.New("theauth: authorization server not configured")
	}
	return s.currentKeyForAlg(s.defaultSigningAlg())
}

// currentKeyForAlg returns the current key for alg from the snapshot, served from the per-snapshot
// private key cache.
func (s *Service) currentKeyForAlg(alg string) (models.JWKSKey, crypto.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.keys {
		if k.State == models.JWKSStateCurrent && k.Alg == alg {
			if priv, ok := s.privKeyByKID[k.KID]; ok && priv != nil {
				return k, priv, nil
			}
			// Defensive fallback for a cache miss, such as a bootstrap race: decrypt on the slow path so the
			// request still succeeds.
			fallback, err := s.loadPrivateKey(k)
			if err != nil {
				return models.JWKSKey{}, nil, err
			}
			return k, fallback, nil
		}
	}
	return models.JWKSKey{}, nil, fmt.Errorf("theauth: no current JWKS key for alg %s", alg)
}

// SigningAlgEnabled reports whether tokens may be signed with alg. The default is always enabled;
// others must be in TokenPolicy.SigningAlgs.
func (s *Service) SigningAlgEnabled(alg string) bool {
	if alg == s.defaultSigningAlg() {
		return true
	}
	if s.Cfg.TokenPolicy == nil {
		return false
	}
	for _, a := range s.Cfg.TokenPolicy.SigningAlgs {
		if a == alg {
			return true
		}
	}
	return false
}

// SigningKeyFor returns the current signing key for alg, minting the keyset on first use.
func (s *Service) SigningKeyFor(ctx context.Context, alg string) (models.JWKSKey, crypto.Signer, error) {
	if s == nil {
		return models.JWKSKey{}, nil, errors.New("theauth: authorization server not configured")
	}
	if !s.SigningAlgEnabled(alg) {
		return models.JWKSKey{}, nil, fmt.Errorf("theauth: signing alg %s is not enabled", alg)
	}
	if k, priv, err := s.currentKeyForAlg(alg); err == nil {
		return k, priv, nil
	}
	s.rotationMu.Lock()
	err := s.ensureKeysetLocked(ctx, alg)
	s.rotationMu.Unlock()
	if err != nil {
		return models.JWKSKey{}, nil, err
	}
	return s.currentKeyForAlg(alg)
}

// PublicKeyByKID returns the Ed25519 public key for kid, used at verify time. It is false for
// unknown, retired or non-Ed25519 keys.
func (s *Service) PublicKeyByKID(kid string) (ed25519.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	alg, pub, ok := s.VerificationKey(kid)
	if !ok || alg != jwt.AlgEdDSA {
		return nil, false
	}
	k, ok := pub.(ed25519.PublicKey)
	return k, ok
}

// VerificationKey resolves a kid to its algorithm and public key for a non-retired key. It
// satisfies jwt.KeyResolver.
func (s *Service) VerificationKey(kid string) (string, crypto.PublicKey, bool) {
	if s == nil {
		return "", nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keyMap[kid]
	if !ok || k.State == models.JWKSStateRetired {
		return "", nil, false
	}
	vk, ok := s.pubByKID[kid]
	if !ok {
		return "", nil, false
	}
	return vk.alg, vk.pub, true
}

// RenderJWKSDoc serializes the JWKS document. Current, next and previous keys are included; retired
// keys are omitted.
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

// jwksRotationLoop rotates the signing keys at the configured cadence. It exits when rotationStop closes.
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

// RotateSigningKey advances the key state machine one step for every algorithm with a keyset.
// rotationMu serializes in-process callers, so two goroutines cannot both produce a second current
// row. A storage implementing JWKSAtomicRotator also makes each transition one database
// transaction, which guards separate instances.
func (s *Service) RotateSigningKey(ctx context.Context) error {
	if s == nil {
		return errors.New("theauth: authorization server not configured")
	}
	// Serialise callers in this process so two cannot both see the same snapshot and produce two current rows.
	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	s.mu.Lock()
	snapshot := append([]models.JWKSKey(nil), s.keys...)
	s.mu.Unlock()
	now := time.Now().UTC()

	byAlg := map[string][]models.JWKSKey{}
	for _, k := range snapshot {
		byAlg[k.Alg] = append(byAlg[k.Alg], k)
	}
	algs := make([]string, 0, len(byAlg))
	for a := range byAlg {
		algs = append(algs, a)
	}
	sort.Strings(algs)
	if len(algs) == 0 {
		return errors.New("theauth: cannot rotate without current + next keys")
	}
	var errs []error
	for _, alg := range algs {
		if err := s.rotateAlg(ctx, byAlg[alg], now); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", alg, err))
		}
	}
	if len(errs) > 0 && len(errs) == len(algs) {
		return errors.Join(errs...)
	}
	updated, err := s.Storage.JWKSKeysAll(ctx)
	if err != nil {
		return fmt.Errorf("reload jwks: %w", err)
	}
	cutoff := now.Add(-s.Cfg.KeyRetention)
	filtered := make([]models.JWKSKey, 0, len(updated))
	for _, k := range updated {
		if k.State == models.JWKSStateRetired && k.RetiredAt != nil && k.RetiredAt.Before(cutoff) {
			continue
		}
		filtered = append(filtered, k)
	}
	s.refreshJWKSSnapshot(filtered)
	return errors.Join(errs...)
}

// rotateAlg advances one algorithm's keyset. rows are that algorithm's stored keys.
func (s *Service) rotateAlg(ctx context.Context, keys []models.JWKSKey, now time.Time) error {
	var current, next models.JWKSKey
	var retireKIDs []string
	alg := ""
	for _, k := range keys {
		alg = k.Alg
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
	fresh, err := s.generateKeypair(alg, models.JWKSStateNext)
	if err != nil {
		return err
	}
	if ar, ok := s.Storage.(JWKSAtomicRotator); ok {
		// Fast path: all state changes go in one transaction, so no concurrent rotation can interleave.
		if err := ar.AtomicRotateJWKS(ctx, retireKIDs, current.KID, next.KID, fresh, now); err != nil {
			return fmt.Errorf("atomic jwks rotate: %w", err)
		}
		return nil
	}
	// Fallback for stores without JWKSAtomicRotator (for example the in-memory store in unit tests).
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
	return nil
}
