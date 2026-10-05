package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrNotLoggedIn means the store holds no credential for the server.
var ErrNotLoggedIn = errors.New("clientauth: not logged in")

// Credential is one stored login.
type Credential struct {
	ServerURL   string    `json:"server_url"`
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type,omitempty"`
	Scope       string    `json:"scope,omitempty"`
	IssuedAt    time.Time `json:"issued_at"`
	// ExpiresAt is zero when the server reported no lifetime.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Expired reports whether the credential is past its expiry at now.
func (c Credential) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

// TokenStore persists credentials keyed by server URL. Implementations must be safe for concurrent use.
type TokenStore interface {
	// Load returns ErrNotLoggedIn when no credential exists for serverURL.
	Load(ctx context.Context, serverURL string) (Credential, error)
	Save(ctx context.Context, cred Credential) error
	Delete(ctx context.Context, serverURL string) error
}

// NormalizeServerURL canonicalizes a server URL so store keys compare equal.
func NormalizeServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("clientauth: invalid server URL %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// FileStore keeps credentials for many servers in one 0600 JSON file.
type FileStore struct {
	path string
	// LockTimeout bounds the wait for the cross-process lock file. Default 5s.
	LockTimeout time.Duration
	// LockStale is the age after which a lock file is treated as abandoned. Default 30s.
	LockStale time.Duration
}

var pathLocks sync.Map

// NewFileStore stores credentials in os.UserConfigDir()/<app>/credentials.json.
func NewFileStore(app string) (*FileStore, error) {
	if app == "" || strings.ContainsAny(app, `/\`) {
		return nil, fmt.Errorf("clientauth: invalid app name %q", app)
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("clientauth: locate config dir: %w", err)
	}
	return NewFileStoreAt(filepath.Join(dir, app, "credentials.json")), nil
}

// NewFileStoreAt stores credentials at an explicit path.
func NewFileStoreAt(path string) *FileStore {
	return &FileStore{path: path, LockTimeout: 5 * time.Second, LockStale: 30 * time.Second}
}

// Path returns the credentials file path.
func (s *FileStore) Path() string { return s.path }

type fileDoc struct {
	Servers map[string]Credential `json:"servers"`
}

func (s *FileStore) read() (fileDoc, error) {
	doc := fileDoc{Servers: map[string]Credential{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return doc, fmt.Errorf("clientauth: read %s: %w", s.path, err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return doc, fmt.Errorf("clientauth: parse %s: %w", s.path, err)
	}
	if doc.Servers == nil {
		doc.Servers = map[string]Credential{}
	}
	return doc, nil
}

func (s *FileStore) write(doc fileDoc) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("clientauth: create %s: %w", dir, err)
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("clientauth: encode credentials: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*")
	if err != nil {
		return fmt.Errorf("clientauth: create temp file: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("clientauth: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("clientauth: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("clientauth: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("clientauth: close temp file: %w", err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("clientauth: replace %s: %w", s.path, err)
	}
	return nil
}

// lock serializes read-modify-write across goroutines and processes.
func (s *FileStore) lock(ctx context.Context) (func(), error) {
	mu, _ := pathLocks.LoadOrStore(s.path, &sync.Mutex{})
	m := mu.(*sync.Mutex)
	m.Lock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		m.Unlock()
		return nil, fmt.Errorf("clientauth: create config dir: %w", err)
	}
	lockPath := s.path + ".lock"
	deadline := time.Now().Add(s.LockTimeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(lockPath); m.Unlock() }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			m.Unlock()
			return nil, fmt.Errorf("clientauth: acquire lock: %w", err)
		}
		if fi, serr := os.Stat(lockPath); serr == nil && time.Since(fi.ModTime()) > s.LockStale {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			m.Unlock()
			return nil, errors.New("clientauth: timed out waiting for credentials lock")
		}
		if err := sleepCtx(ctx, 5*time.Millisecond); err != nil {
			m.Unlock()
			return nil, fmt.Errorf("clientauth: waiting for credentials lock: %w", err)
		}
	}
}

// Load implements TokenStore.
func (s *FileStore) Load(_ context.Context, serverURL string) (Credential, error) {
	key, err := NormalizeServerURL(serverURL)
	if err != nil {
		return Credential{}, err
	}
	doc, err := s.read()
	if err != nil {
		return Credential{}, err
	}
	c, ok := doc.Servers[key]
	if !ok {
		return Credential{}, ErrNotLoggedIn
	}
	return c, nil
}

// Save implements TokenStore.
func (s *FileStore) Save(ctx context.Context, cred Credential) error {
	key, err := NormalizeServerURL(cred.ServerURL)
	if err != nil {
		return err
	}
	cred.ServerURL = key
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	doc, err := s.read()
	if err != nil {
		return err
	}
	doc.Servers[key] = cred
	return s.write(doc)
}

// Delete implements TokenStore and is a no-op for an unknown server.
func (s *FileStore) Delete(ctx context.Context, serverURL string) error {
	key, err := NormalizeServerURL(serverURL)
	if err != nil {
		return err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	doc, err := s.read()
	if err != nil {
		return err
	}
	if _, ok := doc.Servers[key]; !ok {
		return nil
	}
	delete(doc.Servers, key)
	return s.write(doc)
}

// KeychainBackend is the minimal OS keychain surface. The functions of
// github.com/zalando/go-keyring (Get, Set, Delete) fit it directly, which
// keeps cgo and platform dependencies out of this package.
type KeychainBackend interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

// ErrKeychainNotFound is what a KeychainBackend returns for a missing item.
var ErrKeychainNotFound = errors.New("clientauth: keychain item not found")

// KeychainStore keeps each credential as one keychain item.
type KeychainStore struct {
	service string
	backend KeychainBackend
}

// NewKeychainStore wraps backend, using service as the keychain service name.
func NewKeychainStore(service string, backend KeychainBackend) *KeychainStore {
	return &KeychainStore{service: service, backend: backend}
}

// Load implements TokenStore.
func (s *KeychainStore) Load(_ context.Context, serverURL string) (Credential, error) {
	key, err := NormalizeServerURL(serverURL)
	if err != nil {
		return Credential{}, err
	}
	raw, err := s.backend.Get(s.service, key)
	if errors.Is(err, ErrKeychainNotFound) {
		return Credential{}, ErrNotLoggedIn
	}
	if err != nil {
		return Credential{}, fmt.Errorf("clientauth: read keychain: %w", err)
	}
	var c Credential
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return Credential{}, fmt.Errorf("clientauth: parse keychain item: %w", err)
	}
	return c, nil
}

// Save implements TokenStore.
func (s *KeychainStore) Save(_ context.Context, cred Credential) error {
	key, err := NormalizeServerURL(cred.ServerURL)
	if err != nil {
		return err
	}
	cred.ServerURL = key
	b, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("clientauth: encode credential: %w", err)
	}
	if err := s.backend.Set(s.service, key, string(b)); err != nil {
		return fmt.Errorf("clientauth: write keychain: %w", err)
	}
	return nil
}

// Delete implements TokenStore and is a no-op for an unknown server.
func (s *KeychainStore) Delete(_ context.Context, serverURL string) error {
	key, err := NormalizeServerURL(serverURL)
	if err != nil {
		return err
	}
	if err := s.backend.Delete(s.service, key); err != nil && !errors.Is(err, ErrKeychainNotFound) {
		return fmt.Errorf("clientauth: delete keychain item: %w", err)
	}
	return nil
}
