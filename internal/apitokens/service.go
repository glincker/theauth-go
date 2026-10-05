package apitokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/revocation"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// Errors returned by the API token service.
var (
	ErrAPITokensDisabled = errors.New("theauth: API tokens are not enabled in Config")
	ErrAPITokenInvalid   = errors.New("theauth: API token is invalid, expired, revoked or its owner is inactive")
	ErrAbilityInvalid    = errors.New("theauth: invalid ability list")
	ErrAbilityNotHeld    = errors.New("theauth: requested ability exceeds what the grantor holds")
	ErrTokenTTLInvalid   = errors.New("theauth: token lifetime is out of range")
)

// Config enables scoped API tokens (and, via Device, the RFC 8628
// device grant). Every field is optional.
type Config struct {
	// Prefix is prepended to every token secret. Defaults to "tk".
	Prefix string
	// AcceptUnprefixed also accepts bearer secrets that lack the prefix,
	// looked up by the same SHA-256 hash. For migrating legacy random tokens.
	AcceptUnprefixed bool
	// Abilities restricts caller-defined ability names. Empty accepts any
	// well-formed name. AbilityRoot is always allowed and always exclusive.
	Abilities []string
	// DefaultTTL applies when a mint asks for no lifetime. Defaults to 90 days.
	DefaultTTL time.Duration
	// MaxTTL caps any token lifetime. Defaults to 365 days.
	MaxTTL time.Duration
	// AgentTTL applies when an agent token is minted with no lifetime.
	// Defaults to one hour.
	AgentTTL time.Duration
	// AgentMaxTTL caps agent token lifetimes. Defaults to 24 hours.
	AgentMaxTTL time.Duration
	// UserAbilities returns the abilities a user currently holds. Default:
	// [AbilityRoot] for an admin (see IsAdmin), nothing otherwise. Evaluated
	// on every request, so a demotion takes effect immediately.
	UserAbilities func(ctx context.Context, u *User) ([]string, error)
	// IsAdmin reports whether the user may manage other owners' tokens.
	// Default: holds the system super_admin RBAC role, false without RBAC storage.
	IsAdmin func(ctx context.Context, u *User) (bool, error)
	// OwnerActive reports whether an owner (user or service account) may
	// still use tokens. Use it to model disabled accounts. A user whose row
	// is gone is always inactive. Default: active.
	OwnerActive func(ctx context.Context, ownerID ULID) (bool, error)
	// DeviceRequestsAbility is the ability a signed-in session must hold to
	// list and decide pending device requests by ID. Empty means root.
	DeviceRequestsAbility string
	// DeviceRequestsAnySignedInUser lets any signed-in user list and decide
	// pending requests by ID. Off by default: approving from a list skips the
	// proof of holding the code shown on the device, which aids phishing in a
	// multi-user app.
	DeviceRequestsAnySignedInUser bool
	// Device enables /auth/device/*. Nil leaves the device grant off.
	Device *DeviceConfig
}

var abilityNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9:_.\-]{0,63}$`)

// UserLookup is the user capability the service needs.
type UserLookup interface {
	UserByID(ctx context.Context, id ULID) (*User, error)
}

// RoleLister is the optional RBAC capability behind the default admin check.
type RoleLister interface {
	RolesForUser(ctx context.Context, userID ULID, orgID *ULID) ([]models.Role, error)
}

// Service is the API token service.
type Service struct {
	host  Host
	cfg   Config
	store APITokenStorage
	dev   DeviceCodeStorage
	rbac  RoleLister
	users UserLookup
	now   func() time.Time
	fails *attemptLimiter
}

// New builds the service from cfg and the raw storage, which must implement
// APITokenStorage (and DeviceCodeStorage when cfg.Device is set). It returns
// nil, nil for a nil cfg.
func New(host Host, cfg *Config, raw any, users UserLookup, baseURL string) (*Service, error) {
	if cfg == nil {
		return nil, nil
	}
	ts, ok := raw.(APITokenStorage)
	if !ok {
		return nil, fmt.Errorf("%w: Config.APITokens requires APITokenStorage", models.ErrStorageMissingCapability)
	}
	c := *cfg
	if c.Prefix == "" {
		c.Prefix = "tk"
	}
	if c.DefaultTTL <= 0 {
		c.DefaultTTL = 90 * 24 * time.Hour
	}
	if c.MaxTTL <= 0 {
		c.MaxTTL = 365 * 24 * time.Hour
	}
	if c.AgentTTL <= 0 {
		c.AgentTTL = time.Hour
	}
	if c.AgentMaxTTL <= 0 {
		c.AgentMaxTTL = 24 * time.Hour
	}
	for _, name := range c.Abilities {
		if name == AbilityRoot || !abilityNameRE.MatchString(name) {
			return nil, fmt.Errorf("%w: Config.APITokens.Abilities entry %q", ErrAbilityInvalid, name)
		}
	}
	s := &Service{host: host, cfg: c, store: ts, users: users, now: time.Now, fails: newAttemptLimiter(5, 15*time.Minute)}
	s.rbac, _ = raw.(RoleLister)
	if c.Device != nil {
		ds, ok := raw.(DeviceCodeStorage)
		if !ok {
			return nil, fmt.Errorf("%w: Config.APITokens.Device requires DeviceCodeStorage", models.ErrStorageMissingCapability)
		}
		s.dev = ds
		dc := c.Device.withDefaults(baseURL)
		s.cfg.Device = &dc
		if err := s.validateAbilities(dc.DefaultAbilities, true); err != nil {
			return nil, fmt.Errorf("Config.APITokens.Device.DefaultAbilities: %w", err)
		}
	}
	return s, nil
}

func hashToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func holdsAbility(held []string, need string) bool {
	return slices.Contains(held, AbilityRoot) || slices.Contains(held, need)
}

// clampAbilities keeps the requested abilities the holder actually has. A
// requested root survives only when the holder literally holds root.
func clampAbilities(requested, held []string) []string {
	out := make([]string, 0, len(requested))
	for _, r := range requested {
		if r == AbilityRoot {
			if slices.Contains(held, AbilityRoot) {
				out = append(out, r)
			}
			continue
		}
		if holdsAbility(held, r) {
			out = append(out, r)
		}
	}
	return out
}

func (s *Service) validateAbilities(abilities []string, allowEmpty bool) error {
	if len(abilities) == 0 {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%w: at least one ability is required", ErrAbilityInvalid)
	}
	if slices.Contains(abilities, AbilityRoot) && len(abilities) > 1 {
		return fmt.Errorf("%w: root cannot be combined with other abilities", ErrAbilityInvalid)
	}
	seen := map[string]struct{}{}
	for _, name := range abilities {
		if _, dup := seen[name]; dup {
			return fmt.Errorf("%w: duplicate ability %q", ErrAbilityInvalid, name)
		}
		seen[name] = struct{}{}
		if name == AbilityRoot {
			continue
		}
		if !abilityNameRE.MatchString(name) {
			return fmt.Errorf("%w: malformed ability %q", ErrAbilityInvalid, name)
		}
		if len(s.cfg.Abilities) > 0 && !slices.Contains(s.cfg.Abilities, name) {
			return fmt.Errorf("%w: unknown ability %q", ErrAbilityInvalid, name)
		}
	}
	return nil
}

func (s *Service) IsAdmin(ctx context.Context, u *User) (bool, error) {
	if s.cfg.IsAdmin != nil {
		return s.cfg.IsAdmin(ctx, u)
	}
	if s.rbac == nil {
		return false, nil
	}
	roles, err := s.rbac.RolesForUser(ctx, u.ID, nil)
	if err != nil {
		return false, fmt.Errorf("theauth: load roles for admin check: %w", err)
	}
	for _, r := range roles {
		if r.Name == models.SystemRoleSuperAdmin {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) UserAbilities(ctx context.Context, u *User) ([]string, error) {
	if s.cfg.UserAbilities != nil {
		return s.cfg.UserAbilities(ctx, u)
	}
	admin, err := s.IsAdmin(ctx, u)
	if err != nil || !admin {
		return nil, err
	}
	return []string{AbilityRoot}, nil
}

func (s *Service) ownerActive(ctx context.Context, kind string, ownerID ULID) (*User, bool, error) {
	var user *User
	if kind == OwnerKindUser {
		u, err := s.users.UserByID(ctx, ownerID)
		if errors.Is(err, models.ErrStorageNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("theauth: load token owner: %w", err)
		}
		user = u
	}
	if s.cfg.OwnerActive != nil {
		ok, err := s.cfg.OwnerActive(ctx, ownerID)
		if err != nil {
			return nil, false, fmt.Errorf("theauth: owner active check: %w", err)
		}
		if !ok {
			return nil, false, nil
		}
	}
	return user, true, nil
}

// MintAPITokenInput describes a token to mint. It is trusted input: the HTTP
// and device paths cap Abilities to the grantor before calling it.
type MintAPITokenInput struct {
	OwnerID   ULID
	OwnerKind string
	Name      string
	Abilities []string
	// TTL is the lifetime. Zero uses Config.APITokens.DefaultTTL.
	TTL time.Duration
	// Kind is APITokenKindPersonal (default) or APITokenKindAgent.
	Kind string
	// AgentName is required for agent tokens.
	AgentName string
	// DelegatedBy is the human an agent token acts for. It must equal
	// OwnerID, which defaults it when nil.
	DelegatedBy *ULID
}

func (s *Service) Mint(ctx context.Context, in MintAPITokenInput) (string, APIToken, error) {
	if in.OwnerKind != OwnerKindUser && in.OwnerKind != OwnerKindServiceAccount {
		return "", APIToken{}, fmt.Errorf("theauth: unknown owner kind %q", in.OwnerKind)
	}
	if err := s.validateAbilities(in.Abilities, false); err != nil {
		return "", APIToken{}, err
	}
	kind := in.Kind
	if kind == "" {
		kind = APITokenKindPersonal
	}
	maxTTL, defTTL := s.cfg.MaxTTL, s.cfg.DefaultTTL
	var delegatedBy *ULID
	agentName := ""
	switch kind {
	case APITokenKindPersonal:
		if in.AgentName != "" || in.DelegatedBy != nil {
			return "", APIToken{}, errors.New("theauth: agent_name and delegated_by apply only to agent tokens")
		}
	case APITokenKindAgent:
		if in.OwnerKind != OwnerKindUser {
			return "", APIToken{}, errors.New("theauth: agent tokens must be owned by a user")
		}
		agentName = strings.TrimSpace(in.AgentName)
		if agentName == "" || len(agentName) > 120 {
			return "", APIToken{}, errors.New("theauth: agent name must be 1 to 120 characters")
		}
		if in.DelegatedBy != nil && *in.DelegatedBy != in.OwnerID {
			return "", APIToken{}, errors.New("theauth: agent token delegated_by must be its owner")
		}
		owner := in.OwnerID
		delegatedBy = &owner
		maxTTL, defTTL = s.cfg.AgentMaxTTL, s.cfg.AgentTTL
	default:
		return "", APIToken{}, fmt.Errorf("theauth: unknown token kind %q", kind)
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = defTTL
	}
	if ttl < 0 || ttl > maxTTL {
		return "", APIToken{}, ErrTokenTTLInvalid
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 120 {
		return "", APIToken{}, errors.New("theauth: token name must be 1 to 120 characters")
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", APIToken{}, fmt.Errorf("theauth: generate token: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	raw := s.cfg.Prefix + "_" + secret
	now := s.now().UTC()
	exp := now.Add(ttl)
	t := APIToken{
		ID: ulid.New(), OwnerID: in.OwnerID, OwnerKind: in.OwnerKind, Name: name,
		Abilities: slices.Clone(in.Abilities), TokenHash: hashToken(raw),
		Hint: s.cfg.Prefix + "_..." + secret[len(secret)-4:], CreatedAt: now, ExpiresAt: &exp,
		Kind: kind, AgentName: agentName, DelegatedBy: delegatedBy,
	}
	saved, err := s.store.InsertAPIToken(ctx, t)
	if err != nil {
		return "", APIToken{}, fmt.Errorf("theauth: store API token: %w", err)
	}
	return raw, saved, nil
}

// ImportedToken is an existing token record to insert by hash. The secret is never supplied.
type ImportedToken struct {
	// ID is optional; a new one is generated when zero.
	ID         ULID
	OwnerID    ULID
	OwnerKind  string
	Name       string
	Abilities  []string
	TokenHash  []byte
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
}

// Import inserts an existing token by its SHA-256 hash. The hash must
// cover the full raw secret as presented by clients; tokens lacking the
// configured prefix authenticate only when Config.AcceptUnprefixed is set.
func (s *Service) Import(ctx context.Context, in ImportedToken) (APIToken, error) {
	return importAPIToken(ctx, s.store, s, in, s.now())
}

func importAPIToken(ctx context.Context, store APITokenStorage, v *Service, in ImportedToken, now time.Time) (APIToken, error) {
	if in.OwnerKind == "" {
		in.OwnerKind = OwnerKindUser
	}
	if in.OwnerKind != OwnerKindUser && in.OwnerKind != OwnerKindServiceAccount {
		return APIToken{}, fmt.Errorf("theauth: unknown owner kind %q", in.OwnerKind)
	}
	if len(in.TokenHash) != sha256.Size {
		return APIToken{}, errors.New("theauth: imported token hash must be a 32 byte SHA-256 digest")
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 120 {
		return APIToken{}, errors.New("theauth: token name must be 1 to 120 characters")
	}
	if err := v.validateAbilities(in.Abilities, false); err != nil {
		return APIToken{}, err
	}
	if _, err := store.APITokenByHash(ctx, in.TokenHash); err == nil {
		return APIToken{}, fmt.Errorf("theauth: import API token: %w", models.ErrImportDuplicate)
	} else if !errors.Is(err, models.ErrStorageNotFound) {
		return APIToken{}, fmt.Errorf("theauth: import API token: look up hash: %w", err)
	}
	id := in.ID
	if id == (ULID{}) {
		id = ulid.New()
	}
	created := in.CreatedAt
	if created.IsZero() {
		created = now
	}
	t := APIToken{
		ID: id, OwnerID: in.OwnerID, OwnerKind: in.OwnerKind, Name: name,
		Abilities: slices.Clone(in.Abilities), TokenHash: slices.Clone(in.TokenHash),
		Hint: "imported", CreatedAt: created.UTC(), ExpiresAt: in.ExpiresAt, LastUsedAt: in.LastUsedAt,
		Kind: APITokenKindPersonal,
	}
	saved, err := store.InsertAPIToken(ctx, t)
	if err != nil {
		return APIToken{}, fmt.Errorf("theauth: import API token: %w", err)
	}
	return saved, nil
}

// ImportTo inserts an existing token by hash straight into store, with no TheAuth instance.
//
// Abilities are checked for syntax only, since there is no configured allowlist.
func ImportTo(ctx context.Context, store APITokenStorage, in ImportedToken) (APIToken, error) {
	if store == nil {
		return APIToken{}, errors.New("theauth: nil storage")
	}
	return importAPIToken(ctx, store, &Service{}, in, time.Now())
}

// touchInterval bounds last_used_at writes to one per token per interval.
const touchInterval = time.Minute

func (s *Service) Authenticate(ctx context.Context, raw string) (*Principal, error) {
	if raw == "" || (!s.cfg.AcceptUnprefixed && !strings.HasPrefix(raw, s.cfg.Prefix+"_")) {
		return nil, ErrAPITokenInvalid
	}
	tok, err := s.store.APITokenByHash(ctx, hashToken(raw))
	if errors.Is(err, models.ErrStorageNotFound) {
		return nil, ErrAPITokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("theauth: look up API token: %w", err)
	}
	now := s.now()
	if !tok.Usable(now) {
		return nil, ErrAPITokenInvalid
	}
	user, active, err := s.ownerActive(ctx, tok.OwnerKind, tok.OwnerID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrAPITokenInvalid
	}
	abilities := tok.Abilities
	if user != nil {
		held, err := s.UserAbilities(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("theauth: resolve owner abilities: %w", err)
		}
		abilities = clampAbilities(tok.Abilities, held)
	}
	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= touchInterval {
		_ = s.store.TouchAPITokenLastUsed(ctx, tok.ID, now.UTC())
	}
	id := tok.ID
	return &Principal{
		Kind: PrincipalToken, UserID: tok.OwnerID, OwnerKind: tok.OwnerKind, TokenID: &id, Abilities: abilities, user: user,
		TokenKind: tok.Kind, AgentName: tok.AgentName, DelegatedBy: tok.DelegatedBy,
	}, nil
}

// List returns the owner's tokens, newest first.
func (s *Service) List(ctx context.Context, ownerID ULID) ([]APIToken, error) {
	return s.store.APITokensByOwner(ctx, ownerID)
}

// ListAll returns every token. Intended for admin tooling.
func (s *Service) ListAll(ctx context.Context) ([]APIToken, error) {
	return s.store.ListAPITokens(ctx)
}

// Revoke revokes one token by ID without an ownership check.
func (s *Service) Revoke(ctx context.Context, id ULID) error {
	if err := s.store.RevokeAPIToken(ctx, id, s.now().UTC()); err != nil {
		return err
	}
	ev := revocation.Event{Kind: revocation.APIToken, ID: id.String(), Reason: "revoked"}
	if tok, err := s.store.APITokenByID(ctx, id); err == nil {
		ev.UserID = tok.OwnerID.String()
	}
	s.host.PublishRevocation(ctx, ev)
	return nil
}

// RevokeOwner revokes every live token of an owner. Call it when a
// user is deleted or a service account is retired.
func (s *Service) RevokeOwner(ctx context.Context, ownerID ULID) (int, error) {
	n, err := s.store.RevokeAPITokensByOwner(ctx, ownerID, s.now().UTC())
	if err != nil {
		return n, err
	}
	s.host.PublishRevocation(ctx, revocation.Event{Kind: revocation.APIToken, UserID: ownerID.String(), Reason: "owner tokens revoked"})
	return n, nil
}

// SetClock replaces the clock the service reads.
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// DeviceEnabled reports whether the device grant is configured.
func (s *Service) DeviceEnabled() bool { return s.dev != nil }
