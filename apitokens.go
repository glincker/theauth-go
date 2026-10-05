package theauth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/internal/agent"
	"github.com/glincker/theauth-go/v2/internal/apitokens"
	"github.com/glincker/theauth-go/v2/internal/httpx"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/revocation"
)

// Ability, owner, token kind and device status constants.
const (
	AbilityRoot             = apitokens.AbilityRoot
	OwnerKindUser           = apitokens.OwnerKindUser
	OwnerKindServiceAccount = apitokens.OwnerKindServiceAccount
	APITokenKindPersonal    = apitokens.APITokenKindPersonal
	APITokenKindAgent       = apitokens.APITokenKindAgent
	DeviceStatusPending     = apitokens.DeviceStatusPending
	DeviceStatusApproved    = apitokens.DeviceStatusApproved
	DeviceStatusDenied      = apitokens.DeviceStatusDenied
	DeviceStatusRedeemed    = apitokens.DeviceStatusRedeemed
)

// Principal kinds and actor kinds.
const (
	PrincipalSession = apitokens.PrincipalSession
	PrincipalToken   = apitokens.PrincipalToken
	ActorKindUser    = apitokens.ActorKindUser
	ActorKindAgent   = apitokens.ActorKindAgent
)

// Token, device and principal types.
type (
	APIToken             = apitokens.APIToken
	DeviceCode           = apitokens.DeviceCode
	DeviceDecision       = apitokens.DeviceDecision
	APITokenStorage      = apitokens.APITokenStorage
	DeviceCodeStorage    = apitokens.DeviceCodeStorage
	DevicePendingFilter  = apitokens.DevicePendingFilter
	DeviceCodeLister     = apitokens.DeviceCodeLister
	APITokensConfig      = apitokens.Config
	DeviceConfig         = apitokens.DeviceConfig
	MintAPITokenInput    = apitokens.MintAPITokenInput
	ImportedToken        = apitokens.ImportedToken
	DeviceAuthStart      = apitokens.DeviceAuthStart
	StartDeviceAuthInput = apitokens.StartDeviceAuthInput
	DeviceRequestInfo    = apitokens.DeviceRequestInfo
	DeviceToken          = apitokens.DeviceToken
	DeviceRequestSummary = apitokens.DeviceRequestSummary
	PrincipalKind        = apitokens.PrincipalKind
	Principal            = apitokens.Principal
	Actor                = apitokens.Actor
	MintAgentTokenInput  = apitokens.MintAgentTokenInput
	RegisterAgentInput   = agent.RegisterInput
	AgentRegistration    = agent.Registration
)

// Errors returned by the API token service and the device grant.
var (
	ErrAPITokensDisabled          = apitokens.ErrAPITokensDisabled
	ErrAPITokenInvalid            = apitokens.ErrAPITokenInvalid
	ErrAbilityInvalid             = apitokens.ErrAbilityInvalid
	ErrAbilityNotHeld             = apitokens.ErrAbilityNotHeld
	ErrTokenTTLInvalid            = apitokens.ErrTokenTTLInvalid
	ErrDeviceUserCodeTaken        = apitokens.ErrDeviceUserCodeTaken
	ErrDeviceDisabled             = apitokens.ErrDeviceDisabled
	ErrDeviceAuthorizationPending = apitokens.ErrDeviceAuthorizationPending
	ErrDeviceSlowDown             = apitokens.ErrDeviceSlowDown
	ErrDeviceExpired              = apitokens.ErrDeviceExpired
	ErrDeviceDenied               = apitokens.ErrDeviceDenied
	ErrDeviceInvalid              = apitokens.ErrDeviceInvalid
	ErrDeviceAttemptsExceeded     = apitokens.ErrDeviceAttemptsExceeded
	ErrDeviceListUnsupported      = apitokens.ErrDeviceListUnsupported
	ErrAgentIdentityDisabled      = agent.ErrIdentityDisabled
)

// FormatUserCode renders a user code as XXXX-XXXX for display.
func FormatUserCode(code string) string { return apitokens.FormatUserCode(code) }

// PrincipalFromContext returns the Principal attached by RequireAbility.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	return apitokens.PrincipalFromContext(ctx)
}

// ImportAPITokenTo inserts an existing token by hash straight into store, with no TheAuth instance.
//
// Abilities are checked for syntax only, since there is no configured allowlist.
func ImportAPITokenTo(ctx context.Context, store APITokenStorage, in ImportedToken) (APIToken, error) {
	return apitokens.ImportTo(ctx, store, in)
}

type tokenHost struct{ a *TheAuth }

func (h tokenHost) CookieName() string { return h.a.cookieName }
func (h tokenHost) PathPrefix() string { return h.a.pathPrefix }
func (h tokenHost) ValidateSession(ctx context.Context, token string) (*Session, *User, error) {
	return h.a.validateSession(ctx, token)
}
func (h tokenHost) PublishRevocation(ctx context.Context, ev revocation.Event) {
	h.a.publishRevocation(ctx, ev)
}
func (h tokenHost) RecordTokenMinted(ctx context.Context, userID ULID, kind string) {
	h.a.RecordTokenMinted(ctx, userID, kind)
}
func (h tokenHost) RecordTokenRevoked(ctx context.Context, userID ULID, kind string) {
	h.a.RecordTokenRevoked(ctx, userID, kind)
}
func (h tokenHost) EmitAudit(ctx context.Context, action string, target models.TargetRef, md map[string]any) {
	h.a.EmitAudit(ctx, action, target, md)
}
func (h tokenHost) ClientIP(r *http.Request) string {
	return extractClientIPTrusting(r, h.a.trustedProxies)
}
func (h tokenHost) RequireAuth() func(http.Handler) http.Handler { return h.a.RequireAuth() }
func (h tokenHost) RateLimitByIP(n int) func(http.Handler) http.Handler {
	return h.a.RateLimitByIP(n)
}
func (h tokenHost) UserFromContext(ctx context.Context) (*User, bool) { return UserFromContext(ctx) }
func (h tokenHost) WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

func (a *TheAuth) apiSvc() (*apitokens.Service, error) {
	if a.apiTokens == nil {
		return nil, ErrAPITokensDisabled
	}
	return a.apiTokens, nil
}

// MintAPIToken creates a token and returns the secret, which is never retrievable again.
func (a *TheAuth) MintAPIToken(ctx context.Context, in MintAPITokenInput) (string, APIToken, error) {
	s, err := a.apiSvc()
	if err != nil {
		return "", APIToken{}, err
	}
	return s.Mint(ctx, in)
}

// ImportAPIToken inserts an existing token by its SHA-256 hash. The hash must
// cover the full raw secret as presented by clients; tokens lacking the
// configured prefix authenticate only when Config.APITokens.AcceptUnprefixed is set.
func (a *TheAuth) ImportAPIToken(ctx context.Context, in ImportedToken) (APIToken, error) {
	s, err := a.apiSvc()
	if err != nil {
		return APIToken{}, err
	}
	return s.Import(ctx, in)
}

// AuthenticateAPIToken resolves a raw bearer secret to a Principal, re-checking
// expiry, revocation, owner status and the owner's current abilities.
func (a *TheAuth) AuthenticateAPIToken(ctx context.Context, raw string) (*Principal, error) {
	s, err := a.apiSvc()
	if err != nil {
		return nil, err
	}
	return s.Authenticate(ctx, raw)
}

// ListAPITokens returns the owner's tokens, newest first.
func (a *TheAuth) ListAPITokens(ctx context.Context, ownerID ULID) ([]APIToken, error) {
	s, err := a.apiSvc()
	if err != nil {
		return nil, err
	}
	return s.List(ctx, ownerID)
}

// ListAllAPITokens returns every token. Intended for admin tooling.
func (a *TheAuth) ListAllAPITokens(ctx context.Context) ([]APIToken, error) {
	s, err := a.apiSvc()
	if err != nil {
		return nil, err
	}
	return s.ListAll(ctx)
}

// RevokeAPIToken revokes one token by ID without an ownership check.
func (a *TheAuth) RevokeAPIToken(ctx context.Context, id ULID) error {
	s, err := a.apiSvc()
	if err != nil {
		return err
	}
	return s.Revoke(ctx, id)
}

// RevokeOwnerAPITokens revokes every live token of an owner. Call it when a
// user is deleted or a service account is retired.
func (a *TheAuth) RevokeOwnerAPITokens(ctx context.Context, ownerID ULID) (int, error) {
	s, err := a.apiSvc()
	if err != nil {
		return 0, err
	}
	return s.RevokeOwner(ctx, ownerID)
}

// RequireAbility accepts either a full session or an API bearer token and
// rejects callers that do not currently hold ability. A presented bearer
// token never falls back to the cookie. Needs Config.APITokens.
func (a *TheAuth) RequireAbility(ability string) func(http.Handler) http.Handler {
	s, err := a.apiSvc()
	if err != nil {
		return func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				httpx.WriteProblemJSON(w, http.StatusInternalServerError, "apitokens.disabled", "API tokens are not enabled in Config", "")
			})
		}
	}
	return s.RequireAbility(ability)
}

// AuthenticatePrincipal resolves the request's session or API bearer token
// into a Principal with its current abilities, writing the 401 or 500
// response itself when it cannot. The returned request carries the Principal
// and user in its context. Needs Config.APITokens.
func (a *TheAuth) AuthenticatePrincipal(w http.ResponseWriter, r *http.Request) (*http.Request, *Principal, bool) {
	s, err := a.apiSvc()
	if err != nil {
		httpx.WriteProblemJSON(w, http.StatusInternalServerError, "apitokens.disabled", "API tokens are not enabled in Config", "")
		return r, nil, false
	}
	return s.AuthenticatePrincipal(w, r)
}

func (a *TheAuth) deviceSvc() (*apitokens.Service, error) {
	if a.apiTokens == nil || !a.apiTokens.DeviceEnabled() {
		return nil, ErrDeviceDisabled
	}
	return a.apiTokens, nil
}

// StartDeviceAuth opens a device authorization request.
func (a *TheAuth) StartDeviceAuth(ctx context.Context, in StartDeviceAuthInput) (DeviceAuthStart, error) {
	s, err := a.deviceSvc()
	if err != nil {
		return DeviceAuthStart{}, err
	}
	return s.StartDeviceAuth(ctx, in)
}

// LookupDeviceRequest returns the pending request behind a user code so the
// approver can review it. Failed lookups count against a per-approver budget
// (ErrDeviceAttemptsExceeded once spent).
func (a *TheAuth) LookupDeviceRequest(ctx context.Context, approver *User, ip, userCode string) (*DeviceRequestInfo, error) {
	s, err := a.deviceSvc()
	if err != nil {
		return nil, err
	}
	return s.LookupDeviceRequest(ctx, approver, ip, userCode)
}

// DecideDeviceRequest approves or denies a pending request as approver. On
// approval the abilities are the requested set (or the narrower subset in
// abilities) capped to what the approver holds now. Root is granted only when
// requested and the approver holds root; it is never downgraded silently.
func (a *TheAuth) DecideDeviceRequest(ctx context.Context, approver *User, ip, userCode string, approve bool, abilities []string) error {
	s, err := a.deviceSvc()
	if err != nil {
		return err
	}
	return s.DecideDeviceRequest(ctx, approver, ip, userCode, approve, abilities)
}

// RedeemDeviceCode exchanges an approved device code for a token. The
// approved to redeemed transition is one atomic claim, so concurrent polls
// mint at most one token. Polling faster than the interval returns
// ErrDeviceSlowDown and widens the interval.
func (a *TheAuth) RedeemDeviceCode(ctx context.Context, deviceCode string) (DeviceToken, error) {
	s, err := a.deviceSvc()
	if err != nil {
		return DeviceToken{}, err
	}
	return s.RedeemDeviceCode(ctx, deviceCode)
}

// PurgeExpiredDeviceCodes deletes requests that expired before the cutoff.
func (a *TheAuth) PurgeExpiredDeviceCodes(ctx context.Context, before time.Time) (int, error) {
	s, err := a.deviceSvc()
	if err != nil {
		return 0, err
	}
	return s.PurgeExpiredDeviceCodes(ctx, before)
}

// ListDeviceRequests returns the pending, unexpired device requests, newest
// first, without any device or user code.
func (a *TheAuth) ListDeviceRequests(ctx context.Context) ([]DeviceRequestSummary, error) {
	s, err := a.deviceSvc()
	if err != nil {
		return nil, err
	}
	return s.ListDeviceRequests(ctx)
}

// DecideDeviceRequestByID approves or denies a pending request by its ID with
// the same rules as DecideDeviceRequest. An unknown, expired or already
// decided ID returns ErrDeviceInvalid or ErrDeviceExpired.
func (a *TheAuth) DecideDeviceRequestByID(ctx context.Context, approver *User, id ULID, approve bool, abilities []string) error {
	s, err := a.deviceSvc()
	if err != nil {
		return err
	}
	return s.DecideDeviceRequestByID(ctx, approver, id, approve, abilities)
}

// MintAgentToken mints an API token with kind=agent acting for UserID. It
// returns ErrAbilityNotHeld when Abilities exceeds what the user holds now.
// Needs Config.APITokens.
func (a *TheAuth) MintAgentToken(ctx context.Context, in MintAgentTokenInput) (string, APIToken, error) {
	s, err := a.apiSvc()
	if err != nil {
		return "", APIToken{}, err
	}
	return s.MintAgentToken(ctx, in)
}

// DelegatedAbilities returns the intersection of an agent's allowed scopes
// and what the user holds right now, for resource servers that authenticate
// agents by another path (for example an OAuth access token) and want the same
// per-request cut as agent API tokens. Needs Config.APITokens.
func (a *TheAuth) DelegatedAbilities(ctx context.Context, userID ULID, agentScopes []string) ([]string, error) {
	s, err := a.apiSvc()
	if err != nil {
		return nil, err
	}
	return s.DelegatedAbilities(ctx, userID, agentScopes)
}

// RegisterAgent creates an agent owned by a user and, when Resource is set,
// the delegation grant that lets it exchange tokens for that user. Needs
// Config.AgentIdentity and Config.AuthorizationServer.
func (a *TheAuth) RegisterAgent(ctx context.Context, in RegisterAgentInput) (AgentRegistration, error) {
	if a.agentCfg == nil {
		return AgentRegistration{}, ErrAgentIdentityDisabled
	}
	return agent.Register(ctx, a.agentSvc, a.delegationSvc, a.agentCfg.DefaultDelegatedTokenTTL, in)
}

// RevocationKind says what was revoked.
type RevocationKind = revocation.Kind

// Revocation kinds.
const (
	RevocationSession         = revocation.Session
	RevocationAPIToken        = revocation.APIToken
	RevocationAgent           = revocation.Agent
	RevocationAgentCredential = revocation.AgentCredential
	RevocationDelegation      = revocation.Delegation
	// RevocationOwner means a user was disabled or deleted: every credential
	// that user owns or delegated is void.
	RevocationOwner = revocation.Owner
)

// RevocationEvent reports one revocation. An empty ID means "every credential
// of this kind belonging to UserID".
type RevocationEvent = revocation.Event

// RevocationBus fans revocation events out to subscribers.
type RevocationBus = revocation.Bus

// MemoryRevocationBus is the in-process RevocationBus.
type MemoryRevocationBus = revocation.MemoryBus

// RevocationTarget names the credential a stream was opened with.
type RevocationTarget = revocation.Target

// WatchOptions tunes WatchRevocation.
type WatchOptions = revocation.WatchOptions

// NewMemoryRevocationBus returns an empty in-process bus.
func NewMemoryRevocationBus() *MemoryRevocationBus { return revocation.NewMemoryBus() }

// PublishRevocation sends ev on the revocation bus, stamping At when zero.
func (a *TheAuth) PublishRevocation(ctx context.Context, ev RevocationEvent) error {
	return revocation.Publish(ctx, a.revocations, ev)
}

func (a *TheAuth) publishRevocation(ctx context.Context, ev RevocationEvent) {
	revocation.PublishQuiet(ctx, a.revocations, ev)
}

// SubscribeRevocations registers fn for every revocation event.
func (a *TheAuth) SubscribeRevocations(fn func(RevocationEvent)) (func(), error) {
	return a.revocations.Subscribe(fn)
}

// NotifyOwnerDisabled tells watchers that a user was disabled or deleted. The
// library cannot see host-side disable flags, so the host calls this when it
// flips them (the same flag Config.APITokens.OwnerActive reads).
func (a *TheAuth) NotifyOwnerDisabled(ctx context.Context, userID ULID, reason string) error {
	return a.PublishRevocation(ctx, RevocationEvent{Kind: RevocationOwner, UserID: userID.String(), Reason: reason})
}

func (a *TheAuth) revocationFromAudit(ctx context.Context, action string, target TargetRef, md map[string]any) {
	if ev, ok := revocation.FromAudit(action, target, md); ok {
		a.publishRevocation(ctx, ev)
	}
}

func (a *TheAuth) revocationWatcher() revocation.Watcher {
	w := revocation.Watcher{Bus: a.revocations}
	if a.sessionSvc != nil {
		w.WatchSession = a.WatchSession
	}
	if a.apiTokens != nil {
		w.CheckBearer = func(ctx context.Context, raw string) error {
			_, err := a.apiTokens.Authenticate(ctx, raw)
			return err
		}
	}
	return w
}

// WatchRevocation returns a context cancelled, with an error wrapping
// ErrCredentialRevoked as its cause, as soon as an event matches target or a
// poll finds the credential invalid. Call the cancel func when the stream ends.
func (a *TheAuth) WatchRevocation(ctx context.Context, target RevocationTarget, opts WatchOptions) (context.Context, context.CancelCauseFunc) {
	return a.revocationWatcher().Watch(ctx, target, opts)
}

// TargetForPrincipal builds the watch target for an authenticated principal.
func TargetForPrincipal(p *Principal) RevocationTarget {
	t := RevocationTarget{UserID: p.UserID.String()}
	if p.TokenID != nil {
		t.TokenID = p.TokenID.String()
	}
	return t
}

// WatchRevocationMiddleware cancels the request context when the presented
// credential is revoked, so SSE, MCP and other long-lived handlers drop within
// seconds. Place it after RequireAbility, which supplies the Principal; a
// session cookie is used when no bearer token was presented.
func (a *TheAuth) WatchRevocationMiddleware(opts WatchOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			target := TargetForPrincipal(p)
			o := opts
			o.SessionToken, o.BearerToken = "", ""
			if raw, ok := apitokens.BearerToken(r); ok && p.TokenID != nil {
				o.BearerToken = raw
			} else if c, err := r.Cookie(a.cookieName); err == nil && c.Value != "" {
				o.SessionToken = c.Value
				if sess, _, err := a.validateSession(r.Context(), c.Value); err == nil {
					target.SessionID = sess.ID.String()
				}
			}
			if strings.TrimSpace(o.BearerToken) == "" && o.SessionToken == "" && p.TokenID == nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx, cancel := a.WatchRevocation(r.Context(), target, o)
			defer cancel(nil)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
