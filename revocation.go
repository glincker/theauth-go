package theauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/glincker/theauth-go/v2/internal/apitokens"
	"github.com/glincker/theauth-go/v2/internal/revocation"
)

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
