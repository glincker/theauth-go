package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/glincker/theauth-go"
)

// Authenticator resolves the caller; *theauth.TheAuth implements it.
type Authenticator interface {
	AuthenticatePrincipal(w http.ResponseWriter, r *http.Request) (*http.Request, *theauth.Principal, bool)
}

// Auditor records decisions; *theauth.TheAuth implements it.
type Auditor interface {
	EmitAudit(ctx context.Context, action string, target theauth.TargetRef, metadata map[string]any)
}

// Audit action emitted for every guarded decision.
const AuditActionDecision = "policy.decision"

// ErrorCodeDenied is the problem code returned on a denied request.
const ErrorCodeDenied = "policy.denied"

// Resource names what a request touches and supplies {var} values.
type Resource struct {
	Name       string
	Attributes map[string]string
}

// Options configures a Guard.
type Options struct {
	Auth  Authenticator
	Store Storage
	// Audit is optional; decisions are not recorded when nil.
	Audit Auditor
	// AuditDenyOnly skips audit events for allowed requests.
	AuditDenyOnly bool
	// Subjects adds subjects such as the user's groups and roles. It runs on
	// every request so membership changes apply immediately.
	Subjects func(ctx context.Context, p *theauth.Principal) ([]Subject, error)
	// Attributes adds request attributes for variables and conditions.
	Attributes func(r *http.Request, p *theauth.Principal) map[string]string
	// ClientIP overrides the client address; default is RemoteAddr.
	ClientIP  func(r *http.Request) string
	Evaluator Evaluator
}

// Guard evaluates stored policies for authenticated requests.
type Guard struct{ o Options }

// New returns a Guard. Auth and Store are required.
func New(o Options) (*Guard, error) {
	if o.Auth == nil || o.Store == nil {
		return nil, fmt.Errorf("policy: Auth and Store are required")
	}
	return &Guard{o: o}, nil
}

// PrincipalSubjects returns the subjects a principal always has: the acting
// user (the delegating human for an agent token) and the token itself.
func PrincipalSubjects(p *theauth.Principal) []Subject {
	owner := p.UserID
	if p.DelegatedBy != nil {
		owner = *p.DelegatedBy
	}
	subs := []Subject{{Kind: SubjectUser, ID: owner.String()}}
	if p.TokenID != nil {
		subs = append(subs, Subject{Kind: SubjectToken, ID: p.TokenID.String()})
	}
	return subs
}

// Decide loads the principal's current policies and evaluates the request.
// Policies attached to the token form a boundary that only narrows access.
func (g *Guard) Decide(ctx context.Context, p *theauth.Principal, req Request) (Decision, error) {
	subs := PrincipalSubjects(p)
	if g.o.Subjects != nil {
		extra, err := g.o.Subjects(ctx, p)
		if err != nil {
			return Decision{}, fmt.Errorf("policy: resolve subjects: %w", err)
		}
		subs = append(subs, extra...)
	}
	attached, err := g.o.Store.PoliciesFor(ctx, subs)
	if err != nil {
		return Decision{}, fmt.Errorf("policy: load policies: %w", err)
	}
	var identity, boundary []*Policy
	for _, a := range attached {
		doc, err := Parse(a.Record.Document)
		if err != nil {
			return Decision{}, fmt.Errorf("policy: stored policy %q: %w", a.Record.ID, err)
		}
		doc.ID = a.Record.ID
		if a.Subject.Kind == SubjectToken {
			boundary = append(boundary, doc)
		} else {
			identity = append(identity, doc)
		}
	}
	return g.o.Evaluator.EvaluateWithBoundary(req, identity, boundary), nil
}

type decisionKey struct{}

// DecisionFromContext returns the allow decision stored by RequirePolicy.
func DecisionFromContext(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(decisionKey{}).(Decision)
	return d, ok
}

// RequirePolicy authenticates the caller, evaluates action on the resource
// returned by resourceFn, and responds 403 with code policy.denied on denial.
func (g *Guard) RequirePolicy(action string, resourceFn func(*http.Request) Resource) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, p, ok := g.o.Auth.AuthenticatePrincipal(w, r)
			if !ok {
				return
			}
			res := resourceFn(r)
			req := g.request(r, p, action, res)
			d, err := g.Decide(r.Context(), p, req)
			if err != nil {
				slog.Error("theauth policy: evaluation failed", "err", err.Error())
				writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "policy.error", "detail": "Authorization failed"})
				return
			}
			g.audit(r.Context(), p, req, d)
			if !d.Allowed {
				writeJSON(w, http.StatusForbidden, map[string]any{
					"code": ErrorCodeDenied, "status": http.StatusForbidden,
					"detail": d.Reason, "decision": d,
				})
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), decisionKey{}, d)))
		})
	}
}

func (g *Guard) request(r *http.Request, p *theauth.Principal, action string, res Resource) Request {
	attrs := map[string]string{
		"principal.id":   p.UserID.String(),
		"principal.kind": string(p.Kind),
	}
	if p.TokenID != nil {
		attrs["token.id"] = p.TokenID.String()
	}
	if p.AgentName != "" {
		attrs["agent.name"] = p.AgentName
	}
	if g.o.Attributes != nil {
		for k, v := range g.o.Attributes(r, p) {
			attrs[k] = v
		}
	}
	for k, v := range res.Attributes {
		attrs[k] = v
	}
	return Request{Action: action, Resource: res.Name, Attributes: attrs, IP: g.clientIP(r)}
}

func (g *Guard) clientIP(r *http.Request) string {
	if g.o.ClientIP != nil {
		return g.o.ClientIP(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (g *Guard) audit(ctx context.Context, p *theauth.Principal, req Request, d Decision) {
	if g.o.Audit == nil || (d.Allowed && g.o.AuditDenyOnly) {
		return
	}
	md := map[string]any{
		"allowed": d.Allowed, "action": req.Action, "resource": req.Resource,
		"reason": d.Reason, "boundary": d.Boundary,
		"principal_kind": string(p.Kind),
	}
	if d.PolicyID != "" {
		md["policy_id"] = d.PolicyID
	}
	if d.StatementID != "" {
		md["statement_id"] = d.StatementID
	}
	g.o.Audit.EmitAudit(ctx, AuditActionDecision, theauth.TargetRef{Type: "resource", ID: req.Resource}, md)
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
