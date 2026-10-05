package policy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/policy"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

type recorder struct {
	mu     sync.Mutex
	events []map[string]any
}

func (r *recorder) EmitAudit(_ context.Context, action string, _ theauth.TargetRef, md map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	md["_action"] = action
	r.events = append(r.events, md)
}

type env struct {
	t     *testing.T
	a     *theauth.TheAuth
	store *policy.Memory
	rec   *recorder
	user  theauth.User
	srv   *httptest.Server
	mu    sync.Mutex
	group []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, store: policy.NewMemory(), rec: &recorder{}}
	ms := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage: ms, BaseURL: "http://localhost", SessionTTL: time.Hour, MagicLinkTTL: time.Minute,
		RateLimitPerIP: 1000, RateLimitPerEmail: 1000,
		APITokens: &theauth.APITokensConfig{Prefix: "tk"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	e.a = a
	u, err := ms.CreateUser(context.Background(), theauth.User{ID: ulid.New(), Email: "u@x.test", Name: "u", CreatedAt: time.Now(), UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	e.user = u
	g, err := policy.New(policy.Options{
		Auth: a, Store: e.store, Audit: e.rec,
		Subjects: func(_ context.Context, p *theauth.Principal) ([]policy.Subject, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			var out []policy.Subject
			for _, id := range e.group {
				out = append(out, policy.Subject{Kind: policy.SubjectGroup, ID: id})
			}
			return out, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	res := func(r *http.Request) policy.Resource {
		id := r.PathValue("project")
		return policy.Resource{Name: "project/" + id, Attributes: map[string]string{"project_id": id}}
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, _ := policy.DecisionFromContext(r.Context())
		_, _ = w.Write([]byte(d.StatementID))
	})
	mux.Handle("POST /projects/{project}/deploy", g.RequirePolicy("deploy:create", res)(ok))
	mux.Handle("GET /projects/{project}", g.RequirePolicy("project:read", res)(ok))
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) put(id, doc string) {
	e.t.Helper()
	if err := e.store.PutPolicy(context.Background(), policy.Record{ID: id, Document: []byte(doc)}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) attach(kind policy.SubjectKind, subj, id string) {
	e.t.Helper()
	if err := e.store.AttachPolicy(context.Background(), policy.Subject{Kind: kind, ID: subj}, id); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) token(in theauth.MintAPITokenInput) (string, theauth.APIToken) {
	e.t.Helper()
	in.OwnerKind = theauth.OwnerKindUser
	if in.OwnerID == (theauth.ULID{}) {
		in.OwnerID = e.user.ID
	}
	in.Name = "t"
	in.Abilities = []string{"read"}
	raw, tok, err := e.a.MintAPIToken(context.Background(), in)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw, tok
}

func (e *env) call(method, path, bearer string) (int, map[string]any, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	var m map[string]any
	_ = json.Unmarshal(buf[:n], &m)
	return resp.StatusCode, m, string(buf[:n])
}

const (
	deployP1 = `{"version":"1","statements":[{"id":"deploy-own-project","effect":"allow","actions":["deploy:*","project:read"],"resources":["project/p1"]}]}`
	readOnly = `{"version":"1","statements":[{"id":"read-only","effect":"allow","actions":["project:read"],"resources":["project/*"]}]}`
)

func TestRequirePolicy(t *testing.T) {
	e := newEnv(t)
	raw, tok := e.token(theauth.MintAPITokenInput{})
	uid := e.user.ID.String()

	code, body, _ := e.call("POST", "/projects/p1/deploy", raw)
	if code != 403 || body["code"] != "policy.denied" {
		t.Fatalf("default deny: %d %v", code, body)
	}

	e.put("deploy-p1", deployP1)
	e.attach(policy.SubjectUser, uid, "deploy-p1")
	if code, _, b := e.call("POST", "/projects/p1/deploy", raw); code != 200 || b != "deploy-own-project" {
		t.Fatalf("allowed: %d %q", code, b)
	}
	if code, _, _ := e.call("POST", "/projects/p2/deploy", raw); code != 403 {
		t.Fatalf("other project must be denied, got %d", code)
	}

	t.Run("boundary narrows and never widens", func(t *testing.T) {
		e.put("ro", readOnly)
		e.attach(policy.SubjectToken, tok.ID.String(), "ro")
		code, body, _ := e.call("POST", "/projects/p1/deploy", raw)
		if code != 403 || body["code"] != "policy.denied" {
			t.Fatalf("boundary should block deploy: %d %v", code, body)
		}
		if d, _ := body["decision"].(map[string]any); d["boundary"] != true {
			t.Fatalf("decision should flag boundary: %v", body)
		}
		if code, _, _ := e.call("GET", "/projects/p1", raw); code != 200 {
			t.Fatalf("read inside both should pass: %d", code)
		}
		if code, _, _ := e.call("GET", "/projects/p2", raw); code != 403 {
			t.Fatalf("read p2 is outside owner policy even though boundary allows it: %d", code)
		}
	})

	t.Run("group policy is read fresh per request", func(t *testing.T) {
		raw2, _ := e.token(theauth.MintAPITokenInput{})
		if code, _, _ := e.call("GET", "/projects/p9", raw2); code != 403 {
			t.Fatalf("want deny, got %d", code)
		}
		e.put("grp", `{"version":"1","statements":[{"id":"grp-read","effect":"allow","actions":["project:read"],"resources":["project/*"]}]}`)
		e.attach(policy.SubjectGroup, "g1", "grp")
		e.mu.Lock()
		e.group = []string{"g1"}
		e.mu.Unlock()
		if code, _, b := e.call("GET", "/projects/p9", raw2); code != 200 || b != "grp-read" {
			t.Fatalf("joined group: %d %q", code, b)
		}
		e.mu.Lock()
		e.group = nil
		e.mu.Unlock()
		if code, _, _ := e.call("GET", "/projects/p9", raw2); code != 403 {
			t.Fatalf("left group must lose access immediately: %d", code)
		}
	})

	t.Run("agent token uses delegating human with its own boundary", func(t *testing.T) {
		agent, atok := e.token(theauth.MintAPITokenInput{Kind: theauth.APITokenKindAgent, AgentName: "bot", DelegatedBy: &e.user.ID})
		if code, _, _ := e.call("POST", "/projects/p1/deploy", agent); code != 200 {
			t.Fatalf("agent inherits delegator policy: %d", code)
		}
		e.attach(policy.SubjectToken, atok.ID.String(), "ro")
		if code, _, _ := e.call("POST", "/projects/p1/deploy", agent); code != 403 {
			t.Fatalf("agent boundary must narrow: %d", code)
		}
	})

	t.Run("explicit deny wins across subjects", func(t *testing.T) {
		raw3, _ := e.token(theauth.MintAPITokenInput{})
		e.put("deny", `{"version":"1","statements":[{"id":"freeze","effect":"deny","actions":["deploy:*"],"resources":["*"]}]}`)
		e.attach(policy.SubjectUser, uid, "deny")
		code, body, _ := e.call("POST", "/projects/p1/deploy", raw3)
		d, _ := body["decision"].(map[string]any)
		if code != 403 || d["statementId"] != "freeze" || d["policyId"] != "deny" {
			t.Fatalf("freeze: %d %v", code, body)
		}
	})

	t.Run("unauthenticated is 401", func(t *testing.T) {
		if code, _, _ := e.call("GET", "/projects/p1", ""); code != 401 {
			t.Fatalf("want 401, got %d", code)
		}
	})

	t.Run("audit records allow and deny", func(t *testing.T) {
		e.rec.mu.Lock()
		defer e.rec.mu.Unlock()
		var allows, denies int
		for _, ev := range e.rec.events {
			if ev["_action"] != policy.AuditActionDecision || ev["reason"] == nil || ev["resource"] == nil {
				t.Fatalf("bad audit event: %v", ev)
			}
			if ev["allowed"] == true {
				allows++
			} else {
				denies++
			}
		}
		if allows == 0 || denies == 0 {
			t.Fatalf("want both allow and deny events, got %d/%d", allows, denies)
		}
	})
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := policy.New(policy.Options{}); err == nil {
		t.Fatal("want error")
	}
}
