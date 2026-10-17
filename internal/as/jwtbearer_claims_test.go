package as_test

// jwtbearer_claims_test.go: required claim matchers on a TrustedJWTIssuer and
// the GitHub Actions constructor. Uses a local ES256 issuer with an httptest
// JWKS; nothing touches the network.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const claimsTestIssuer = "https://token.actions.example.test"

type fixedMapper struct{ id theauth.ULID }

func (m fixedMapper) Resolve(map[string]any) (theauth.ULID, error) { return m.id, nil }

type claimsEnv struct {
	a     *theauth.TheAuth
	store *memory.Store
	priv  *ecdsa.PrivateKey
	audit *policyAudit
}

func newClaimsEnv(t *testing.T, matchers []theauth.ClaimMatcher) *claimsEnv {
	t.Helper()
	env, err := tryClaimsEnv(t, matchers)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return env
}

func tryClaimsEnv(t *testing.T, matchers []theauth.ClaimMatcher) (*claimsEnv, error) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return tryClaimsEnvIssuer(t, priv, theauth.TrustedJWTIssuer{
		Issuer: claimsTestIssuer, JWKSURL: jwksServerForECKey(t, &priv.PublicKey),
		AllowedAlgorithms: []string{"ES256"}, SubjectMapper: fixedMapper{id: ulid.New()},
		RequiredClaims: matchers,
	})
}

func tryClaimsEnvIssuer(t *testing.T, priv *ecdsa.PrivateKey, iss theauth.TrustedJWTIssuer) (*claimsEnv, error) {
	t.Helper()
	store := memory.New()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cap := &policyAudit{}
	a, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: "https://auth.example.com", EncryptionKey: key,
		Audit:         &theauth.AuditConfig{FlushInterval: 5 * time.Millisecond, Sinks: []theauth.AuditSink{cap}},
		AgentIdentity: &theauth.AgentConfig{},
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:          "https://auth.example.com",
			Resources:       []theauth.ProtectedResource{{Identifier: "https://api.example.com/mcp", Scopes: []string{"api.read"}}},
			DisableRotation: true,
			JWTBearer: &theauth.JWTBearerConfig{
				TrustedJWTIssuers: []theauth.TrustedJWTIssuer{iss}, AllowPrivateJWKSNetworks: true,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	t.Cleanup(a.Close)
	return &claimsEnv{a: a, store: store, priv: priv, audit: cap}, nil
}

func (e *claimsEnv) assertion(t *testing.T, extra map[string]any) string {
	t.Helper()
	now := time.Now()
	p := map[string]any{
		"iss": claimsTestIssuer, "sub": "repo:acme/app:ref:refs/heads/main", "aud": "https://auth.example.com",
		"jti": ulid.New().String(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range extra {
		if v == nil {
			delete(p, k)
			continue
		}
		p[k] = v
	}
	return signJWT(t, e.priv, map[string]any{"alg": "ES256", "typ": "JWT"}, p)
}

func (e *claimsEnv) exchange(assertion, clientID string) error {
	_, err := e.a.JWTBearerGrant(context.Background(), theauth.TokenRequest{
		GrantType: models.GrantTypeJWTBearer, ClientID: clientID,
		Resource: "https://api.example.com/mcp", Scope: []string{"api.read"},
	}, assertion)
	return err
}

func ghClaims() map[string]any {
	return map[string]any{
		"repository": "acme/app", "repository_owner": "acme", "ref": "refs/heads/main",
		"environment": "production", "ref_type": "branch", "run_id": "42",
		"job_workflow_ref": "acme/app/.github/workflows/deploy.yml@refs/heads/main",
	}
}

func merge(base, over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func TestJWTBearerClaimsMatching(t *testing.T) {
	eq := func(c, v string) theauth.ClaimMatcher { return theauth.ClaimMatcher{Claim: c, Equals: v} }
	tests := []struct {
		name     string
		matchers []theauth.ClaimMatcher
		claims   map[string]any
		wantOK   bool
	}{
		{"exact match passes", []theauth.ClaimMatcher{eq("repository", "acme/app")}, ghClaims(), true},
		{"wrong repo fails", []theauth.ClaimMatcher{eq("repository", "acme/app")}, merge(ghClaims(), map[string]any{"repository": "evil/app"}), false},
		{"wrong ref fails", []theauth.ClaimMatcher{eq("ref", "refs/heads/main")}, merge(ghClaims(), map[string]any{"ref": "refs/heads/dev"}), false},
		{"missing claim fails closed", []theauth.ClaimMatcher{eq("environment", "production")}, merge(ghClaims(), map[string]any{"environment": nil}), false},
		{"equals is case sensitive", []theauth.ClaimMatcher{eq("repository", "acme/app")}, merge(ghClaims(), map[string]any{"repository": "Acme/App"}), false},
		{"oneof hit", []theauth.ClaimMatcher{{Claim: "ref", OneOf: []string{"refs/heads/main", "refs/heads/prod"}}}, merge(ghClaims(), map[string]any{"ref": "refs/heads/prod"}), true},
		{"oneof miss", []theauth.ClaimMatcher{{Claim: "ref", OneOf: []string{"refs/heads/main", "refs/heads/prod"}}}, merge(ghClaims(), map[string]any{"ref": "refs/heads/dev"}), false},
		{"glob ref passes", []theauth.ClaimMatcher{{Claim: "ref", Pattern: "refs/heads/release/*"}}, merge(ghClaims(), map[string]any{"ref": "refs/heads/release/1.2"}), true},
		{"glob ref wrong prefix fails", []theauth.ClaimMatcher{{Claim: "ref", Pattern: "refs/heads/release/*"}}, merge(ghClaims(), map[string]any{"ref": "refs/heads/releases/1"}), false},
		{"glob is anchored at the end", []theauth.ClaimMatcher{{Claim: "ref", Pattern: "refs/heads/m*n"}}, merge(ghClaims(), map[string]any{"ref": "refs/heads/main2"}), false},
		{"glob is anchored at the start", []theauth.ClaimMatcher{{Claim: "ref", Pattern: "heads/main"}}, ghClaims(), false},
		{"no substring match", []theauth.ClaimMatcher{eq("repository_owner", "acme")}, merge(ghClaims(), map[string]any{"repository_owner": "acme-evil"}), false},
		{"pattern is not a regex", []theauth.ClaimMatcher{{Claim: "ref", Pattern: "refs/heads/.*"}}, ghClaims(), false},
		{"multiple matchers all pass", []theauth.ClaimMatcher{eq("repository", "acme/app"), eq("ref", "refs/heads/main"), eq("environment", "production")}, ghClaims(), true},
		{"multiple matchers one fails", []theauth.ClaimMatcher{eq("repository", "acme/app"), eq("ref", "refs/heads/main"), eq("environment", "production")}, merge(ghClaims(), map[string]any{"environment": "staging"}), false},
		{"present passes", []theauth.ClaimMatcher{{Claim: "environment", Present: true}}, ghClaims(), true},
		{"present fails when absent", []theauth.ClaimMatcher{{Claim: "environment", Present: true}}, merge(ghClaims(), map[string]any{"environment": nil}), false},
		{"present fails on empty string", []theauth.ClaimMatcher{{Claim: "environment", Present: true}}, merge(ghClaims(), map[string]any{"environment": ""}), false},
		{"no coercion of numbers", []theauth.ClaimMatcher{eq("run_id", "42")}, merge(ghClaims(), map[string]any{"run_id": 42}), false},
		{"no coercion of booleans", []theauth.ClaimMatcher{eq("flag", "true")}, merge(ghClaims(), map[string]any{"flag": true}), false},
		{"array claim any element", []theauth.ClaimMatcher{eq("groups", "deployers")}, merge(ghClaims(), map[string]any{"groups": []any{"dev", "deployers"}}), true},
		{"array claim no element", []theauth.ClaimMatcher{eq("groups", "deployers")}, merge(ghClaims(), map[string]any{"groups": []any{"dev", 7}}), false},
		{"nested dotted path", []theauth.ClaimMatcher{eq("ctx.team", "core")}, merge(ghClaims(), map[string]any{"ctx": map[string]any{"team": "core"}}), true},
		{"nested path missing", []theauth.ClaimMatcher{eq("ctx.team", "core")}, ghClaims(), false},
		{"no matchers keeps current behavior", nil, map[string]any{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := newClaimsEnv(t, tc.matchers)
			err := env.exchange(env.assertion(t, tc.claims), "")
			if tc.wantOK && err != nil {
				t.Fatalf("want success, got %v", err)
			}
			if !tc.wantOK && !errors.Is(err, models.ErrOAuthInvalidGrant) {
				t.Fatalf("want invalid_grant, got %v", err)
			}
			if !tc.wantOK && strings.Contains(err.Error(), "acme") {
				t.Fatalf("error echoes claim data: %v", err)
			}
		})
	}
}

func TestJWTBearerClaimMatcherConfigRejected(t *testing.T) {
	tests := []struct {
		name string
		m    theauth.ClaimMatcher
	}{
		{"empty claim", theauth.ClaimMatcher{Equals: "x"}},
		{"no operator", theauth.ClaimMatcher{Claim: "ref"}},
		{"two operators", theauth.ClaimMatcher{Claim: "ref", Equals: "a", Pattern: "a*"}},
		{"present plus equals", theauth.ClaimMatcher{Claim: "ref", Equals: "a", Present: true}},
		{"empty oneof entry", theauth.ClaimMatcher{Claim: "ref", OneOf: []string{"a", ""}}},
		{"bad path", theauth.ClaimMatcher{Claim: "a..b", Equals: "x"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tryClaimsEnv(t, []theauth.ClaimMatcher{tc.m})
			if !errors.Is(err, theauth.ErrInvalidClaimMatcher) {
				t.Fatalf("want ErrInvalidClaimMatcher at New, got %v", err)
			}
			if !strings.Contains(err.Error(), claimsTestIssuer) {
				t.Fatalf("error should name the issuer: %v", err)
			}
		})
	}
}

func TestGitHubActionsIssuerConstructor(t *testing.T) {
	t.Run("requires repository or owner", func(t *testing.T) {
		for _, o := range []theauth.GitHubActionsOptions{{}, {Refs: []string{"refs/heads/main"}, Environment: "prod"}} {
			if _, err := theauth.GitHubActionsIssuer(o); !errors.Is(err, theauth.ErrGitHubActionsUnrestricted) {
				t.Fatalf("want ErrGitHubActionsUnrestricted, got %v", err)
			}
		}
	})
	t.Run("bad options", func(t *testing.T) {
		for _, o := range []theauth.GitHubActionsOptions{
			{Repository: "acme"}, {Repository: "acme/*"}, {RepositoryOwner: "acme/app"},
			{Repository: "acme/app", Refs: []string{"refs/heads/main", "refs/heads/rel/*"}},
		} {
			if _, err := theauth.GitHubActionsIssuer(o); !errors.Is(err, theauth.ErrInvalidClaimMatcher) {
				t.Fatalf("%+v: want ErrInvalidClaimMatcher, got %v", o, err)
			}
		}
	})
	t.Run("fields and matchers", func(t *testing.T) {
		iss, err := theauth.GitHubActionsIssuer(theauth.GitHubActionsOptions{
			Repository: "acme/app", RepositoryOwner: "acme", Refs: []string{"refs/heads/main", "refs/heads/prod"},
			Environment: "production", Audience: "https://auth.example.com/gh",
		})
		if err != nil {
			t.Fatal(err)
		}
		if iss.Issuer != "https://token.actions.githubusercontent.com" ||
			iss.JWKSURL != "https://token.actions.githubusercontent.com/.well-known/jwks" ||
			len(iss.AllowedAlgorithms) != 1 || iss.AllowedAlgorithms[0] != "RS256" ||
			iss.Audience != "https://auth.example.com/gh" || len(iss.RequiredClaims) != 4 {
			t.Fatalf("unexpected issuer: %+v", iss)
		}
	})
	t.Run("owner only is enough and glob single ref is a pattern", func(t *testing.T) {
		iss, err := theauth.GitHubActionsIssuer(theauth.GitHubActionsOptions{RepositoryOwner: "acme", Refs: []string{"refs/heads/release/*"}})
		if err != nil || len(iss.RequiredClaims) != 2 || iss.RequiredClaims[1].Pattern != "refs/heads/release/*" {
			t.Fatalf("%+v %v", iss, err)
		}
	})
	t.Run("end to end with a local issuer", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		iss, err := theauth.GitHubActionsIssuer(theauth.GitHubActionsOptions{
			Repository: "acme/app", Refs: []string{"refs/heads/main"}, Environment: "production",
			Audience: "gh-aud", SubjectMapper: fixedMapper{id: ulid.New()},
		})
		if err != nil {
			t.Fatal(err)
		}
		// Point the issuer at the local fake; keep the generated matchers.
		iss.Issuer, iss.JWKSURL, iss.AllowedAlgorithms = claimsTestIssuer, jwksServerForECKey(t, &priv.PublicKey), []string{"ES256"}
		env, err := tryClaimsEnvIssuer(t, priv, iss)
		if err != nil {
			t.Fatal(err)
		}
		if err := env.exchange(env.assertion(t, merge(ghClaims(), map[string]any{"aud": "https://auth.example.com"})), ""); !errors.Is(err, models.ErrOAuthInvalidGrant) {
			t.Fatalf("default AS audience must be refused when Audience is set: %v", err)
		}
		if err := env.exchange(env.assertion(t, merge(ghClaims(), map[string]any{"aud": "gh-aud"})), ""); err != nil {
			t.Fatalf("matching token: %v", err)
		}
		if err := env.exchange(env.assertion(t, merge(ghClaims(), map[string]any{"aud": "gh-aud", "repository": "evil/app"})), ""); !errors.Is(err, models.ErrOAuthInvalidGrant) {
			t.Fatalf("other repo: %v", err)
		}
	})
}

func TestJWTBearerClaimsDeniedAudit(t *testing.T) {
	env := newClaimsEnv(t, []theauth.ClaimMatcher{
		{Claim: "repository", Equals: "acme/app"}, {Claim: "ref", Equals: "refs/heads/main"}, {Claim: "environment", Equals: "production"},
	})
	ctx := context.Background()
	u := theauth.User{ID: ulid.New(), Email: "owner@example.com"}
	if _, err := env.store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	uid := u.ID
	ag, sec, err := env.a.CreateAgent(ctx, theauth.CreateAgentInput{Owner: theauth.AgentOwner{UserID: &uid}, Name: "deployer", Scope: []string{"api.read"}})
	if err != nil {
		t.Fatal(err)
	}
	bad := merge(ghClaims(), map[string]any{"repository": "evil/secret-repo", "ref": "refs/heads/leaked-branch"})
	if err := env.exchange(env.assertion(t, bad), sec.ClientID); !errors.Is(err, models.ErrOAuthInvalidGrant) {
		t.Fatalf("want invalid_grant, got %v", err)
	}
	var ev *theauth.AuditEvent
	for i := 0; i < 400 && ev == nil; i++ {
		time.Sleep(5 * time.Millisecond)
		ev = env.audit.find("jwt_bearer.claims_denied")
	}
	if ev == nil {
		t.Fatal("no jwt_bearer.claims_denied audit event")
	}
	if ev.Metadata["issuer"] != claimsTestIssuer || ev.Metadata["agent_id"] != ag.ID.String() {
		t.Fatalf("metadata: %+v", ev.Metadata)
	}
	raw, _ := json.Marshal(ev)
	if got := fmt.Sprint(ev.Metadata["failed_claims"]); got != "[repository ref]" {
		t.Errorf("failed_claims should name only the claims that failed: %v", ev.Metadata["failed_claims"])
	}
	for _, leaked := range []string{"evil/secret-repo", "leaked-branch", "acme/app", "refs/heads/main"} {
		if strings.Contains(string(raw), leaked) {
			t.Errorf("audit leaks claim value %q: %s", leaked, raw)
		}
	}
}

func TestJWTBearerClaimsConcurrent(t *testing.T) {
	env := newClaimsEnv(t, []theauth.ClaimMatcher{
		{Claim: "repository", Equals: "acme/app"}, {Claim: "ref", Pattern: "refs/heads/*"},
	})
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			repo := "acme/app"
			if i%2 == 1 {
				repo = "evil/app"
			}
			err := env.exchange(env.assertion(t, merge(ghClaims(), map[string]any{"repository": repo})), "")
			if (i%2 == 0) != (err == nil) {
				errs <- fmt.Errorf("worker %d repo %s: err=%v", i, repo, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
