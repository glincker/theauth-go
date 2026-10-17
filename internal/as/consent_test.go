package as_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/internal/cimd"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

const consentCB = "https://app.example.com/cb"

type consentEnv struct {
	a        *theauth.TheAuth
	user     theauth.User
	client   theauth.RegisteredClient
	verifier string
	seen     []theauth.ConsentRequest
}

// newConsentEnv builds an AS whose ConsentHandler returns whatever *dec holds.
func newConsentEnv(t *testing.T, dec *theauth.ConsentDecision, mut ...func(*theauth.AuthorizationServerConfig)) *consentEnv {
	t.Helper()
	env := &consentEnv{}
	mut = append([]func(*theauth.AuthorizationServerConfig){func(c *theauth.AuthorizationServerConfig) {
		c.ConsentHandler = func(_ context.Context, r theauth.ConsentRequest) (theauth.ConsentDecision, error) {
			env.seen = append(env.seen, r)
			return *dec, nil
		}
	}}, mut...)
	a, store := newASInstance(t, mut...)
	env.a = a
	env.user = theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	if _, err := store.CreateUser(context.Background(), env.user); err != nil {
		t.Fatal(err)
	}
	env.client = confidentialClient(t, a)
	env.verifier, _ = crypto.NewCodeVerifier()
	return env
}

func (e *consentEnv) authorize(t *testing.T, user *theauth.User) (theauth.AuthorizeResult, error) {
	t.Helper()
	return e.a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID:            e.client.ClientID,
		RedirectURI:         consentCB,
		ResponseType:        "code",
		Scope:               []string{"files.read", "files.write"},
		State:               "st8",
		CodeChallenge:       crypto.CodeChallenge(e.verifier),
		CodeChallengeMethod: "S256",
		Resource:            "https://files.example.com/mcp",
	}, user)
}

func (e *consentEnv) exchange(t *testing.T, redirect string) (theauth.TokenResponse, error) {
	t.Helper()
	return e.a.ExchangeAuthorizationCode(context.Background(), theauth.TokenRequest{
		GrantType:    theauth.GrantTypeAuthorizationCode,
		ClientID:     e.client.ClientID,
		ClientSecret: e.client.ClientSecret,
		Code:         codeFromRedirect(t, redirect),
		CodeVerifier: e.verifier,
		RedirectURI:  consentCB,
	})
}

func ticketOf(t *testing.T, redirect string) string {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	tk := u.Query().Get("consent_ticket")
	if tk == "" {
		t.Fatalf("no consent_ticket in %q", redirect)
	}
	return tk
}

func TestConsentApproveDecisions(t *testing.T) {
	tests := []struct {
		name      string
		dec       theauth.ConsentDecision
		wantErr   error
		wantScope string
		maxExpiry time.Duration
	}{
		{name: "subset narrows scope", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}}, wantScope: "files.read"},
		{name: "full scope", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read", "files.write"}}, wantScope: "files.read files.write"},
		{name: "superset rejected", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read", "admin"}}, wantErr: theauth.ErrConsentDecisionInvalid},
		{name: "scope not in request rejected", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.delete"}}, wantErr: theauth.ErrConsentDecisionInvalid},
		{name: "empty grant rejected", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove}, wantErr: theauth.ErrConsentDecisionInvalid},
		{name: "unknown action rejected", dec: theauth.ConsentDecision{Action: "maybe", GrantedScopes: []string{"files.read"}}, wantErr: theauth.ErrConsentDecisionInvalid},
		{name: "past expiry rejected", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}, ExpiresAt: time.Now().Add(-time.Minute)}, wantErr: theauth.ErrConsentDecisionInvalid},
		{name: "max ttl bounds tokens", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}, MaxTTL: 5 * time.Minute}, wantScope: "files.read", maxExpiry: 5 * time.Minute},
		{name: "expires at bounds tokens", dec: theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}, ExpiresAt: time.Now().Add(10 * time.Minute)}, wantScope: "files.read", maxExpiry: 10 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := tc.dec
			env := newConsentEnv(t, &dec)
			res, err := env.authorize(t, &env.user)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tok, err := env.exchange(t, res.RedirectURL)
			if err != nil {
				t.Fatal(err)
			}
			if tok.Scope != tc.wantScope {
				t.Fatalf("scope = %q, want %q", tok.Scope, tc.wantScope)
			}
			if tc.maxExpiry > 0 && time.Duration(tok.ExpiresIn)*time.Second > tc.maxExpiry {
				t.Fatalf("expires_in %d exceeds %v", tok.ExpiresIn, tc.maxExpiry)
			}
			if tc.maxExpiry > 0 {
				// Refresh must keep the cap and the narrowed scope.
				rt, err := env.a.RefreshAccessToken(context.Background(), theauth.TokenRequest{
					GrantType: theauth.GrantTypeRefreshToken, ClientID: env.client.ClientID,
					ClientSecret: env.client.ClientSecret, RefreshToken: tok.RefreshToken,
				})
				if err != nil {
					t.Fatal(err)
				}
				if time.Duration(rt.ExpiresIn)*time.Second > tc.maxExpiry || rt.Scope != tc.wantScope {
					t.Fatalf("refresh escaped the grant: %+v", rt)
				}
			}
		})
	}
}

func TestConsentExpiryClampedToServerMax(t *testing.T) {
	dec := theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}, MaxTTL: 24 * time.Hour}
	env := newConsentEnv(t, &dec, func(c *theauth.AuthorizationServerConfig) {
		c.ConsentMaxGrantTTL = 2 * time.Minute
	})
	res, err := env.authorize(t, &env.user)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.exchange(t, res.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresIn > 120 || tok.ExpiresIn < 100 {
		t.Fatalf("expires_in = %d, want about 120", tok.ExpiresIn)
	}
	// No requested expiry also gets the server maximum.
	dec.MaxTTL = 0
	res, err = env.authorize(t, &env.user)
	if err != nil {
		t.Fatal(err)
	}
	if tok, err = env.exchange(t, res.RedirectURL); err != nil || tok.ExpiresIn > 120 {
		t.Fatalf("default not clamped: %+v %v", tok, err)
	}
}

func TestConsentRequestContents(t *testing.T) {
	dec := theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}}
	env := newConsentEnv(t, &dec)
	if _, err := env.authorize(t, &env.user); err != nil {
		t.Fatal(err)
	}
	r := env.seen[0]
	if r.User.ID != env.user.ID || r.Client.ID != env.client.ClientID || r.Client.RedirectURI != consentCB ||
		r.Client.MetadataSource != theauth.ConsentSourceRegistered || r.Client.Verified ||
		r.State != "st8" || r.RequestedResource != "https://files.example.com/mcp" ||
		strings.Join(r.RequestedScopes, " ") != "files.read files.write" {
		t.Fatalf("unexpected request: %+v", r)
	}
}

func TestConsentDeny(t *testing.T) {
	dec := theauth.ConsentDecision{Action: theauth.ConsentDeny}
	env := newConsentEnv(t, &dec)
	res, err := env.authorize(t, &env.user)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(res.RedirectURL)
	q := u.Query()
	if u.Host+u.Path != "app.example.com/cb" || q.Get("error") != "access_denied" || q.Get("state") != "st8" || q.Get("code") != "" {
		t.Fatalf("bad deny redirect %q", res.RedirectURL)
	}
}

func TestConsentInteractThenComplete(t *testing.T) {
	dec := theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: "/consent?x=1"}
	env := newConsentEnv(t, &dec)
	res, err := env.authorize(t, &env.user)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.RedirectURL, "/consent?") {
		t.Fatalf("redirect = %q", res.RedirectURL)
	}
	ticket := ticketOf(t, res.RedirectURL)
	ctx := context.Background()

	// Superset on completion is refused and does not burn the ticket.
	if _, err := env.a.CompleteConsent(ctx, ticket, theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read", "root"}}, &env.user); !errors.Is(err, theauth.ErrConsentDecisionInvalid) {
		t.Fatalf("superset: %v", err)
	}
	done, err := env.a.CompleteConsent(ctx, ticket, theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.write"}, MaxTTL: time.Minute}, &env.user)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := env.exchange(t, done.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Scope != "files.write" || tok.ExpiresIn > 60 {
		t.Fatalf("token = %+v", tok)
	}
	if len(env.seen) != 1 {
		t.Fatalf("handler ran %d times, want 1", len(env.seen))
	}
	// Replay.
	if _, err := env.a.CompleteConsent(ctx, ticket, theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.write"}}, &env.user); !errors.Is(err, theauth.ErrConsentTicketInvalid) {
		t.Fatalf("replay: %v", err)
	}
}

func TestConsentCompleteDeny(t *testing.T) {
	dec := theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: "https://app.example.com/consent"}
	env := newConsentEnv(t, &dec)
	res, _ := env.authorize(t, &env.user)
	done, err := env.a.CompleteConsent(context.Background(), ticketOf(t, res.RedirectURL), theauth.ConsentDecision{Action: theauth.ConsentDeny}, &env.user)
	if err != nil || !strings.Contains(done.RedirectURL, "error=access_denied") || !strings.Contains(done.RedirectURL, "state=st8") {
		t.Fatalf("deny: %q %v", done.RedirectURL, err)
	}
}

func TestConsentTicketRejections(t *testing.T) {
	approve := theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}}
	tests := []struct {
		name   string
		cfg    func(*theauth.AuthorizationServerConfig)
		mutate func(t *testing.T, env *consentEnv, ticket string) (string, *theauth.User)
	}{
		{name: "other user", mutate: func(t *testing.T, env *consentEnv, tk string) (string, *theauth.User) {
			other := theauth.User{ID: ulid.New(), Email: "mallory@example.com"}
			return tk, &other
		}},
		{name: "no user", mutate: func(t *testing.T, env *consentEnv, tk string) (string, *theauth.User) { return tk, nil }},
		{name: "tampered payload", mutate: func(t *testing.T, env *consentEnv, tk string) (string, *theauth.User) {
			// Swap in the payload of a ticket for a different client.
			dec := theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: "/c"}
			env2 := newConsentEnv(t, &dec)
			env2.user = env.user
			res, _ := env2.authorize(t, &env2.user)
			forged := ticketOf(t, res.RedirectURL)
			payload, _, _ := strings.Cut(forged, ".")
			_, sig, _ := strings.Cut(tk, ".")
			return payload + "." + sig, &env.user
		}},
		{name: "garbage", mutate: func(t *testing.T, env *consentEnv, tk string) (string, *theauth.User) {
			return "not.a.ticket", &env.user
		}},
		{name: "expired", cfg: func(c *theauth.AuthorizationServerConfig) { c.ConsentTicketTTL = time.Millisecond },
			mutate: func(t *testing.T, env *consentEnv, tk string) (string, *theauth.User) {
				time.Sleep(1100 * time.Millisecond)
				return tk, &env.user
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: "/consent"}
			var mut []func(*theauth.AuthorizationServerConfig)
			if tc.cfg != nil {
				mut = append(mut, tc.cfg)
			}
			env := newConsentEnv(t, &dec, mut...)
			res, err := env.authorize(t, &env.user)
			if err != nil {
				t.Fatal(err)
			}
			tk, user := tc.mutate(t, env, ticketOf(t, res.RedirectURL))
			if _, err := env.a.CompleteConsent(context.Background(), tk, approve, user); !errors.Is(err, theauth.ErrConsentTicketInvalid) {
				t.Fatalf("err = %v, want ticket invalid", err)
			}
		})
	}
}

func TestConsentInteractURLValidation(t *testing.T) {
	for _, bad := range []string{"", "//evil.example/x", "javascript:alert(1)", "ftp://x/y", `/\evil.example`, "relative/path"} {
		dec := theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: bad}
		env := newConsentEnv(t, &dec)
		if _, err := env.authorize(t, &env.user); !errors.Is(err, theauth.ErrConsentDecisionInvalid) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func TestConsentUnregisteredRedirectNeverReachesHandler(t *testing.T) {
	dec := theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"}}
	env := newConsentEnv(t, &dec)
	_, err := env.a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID: env.client.ClientID, RedirectURI: "https://evil.example/cb", ResponseType: "code",
		Scope: []string{"files.read"}, CodeChallenge: crypto.CodeChallenge(env.verifier),
		CodeChallengeMethod: "S256", Resource: "https://files.example.com/mcp",
	}, &env.user)
	if err == nil || len(env.seen) != 0 {
		t.Fatalf("err=%v handler calls=%d", err, len(env.seen))
	}
}

func TestConsentNoHandlerUnchanged(t *testing.T) {
	a, store := newASInstance(t)
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(context.Background(), user)
	client := confidentialClient(t, a)
	verifier, _ := crypto.NewCodeVerifier()
	res, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: consentCB, ResponseType: "code",
		Scope: []string{"files.read", "files.write"}, CodeChallenge: crypto.CodeChallenge(verifier),
		CodeChallengeMethod: "S256", Resource: "https://files.example.com/mcp",
	}, &user)
	if err != nil {
		t.Fatal(err)
	}
	if code := codeFromRedirect(t, res.RedirectURL); strings.Contains(code, "~") {
		t.Fatalf("code carries a grant expiry without a handler: %q", code)
	}
	tok, err := a.ExchangeAuthorizationCode(context.Background(), theauth.TokenRequest{
		GrantType: theauth.GrantTypeAuthorizationCode, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		Code: codeFromRedirect(t, res.RedirectURL), CodeVerifier: verifier, RedirectURI: consentCB,
	})
	if err != nil || tok.Scope != "files.read files.write" {
		t.Fatalf("tok=%+v err=%v", tok, err)
	}
	if _, err := a.CompleteConsent(context.Background(), "x", theauth.ConsentDecision{Action: theauth.ConsentDeny}, &user); err == nil {
		t.Fatal("CompleteConsent must fail without a handler")
	}
}

func TestConsentRequestExposesCIMDMetadata(t *testing.T) {
	cs := newCIMDServer(t)
	var got theauth.ConsentRequest
	a, store := newASInstance(t, func(c *theauth.AuthorizationServerConfig) {
		c.CIMD = &theauth.CIMDConfig{TrustPolicy: theauth.AllowAnyHTTPS(), HTTPClient: cs.trustingClient(), CacheTTL: time.Minute}
		c.ConsentHandler = func(_ context.Context, r theauth.ConsentRequest) (theauth.ConsentDecision, error) {
			got = r
			return theauth.ConsentDecision{Action: theauth.ConsentDeny}, nil
		}
	})
	cs.publish(cimd.Document{
		ClientID: cs.URL(), ClientName: "Claude Desktop", LogoURI: "https://app.example.com/logo.png",
		ClientURI: "https://app.example.com", RedirectURIs: []string{consentCB},
		GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"},
		TokenEndpointAuthMethod: "none", Scope: "files.read",
	})
	user := theauth.User{ID: ulid.New(), Email: "alice@example.com"}
	_, _ = store.CreateUser(context.Background(), user)
	verifier, _ := crypto.NewCodeVerifier()
	if _, err := a.StartAuthorize(context.Background(), theauth.AuthorizeRequest{
		ClientID: cs.URL(), RedirectURI: consentCB, ResponseType: "code", Scope: []string{"files.read"},
		CodeChallenge: crypto.CodeChallenge(verifier), CodeChallengeMethod: "S256", Resource: "https://files.example.com/mcp",
	}, &user); err != nil {
		t.Fatal(err)
	}
	c := got.Client
	if c.Name != "Claude Desktop" || c.LogoURI != "https://app.example.com/logo.png" || c.ClientURI != "https://app.example.com" ||
		c.MetadataSource != theauth.ConsentSourceCIMD || !c.Verified {
		t.Fatalf("client = %+v", c)
	}
}
