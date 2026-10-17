// Command token-vault shows an agent obtaining a short lived access token for
// a connected provider on behalf of a user, without ever holding the refresh
// token. A stub provider runs in process; no network access is needed.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/glincker/theauth-go/v2/tokenvault"
	"github.com/oklog/ulid/v2"
)

func main() {
	ctx := context.Background()

	// Stub provider: its token endpoint honours the refresh grant.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("refresh_token") != "stub-refresh-token" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "stub-access-token-2", "expires_in": 3600, "scope": "calendar.read",
		})
	}))
	defer provider.Close()

	// 32 random bytes for the demo. In production load them from a KMS or secret manager.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Fatal(err)
	}
	keys, err := tokenvault.NewKeyRing("2026-10", map[string][]byte{"2026-10": raw})
	if err != nil {
		log.Fatal(err)
	}

	store := memory.New()
	user, agent := ulid.Make(), ulid.Make()

	// The user delegates the calendar scope for provider "acme" to the agent.
	_, err = store.InsertDelegationGrant(ctx, theauth.DelegationGrant{
		ID: ulid.Make(), UserID: user, AgentID: agent, Resource: tokenvault.Resource("acme"),
		Scope: []string{"calendar.read"}, CreatedAt: time.Now(),
	})
	if err != nil {
		log.Fatal(err)
	}

	v, err := tokenvault.New(tokenvault.Config{
		Store:       store,
		Keys:        keys,
		Delegations: tokenvault.GrantDelegations{Store: store},
		Audit:       tokenvault.AuditStorageSink{Store: store},
		Providers: map[string]tokenvault.Refresher{
			"acme": tokenvault.OAuthRefresher{
				TokenURL: provider.URL, ClientID: "demo", ClientSecret: "demo-secret", AllowInsecureHTTP: true,
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// The user finishes the provider's OAuth flow; the app stores the result.
	// The stored access token is already expired, so the first use refreshes it.
	if _, err = v.Connect(ctx, tokenvault.ConnectInput{
		UserID: user.String(), Provider: "acme", AccountID: "user@example.com",
		AccessToken: "stub-access-token-1", RefreshToken: "stub-refresh-token",
		ExpiresAt: time.Now().Add(-time.Minute), Scopes: []string{"calendar.read"},
	}); err != nil {
		log.Fatal(err)
	}

	// The agent asks for a token. It receives only the access token.
	tok, err := v.AccessToken(ctx, tokenvault.Request{
		AgentID: agent.String(), UserID: user.String(), Provider: "acme", Scopes: []string{"calendar.read"},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("agent got a bearer token, expires", tok.ExpiresAt.Format(time.RFC3339), "(token:", tok, ")")

	// An agent without a delegation is refused.
	_, err = v.AccessToken(ctx, tokenvault.Request{
		AgentID: ulid.Make().String(), UserID: user.String(), Provider: "acme", Scopes: []string{"calendar.read"},
	})
	fmt.Println("other agent:", err)

	// Every decision was audited, none contains a token.
	events, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{})
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range events {
		fmt.Println("audit:", e.Action, e.Metadata)
	}
}
