// Host-owned OAuth consent demo. Runs in memory, no network.
//
// The ConsentHandler sends every request to the host's own consent page. The
// demo plays the browser: it reads the consent_ticket from the redirect, then
// calls the same code a POST /consent handler would, with the user having
// unticked one scope and picked a one hour grant.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	oklog "github.com/oklog/ulid/v2"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/crypto"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const (
	resource    = "https://files.example.com/mcp"
	redirectURI = "https://app.example.com/cb"
)

func main() {
	ctx := context.Background()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	store := memory.New()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://auth.example.com",
		EncryptionKey: key,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:             "https://auth.example.com",
			Resources:          []theauth.ProtectedResource{{Identifier: resource, Scopes: []string{"files.read", "files.write"}}},
			ConsentMaxGrantTTL: 24 * time.Hour,
			ConsentHandler: func(_ context.Context, r theauth.ConsentRequest) (theauth.ConsentDecision, error) {
				fmt.Printf("consent page would show: %q (%s, verified=%v) asks for %v\n",
					r.Client.Name, r.Client.MetadataSource, r.Client.Verified, r.RequestedScopes)
				return theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: "/consent"}, nil
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	user := theauth.User{ID: theauth.ULID(oklog.Make()), Email: "alice@example.com"}
	if _, err := store.CreateUser(ctx, user); err != nil {
		log.Fatal(err)
	}
	client, err := a.RegisterClient(ctx, theauth.ClientRegistrationRequest{
		ClientName:              "Demo MCP client",
		RedirectURIs:            []string{redirectURI},
		TokenEndpointAuthMethod: theauth.ClientAuthSecretBasic,
	}, false)
	if err != nil {
		log.Fatal(err)
	}

	verifier, _ := crypto.NewCodeVerifier()
	res, err := a.StartAuthorize(ctx, theauth.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: redirectURI, ResponseType: "code",
		Scope: []string{"files.read", "files.write"}, State: "xyz",
		CodeChallenge: crypto.CodeChallenge(verifier), CodeChallengeMethod: "S256", Resource: resource,
	}, &user)
	if err != nil {
		log.Fatal(err)
	}
	u, _ := url.Parse(res.RedirectURL)
	fmt.Println("browser sent to", u.Path)

	// What a POST /consent handler does (behind the host's CSRF protection).
	done, err := a.CompleteConsent(ctx, u.Query().Get("consent_ticket"), theauth.ConsentDecision{
		Action:        theauth.ConsentApprove,
		GrantedScopes: []string{"files.read"},
		MaxTTL:        time.Hour,
	}, &user)
	if err != nil {
		log.Fatal(err)
	}
	cb, _ := url.Parse(done.RedirectURL)

	tok, err := a.ExchangeAuthorizationCode(ctx, theauth.TokenRequest{
		GrantType: theauth.GrantTypeAuthorizationCode, ClientID: client.ClientID, ClientSecret: client.ClientSecret,
		Code: cb.Query().Get("code"), CodeVerifier: verifier, RedirectURI: redirectURI,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("token scope=%q expires_in=%ds\n", tok.Scope, tok.ExpiresIn)
}

// consentSubmit shows the same step as an HTTP handler.
func consentSubmit(a *theauth.TheAuth, currentUser func(*http.Request) *theauth.User) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		dec := theauth.ConsentDecision{Action: theauth.ConsentDeny}
		if r.PostFormValue("decision") == "allow" {
			dec = theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: r.PostForm["scope"], MaxTTL: 7 * 24 * time.Hour}
		}
		res, err := a.CompleteConsent(r.Context(), r.PostFormValue("consent_ticket"), dec, currentUser(r))
		if err != nil {
			http.Error(w, "consent expired, start again", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, res.RedirectURL, http.StatusFound)
	}
}

var _ = consentSubmit
