# Let your app own the OAuth consent screen

By default the authorization server approves a signed-in user's request at once and issues every scope the client asked for, so you cannot show your own consent page, let the user untick an ability, or cap how long a grant lasts.

In this tutorial you set a `ConsentHandler` that sends each request to your own `/consent` page, then complete the decision with `CompleteConsent`: a narrowed scope list and a one hour limit. You also watch the library refuse a widened grant and a replayed ticket.

## Prerequisites

- Go 1.25 or newer.
- A theauth instance with the authorization server enabled. The demo below uses the in-memory store and needs no network.

```sh
go get github.com/glincker/theauth-go/v2@latest
```

Host-owned consent ships in the next release after v2.10.0. Until it is tagged, use `@main`. With no `ConsentHandler` set, nothing changes.

## 1. Add the handler

The handler receives a read-only `ConsentRequest`: the signed-in user, the client's name and metadata, the requested scopes and the resource. It answers with approve, deny or interact. Here it always interacts, which redirects the browser to your page with a `consent_ticket` query parameter.

```go
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
```

The request also carries `Client.MetadataSource`, which tells you whether the client was registered (for example by dynamic registration) or fetched by its metadata document URL, and `Client.RedirectURI`, the redirect that was already validated against the registered one. Your page can print the client name, the host it redirects to, and the scopes, in plain words. Show the host too, because a name is only a claim.

`ConsentMaxGrantTTL` is a server ceiling on how long any grant can last. The `ConsentApprove` answer is also available in the handler, for example to skip the page when the user already granted the same scopes to the same client.

## 2. Start an authorization request

The demo registers a client and starts the request as a signed-in user. In production the browser does this by visiting `/oauth/authorize`.

```go
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
```

## 3. Try to widen the grant

The ticket binds the pending request to the user. Granted scopes can only narrow the request, so asking for `admin`, which the client never requested, fails with `ErrConsentDecisionInvalid`.

```go
	ticket := u.Query().Get("consent_ticket")

	// A user cannot widen the grant: asking for a scope the client never requested is refused.
	_, err = a.CompleteConsent(ctx, ticket, theauth.ConsentDecision{
		Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read", "admin"},
	}, &user)
	fmt.Println("superset refused:", errors.Is(err, theauth.ErrConsentDecisionInvalid))
```

A refused decision does not burn the ticket, so the user can retry.

## 4. Complete the consent

This is what your POST `/consent` handler does after the user unticks `files.write` and picks a one hour grant. The code then exchanges for a token as usual.

```go
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
```

## 5. Replay the ticket

```go
	// The ticket is single use.
	_, err = a.CompleteConsent(ctx, ticket, theauth.ConsentDecision{
		Action: theauth.ConsentApprove, GrantedScopes: []string{"files.read"},
	}, &user)
	fmt.Println("replay refused:", errors.Is(err, theauth.ErrConsentTicketInvalid))
```

## What the output means

```text
consent page would show: "Demo MCP client" (registered, verified=false) asks for [files.read files.write]
browser sent to /consent
superset refused: true
token scope="files.read" expires_in=3599s
replay refused: true
```

Your handler saw the client name and both scopes. The browser went to `/consent`. The token carries only `files.read` and expires in about an hour, not the 24 hour server ceiling. Refresh rotation keeps the narrowed scope and never extends past the grant expiry. `verified=false` is normal for a registered client, whose metadata is self-asserted. For a client fetched by CIMD it is true, but even then it does not vouch for the name or logo, so show the host name next to them.

## The HTTP handler

Your `/consent` endpoint is plain `net/http`. This one is in the same example file.

```go
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
```

## Security notes

The endpoint that calls `CompleteConsent` is yours, and a forged request to it approves on the user's behalf. Accept POST only, and protect it like any state changing form with a CSRF token or a `SameSite` cookie plus an `Origin` check. The ticket is not a CSRF token. It sits in the URL.

Tickets last `ConsentTicketTTL` (10 minutes by default) and are single use. The record of used tickets lives in `Stores.ReplayCache`, which is in memory unless you provide one, so with more than one replica use a shared cache. A ticket is bound to the user and session, so a different user gets `ErrConsentTicketInvalid`.

## Limits

- The demo skips the page itself. Rendering the screen, checkboxes and "remember this choice" storage are yours.
- Expiry is carried inside the code and refresh token strings. It cannot be altered afterwards.
- Authorization details (RFC 9396) pass through unchanged. The handler cannot edit them.

## Next

- [Host-owned OAuth consent reference](../oauth-consent.md)
- [Example: examples/oauth-consent](https://github.com/glincker/theauth-go/tree/main/examples/oauth-consent)
- [The tests](https://github.com/glincker/theauth-go/blob/main/internal/as/consent_test.go) cover ticket tampering, expiry and CIMD metadata.
- [Deny risky actions for AI agents with IAM policies](deny-risky-ai-agent-actions-with-iam-policies.md)
