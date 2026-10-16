# Host-owned OAuth consent

By default the authorization server approves an authenticated request straight away and issues a code for every scope asked for. `AuthorizationServerConfig.ConsentHandler` hands that decision to your app, so you can show your own consent page with the client's name, let the user choose which abilities to grant, and set an expiry.

With no `ConsentHandler` set nothing changes.

## The flow

1. The client sends the user to `/oauth/authorize`. The user is signed in and the request is valid (client, exact `redirect_uri`, PKCE, resource, scope).
2. The library calls your `ConsentHandler` with a read-only `ConsentRequest`.
3. You answer with a `ConsentDecision`:
   - `ConsentApprove`: issue a code for `GrantedScopes` (a non-empty subset of the request), bounded by `ExpiresAt` and/or `MaxTTL`.
   - `ConsentDeny`: redirect to the client with `error=access_denied`, `state` and `iss`.
   - `ConsentInteract`: redirect the browser to `RedirectToConsentURL` (an absolute path such as `/consent`, or an http(s) URL) with a `consent_ticket` query parameter.
4. For `Interact`, your page renders the screen. When the user submits, your handler calls `TheAuth.CompleteConsent(ctx, ticket, decision, user)` and redirects the browser to the returned `RedirectURL`.

## ConsentRequest

| Field | Meaning |
| --- | --- |
| `User` | The signed-in user (a copy). |
| `Client.ID`, `Name`, `LogoURI`, `ClientURI`, `PolicyURI`, `TosURI` | Client metadata. |
| `Client.RedirectURI` | The validated redirect URI of this request. |
| `Client.MetadataSource` | `ConsentSourceRegistered` (stored, for example from dynamic registration) or `ConsentSourceCIMD` (fetched from the `client_id` URL). |
| `Client.Verified` | True for CIMD clients: the document was fetched over https from the `client_id` URL and matches it. It does not vouch for the name or logo, so show the host name too. Registered clients are self-asserted and report false. |
| `RequestedScopes` | Validated scopes the client asked for. |
| `RequestedResource` | The RFC 8707 resource. |
| `RequestedAuthorizationDetails` | Raw RFC 9396 JSON, empty if none. Carried through unchanged. |
| `State` | The client's `state`. |
| `MaxGrantTTL` | The server cap on grant lifetime (`ConsentMaxGrantTTL`), zero if none. |

## Scopes and expiry

- `GrantedScopes` may only narrow. A scope that was not requested, or an empty list, fails with `ErrConsentDecisionInvalid` and nothing is issued. Duplicates are dropped.
- The authorization code, the access token `scope` claim, `scope` in the token response and every refresh rotation carry the granted scopes.
- `ExpiresAt` and `MaxTTL` bound the access token and the refresh token; when both are set the earlier wins. `ConsentMaxGrantTTL` is a server ceiling applied on top, and also used when you give no expiry. An expiry in the past is refused. Refresh rotation never extends past the grant expiry; the expiry is carried inside the code and refresh token strings, whose stored keys are hashes of the whole string, so it needs no extra column and cannot be altered.

## Tickets

`consent_ticket` is `base64url(payload).base64url(HMAC-SHA256)` with a key derived from the server encryption key. It binds the pending request (client, `redirect_uri`, scopes, PKCE challenge, state, resource) to the user and, when the authorize request carried an `AuthContext`, the session. It lives for `ConsentTicketTTL` (default 10 minutes) and is single use: it is recorded in the replay cache (`Stores.ReplayCache`, in memory by default; use a shared one with more than one replica) only when a decision is accepted, so a rejected decision can be retried.

`CompleteConsent` fails with `ErrConsentTicketInvalid` for a malformed, forged, expired or already used ticket, a different user, or a different session. It re-validates the client and redirect URI against the registered or CIMD metadata (exact match) before issuing. The handler is not called again, and `ConsentInteract` is not a valid answer when completing.

## CSRF

The endpoint that calls `CompleteConsent` is yours, and a forged request to it would approve for the user. Protect it like any state changing form: a CSRF token or `SameSite` cookie plus an `Origin` check, and accept only POST. The ticket is not a CSRF token; it is visible in the URL.

## Example

```go
a, _ := theauth.New(theauth.Config{
	// ...
	AuthorizationServer: &theauth.AuthorizationServerConfig{
		// ...
		ConsentMaxGrantTTL: 30 * 24 * time.Hour,
		ConsentHandler: func(ctx context.Context, r theauth.ConsentRequest) (theauth.ConsentDecision, error) {
			if remembered(r.User.ID, r.Client.ID, r.RequestedScopes) {
				return theauth.ConsentDecision{Action: theauth.ConsentApprove, GrantedScopes: r.RequestedScopes}, nil
			}
			return theauth.ConsentDecision{Action: theauth.ConsentInteract, RedirectToConsentURL: "/consent"}, nil
		},
	},
})

// POST /consent (behind your CSRF protection)
func consentSubmit(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	dec := theauth.ConsentDecision{Action: theauth.ConsentDeny}
	if r.PostFormValue("decision") == "allow" {
		dec = theauth.ConsentDecision{
			Action:        theauth.ConsentApprove,
			GrantedScopes: r.PostForm["scope"], // the boxes the user left checked
			MaxTTL:        7 * 24 * time.Hour,
		}
	}
	res, err := a.CompleteConsent(r.Context(), r.PostFormValue("consent_ticket"), dec, user)
	if err != nil {
		http.Error(w, "consent expired, start again", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}
```

A runnable version is in `examples/oauth-consent`.

## Client metadata support

Registered clients and CIMD clients (`AuthorizationServerConfig.CIMD`) both reach the handler with `Name`, `LogoURI`, `ClientURI`, `PolicyURI` and `TosURI` from their metadata. CIMD fetching, its trust policy, size and time limits and private address blocking are the existing `internal/cimd` resolver; the consent feature adds no fetching. Not exposed: the CIMD cache age, or whether the document was served from cache.
