# Security notes

## CodeQL alert triage

- `go/unvalidated-url-redirection` at `internal/as/handlers/handlers.go` (success redirect after `StartAuthorize`): false positive. `StartAuthorize` rejects the request unless `redirect_uri` exactly matches a URI registered for the client (`redirectURIRegistered`) before it builds `RedirectURL`, so CodeQL's taint flow cannot see that the value is already validated.
- The error-redirect path in the same file and the SAML `RelayState` redirect were real and are fixed (registered-URI check, same-site or allow-listed RelayState).
- `go/request-forgery` in `internal/cimd/service.go` was real and is fixed by the guarded default client in `internal/cimd/safefetch.go`. CodeQL may keep flagging the call because the check happens in the dialer, not on the URL.
