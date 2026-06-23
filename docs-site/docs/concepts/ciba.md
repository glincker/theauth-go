# CIBA: Client-Initiated Backchannel Authentication

CIBA (Client-Initiated Backchannel Authentication, RFC 9509) decouples the
consumption device from the authentication device. A user interacts with an
authentication device (e.g., a phone app receiving a push notification) to
approve a request initiated by a completely separate consumption device (e.g.,
a call center agent's desktop, an IoT appliance, or a voice assistant speaker).
No browser redirect is required.

## When to use CIBA

| Scenario | Why CIBA fits |
|---|---|
| **Call center step-up** | The agent's desktop initiates auth; the customer approves on their phone. |
| **IoT / appliance pairing** | A smart TV or thermostat cannot run a browser; the user approves on their phone. |
| **Voice assistant** | A speaker or IVR system cannot display a URL; push notification to the user's phone approves the action. |
| **Headless POS terminal** | The terminal triggers auth; the customer approves on a mobile device. |
| **Unattended workstation** | A background service needs a user token; the user approves on a separate device. |

CIBA is not suitable when the same device both initiates and completes
authentication. For that case, use the standard authorization code flow.

## Modes

### Poll mode

The client polls the token endpoint periodically until the user approves or
denies on their authentication device.

```
Client App                 theauth-go AS            Authentication Device (phone)
    |                           |                            |
    | POST /ciba/bc-authorize   |                            |
    |  login_hint=user@example  |                            |
    |  scope=read:data          |                            |
    |  binding_message=TX-1234  |                            |
    |-------------------------->|                            |
    |  { auth_req_id, interval: 5, expires_in: 120 }        |
    |<--------------------------|                            |
    |                           | AuthenticationDevice.Notify(CIBARequest)
    |                           |--------------------------->|
    |                           |         (push notification delivered)
    |                           |                            |
    |   (wait interval seconds) |                            | User taps "Approve"
    |                           |<---------------------------|
    | POST /ciba/token          |                            |
    |  auth_req_id=...          |                            |
    |-------------------------->|                            |
    |  { access_token, ... }    |                            |
    |<--------------------------|                            |
```

### Ping mode

The AS notifies the client when the user has approved, instead of the client
polling. The client registers a `client_notification_endpoint`.

```
Client App                 theauth-go AS            Authentication Device (phone)
    |                           |                            |
    | POST /ciba/bc-authorize   |                            |
    |  login_hint=user@example  |                            |
    |  client_notification_token=<secret>                    |
    |-------------------------->|                            |
    |  { auth_req_id, expires_in: 120 }                     |
    |<--------------------------|                            |
    |                           | AuthenticationDevice.Notify(CIBARequest)
    |                           |--------------------------->|
    |                           |                            | User taps "Approve"
    |                           |<---------------------------|
    |                           |                            |
    |                           | POST client_notification_endpoint
    |<--------------------------|  Authorization: Bearer <client_notification_token>
    |  { auth_req_id, ... }     |  { auth_req_id }           |
    |                           |                            |
    | POST /ciba/token          |                            |
    |  auth_req_id=...          |                            |
    |-------------------------->|                            |
    |  { access_token, ... }    |                            |
    |<--------------------------|                            |
```

Push mode (where the AS delivers the token directly to the client notification
endpoint) is not supported in v2.4. Use Poll or Ping.

## The `AuthenticationDevice` interface

Implement this interface to deliver the out-of-band authentication request to
the user's device:

```go
type AuthenticationDevice interface {
    // Notify delivers a CIBA authentication request to the user.
    // Return a non-nil error if the user cannot be reached.
    // The AS records a failed notification in the audit log.
    Notify(ctx context.Context, req CIBARequest) error
}

type CIBARequest struct {
    // AuthReqID is the opaque handle for this request.
    AuthReqID string
    // UserID is the theauth user ID resolved from the login hint.
    UserID string
    // Scope is the requested scope set.
    Scope []string
    // BindingMessage is an optional operator-supplied short string
    // (e.g., "TX-1234") displayed on both the consumption device and
    // the authentication device to let the user correlate them.
    BindingMessage string
    // ExpiresAt is when this auth request expires.
    ExpiresAt time.Time
}
```

A minimal push-notification implementation using Firebase Cloud Messaging:

```go
type FCMDevice struct {
    fcmClient *fcm.Client
}

func (d *FCMDevice) Notify(ctx context.Context, req theauth.CIBARequest) error {
    _, err := d.fcmClient.Send(ctx, &fcm.Message{
        Topic: "user-" + req.UserID,
        Data: map[string]string{
            "auth_req_id":     req.AuthReqID,
            "binding_message": req.BindingMessage,
            "scope":           strings.Join(req.Scope, " "),
        },
    })
    return err
}
```

## Configuration

```go
cfg := theauth.Config{
    AuthorizationServer: &theauth.AuthorizationServerConfig{
        Issuer: "https://auth.example.com",
        CIBA: &theauth.CIBAConfig{
            // AuthenticationDevice is called when a bc-authorize request
            // is received. Required.
            AuthenticationDevice: &myFCMDevice{},
            // ExpiresIn is the auth_req_id lifetime (default: 120s).
            ExpiresIn: 120 * time.Second,
            // PollingInterval is the minimum poll interval in seconds
            // returned to clients (default: 5).
            PollingInterval: 5,
        },
    },
}
```

## Endpoints

### `POST /ciba/bc-authorize`

Initiates a backchannel authentication request.

| Parameter | Required | Notes |
|---|---|---|
| `login_hint` | Yes (one of) | User email or ID. |
| `id_token_hint` | Yes (one of) | An ID token previously issued to this client. |
| `scope` | Yes | Space-separated scope list. |
| `binding_message` | No | Short string shown on both devices for correlation. |
| `client_notification_token` | Ping mode only | Token the AS uses when POSTing to your notification endpoint. |

Response (200 OK):

```json
{
  "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac9",
  "expires_in": 120,
  "interval": 5
}
```

### `POST /ciba/token`

Redeems an `auth_req_id` for an access token.

| Parameter | Required | Notes |
|---|---|---|
| `grant_type` | Yes | `urn:openid:params:grant-type:ciba` |
| `auth_req_id` | Yes | Handle from bc-authorize. |

Returns `authorization_pending` (slow down if hitting the interval) or the
standard token response on approval.

## Error responses

| Error | Meaning |
|---|---|
| `authorization_pending` | User has not yet approved. Poll again after `interval` seconds. |
| `slow_down` | Client is polling too fast. Increase poll interval by 5s. |
| `access_denied` | User denied the request. |
| `expired_token` | The `auth_req_id` has expired. |

## See also

- [JWT-Bearer client auth](jwt-bearer.md)
- [PAR + JAR](par-jar.md)
- [Configuration reference](../reference/configuration.md)
- RFC 9509: OAuth 2.0 Client-Initiated Backchannel Authentication
