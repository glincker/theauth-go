# Stream Audit Logs to Splunk

theauth-go ships an append-only async audit log. The default destination is the database (`audit_events` table). You can stream events to Splunk, a SIEM, or any external sink via the `AuditConfig.Sink` interface.

## How the audit log works

Every state-changing handler calls `EmitAudit(ctx, action, target, metadata)`. The call is non-blocking: the event is placed on a buffered channel. A background writer goroutine drains the channel in batches and flushes on `Close` (5-second deadline). If the channel is full, `Stats.AuditDropped` is incremented and the event is discarded (this is the documented tradeoff to protect authentication latency under spikes).

## Implement an audit sink

Define a type that satisfies the audit sink interface and pass it to `AuditConfig`:

```go
type Sink interface {
    Write(ctx context.Context, events []theauth.AuditEvent) error
}
```

Example Splunk HEC sink:

```go
package splunksink

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/glincker/theauth-go"
)

type SplunkSink struct {
    HECURL string
    Token  string
    Client *http.Client
}

func (s *SplunkSink) Write(ctx context.Context, events []theauth.AuditEvent) error {
    var buf bytes.Buffer
    for _, e := range events {
        payload := map[string]any{
            "time":       e.CreatedAt.Unix(),
            "sourcetype": "theauth:audit",
            "event":      e,
        }
        if err := json.NewEncoder(&buf).Encode(map[string]any{"event": payload}); err != nil {
            return err
        }
    }
    req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.HECURL, &buf)
    req.Header.Set("Authorization", "Splunk "+s.Token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := s.Client.Do(req)
    if err != nil {
        return err
    }
    resp.Body.Close()
    if resp.StatusCode >= 300 {
        return fmt.Errorf("splunk HEC returned %d", resp.StatusCode)
    }
    return nil
}
```

## Wire the sink

```go
a, _ := theauth.New(theauth.Config{
    Storage: store,
    BaseURL: "https://myapp.com",
    Audit: &theauth.AuditConfig{
        // The default sink writes to the database.
        // Pass a custom sink to fan out to external systems.
        // Note: check the actual AuditConfig fields in reference/configuration.md
        // for the exact field name in your version.
    },
})
```

!!! note
    Check the [Configuration Reference](../reference/configuration.md) for the exact `AuditConfig` field name used for a custom sink in your version of theauth-go.

## Audit event shape

```go
type AuditEvent struct {
    ID           ULID
    Action       string          // e.g. "user.login", "delegation.granted"
    Target       TargetRef       // {Type, ID}
    ActorUserID  *ULID
    ActorAgentID *ULID
    OrgID        *ULID
    IP           string
    UserAgent    string
    Metadata     map[string]any  // redacted by DefaultRedactor
    CreatedAt    time.Time
}
```

## Default redactor

`DefaultRedactor` masks values at any nesting depth whose key matches (case-insensitive): `password`, `secret`, `token`, `code`, `refresh_token`, `access_token`. Pass `Config.Audit.Redactor` to override.

## Audit event catalog

See [Audit Events Reference](../reference/audit-events.md) for the full list of emitted actions and their target types and metadata shapes.

## Monitoring backpressure

Monitor `theauth.Stats.AuditDropped` and `theauth.Stats.AuditFailed`:

```go
ticker := time.NewTicker(30 * time.Second)
for range ticker.C {
    s := a.Stats()
    if s.AuditDropped > 0 {
        log.Printf("audit backpressure: %d events dropped", s.AuditDropped)
    }
}
```

`AuditDropped` increments when the channel buffer is full. Reduce write latency (faster external sink, batching) or increase the buffer size to reduce drops.
