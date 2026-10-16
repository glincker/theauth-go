# taint-guard-go

Runnable demo of the taint aware tool guard (`policy/toolguard` plus
`policy.TaintRule`). In memory, no model, no API key.

```
go run ./examples/taint-guard-go
```

A `ProvenanceTracker` labels the output of `fetch_page` as
`tool_output:fetch_page`. When the model copies an address from that page into
`send_email`, the taint rule escalates the call. A user typed address passes.
After a human approves, the retry spends the approval once, and a replay is
refused. With `Effect: policy.Deny` the call fails with
`toolguard.ErrTaintViolation`.

Set `Guard.Audit` to `(*theauth.TheAuth).EmitAudit` to record the labels and the
verdict as the input provenance of the signed audit decision record.
