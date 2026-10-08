# doctor-admin

Serves `/healthz` publicly and a root-only `/admin/security` page that renders the report from `Doctor`, the configuration auditor. Access is gated with `RequireAbility(theauth.AbilityRoot)`.

## Run

```bash
go run .
```

It listens on `:8080` with in-memory storage and the bootstrap flow enabled; `BASE_URL` overrides the origin. See [Security doctor](https://docs.theauth.dev/go/guides/security-doctor).
