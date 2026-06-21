# TheAuth chi-app example

Minimal runnable example demonstrating magic-link auth.

## Run it

```bash
# in-memory storage (no DB required)
go run main.go

# Postgres storage (run migrations from ../../storage/postgres/migrations first)
DATABASE_URL=postgres://user:pass@localhost:5432/yourdb go run main.go
```

Open http://localhost:8080.

1. Submit your email. The magic-link URL is logged to your terminal (default email sender is `noop`, which just prints to stdout)
2. Paste the verify URL into your browser address bar
3. You'll receive a session cookie
4. Visit `/auth/me` to see your user record
