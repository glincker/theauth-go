## Summary

2-3 sentences describing what this PR does and why. Link the issue it closes: `Closes #<number>`

## Type of change

- [ ] feat: new feature
- [ ] fix: bug fix
- [ ] perf: performance improvement
- [ ] refactor: no behavior change
- [ ] docs: documentation only
- [ ] test: new or updated tests / fuzz targets
- [ ] chore: tooling, CI, dependency update
- [ ] breaking-change: public API or Storage interface change

## Related issues

`Closes #`

## Test plan

How was this tested? Include the commands you ran and what you verified.

```bash
go test -race ./...
go vet ./...
```

## Public API impact

- [ ] No public API change
- [ ] Yes -- describe what changed:

(If yes, confirm [STABILITY.md](STABILITY.md) is updated and `CHANGELOG.md` has an entry under `[Unreleased]`.)

## Storage migration

- [ ] No storage changes
- [ ] Yes -- migration file path:

## mcpresource go.mod impact

- [ ] No change to `mcpresource/go.mod`
- [ ] Yes -- describe why (must be intentional and reviewed carefully):

## Documentation updated

- [ ] No documentation changes needed
- [ ] Yes -- files updated:

## Checklist

- [ ] `go test -race ./...` passes locally
- [ ] `go vet ./...` passes locally
- [ ] New behavior is covered by tests (unit or storagetest contract)
- [ ] No `any` types added; no `fmt.Println` in production paths
- [ ] CHANGELOG.md updated under `[Unreleased]` (for feat/fix/perf/breaking)

## Em-dash check

- [ ] Confirmed: no em dashes (--) or en dashes (-) appear in any changed files (project convention -- use commas, periods, or parentheses instead)

## Notes for reviewer

Anything that needs extra context: tradeoffs, alternative approaches considered, follow-up issues.
