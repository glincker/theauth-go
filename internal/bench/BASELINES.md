# theauth-go benchmark baselines

These numbers are the v0.6 reference for the five hot paths. Future PRs
that change any hot path should re-run the suite and update this file
when the delta moves more than 25% (in either direction) on the same
hardware.

## How to re-run

```
go test -bench=. -benchmem -run=^$ -benchtime=3s ./internal/bench/...
```

## Reference machine

- Hardware: Apple M4 Max
- OS: darwin (macOS), arm64
- Go: 1.25.0
- Date captured: 2026-06-20
- All adapters: in-memory (Postgres adds round-trip cost not measured here)

## Raw output

```
goos: darwin
goarch: arm64
pkg: github.com/glincker/theauth-go/internal/bench
cpu: Apple M4 Max
BenchmarkLoginPassword-14       	     132	  27097065 ns/op	67138695 B/op	     183 allocs/op
BenchmarkMagicLinkConsume-14    	  747979	      4673 ns/op	    8655 B/op	      56 allocs/op
BenchmarkOAuthCallback-14       	 4761904	       750.3 ns/op	    1376 B/op	       5 allocs/op
BenchmarkPKCEChallenge-14       	11453178	       317.1 ns/op	     240 B/op	       5 allocs/op
BenchmarkSessionLookup-14       	 1351134	      2724 ns/op	    8592 B/op	      42 allocs/op
```

## Summary table

| Benchmark              | ns/op       | B/op       | allocs/op | Notes                                    |
| ---------------------- | ----------- | ---------- | --------- | ---------------------------------------- |
| BenchmarkLoginPassword | 27,097,065  | 67,138,695 | 183       | Argon2id verify dominates                |
| BenchmarkMagicLinkConsume | 4,673    | 8,655      | 56        | Magic link request round trip            |
| BenchmarkOAuthCallback | 750         | 1,376      | 5         | AES-GCM encrypt plus in-memory upsert    |
| BenchmarkPKCEChallenge | 317         | 240        | 5         | crypto/rand 32 bytes plus SHA-256        |
| BenchmarkSessionLookup | 2,724       | 8,592      | 42        | Cookie parse plus token hash plus lookup |

## Deviations from spec defaults

The v0.6 design doc cited expected baselines from an Apple M2 in 2026.
This machine is an Apple M4 Max, roughly 3 to 4 times faster than the
M2 for CPU-bound work. The 27 ms BenchmarkLoginPassword result is
consistent with that, given the Argon2id parameters (m=64 MiB, t=3,
p=4) are unchanged.

## Regression rule

A PR that regresses any of these numbers by more than 25% on the same
reference machine must:

1. Profile the affected benchmark (`go test -bench=BenchmarkX
   -cpuprofile=cpu.out`).
2. Identify the cause: new allocations, new storage round trips, new
   crypto operations, weakened Argon2 params (should never happen), or
   genuine algorithmic change.
3. Either revert the regression or update this file with the new
   baseline and a one-paragraph justification.
