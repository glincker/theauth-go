# Device fleet conformance kit

`iot/fleet` runs a fleet of simulated devices against a real in process theauth-go authorization server and its real HTTP handlers, with a deterministic virtual clock. It is the Go twin of the TypeScript kit (`@glinr/theauth/testing/devices`, documented in `device-conformance-kit.mdx` of the TypeScript repo). Use it to check device code and policy when devices go offline, drift in time or get revoked, or as a fixed set of scenarios to compare a verifier against. Nothing in it imports `testing`.

```go
f, err := fleet.New(ctx, fleet.Options{Size: 100})
if err != nil {
	log.Fatal(err)
}
defer f.Close()
report := f.Run(ctx)
for _, s := range report.Scenarios {
	fmt.Println(s.Name, s.Checks, s.Failures)
}
```

`fleet.New` builds the server (memory store, `DeviceTokens` on), mints one bulk join token and enrolls every device through `POST /oauth/devices/challenge` and `/oauth/devices/enroll` with its own ES256 key. A device then mints tokens with the RFC 7523 assertion grant, signed with its own clock. The handlers' per address rate limiter stays on: loopback is a trusted proxy and each device presents its own address in `X-Forwarded-For`.

`f.Clock` is the Clock of the authorization server, so token, challenge and replay windows read it. It does not replace `time.Now` process wide, and the HTTP client and the limiter still use real time. `f.Clock.Advance(2 * time.Hour)` moves a run forward; `device.SetSkew(10 * time.Minute)` makes one device's clock run fast.

## What differs from the TypeScript kit

- The Go server mints scoped access tokens and has no per action authorize route. The "assertion" scenario therefore asks the token endpoint: a granted scope gets a token, an ungranted scope is refused with `invalid_scope`.
- Offline policy bundles and revocation snapshots are issued by the TypeScript core in production. The kit plays a Go gateway acting as a local issuer (`iot/device` `Signer`) behind the same assertion check, with the same formats, so the device side code under test (`device.VerifyBundle`, `device.Evaluate`, `device.VerifyRevocations`) is the real one.
- One extra scenario, suspend and resume.

## Scenarios

1. enrollment: every device has a distinct id.
2. assertion: a granted scope gets a token, an ungranted one `invalid_scope`.
3. bundle and snapshot: the bundle and snapshot verify on the device, and the offline decision allows a granted action and denies an ungranted one.
4. clock skew: a device 10 seconds fast or slow is accepted, one 10 minutes off is refused with `invalid_grant`. Running this against the Go server found that the device grant refused a clock one second fast, because `Config.ClockSkew` defaults to zero. The grant now tolerates 30 seconds when the skew is zero, like the TypeScript device module.
5. rollback: an older bundle presented after a newer one was accepted is refused.
6. offline and online: offline devices cannot reach the server but decide from the bundle; past the bundle lifetime they fail closed; back online they fetch a new bundle and recover.
7. suspend and resume: a suspended device gets no token and no bundle, a resumed one works again.
8. revocation mid session: revoked devices are refused tokens and bundles, healthy devices are unaffected, and a snapshot fetched afterwards lists exactly the revoked devices. A device that keeps an old snapshot learns of a revocation only when it fetches a new one or the snapshot passes the maximum age you give `VerifyBundle`.

## Measured numbers

Command: `go run ./iot/fleet/cmd/fleetbench 1000`. It runs all eight scenarios with 1000 devices (12,163 checks, all passing).

Environment: one process, Go 1.26.5, in memory storage, loopback HTTP, Apple M4 Max with 36 GB of RAM, macOS. Three runs on one laptop, no real network and no database round trip, so read the figures as the cost of the library code and not of a deployed service. 25 devices act at a time, so each latency includes waiting behind other devices. Ranges are the lowest and highest of the three runs.

| Operation | Calls | p50 | p99 |
| --- | --- | --- | --- |
| enroll (challenge, proof, enroll) | 1000 | 0.9 to 1.8 ms | 7.1 to 10.3 ms |
| token (RFC 7523 assertion grant) | 1000 | 1.4 to 1.5 ms | 4.6 to 6.0 ms |
| fetch bundle and snapshot | 1000 | 1.1 to 1.4 ms | 5.6 to 7.2 ms |
| verify bundle and snapshot (device side) | 1000 | 0.10 ms | 1.7 to 2.1 ms |
| decide offline (verify, then evaluate) | 1000 | 0.09 ms | 1.4 to 2.3 ms |

Setup (enrolling 1000 devices) took 0.1 s and the whole run 0.8 to 0.9 s. Heap in use went from 1.2 MB to 28 MB and the memory the Go runtime obtained from the OS (`MemStats.Sys`, an upper bound on resident memory, not the resident size) from 8 MB to 145 MB, sampled at the end without forcing a collection.

These are single laptop runs, and the TypeScript kit numbers in its own doc come from a different runtime and database, so do not read the two columns as a language comparison. Rerun the command on your hardware before you plan capacity from it.
