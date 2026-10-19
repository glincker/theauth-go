# Performance

This page records what was measured on the authorization hot paths, what was changed because of it, and what was left alone. Every number comes from a Go benchmark or an `EXPLAIN` that is in the repository, so you can rerun it. It states the noise of each run, because the machine was not quiet.

## How to read the numbers

| | |
| --- | --- |
| Machine | Apple M4 Max, 14 cores, macOS, Go 1.26.5 (one laptop) |
| Databases | SQLite through `modernc.org/sqlite`, Postgres 14 on the same machine |
| Load | Other work was running. The load average was between 8 and 18 on 14 cores during the runs |
| Method | `go test -bench ... -benchmem -count 6`, then the best of the samples for before and after |
| Noise column | How far the median of the samples sat above the best one, before and after. A large value means that row is unreliable |

Take the speedups as the direction and rough size of a change, not as figures to quote. One laptop, a busy one, says little about your hardware. Rows that show 0.9x to 1.1x are within noise: those code paths were not touched. The "before" numbers come from the tree as it was at the start of this work, with the same benchmark files, so each pair compares the same loop.

The benchmarks live next to the code they measure:

- `policy/glob_bench_test.go`, `policy/eval_bench_test.go`
- `policy/pathmatch/pathmatch_bench_test.go`
- `agentpolicy/agentpolicy_bench_test.go`
- `policy/toolguard/approval_hash_bench_test.go`
- `mcpresource/validator_bench_test.go`
- `iot/mqttauth/bench_test.go`, `iot/mqttauth/sqlstore_bench_test.go` (Postgres, set `THEAUTH_TEST_PG_DSN`)
- `storage/sqlite/mqttauth_sqlstore_bench_test.go`

Run one package the way these numbers were taken, and compare two runs with `benchstat`:

```bash
go test -run xxx -bench . -benchmem -count 6 ./policy/pathmatch > new.txt
benchstat old.txt new.txt
```

## Where the time went

### Policy matching and evaluation

`policy.Match` is the glob matcher behind every action pattern. It already allocated nothing and runs in 10 to 35 ns, so it was left alone. Evaluating a request (`Evaluator.Evaluate`) lost its per statement allocations: a statement that matched but was not the one returned no longer builds a decision on the heap, statements are read in place instead of copied, and a condition only builds its expanded value list when a value contains a `{var}` placeholder.

| Benchmark | Before | After | Speedup | Allocs per op | Bytes per op | Noise before / after |
|---|---|---|---|---|---|---|
| Authorize | 381 ns | 348 ns | 1.09x | 5 to 4 | 160 to 48 | 1% / 3% |
| AuthorizeDefaultDeny | 145 ns | 120 ns | 1.20x | 0 to 0 | 0 to 0 | 1% / 1% |
| MatchExact | 10 ns | 11 ns | 0.92x | 0 to 0 | 0 to 0 | 3% / 3% |
| MatchManyStars | 20 ns | 22 ns | 0.89x | 0 to 0 | 0 to 0 | 7% / 9% |
| MatchMiddleStar | 20 ns | 20 ns | 0.96x | 0 to 0 | 0 to 0 | 1% / 13% |
| MatchMiss | 32 ns | 34 ns | 0.92x | 0 to 0 | 0 to 0 | 4% / 4% |
| MatchPrefixStar | 21 ns | 22 ns | 0.94x | 0 to 0 | 0 to 0 | 1% / 2% |

### Path matching and the delegation check

`pathmatch.MatchColon` and `MatchPath` split the pattern and the resource on every call. They now walk the strings in place, and the per segment path matcher keeps its work arrays on the stack for up to 32 path parts. `PermissionSubset`, the check that a child agent holds no more than its parent, calls these matchers once per parent and child pair, so it gains the same way.

| Benchmark | Before | After | Speedup | Allocs per op | Bytes per op | Noise before / after |
|---|---|---|---|---|---|---|
| MatchColonExact | 70 ns | 24 ns | 2.88x | 2 to 0 | 128 to 0 | 1% / 3% |
| MatchColonMiss | 70 ns | 25 ns | 2.78x | 2 to 0 | 128 to 0 | 1% / 418% |
| MatchColonStar | 65 ns | 18 ns | 3.61x | 2 to 0 | 112 to 0 | 0% / 2% |
| MatchPathDoubleStar | 160 ns | 87 ns | 1.83x | 4 to 0 | 208 to 0 | 1% / 2% |
| MatchPathDoubleStarMid | 179 ns | 101 ns | 1.77x | 4 to 0 | 224 to 0 | 1% / 2% |
| MatchPathExact | 51 ns | 15 ns | 3.48x | 2 to 0 | 64 to 0 | 2% / 45% |
| MatchPathMiss | 165 ns | 88 ns | 1.88x | 4 to 0 | 208 to 0 | 1% / 3% |
| MatchPathSegmentWildcard | 151 ns | 79 ns | 1.92x | 4 to 0 | 192 to 0 | 2% / 3% |
| PermissionSubset/colon | 1.9 us | 459 ns | 4.20x | 82 to 0 | 2672 to 0 | 2% / 1% |
| PermissionSubset/path | 2.3 us | 672 ns | 3.41x | 86 to 0 | 2832 to 0 | 1% / 1% |
| ResourcesOverlapPath | 221 ns | 236 ns | 0.94x | 8 to 8 | 320 to 320 | 1% / 1% |

### Agent policy decisions

`agentpolicy.Engine.Decide` hashed the JSON of every policy on every call. The JSON of the static base policies is now encoded once when the engine is built, and one clock read serves all queries of a call. The hash is byte for byte the same value, and a test pins it to an independent SHA-256 of the documents.

| Benchmark | Before | After | Speedup | Allocs per op | Bytes per op | Noise before / after |
|---|---|---|---|---|---|---|
| DecideDefault | 2.5 us | 1.4 us | 1.73x | 25 to 19 | 1979 to 1080 | 2% / 24% |
| DecidePathMode | 3.0 us | 1.7 us | 1.81x | 43 to 19 | 2764 to 1080 | 1% / 21% |
| DecideResolver | 2.8 us | 2.2 us | 1.25x | 38 to 33 | 2900 to 2322 | 2% / 2% |
| DecideSingleQuery | 1.4 us | 616 ns | 2.26x | 14 to 11 | 1225 to 664 | 1% / 4% |

### Approval hash canonicalization

`toolguard.HashApprovalAction` produced the canonical JSON by encoding the arguments, decoding them, fixing the numbers and encoding again. For arguments made of plain Go values (maps, slices, strings, numbers, booleans, nil) it now writes the canonical form in one pass. Anything it is not sure about, such as a struct, a pointer, invalid UTF-8 or a fraction held in a `json.Number`, goes to the old path, which is kept as the reference. The digest is unchanged: the 50 shared vectors replay in both decodings, and a differential test compares the two paths on 20,000 random argument sets, including odd strings (HTML characters, U+2028, control bytes, invalid UTF-8), every number shape and reserved keys.

| Benchmark | Before | After | Speedup | Allocs per op | Bytes per op | Noise before / after |
|---|---|---|---|---|---|---|
| HashApprovalNested | 6.7 us | 851 ns | 7.89x | 154 to 3 | 6365 to 144 | 2% / 1% |
| HashApprovalNil | 559 ns | 133 ns | 4.22x | 15 to 2 | 832 to 128 | 2% / 13% |
| HashApprovalSmall | 2.1 us | 281 ns | 7.44x | 52 to 2 | 2833 to 128 | 0% / 1% |

### Token validation for MCP resource servers

Validation is dominated by the signature check. A bare Ed25519 verification takes about 29 us on this machine, out of 33 us for the bearer path. The DPoP path adds an ES256 verification of about 38 us, so two signature checks make up 67 of its 77 us. A revocation checker that answers from memory adds under 1 us, and the built in device revocation check with a warm introspection cache adds about 1 us as well. The profile shows no lock contention (the JWKS and introspection caches already read under a shared lock). Nothing was changed here, and the table is the record that the numbers were taken.

| Benchmark | Before | After | Speedup | Allocs per op | Bytes per op | Noise before / after |
|---|---|---|---|---|---|---|
| ValidateBearer | 32.7 us | 32.6 us | 1.01x | 34 to 34 | 3421 to 3422 | 1% / 2% |
| ValidateBearerParallel | 4.8 us | 4.3 us | 1.11x | 36 to 36 | 3773 to 3774 | 10% / 32% |
| ValidateBearerRevocation | 33.3 us | 32.9 us | 1.01x | 35 to 35 | 3438 to 3438 | 1% / 2% |
| ValidateDPoP | 75.6 us | 76.8 us | 0.98x | 117 to 117 | 9156 to 9156 | 1% / 2% |
| ValidateDPoPRevocation | 76.4 us | 76.9 us | 0.99x | 118 to 118 | 9348 to 9348 | 2% / 3% |
| ValidateTopicName | 15 ns | 15 ns | 0.99x | 0 to 0 | 0 to 0 | 1% / 4% |

### MQTT broker authorization

The broker calls `/authz` on every publish and subscribe. Four things were costing time:

- `MemoryStore` looked a device up by sorting every ID and scanning. It now keeps a map by ID and one index each for subject and certificate fingerprint, so a lookup and the uniqueness check in `PutDevice` are map accesses. With 10,000 devices a lookup went from about 1.1 ms to about 150 ns.
- The decision and device cache sat behind one mutex. It is now 16 shards, each with a read write lock, keyed by device ID so a purge still touches one shard. The expiry and the purge rules did not change: an entry still lives at most `CacheTTL`, and `Purge` and `PurgeAll` still drop state at once. A cache sized below 128 entries keeps one shard, so small limits evict exactly as before.
- The counters took a mutex on every increment. They now read under a shared lock and add atomically.
- Topic matching, filter validation and the placeholder substitution in rules allocated on every call. They now allocate nothing on the common path. Matching is checked against the old code on about 2.4 million filter and topic pairs.

| Benchmark | Before | After | Speedup | Allocs per op | Bytes per op | Noise before / after |
|---|---|---|---|---|---|---|
| AuthorizeCached | 168 ns | 174 ns | 0.96x | 1 to 1 | 48 to 48 | 1% / 2% |
| AuthorizeUncached | 4.7 us | 373 ns | 12.54x | 33 to 6 | 4048 to 560 | 6% / 3% |
| AuthorizeUncachedBigRegistry | 992.7 us | 388 ns | 2557.78x | 33 to 6 | 166096 to 560 | 0% / 4% |
| CacheDecisionHit | 42 ns | 43 ns | 0.97x | 0 to 0 | 0 to 0 | 1% / 1% |
| CacheParallel | 389 ns | 46 ns | 8.46x | 0 to 0 | 0 to 0 | 1% / 7% |
| FilterCovers | 67 ns | 22 ns | 2.97x | 2 to 0 | 112 to 0 | 2% / 1% |
| FiltersOverlap | 76 ns | 34 ns | 2.21x | 2 to 0 | 128 to 0 | 2% / 1% |
| MatchTopic | 84 ns | 27 ns | 3.14x | 2 to 0 | 144 to 0 | 1% / 1% |
| MatchTopicMiss | 81 ns | 13 ns | 6.07x | 2 to 0 | 144 to 0 | 2% / 2% |
| MemoryStoreDeviceByID/10 | 376 ns | 120 ns | 3.13x | 4 to 3 | 592 to 432 | 5% / 1% |
| MemoryStoreDeviceByID/1000 | 82.7 us | 158 ns | 523.88x | 5 to 4 | 16819 to 435 | 1% / 39% |
| MemoryStoreDeviceByID/10000 | 1.10 ms | 149 ns | 7370.41x | 5 to 4 | 164276 to 436 | 1% / 105% |
| MemoryStoreDeviceBySubject | 83.6 us | 160 ns | 523.76x | 4 to 3 | 16816 to 432 | 1% / 11% |
| ParseSubscription | 107 ns | 39 ns | 2.75x | 1 to 0 | 64 to 0 | 2% / 0% |
| PolicyPublishAllow | 1.1 us | 914 ns | 1.25x | 23 to 18 | 1088 to 672 | 1% / 2% |
| PolicyPublishDeny | 1.1 us | 1.0 us | 1.13x | 25 to 22 | 912 to 752 | 3% / 4% |
| PolicySubscribeWildcard | 1.5 us | 1.3 us | 1.18x | 34 to 27 | 1376 to 880 | 4% / 2% |
| RulePublishAllow | 1.2 us | 173 ns | 6.94x | 28 to 2 | 1824 to 80 | 1% / 2% |
| RulePublishDeny | 1.2 us | 153 ns | 7.56x | 28 to 2 | 1776 to 80 | 1% / 2% |
| RuleSubscribeWildcard | 1.3 us | 248 ns | 5.39x | 34 to 3 | 1992 to 104 | 3% / 3% |
| ServeAuthzHTTP | 1.7 us | 1.7 us | 1.01x | 24 to 24 | 1777 to 1777 | 2% / 3% |
| ServeAuthzHTTPParallel | 2.8 us | 679 ns | 4.18x | 25 to 24 | 4180 to 1789 | 8% / 3% |
| ValidateTopicName | 15 ns | 15 ns | 1.00x | 0 to 0 | 0 to 0 | 1% / 1% |

The serial `ServeAuthzHTTP` row did not move: it is dominated by decoding the request JSON. The parallel row improved because the counters and the cache no longer serialize the cores.

### SQL device store

`SQLStore` read the device row and its certificate fingerprints in two round trips. It now reads both with one `LEFT JOIN`, and the Postgres placeholder rewrite is memoized instead of redone on every call. The subject lookup also gained a predicate that lets it use its index (see below).

| Benchmark | Before | After | Speedup | Allocs per op | Bytes per op | Noise before / after |
|---|---|---|---|---|---|---|
| SQLStorePostgres/AuthorizeUncached | 59.3 us | 58.7 us | 1.01x | 135 to 86 | 7232 to 4388 | 15% / 49% |
| SQLStorePostgres/DeviceByCertFingerprint | 65.2 us | 59.7 us | 1.09x | 105 to 81 | 5600 to 4192 | 7% / 9% |
| SQLStorePostgres/DeviceByID | 59.4 us | 37.4 us | 1.59x | 106 to 83 | 5360 to 4208 | 12% / 11% |
| SQLStorePostgres/DeviceBySubject | 66.0 us | 41.8 us | 1.58x | 106 to 83 | 5392 to 4224 | 14% / 8% |
| MQTTSQLStore/DeviceByCertFingerprint | 18.0 us | 18.1 us | 1.00x | 81 to 67 | 2848 to 2400 | 2% / 1% |
| MQTTSQLStore/DeviceByID | 15.4 us | 15.6 us | 0.99x | 81 to 67 | 2848 to 2400 | 2% / 3% |
| MQTTSQLStore/DeviceBySubject | 316.8 us | 17.0 us | 18.60x | 82 to 68 | 2880 to 2432 | 1% / 3% |

## Indexes

Every hot lookup was checked with `EXPLAIN QUERY PLAN` on SQLite. On Postgres the index list was checked for each of them, and the approval and MQTT queries were run with `EXPLAIN ANALYZE` on generated data (500,000 approvals, 200,000 devices). These already use an index and were left alone: session, API token, SCIM token, opaque token and refresh token by hash, device code and device authorization by hash, registration and join token by hash, IoT device by ID, SPIFFE ID and key thumbprint, approval by ID, the approval consume statement and approval votes.

Three plans did not hold up, and one of them needed a migration.

| Query | Plan before | Plan after | Cost before | Cost after |
|---|---|---|---|---|
| Tool approval admin list (`ORDER BY created_at DESC LIMIT 100`), SQLite, 500,000 rows | scan and sort | index in order | 552 ms | 0.12 ms |
| Same query, Postgres, 500,000 rows | parallel scan and sort | index scan | 56 ms | 0.04 ms |
| Overdue approval sweep, SQLite | whole `expires_at` range, filtered | partial index of undecided rows | 1.7 ms | 0.04 ms |
| Same query, Postgres | whole `expires_at` range, filtered | index only scan of the partial index | 3.3 ms | 0.04 ms |
| Refresh token family by authorization code (code replay), SQLite, 200,000 rows | table scan | partial index | 18.5 ms | 0.03 ms |
| MQTT device by subject, SQLite, 10,000 devices | table scan | partial unique index | 317 us | 17 us |

The overdue sweep runs on a timer, the admin list serves the approvals inbox, and the other two are on the code replay and the JWT connect paths. Every figure in the table is the best of several runs on a freshly seeded database, not an average, and it is the cost of the statement alone.

What changed:

- Migration SQLite `0041_tool_approval_hot_indexes.sql` and Postgres `0038_tool_approval_hot_indexes` add `theauth_tool_approvals_pending_idx` (partial, only undecided approvals) and `theauth_tool_approvals_created_idx`. On Postgres the partial index is 176 kB where the full `expires_at` index is 11 MB. Both are additive and use `IF NOT EXISTS`. MySQL has no partial indexes, so it has its own migration, `0039_tool_approval_hot_indexes` (see below).
- MySQL `0039_tool_approval_hot_indexes` adds `theauth_tool_approvals_created_idx (created_at DESC, id ASC)` for the admin list and `theauth_tool_approvals_pending_idx (approved_at, consumed_at, denied_at, expired_at, expires_at, id)` for the overdue sweep. With no partial index, the four decision columns lead the key: the sweep tests them with `IS NULL`, which MySQL reads as an equality prefix, then ranges on `expires_at` and reads in `expires_at, id` order with no sort. The number follows 0038 (device purge events). 0035 was never used on MySQL and the migrator orders by file name, so the gap is harmless. Measured with `EXPLAIN ANALYZE` on MySQL 8.4.11 in Docker, 500,000 approvals of which 250 are undecided (the overdue sweep then has 99,001 older decided rows to get past), one run each: the admin list (`LIMIT 100`) went from a table scan and sort at 168 ms to an index read at 0.56 ms (0.22 ms with every column selected), and the sweep from walking 99,001 index entries at 249 ms to 0.04 ms (0.41 ms with every column selected, which adds the 100 row lookups). Cost of the index: every approval row gets one more entry in each index, so the table writes a little more per insert and per decision. Approvals are low volume, so we judged that a fair trade. These are single runs, not best of several like the table above, so read them as the order of magnitude.
- The refresh family query and the MQTT subject query had a partial index that the planner could not use, because a bound parameter does not prove the index condition (`auth_code_hash <> ''`, `subject <> ''`). Adding the same condition to the query fixes it, with no schema change and no change in what the query returns. Postgres picks the index when it plans with the literal value, but a generic plan scanned 200,000 rows in 9.1 ms in a test, so the condition is there for both.
- `storage/sqlite/hot_query_plans_test.go` pins the plan of these lookups, so a dropped index or an unprovable condition fails a test.

## What was not changed

- No cache was added and no cache lifetime was lengthened. The MQTT cache is bounded by `CacheTTL` as before, and `Purge` is immediate. The only new state is the 16 shard split, which keeps the same expiry and purge behavior.
- Signature checks, DPoP replay handling, revocation checks and the deny rules are untouched. The faster code paths return the same decisions: the shared pathmatch vectors (8,100 pattern and resource pairs) and the subset vectors, the 50 approval hash vectors, and oracle tests that keep the old implementations and compare them with the new ones on large generated corpora all pass.
- Parts of the cost remain: JSON decoding in the HTTP handler, the two policy evaluations the policy authorizer makes per topic (one for the resource and one for the parent level), and the signature math in token validation.

## Reproduce the index measurements

The plan test runs with `go test ./storage/sqlite -run TestHotQueryPlans`. For Postgres, migrate a scratch database with `postgres.Migrate`, load rows with `generate_series`, run `ANALYZE`, then `EXPLAIN (ANALYZE, BUFFERS)` the statements from `storage/postgres/postgres_toolapprovals_admin.go`. The MQTT store benchmarks run against a scratch Postgres with `THEAUTH_TEST_PG_DSN` set, and against SQLite with `go test ./storage/sqlite -bench MQTTSQLStore`.
