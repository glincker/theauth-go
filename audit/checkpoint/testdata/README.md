# Interop fixtures

These files pin the Go package to the TypeScript SDK (`packages/core/src/audit/checkpoint*.ts`).

- `ts-fixture.json`: written by the TypeScript SDK from a real SQLite audit chain (v1 and v2 rows, odd JSON values). Holds the rows, keys (test only, including private seeds), checkpoints, all inclusion proofs, a consistency proof, receipts, and 26 tampering cases with the TypeScript verifier's result. `TestTSFixtureVerifies` checks Go gives the same outcome for each. `TestTSFixtureRebuilt` rebuilds checkpoint, proofs and receipts in Go from the rows and requires the same bytes, signature included (Ed25519 is deterministic).
- `ts-merkle-vectors.json`: TypeScript roots and path digests for tree sizes 1 to 33 (`TestMerkleMatchesTSVectors`).
- `go-fixture.json`: written by Go, to be verified by the TypeScript verifiers.

## Regenerate the TypeScript fixtures

```sh
mkdir sdk/packages/core/.tmp-ex
cp go/audit/checkpoint/testdata/gen-ts-fixture.ts sdk/packages/core/.tmp-ex/gen.ts
cd sdk/packages/core
npx tsx .tmp-ex/gen.ts "$PWD/../../../go/audit/checkpoint/testdata/ts-fixture.json"
rm -rf .tmp-ex
```

`ts-merkle-vectors.json` came from a short script over `inclusionPath`, `consistencyPath` and `merkleRoot` (leaf i is the leaf hash of the ASCII bytes `leaf-i`; digests are SHA-256 over all inclusion paths in index order and all consistency paths for old sizes 0..n).

## Regenerate and check the Go fixture

```sh
cd go
THEAUTH_WRITE_GO_FIXTURE=1 go test -run TestWriteGoFixture ./audit/checkpoint
mkdir sdk/packages/core/.tmp-ex
cp go/audit/checkpoint/testdata/verify-go-fixture.ts sdk/packages/core/.tmp-ex/
cd sdk/packages/core
npx tsx .tmp-ex/verify-go-fixture.ts "$PWD/../../../go/audit/checkpoint/testdata/go-fixture.json"
rm -rf .tmp-ex
```

The script prints `33 checks run, 0 failures` when the TypeScript SDK accepts every Go proof and rejects every Go tampering case with the expected reason.
