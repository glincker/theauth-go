# audit-receipts-go

Signed audit checkpoint, portable receipt and consistency proof over a real chained SQLite audit log. Go port of `sdk/examples/audit-receipts`, using `github.com/glincker/theauth-go/v2/audit/checkpoint`.

```sh
cd examples/audit-receipts-go
go run .
```

Output:

```
checkpoint: size=3 root=03e530fe0079cd3e...
receipt is 2018 bytes and hides the metadata, ip and policy fields
receipt verifies: true
forged receipt verifies: false (leaf_mismatch)
newer checkpoint (size 4) extends the older: true
```

The receipt is plain JSON and verifies the same way in the TypeScript SDK (`verifyReceipt`) as long as the rows use a TypeScript field set; rows of the Go chain use hash version 101 and their own field set, so verify those with the Go package.
