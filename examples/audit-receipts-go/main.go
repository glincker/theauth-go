// Command audit-receipts-go signs a checkpoint of a real chained audit log
// (SQLite), mints a portable receipt for one decision that hides most of the
// row, verifies it offline with only the public key, then proves a later
// checkpoint extends the first. It mirrors the TypeScript example in
// sdk/examples/audit-receipts.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/glincker/theauth-go/storage/sqlite"
	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/audit/checkpoint"
	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

func main() {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:receipts?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := sqlite.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}
	store, err := sqlite.New(db)
	if err != nil {
		log.Fatal(err)
	}

	base := time.Now().UTC().Add(-time.Minute)
	record := func(n int, result string) ulid.ULID {
		e := theauth.AuditEvent{
			ID: ulid.Make(), Action: "tool.execute", TargetType: "tool", TargetID: "mcp:payments:refund",
			Metadata:  map[string]any{"orderId": fmt.Sprintf("order-%d", n), "amountCents": 4200, "result": result},
			IP:        "203.0.113.7",
			CreatedAt: base.Add(time.Duration(n) * time.Second), ActorID: "refund-worker", SubjectID: "user-alice", ApproverID: "user-alice",
		}
		if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{e}); err != nil {
			log.Fatal(err)
		}
		return e.ID
	}
	record(1, "allowed")
	decision := record(2, "allowed")
	record(3, "denied")

	// The audit key lets the operator rebuild every field salt. Keep it secret.
	lg := checkpoint.Log{Source: checkpoint.EventSource{Store: store}, SaltKey: []byte("demo-only-audit-key")}
	signer, pub, err := checkpoint.GenerateKeyPair("audit-2026-10")
	if err != nil {
		log.Fatal(err)
	}

	// Operator side: sign the log head, then mint a receipt for one decision.
	first, err := checkpoint.CreateCheckpoint(ctx, lg, checkpoint.CreateOptions{Signer: signer})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("checkpoint: size=%d root=%s...\n", first.Size, first.RootHash[:16])
	receipt, err := checkpoint.CreateReceipt(ctx, lg, decision.String(), first, []string{"action", "targetId", "createdAtMicro"})
	if err != nil {
		log.Fatal(err)
	}
	wire, err := json.Marshal(receipt)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("receipt is %d bytes and hides the metadata, ip and policy fields\n", len(wire))

	// Counterparty side: only the receipt JSON and the published public key.
	var received checkpoint.Receipt
	if err := json.Unmarshal(wire, &received); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("receipt verifies: %v\n", checkpoint.VerifyReceipt(received, pub).Valid)

	// A forged value is caught.
	forged := received
	forged.Decision.Revealed = map[string]checkpoint.RevealedField{}
	for k, v := range received.Decision.Revealed {
		forged.Decision.Revealed[k] = v
	}
	f := forged.Decision.Revealed["targetId"]
	f.Value = "mcp:payments:wire-transfer"
	forged.Decision.Revealed["targetId"] = f
	fmt.Printf("forged receipt verifies: %v (%s)\n", checkpoint.VerifyReceipt(forged, pub).Valid, checkpoint.VerifyReceipt(forged, pub).Reason)

	// Later: the log grew. Prove the new head extends the old one.
	record(4, "allowed")
	second, err := checkpoint.CreateCheckpoint(ctx, lg, checkpoint.CreateOptions{Signer: signer})
	if err != nil {
		log.Fatal(err)
	}
	proof, err := checkpoint.CreateConsistencyProof(ctx, lg, first, second)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("newer checkpoint (size %d) extends the older: %v\n", second.Size, checkpoint.VerifyConsistencyProof(proof, first, second, pub).Valid)
}
