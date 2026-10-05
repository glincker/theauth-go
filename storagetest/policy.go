package storagetest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/glincker/theauth-go/policy"
)

const contractDoc = `{"version":"1","statements":[{"id":"s","effect":"allow","actions":["a:*"],"resources":["*"]}]}`

// RunPolicy runs the policy.Storage contract tests.
func RunPolicy(t *testing.T, store policy.Storage) {
	t.Helper()
	ctx := context.Background()
	pfx := newID().String()
	id := func(n string) string { return pfx + "-" + n }

	t.Run("PutGetUpsert", func(t *testing.T) {
		if err := store.PutPolicy(ctx, policy.Record{ID: id("p1"), Name: "one", Document: []byte(contractDoc)}); err != nil {
			t.Fatalf("PutPolicy: %v", err)
		}
		got, err := store.GetPolicy(ctx, id("p1"))
		if err != nil || got.Name != "one" || string(got.Document) != contractDoc || got.CreatedAt.IsZero() {
			t.Fatalf("GetPolicy = %+v, %v", got, err)
		}
		created := got.CreatedAt
		if err := store.PutPolicy(ctx, policy.Record{ID: id("p1"), Name: "renamed", Document: []byte(contractDoc)}); err != nil {
			t.Fatalf("PutPolicy upsert: %v", err)
		}
		got, _ = store.GetPolicy(ctx, id("p1"))
		if got.Name != "renamed" || !got.CreatedAt.Equal(created) {
			t.Fatalf("upsert changed CreatedAt or ignored name: %+v", got)
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		if _, err := store.GetPolicy(ctx, id("nope")); !errors.Is(err, policy.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("ListOrdered", func(t *testing.T) {
		for _, n := range []string{"b", "a"} {
			if err := store.PutPolicy(ctx, policy.Record{ID: id("l-" + n), Document: []byte(contractDoc)}); err != nil {
				t.Fatal(err)
			}
		}
		all, err := store.ListPolicies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ia, ib := -1, -1
		for i, r := range all {
			switch r.ID {
			case id("l-a"):
				ia = i
			case id("l-b"):
				ib = i
			}
			if i > 0 && all[i-1].ID > r.ID {
				t.Fatalf("not ordered by ID at %d", i)
			}
		}
		if ia < 0 || ib < 0 || ia > ib {
			t.Fatalf("missing or misordered: a=%d b=%d", ia, ib)
		}
	})

	t.Run("AttachQueryDetach", func(t *testing.T) {
		u := policy.Subject{Kind: policy.SubjectUser, ID: id("u")}
		tok := policy.Subject{Kind: policy.SubjectToken, ID: id("t")}
		if err := store.AttachPolicy(ctx, u, id("nope")); !errors.Is(err, policy.ErrNotFound) {
			t.Fatalf("attach unknown policy: %v", err)
		}
		for i := 0; i < 2; i++ {
			if err := store.AttachPolicy(ctx, u, id("p1")); err != nil {
				t.Fatalf("AttachPolicy (idempotent): %v", err)
			}
		}
		if err := store.AttachPolicy(ctx, tok, id("l-a")); err != nil {
			t.Fatal(err)
		}
		got, err := store.PoliciesFor(ctx, []policy.Subject{u, tok, u})
		if err != nil || len(got) != 2 {
			t.Fatalf("PoliciesFor = %d, %v", len(got), err)
		}
		if got[0].Record.ID != id("l-a") || got[0].Subject != tok || got[1].Subject != u {
			t.Fatalf("unexpected order or subjects: %+v", got)
		}
		none, _ := store.PoliciesFor(ctx, []policy.Subject{{Kind: policy.SubjectGroup, ID: id("g")}})
		if len(none) != 0 {
			t.Fatalf("unattached subject returned %d", len(none))
		}
		if err := store.DetachPolicy(ctx, u, id("p1")); err != nil {
			t.Fatal(err)
		}
		if err := store.DetachPolicy(ctx, u, id("p1")); err != nil {
			t.Fatalf("DetachPolicy (idempotent): %v", err)
		}
		got, _ = store.PoliciesFor(ctx, []policy.Subject{u})
		if len(got) != 0 {
			t.Fatalf("still attached after detach: %d", len(got))
		}
	})

	t.Run("DeleteCascades", func(t *testing.T) {
		g := policy.Subject{Kind: policy.SubjectGroup, ID: id("g2")}
		if err := store.PutPolicy(ctx, policy.Record{ID: id("del"), Document: []byte(contractDoc)}); err != nil {
			t.Fatal(err)
		}
		if err := store.AttachPolicy(ctx, g, id("del")); err != nil {
			t.Fatal(err)
		}
		if err := store.DeletePolicy(ctx, id("del")); err != nil {
			t.Fatal(err)
		}
		if err := store.DeletePolicy(ctx, id("del")); err != nil {
			t.Fatalf("DeletePolicy (idempotent): %v", err)
		}
		if got, _ := store.PoliciesFor(ctx, []policy.Subject{g}); len(got) != 0 {
			t.Fatalf("attachment survived delete: %d", len(got))
		}
	})

	t.Run("DocumentIsolated", func(t *testing.T) {
		doc := []byte(contractDoc)
		if err := store.PutPolicy(ctx, policy.Record{ID: id("iso"), Document: doc}); err != nil {
			t.Fatal(err)
		}
		doc[0] = 'X'
		got, _ := store.GetPolicy(ctx, id("iso"))
		got.Document[0] = 'Y'
		again, _ := store.GetPolicy(ctx, id("iso"))
		if string(again.Document) != contractDoc {
			t.Fatal(fmt.Sprintf("stored document aliased caller bytes: %q", again.Document))
		}
	})
}
