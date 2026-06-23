package storagetest

import (
	"context"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

func testAuditEvents(t *testing.T, store theauth.Storage) {
	t.Helper()
	ctx := context.Background()

	actorID := newID()

	t.Run("InsertSingle", func(t *testing.T) {
		ev := theauth.AuditEvent{
			ID:          newID(),
			ActorUserID: &actorID,
			Action:      "storagetest.single",
			CreatedAt:   time.Now(),
		}
		if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{ev}); err != nil {
			t.Fatalf("InsertAuditEvents (single): %v", err)
		}

		events, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{
			ActorUserID: &actorID,
			Action:      "storagetest.single",
			Limit:       10,
		})
		if err != nil {
			t.Fatalf("QueryAuditEvents: %v", err)
		}
		if len(events) < 1 {
			t.Fatalf("expected at least 1 event, got %d", len(events))
		}
	})

	t.Run("InsertBatch", func(t *testing.T) {
		batchActorID := newID()
		if _, err := store.CreateUser(ctx, theauth.User{
			ID:        batchActorID,
			Email:     "audit-batch@storagetest.example",
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		var events []theauth.AuditEvent
		for i := 0; i < 5; i++ {
			events = append(events, theauth.AuditEvent{
				ID:          newID(),
				ActorUserID: &batchActorID,
				Action:      "storagetest.batch",
				CreatedAt:   time.Now(),
			})
		}
		if err := store.InsertAuditEvents(ctx, events); err != nil {
			t.Fatalf("InsertAuditEvents (batch): %v", err)
		}

		got, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{
			ActorUserID: &batchActorID,
			Limit:       10,
		})
		if err != nil {
			t.Fatalf("QueryAuditEvents after batch: %v", err)
		}
		if len(got) < 5 {
			t.Fatalf("expected at least 5 events, got %d", len(got))
		}
	})

	t.Run("Pagination", func(t *testing.T) {
		pageActorID := newID()
		if _, err := store.CreateUser(ctx, theauth.User{
			ID:        pageActorID,
			Email:     "audit-page@storagetest.example",
			CreatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		// Insert 6 events with distinct timestamps.
		for i := 0; i < 6; i++ {
			ev := theauth.AuditEvent{
				ID:          newID(),
				ActorUserID: &pageActorID,
				Action:      "storagetest.page",
				CreatedAt:   time.Now().Add(time.Duration(i) * time.Millisecond),
			}
			if err := store.InsertAuditEvents(ctx, []theauth.AuditEvent{ev}); err != nil {
				t.Fatalf("InsertAuditEvents[%d]: %v", i, err)
			}
		}

		// First page: 3 events.
		page1, cursor, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{
			ActorUserID: &pageActorID,
			Limit:       3,
		})
		if err != nil {
			t.Fatalf("QueryAuditEvents page1: %v", err)
		}
		if len(page1) != 3 {
			t.Fatalf("page1: want 3 events, got %d", len(page1))
		}
		if cursor == "" {
			t.Fatal("page1: expected non-empty cursor for next page")
		}

		// Second page using cursor.
		page2, _, err := store.QueryAuditEvents(ctx, theauth.AuditQuery{
			ActorUserID: &pageActorID,
			Limit:       3,
			After:       cursor,
		})
		if err != nil {
			t.Fatalf("QueryAuditEvents page2: %v", err)
		}
		if len(page2) < 1 {
			t.Fatal("page2: expected at least 1 event after cursor")
		}

		// Verify no overlap: IDs in page2 must not appear in page1.
		p1IDs := map[theauth.ULID]struct{}{}
		for _, e := range page1 {
			p1IDs[e.ID] = struct{}{}
		}
		for _, e := range page2 {
			if _, dup := p1IDs[e.ID]; dup {
				t.Fatalf("duplicate event %s found in both pages", e.ID)
			}
		}
	})

	t.Run("EmptyBatch", func(t *testing.T) {
		// Empty insert must not error.
		if err := store.InsertAuditEvents(ctx, nil); err != nil {
			t.Fatalf("InsertAuditEvents (empty): %v", err)
		}
	})
}
