package storagetest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
)

// AuditOrderCapable is the capability flag for audit write order. A backend returns true from
// AuditOrderSupported once it stores AuditEvent.RecordedAtUs and AuditEvent.Event and serves
// AuditQuery.Order, AuditQuery.Event and the "c1." keyset cursor. Backends that do not declare it
// skip RunAuditOrder with a message, so a released backend module is not broken by contract
// cases it cannot satisfy yet.
//
// Contract: the store assigns RecordedAtUs inside the append (a value passed in is ignored),
// strictly increasing per chain key (the organization id, or empty); rows of one batch get
// consecutive increasing stamps in slice order; rows written before the capability read back
// with Event "" and a RecordedAtUs derived from their creation time.
type AuditOrderCapable interface {
	AuditOrderSupported() bool
}

// RunAuditOrder runs the audit write order contract against store. It skips when store does not
// implement AuditOrderCapable or reports false.
func RunAuditOrder(t *testing.T, store AuditSuiteStorage) {
	t.Helper()
	c, ok := store.(AuditOrderCapable)
	if !ok || !c.AuditOrderSupported() {
		t.Skip("backend does not declare AuditOrderCapable (recorded_at_us, event, order and c1 cursors); skipping until its audit write order task lands")
	}
	t.Run("AuditOrder", func(t *testing.T) {
		t.Run("RecordedAtUsStrictlyIncreasing", func(t *testing.T) { orderRecordedIncreases(t, store) })
		t.Run("OrderAscAndDesc", func(t *testing.T) { orderAscDesc(t, store) })
		t.Run("KeysetPagingSameMicrosecond", func(t *testing.T) { orderKeysetSameMicrosecond(t, store) })
		t.Run("EventRoundTripAndFilter", func(t *testing.T) { orderEventFilter(t, store) })
		t.Run("EventNullableForOldRows", func(t *testing.T) { orderEventNullable(t, store) })
		t.Run("CursorGarbageRejected", func(t *testing.T) { orderCursorGarbage(t, store) })
		t.Run("InvalidOrderRejected", func(t *testing.T) { orderInvalidOrder(t, store) })
		t.Run("PerOrganizationChain", func(t *testing.T) { orderPerOrg(t, store) })
	})
}

// orderAction returns a unique action so the shared database can hold other suites' rows.
func orderAction(name string) string { return "storagetest.order." + name + "." + newID().String() }

func insertBatch(t *testing.T, store AuditSuiteStorage, evs []theauth.AuditEvent) {
	t.Helper()
	if err := store.InsertAuditEvents(context.Background(), evs); err != nil {
		t.Fatalf("InsertAuditEvents: %v", err)
	}
}

func queryAll(t *testing.T, store AuditSuiteStorage, q theauth.AuditQuery) []theauth.AuditEvent {
	t.Helper()
	q.Limit = 200
	got, _, err := store.QueryAuditEvents(context.Background(), q)
	if err != nil {
		t.Fatalf("QueryAuditEvents(%+v): %v", q, err)
	}
	return got
}

func idsOf(evs []theauth.AuditEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID.String()
	}
	return out
}

// pageAll follows nextCursor until it is empty or a page comes back empty, so a store that
// returns a cursor on an exactly full last page still terminates.
func pageAll(t *testing.T, store AuditSuiteStorage, q theauth.AuditQuery, size int) []theauth.AuditEvent {
	t.Helper()
	var all []theauth.AuditEvent
	q.Limit = size
	for i := 0; i < 100; i++ {
		page, next, err := store.QueryAuditEvents(context.Background(), q)
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		all = append(all, page...)
		if next == "" || len(page) == 0 {
			return all
		}
		q.After = next
	}
	t.Fatal("paging did not terminate")
	return nil
}

func orderRecordedIncreases(t *testing.T, store AuditSuiteStorage) {
	action := orderAction("increase")
	at := time.Now().Truncate(time.Millisecond)
	var wantOrder []string
	for _, n := range []int{1, 5, 1, 3} {
		batch := make([]theauth.AuditEvent, n)
		for i := range batch {
			// Same CreatedAt on every row, and a bogus caller stamp that must be ignored.
			batch[i] = theauth.AuditEvent{ID: newID(), Action: action, CreatedAt: at, RecordedAtUs: 1}
			wantOrder = append(wantOrder, batch[i].ID.String())
		}
		insertBatch(t, store, batch)
	}
	got := queryAll(t, store, theauth.AuditQuery{Action: action, Order: theauth.AuditOrderAsc})
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d rows, want %d", len(got), len(wantOrder))
	}
	var prev int64
	for i, e := range got {
		if e.RecordedAtUs <= 1 {
			t.Fatalf("row %d: RecordedAtUs = %d, the caller value must be replaced by a store stamp", i, e.RecordedAtUs)
		}
		if e.RecordedAtUs <= prev {
			t.Fatalf("row %d: RecordedAtUs %d not greater than previous %d", i, e.RecordedAtUs, prev)
		}
		prev = e.RecordedAtUs
	}
	if !slices.Equal(idsOf(got), wantOrder) {
		t.Fatalf("asc order is not write order:\n got %v\nwant %v", idsOf(got), wantOrder)
	}
}

func orderAscDesc(t *testing.T, store AuditSuiteStorage) {
	action := orderAction("ascdesc")
	batch := make([]theauth.AuditEvent, 6)
	for i := range batch {
		batch[i] = theauth.AuditEvent{ID: newID(), Action: action, CreatedAt: time.Now()}
	}
	insertBatch(t, store, batch)
	asc := idsOf(queryAll(t, store, theauth.AuditQuery{Action: action, Order: theauth.AuditOrderAsc}))
	desc := idsOf(queryAll(t, store, theauth.AuditQuery{Action: action, Order: theauth.AuditOrderDesc}))
	deflt := idsOf(queryAll(t, store, theauth.AuditQuery{Action: action}))
	if len(asc) != 6 {
		t.Fatalf("asc returned %d rows", len(asc))
	}
	rev := slices.Clone(asc)
	slices.Reverse(rev)
	if !slices.Equal(desc, rev) {
		t.Fatalf("desc is not the reverse of asc:\n asc %v\ndesc %v", asc, desc)
	}
	if !slices.Equal(deflt, desc) {
		t.Fatalf("default order must be desc:\n got %v\nwant %v", deflt, desc)
	}
}

func orderKeysetSameMicrosecond(t *testing.T, store AuditSuiteStorage) {
	at := time.UnixMicro(time.Now().UnixMicro())
	const n = 13
	for _, order := range []string{theauth.AuditOrderAsc, theauth.AuditOrderDesc} {
		order := order
		t.Run(order, func(t *testing.T) {
			// A fresh action per order, because the case below writes one more row.
			action := orderAction("keyset." + order)
			batch := make([]theauth.AuditEvent, n)
			for i := range batch {
				batch[i] = theauth.AuditEvent{ID: newID(), Action: action, CreatedAt: at}
			}
			insertBatch(t, store, batch)
			full := idsOf(queryAll(t, store, theauth.AuditQuery{Action: action, Order: order}))
			if len(full) != n {
				t.Fatalf("full read = %d rows, want %d", len(full), n)
			}
			for _, size := range []int{1, 4, 5, n, n + 1} {
				paged := idsOf(pageAll(t, store, theauth.AuditQuery{Action: action, Order: order}, size))
				if !slices.Equal(paged, full) {
					t.Fatalf("page size %d lost or repeated rows:\n got %v\nwant %v", size, paged, full)
				}
			}
			// Rows written between pages must not shift the window.
			first, next, err := store.QueryAuditEvents(context.Background(), theauth.AuditQuery{Action: action, Order: order, Limit: 4})
			if err != nil || len(first) != 4 || next == "" {
				t.Fatalf("first page: %d rows, cursor %q, %v", len(first), next, err)
			}
			insertBatch(t, store, []theauth.AuditEvent{{ID: newID(), Action: action, CreatedAt: at}})
			rest := pageAll(t, store, theauth.AuditQuery{Action: action, Order: order, After: next}, 4)
			seen := map[string]bool{}
			for _, id := range idsOf(first) {
				seen[id] = true
			}
			for _, id := range idsOf(rest) {
				if seen[id] {
					t.Fatalf("row %s repeated after a concurrent write", id)
				}
				seen[id] = true
			}
			for _, id := range full {
				if !seen[id] {
					t.Fatalf("row %s skipped after a concurrent write", id)
				}
			}
		})
	}
}

func orderEventFilter(t *testing.T, store AuditSuiteStorage) {
	action := orderAction("event")
	insertBatch(t, store, []theauth.AuditEvent{
		{ID: newID(), Action: action, Event: "authorize", CreatedAt: time.Now()},
		{ID: newID(), Action: action, Event: "policy.evaluate", CreatedAt: time.Now()},
		{ID: newID(), Action: action, Event: "authorize", CreatedAt: time.Now()},
		{ID: newID(), Action: action, CreatedAt: time.Now()},
	})
	all := queryAll(t, store, theauth.AuditQuery{Action: action, Order: theauth.AuditOrderAsc})
	if len(all) != 4 {
		t.Fatalf("got %d rows", len(all))
	}
	var events []string
	for _, e := range all {
		events = append(events, e.Event)
	}
	if want := []string{"authorize", "policy.evaluate", "authorize", ""}; !slices.Equal(events, want) {
		t.Fatalf("Event round trip = %q, want %q", events, want)
	}
	for ev, want := range map[string]int{"authorize": 2, "policy.evaluate": 1, "delegation.create": 0} {
		got := queryAll(t, store, theauth.AuditQuery{Action: action, Event: ev})
		if len(got) != want {
			t.Fatalf("filter Event=%q returned %d rows, want %d", ev, len(got), want)
		}
		for _, e := range got {
			if e.Event != ev {
				t.Fatalf("filter Event=%q returned a %q row", ev, e.Event)
			}
		}
	}
	paged := pageAll(t, store, theauth.AuditQuery{Action: action, Event: "authorize", Order: theauth.AuditOrderAsc}, 1)
	if len(paged) != 2 {
		t.Fatalf("paging with an event filter returned %d rows, want 2", len(paged))
	}
}

func orderEventNullable(t *testing.T, store AuditSuiteStorage) {
	action := orderAction("nullable")
	insertBatch(t, store, []theauth.AuditEvent{{ID: newID(), Action: action, CreatedAt: time.Now()}})
	got := queryAll(t, store, theauth.AuditQuery{Action: action})
	if len(got) != 1 || got[0].Event != "" {
		t.Fatalf("row without an event must read back with Event empty, got %+v", got)
	}
	if got[0].RecordedAtUs == 0 {
		t.Fatal("row without an event must still carry RecordedAtUs")
	}
	if n := len(queryAll(t, store, theauth.AuditQuery{Action: action, Event: "authorize"})); n != 0 {
		t.Fatalf("an event filter matched %d rows with no event", n)
	}
}

func orderCursorGarbage(t *testing.T, store AuditSuiteStorage) {
	action := orderAction("cursor")
	insertBatch(t, store, []theauth.AuditEvent{
		{ID: newID(), Action: action, CreatedAt: time.Now()},
		{ID: newID(), Action: action, CreatedAt: time.Now()},
	})
	_, asc, err := store.QueryAuditEvents(context.Background(), theauth.AuditQuery{Action: action, Order: theauth.AuditOrderAsc, Limit: 1})
	if err != nil || asc == "" {
		t.Fatalf("asc first page: cursor %q, %v", asc, err)
	}
	flipped := []byte(asc)
	flipped[len(flipped)/2] ^= 0x01
	cases := map[string]struct{ order, cursor string }{
		"not base64":         {"", "!!!garbage!!!"},
		"prefix only":        {"", "c1."},
		"no checksum":        {"", "c1.MTpmb286ZA"},
		"bad checksum":       {"", "c1.MTpmb286ZA.AAAAAA"},
		"flipped byte":       {theauth.AuditOrderAsc, string(flipped)},
		"truncated":          {theauth.AuditOrderAsc, asc[:len(asc)-4]},
		"asc cursor, desc":   {theauth.AuditOrderDesc, asc},
		"asc cursor, dflt":   {"", asc},
		"asc order, garbage": {theauth.AuditOrderAsc, "garbage"},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			_, _, err := store.QueryAuditEvents(context.Background(), theauth.AuditQuery{Action: action, Order: tc.order, After: tc.cursor, Limit: 10})
			if !errors.Is(err, theauth.ErrBadCursor) {
				t.Fatalf("cursor %q: err = %v, want ErrBadCursor", tc.cursor, err)
			}
		})
	}
}

func orderInvalidOrder(t *testing.T, store AuditSuiteStorage) {
	for _, order := range []string{"sideways", "ASC", "newest"} {
		_, _, err := store.QueryAuditEvents(context.Background(), theauth.AuditQuery{Order: order, Limit: 1})
		if !errors.Is(err, theauth.ErrBadAuditOrder) {
			t.Fatalf("Order %q: err = %v, want ErrBadAuditOrder", order, err)
		}
	}
}

// orderPerOrg checks stamps in an organization chain when the store can create one.
func orderPerOrg(t *testing.T, store AuditSuiteStorage) {
	orgs, ok := store.(theauth.OrganizationStorage)
	if !ok {
		t.Skip("store has no OrganizationStorage; per organization chain not checked")
	}
	ctx := context.Background()
	orgID := newID()
	if _, err := orgs.InsertOrganization(ctx, theauth.Organization{
		ID: orgID, Name: "order", Slug: "order-" + orgID.String(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("InsertOrganization: %v", err)
	}
	action := orderAction("org")
	var want []string
	for i := 0; i < 4; i++ {
		org := orgID
		e := theauth.AuditEvent{ID: newID(), OrganizationID: &org, Action: action, CreatedAt: time.Now()}
		want = append(want, e.ID.String())
		insertBatch(t, store, []theauth.AuditEvent{e})
	}
	got := queryAll(t, store, theauth.AuditQuery{OrganizationID: &orgID, Action: action, Order: theauth.AuditOrderAsc})
	if !slices.Equal(idsOf(got), want) {
		t.Fatalf("org chain order = %v, want %v", idsOf(got), want)
	}
	for i := 1; i < len(got); i++ {
		if got[i].RecordedAtUs <= got[i-1].RecordedAtUs {
			t.Fatalf("org chain stamps not strictly increasing at %d: %d then %d", i, got[i-1].RecordedAtUs, got[i].RecordedAtUs)
		}
	}
}
