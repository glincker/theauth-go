package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/admin"
	internalulid "github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const auditQueryAction = "parity.audit_query"

type auditPage struct {
	Events     []theauth.AuditEvent `json:"events"`
	Next       string               `json:"next"`
	NextCursor string               `json:"next_cursor"`
}

// seedAuditRows writes n rows of auditQueryAction for the fixture organization, in order. The row at
// index i gets the event names[i%len(names)] ("" for none). It returns the ids in write order.
func seedAuditRows(t *testing.T, fx adminFixture, n int, names ...string) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		org := fx.orgID
		ev := theauth.AuditEvent{
			ID: internalulid.New(), OrganizationID: &org, Action: auditQueryAction,
			TargetType: "t", TargetID: "x", CreatedAt: time.Now(),
		}
		if len(names) > 0 {
			ev.Event = names[i%len(names)]
		}
		if err := fx.store.InsertAuditEvents(t.Context(), []theauth.AuditEvent{ev}); err != nil {
			t.Fatalf("InsertAuditEvents: %v", err)
		}
		ids = append(ids, ev.ID.String())
	}
	return ids
}

func queryAuditPage(t *testing.T, fx adminFixture, params url.Values) (int, auditPage, map[string]any) {
	t.Helper()
	params.Set("action", auditQueryAction)
	path := "/admin/v1/organizations/" + fx.orgID.String() + "/audit?" + params.Encode()
	resp, body := fx.do(t, http.MethodGet, path, fx.ownerTok, nil)
	var page auditPage
	var problem map[string]any
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatalf("decode page: %v body=%s", err, body)
		}
	} else if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("decode problem: %v body=%s", err, body)
	}
	return resp.StatusCode, page, problem
}

func pageIDs(p auditPage) []string {
	out := make([]string, 0, len(p.Events))
	for _, e := range p.Events {
		out = append(out, e.ID.String())
	}
	return out
}

func TestAdminAuditOrderAscAndDesc(t *testing.T) {
	fx := newAdminFixture(t)
	written := seedAuditRows(t, fx, 5)
	reversed := slices.Clone(written)
	slices.Reverse(reversed)
	tests := []struct {
		name  string
		order string
		want  []string
	}{
		{"default is desc", "", reversed},
		{"explicit desc", "desc", reversed},
		{"asc", "asc", written},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := url.Values{"limit": {"50"}}
			if tc.order != "" {
				params.Set("order", tc.order)
			}
			status, page, problem := queryAuditPage(t, fx, params)
			if status != http.StatusOK {
				t.Fatalf("status=%d problem=%v", status, problem)
			}
			if got := pageIDs(page); !slices.Equal(got, tc.want) {
				t.Fatalf("ids=%v want %v", got, tc.want)
			}
		})
	}
}

func TestAdminAuditCursorRoundTripAcrossPages(t *testing.T) {
	fx := newAdminFixture(t)
	written := seedAuditRows(t, fx, 5)
	reversed := slices.Clone(written)
	slices.Reverse(reversed)
	for _, tc := range []struct {
		order string
		want  []string
	}{{"asc", written}, {"desc", reversed}} {
		t.Run("order "+tc.order, func(t *testing.T) {
			var got []string
			cursor := ""
			for pages := 0; pages < 10; pages++ {
				params := url.Values{"limit": {"2"}, "order": {tc.order}}
				if cursor != "" {
					params.Set("cursor", cursor)
				}
				status, page, problem := queryAuditPage(t, fx, params)
				if status != http.StatusOK {
					t.Fatalf("status=%d problem=%v", status, problem)
				}
				got = append(got, pageIDs(page)...)
				if page.NextCursor != page.Next {
					t.Fatalf("next_cursor %q and next %q must match", page.NextCursor, page.Next)
				}
				if page.NextCursor == "" || len(page.Events) < 2 {
					break
				}
				cursor = page.NextCursor
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("paged ids=%v want %v", got, tc.want)
			}
		})
	}
}

func TestAdminAuditLegacyCursorStillWorksForDesc(t *testing.T) {
	fx := newAdminFixture(t)
	seedAuditRows(t, fx, 3)
	_, first, _ := queryAuditPage(t, fx, url.Values{"limit": {"3"}})
	if len(first.Events) != 3 {
		t.Fatalf("got %d events", len(first.Events))
	}
	// A cursor minted before write order existed: "<created_at micros>:<id>" of the newest row.
	newest := first.Events[0]
	legacy := admin.EncodeCursor(newest.CreatedAt, newest.ID)
	status, page, problem := queryAuditPage(t, fx, url.Values{"cursor": {legacy}, "limit": {"10"}})
	if status != http.StatusOK {
		t.Fatalf("legacy desc cursor: status=%d problem=%v", status, problem)
	}
	if len(page.Events) != 2 {
		t.Fatalf("legacy cursor returned %d events, want the 2 older rows", len(page.Events))
	}
	status, _, problem = queryAuditPage(t, fx, url.Values{"cursor": {legacy}, "order": {"asc"}})
	if status != http.StatusBadRequest || problem["code"] != "pagination.bad_cursor" {
		t.Fatalf("legacy cursor with asc: status=%d problem=%v", status, problem)
	}
}

func TestAdminAuditBadInputs(t *testing.T) {
	fx := newAdminFixture(t)
	seedAuditRows(t, fx, 2)
	_, ascPage, _ := queryAuditPage(t, fx, url.Values{"limit": {"1"}, "order": {"asc"}})
	tests := []struct {
		name     string
		params   url.Values
		wantCode string
	}{
		{"garbage cursor", url.Values{"cursor": {"garbage"}}, "pagination.bad_cursor"},
		{"garbage c1 cursor", url.Values{"cursor": {"c1.AAAA.AAAA"}}, "pagination.bad_cursor"},
		{"asc cursor reused for desc", url.Values{"cursor": {ascPage.NextCursor}}, "pagination.bad_cursor"},
		{"unknown order", url.Values{"order": {"sideways"}}, "validation.invalid"},
		{"uppercase order", url.Values{"order": {"ASC"}}, "validation.invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _, problem := queryAuditPage(t, fx, tc.params)
			if status != http.StatusBadRequest {
				t.Fatalf("status=%d problem=%v", status, problem)
			}
			if problem["code"] != tc.wantCode {
				t.Fatalf("code=%v want %s", problem["code"], tc.wantCode)
			}
			if problem["status"] != float64(http.StatusBadRequest) {
				t.Fatalf("problem body is not the standard format: %v", problem)
			}
		})
	}
}

func TestAdminAuditEventFilter(t *testing.T) {
	fx := newAdminFixture(t)
	seedAuditRows(t, fx, 6, "authorize", "", "policy.evaluate")
	tests := []struct {
		event string
		want  int
	}{
		{"authorize", 2},
		{"policy.evaluate", 2},
		{"vault.read", 0},
		{"", 6},
	}
	for _, tc := range tests {
		t.Run("event "+tc.event, func(t *testing.T) {
			params := url.Values{"limit": {"50"}}
			if tc.event != "" {
				params.Set("event", tc.event)
			}
			status, page, problem := queryAuditPage(t, fx, params)
			if status != http.StatusOK {
				t.Fatalf("status=%d problem=%v", status, problem)
			}
			if len(page.Events) != tc.want {
				t.Fatalf("got %d events, want %d", len(page.Events), tc.want)
			}
			for _, e := range page.Events {
				if tc.event != "" && e.Event != tc.event {
					t.Fatalf("event %q leaked into %q filter", e.Event, tc.event)
				}
			}
		})
	}
}

// hidesAuditOrder wraps a store so the optional AuditOrderSupported flag is not visible, like a
// custom backend written before write order existed.
type hidesAuditOrder struct{ theauth.Storage }

func TestAdminAuditBackendWithoutWriteOrderFailsClearly(t *testing.T) {
	fx := newAdminFixtureWithStorage(t, func(s *memory.Store) theauth.Storage { return hidesAuditOrder{s} })
	seedAuditRows(t, fx, 3, "authorize")
	for _, tc := range []struct {
		name   string
		params url.Values
	}{
		{"order asc", url.Values{"order": {"asc"}}},
		{"event filter", url.Values{"event": {"authorize"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _, problem := queryAuditPage(t, fx, tc.params)
			if status != http.StatusBadRequest || problem["code"] != "validation.invalid" {
				t.Fatalf("status=%d problem=%v, want a 400 validation.invalid, not silently ignored", status, problem)
			}
			if detail, _ := problem["detail"].(string); detail == "" {
				t.Fatalf("problem has no detail: %v", problem)
			}
		})
	}
	status, page, problem := queryAuditPage(t, fx, url.Values{"limit": {"50"}})
	if status != http.StatusOK || len(page.Events) != 3 {
		t.Fatalf("plain desc query: status=%d events=%d problem=%v", status, len(page.Events), problem)
	}
}

func TestQueryAuditWithoutWriteOrderReturnsSentinel(t *testing.T) {
	fx := newAdminFixtureWithStorage(t, func(s *memory.Store) theauth.Storage { return hidesAuditOrder{s} })
	_, _, err := fx.auth.QueryAudit(t.Context(), theauth.AuditQuery{Order: theauth.AuditOrderAsc})
	if err != theauth.ErrAuditOrderUnsupported {
		t.Fatalf("err=%v want ErrAuditOrderUnsupported", err)
	}
}
