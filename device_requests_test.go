package theauth_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type pendingRow struct {
	ID                 string   `json:"id"`
	ClientName         string   `json:"clientName"`
	RequestedAbilities []string `json:"requestedAbilities"`
	RequesterIP        string   `json:"requesterIp"`
	RequesterUserAgent string   `json:"requesterUserAgent"`
}

func (e *tokenEnv) listRequests(who string) (int, string, []pendingRow) {
	e.t.Helper()
	code, body := e.rawDo("GET", "/auth/device/requests", e.cookies[who], "")
	var out struct {
		Requests []pendingRow `json:"requests"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	return code, body, out.Requests
}

func TestDevicePendingList(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("admin", "root")
	e.addUser("bob", "read")

	t.Run("lists only pending unexpired and never leaks secrets", func(t *testing.T) {
		pending := e.deviceStart("read")
		approved := e.deviceStart("read")
		denied := e.deviceStart("read")
		redeemed := e.deviceStart("read")
		if got := e.deviceApprove("bob", approved["user_code"].(string), "approve"); got != 204 {
			t.Fatalf("approve: %d", got)
		}
		if got := e.deviceApprove("bob", denied["user_code"].(string), "deny"); got != 204 {
			t.Fatalf("deny: %d", got)
		}
		if got := e.deviceApprove("bob", redeemed["user_code"].(string), "approve"); got != 204 {
			t.Fatalf("approve: %d", got)
		}
		if status, out := e.devicePoll(redeemed["device_code"].(string)); status != 200 {
			t.Fatalf("redeem: %d %v", status, out)
		}

		code, body, rows := e.listRequests("bob")
		if code != 200 || len(rows) != 1 {
			t.Fatalf("list: %d rows=%d body=%s", code, len(rows), body)
		}
		if rows[0].ClientName != "laptop" || rows[0].RequesterUserAgent == "" || rows[0].RequesterIP == "" {
			t.Fatalf("row lacks requester details: %+v", rows[0])
		}
		for _, secret := range []string{
			pending["device_code"].(string), pending["user_code"].(string),
			strings.ReplaceAll(pending["user_code"].(string), "-", ""),
			approved["user_code"].(string), "device_code", "user_code", "userCode", "Hash", "hash",
		} {
			if strings.Contains(body, secret) {
				t.Fatalf("response leaks %q: %s", secret, body)
			}
		}

		e.advance(11 * time.Minute)
		if _, _, rows := e.listRequests("bob"); len(rows) != 0 {
			t.Fatalf("expired request still listed: %+v", rows)
		}
	})

	t.Run("bearer token and anonymous callers are rejected", func(t *testing.T) {
		raw, _ := e.mint("admin", "root")
		start := e.deviceStart("read")
		_ = start
		_, _, rows := e.listRequests("admin")
		if len(rows) != 1 {
			t.Fatalf("setup: %d rows", len(rows))
		}
		for _, tc := range []struct{ method, path string }{
			{"GET", "/auth/device/requests"},
			{"POST", "/auth/device/requests/" + rows[0].ID + "/approve"},
			{"POST", "/auth/device/requests/" + rows[0].ID + "/deny"},
		} {
			if code, _ := e.rawDo(tc.method, tc.path, nil, raw); code != 401 {
				t.Fatalf("bearer %s %s: %d, want 401", tc.method, tc.path, code)
			}
			if code, _ := e.rawDo(tc.method, tc.path, nil, ""); code != 401 {
				t.Fatalf("anonymous %s %s: %d, want 401", tc.method, tc.path, code)
			}
		}
		if _, _, rows := e.listRequests("admin"); len(rows) != 1 {
			t.Fatalf("rejected calls changed state: %+v", rows)
		}
	})
}

func TestDeviceApproveByIDMatchesUserCode(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("admin", "root")
	e.addUser("bob", "read")

	scopeOf := func(start map[string]any) (int, any) {
		status, out := e.devicePoll(start["device_code"].(string))
		return status, out["scope"]
	}
	idOf := func() string {
		_, _, rows := e.listRequests("bob")
		if len(rows) != 1 {
			t.Fatalf("want one pending row, got %+v", rows)
		}
		return rows[0].ID
	}

	byCode := e.deviceStart("read deploy")
	if got := e.deviceApprove("bob", byCode["user_code"].(string), "approve"); got != 204 {
		t.Fatalf("approve by code: %d", got)
	}
	codeStatus, codeScope := scopeOf(byCode)

	byID := e.deviceStart("read deploy")
	if code, _ := e.rawDo("POST", "/auth/device/requests/"+idOf()+"/approve", e.cookies["bob"], ""); code != 204 {
		t.Fatalf("approve by id: %d", code)
	}
	idStatus, idScope := scopeOf(byID)
	if codeStatus != idStatus || codeScope != idScope || idScope != "read" {
		t.Fatalf("outcomes differ: code=%d %v id=%d %v", codeStatus, codeScope, idStatus, idScope)
	}

	rootReq := e.deviceStart("root")
	rootID := idOf()
	if code, _ := e.rawDo("POST", "/auth/device/requests/"+rootID+"/approve", e.cookies["bob"], ""); code != 403 {
		t.Fatalf("root by non-root: %d, want 403", code)
	}
	if code, _ := e.rawDo("POST", "/auth/device/requests/"+rootID+"/approve", e.cookies["admin"], ""); code != 204 {
		t.Fatalf("root by admin: %d, want 204", code)
	}
	if _, scope := scopeOf(rootReq); scope != "root" {
		t.Fatalf("scope %v, want root", scope)
	}

	deny := e.deviceStart("read")
	if code, _ := e.rawDo("POST", "/auth/device/requests/"+idOf()+"/deny", e.cookies["bob"], ""); code != 204 {
		t.Fatalf("deny by id: %d", code)
	}
	if status, out := e.devicePoll(deny["device_code"].(string)); status != 400 || out["error"] != "access_denied" {
		t.Fatalf("poll after deny: %d %v", status, out)
	}
	if code, _ := e.rawDo("POST", "/auth/device/requests/"+rootID+"/approve", e.cookies["admin"], ""); code != 404 {
		t.Fatalf("decided request again: %d, want 404", code)
	}
	if code, _ := e.rawDo("POST", "/auth/device/requests/not-an-id/approve", e.cookies["bob"], ""); code != 404 {
		t.Fatalf("bad id: %d, want 404", code)
	}
}

func TestDeviceConcurrentApproveDenyOneWins(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("admin", "root")
	for round := 0; round < 20; round++ {
		start := e.deviceStart("read")
		_, _, rows := e.listRequests("admin")
		if len(rows) != 1 {
			t.Fatalf("round %d: %d rows", round, len(rows))
		}
		id := rows[0].ID
		codes := make([]int, 2)
		var wg sync.WaitGroup
		for i, action := range []string{"approve", "deny"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i], _ = e.rawDo("POST", "/auth/device/requests/"+id+"/"+action, e.cookies["admin"], "")
			}()
		}
		wg.Wait()
		wins := 0
		for _, c := range codes {
			if c == 204 {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("round %d: statuses %v, want exactly one 204", round, codes)
		}
		status, out := e.devicePoll(start["device_code"].(string))
		approvedWon := codes[0] == 204
		if approvedWon && status != 200 || !approvedWon && out["error"] != "access_denied" {
			t.Fatalf("round %d: winner %v but poll gave %d %v", round, codes, status, out)
		}
	}
}
