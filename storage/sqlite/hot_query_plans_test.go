package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// TestHotQueryPlans pins the SQLite plan of the lookups that run on every request or on a timer.
// Each query follows the text the store runs. A change that makes one of them scan a table (a dropped
// index, or a partial index term the planner can no longer prove) fails here.
func TestHotQueryPlans(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "plans.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, query, want string }{
		{"session token hash", `SELECT id FROM theauth_sessions WHERE token_hash = ?`, "USING INDEX theauth_sessions_token_hash_uq"},
		{"api token hash", `SELECT id FROM theauth_api_tokens WHERE token_hash = ?`, "USING INDEX theauth_api_tokens_hash_uq"},
		{"scim token hash", `SELECT id FROM theauth_scim_tokens WHERE token_hash = ?`, "theauth_scim_tokens_hash_uq"},
		{"opaque token hash", `SELECT 1 FROM theauth_oauth_opaque_access_tokens WHERE hash = ?`, "(hash=?)"},
		{"refresh token hash", `SELECT 1 FROM theauth_oauth_refresh_tokens WHERE hash = ?`, "theauth_oauth_refresh_tokens_hash_uq"},
		{"iot device by id", `SELECT 1 FROM theauth_iot_devices WHERE id = ?`, "(id=?)"},
		{"iot device by spiffe id", `SELECT 1 FROM theauth_iot_devices WHERE spiffe_id = ?`, "theauth_iot_devices_spiffe_uq"},
		{"iot device by thumbprint", `SELECT 1 FROM theauth_iot_devices WHERE key_thumbprint = ? ORDER BY created_at DESC, id DESC LIMIT 1`, "theauth_iot_devices_thumbprint_idx"},
		{"refresh family by auth code", `UPDATE theauth_oauth_refresh_tokens SET revoked_at = 1 WHERE revoked_at IS NULL AND family_id IN (SELECT family_id FROM theauth_oauth_refresh_tokens WHERE auth_code_hash = ? AND auth_code_hash <> '')`, "theauth_oauth_refresh_tokens_auth_code_idx"},
		{"approvals overdue sweep", `SELECT id FROM theauth_tool_approvals WHERE approved_at IS NULL AND consumed_at IS NULL AND denied_at IS NULL AND expired_at IS NULL AND expires_at > 0 AND expires_at <= ? ORDER BY expires_at ASC, id ASC LIMIT ?`, "theauth_tool_approvals_pending_idx"},
		{"approvals admin list", `SELECT id FROM theauth_tool_approvals ORDER BY created_at DESC, id ASC LIMIT ?`, "theauth_tool_approvals_created_idx"},
		{"approval votes", `SELECT approver FROM theauth_tool_approval_votes WHERE approval_id = ?`, "(approval_id=?)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := make([]any, strings.Count(c.query, "?"))
			for i := range args {
				args[i] = 1
			}
			rows, err := db.Query("EXPLAIN QUERY PLAN "+c.query, args...)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rows.Close() }()
			var plan []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			joined := strings.Join(plan, " | ")
			if !strings.Contains(joined, c.want) {
				t.Fatalf("plan %q does not use %q", joined, c.want)
			}
			for _, step := range plan {
				if strings.HasPrefix(step, "SCAN theauth_") && !strings.Contains(step, " USING ") {
					t.Fatalf("plan scans a table: %q", joined)
				}
			}
		})
	}
}
