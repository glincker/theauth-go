package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestEventVocabularyMatchesTypeScript(t *testing.T) {
	t.Parallel()
	want := []string{
		"agent.cascade.revoked", "agent.create", "agent.revoke", "approval.approve", "approval.deny",
		"approval.request", "audit.checkpoint", "audit.erasure", "audit.write_failed", "authorize",
		"authorize.token", "delegation.create", "delegation.revoke", "mcp.tool.call",
		"policy.evaluate", "vault.read",
	}
	if got := Events(); !slices.Equal(got, want) {
		t.Fatalf("Events() = %v\nwant %v", got, want)
	}
}

func TestValidateEvent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		valid   bool
		wantErr bool
	}{
		{"authorize", true, false},
		{"mcp.tool.call", true, false},
		{"", false, false},
		{"Authorize", false, true},
		{"agent.suspended", false, true},
		{" authorize", false, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run("value "+tc.in, func(t *testing.T) {
			t.Parallel()
			if got := ValidEvent(tc.in); got != tc.valid {
				t.Fatalf("ValidEvent(%q) = %v", tc.in, got)
			}
			if err := ValidateEvent(tc.in); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateEvent(%q) = %v", tc.in, err)
			}
		})
	}
}

func TestEventForActionTable(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"agent.authorize":        "authorize",
		"agent.authorize_denied": "authorize",
		"agent.token_minted":     "authorize.token",
		"agent.token_denied":     "authorize.token",
		"policy.decision":        "policy.evaluate",
		"delegation.granted":     "delegation.create",
		"delegation.revoked":     "delegation.revoke",
		"agent.created":          "agent.create",
		"agent.revoked":          "agent.revoke",
		"agent.cascade.revoked":  "agent.cascade.revoked",
		"approval.request":       "approval.request",
		"tool_approval.approved": "approval.approve",
		"tool_approval.denied":   "approval.deny",
		"vault.token.issued":     "vault.read",
		"audit.events_dropped":   "audit.write_failed",
		"agent.suspended":        "",
		"agent.resumed":          "",
		"approval.decided":       "",
		"policy.denied":          "",
		"vault.token.denied":     "",
		"totally.unknown":        "",
		"":                       "",
	}
	for action, want := range tests {
		action, want := action, want
		t.Run("action "+action, func(t *testing.T) {
			t.Parallel()
			if got := EventForAction(action); got != want {
				t.Fatalf("EventForAction(%q) = %q, want %q", action, got, want)
			}
		})
	}
}

func TestActionEventsOnlyYieldValidEvents(t *testing.T) {
	t.Parallel()
	for action, ev := range ActionEvents() {
		if !ValidEvent(ev) {
			t.Fatalf("action %q maps to %q, not in the vocabulary", action, ev)
		}
	}
	m := ActionEvents()
	m["agent.authorize"] = "mutated"
	if EventForAction("agent.authorize") != EventAuthorize {
		t.Fatal("ActionEvents must return a copy")
	}
}

// noEventPrefixes lists action families that deliberately have no shared event.
// A new action whose name matches neither this list nor the mapping table fails
// TestEveryWrittenActionIsMappedOrDeliberatelyEmpty, so adding a writer forces a
// decision: map it or add it here.
var noEventPrefixes = []string{
	"session.", "user.", "password.", "login.", "identity.", "account.", "trusted_device.",
	"totp.", "token.", "role.", "passkey.", "organization.", "oauth.", "oauth_account.",
	"magic_link.", "jwt_bearer.", "id_jag.", "device.", "api_token.", "agent_credential.",
	"saml.", "vault.", "audit.queried",
	"agent.suspended", "agent.resumed", "agent.rate_limited", "agent.policy_resolver_failed",
	"agent.expiry_changed", "approval.decided", "policy.denied",
}

var (
	emitCall   = regexp.MustCompile(`(?:EmitAudit|emitAgentEvent|emit|changeAgentStatus)\([^"\n)]*"([a-z_]+(?:\.[a-z_]+)+)"`)
	actionLit  = regexp.MustCompile(`\bAction(?:[A-Za-z]*)?\s*(?::|=)\s*"([a-z_]+(?:\.[a-z_]+)+)"`)
	skipDirs   = map[string]bool{"docs-site": true, "examples": true, "storagetest": true, "node_modules": true, ".git": true, "testdata": true}
	scanOnce   sync.Once
	scanned    map[string][]string
	scanErr    error
	repoRootUp = "../.."
)

func scanWrittenActions(t *testing.T) map[string][]string {
	t.Helper()
	scanOnce.Do(func() {
		scanned = map[string][]string{}
		scanErr = filepath.Walk(repoRootUp, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if skipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, re := range []*regexp.Regexp{emitCall, actionLit} {
				for _, m := range re.FindAllStringSubmatch(string(src), -1) {
					scanned[m[1]] = append(scanned[m[1]], path)
				}
			}
			return nil
		})
	})
	if scanErr != nil {
		t.Fatal(scanErr)
	}
	return scanned
}

func TestEveryWrittenActionIsMappedOrDeliberatelyEmpty(t *testing.T) {
	t.Parallel()
	found := scanWrittenActions(t)
	if len(found) < 20 {
		t.Fatalf("scan found only %d action strings, the pattern is stale", len(found))
	}
	for action, files := range found {
		if _, mapped := actionEvents[action]; mapped {
			continue
		}
		deliberate := false
		for _, p := range noEventPrefixes {
			if strings.HasPrefix(action, p) {
				deliberate = true
				break
			}
		}
		if !deliberate {
			t.Errorf("action %q (written in %v) has no event mapping and is not in noEventPrefixes", action, files)
		}
	}
	for _, want := range []string{"agent.created", "delegation.granted", "agent.token_minted"} {
		if _, ok := found[want]; !ok {
			t.Errorf("scan did not find %q, the pattern is stale", want)
		}
	}
}

func TestNextRecordedAtUsStrictlyIncreasing(t *testing.T) {
	t.Parallel()
	var prev int64
	for i := 0; i < 5000; i++ {
		got := NextRecordedAtUs(0)
		if got <= prev {
			t.Fatalf("stamp %d not greater than %d at %d", got, prev, i)
		}
		prev = got
	}
	if got := NextRecordedAtUs(prev + 10_000_000); got != prev+10_000_001 {
		t.Fatalf("floor not honoured: %d", got)
	}
}

func TestNextRecordedAtUsConcurrentUnique(t *testing.T) {
	t.Parallel()
	const n, per = 8, 500
	out := make(chan int64, n*per)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				out <- NextRecordedAtUs(0)
			}
		}()
	}
	wg.Wait()
	close(out)
	seen := map[int64]bool{}
	for v := range out {
		if seen[v] {
			t.Fatalf("duplicate stamp %d", v)
		}
		seen[v] = true
	}
}
