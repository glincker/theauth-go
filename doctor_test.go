package theauth_test

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
)

var updateGolden = flag.Bool("update-doctor-golden", false, "rewrite doctor golden files")

func TestDoctorRoute(t *testing.T) {
	e := newTokenEnv(t, nil)
	e.addUser("admin", theauth.AbilityRoot)
	e.addUser("plain", "read")
	adminTok, _ := e.mint("admin", theauth.AbilityRoot)
	plainTok, _ := e.mint("plain", "read")

	if code, _ := e.rawDo("GET", "/auth/admin/doctor", nil, ""); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := e.rawDo("GET", "/auth/admin/doctor", nil, plainTok); code != 403 {
		t.Fatalf("non admin: %d", code)
	}
	code, body := e.rawDo("GET", "/auth/admin/doctor", nil, adminTok)
	if code != 200 {
		t.Fatalf("admin: %d %s", code, body)
	}
	if strings.Contains(body, adminTok) || strings.Contains(strings.ToLower(body), "hash") {
		t.Fatalf("report leaks secret material: %s", body)
	}
	var rep theauth.Report
	if err := json.Unmarshal([]byte(body), &rep); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, f := range rep.Findings {
		ids[f.ID] = true
	}
	for _, want := range []string{theauth.DoctorSignupOpen, theauth.DoctorTrustedProxies, theauth.DoctorAuditSink, theauth.DoctorTokenRoot} {
		if !ids[want] {
			t.Errorf("expected %s in %v", want, ids)
		}
	}
	if rep.Summary[theauth.SeverityHigh] == 0 {
		t.Errorf("summary missing high count: %v", rep.Summary)
	}
}

func TestDoctorReportGolden(t *testing.T) {
	rep := theauth.Report{
		GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Summary:     map[theauth.Severity]int{"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
		Findings: []theauth.Finding{{
			ID: "csrf.disabled", Severity: theauth.SeverityHigh, Title: "CSRF protection is disabled",
			Detail: "detail", Remediation: "fix", DocsAnchor: "security-doctor.md#csrf-disabled",
		}},
	}
	got, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	const path = "testdata/doctor_report.golden.json"
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("golden mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestDoctorDocsListEveryFinding(t *testing.T) {
	b, err := os.ReadFile("docs/SECURITY-DOCTOR.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, id := range theauth.DoctorFindingIDs() {
		if !strings.Contains(doc, "| `"+id+"` |") {
			t.Errorf("docs table missing %s", id)
		}
		if !strings.Contains(doc, `<a id="`+strings.ReplaceAll(id, ".", "-")+`"></a>`) {
			t.Errorf("docs anchor missing for %s", id)
		}
	}
}
