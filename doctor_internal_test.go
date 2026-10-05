package theauth

import (
	"testing"
	"time"
)

func secureInput() doctorInput {
	return doctorInput{
		BaseURL: "https://app.example.com", SecureCookie: true,
		RateLimitPerIP: 5, TrustedProxies: 1,
		GraceFailures: 3, UserMaxFailures: 10, MFAMaxFailures: 5,
		PasswordMinLength: 12, HasBreachChecker: true,
		BootstrapOn: true, UserCount: 1, OAuthSignupPolicy: OAuthSignupClosed,
		TOTPEnabled: true, WebAuthnEnabled: true, AdminCount: unknownCount, AdminsWithoutMF: unknownCount,
		SessionTTL: 24 * time.Hour, IdleTimeout: time.Hour,
		TokensKnown: true, SessionsExpired: unknownCount,
		EncryptionKeyLen: 32, AuditConfigured: true, AuditSinkCount: 1,
		HasProviders: true, OAuthReturnTo: 1,
	}
}

func TestDoctorChecks(t *testing.T) {
	cases := []struct {
		name  string
		id    string
		sev   Severity
		insec func(*doctorInput)
	}{
		{"signup open", DoctorSignupOpen, SeverityMedium, func(i *doctorInput) { i.BootstrapOn = false }},
		{"signup open via reopen", DoctorSignupOpen, SeverityMedium, func(i *doctorInput) { i.BootstrapOpen = true }},
		{"signup open via oauth", DoctorSignupOpen, SeverityMedium, func(i *doctorInput) { i.OAuthSignupPolicy = OAuthSignupOpen }},
		{"bootstrap off zero users", DoctorBootstrapOff, SeverityCritical, func(i *doctorInput) { i.BootstrapOn = false; i.UserCount = 0 }},
		{"proxies empty", DoctorTrustedProxies, SeverityMedium, func(i *doctorInput) { i.TrustedProxies = 0 }},
		{"cookie insecure", DoctorSecureCookie, SeverityHigh, func(i *doctorInput) { i.BaseURL = "http://app.example.com"; i.SecureCookie = false }},
		{"csrf off", DoctorCSRFDisabled, SeverityHigh, func(i *doctorInput) { i.CSRFDisabled = true }},
		{"throttle off", DoctorThrottleDisabled, SeverityHigh, func(i *doctorInput) { i.ThrottleDisabled = true }},
		{"throttle lax", DoctorThrottleLax, SeverityMedium, func(i *doctorInput) { i.UserMaxFailures = 500 }},
		{"min length", DoctorPasswordMinLength, SeverityMedium, func(i *doctorInput) { i.PasswordMinLength = 8 }},
		{"no breach checker", DoctorPasswordNoBreach, SeverityInfo, func(i *doctorInput) { i.HasBreachChecker = false }},
		{"admin no totp", DoctorAdminNoTOTP, SeverityHigh, func(i *doctorInput) { i.AdminCount = 2; i.AdminsWithoutMF = 1 }},
		{"no second factor", DoctorNoSecondFactor, SeverityMedium, func(i *doctorInput) { i.TOTPEnabled = false; i.WebAuthnEnabled = false }},
		{"session ttl", DoctorSessionTTLLong, SeverityMedium, func(i *doctorInput) { i.SessionTTL = 90 * 24 * time.Hour }},
		{"no idle", DoctorSessionNoIdle, SeverityLow, func(i *doctorInput) { i.IdleTimeout = 0 }},
		{"token no expiry", DoctorTokenNoExpiry, SeverityHigh, func(i *doctorInput) { i.TokensNoExpiry = 2 }},
		{"token beyond year", DoctorTokenLongExpiry, SeverityMedium, func(i *doctorInput) { i.TokensBeyondYear = 1 }},
		{"token root", DoctorTokenRoot, SeverityHigh, func(i *doctorInput) { i.TokensRoot = 1 }},
		{"agent token long", DoctorAgentTokenLong, SeverityMedium, func(i *doctorInput) { i.AgentTokensLong = 1 }},
		{"tokens unpruned", DoctorTokensUnpruned, SeverityInfo, func(i *doctorInput) { i.TokensExpired = 3 }},
		{"sessions unpruned", DoctorSessionsUnpruned, SeverityInfo, func(i *doctorInput) { i.SessionsExpired = 3 }},
		{"key missing with providers", DoctorEncryptionKey, SeverityHigh, func(i *doctorInput) { i.EncryptionKeyLen = 0; i.EncryptionNeeded = true }},
		{"key short unused", DoctorEncryptionKey, SeverityLow, func(i *doctorInput) { i.EncryptionKeyLen = 16 }},
		{"audit missing", DoctorAuditSink, SeverityLow, func(i *doctorInput) { i.AuditConfigured = false }},
		{"audit no sink", DoctorAuditSink, SeverityLow, func(i *doctorInput) { i.AuditSinkCount = 0 }},
		{"rpid mismatch", DoctorWebAuthnRPID, SeverityHigh, func(i *doctorInput) { i.WebAuthnConfigured = true; i.WebAuthnRPID = "other.com" }},
		{"redirect allowlist", DoctorRedirectAllowList, SeverityInfo, func(i *doctorInput) { i.OAuthReturnTo = 0 }},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.id] = true
		t.Run(tc.name+"/secure", func(t *testing.T) {
			rep := buildReport(secureInput())
			for _, f := range rep.Findings {
				if f.ID == tc.id {
					t.Fatalf("secure config produced %s", tc.id)
				}
			}
		})
		t.Run(tc.name+"/insecure", func(t *testing.T) {
			in := secureInput()
			tc.insec(&in)
			var got *Finding
			for _, f := range buildReport(in).Findings {
				if f.ID == tc.id {
					f := f
					got = &f
				}
			}
			if got == nil {
				t.Fatalf("expected finding %s", tc.id)
			}
			if got.Severity != tc.sev {
				t.Fatalf("severity %s, want %s", got.Severity, tc.sev)
			}
			if got.Title == "" || got.Detail == "" || got.Remediation == "" || got.DocsAnchor == "" {
				t.Fatalf("incomplete finding: %+v", got)
			}
		})
	}
	for _, id := range DoctorFindingIDs() {
		if !covered[id] {
			t.Errorf("finding %s has no table case", id)
		}
	}
	if got := buildReport(secureInput()).Findings; len(got) != 0 {
		t.Fatalf("secure baseline should be clean, got %+v", got)
	}
}

func TestDoctorSecureCookieLocalhostExempt(t *testing.T) {
	in := secureInput()
	in.BaseURL, in.SecureCookie = "http://localhost:8080", false
	for _, f := range buildReport(in).Findings {
		if f.ID == DoctorSecureCookie {
			t.Fatal("localhost must not be flagged")
		}
	}
}

func TestDoctorWebAuthnParentDomainOK(t *testing.T) {
	in := secureInput()
	in.WebAuthnConfigured, in.WebAuthnRPID = true, "example.com"
	for _, f := range buildReport(in).Findings {
		if f.ID == DoctorWebAuthnRPID {
			t.Fatal("parent domain RP ID must be accepted")
		}
	}
}

func TestDoctorUnknownCapabilitiesSkipped(t *testing.T) {
	in := secureInput()
	in.TokensKnown = false
	in.TokensNoExpiry, in.TokensRoot = 5, 5
	in.UserCount = unknownCount
	in.BootstrapOn = false
	in.OAuthSignupPolicy = OAuthSignupClosed
	for _, f := range buildReport(in).Findings {
		switch f.ID {
		case DoctorTokenNoExpiry, DoctorTokenRoot, DoctorBootstrapOff:
			t.Fatalf("%s must be skipped when its data is unavailable", f.ID)
		}
	}
}

func TestTallyTokens(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	revoked := now
	toks := []APIToken{
		{CreatedAt: now, ExpiresAt: nil},
		{CreatedAt: now, ExpiresAt: at(400 * 24 * time.Hour)},
		{CreatedAt: now, ExpiresAt: at(time.Hour), Abilities: []string{"read", AbilityRoot}},
		{CreatedAt: now, ExpiresAt: at(48 * time.Hour), Kind: APITokenKindAgent},
		{CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: at(-time.Hour)},
		{CreatedAt: now, ExpiresAt: nil, RevokedAt: &revoked},
	}
	in := doctorInput{Now: now}
	tallyTokens(&in, toks)
	if in.TokensNoExpiry != 1 || in.TokensBeyondYear != 1 || in.TokensRoot != 1 || in.AgentTokensLong != 1 || in.TokensExpired != 1 {
		t.Fatalf("tally wrong: %+v", in)
	}
}
