package visitorsignal

import (
	"math"
	"slices"
	"testing"
)

const (
	chromeWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	chromeMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	androidUA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36"
	iphoneUA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	operaUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
	samsungUA = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36"
	yandexUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 YaBrowser/24.9.0 Yowser/2.5 Safari/537.36"
	edgeUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"
	firefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
)

func cleanPayload() Payload {
	return Payload{
		Mode: ModeFraudPrevention,
		Components: Components{
			Platform: ptr("Win32"), UABrand: ptr("Chrome"), UAMajor: ptr(130), Mobile: ptr(false), Lang: ptr("en-US"),
		},
	}
}

func cleanMeta() RequestMeta {
	return RequestMeta{UserAgent: chromeWin, AcceptLanguage: "en-US,en;q=0.9", SecCHUAMobile: "?0", SecCHUAPlatform: `"Windows"`}
}

func TestAssess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mut    func(*Payload, *RequestMeta)
		risk   float64
		reason []string
	}{
		{"clean", func(*Payload, *RequestMeta) {}, 0, []string{}},
		{"webdriver", func(p *Payload, _ *RequestMeta) { p.Flags.Webdriver = true }, 0.60, []string{ReasonWebdriver}},
		{"automation_globals", func(p *Payload, _ *RequestMeta) { p.Flags.AutomationGlobals = 1 }, 0.30, []string{ReasonAutomationGlobals}},
		{"headless_hint", func(p *Payload, _ *RequestMeta) { p.Flags.HeadlessHint = true }, 0.30, []string{ReasonHeadlessHint}},
		{"inconsistent", func(p *Payload, _ *RequestMeta) { p.Flags.Inconsistent = true }, 0.20, []string{ReasonInconsistent}},
		{"no_input_fraud", func(p *Payload, _ *RequestMeta) { p.Flags.NoInputObserved = true }, 0.10, []string{ReasonNoInput}},
		{"no_input_analytics_ignored", func(p *Payload, _ *RequestMeta) {
			p.Mode = ModeAnalytics
			p.Flags.NoInputObserved = true
		}, 0, []string{}},
		{"protected_browser_alone", func(p *Payload, _ *RequestMeta) { p.Flags.ProtectedBrowser = true }, 0, []string{}},
		{"ua_missing", func(p *Payload, m *RequestMeta) { m.UserAgent = "  "; m.SecCHUAPlatform = "" }, 0.30, []string{ReasonUAMissing}},
		{"ua_major_mismatch", func(p *Payload, _ *RequestMeta) { p.Components.UAMajor = ptr(129) }, 0.30, []string{ReasonUAMajorMismatch}},
		{"ua_major_firefox_ok", func(p *Payload, m *RequestMeta) {
			m.UserAgent = firefoxUA
			m.SecCHUAPlatform = ""
			p.Components.UABrand = ptr("Firefox")
			p.Components.UAMajor = ptr(131)
			p.Components.Platform = ptr("Linux x86_64")
		}, 0, []string{}},
		{"ua_major_safari_version", func(p *Payload, m *RequestMeta) {
			m.UserAgent = iphoneUA
			m.SecCHUAPlatform = ""
			m.SecCHUAMobile = "?1"
			p.Components.UABrand = ptr("Safari")
			p.Components.UAMajor = ptr(16)
			p.Components.Platform = ptr("iPhone")
			p.Components.Mobile = ptr(true)
		}, 0.30, []string{ReasonUAMajorMismatch}},
		{"ua_no_known_token_no_fire", func(p *Payload, m *RequestMeta) { m.UserAgent = "curl/8.0" }, 0, []string{}},
		{"ua_major_opera_skipped", func(p *Payload, m *RequestMeta) {
			m.UserAgent = operaUA
			p.Components.UABrand = ptr("Opera")
			p.Components.UAMajor = ptr(106)
		}, 0, []string{}},
		{"ua_major_samsung_skipped", func(p *Payload, m *RequestMeta) {
			m.UserAgent = samsungUA
			p.Components.UABrand = ptr("Samsung Internet")
			p.Components.UAMajor = ptr(23)
		}, 0, []string{}},
		{"ua_major_yandex_skipped", func(p *Payload, m *RequestMeta) {
			m.UserAgent = yandexUA
			p.Components.UABrand = ptr("Yandex")
			p.Components.UAMajor = ptr(24)
		}, 0, []string{}},
		{"ua_major_edge_chromium_major", func(p *Payload, m *RequestMeta) {
			m.UserAgent = edgeUA
			p.Components.UABrand = ptr("Microsoft Edge")
			p.Components.UAMajor = ptr(130)
		}, 0, []string{}},
		{"ua_major_edge_own_major_fires", func(p *Payload, m *RequestMeta) {
			m.UserAgent = edgeUA
			p.Components.UABrand = ptr("Microsoft Edge")
			p.Components.UAMajor = ptr(131)
		}, 0.30, []string{ReasonUAMajorMismatch}},
		{"ua_major_no_brand_skipped", func(p *Payload, _ *RequestMeta) {
			p.Components.UABrand = nil
			p.Components.UAMajor = ptr(1)
		}, 0, []string{}},
		{"platform_hint_beats_desktop_site_ua", func(p *Payload, m *RequestMeta) {
			m.UserAgent = chromeMac
			m.SecCHUAPlatform = `"Android"`
			m.SecCHUAMobile = "?0"
			p.Components.Platform = ptr("Linux armv8l")
		}, 0, []string{}},
		{"platform_hint_present_ua_ignored", func(p *Payload, m *RequestMeta) {
			m.UserAgent = chromeMac
			m.SecCHUAPlatform = `"Windows"`
		}, 0, []string{}},
		{"language_empty_header", func(p *Payload, m *RequestMeta) { m.AcceptLanguage = "" }, 0, []string{}},
		{"language_blank_header", func(p *Payload, m *RequestMeta) { m.AcceptLanguage = "  " }, 0, []string{}},
		{"mobile_mismatch", func(p *Payload, _ *RequestMeta) { p.Components.Mobile = ptr(true) }, 0.20, []string{ReasonMobileMismatch}},
		{"mobile_header_absent", func(p *Payload, m *RequestMeta) { p.Components.Mobile = ptr(true); m.SecCHUAMobile = "" }, 0, []string{}},
		{"platform_mismatch_ua", func(p *Payload, m *RequestMeta) { m.UserAgent = chromeMac; m.SecCHUAPlatform = "" }, 0.20, []string{ReasonPlatformMismatch}},
		{"platform_mismatch_hint", func(p *Payload, m *RequestMeta) { m.SecCHUAPlatform = `"macOS"` }, 0.20, []string{ReasonPlatformMismatch}},
		{"android_linux_armv_ok", func(p *Payload, m *RequestMeta) {
			m.UserAgent = androidUA
			m.SecCHUAPlatform = `"Android"`
			m.SecCHUAMobile = "?1"
			p.Components.Platform = ptr("Linux armv8l")
			p.Components.Mobile = ptr(true)
		}, 0, []string{}},
		{"language_mismatch", func(p *Payload, m *RequestMeta) { m.AcceptLanguage = "fr-FR,fr;q=0.9" }, 0.10, []string{ReasonLanguageMismatch}},
		{"language_wildcard_ok", func(p *Payload, m *RequestMeta) { m.AcceptLanguage = "*" }, 0, []string{}},
		{"language_primary_subtag_only", func(p *Payload, m *RequestMeta) { m.AcceptLanguage = "en-GB;q=0.8" }, 0, []string{}},
		{"two_reasons_in_order", func(p *Payload, m *RequestMeta) {
			p.Flags.HeadlessHint = true
			m.AcceptLanguage = "fr"
		}, 0.40, []string{ReasonHeadlessHint, ReasonLanguageMismatch}},
		{"capped_at_one", func(p *Payload, m *RequestMeta) {
			p.Flags = Flags{Webdriver: true, HeadlessHint: true, AutomationGlobals: 3, Inconsistent: true}
			m.UserAgent = ""
		}, 1, []string{ReasonWebdriver, ReasonAutomationGlobals, ReasonHeadlessHint, ReasonInconsistent, ReasonUAMissing}},
	}
	model := DefaultRiskModel()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, meta := cleanPayload(), cleanMeta()
			tc.mut(&p, &meta)
			risk, reasons := Assess(p, meta, model)
			if math.Abs(risk-tc.risk) > 1e-9 || !slices.Equal(reasons, tc.reason) {
				t.Fatalf("got %v %v, want %v %v", risk, reasons, tc.risk, tc.reason)
			}
		})
	}
}
