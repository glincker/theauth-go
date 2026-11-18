package visitorsignal

import (
	"math"
	"testing"
)

// richComponents has 6 components so the few-components term stays off.
func richComponents() Components {
	return Components{
		TZ: ptr("UTC"), Lang: ptr("en-US"), Platform: ptr("Win32"),
		Cores: ptr(8), Caps: ptr(uint32(1)), Mobile: ptr(false),
	}
}

func TestScore(t *testing.T) {
	t.Parallel()
	m := DefaultConfidenceModel()
	with := func(mut func(*Payload)) Payload {
		p := Payload{Mode: ModeFraudPrevention, Components: richComponents()}
		mut(&p)
		return p
	}
	tests := []struct {
		name string
		p    Payload
		want float64
	}{
		{"base", with(func(*Payload) {}), 0.90},
		{"analytics", with(func(p *Payload) { p.Mode = ModeAnalytics }), 0.75},
		{"iphone", with(func(p *Payload) { p.Components.Platform = ptr("iPhone") }), 0.60},
		{"ipad", with(func(p *Payload) { p.Components.Platform = ptr("iPad") }), 0.60},
		{"mobile_safari_brand", with(func(p *Payload) {
			p.Components.Mobile = ptr(true)
			p.Components.UABrand = ptr("Safari")
		}), 0.60},
		{"android_linux_armv", with(func(p *Payload) {
			p.Components.Platform = ptr("Linux armv8l")
			p.Components.Mobile = ptr(true)
		}), 0.70},
		{"android_platform", with(func(p *Payload) {
			p.Components.Platform = ptr("Android")
			p.Components.Mobile = ptr(true)
		}), 0.70},
		{"linux_armv_not_mobile", with(func(p *Payload) { p.Components.Platform = ptr("Linux armv8l") }), 0.90},
		{"protected_browser", with(func(p *Payload) { p.Flags.ProtectedBrowser = true }), 0.60},
		{"inconsistent", with(func(p *Payload) { p.Flags.Inconsistent = true }), 0.70},
		{"one_unavailable", with(func(p *Payload) { p.Unavailable = []string{"tz"} }), 0.85},
		{"unavailable_capped", with(func(p *Payload) {
			p.Unavailable = []string{"tz", "lang", "platform", "ua", "screen", "touch", "cores"}
		}), 0.65},
		{"few_components", with(func(p *Payload) { p.Components = Components{TZ: ptr("UTC")} }), 0.80},
		{"five_components_is_few", with(func(p *Payload) { p.Components.Caps = nil }), 0.80},
		{"clamp_low", with(func(p *Payload) {
			p.Mode = ModeAnalytics
			p.Components = Components{}
			p.Flags = Flags{ProtectedBrowser: true, Inconsistent: true}
			p.Unavailable = []string{"tz", "lang", "platform", "ua", "screen"}
		}), 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Score(tc.p, m); math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScoreClampHigh(t *testing.T) {
	t.Parallel()
	m := DefaultConfidenceModel()
	m.Base = 1.5
	if got := Score(Payload{Mode: ModeFraudPrevention, Components: richComponents()}, m); got != 1 {
		t.Fatalf("got %v, want 1", got)
	}
}

func TestScoreVectors(t *testing.T) {
	t.Parallel()
	var ef struct {
		Confidence []struct {
			Name     string  `json:"name"`
			Mode     Mode    `json:"mode"`
			Platform *string `json:"platform"`
			Mobile   *bool   `json:"mobile"`
			UABrand  *string `json:"uaBrand"`
			Flags    struct {
				ProtectedBrowser bool `json:"protectedBrowser"`
				Inconsistent     bool `json:"inconsistent"`
			} `json:"flags"`
			Unavailable []string `json:"unavailable"`
			Components  int      `json:"components"`
			Score       float64  `json:"score"`
		} `json:"confidence"`
	}
	loadJSON(t, "vectors-extra.json", &ef)
	if len(ef.Confidence) != 10 {
		t.Fatalf("got %d confidence vectors, want 10", len(ef.Confidence))
	}
	for _, v := range ef.Confidence {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			c := Components{Platform: v.Platform, Mobile: v.Mobile, UABrand: v.UABrand}
			// Pad to the stated count with components the score ignores.
			pad := []func(){
				func() { c.TZ = ptr("UTC") }, func() { c.Lang = ptr("en") },
				func() { c.Cores = ptr(4) }, func() { c.Caps = ptr(uint32(1)) },
				func() { c.ColorDepth = ptr(24) }, func() { c.TouchPoints = ptr(0) },
				func() { c.LangCount = ptr(1) }, func() { c.UAMajor = ptr(1) },
			}
			for i := 0; c.Count() < v.Components && i < len(pad); i++ {
				pad[i]()
			}
			if c.Count() != v.Components {
				t.Fatalf("built %d components, want %d", c.Count(), v.Components)
			}
			p := Payload{
				Mode: v.Mode, Components: c, Unavailable: v.Unavailable,
				Flags: Flags{ProtectedBrowser: v.Flags.ProtectedBrowser, Inconsistent: v.Flags.Inconsistent},
			}
			if got := Score(p, DefaultConfidenceModel()); got != v.Score {
				t.Fatalf("got %v, want %v", got, v.Score)
			}
		})
	}
}
