package visitorsignal

import (
	"regexp"
	"strconv"
	"strings"
)

// RequestMeta carries what the server observed on the request. Observed
// values outrank what the client claims.
type RequestMeta struct {
	UserAgent       string
	AcceptLanguage  string
	SecCHUAMobile   string
	SecCHUAPlatform string
}

// Reason codes returned by Assess.
const (
	ReasonWebdriver         = "webdriver"
	ReasonAutomationGlobals = "automation_globals"
	ReasonHeadlessHint      = "headless_hint"
	ReasonInconsistent      = "inconsistent"
	ReasonNoInput           = "no_input"
	ReasonUAMissing         = "ua_missing"
	ReasonUAMajorMismatch   = "ua_major_mismatch"
	ReasonMobileMismatch    = "mobile_mismatch"
	ReasonPlatformMismatch  = "platform_mismatch"
	ReasonLanguageMismatch  = "language_mismatch"
)

// RiskModel holds the weight of each reason. The sum is capped at 1.
type RiskModel struct {
	Webdriver         float64
	AutomationGlobals float64
	HeadlessHint      float64
	Inconsistent      float64
	NoInput           float64
	UAMissing         float64
	UAMajorMismatch   float64
	MobileMismatch    float64
	PlatformMismatch  float64
	LanguageMismatch  float64
}

// DefaultRiskModel returns the SPEC part 2 weights.
func DefaultRiskModel() RiskModel {
	return RiskModel{
		Webdriver: 0.60, AutomationGlobals: 0.30, HeadlessHint: 0.30,
		Inconsistent: 0.20, NoInput: 0.10, UAMissing: 0.30,
		UAMajorMismatch: 0.30, MobileMismatch: 0.20, PlatformMismatch: 0.20,
		LanguageMismatch: 0.10,
	}
}

// Assess returns a risk score in [0, 1] and the reason codes that fired. It
// is a score, not a verdict. protectedBrowser alone never adds risk.
func Assess(p Payload, meta RequestMeta, m RiskModel) (float64, []string) {
	reasons := []string{}
	risk := 0.0
	add := func(code string, w float64) {
		reasons = append(reasons, code)
		risk += w
	}
	f := p.Flags
	if f.Webdriver {
		add(ReasonWebdriver, m.Webdriver)
	}
	if f.AutomationGlobals > 0 {
		add(ReasonAutomationGlobals, m.AutomationGlobals)
	}
	if f.HeadlessHint {
		add(ReasonHeadlessHint, m.HeadlessHint)
	}
	if f.Inconsistent {
		add(ReasonInconsistent, m.Inconsistent)
	}
	if f.NoInputObserved && p.Mode == ModeFraudPrevention {
		add(ReasonNoInput, m.NoInput)
	}
	ua := strings.TrimSpace(meta.UserAgent)
	if ua == "" {
		add(ReasonUAMissing, m.UAMissing)
	}
	if uaMajorMismatch(p.Components, ua) {
		add(ReasonUAMajorMismatch, m.UAMajorMismatch)
	}
	if mobileMismatch(p.Components, meta.SecCHUAMobile) {
		add(ReasonMobileMismatch, m.MobileMismatch)
	}
	if platformMismatch(p.Components, ua, meta.SecCHUAPlatform) {
		add(ReasonPlatformMismatch, m.PlatformMismatch)
	}
	if languageMismatch(p.Components, meta.AcceptLanguage) {
		add(ReasonLanguageMismatch, m.LanguageMismatch)
	}
	if risk > 1 {
		risk = 1
	}
	return risk, reasons
}

var (
	chromeMajorRe  = regexp.MustCompile(`Chrome/(\d+)`)
	firefoxMajorRe = regexp.MustCompile(`Firefox/(\d+)`)
	safariMajorRe  = regexp.MustCompile(`Version/(\d+)`)
)

// uaMajorMismatch compares only for brands whose UA token carries the same
// major. Other Chromium forks (Opera, Samsung, Yandex) put their own version
// in uaMajor, so a comparison would be a false positive and is skipped.
func uaMajorMismatch(c Components, ua string) bool {
	if c.UAMajor == nil || c.UABrand == nil {
		return false
	}
	var re *regexp.Regexp
	switch *c.UABrand {
	case "Chrome", "Google Chrome", "Chromium", "Microsoft Edge", "Brave":
		re = chromeMajorRe
	case "Firefox":
		re = firefoxMajorRe
	case "Safari":
		re = safariMajorRe
	default:
		return false
	}
	m := re.FindStringSubmatch(ua)
	if m == nil {
		return false
	}
	n, err := strconv.Atoi(m[1])
	return err == nil && n != *c.UAMajor
}

func mobileMismatch(c Components, header string) bool {
	h := strings.TrimSpace(header)
	if c.Mobile == nil || h == "" {
		return false
	}
	return (h == "?1") != *c.Mobile
}

func payloadFamily(platform string) string {
	switch {
	case strings.HasPrefix(platform, "Win"):
		return "Win"
	case strings.HasPrefix(platform, "Mac"):
		return "Mac"
	case strings.HasPrefix(platform, "iPhone"):
		return "iPhone"
	case strings.HasPrefix(platform, "iPad"):
		return "iPad"
	case strings.HasPrefix(platform, "Android"):
		return "Android"
	case strings.HasPrefix(platform, "Linux"):
		return "Linux"
	}
	return ""
}

// uaFamilies lists the families a User-Agent implies. Android implies Linux
// because navigator.platform reports "Linux armv..." on Android devices.
func uaFamilies(ua string) map[string]bool {
	s := map[string]bool{}
	switch {
	case strings.Contains(ua, "iPhone"):
		s["iPhone"] = true
	case strings.Contains(ua, "iPad"):
		s["iPad"] = true
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X"):
		s["Mac"] = true
	}
	if strings.Contains(ua, "Windows") {
		s["Win"] = true
	}
	if strings.Contains(ua, "Android") {
		s["Android"], s["Linux"] = true, true
	}
	if strings.Contains(ua, "Linux") || strings.Contains(ua, "X11") {
		s["Linux"] = true
	}
	return s
}

func hintFamilies(hint string) map[string]bool {
	s := map[string]bool{}
	switch strings.ToLower(strings.Trim(strings.TrimSpace(hint), `"`)) {
	case "windows":
		s["Win"] = true
	case "macos":
		s["Mac"] = true
	case "linux", "chrome os":
		s["Linux"] = true
	case "android":
		s["Android"], s["Linux"] = true, true
	case "ios":
		s["iPhone"], s["iPad"] = true, true
	}
	return s
}

// platformMismatch fires when the claimed family disagrees with the observed
// one, taken from Sec-CH-UA-Platform when present and the User-Agent otherwise.
func platformMismatch(c Components, ua, hint string) bool {
	if c.Platform == nil {
		return false
	}
	fam := payloadFamily(*c.Platform)
	if fam == "" {
		return false
	}
	// The client hint is the stronger signal. Android Chrome in desktop-site
	// mode sends a desktop UA, so the UA is consulted only without a hint.
	if strings.TrimSpace(hint) != "" {
		set := hintFamilies(hint)
		return len(set) > 0 && !set[fam]
	}
	set := uaFamilies(ua)
	return len(set) > 0 && !set[fam]
}

func languageMismatch(c Components, header string) bool {
	if c.Lang == nil || *c.Lang == "" || strings.TrimSpace(header) == "" {
		return false
	}
	primary := strings.ToLower(strings.SplitN(*c.Lang, "-", 2)[0])
	for _, part := range strings.Split(header, ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if tag == "*" || strings.ToLower(strings.SplitN(tag, "-", 2)[0]) == primary {
			return false
		}
	}
	return true
}
