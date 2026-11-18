package visitorsignal

import (
	"math"
	"strings"
)

// ConfidenceModel holds the heuristic terms. It is not a calibrated
// probability. Penalties are positive numbers that Score subtracts.
type ConfidenceModel struct {
	Base                    float64
	AnalyticsPenalty        float64
	MobileSafariPenalty     float64
	AndroidPenalty          float64
	ProtectedBrowserPenalty float64
	InconsistentPenalty     float64
	// UnavailablePenalty applies per unavailable entry, up to UnavailableCap in total.
	UnavailablePenalty float64
	UnavailableCap     float64
	// FewComponentsPenalty applies when fewer than FewComponentsBelow are present.
	FewComponentsPenalty float64
	FewComponentsBelow   int
}

// DefaultConfidenceModel returns the SPEC part 2 defaults.
func DefaultConfidenceModel() ConfidenceModel {
	return ConfidenceModel{
		Base:                    0.90,
		AnalyticsPenalty:        0.15,
		MobileSafariPenalty:     0.30,
		AndroidPenalty:          0.20,
		ProtectedBrowserPenalty: 0.30,
		InconsistentPenalty:     0.20,
		UnavailablePenalty:      0.05,
		UnavailableCap:          0.25,
		FewComponentsPenalty:    0.10,
		FewComponentsBelow:      6,
	}
}

// Score returns the heuristic confidence in [0, 1] for p.
func Score(p Payload, m ConfidenceModel) float64 {
	s := m.Base
	if p.Mode == ModeAnalytics {
		s -= m.AnalyticsPenalty
	}
	c := p.Components
	platform := ""
	if c.Platform != nil {
		platform = *c.Platform
	}
	mobile := c.Mobile != nil && *c.Mobile
	// First match wins: the Safari penalty and the Android penalty never stack.
	switch {
	case platform == "iPhone" || platform == "iPad" ||
		(mobile && c.UABrand != nil && *c.UABrand == "Safari"):
		s -= m.MobileSafariPenalty
	case mobile && (strings.HasPrefix(platform, "Linux armv") || strings.HasPrefix(platform, "Android")):
		s -= m.AndroidPenalty
	}
	if p.Flags.ProtectedBrowser {
		s -= m.ProtectedBrowserPenalty
	}
	if p.Flags.Inconsistent {
		s -= m.InconsistentPenalty
	}
	un := float64(len(p.Unavailable)) * m.UnavailablePenalty
	if un > m.UnavailableCap {
		un = m.UnavailableCap
	}
	s -= un
	if c.Count() < m.FewComponentsBelow {
		s -= m.FewComponentsPenalty
	}
	switch {
	case s < 0:
		return 0
	case s > 1:
		return 1
	}
	// Four decimals keeps the Go and TypeScript scores equal despite float noise.
	return math.Round(s*1e4) / 1e4
}
