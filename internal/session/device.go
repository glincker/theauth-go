package session

import (
	"net"
	"net/netip"
	"strings"
)

// DeviceLabel derives a short "Browser on OS" label from a User-Agent string.
// It returns "Unknown device" when nothing recognizable is present.
func DeviceLabel(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "Unknown device"
	}
	browser := firstMatch(ua, [][2]string{
		{"Edg/", "Edge"}, {"EdgA/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}, {"curl/", "curl"},
	})
	osName := firstMatch(ua, [][2]string{
		{"iPhone", "iOS"}, {"iPad", "iPadOS"}, {"Android", "Android"}, {"CrOS", "ChromeOS"},
		{"Windows", "Windows"}, {"Mac OS X", "macOS"}, {"Macintosh", "macOS"}, {"Linux", "Linux"},
	})
	switch {
	case browser != "" && osName != "":
		return browser + " on " + osName
	case browser != "":
		return browser
	case osName != "":
		return osName
	}
	return "Unknown device"
}

func firstMatch(ua string, table [][2]string) string {
	for _, e := range table {
		if strings.Contains(ua, e[0]) {
			return e[1]
		}
	}
	return ""
}

// IPPrefix masks an address to /24 (IPv4) or /48 (IPv6) so a session list can
// show where a session is from without exposing the full address. Returns ""
// when ip does not parse.
func IPPrefix(ip string) string {
	ip = strings.TrimSpace(ip)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}
