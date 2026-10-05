package httpx

import "net/http"

// WriteProblemJSON emits a minimal RFC 7807 problem+json body. The admin
// package owns the richer variant with type URIs; this in-package helper
// keeps the middleware self-contained and avoids an import cycle.
func WriteProblemJSON(w http.ResponseWriter, status int, code, detail, instance string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write(problemBody(status, code, detail, instance))
}

// WriteUnauthenticated emits a 401 with both the RFC 7807 body and an
// RFC 7235 WWW-Authenticate header. Session-cookie auth is the primary
// scheme; consumers using bearer tokens against the OAuth AS / mcpresource
// surface get the Bearer challenge from those packages instead.
func WriteUnauthenticated(w http.ResponseWriter, code, detail string) {
	w.Header().Set("WWW-Authenticate", `Session realm="theauth", error="`+code+`"`)
	WriteProblemJSON(w, http.StatusUnauthorized, code, detail, "")
}

func problemBody(status int, code, detail, instance string) []byte {
	// Tiny hand-built JSON encoder so the middleware avoids encoding/json
	// in the hot path. Six fields, two of which are optional. Numbers and
	// strings only, no escaping concerns since values are library-owned.
	b := []byte(`{"type":"https://theauth.dev/problems/`)
	b = append(b, code...)
	b = append(b, `","title":"`...)
	b = append(b, http.StatusText(status)...)
	b = append(b, `","status":`...)
	b = appendInt(b, status)
	b = append(b, `,"detail":`...)
	b = appendJSONString(b, detail)
	b = append(b, `,"code":"`...)
	b = append(b, code...)
	b = append(b, '"')
	if instance != "" {
		b = append(b, `,"instance":`...)
		b = appendJSONString(b, instance)
	}
	b = append(b, '}')
	return b
}

func appendInt(b []byte, n int) []byte {
	if n == 0 {
		return append(b, '0')
	}
	var tmp [20]byte
	i := len(tmp)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		tmp[i] = '-'
	}
	return append(b, tmp[i:]...)
}

func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b = append(b, '\\', byte(r))
		case '\n':
			b = append(b, '\\', 'n')
		case '\r':
			b = append(b, '\\', 'r')
		case '\t':
			b = append(b, '\\', 't')
		default:
			if r < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hexDigit(byte(r>>4)), hexDigit(byte(r&0xf)))
			} else {
				b = appendRune(b, r)
			}
		}
	}
	return append(b, '"')
}

func hexDigit(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'a' + (b - 10)
}

func appendRune(b []byte, r rune) []byte {
	const (
		t1 = 0x00
		tx = 0x80
		t2 = 0xC0
		t3 = 0xE0
		t4 = 0xF0
	)
	switch {
	case r < 0x80:
		return append(b, byte(r))
	case r < 0x800:
		return append(b, t2|byte(r>>6), tx|byte(r)&0x3F)
	case r < 0x10000:
		return append(b, t3|byte(r>>12), tx|byte(r>>6)&0x3F, tx|byte(r)&0x3F)
	default:
		return append(b, t4|byte(r>>18), tx|byte(r>>12)&0x3F, tx|byte(r>>6)&0x3F, tx|byte(r)&0x3F)
	}
}
