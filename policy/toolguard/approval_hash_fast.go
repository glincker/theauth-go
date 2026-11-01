package toolguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// This file is the fast path of HashApprovalAction. For arguments built from plain Go values
// (maps, slices, strings, numbers, bools, nil) it writes the canonical JSON in one pass, without
// the encode, decode and encode round trip through encoding/json that normalizeArgs does. The
// bytes are identical to that slow path, which stays the reference: any value the fast path is
// not sure about (a struct, a pointer, a named type, invalid UTF-8, a fraction held in a
// json.Number, NaN) makes it report false and the caller runs the slow path instead. The tests
// compare both paths on a large corpus and replay the shared vectors.

// jsonHex is the digit table encoding/json uses for \u00XX escapes.
const jsonHex = "0123456789abcdef"

// htmlSafe reports whether encoding/json writes an ASCII byte as is with HTML escaping on:
// everything printable except quote, backslash, "<", ">" and "&".
func htmlSafe(b byte) bool {
	return b >= 0x20 && b != '"' && b != '\\' && b != '<' && b != '>' && b != '&'
}

// appendJSONString appends s the way encoding/json does with HTML escaping on. With strict set
// it reports false for invalid UTF-8: the slow path turns such bytes into a literal U+FFFD before
// the final encode, which the fast path does not reproduce.
func appendJSONString(dst []byte, s string, strict bool) ([]byte, bool) {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if htmlSafe(b) {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch b {
			case '\\', '"':
				dst = append(dst, '\\', b)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				dst = append(dst, '\\', 'u', '0', '0', jsonHex[b>>4], jsonHex[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if strict {
				return dst, false
			}
			dst = append(dst, s[start:i]...)
			dst = append(dst, "\\ufffd"...)
			i += size
			start = i
			continue
		}
		if c == '\u2028' || c == '\u2029' {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', jsonHex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"'), true
}

// appendJSONFloat appends f the way encoding/json writes a float64. It reports false for NaN and
// the infinities, which encoding/json refuses (the slow path produces that error).
func appendJSONFloat(dst []byte, f float64) ([]byte, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return dst, false
	}
	format := byte('f')
	if abs := math.Abs(f); abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		format = 'e'
	}
	dst = strconv.AppendFloat(dst, f, format, -1, 64)
	if format == 'e' {
		// Clean up e-09 to e-9, as encoding/json does.
		if n := len(dst); n >= 4 && dst[n-4] == 'e' && dst[n-3] == '-' && dst[n-2] == '0' {
			dst[n-2] = dst[n-1]
			dst = dst[:n-1]
		}
	}
	return dst, true
}

// plainInteger reports whether s is a valid JSON integer in the form canonNumber leaves alone:
// optional minus, then 0 or a nonzero digit followed by digits, and not "-0".
func plainInteger(s string) bool {
	d := strings.TrimPrefix(s, "-")
	switch {
	case d == "" || s == "-0":
		return false
	case d[0] == '0':
		return len(d) == 1
	}
	return strings.Trim(d, "0123456789") == ""
}

// appendCanonical appends the canonical JSON of v. ok is false when v holds something the fast
// path does not handle. A nil map or slice is written as null, like encoding/json.
func appendCanonical(dst []byte, v any) ([]byte, bool) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), true
	case string:
		return appendJSONString(dst, x, true)
	case bool:
		return strconv.AppendBool(dst, x), true
	case float64:
		return appendJSONFloat(dst, x)
	case int:
		return strconv.AppendInt(dst, int64(x), 10), true
	case int8:
		return strconv.AppendInt(dst, int64(x), 10), true
	case int16:
		return strconv.AppendInt(dst, int64(x), 10), true
	case int32:
		return strconv.AppendInt(dst, int64(x), 10), true
	case int64:
		return strconv.AppendInt(dst, x, 10), true
	case uint:
		return strconv.AppendUint(dst, uint64(x), 10), true
	case uint8:
		return strconv.AppendUint(dst, uint64(x), 10), true
	case uint16:
		return strconv.AppendUint(dst, uint64(x), 10), true
	case uint32:
		return strconv.AppendUint(dst, uint64(x), 10), true
	case uint64:
		return strconv.AppendUint(dst, x, 10), true
	case json.Number:
		if !plainInteger(string(x)) {
			return dst, false
		}
		return append(dst, x...), true
	case []any:
		if x == nil {
			return append(dst, "null"...), true
		}
		dst = append(dst, '[')
		for i, e := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var ok bool
			if dst, ok = appendCanonical(dst, e); !ok {
				return dst, false
			}
		}
		return append(dst, ']'), true
	case []string:
		if x == nil {
			return append(dst, "null"...), true
		}
		dst = append(dst, '[')
		for i, e := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var ok bool
			if dst, ok = appendJSONString(dst, e, true); !ok {
				return dst, false
			}
		}
		return append(dst, ']'), true
	case map[string]any:
		if x == nil {
			return append(dst, "null"...), true
		}
		return appendMapAny(dst, x, nil)
	case map[string]string:
		if x == nil {
			return append(dst, "null"...), true
		}
		var kb [16]string
		keys := kb[:0]
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			var ok bool
			if dst, ok = appendJSONString(dst, k, true); !ok {
				return dst, false
			}
			dst = append(dst, ':')
			if dst, ok = appendJSONString(dst, x[k], true); !ok {
				return dst, false
			}
		}
		return append(dst, '}'), true
	}
	return dst, false
}

// appendMapAny writes a map with its keys in byte order, which is the order encoding/json uses.
// A key for which skip returns true is validated like any other entry but left out of the output.
func appendMapAny(dst []byte, m map[string]any, skip func(string) bool) ([]byte, bool) {
	var kb [16]string
	keys := kb[:0]
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	dst = append(dst, '{')
	first := true
	for _, k := range keys {
		mark := len(dst)
		if !first {
			dst = append(dst, ',')
		}
		var ok bool
		if dst, ok = appendJSONString(dst, k, true); !ok {
			return dst, false
		}
		dst = append(dst, ':')
		if dst, ok = appendCanonical(dst, m[k]); !ok {
			return dst, false
		}
		if skip != nil && skip(k) {
			dst = dst[:mark]
			continue
		}
		first = false
	}
	return append(dst, '}'), true
}

// hashBufPool holds the scratch buffers the canonical JSON is written into. A buffer that grew
// past maxPooledHashBuf for one huge argument set is dropped instead of kept.
var hashBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 1024); return &b }}

const maxPooledHashBuf = 64 << 10

// fastHashApproval is the one pass version of HashApprovalAction. ok is false when the caller
// must use the slow path.
func fastHashApproval(action, resource string, args any) (string, bool) {
	bp := hashBufPool.Get().(*[]byte)
	dst := append((*bp)[:0], `{"action":`...)
	defer func() {
		if cap(dst) <= maxPooledHashBuf {
			*bp = dst[:0]
			hashBufPool.Put(bp)
		}
	}()
	var ok bool
	if dst, ok = appendJSONString(dst, action, false); !ok {
		return "", false
	}
	dst = append(dst, `,"arguments":`...)
	switch m := args.(type) {
	case nil:
		dst = append(dst, "{}"...)
	case map[string]any:
		if m == nil {
			dst = append(dst, "{}"...)
			break
		}
		dst, ok = appendMapAny(dst, m, reservedArgKey)
	default:
		// Only the object shapes above are fast: a top level scalar or array keeps its slow path
		// (it is rare, and the slow path defines what null like values hash to).
		return "", false
	}
	if !ok {
		return "", false
	}
	dst = append(dst, `,"resource":`...)
	if dst, ok = appendJSONString(dst, resource, false); !ok {
		return "", false
	}
	dst = append(dst, '}')
	sum := sha256.Sum256(dst)
	return hex.EncodeToString(sum[:]), true
}
