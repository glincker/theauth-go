package checkpoint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// CanonicalJSON serializes v as the TypeScript SDK's canonicalJson does: keys sorted by UTF-16 code
// unit at every depth, no whitespace, JavaScript string escaping and number formatting. Non-finite
// floats encode as null.
func CanonicalJSON(v any) (string, error) {
	var b strings.Builder
	if err := writeCanonical(&b, v, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

const maxCanonicalDepth = 256

func writeCanonical(b *strings.Builder, v any, depth int) error {
	if depth > maxCanonicalDepth {
		return fmt.Errorf("canonical json: nesting too deep")
	}
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case string:
		writeJSString(b, t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return fmt.Errorf("canonical json: bad number %q", string(t))
		}
		b.WriteString(jsNumber(f))
	case float64:
		b.WriteString(jsNumber(t))
	case float32:
		b.WriteString(jsNumber(float64(t)))
	case int:
		b.WriteString(jsNumber(float64(t)))
	case int8, int16, int32, int64:
		b.WriteString(jsNumber(float64(reflect.ValueOf(t).Int())))
	case uint, uint8, uint16, uint32, uint64:
		b.WriteString(jsNumber(float64(reflect.ValueOf(t).Uint())))
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return compareCodeUnits(keys[i], keys[j]) < 0 })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJSString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, t[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("canonical json: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var generic any
		if err := dec.Decode(&generic); err != nil {
			return fmt.Errorf("canonical json: %w", err)
		}
		return writeCanonical(b, generic, depth+1)
	}
	return nil
}

// compareCodeUnits orders strings by UTF-16 code unit, like JavaScript's < on strings.
func compareCodeUnits(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	}
	return 0
}

// jsNumber formats f like JavaScript's Number.prototype.toString for JSON.
func jsNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	if f == 0 {
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e21 || abs < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mant, exp, _ := strings.Cut(s, "e")
		sign := exp[0]
		digits := strings.TrimLeft(exp[1:], "0")
		return mant + "e" + string(sign) + digits
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

const hexDigits = "0123456789abcdef"

// writeJSString writes s as JSON.stringify would: only quote, backslash and
// control characters are escaped, everything else is emitted as is.
func writeJSString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			r = utf8.RuneError
		}
		i += size
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hexDigits[r>>4])
			b.WriteByte(hexDigits[r&0xf])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}
