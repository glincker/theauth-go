package device

import (
	"errors"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// This file holds a small JSON reader and writer. The verify path of a device library
// should not pull in encoding/json: it relies on reflection, which is heavy on a
// microcontroller and only partly supported by TinyGo. Values decode to the plain
// shapes map[string]any, []any, string, float64, bool and nil.

const maxJSONDepth = 64

var errJSON = errors.New("device: malformed JSON")

type jsonReader struct {
	b []byte
	i int
}

func parseJSON(b []byte) (any, error) {
	r := &jsonReader{b: b}
	r.skipSpace()
	v, err := r.value(0)
	if err != nil {
		return nil, err
	}
	r.skipSpace()
	if r.i != len(r.b) {
		return nil, errJSON
	}
	return v, nil
}

func (r *jsonReader) skipSpace() {
	for r.i < len(r.b) {
		switch r.b[r.i] {
		case ' ', '\t', '\n', '\r':
			r.i++
		default:
			return
		}
	}
}

func (r *jsonReader) value(depth int) (any, error) {
	if depth > maxJSONDepth || r.i >= len(r.b) {
		return nil, errJSON
	}
	switch c := r.b[r.i]; {
	case c == '{':
		return r.object(depth)
	case c == '[':
		return r.array(depth)
	case c == '"':
		return r.str()
	case c == 't':
		return r.literal("true", true)
	case c == 'f':
		return r.literal("false", false)
	case c == 'n':
		return r.literal("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return r.number()
	}
	return nil, errJSON
}

func (r *jsonReader) literal(word string, v any) (any, error) {
	if len(r.b)-r.i < len(word) || string(r.b[r.i:r.i+len(word)]) != word {
		return nil, errJSON
	}
	r.i += len(word)
	return v, nil
}

func (r *jsonReader) number() (any, error) {
	start := r.i
	if r.b[r.i] == '-' {
		r.i++
	}
	digits := func() int {
		n := 0
		for r.i < len(r.b) && r.b[r.i] >= '0' && r.b[r.i] <= '9' {
			r.i++
			n++
		}
		return n
	}
	if r.i < len(r.b) && r.b[r.i] == '0' {
		r.i++
	} else if digits() == 0 {
		return nil, errJSON
	}
	if r.i < len(r.b) && r.b[r.i] == '.' {
		r.i++
		if digits() == 0 {
			return nil, errJSON
		}
	}
	if r.i < len(r.b) && (r.b[r.i] == 'e' || r.b[r.i] == 'E') {
		r.i++
		if r.i < len(r.b) && (r.b[r.i] == '+' || r.b[r.i] == '-') {
			r.i++
		}
		if digits() == 0 {
			return nil, errJSON
		}
	}
	f, err := strconv.ParseFloat(string(r.b[start:r.i]), 64)
	if err != nil {
		return nil, errJSON
	}
	return f, nil
}

func (r *jsonReader) hex4() (rune, error) {
	if len(r.b)-r.i < 4 {
		return 0, errJSON
	}
	n, err := strconv.ParseUint(string(r.b[r.i:r.i+4]), 16, 32)
	if err != nil {
		return 0, errJSON
	}
	r.i += 4
	return rune(n), nil
}

func (r *jsonReader) str() (string, error) {
	r.i++ // opening quote
	var out []byte
	for r.i < len(r.b) {
		c := r.b[r.i]
		switch {
		case c == '"':
			r.i++
			return string(out), nil
		case c < 0x20:
			return "", errJSON
		case c != '\\':
			out = append(out, c)
			r.i++
		default:
			r.i++
			if r.i >= len(r.b) {
				return "", errJSON
			}
			e := r.b[r.i]
			r.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				cp, err := r.hex4()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(cp) {
					if len(r.b)-r.i >= 6 && r.b[r.i] == '\\' && r.b[r.i+1] == 'u' {
						save := r.i
						r.i += 2
						lo, err := r.hex4()
						if err == nil {
							if combined := utf16.DecodeRune(cp, lo); combined != utf8.RuneError {
								out = utf8.AppendRune(out, combined)
								continue
							}
						}
						r.i = save
					}
					cp = utf8.RuneError
				}
				out = utf8.AppendRune(out, cp)
			default:
				return "", errJSON
			}
		}
	}
	return "", errJSON
}

func (r *jsonReader) array(depth int) (any, error) {
	r.i++
	out := []any{}
	r.skipSpace()
	if r.i < len(r.b) && r.b[r.i] == ']' {
		r.i++
		return out, nil
	}
	for {
		r.skipSpace()
		v, err := r.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		r.skipSpace()
		if r.i >= len(r.b) {
			return nil, errJSON
		}
		switch r.b[r.i] {
		case ',':
			r.i++
		case ']':
			r.i++
			return out, nil
		default:
			return nil, errJSON
		}
	}
}

func (r *jsonReader) object(depth int) (any, error) {
	r.i++
	out := map[string]any{}
	r.skipSpace()
	if r.i < len(r.b) && r.b[r.i] == '}' {
		r.i++
		return out, nil
	}
	for {
		r.skipSpace()
		if r.i >= len(r.b) || r.b[r.i] != '"' {
			return nil, errJSON
		}
		k, err := r.str()
		if err != nil {
			return nil, err
		}
		r.skipSpace()
		if r.i >= len(r.b) || r.b[r.i] != ':' {
			return nil, errJSON
		}
		r.i++
		r.skipSpace()
		v, err := r.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out[k] = v
		r.skipSpace()
		if r.i >= len(r.b) {
			return nil, errJSON
		}
		switch r.b[r.i] {
		case ',':
			r.i++
		case '}':
			r.i++
			return out, nil
		default:
			return nil, errJSON
		}
	}
}

// appendJSON writes v in the same plain shapes parseJSON produces, plus int and int64
// and []string. Object keys are sorted so output is stable.
func appendJSON(dst []byte, v any) []byte {
	switch t := v.(type) {
	case nil:
		return append(dst, "null"...)
	case bool:
		return strconv.AppendBool(dst, t)
	case int:
		return strconv.AppendInt(dst, int64(t), 10)
	case int64:
		return strconv.AppendInt(dst, t, 10)
	case float64:
		return strconv.AppendFloat(dst, t, 'f', -1, 64)
	case string:
		return appendJSONString(dst, t)
	case []string:
		dst = append(dst, '[')
		for i, s := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, s)
		}
		return append(dst, ']')
	case []any:
		dst = append(dst, '[')
		for i, e := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSON(dst, e)
		}
		return append(dst, ']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, k)
			dst = append(dst, ':')
			dst = appendJSON(dst, t[k])
		}
		return append(dst, '}')
	}
	return append(dst, "null"...)
}

func appendJSONString(dst []byte, s string) []byte {
	const hexDigits = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c == '\n':
			dst = append(dst, '\\', 'n')
		case c == '\r':
			dst = append(dst, '\\', 'r')
		case c == '\t':
			dst = append(dst, '\\', 't')
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&15])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}
