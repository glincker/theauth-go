package visitorsignal

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// entry is one component name with its canonical JSON value.
type entry struct {
	name  string
	value string
}

// Canonicalise returns the RFC 8785 style JSON of c: sorted keys, no
// whitespace, absent components omitted. It is the hash input.
func Canonicalise(c Components) ([]byte, error) {
	entries, err := componentEntries(c)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quoteJSON(e.name))
		b.WriteByte(':')
		b.WriteString(e.value)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// componentEntries returns present components sorted by name with their
// canonical values. Component names are ASCII, so byte order equals the
// UTF-16 code unit order that RFC 8785 requires.
func componentEntries(c Components) ([]entry, error) {
	var out []entry
	var firstErr error
	str := func(name string, v *string) {
		if v == nil {
			return
		}
		if !utf8.ValidString(*v) {
			firstErr = errors.Join(firstErr, fmt.Errorf("visitorsignal: component %s is not valid UTF-8", name))
			return
		}
		out = append(out, entry{name, quoteJSON(*v)})
	}
	num := func(name string, v *int) {
		if v != nil {
			out = append(out, entry{name, strconv.Itoa(*v)})
		}
	}
	boolean := func(name string, v *bool) {
		if v != nil {
			out = append(out, entry{name, strconv.FormatBool(*v)})
		}
	}
	str("tz", c.TZ)
	num("tzOffsetMin", c.TZOffsetMin)
	str("lang", c.Lang)
	num("langCount", c.LangCount)
	str("platform", c.Platform)
	str("uaBrand", c.UABrand)
	num("uaMajor", c.UAMajor)
	boolean("mobile", c.Mobile)
	str("screenBucket", c.ScreenBucket)
	num("colorDepth", c.ColorDepth)
	num("touchPoints", c.TouchPoints)
	num("cores", c.Cores)
	if c.MemoryGB != nil {
		s, err := formatFloat(*c.MemoryGB)
		if err != nil {
			firstErr = errors.Join(firstErr, err)
		} else {
			out = append(out, entry{"memoryGb", s})
		}
	}
	boolean("reducedMotion", c.ReducedMotion)
	str("colorScheme", c.ColorScheme)
	if c.Caps != nil {
		out = append(out, entry{"caps", strconv.FormatUint(uint64(*c.Caps), 10)})
	}
	str("renderHash", c.RenderHash)
	if firstErr != nil {
		return nil, firstErr
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// formatFloat writes the plain decimal form, which matches RFC 8785 for the
// magnitudes the schema allows. Values outside that range are refused rather
// than risk a different exponent form.
func formatFloat(f float64) (string, error) {
	abs := math.Abs(f)
	if math.IsNaN(f) || math.IsInf(f, 0) || abs >= 1e21 || (abs != 0 && abs < 1e-6) {
		return "", fmt.Errorf("visitorsignal: memoryGb %v is not canonicalisable", f)
	}
	if f == 0 {
		return "0", nil
	}
	return strconv.FormatFloat(f, 'f', -1, 64), nil
}

// quoteJSON escapes only the quote, the backslash and control characters,
// so <, > and & stay literal as the contract requires.
func quoteJSON(s string) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			b.WriteString(`\"`)
		case ch == '\\':
			b.WriteString(`\\`)
		case ch == '\b':
			b.WriteString(`\b`)
		case ch == '\f':
			b.WriteString(`\f`)
		case ch == '\n':
			b.WriteString(`\n`)
		case ch == '\r':
			b.WriteString(`\r`)
		case ch == '\t':
			b.WriteString(`\t`)
		case ch < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[ch>>4])
			b.WriteByte(hex[ch&0xf])
		default:
			b.WriteByte(ch)
		}
	}
	b.WriteByte('"')
	return b.String()
}
