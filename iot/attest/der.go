package attest

import (
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file is a minimal DER reader (ITU-T X.690) for X.509 and attestation extensions. It
// ports the TypeScript reader: definite lengths only, every read is bounds checked, and nothing
// allocates more than the input.

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER. The TypeScript reader refuses integers
// beyond it, and so does this one, so both accept the same inputs.
const maxSafeInteger = 1<<53 - 1

type derError struct{ msg string }

func (e *derError) Error() string { return e.msg }

func derErr(msg string) error { return &derError{msg: msg} }

// tlv is one DER element.
type tlv struct {
	cls         int
	constructed bool
	tag         int
	// raw is the whole element: identifier, length and content.
	raw     []byte
	content []byte
}

const (
	tagBoolean     = 1
	tagInteger     = 2
	tagBitString   = 3
	tagOctetString = 4
	tagOID         = 6
	tagSequence    = 16
	tagSet         = 17
	tagUTCTime     = 23
	tagGenTime     = 24
)

// readTLV reads one element at the start of buf and returns it and the bytes it used.
func readTLV(buf []byte) (tlv, int, error) {
	i := 0
	if len(buf) == 0 {
		return tlv{}, 0, derErr("empty input")
	}
	first := buf[i]
	i++
	cls := int(first >> 6)
	constructed := first&0x20 != 0
	tag := int(first & 0x1f)
	if tag == 0x1f {
		tag = 0
		for n := 0; ; n++ {
			if i >= len(buf) || n > 3 {
				return tlv{}, 0, derErr("bad high tag number")
			}
			b := buf[i]
			i++
			tag = tag*128 + int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(buf) {
		return tlv{}, 0, derErr("truncated length")
	}
	lenByte := buf[i]
	i++
	length := int(lenByte)
	if lenByte&0x80 != 0 {
		count := int(lenByte & 0x7f)
		if count == 0 || count > 4 {
			return tlv{}, 0, derErr("unsupported length form")
		}
		length = 0
		for n := 0; n < count; n++ {
			if i >= len(buf) {
				return tlv{}, 0, derErr("truncated length")
			}
			length = length*256 + int(buf[i])
			i++
		}
	}
	end := i + length
	if end > len(buf) {
		return tlv{}, 0, derErr("element runs past its parent")
	}
	return tlv{cls: cls, constructed: constructed, tag: tag, raw: buf[:end], content: buf[i:end]}, end, nil
}

// parseOne parses the whole buffer as exactly one element.
func parseOne(buf []byte) (tlv, error) {
	t, size, err := readTLV(buf)
	if err != nil {
		return tlv{}, err
	}
	if size != len(buf) {
		return tlv{}, derErr("trailing bytes after element")
	}
	return t, nil
}

// children returns the children of a constructed element, in order.
func children(t tlv) ([]tlv, error) {
	if !t.constructed {
		return nil, derErr("not a constructed element")
	}
	var out []tlv
	rest := t.content
	for len(rest) > 0 {
		c, size, err := readTLV(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		rest = rest[size:]
	}
	return out, nil
}

func isUniversal(t tlv, tag int) bool { return t.cls == 0 && t.tag == tag }

func bigIntOf(t tlv) (*big.Int, error) {
	if len(t.content) == 0 {
		return nil, derErr("empty INTEGER")
	}
	v := new(big.Int).SetBytes(t.content)
	if t.content[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(t.content))))
	}
	return v, nil
}

// intOf reads an INTEGER or ENUMERATED that must fit in a JavaScript safe integer.
func intOf(t tlv) (int64, error) {
	v, err := bigIntOf(t)
	if err != nil {
		return 0, err
	}
	limit := big.NewInt(maxSafeInteger)
	if v.Cmp(limit) > 0 || v.Cmp(new(big.Int).Neg(limit)) < 0 {
		return 0, derErr("integer out of range")
	}
	return v.Int64(), nil
}

func boolOf(t tlv) (bool, error) {
	if !isUniversal(t, tagBoolean) || len(t.content) != 1 {
		return false, derErr("bad BOOLEAN")
	}
	return t.content[0] != 0, nil
}

func oidOf(t tlv) (string, error) {
	if !isUniversal(t, tagOID) || len(t.content) == 0 {
		return "", derErr("bad OID")
	}
	var arcs []string
	var v int64
	for _, b := range t.content {
		v = v*128 + int64(b&0x7f)
		if v > maxSafeInteger/128 {
			return "", derErr("OID arc too large")
		}
		if b&0x80 == 0 {
			if len(arcs) == 0 {
				first := int64(2)
				if v < 80 {
					first = v / 40
				}
				arcs = append(arcs, strconv.FormatInt(first, 10), strconv.FormatInt(v-first*40, 10))
			} else {
				arcs = append(arcs, strconv.FormatInt(v, 10))
			}
			v = 0
		}
	}
	return strings.Join(arcs, "."), nil
}

func stringOf(t tlv) (string, error) {
	if !utf8.Valid(t.content) {
		return "", reasonErr("The encoded data was not valid for encoding utf-8")
	}
	return string(t.content), nil
}

// bitStringBytes returns a BIT STRING without the leading unused-bits octet.
func bitStringBytes(t tlv) ([]byte, error) {
	if !isUniversal(t, tagBitString) || len(t.content) == 0 {
		return nil, derErr("bad BIT STRING")
	}
	return t.content[1:], nil
}
