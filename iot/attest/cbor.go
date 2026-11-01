package attest

import (
	"strconv"
	"unicode/utf8"
)

// This file is a strict CBOR reader (RFC 8949) for attestation objects, ported from the
// TypeScript reader. It reports how many bytes an item used (WebAuthn style authenticator data
// puts a CBOR key in the middle of a byte string), refuses duplicate map keys, indefinite
// lengths, floats and integers beyond 2^53, and caps depth and size.

const (
	cborMaxSize  = 1_048_576
	cborMaxDepth = 16
)

type cborError struct{ msg string }

func (e *cborError) Error() string { return "CBOR: " + e.msg }

func cborErr(msg string) error { return &cborError{msg: msg} }

// cborMap is a decoded CBOR map. Keys are text strings or integers only, stored as "s:<text>"
// and "i:<number>" so a text key "1" and an integer key 1 stay distinct.
type cborMap map[string]any

func (m cborMap) str(key string) (any, bool) { v, ok := m["s:"+key]; return v, ok }
func (m cborMap) num(key int64) (any, bool) {
	v, ok := m["i:"+strconv.FormatInt(key, 10)]
	return v, ok
}

type cborState struct {
	data   []byte
	offset int
}

func (s *cborState) take(n uint64) ([]byte, error) {
	if n > uint64(len(s.data)-s.offset) {
		return nil, cborErr("unexpected end of data")
	}
	out := s.data[s.offset : s.offset+int(n)]
	s.offset += int(n)
	return out, nil
}

func (s *cborState) argument(info int) (uint64, error) {
	if info < 24 {
		return uint64(info), nil
	}
	if info > 27 {
		return 0, cborErr("indefinite or reserved length form")
	}
	b, err := s.take(uint64(1) << (info - 24))
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	if v > maxSafeInteger {
		return 0, cborErr("integer beyond 2^53")
	}
	return v, nil
}

func (s *cborState) item(depth int) (any, error) {
	if depth > cborMaxDepth {
		return nil, cborErr("nesting too deep")
	}
	hb, err := s.take(1)
	if err != nil {
		return nil, err
	}
	head := hb[0]
	major := int(head >> 5)
	info := int(head & 0x1f)
	switch major {
	case 0:
		v, err := s.argument(info)
		return int64(v), err
	case 1:
		v, err := s.argument(info)
		return -1 - int64(v), err
	case 2:
		n, err := s.argument(info)
		if err != nil {
			return nil, err
		}
		return s.take(n)
	case 3:
		n, err := s.argument(info)
		if err != nil {
			return nil, err
		}
		b, err := s.take(n)
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, cborErr("invalid UTF-8")
		}
		return string(b), nil
	case 4:
		count, err := s.argument(info)
		if err != nil {
			return nil, err
		}
		if count > uint64(len(s.data)-s.offset) {
			return nil, cborErr("array longer than input")
		}
		out := make([]any, 0, count)
		for i := uint64(0); i < count; i++ {
			v, err := s.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		count, err := s.argument(info)
		if err != nil {
			return nil, err
		}
		if count > uint64(len(s.data)-s.offset) {
			return nil, cborErr("map longer than input")
		}
		out := make(cborMap, count)
		for i := uint64(0); i < count; i++ {
			k, err := s.item(depth + 1)
			if err != nil {
				return nil, err
			}
			var key string
			switch kv := k.(type) {
			case string:
				key = "s:" + kv
			case int64:
				key = "i:" + strconv.FormatInt(kv, 10)
			default:
				return nil, cborErr("map key type")
			}
			if _, dup := out[key]; dup {
				return nil, cborErr("duplicate map key")
			}
			v, err := s.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		return out, nil
	case 7:
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, cborErr("unsupported simple or float value")
	default:
		return nil, cborErr("unsupported major type " + strconv.Itoa(major))
	}
}

// decodeCBORPrefix decodes the item at the start of data and returns it and the bytes it used.
func decodeCBORPrefix(data []byte) (any, int, error) {
	if len(data) == 0 || len(data) > cborMaxSize {
		return nil, 0, cborErr("bad input size")
	}
	s := &cborState{data: data}
	v, err := s.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, s.offset, nil
}

// decodeCBORExact decodes data as exactly one item.
func decodeCBORExact(data []byte) (any, error) {
	v, size, err := decodeCBORPrefix(data)
	if err != nil {
		return nil, err
	}
	if size != len(data) {
		return nil, cborErr("trailing bytes")
	}
	return v, nil
}
