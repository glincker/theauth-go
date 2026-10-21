package attest

// berToDER normalizes a BER structure with indefinite lengths (what OpenSSL streaming and Apple emit
// for CMS) into DER-like definite lengths, so the strict DER reader in der.go can parse it. It joins
// the chunks of constructed OCTET STRINGs into one primitive string and leaves definite primitive
// elements byte for byte, which keeps signed attributes and certificates exactly as signed. It is the
// twin of ber.ts.

const (
	maxBERDepth = 24
	maxBERSize  = 1 << 20
)

type berHeader struct {
	id          []byte
	constructed bool
	cls         int
	tag         int
	length      int // -1 for the indefinite form
	start       int
}

func readBERHeader(buf []byte, at int) (berHeader, error) {
	i := at
	if i >= len(buf) {
		return berHeader{}, derErr("empty input")
	}
	first := buf[i]
	i++
	tag := int(first & 0x1f)
	if tag == 0x1f {
		tag = 0
		for n := 0; ; n++ {
			if i >= len(buf) || n > 3 {
				return berHeader{}, derErr("bad high tag number")
			}
			b := buf[i]
			i++
			tag = tag*128 + int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	id := buf[at:i]
	if i >= len(buf) {
		return berHeader{}, derErr("truncated length")
	}
	lenByte := buf[i]
	i++
	length := int(lenByte)
	switch {
	case lenByte == 0x80:
		length = -1
	case lenByte&0x80 != 0:
		count := int(lenByte & 0x7f)
		if count > 4 {
			return berHeader{}, derErr("unsupported length form")
		}
		length = 0
		for n := 0; n < count; n++ {
			if i >= len(buf) {
				return berHeader{}, derErr("truncated length")
			}
			length = length*256 + int(buf[i])
			i++
		}
	}
	return berHeader{id: id, constructed: first&0x20 != 0, cls: int(first >> 6), tag: tag, length: length, start: i}, nil
}

func encodeDERLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for v := n; v > 0; v >>= 8 {
		b = append([]byte{byte(v & 0xff)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

type berNode struct {
	bytes     []byte
	next      int
	primitive []byte
	isPrim    bool
}

func berElement(buf []byte, at, depth int) (berNode, error) {
	if depth > maxBERDepth {
		return berNode{}, derErr("BER nesting is too deep")
	}
	h, err := readBERHeader(buf, at)
	if err != nil {
		return berNode{}, err
	}
	if !h.constructed {
		if h.length < 0 {
			return berNode{}, derErr("indefinite length on a primitive element")
		}
		end := h.start + h.length
		if end > len(buf) {
			return berNode{}, derErr("element runs past its parent")
		}
		return berNode{bytes: buf[at:end], next: end, primitive: buf[h.start:end], isPrim: true}, nil
	}
	var kids []berNode
	i := h.start
	var next int
	if h.length < 0 {
		for {
			if i+1 < len(buf) && buf[i] == 0 && buf[i+1] == 0 {
				next = i + 2
				break
			}
			if i >= len(buf) {
				return berNode{}, derErr("missing end of contents")
			}
			k, err := berElement(buf, i, depth+1)
			if err != nil {
				return berNode{}, err
			}
			kids = append(kids, k)
			i = k.next
		}
	} else {
		end := h.start + h.length
		if end > len(buf) {
			return berNode{}, derErr("element runs past its parent")
		}
		for i < end {
			k, err := berElement(buf[:end], i, depth+1)
			if err != nil {
				return berNode{}, err
			}
			kids = append(kids, k)
			i = k.next
		}
		next = end
	}
	total := 0
	for _, k := range kids {
		total += len(k.bytes)
	}
	if total > maxBERSize {
		return berNode{}, derErr("BER input is too large")
	}
	if h.cls == 0 && h.tag == 4 {
		var body []byte
		for _, k := range kids {
			body = append(body, k.primitive...)
		}
		out := append([]byte{0x04}, encodeDERLength(len(body))...)
		return berNode{bytes: append(out, body...), next: next, primitive: body, isPrim: true}, nil
	}
	body := make([]byte, 0, total)
	for _, k := range kids {
		body = append(body, k.bytes...)
	}
	out := append(append([]byte{}, h.id...), encodeDERLength(len(body))...)
	return berNode{bytes: append(out, body...), next: next}, nil
}

// berToDER normalizes one BER element that spans the whole input.
func berToDER(in []byte) ([]byte, error) {
	n, err := berElement(in, 0, 0)
	if err != nil {
		return nil, err
	}
	if n.next != len(in) {
		return nil, derErr("trailing bytes after element")
	}
	return n.bytes, nil
}
