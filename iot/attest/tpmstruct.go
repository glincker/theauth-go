package attest

import (
	"math/big"
)

// Parsers for the TPM 2.0 structures a quote needs, from the TCG TPM 2.0 Library specification
// (https://trustedcomputinggroup.org/resource/tpm-library-specification/), Part 2 "Structures":
// TPMT_PUBLIC (12.2.4), TPMS_ATTEST (10.12.8), TPMS_QUOTE_INFO (10.12.4) and TPMT_SIGNATURE
// (11.3.4). All integers are big endian, every read is bounds checked and every parse must use
// all of its input. Ported from the TypeScript parsers.

const (
	tpmAlgRSA    = 0x0001
	tpmAlgSHA1   = 0x0004
	tpmAlgSHA256 = 0x000b
	tpmAlgSHA384 = 0x000c
	tpmAlgSHA512 = 0x000d
	tpmAlgNull   = 0x0010
	tpmAlgRSASSA = 0x0014
	tpmAlgRSAPSS = 0x0016
	tpmAlgECDSA  = 0x0018
	tpmAlgECC    = 0x0023

	tpmGenerated    = 0xff544347
	tpmSTAttestQuot = 0x8018

	// TPMA_OBJECT bits (Part 2, 8.3.2).
	attrFixedTPM    = 0x2
	attrFixedParent = 0x10
	attrRestricted  = 0x10000
	attrDecrypt     = 0x20000
	attrSign        = 0x40000
)

// hashByAlg maps a TPM_ALG_ID to the hash name the TypeScript verifier uses.
var hashByAlg = map[uint16]string{
	tpmAlgSHA1: "sha1", tpmAlgSHA256: "sha256", tpmAlgSHA384: "sha384", tpmAlgSHA512: "sha512",
}

var hashSize = map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

type tpmReader struct {
	data   []byte
	offset int
}

var errTruncated = reasonErr("TPM structure is truncated")

func (r *tpmReader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.offset {
		return nil, errTruncated
	}
	out := r.data[r.offset : r.offset+n]
	r.offset += n
	return out, nil
}

func (r *tpmReader) u8() (uint8, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *tpmReader) u16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (r *tpmReader) u32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func (r *tpmReader) u64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// sized reads a TPM2B_*: a 16 bit size then that many bytes.
func (r *tpmReader) sized() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	return r.take(int(n))
}

func (r *tpmReader) done() error {
	if r.offset != len(r.data) {
		return reasonErr("TPM structure has trailing bytes")
	}
	return nil
}

type tpmScheme struct{ alg, hash uint16 }

type tpmPublic struct {
	isRSA      bool
	nameAlg    uint16
	attributes uint32
	// scheme is the scheme the key is bound to, nil when the key accepts any (TPM_ALG_NULL).
	scheme *tpmScheme
	rsaN   []byte
	rsaE   uint32
	rsaBit uint16
	curve  string
	eccX   []byte
	eccY   []byte
	// raw is the exact TPMT_PUBLIC bytes, used to compute the key name.
	raw []byte
}

var tpmCurves = map[uint16]string{3: "P-256", 4: "P-384", 5: "P-521"}

// parseTPMPublic accepts TPMT_PUBLIC, or TPM2B_PUBLIC (what tpm2_readpublic and TSS write), told
// apart by the leading size.
func parseTPMPublic(input []byte) (*tpmPublic, error) {
	data := input
	if len(data) > 2 && int(data[0])<<8+int(data[1]) == len(data)-2 {
		data = data[2:]
	}
	r := &tpmReader{data: data}
	typeCode, err := r.u16()
	if err != nil {
		return nil, err
	}
	out := &tpmPublic{raw: data}
	if out.nameAlg, err = r.u16(); err != nil {
		return nil, err
	}
	if out.attributes, err = r.u32(); err != nil {
		return nil, err
	}
	if _, err = r.sized(); err != nil { // authPolicy
		return nil, err
	}
	readSymmetric := func() error {
		v, err := r.u16()
		if err != nil {
			return err
		}
		if v != tpmAlgNull {
			return reasonErr("A signing key must have a null symmetric")
		}
		return nil
	}
	readScheme := func() (*tpmScheme, error) {
		alg, err := r.u16()
		if err != nil {
			return nil, err
		}
		if alg == tpmAlgNull {
			return nil, nil
		}
		if alg != tpmAlgRSASSA && alg != tpmAlgRSAPSS && alg != tpmAlgECDSA {
			return nil, reasonErr("Unsupported signing scheme")
		}
		h, err := r.u16()
		if err != nil {
			return nil, err
		}
		return &tpmScheme{alg: alg, hash: h}, nil
	}
	switch typeCode {
	case tpmAlgRSA:
		out.isRSA = true
		if err = readSymmetric(); err != nil {
			return nil, err
		}
		if out.scheme, err = readScheme(); err != nil {
			return nil, err
		}
		if out.rsaBit, err = r.u16(); err != nil {
			return nil, err
		}
		if out.rsaE, err = r.u32(); err != nil {
			return nil, err
		}
		if out.rsaE == 0 {
			out.rsaE = 65537
		}
		if out.rsaN, err = r.sized(); err != nil {
			return nil, err
		}
	case tpmAlgECC:
		if err = readSymmetric(); err != nil {
			return nil, err
		}
		if out.scheme, err = readScheme(); err != nil {
			return nil, err
		}
		c, err := r.u16()
		if err != nil {
			return nil, err
		}
		curve, ok := tpmCurves[c]
		if !ok {
			return nil, reasonErr("Unsupported curve")
		}
		out.curve = curve
		kdf, err := r.u16()
		if err != nil {
			return nil, err
		}
		if kdf != tpmAlgNull {
			return nil, reasonErr("Unexpected key derivation function")
		}
		if out.eccX, err = r.sized(); err != nil {
			return nil, err
		}
		if out.eccY, err = r.sized(); err != nil {
			return nil, err
		}
	default:
		return nil, reasonErr("Unsupported key type")
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}

type tpmSignature struct {
	alg, hash uint16
	rsa       []byte
	r, s      []byte
}

func parseTPMSignature(data []byte) (*tpmSignature, error) {
	r := &tpmReader{data: data}
	out := &tpmSignature{}
	var err error
	if out.alg, err = r.u16(); err != nil {
		return nil, err
	}
	if out.hash, err = r.u16(); err != nil {
		return nil, err
	}
	switch out.alg {
	case tpmAlgRSASSA:
		out.rsa, err = r.sized()
	case tpmAlgECDSA:
		if out.r, err = r.sized(); err == nil {
			out.s, err = r.sized()
		}
	default:
		return nil, reasonErr("Unsupported signature algorithm")
	}
	if err != nil {
		return nil, err
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}

type pcrSelection struct {
	hash    uint16
	indexes []int
}

type tpmQuote struct {
	extraData       []byte
	resetCount      uint32
	restartCount    uint32
	safe            bool
	firmwareVersion uint64
	selections      []pcrSelection
	pcrDigest       []byte
}

// parseTPMQuote reads a TPMS_ATTEST of type TPM_ST_ATTEST_QUOTE. The magic proves the TPM built
// it, if the signing key is restricted.
func parseTPMQuote(data []byte) (*tpmQuote, error) {
	r := &tpmReader{data: data}
	magic, err := r.u32()
	if err != nil {
		return nil, err
	}
	if magic != tpmGenerated {
		return nil, reasonErr("Quote does not start with TPM_GENERATED_VALUE")
	}
	typ, err := r.u16()
	if err != nil {
		return nil, err
	}
	if typ != tpmSTAttestQuot {
		return nil, reasonErr("Attestation is not a quote")
	}
	q := &tpmQuote{}
	if _, err = r.sized(); err != nil { // qualifiedSigner
		return nil, err
	}
	if q.extraData, err = r.sized(); err != nil {
		return nil, err
	}
	if _, err = r.u64(); err != nil { // clock
		return nil, err
	}
	if q.resetCount, err = r.u32(); err != nil {
		return nil, err
	}
	if q.restartCount, err = r.u32(); err != nil {
		return nil, err
	}
	safe, err := r.u8()
	if err != nil {
		return nil, err
	}
	q.safe = safe != 0
	if q.firmwareVersion, err = r.u64(); err != nil {
		return nil, err
	}
	count, err := r.u32()
	if err != nil {
		return nil, err
	}
	if count == 0 || count > 16 {
		return nil, reasonErr("Quote selects an unreasonable number of PCR banks")
	}
	for i := uint32(0); i < count; i++ {
		hash, err := r.u16()
		if err != nil {
			return nil, err
		}
		n, err := r.u8()
		if err != nil {
			return nil, err
		}
		bitmap, err := r.take(int(n))
		if err != nil {
			return nil, err
		}
		var indexes []int
		for bi, b := range bitmap {
			for bit := 0; bit < 8; bit++ {
				if b&(1<<bit) != 0 {
					indexes = append(indexes, bi*8+bit)
				}
			}
		}
		q.selections = append(q.selections, pcrSelection{hash: hash, indexes: indexes})
	}
	if q.pcrDigest, err = r.sized(); err != nil {
		return nil, err
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return q, nil
}

func bigOf(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
