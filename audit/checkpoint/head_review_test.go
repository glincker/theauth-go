package checkpoint

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/glincker/theauth-go/v2/internal/models"
	"github.com/glincker/theauth-go/v2/internal/ulid"
)

// ed25519 group order L, little endian bytes are produced from this big endian value.
const ed25519Order = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"

func addOrder(sig []byte) []byte {
	l, _ := new(big.Int).SetString(ed25519Order, 16)
	s := new(big.Int)
	rev := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rev[i] = sig[63-i]
	}
	s.SetBytes(rev)
	s.Add(s, l)
	out := append([]byte(nil), sig...)
	b := s.FillBytes(make([]byte, 32))
	for i := 0; i < 32; i++ {
		out[32+i] = b[31-i]
	}
	return out
}

func TestHeadSignatureEncodingIsNotMalleable(t *testing.T) {
	signer, pub, _ := GenerateKeyPair("k1")
	hc, err := CreateHeadCheckpoint(context.Background(), globalChain(2), HeadOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(hc.Signature)
	cases := map[string]string{
		"embedded newline":   hc.Signature[:10] + "\n" + hc.Signature[10:],
		"trailing newline":   hc.Signature + "\n",
		"embedded cr":        hc.Signature[:5] + "\r" + hc.Signature[5:],
		"padded":             hc.Signature + "==",
		"std alphabet":       strings.NewReplacer("-", "+", "_", "/").Replace(hc.Signature),
		"s plus group order": base64.RawURLEncoding.EncodeToString(addOrder(raw)),
	}
	last := hc.Signature[len(hc.Signature)-1]
	alt := []byte(hc.Signature)
	alt[len(alt)-1] = base64.RawURLEncoding.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})[85]
	if alt[len(alt)-1] != last {
		cases["nonzero trailing bits"] = string(alt)
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			h := hc
			h.Signature = sig
			if o := VerifyHeadCheckpoint(h, pub); o.Valid {
				t.Fatalf("accepted a second encoding of the signature: %q", sig)
			}
		})
	}
	// The public key encoding must be as strict as the signature.
	badKey := pub
	badKey.PublicKey.X = pub.PublicKey.X[:8] + "\n" + pub.PublicKey.X[8:]
	if o := VerifyHeadCheckpoint(hc, badKey); o.Valid {
		t.Fatal("accepted a public key with an embedded newline")
	}
}

func TestHeadAndMerkleSignaturesDoNotCross(t *testing.T) {
	ctx := context.Background()
	signer, pub, _ := GenerateKeyPair("k1")
	hc, _ := CreateHeadCheckpoint(ctx, globalChain(2), HeadOptions{Signer: signer})
	cp := Checkpoint{Version: checkpointVersion, Alg: algEd25519, KeyID: "k1", RootHash: hashOf(1), Signature: hc.Signature}
	if o := VerifyCheckpoint(cp, pub); o.Valid {
		t.Fatal("head signature verified as a Merkle checkpoint")
	}
	// A Merkle signature, whatever it covers, must not verify as a head signature.
	msg, _ := signedBytes(cp)
	sig, _ := signer.Sign(msg)
	h := hc
	h.Signature = base64.RawURLEncoding.EncodeToString(sig)
	if o := VerifyHeadCheckpoint(h, pub); o.Valid {
		t.Fatal("Merkle signature verified as a head checkpoint")
	}
	if strings.HasPrefix(signDomain, headSignDomain) || strings.HasPrefix(headSignDomain, signDomain) {
		t.Fatal("signing domains share a prefix")
	}
	// A signer that signs raw bytes for the head message must not produce a Merkle-valid signature.
	hm, _ := headSignedBytes(hc)
	if !ed25519.Verify(mustPub(t, pub), hm, mustSig(t, hc.Signature)) {
		t.Fatal("sanity: head signature should cover headSignedBytes")
	}
}

func mustPub(t *testing.T, k PublicKey) ed25519.PublicKey {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(k.PublicKey.X)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustSig(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHeadCheckpointShapeRejections(t *testing.T) {
	signer, pub, _ := GenerateKeyPair("k1")
	org := ulid.New()
	log := append(globalChain(2), models.AuditEvent{ID: ulid.New(), OrganizationID: &org, ChainSeq: 1, Hash: hashOf(7)})
	hc, _ := CreateHeadCheckpoint(context.Background(), log, HeadOptions{Signer: signer})
	cases := map[string]func(h *HeadCheckpoint){
		"reordered heads":  func(h *HeadCheckpoint) { h.Heads[0], h.Heads[1] = h.Heads[1], h.Heads[0] },
		"duplicate chain":  func(h *HeadCheckpoint) { h.Heads[1] = h.Heads[0] },
		"zero seq":         func(h *HeadCheckpoint) { h.Heads[0].Seq = 0 },
		"uppercase hash":   func(h *HeadCheckpoint) { h.Heads[0].Hash = strings.ToUpper(h.Heads[0].Hash) },
		"dropped one head": func(h *HeadCheckpoint) { h.Heads = h.Heads[:1] },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			h := hc
			h.Heads = append([]ChainHead(nil), hc.Heads...)
			edit(&h)
			if o := VerifyHeadCheckpoint(h, pub); o.Valid {
				t.Fatal("accepted")
			}
		})
	}
	if res, _ := CheckHeadCheckpoint(context.Background(), log[:2], hc, pub); res.Valid || res.Reason != ReasonChainTruncated || res.ChainKey != org.String() {
		t.Fatalf("lost org chain = %+v", res)
	}
}

func TestHeadCheckpointRowNoLongerRetained(t *testing.T) {
	ctx := context.Background()
	signer, pub, _ := GenerateKeyPair("k1")
	log := globalChain(4)
	hc, _ := CreateHeadCheckpoint(ctx, log[:2], HeadOptions{Signer: signer})
	// Rows 1 and 2 are gone but the chain grew past the signed head: not a mismatch, not a forgery.
	if res, _ := CheckHeadCheckpoint(ctx, log[2:], hc, pub); res.Valid || res.Reason != ReasonHeadNotRetained {
		t.Fatalf("evicted = %+v", res)
	}
	// A retained row with the wrong hash is still a mismatch.
	bad := append(fakeEvents(nil), log...)
	bad[1].Hash = hashOf(90)
	if res, _ := CheckHeadCheckpoint(ctx, bad, hc, pub); res.Valid || res.Reason != ReasonHeadMismatch {
		t.Fatalf("rewritten = %+v", res)
	}
}
