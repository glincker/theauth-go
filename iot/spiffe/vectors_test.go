package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

type vectorFile struct {
	Bundle  json.RawMessage `json:"bundle"`
	BundleB json.RawMessage `json:"bundleB"`
	IDs     []struct {
		ID          string `json:"id"`
		OK          bool   `json:"ok"`
		TrustDomain string `json:"trustDomain"`
		Path        string `json:"path"`
	} `json:"ids"`
	X509 []struct {
		Name           string   `json:"name"`
		Chain          []string `json:"chain"`
		Now            string   `json:"now"`
		SkewSeconds    *int     `json:"skewSeconds"`
		MaxLifetimeSec int      `json:"maxLifetimeSeconds"`
		Expect         expect   `json:"expect"`
	} `json:"x509"`
	JWT []struct {
		Name       string   `json:"name"`
		Token      string   `json:"token"`
		Audience   []string `json:"audience"`
		Now        string   `json:"now"`
		MaxTTLSecs int      `json:"maxTtlSeconds"`
		Expect     expect   `json:"expect"`
	} `json:"jwt"`
}

type expect struct {
	OK          bool     `json:"ok"`
	Code        string   `json:"code"`
	SPIFFEID    string   `json:"spiffeId"`
	TrustDomain string   `json:"trustDomain"`
	Thumbprint  string   `json:"thumbprint"`
	KID         string   `json:"kid"`
	Audience    []string `json:"audience"`
}

func loadVectors(t *testing.T) (vectorFile, *Store) {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(map[string]TrustDomainConfig{
		"example.org": {Bundle: v.Bundle},
		"b.example":   {Bundle: v.BundleB},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return v, store
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestVectorsIDs(t *testing.T) {
	v, _ := loadVectors(t)
	for _, c := range v.IDs {
		id, err := ParseID(c.ID)
		if (err == nil) != c.OK {
			t.Errorf("%.60q: ok=%v want %v (%v)", c.ID, err == nil, c.OK, err)
			continue
		}
		if c.OK && (id.TrustDomain != c.TrustDomain || id.Path != c.Path) {
			t.Errorf("%q: parsed %q %q", c.ID, id.TrustDomain, id.Path)
		}
	}
}

func parseChain(t *testing.T, pems []string) []*x509.Certificate {
	t.Helper()
	var chain []*x509.Certificate
	for _, p := range pems {
		blk, _ := pem.Decode([]byte(p))
		if blk == nil {
			t.Fatal("bad PEM in vector")
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			// A certificate Go refuses to parse is the "garbage" vector: malformed.
			return nil
		}
		chain = append(chain, cert)
	}
	return chain
}

func TestVectorsX509(t *testing.T) {
	v, store := loadVectors(t)
	for _, c := range v.X509 {
		t.Run(c.Name, func(t *testing.T) {
			opts := X509Options{Now: mustTime(t, c.Now), MaxLifetime: time.Duration(c.MaxLifetimeSec) * time.Second}
			if c.SkewSeconds != nil {
				opts.ClockSkew = time.Duration(*c.SkewSeconds) * time.Second
				opts.NoSkew = *c.SkewSeconds == 0
			}
			id, err := VerifyX509(context.Background(), parseChain(t, c.Chain), store, opts)
			if c.Expect.OK {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if id.ID.String != c.Expect.SPIFFEID || id.ID.TrustDomain != c.Expect.TrustDomain || id.Thumbprint != c.Expect.Thumbprint {
					t.Fatalf("got %q %q %q, want %q %q %q", id.ID.String, id.ID.TrustDomain, id.Thumbprint, c.Expect.SPIFFEID, c.Expect.TrustDomain, c.Expect.Thumbprint)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want %s", c.Expect.Code)
			}
			if err.Code != c.Expect.Code {
				t.Fatalf("code %s (%s), want %s", err.Code, err.Reason, c.Expect.Code)
			}
		})
	}
}

func TestVectorsJWT(t *testing.T) {
	v, store := loadVectors(t)
	for _, c := range v.JWT {
		t.Run(c.Name, func(t *testing.T) {
			opts := JWTOptions{Audience: c.Audience, Now: mustTime(t, c.Now), MaxTTL: time.Duration(c.MaxTTLSecs) * time.Second}
			id, err := VerifyJWT(context.Background(), c.Token, store, opts)
			if c.Expect.OK {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if id.ID.String != c.Expect.SPIFFEID || id.KID != c.Expect.KID || len(id.Audience) != len(c.Expect.Audience) {
					t.Fatalf("got %+v, want %+v", id, c.Expect)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted, want %s", c.Expect.Code)
			}
			if err.Code != c.Expect.Code {
				t.Fatalf("code %s (%s), want %s", err.Code, err.Reason, c.Expect.Code)
			}
		})
	}
}
