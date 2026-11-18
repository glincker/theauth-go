package device

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// vectors.json is produced by docs-local/vectors/gen-device-vectors.mjs from the TS
// reference. These tests replay it: same bundle, same decisions.

type vectorFile struct {
	DeviceID string          `json:"deviceId"`
	JWKS     json.RawMessage `json:"jwks"`
	Bundle   struct {
		Token string `json:"token"`
	} `json:"bundle"`
	Verify []struct {
		Name     string `json:"name"`
		Token    string `json:"token"`
		DeviceID string `json:"deviceId"`
		Issuer   string `json:"issuer"`
		LastSeq  int64  `json:"lastSeq"`
		Now      int64  `json:"now"`
		Expect   struct {
			OK     bool   `json:"ok"`
			Reason string `json:"reason"`
		} `json:"expect"`
		GoExpect *struct {
			OK     bool   `json:"ok"`
			Reason string `json:"reason"`
		} `json:"goExpect"`
	} `json:"verify"`
	Evaluate []struct {
		Name      string         `json:"name"`
		Action    string         `json:"action"`
		Resource  string         `json:"resource"`
		NowMs     int64          `json:"nowMs"`
		Arguments map[string]any `json:"arguments"`
		IP        string         `json:"ip"`
		Calls     *int           `json:"callsInLastHour"`
		Expect    struct {
			Allowed bool   `json:"allowed"`
			Code    string `json:"code"`
		} `json:"expect"`
	} `json:"evaluate"`
	Assertions []struct {
		Name     string          `json:"name"`
		Token    string          `json:"token"`
		JWK      json.RawMessage `json:"jwk"`
		Kid      string          `json:"kid"`
		DeviceID string          `json:"deviceId"`
		Audience string          `json:"audience"`
		Now      int64           `json:"now"`
		Expect   struct {
			OK bool `json:"ok"`
		} `json:"expect"`
	} `json:"assertions"`
	Revocation []struct {
		Name          string `json:"name"`
		Token         string `json:"token"`
		Snapshot      string `json:"snapshot"`
		DeviceID      string `json:"deviceId"`
		MaxAgeSeconds int64  `json:"maxAgeSeconds"`
		Now           int64  `json:"now"`
		LastSeq       int64  `json:"lastSeq"`
		Expect        struct {
			OK     bool   `json:"ok"`
			Reason string `json:"reason"`
		} `json:"expect"`
	} `json:"revocation"`
	Snapshots []struct {
		Name          string `json:"name"`
		Token         string `json:"token"`
		Owner         string `json:"owner"`
		MaxAgeSeconds int64  `json:"maxAgeSeconds"`
		Now           int64  `json:"now"`
		Expect        struct {
			OK  bool            `json:"ok"`
			N   int             `json:"n"`
			Has map[string]bool `json:"has"`
		} `json:"expect"`
	} `json:"snapshots"`
	Thumbprints []struct {
		JWK        json.RawMessage `json:"jwk"`
		Thumbprint string          `json:"thumbprint"`
	} `json:"thumbprints"`
}

func loadVectors(t *testing.T) (*vectorFile, *KeySet) {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(v.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	return &v, keys
}

func TestVectorsVerifyBundle(t *testing.T) {
	v, keys := loadVectors(t)
	for _, c := range v.Verify {
		t.Run(c.Name, func(t *testing.T) {
			wantOK, wantReason := c.Expect.OK, c.Expect.Reason
			if c.GoExpect != nil {
				wantOK, wantReason = c.GoExpect.OK, c.GoExpect.Reason
			}
			_, err := VerifyBundle(c.Token, VerifyOptions{
				Keys: keys, DeviceID: c.DeviceID, Issuer: c.Issuer, LastSeq: c.LastSeq, Now: time.Unix(c.Now, 0),
			})
			if wantOK {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			ve, isVE := err.(*VerifyError)
			if !isVE {
				t.Fatalf("want %s, got %v", wantReason, err)
			}
			if string(ve.Reason) != wantReason {
				t.Fatalf("reason %s, want %s", ve.Reason, wantReason)
			}
		})
	}
}

func TestVectorsEvaluate(t *testing.T) {
	v, keys := loadVectors(t)
	claims, err := VerifyBundle(v.Bundle.Token, VerifyOptions{
		Keys: keys, DeviceID: v.DeviceID, Now: time.UnixMilli(v.Evaluate[0].NowMs),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Evaluate {
		t.Run(c.Name, func(t *testing.T) {
			opts := []Option{WithNow(time.UnixMilli(c.NowMs)), WithIP(c.IP)}
			if c.Arguments != nil {
				opts = append(opts, WithArguments(c.Arguments))
			}
			if c.Calls != nil {
				opts = append(opts, WithCallsInLastHour(*c.Calls))
			}
			got := Evaluate(claims, c.Action, c.Resource, opts...)
			if got.Allowed != c.Expect.Allowed || got.Code != c.Expect.Code {
				t.Fatalf("got %v/%s (%s), want %v/%s", got.Allowed, got.Code, got.Reason, c.Expect.Allowed, c.Expect.Code)
			}
		})
	}
}

func TestVectorsAssertions(t *testing.T) {
	v, _ := loadVectors(t)
	for _, c := range v.Assertions {
		t.Run(c.Name, func(t *testing.T) {
			parsed, err := parseJSON(c.JWK)
			if err != nil {
				t.Fatal(err)
			}
			jwk := parsed.(map[string]any)
			jwk["kid"] = c.Kid
			key, err := publicKeyFromJWK(jwk)
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyAssertion(c.Token, key, c.DeviceID, c.Audience, time.Unix(c.Now, 0))
			if (err == nil) != c.Expect.OK {
				t.Fatalf("got err=%v, want ok=%v", err, c.Expect.OK)
			}
		})
	}
}

func TestVectorsThumbprint(t *testing.T) {
	v, _ := loadVectors(t)
	for _, c := range v.Thumbprints {
		parsed, err := parseJSON(c.JWK)
		if err != nil {
			t.Fatal(err)
		}
		jwk := parsed.(map[string]any)
		jwk["kid"] = "k"
		key, err := publicKeyFromJWK(jwk)
		if err != nil {
			t.Fatal(err)
		}
		if got := key.Thumbprint(); got != c.Thumbprint {
			t.Errorf("%v thumbprint %s, want %s", key.Alg, got, c.Thumbprint)
		}
	}
}

func TestVectorsRevocationInBundle(t *testing.T) {
	v, keys := loadVectors(t)
	if len(v.Revocation) == 0 {
		t.Fatal("no revocation vectors")
	}
	for _, c := range v.Revocation {
		t.Run(c.Name, func(t *testing.T) {
			_, err := VerifyBundle(c.Token, VerifyOptions{
				Keys: keys, DeviceID: c.DeviceID, Now: time.Unix(c.Now, 0),
				Revocations: &RevocationOptions{
					Token: c.Snapshot, MaxAge: time.Duration(c.MaxAgeSeconds) * time.Second, LastSeq: c.LastSeq,
				},
			})
			if c.Expect.OK {
				if err != nil {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			ve, isVE := err.(*VerifyError)
			if !isVE {
				t.Fatalf("want %s, got %v", c.Expect.Reason, err)
			}
			if string(ve.Reason) != c.Expect.Reason {
				t.Fatalf("reason %s (%s), want %s", ve.Reason, ve.Message, c.Expect.Reason)
			}
		})
	}
}

func TestVectorsSnapshotMembership(t *testing.T) {
	v, keys := loadVectors(t)
	for _, c := range v.Snapshots {
		t.Run(c.Name, func(t *testing.T) {
			snap, err := VerifyRevocations(RevocationOptions{
				Token: c.Token, Owner: c.Owner, MaxAge: time.Duration(c.MaxAgeSeconds) * time.Second,
			}, keys, "", time.Unix(c.Now, 0))
			if err != nil {
				t.Fatal(err)
			}
			if snap.Count != c.Expect.N {
				t.Fatalf("count %d, want %d", snap.Count, c.Expect.N)
			}
			for id, want := range c.Expect.Has {
				if got := snap.Contains(id); got != want {
					t.Errorf("Contains(%q) = %v, want %v", id, got, want)
				}
			}
		})
	}
}
