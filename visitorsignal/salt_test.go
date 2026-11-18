package visitorsignal

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func vectorMaster(t testing.TB, vf vectorFile) []byte {
	t.Helper()
	b, err := hex.DecodeString(vf.MasterSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeyAndHashVectors(t *testing.T) {
	t.Parallel()
	var vf vectorFile
	loadJSON(t, "vectors.json", &vf)
	master := vectorMaster(t, vf)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			key, err := DeriveKey(master, v.SiteID, v.Mode, v.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(key); got != v.KeyHex {
				t.Fatalf("key = %s, want %s", got, v.KeyHex)
			}
			h, err := NewHasher(master, v.SiteID, v.Mode, v.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			got, err := h.Hash(v.Components)
			if err != nil {
				t.Fatal(err)
			}
			if got != v.Hash {
				t.Fatalf("hash = %s, want %s", got, v.Hash)
			}
			if !HashesEqual(got, v.Hash) || HashesEqual(got, "x") {
				t.Fatal("HashesEqual misbehaves")
			}
		})
	}
}

func TestDeriveKeyRejects(t *testing.T) {
	t.Parallel()
	good := make([]byte, MinMasterSecretLen)
	tests := []struct {
		name   string
		master []byte
		site   string
		mode   Mode
		epoch  string
		want   error
	}{
		{"short_master", good[:31], "s", ModeAnalytics, "d:2026-11-18", ErrMasterSecretTooShort},
		{"nil_master", nil, "s", ModeAnalytics, "d:2026-11-18", ErrMasterSecretTooShort},
		{"bad_mode", good, "s", ModeOff, "d:2026-11-18", nil},
		{"empty_site", good, "", ModeAnalytics, "d:2026-11-18", nil},
		{"nul_in_site", good, "a\x00b", ModeAnalytics, "d:2026-11-18", nil},
		{"nul_in_epoch", good, "s", ModeAnalytics, "d\x00", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := DeriveKey(tc.master, tc.site, tc.mode, tc.epoch)
			if err == nil {
				t.Fatal("want error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := DeriveKey(good, "s", ModeAnalytics, "d:2026-11-18"); err != nil {
		t.Fatalf("exactly 32 bytes should work: %v", err)
	}
}

func TestMemorySaltProvider(t *testing.T) {
	t.Parallel()
	secret := make([]byte, 32)
	secret[0] = 7
	p, err := NewMemorySaltProvider(map[string][]byte{"a": secret})
	if err != nil {
		t.Fatal(err)
	}
	secret[0] = 9 // caller mutation must not leak in
	got, err := p.MasterSecret(context.Background(), "a")
	if err != nil || got[0] != 7 {
		t.Fatalf("got %v, %v", got, err)
	}
	got[0] = 1 // returned copy must not alias
	again, _ := p.MasterSecret(context.Background(), "a")
	if again[0] != 7 {
		t.Fatal("provider returned an aliased slice")
	}
	if _, err := p.MasterSecret(context.Background(), "zzz"); !errors.Is(err, ErrUnknownSite) {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.MasterSecret(ctx, "a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewMemorySaltProvider(map[string][]byte{"a": make([]byte, 31)}); !errors.Is(err, ErrMasterSecretTooShort) {
		t.Fatalf("err = %v", err)
	}
}

func TestHasherRedactsKey(t *testing.T) {
	t.Parallel()
	master := make([]byte, 32)
	h, err := NewHasher(master, "s", ModeAnalytics, "d:2026-11-18")
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(h.key)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
		for name, arg := range map[string]any{"pointer": h, "value": *h} {
			t.Run(verb+"/"+name, func(t *testing.T) {
				t.Parallel()
				out := fmt.Sprintf(verb, arg)
				if strings.Contains(out, keyHex) || strings.Contains(out, fmt.Sprintf("%v", h.key)) {
					t.Fatalf("key leaked: %s", out)
				}
			})
		}
	}
	if got := fmt.Sprintf("%v", h); got != "visitorsignal.Hasher{redacted}" {
		t.Fatalf("got %q", got)
	}
}
