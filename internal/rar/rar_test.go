package rar

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		max     int
		wantErr bool
		wantLen int
	}{
		{"empty is none", "", 0, false, 0},
		{"one object", `[{"type":"payment"}]`, 0, false, 1},
		{"full common fields", `[{"type":"p","locations":["https://a"],"actions":["x"],"datatypes":["d"],"identifier":"i","privileges":["v"]}]`, 0, false, 1},
		{"unknown members kept", `[{"type":"p","creditorName":"ACME"}]`, 0, false, 1},
		{"not an array", `{"type":"p"}`, 0, true, 0},
		{"empty array", `[]`, 0, true, 0},
		{"null entry", `[null]`, 0, true, 0},
		{"string entry", `["p"]`, 0, true, 0},
		{"missing type", `[{"actions":["x"]}]`, 0, true, 0},
		{"empty type", `[{"type":""}]`, 0, true, 0},
		{"type wrong shape", `[{"type":5}]`, 0, true, 0},
		{"actions wrong shape", `[{"type":"p","actions":"x"}]`, 0, true, 0},
		{"locations wrong shape", `[{"type":"p","locations":[1]}]`, 0, true, 0},
		{"identifier wrong shape", `[{"type":"p","identifier":[]}]`, 0, true, 0},
		{"trailing data", `[{"type":"p"}] x`, 0, true, 0},
		{"over the cap", `[{"type":"a"},{"type":"b"},{"type":"c"}]`, 2, true, 0},
		{"at the cap", `[{"type":"a"},{"type":"b"}]`, 2, false, 2},
		{"not json", `payment`, 0, true, 0},
		{"too large", `[{"type":"p","x":"` + strings.Repeat("a", MaxEncodedBytes) + `"}]`, 0, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.raw, tc.max)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v does not wrap ErrInvalid", err)
			}
			if len(got) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(got), tc.wantLen)
			}
		})
	}
}

func TestRoundTripKeepsUnknownFields(t *testing.T) {
	in := `[{"type":"payment","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`
	list, err := Parse(in, 0)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseBytes(enc, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(list, again) {
		t.Fatalf("round trip changed the value:\n%v\n%v", list, again)
	}
	if again[0].Fields["instructedAmount"] == nil {
		t.Fatal("type specific member lost")
	}
}

func TestMarshalEmpty(t *testing.T) {
	if b, err := Marshal(nil); b != nil || err != nil {
		t.Fatalf("got %s, %v", b, err)
	}
}

func TestTypes(t *testing.T) {
	list := []Detail{{Type: "b"}, {Type: "a"}, {Type: "b"}}
	if got := Types(list); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("got %v", got)
	}
}

func TestNarrow(t *testing.T) {
	grant := []Detail{{
		Type: "payment", Locations: []string{"https://bank"}, Actions: []string{"initiate", "status"},
		Identifier: "acct-1", Fields: map[string]any{"currency": "EUR"},
	}}
	tests := []struct {
		name string
		req  []Detail
		ok   bool
		want func(t *testing.T, got []Detail)
	}{
		{"type only inherits the grant", []Detail{{Type: "payment"}}, true, func(t *testing.T, got []Detail) {
			if !reflect.DeepEqual(got[0].Actions, []string{"initiate", "status"}) || got[0].Identifier != "acct-1" || got[0].Fields["currency"] != "EUR" {
				t.Fatalf("got %+v", got[0])
			}
		}},
		{"subset of actions", []Detail{{Type: "payment", Actions: []string{"status"}}}, true, func(t *testing.T, got []Detail) {
			if !reflect.DeepEqual(got[0].Actions, []string{"status"}) {
				t.Fatalf("got %+v", got[0])
			}
		}},
		{"extra action", []Detail{{Type: "payment", Actions: []string{"status", "cancel"}}}, false, nil},
		{"other type", []Detail{{Type: "account"}}, false, nil},
		{"other location", []Detail{{Type: "payment", Locations: []string{"https://evil"}}}, false, nil},
		{"other identifier", []Detail{{Type: "payment", Identifier: "acct-2"}}, false, nil},
		{"conflicting field", []Detail{{Type: "payment", Fields: map[string]any{"currency": "USD"}}}, false, nil},
		{"new field on a constrained grant", []Detail{{Type: "payment", Fields: map[string]any{"limit": 5}}}, false, nil},
		{"one of two uncovered", []Detail{{Type: "payment"}, {Type: "account"}}, false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Narrow(tc.req, grant)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && tc.want != nil {
				tc.want(t, got)
			}
		})
	}

	t.Run("grant without lists allows any request list", func(t *testing.T) {
		got, ok := Narrow([]Detail{{Type: "t", Actions: []string{"x"}, Identifier: "i"}}, []Detail{{Type: "t"}})
		if !ok || got[0].Actions[0] != "x" || got[0].Identifier != "i" {
			t.Fatalf("got %+v ok=%v", got, ok)
		}
	})
	t.Run("never wider than the grant", func(t *testing.T) {
		if _, ok := Narrow([]Detail{{Type: "t"}}, nil); ok {
			t.Fatal("an empty grant covers nothing")
		}
	})
}

func TestClaimConversion(t *testing.T) {
	list := []Detail{{Type: "payment", Actions: []string{"initiate"}, Fields: map[string]any{"n": float64(2)}}}
	v, err := ToAny(list)
	if err != nil {
		t.Fatal(err)
	}
	back := FromAny(v)
	if !reflect.DeepEqual(back, list) {
		t.Fatalf("got %+v", back)
	}
	if FromAny(nil) != nil || FromAny("junk") != nil {
		t.Fatal("non conforming claim values must yield nil")
	}
	if v, err := ToAny(nil); v != nil || err != nil {
		t.Fatalf("got %v, %v", v, err)
	}
}

func TestMarshalRegisteredMembersWin(t *testing.T) {
	d := Detail{Type: "real", Fields: map[string]any{"type": "spoof", "actions": []string{"spoof"}}, Actions: []string{"ok"}}
	b, err := d.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "real" || !reflect.DeepEqual(m["actions"], []any{"ok"}) {
		t.Fatalf("got %s", b)
	}
}
