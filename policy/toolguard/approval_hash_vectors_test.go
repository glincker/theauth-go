package toolguard

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type hashVectorResult struct {
	Canonical string `json:"canonical"`
	Hash      string `json:"hash"`
	Error     string `json:"error"`
}

type hashVectorCase struct {
	Name          string           `json:"name"`
	Action        string           `json:"action"`
	Resource      string           `json:"resource"`
	ArgumentsJSON string           `json:"argumentsJson"`
	Float64       hashVectorResult `json:"float64"`
	UseNumber     hashVectorResult `json:"useNumber"`
}

// TestApprovalHashVectors replays testdata/approval-hash-vectors.json, the same fixture the
// TypeScript core checks (tests/fixtures/approval-hash-vectors.json). Every case is decoded both
// with plain json.Unmarshal (float64) and with UseNumber, and the hash or the error must match.
// Run it after any change to the canonicalization code.
func TestApprovalHashVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/approval-hash-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []hashVectorCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 40 {
		t.Fatalf("fixture has %d cases", len(f.Cases))
	}
	for _, c := range f.Cases {
		for _, mode := range []struct {
			name      string
			useNumber bool
			want      hashVectorResult
		}{{"float64", false, c.Float64}, {"useNumber", true, c.UseNumber}} {
			var v any
			dec := json.NewDecoder(bytes.NewReader([]byte(c.ArgumentsJSON)))
			if mode.useNumber {
				dec.UseNumber()
			}
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			got, err := HashApprovalAction(c.Action, c.Resource, v)
			switch {
			case mode.want.Error != "":
				if err == nil {
					t.Errorf("%s/%s: want an error, got hash %s", c.Name, mode.name, got)
				}
			case err != nil:
				t.Errorf("%s/%s: %v", c.Name, mode.name, err)
			case got != mode.want.Hash:
				t.Errorf("%s/%s: hash %s want %s", c.Name, mode.name, got, mode.want.Hash)
			}
		}
	}
}
