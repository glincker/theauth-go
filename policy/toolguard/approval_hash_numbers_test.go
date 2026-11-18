package toolguard

import (
	"bytes"
	"encoding/json"
	"testing"
)

func hashJSON(t *testing.T, text string, useNumber bool) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	if useNumber {
		dec.UseNumber()
	}
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	h, err := HashApprovalAction("execute", "bank:transfer", v)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestApprovalHashNumberTextIsCanonical(t *testing.T) {
	same := [][]string{
		{`{"n":1}`, `{"n":1.0}`, `{"n":1e0}`, `{"n":10e-1}`},
		{`{"n":100}`, `{"n":1e2}`, `{"n":1E+2}`, `{"n":100.00}`},
		{`{"n":-0}`, `{"n":-0.0}`, `{"n":-0e5}`},
		{`{"n":1e21}`, `{"n":1E21}`, `{"n":1e+21}`},
		{`{"n":0.0000001}`, `{"n":1e-7}`},
	}
	for _, group := range same {
		want := hashJSON(t, group[0], false)
		for _, g := range group {
			if got := hashJSON(t, g, true); got != want {
				t.Errorf("UseNumber %s differs from float64 %s", g, group[0])
			}
		}
	}
}

func TestApprovalHashKeepsExactIntegers(t *testing.T) {
	a := hashJSON(t, `{"n":9007199254740993}`, true)
	b := hashJSON(t, `{"n":9007199254740992}`, true)
	if a == b {
		t.Fatal("integers beyond 2^53 must stay distinct when decoded with UseNumber")
	}
}

func TestApprovalHashRejectsOutOfRangeNumber(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader([]byte(`{"n":1e999}`)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if _, err := HashApprovalAction("a", "r", v); err == nil {
		t.Fatal("want an error for a number that overflows float64")
	}
}
