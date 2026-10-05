package policy

import (
	"errors"
	"strings"
	"testing"
)

func mustParse(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestParseValid(t *testing.T) {
	p := mustParse(t, `{"version":"1","id":"x","statements":[
	 {"id":"a","effect":"allow","actions":["deploy:*"],"resources":["project/{project_id}"],
	  "conditions":[{"op":"ip_cidr","key":"ip","values":["10.0.0.0/8"]},
	                {"op":"time_window","values":["2026-01-01T00:00:00Z",""]},
	                {"op":"daily_window","values":["09:00","17:00"]},
	                {"op":"in","key":"env","values":["prod","stage"]}]}]}`)
	out, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(out); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestParseInvalid(t *testing.T) {
	st := func(s string) string { return `{"version":"1","statements":[` + s + `]}` }
	tests := map[string]string{
		"empty":           ``,
		"not json":        `nope`,
		"wrong version":   `{"version":"2","statements":[]}`,
		"missing version": `{"statements":[]}`,
		"unknown field":   `{"version":"1","statements":[],"extra":1}`,
		"trailing":        `{"version":"1","statements":[]} {}`,
		"bad effect":      st(`{"effect":"maybe","actions":["a"],"resources":["*"]}`),
		"no actions":      st(`{"effect":"allow","actions":[],"resources":["*"]}`),
		"no resources":    st(`{"effect":"allow","actions":["a"]}`),
		"empty pattern":   st(`{"effect":"allow","actions":[""],"resources":["*"]}`),
		"unknown op":      st(`{"effect":"allow","actions":["a"],"resources":["*"],"conditions":[{"op":"xor","key":"k","values":["1"]}]}`),
		"bad cidr":        st(`{"effect":"allow","actions":["a"],"resources":["*"],"conditions":[{"op":"ip_cidr","values":["nope"]}]}`),
		"bad time":        st(`{"effect":"allow","actions":["a"],"resources":["*"],"conditions":[{"op":"time_window","values":["x","y"]}]}`),
		"bad clock":       st(`{"effect":"allow","actions":["a"],"resources":["*"],"conditions":[{"op":"daily_window","values":["25:00","17:00"]}]}`),
		"equals two vals": st(`{"effect":"allow","actions":["a"],"resources":["*"],"conditions":[{"op":"equals","key":"k","values":["1","2"]}]}`),
		"huge pattern":    st(`{"effect":"allow","actions":["` + strings.Repeat("a", MaxPatternLen+1) + `"],"resources":["*"]}`),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(doc))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"version":"1","statements":[{"effect":"allow","actions":["*"],"resources":["{x}"]}]}`))
	f.Add([]byte(`{"version":"1","statements":[{"effect":"deny","actions":["a"],"resources":["b"],"conditions":[{"op":"ip_cidr","values":["::1/128"]}]}]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		out, err := p.Marshal()
		if err != nil {
			t.Fatalf("valid policy failed to marshal: %v", err)
		}
		if _, err := Parse(out); err != nil {
			t.Fatalf("marshal output failed to parse: %v", err)
		}
		_ = Evaluator{}.Evaluate(Request{Action: "a", Resource: "b", IP: "10.0.0.1"}, p)
	})
}
