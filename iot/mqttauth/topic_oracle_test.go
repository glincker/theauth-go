package mqttauth

import (
	"strings"
	"testing"
)

// The functions below are the original strings.Split implementations of the topic matchers. They
// are kept as an oracle: the allocation free versions in topic.go must give the same answer for
// every input, valid or not.

func oracleValidateFilter(filter string) bool {
	if filter == "" || len(filter) > maxTopicLen || strings.ContainsRune(filter, 0) {
		return false
	}
	levels := strings.Split(filter, "/")
	for i, l := range levels {
		switch {
		case l == "#":
			if i != len(levels)-1 {
				return false
			}
		case l == "+":
		case strings.ContainsAny(l, "+#"):
			return false
		}
	}
	return true
}

func oracleMatchTopic(filter, name string) bool {
	f := strings.Split(filter, "/")
	t := strings.Split(name, "/")
	if strings.HasPrefix(name, "$") && isWild(f[0]) {
		return false
	}
	for i, fl := range f {
		if fl == "#" {
			return true
		}
		if i >= len(t) {
			return false
		}
		if fl != "+" && fl != t[i] {
			return false
		}
	}
	return len(f) == len(t)
}

func oracleFilterCovers(grant, req string) bool {
	g := strings.Split(grant, "/")
	r := strings.Split(req, "/")
	for i := 0; ; i++ {
		if i < len(g) && g[i] == "#" {
			return i != 0 || !dollarLiteral(r[0])
		}
		if i >= len(r) {
			return i >= len(g)
		}
		if i >= len(g) || r[i] == "#" {
			return false
		}
		if g[i] == "+" {
			if i == 0 && dollarLiteral(r[0]) {
				return false
			}
			continue
		}
		if r[i] != g[i] {
			return false
		}
	}
}

func oracleFiltersOverlap(a, b string) bool {
	x := strings.Split(a, "/")
	y := strings.Split(b, "/")
	for i := 0; ; i++ {
		xh := i < len(x) && x[i] == "#"
		yh := i < len(y) && y[i] == "#"
		if xh || yh {
			if i == 0 {
				if xh && dollarLiteral(y[0]) || yh && dollarLiteral(x[0]) {
					return false
				}
			}
			return true
		}
		if i >= len(x) || i >= len(y) {
			return i >= len(x) && i >= len(y)
		}
		if x[i] != "+" && y[i] != "+" && x[i] != y[i] {
			return false
		}
		if i == 0 && (x[0] == "+" && dollarLiteral(y[0]) || y[0] == "+" && dollarLiteral(x[0])) {
			return false
		}
	}
}

// topicCorpus builds every topic of one to four levels over a small alphabet that holds the
// interesting cases: empty levels, wildcards, a "$" level and a level with an embedded wildcard.
func topicCorpus() []string {
	alpha := []string{"", "a", "b", "+", "#", "$s"}
	out := []string{}
	var rec func(prefix []string, depth int)
	rec = func(prefix []string, depth int) {
		if len(prefix) > 0 {
			out = append(out, strings.Join(prefix, "/"))
		}
		if depth == 4 {
			return
		}
		for _, l := range alpha {
			rec(append(append([]string(nil), prefix...), l), depth+1)
		}
	}
	rec(nil, 0)
	return append(out, "", "a#", "+a", "a/b#/c", "$share", "a/\x00")
}

func TestTopicMatchersEqualOracle(t *testing.T) {
	corpus := topicCorpus()
	if len(corpus) < 1500 {
		t.Fatalf("corpus too small: %d", len(corpus))
	}
	for _, a := range corpus {
		if got, want := ValidateFilter(a) == nil, oracleValidateFilter(a); got != want {
			t.Fatalf("ValidateFilter(%q) = %v, oracle %v", a, got, want)
		}
	}
	checked := 0
	for _, a := range corpus {
		if a == "" {
			continue
		}
		for _, b := range corpus {
			if b == "" {
				continue
			}
			if got, want := MatchTopic(a, b), oracleMatchTopic(a, b); got != want {
				t.Fatalf("MatchTopic(%q, %q) = %v, oracle %v", a, b, got, want)
			}
			if got, want := FilterCovers(a, b), oracleFilterCovers(a, b); got != want {
				t.Fatalf("FilterCovers(%q, %q) = %v, oracle %v", a, b, got, want)
			}
			if got, want := FiltersOverlap(a, b), oracleFiltersOverlap(a, b); got != want {
				t.Fatalf("FiltersOverlap(%q, %q) = %v, oracle %v", a, b, got, want)
			}
			checked++
		}
	}
	t.Logf("compared %d pairs", checked)
}

func TestSubstitutePlaceholdersEqualsReplacer(t *testing.T) {
	filters := []string{"", "a/b", "{device_id}", "{org_id}/x", "a/{device_id}/b/{org_id}/#", "{{device_id}}", "{device_id", "{org_id}{device_id}", "x{", "{}", "{ORG_ID}"}
	values := [][2]string{{"d1", "o1"}, {"", ""}, {"{org_id}", "{device_id}"}, {"a/b", "+"}}
	for _, f := range filters {
		for _, v := range values {
			want := strings.NewReplacer("{device_id}", v[0], "{org_id}", v[1]).Replace(f)
			if got := substitutePlaceholders(f, v[0], v[1]); got != want {
				t.Errorf("substitutePlaceholders(%q, %q, %q) = %q, replacer %q", f, v[0], v[1], got, want)
			}
		}
	}
}

func oracleTopicResource(topic string) (string, bool) {
	levels := strings.Split(topic, "/")
	out := make([]string, len(levels))
	for i, l := range levels {
		switch {
		case strings.Contains(l, ":"):
			return "", false
		case l == "+" || l == "#":
			out[i] = "*"
		default:
			out[i] = l
		}
	}
	return ResourcePrefix + strings.Join(out, ":"), true
}

func TestTopicResourceEqualsOracle(t *testing.T) {
	corpus := append(topicCorpus(), "a:b", "a/b:c/d", ":", "a/:/b", "/")
	for _, topic := range corpus {
		got, gok := TopicResource(topic)
		want, wok := oracleTopicResource(topic)
		if got != want || gok != wok {
			t.Fatalf("TopicResource(%q) = %q,%v oracle %q,%v", topic, got, gok, want, wok)
		}
	}
}
