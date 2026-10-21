package mqttauth

import "testing"

func TestMatchTopic(t *testing.T) {
	cases := []struct {
		filter, name string
		want         bool
	}{
		// MQTT 5.0 section 4.7.1.2 examples.
		{"sport/tennis/player1/#", "sport/tennis/player1", true},
		{"sport/tennis/player1/#", "sport/tennis/player1/ranking", true},
		{"sport/tennis/player1/#", "sport/tennis/player1/score/wimbledon", true},
		{"sport/#", "sport", true},
		{"#", "sport/tennis", true},
		{"#", "/", true},
		// Section 4.7.1.3 examples.
		{"sport/tennis/+", "sport/tennis/player1", true},
		{"sport/tennis/+", "sport/tennis/player2", true},
		{"sport/tennis/+", "sport/tennis/player1/ranking", false},
		{"sport/+", "sport", false},
		{"sport/+", "sport/", true},
		{"+", "finance", true},
		{"+/tennis/#", "sport/tennis/x/y", true},
		{"+/+", "/finance", true},
		{"/+", "/finance", true},
		{"+", "/finance", false},
		// Literals and empty levels.
		{"a/b", "a/b", true},
		{"a/b", "a/b/c", false},
		{"a/b/c", "a/b", false},
		{"a//b", "a//b", true},
		{"a/+/b", "a//b", true},
		{"A/b", "a/b", false},
		// Section 4.7.2: $ topics.
		{"#", "$SYS/broker/load", false},
		{"+/monitor/Clients", "$SYS/monitor/Clients", false},
		{"$SYS/#", "$SYS/broker/load", true},
		{"$SYS/monitor/+", "$SYS/monitor/Clients", true},
		{"#", "$data", false},
		{"$data/#", "$data", true},
	}
	for _, c := range cases {
		if got := MatchTopic(c.filter, c.name); got != c.want {
			t.Errorf("MatchTopic(%q, %q) = %v, want %v", c.filter, c.name, got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	badNames := []string{"", "a/+", "a/#", "#", "a\x00b"}
	for _, n := range badNames {
		if ValidateTopicName(n) == nil {
			t.Errorf("name %q accepted", n)
		}
	}
	for _, n := range []string{"a", "/", "a//b", "$SYS/x", "sensor/1/temp"} {
		if err := ValidateTopicName(n); err != nil {
			t.Errorf("name %q rejected: %v", n, err)
		}
	}
	badFilters := []string{"", "a/#/b", "a#", "a+", "a/b+/c", "+a", "#/a", "a/#b", "a\x00"}
	for _, f := range badFilters {
		if ValidateFilter(f) == nil {
			t.Errorf("filter %q accepted", f)
		}
	}
	for _, f := range []string{"#", "+", "+/+", "a/+/#", "/", "a//b", "$SYS/#", "a/b"} {
		if err := ValidateFilter(f); err != nil {
			t.Errorf("filter %q rejected: %v", f, err)
		}
	}
}

func TestParseSubscription(t *testing.T) {
	ok := []struct {
		raw  string
		want Subscription
	}{
		{"a/b", Subscription{Filter: "a/b"}},
		{"$share/g1/a/+", Subscription{Filter: "a/+", Group: "g1", Shared: true}},
		{"$share/g/#", Subscription{Filter: "#", Group: "g", Shared: true}},
		{"$SYS/#", Subscription{Filter: "$SYS/#"}},
	}
	for _, c := range ok {
		got, err := ParseSubscription(c.raw)
		if err != nil || got != c.want {
			t.Errorf("ParseSubscription(%q) = %+v, %v; want %+v", c.raw, got, err, c.want)
		}
	}
	bad := []string{"$share", "$share/", "$share/g", "$share//a", "$share/g/", "$share/g+/a", "$share/g#/a", "$share/g/a#", ""}
	for _, raw := range bad {
		if _, err := ParseSubscription(raw); err == nil {
			t.Errorf("ParseSubscription(%q) accepted", raw)
		}
	}
}

func TestFilterCovers(t *testing.T) {
	cases := []struct {
		grant, req string
		want       bool
	}{
		{"a/b", "a/b", true},
		{"a/+", "a/b", true},
		{"a/+", "a/+", true},
		{"a/+", "a/#", false},
		{"a/#", "a/+/c", true},
		{"a/#", "a", true},
		{"a/#", "a/#", true},
		{"a/#", "b/#", false},
		{"#", "a/b/#", true},
		{"#", "#", true},
		{"#", "+", true},
		{"#", "$SYS/#", false},
		{"#", "$SYS/x", false},
		{"+/x", "$SYS/x", false},
		{"+/x", "+/x", true},
		{"$SYS/#", "$SYS/broker/#", true},
		{"$SYS/#", "#", false},
		{"a/b", "a/+", false},
		{"a/b", "a", false},
		{"a", "a/b", false},
		{"a/b/c", "a/b", false},
		{"+/b", "a/b", true},
		{"a/+/c", "a/+/c", true},
		{"a/+/c", "a/#", false},
		{"a/b", "a/b/#", false},
	}
	for _, c := range cases {
		if got := FilterCovers(c.grant, c.req); got != c.want {
			t.Errorf("FilterCovers(%q, %q) = %v, want %v", c.grant, c.req, got, c.want)
		}
	}
}

func TestFiltersOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"secret/#", "#", true},
		{"secret/#", "+/x", true},
		{"secret/#", "public/#", false},
		{"a/b", "a/+", true},
		{"a/b", "a/c", false},
		{"a/b", "a", false},
		{"a/#", "a", true},
		{"a/+", "a/b/c", false},
		{"$SYS/#", "#", false},
		{"$SYS/x", "+/x", false},
		{"+/x", "+/x", true},
		{"#", "#", true},
		{"a/+/c", "a/b/+", true},
	}
	for _, c := range cases {
		if got := FiltersOverlap(c.a, c.b); got != c.want {
			t.Errorf("FiltersOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
		if got := FiltersOverlap(c.b, c.a); got != c.want {
			t.Errorf("FiltersOverlap(%q, %q) = %v, want %v (swapped)", c.b, c.a, got, c.want)
		}
	}
}

// FuzzCoversImpliesMatch checks the soundness of FilterCovers: if grant covers req, any topic
// that matches req must match grant.
func FuzzCoversImpliesMatch(f *testing.F) {
	f.Add("a/+", "a/b", "a/b")
	f.Add("#", "$SYS/#", "$SYS/x")
	f.Fuzz(func(t *testing.T, grant, req, name string) {
		if ValidateFilter(grant) != nil || ValidateFilter(req) != nil || ValidateTopicName(name) != nil {
			return
		}
		if FilterCovers(grant, req) && MatchTopic(req, name) && !MatchTopic(grant, name) {
			t.Fatalf("covers(%q,%q) but %q matches only req", grant, req, name)
		}
		if MatchTopic(req, name) && MatchTopic(grant, name) && !FiltersOverlap(grant, req) {
			t.Fatalf("overlap(%q,%q) false but %q matches both", grant, req, name)
		}
	})
}
