package visitorsignal

import (
	"slices"
	"testing"
	"time"
)

func TestEpochID(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg7 := cfg
	cfg7.FraudWindowDays = 7
	cfgBad := cfg
	cfgBad.FraudWindowDays = 0
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	tests := []struct {
		name string
		mode Mode
		t    time.Time
		cfg  Config
		want string
		err  bool
	}{
		{"analytics_day", ModeAnalytics, at("2026-11-18T12:00:00Z"), cfg, "d:2026-11-18", false},
		{"analytics_converts_to_utc", ModeAnalytics, at("2026-11-18T23:30:00-05:00"), cfg, "d:2026-11-19", false},
		{"analytics_midnight", ModeAnalytics, at("2026-11-19T00:00:00Z"), cfg, "d:2026-11-19", false},
		{"fraud_30_epoch_zero", ModeFraudPrevention, at("1970-01-01T00:00:00Z"), cfg, "w30:0", false},
		{"fraud_30_last_second", ModeFraudPrevention, at("1970-01-30T23:59:59Z"), cfg, "w30:0", false},
		{"fraud_30_next", ModeFraudPrevention, at("1970-01-31T00:00:00Z"), cfg, "w30:1", false},
		{"fraud_7_window", ModeFraudPrevention, at("1970-01-15T00:00:00Z"), cfg7, "w7:2", false},
		{"fraud_pre_1970", ModeFraudPrevention, at("1969-12-31T23:59:59Z"), cfg, "w30:-1", false},
		{"fraud_zero_window", ModeFraudPrevention, at("2026-11-18T00:00:00Z"), cfgBad, "", true},
		{"off_mode", ModeOff, at("2026-11-18T00:00:00Z"), cfg, "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := EpochID(tc.mode, tc.t, tc.cfg)
			if (err != nil) != tc.err || got != tc.want {
				t.Fatalf("got %q, %v; want %q (err %v)", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestEpochIDs(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.EpochGrace = time.Hour
	at := func(s string) time.Time {
		v, _ := time.Parse(time.RFC3339, s)
		return v
	}
	tests := []struct {
		name  string
		mode  Mode
		t     time.Time
		grace time.Duration
		want  []string
	}{
		{"analytics_in_grace", ModeAnalytics, at("2026-11-19T00:30:00Z"), time.Hour, []string{"d:2026-11-19", "d:2026-11-18"}},
		{"analytics_after_grace", ModeAnalytics, at("2026-11-19T01:00:00Z"), time.Hour, []string{"d:2026-11-19"}},
		{"analytics_no_grace", ModeAnalytics, at("2026-11-19T00:00:00Z"), 0, []string{"d:2026-11-19"}},
		{"fraud_in_grace", ModeFraudPrevention, at("1970-01-31T00:10:00Z"), time.Hour, []string{"w30:1", "w30:0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := cfg
			c.EpochGrace = tc.grace
			got, err := EpochIDs(tc.mode, tc.t, c)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"body":   func(c *Config) { c.MaxBodyBytes = 0 },
		"window": func(c *Config) { c.FraudWindowDays = -1 },
		"grace":  func(c *Config) { c.EpochGrace = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := DefaultConfig()
			mut(&c)
			if c.Validate() == nil {
				t.Fatal("want error")
			}
		})
	}
}
