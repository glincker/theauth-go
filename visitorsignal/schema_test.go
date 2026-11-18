package visitorsignal

import (
	"errors"
	"strings"
	"testing"
)

type manifest struct {
	Cases []struct {
		File  string  `json:"file"`
		Valid bool    `json:"valid"`
		Error *string `json:"error"`
	} `json:"cases"`
}

func TestValidatePayloadManifest(t *testing.T) {
	t.Parallel()
	var m manifest
	loadJSON(t, "manifest.json", &m)
	if len(m.Cases) != 14 {
		t.Fatalf("manifest has %d cases, want 14", len(m.Cases))
	}
	for _, tc := range m.Cases {
		t.Run(tc.File, func(t *testing.T) {
			t.Parallel()
			p, err := ValidatePayload(readTestdata(t, tc.File))
			if tc.Valid {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				if p.V != 1 {
					t.Fatalf("V = %d", p.V)
				}
				return
			}
			if err == nil {
				t.Fatal("want error, got valid")
			}
			if got := CodeOf(err); got != ErrorCode(*tc.Error) {
				t.Fatalf("code = %q, want %q (%v)", got, *tc.Error, err)
			}
		})
	}
}

const okBase = `{"v":1,"mode":"analytics","status":"ok","ts":1,"nonce":"abcdefghijklmnop",` +
	`"components":%C,"flags":{"protectedBrowser":false,"webdriver":false,"headlessHint":false,"inconsistent":false}%X}`

func build(comps, extra string) []byte {
	s := strings.Replace(okBase, "%C", comps, 1)
	return []byte(strings.Replace(s, "%X", extra, 1))
}

func TestValidatePayloadRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  []byte
		want ErrorCode
	}{
		{"ok_empty_components", build(`{}`, ""), ""},
		{"not_json", []byte(`nope`), CodeSchemaInvalid},
		{"null_body", []byte(`null`), CodeSchemaInvalid},
		{"array_body", []byte(`[]`), CodeSchemaInvalid},
		{"trailing_data", append(build(`{}`, ""), []byte(` {}`)...), CodeSchemaInvalid},
		{"version_missing", []byte(`{"mode":"analytics"}`), CodeSchemaInvalid},
		{"version_string", []byte(`{"v":"1"}`), CodeSchemaInvalid},
		{"version_zero_wins_over_rest", []byte(`{"v":0,"junk":1}`), CodeUnsupportedVersion},
		{"version_float_one", []byte(`{"v":1.0}`), CodeSchemaInvalid},
		{"wrong_case_key", []byte(strings.Replace(string(build(`{}`, "")), `"mode"`, `"Mode"`, 1)), CodeSchemaInvalid},
		{"null_component", build(`{"tz":null}`, ""), CodeSchemaInvalid},
		{"null_components", build(`null`, ""), CodeSchemaInvalid},
		{"tz_too_long", build(`{"tz":"`+strings.Repeat("a", 65)+`"}`, ""), CodeSchemaInvalid},
		{"tz_offset_high", build(`{"tzOffsetMin":841}`, ""), CodeSchemaInvalid},
		{"tz_offset_fraction", build(`{"tzOffsetMin":1.5}`, ""), CodeSchemaInvalid},
		{"lang_count_high", build(`{"langCount":21}`, ""), CodeSchemaInvalid},
		{"color_depth_bad", build(`{"colorDepth":8}`, ""), CodeSchemaInvalid},
		{"memory_bad", build(`{"memoryGb":3}`, ""), CodeSchemaInvalid},
		{"memory_quarter", build(`{"memoryGb":0.25}`, ""), ""},
		{"color_scheme_bad", build(`{"colorScheme":"sepia"}`, ""), CodeSchemaInvalid},
		{"caps_overflow", build(`{"caps":4294967296}`, ""), CodeSchemaInvalid},
		{"caps_max", build(`{"caps":4294967295}`, ""), ""},
		{"touch_high", build(`{"touchPoints":11}`, ""), CodeSchemaInvalid},
		{"mobile_wrong_type", build(`{"mobile":"yes"}`, ""), CodeSchemaInvalid},
		{"screen_ok", build(`{"screenBucket":"1500x1000@2.0"}`, ""), ""},
		{"screen_no_ratio_fraction", build(`{"screenBucket":"1500x1000@2"}`, ""), ""},
		{"screen_exact", build(`{"screenBucket":"1512x982@2.0"}`, ""), CodeSchemaInvalid},
		{"screen_trailing_newline", build(`{"screenBucket":"1500x1000@2.0\n"}`, ""), CodeSchemaInvalid},
		{"render_hash_in_analytics", build(`{"renderHash":"0123456789abcdef"}`, ""), CodeSchemaInvalid},
		{"unavailable_bad", build(`{}`, `,"unavailable":["gpu"]`), CodeSchemaInvalid},
		{"unavailable_dup", build(`{}`, `,"unavailable":["tz","tz"]`), CodeSchemaInvalid},
		{"collect_ms_high", build(`{}`, `,"collectMs":60001`), CodeSchemaInvalid},
		{"challenge_long", build(`{}`, `,"challenge":"`+strings.Repeat("a", 2049)+`"`), CodeSchemaInvalid},
		{"negative_ts", []byte(strings.Replace(string(build(`{}`, "")), `"ts":1`, `"ts":-1`, 1)), CodeSchemaInvalid},
		{"nonce_bad_char", []byte(strings.Replace(string(build(`{}`, "")), "abcdefghijklmnop", "abcdefghijklmno!", 1)), CodeSchemaInvalid},
		{"nonce_too_long", []byte(strings.Replace(string(build(`{}`, "")), "abcdefghijklmnop", strings.Repeat("a", 65), 1)), CodeSchemaInvalid},
		{"mode_off", []byte(strings.Replace(string(build(`{}`, "")), `"analytics"`, `"off"`, 1)), CodeSchemaInvalid},
		{"status_bad", []byte(strings.Replace(string(build(`{}`, "")), `"ok"`, `"maybe"`, 1)), CodeSchemaInvalid},
		{"unknown_top_level_extra", build(`{}`, `,"x":1`), CodeSchemaInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidatePayload(tc.raw)
			if got := CodeOf(err); got != tc.want {
				t.Fatalf("code = %q, want %q (%v)", got, tc.want, err)
			}
		})
	}
}

func TestValidatePayloadFlagsRange(t *testing.T) {
	t.Parallel()
	raw := strings.Replace(string(build(`{}`, "")), `"inconsistent":false`, `"inconsistent":false,"automationGlobals":33`, 1)
	if _, err := ValidatePayload([]byte(raw)); CodeOf(err) != CodeSchemaInvalid {
		t.Fatalf("err = %v", err)
	}
}

func TestValidatePayloadBodyCap(t *testing.T) {
	t.Parallel()
	raw := build(`{}`, "")
	cfg := DefaultConfig()
	cfg.MaxBodyBytes = int64(len(raw))
	if _, err := ValidatePayloadWithConfig(raw, cfg); err != nil {
		t.Fatalf("at cap: %v", err)
	}
	cfg.MaxBodyBytes--
	if _, err := ValidatePayloadWithConfig(raw, cfg); CodeOf(err) != CodeSchemaInvalid {
		t.Fatalf("over cap: %v", err)
	}
	cfg.MaxBodyBytes = 0
	if _, err := ValidatePayloadWithConfig(raw, cfg); err == nil || CodeOf(err) != "" {
		t.Fatalf("bad config should be a plain error, got %v", err)
	}
}

func TestErrorMatching(t *testing.T) {
	t.Parallel()
	err := newError(CodeNonceReplayed, "x")
	if !errors.Is(err, &Error{Code: CodeNonceReplayed}) {
		t.Fatal("same code should match")
	}
	if errors.Is(err, &Error{Code: CodeRateLimited}) {
		t.Fatal("other code should not match")
	}
	if CodeOf(errors.New("plain")) != "" {
		t.Fatal("plain error has no code")
	}
}
