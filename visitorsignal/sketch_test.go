package visitorsignal

import (
	"maps"
	"testing"
)

func TestSketchOfBase(t *testing.T) {
	t.Parallel()
	var vf vectorFile
	loadJSON(t, "vectors.json", &vf)
	var ef extraFile
	loadJSON(t, "vectors-extra.json", &ef)
	master := vectorMaster(t, vf)
	// "basic" signalV1 vector holds the same 16 components as the sketch base.
	base := ef.SignalV1[0].Components
	got, err := Sketch(master, "site_a", ModeAnalytics, "d:2026-11-18", base)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, ef.Sketch.SketchOfBase) {
		t.Fatalf("got %v\nwant %v", got, ef.Sketch.SketchOfBase)
	}
	other, err := Sketch(master, "site_b", ModeAnalytics, "d:2026-11-18", base)
	if err != nil || maps.Equal(other, got) {
		t.Fatalf("other site must differ: %v", err)
	}
}

func TestSimilarityVectors(t *testing.T) {
	t.Parallel()
	var ef extraFile
	loadJSON(t, "vectors-extra.json", &ef)
	if !maps.Equal(ef.Sketch.Weights, DefaultSketchWeights) || ef.Sketch.MinOverlap != DefaultSketchMinOverlap {
		t.Fatal("default weights drifted from vectors-extra.json")
	}
	for _, c := range ef.Sketch.Cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			if got := Similarity(c.A, c.B); got != c.Similarity {
				t.Fatalf("got %v, want %v", got, c.Similarity)
			}
			if got := Similarity(c.B, c.A); got != c.Similarity {
				t.Fatalf("not symmetric: %v", got)
			}
		})
	}
}

func TestSimilarityWithOverrides(t *testing.T) {
	t.Parallel()
	a := map[string]string{"tz": "1", "lang": "2", "cores": "3"}
	b := map[string]string{"tz": "1", "lang": "9", "cores": "3"}
	tests := []struct {
		name    string
		weights map[string]float64
		min     int
		want    float64
	}{
		{"min_overlap_met", map[string]float64{"tz": 1, "lang": 1, "cores": 1}, 3, 0.6667},
		{"min_overlap_missed", map[string]float64{"tz": 1, "lang": 1, "cores": 1}, 4, 0},
		{"weighted", map[string]float64{"tz": 2, "lang": 6, "cores": 2}, 3, 0.4},
		{"zero_total_weight", map[string]float64{}, 1, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := SimilarityWith(a, b, tc.weights, tc.min); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSketchRejectsShortMaster(t *testing.T) {
	t.Parallel()
	if _, err := Sketch(make([]byte, 8), "s", ModeAnalytics, "d:x", Components{}); err == nil {
		t.Fatal("want error")
	}
}
