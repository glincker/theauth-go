package visitorsignal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
)

const sketchTruncBytes = 4

// DefaultSketchWeights is the per-component weight table from SPEC part 2.
// Integrators may pass their own table to SimilarityWith.
var DefaultSketchWeights = map[string]float64{
	"tz": 1, "tzOffsetMin": 0.5, "lang": 1, "langCount": 0.5, "platform": 1,
	"uaBrand": 0.5, "uaMajor": 0.5, "mobile": 1, "screenBucket": 1.5,
	"colorDepth": 0.5, "touchPoints": 1, "cores": 1, "memoryGb": 1,
	"reducedMotion": 0.5, "colorScheme": 0.5, "caps": 1, "renderHash": 2,
}

// DefaultSketchMinOverlap is the least number of shared components for a non-zero score.
const DefaultSketchMinOverlap = 5

// Sketch returns one short keyed hash per present component, scoped to one
// site, mode and epoch. It reveals per-component equality, so it is opt-in.
func Sketch(master []byte, site string, mode Mode, epoch string, c Components) (map[string]string, error) {
	key, err := deriveKey(sketchInfoPrefix, master, site, mode, epoch)
	if err != nil {
		return nil, err
	}
	entries, err := componentEntries(c)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(e.name))
		mac.Write([]byte{0})
		mac.Write([]byte(e.value))
		out[e.name] = hex.EncodeToString(mac.Sum(nil)[:sketchTruncBytes])
	}
	return out, nil
}

// Similarity scores two sketches with the default weights and overlap.
func Similarity(a, b map[string]string) float64 {
	return SimilarityWith(a, b, DefaultSketchWeights, DefaultSketchMinOverlap)
}

// SimilarityWith is Similarity with caller supplied weights and minimum
// overlap. Names without a weight count toward overlap but add no weight.
func SimilarityWith(a, b map[string]string, weights map[string]float64, minOverlap int) float64 {
	shared := 0
	var equal, total float64
	for name, va := range a {
		vb, ok := b[name]
		if !ok {
			continue
		}
		shared++
		w := weights[name]
		total += w
		if va == vb {
			equal += w
		}
	}
	if shared < minOverlap || total == 0 {
		return 0
	}
	return math.Round(equal/total*1e4) / 1e4
}
