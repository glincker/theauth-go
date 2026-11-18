package visitorsignal

import (
	"fmt"
	"strconv"
	"time"
)

const secondsPerDay = 86400

// EpochID returns the epoch identifier for mode at time t: "d:YYYY-MM-DD" in
// analytics mode (UTC day) and "w<days>:<index>" in fraud_prevention mode.
func EpochID(mode Mode, t time.Time, cfg Config) (string, error) {
	id, _, err := epochAt(mode, t, cfg)
	return id, err
}

// EpochIDs returns the current epoch and, while t is within cfg.EpochGrace of
// the epoch start, the previous one, so a lookup survives the rotation.
func EpochIDs(mode Mode, t time.Time, cfg Config) ([]string, error) {
	cur, start, err := epochAt(mode, t, cfg)
	if err != nil {
		return nil, err
	}
	ids := []string{cur}
	if cfg.EpochGrace > 0 && t.Sub(start) < cfg.EpochGrace {
		prev, _, err := epochAt(mode, start.Add(-time.Second), cfg)
		if err != nil {
			return nil, err
		}
		ids = append(ids, prev)
	}
	return ids, nil
}

// epochAt returns the epoch id and the UTC instant the epoch started.
func epochAt(mode Mode, t time.Time, cfg Config) (string, time.Time, error) {
	if err := cfg.Validate(); err != nil {
		return "", time.Time{}, err
	}
	u := t.UTC()
	switch mode {
	case ModeAnalytics:
		start := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
		return "d:" + start.Format("2006-01-02"), start, nil
	case ModeFraudPrevention:
		window := int64(cfg.FraudWindowDays)
		index := floorDiv(floorDiv(u.Unix(), secondsPerDay), window)
		start := time.Unix(index*window*secondsPerDay, 0).UTC()
		return "w" + strconv.Itoa(cfg.FraudWindowDays) + ":" + strconv.FormatInt(index, 10), start, nil
	default:
		return "", time.Time{}, fmt.Errorf("visitorsignal: no epoch for mode %q", mode)
	}
}

// floorDiv rounds toward negative infinity so pre-1970 times stay monotonic.
func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}
