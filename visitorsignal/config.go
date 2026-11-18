package visitorsignal

import (
	"errors"
	"time"
)

// Config holds every tunable threshold. The package has no hidden limits in
// its code paths, so a host application loads these from its own environment.
type Config struct {
	// MaxBodyBytes caps the raw payload size accepted by validation.
	MaxBodyBytes int64
	// FraudWindowDays is the epoch length in days for fraud_prevention mode.
	FraudWindowDays int
	// EpochGrace is how long after an epoch starts the previous epoch is
	// still reported by EpochIDs, so a lookup survives the rotation.
	EpochGrace time.Duration
}

// DefaultConfig returns the documented defaults: an 8 KiB body cap, 30 day
// fraud epochs and a one hour grace window.
func DefaultConfig() Config {
	return Config{
		MaxBodyBytes:    8 * 1024,
		FraudWindowDays: 30,
		EpochGrace:      time.Hour,
	}
}

// Validate reports a configuration that cannot be used.
func (c Config) Validate() error {
	if c.MaxBodyBytes <= 0 {
		return errors.New("visitorsignal: MaxBodyBytes must be positive")
	}
	if c.FraudWindowDays <= 0 {
		return errors.New("visitorsignal: FraudWindowDays must be positive")
	}
	if c.EpochGrace < 0 {
		return errors.New("visitorsignal: EpochGrace must not be negative")
	}
	return nil
}
