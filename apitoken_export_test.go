package theauth

import "time"

// SetAPITokenClockForTest swaps the clock the API token service reads.
func SetAPITokenClockForTest(a *TheAuth, now func() time.Time) { a.apiTokens.now = now }
