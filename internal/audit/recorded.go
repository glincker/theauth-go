package audit

import (
	"sync/atomic"
	"time"
)

var lastRecordedUs atomic.Int64

// NextRecordedAtUs returns the next write-order stamp in microseconds:
// max(now, last stamp issued by this process + 1, floor + 1). Pass the chain
// head's stamp as floor when the append already holds the head, so a stalled
// clock or another process that wrote ahead cannot make a stamp repeat or go
// backwards. Safe for concurrent use. The stamp is never hashed.
func NextRecordedAtUs(floor int64) int64 {
	for {
		last := lastRecordedUs.Load()
		next := max(time.Now().UnixMicro(), last+1, floor+1)
		if lastRecordedUs.CompareAndSwap(last, next) {
			return next
		}
	}
}
