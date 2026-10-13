package signals

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DeliveryResult summarizes one DeliverDue pass.
type DeliveryResult struct {
	Delivered int
	Retried   int
	Dropped   int
}

// backoff returns the delay before attempt n+1 (n is the number of failed
// attempts so far, at least 1): base * 2^(n-1), capped.
func (t *Transmitter) backoff(n int) time.Duration {
	d := t.cfg.BackoffBase
	for i := 1; i < n; i++ {
		d *= 2
		if d >= t.cfg.BackoffMax {
			return t.cfg.BackoffMax
		}
	}
	if d > t.cfg.BackoffMax {
		return t.cfg.BackoffMax
	}
	return d
}

// DeliverDue pushes every queued SET that is due (RFC 8935). A 2xx answer
// acknowledges the SET. Network errors, 408, 429 and 5xx are retried with
// exponential backoff up to MaxAttempts; any other status (for example a
// 400 carrying an RFC 8935 err) drops the SET because retrying the same
// token cannot succeed.
func (t *Transmitter) DeliverDue(ctx context.Context) (DeliveryResult, error) {
	var res DeliveryResult
	now := t.cfg.Clock()
	due, err := t.store.DuePush(ctx, now, 100)
	if err != nil {
		return res, err
	}
	streams := map[string]Stream{}
	for _, p := range due {
		s, ok := streams[p.StreamID]
		if !ok {
			s, err = t.store.GetStream(ctx, p.StreamID)
			if err != nil {
				_ = t.store.Drop(ctx, p.ID)
				continue
			}
			streams[p.StreamID] = s
		}
		if s.Status != StatusEnabled || !s.IsPush() {
			continue // paused or disabled: keep queued, do not burn attempts
		}
		retry, derr := t.pushOne(ctx, s, p)
		switch {
		case derr == nil:
			_ = t.store.Drop(ctx, p.ID)
			res.Delivered++
		case retry && p.Attempts+1 < t.cfg.MaxAttempts:
			n := p.Attempts + 1
			_ = t.store.MarkAttempt(ctx, p.ID, n, now.Add(t.backoff(n)))
			res.Retried++
			t.log.Warn("signals: push failed, will retry", "stream", s.ID, "jti", p.JTI, "attempt", n, "error", derr)
		default:
			_ = t.store.Drop(ctx, p.ID)
			res.Dropped++
			t.log.Error("signals: push failed permanently", "stream", s.ID, "jti", p.JTI, "error", derr)
		}
	}
	return res, nil
}

// pushOne performs one POST. retry reports whether a failure is transient.
func (t *Transmitter) pushOne(ctx context.Context, s Stream, p PendingSET) (retry bool, err error) {
	if err := ValidateEndpointURL(ctx, s.Delivery.EndpointURL, t.urlPolicy()); err != nil {
		return false, err
	}
	rctx, cancel := context.WithTimeout(ctx, t.cfg.PushTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, s.Delivery.EndpointURL, strings.NewReader(p.Token))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	if h := s.Delivery.AuthorizationHeader; h != "" {
		req.Header.Set("Authorization", h)
	}
	resp, err := t.hc.Do(req)
	if err != nil {
		return true, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return true, fmt.Errorf("receiver answered %d", resp.StatusCode)
	}
	return false, fmt.Errorf("receiver rejected SET with %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// Start runs the push loop until ctx is cancelled. It delivers whenever an
// event is emitted and every PushInterval to pick up retries.
func (t *Transmitter) Start(ctx context.Context) {
	tick := time.NewTicker(t.cfg.PushInterval)
	defer tick.Stop()
	for {
		if _, err := t.DeliverDue(ctx); err != nil && ctx.Err() == nil {
			t.log.Error("signals: delivery pass failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-t.nudge:
		}
	}
}
