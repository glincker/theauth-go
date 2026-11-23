package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GoogleAttestationStatusURL is Google's attestation certificate status list.
const GoogleAttestationStatusURL = "https://android.googleapis.com/attestation/status"

const maxStatusListBytes = 32 << 20

var maxAgeRE = regexp.MustCompile(`max-age=(\d+)`)

// GoogleRevocationListOptions are the options of GoogleRevocationList.
type GoogleRevocationListOptions struct {
	// Client is the HTTP client. Default: a client with a 15 second timeout.
	Client *http.Client
	// URL overrides the status list address, for tests or a proxy.
	URL string
	// MaxAge is the refresh interval. Default: the Cache-Control max-age of the response, else one hour.
	MaxAge time.Duration
	// StaleIfError is the longest the cached list may be used after a refresh fails. Default 0:
	// fail closed at once.
	StaleIfError time.Duration
	// Now is the clock. Tests inject one.
	Now func() time.Time
}

type statusFile struct {
	Entries map[string]struct {
		Status string `json:"status"`
	} `json:"entries"`
}

type revocationCache struct {
	serials   map[string]struct{}
	fetchedAt time.Time
	maxAge    time.Duration
}

// GoogleRevocationList returns a RevocationCheck backed by Google's attestation status list
// (https://source.android.com/docs/security/features/keystore/attestation#certificate-revocation-status-list).
// A serial counts as revoked when it has an entry with status REVOKED or SUSPENDED. The list is
// cached by its Cache-Control header. When it cannot be fetched the check returns an error,
// which refuses the enrollment, so a network failure never lets a revoked key through.
func GoogleRevocationList(opts GoogleRevocationListOptions) RevocationCheck {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	url := opts.URL
	if url == "" {
		url = GoogleAttestationStatusURL
	}
	var mu sync.Mutex
	var cached *revocationCache

	refresh := func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return reasonErr(fmt.Sprintf("Revocation list request failed with %d", res.StatusCode))
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, maxStatusListBytes+1))
		if err != nil {
			return err
		}
		if len(body) > maxStatusListBytes {
			return reasonErr(fmt.Sprintf("Revocation list is larger than %d bytes", maxStatusListBytes))
		}
		var file statusFile
		if err := json.Unmarshal(body, &file); err != nil || file.Entries == nil {
			return reasonErr("Revocation list has no entries object")
		}
		serials := map[string]struct{}{}
		for serial, entry := range file.Entries {
			if entry.Status == "REVOKED" || entry.Status == "SUSPENDED" {
				serials[strings.ToLower(serial)] = struct{}{}
			}
		}
		maxAge := opts.MaxAge
		if maxAge <= 0 {
			maxAge = time.Hour
			if m := maxAgeRE.FindStringSubmatch(res.Header.Get("Cache-Control")); m != nil {
				if secs, err := strconv.ParseInt(m[1], 10, 32); err == nil {
					maxAge = time.Duration(secs) * time.Second
				}
			}
		}
		cached = &revocationCache{serials: serials, fetchedAt: now(), maxAge: maxAge}
		return nil
	}

	return func(ctx context.Context, serialHex string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		stale := cached == nil || now().Sub(cached.fetchedAt) >= cached.maxAge
		if stale {
			age := time.Duration(1<<62 - 1)
			if cached != nil {
				age = now().Sub(cached.fetchedAt)
			}
			if err := refresh(ctx); err != nil {
				if cached == nil || age >= cached.maxAge+opts.StaleIfError {
					return false, err
				}
			}
		}
		if cached == nil {
			return true, nil
		}
		_, revoked := cached.serials[strings.ToLower(serialHex)]
		return revoked, nil
	}
}
