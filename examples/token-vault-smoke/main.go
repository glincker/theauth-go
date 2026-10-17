// Command token-vault-smoke checks a token vault provider preset against the
// REAL provider, using your own test credentials. It sends one refresh_token
// grant through tokenvault.RefresherFromPreset. Nothing runs in CI, and no
// credentials are built into the program.
//
// Usage:
//
//	PROVIDER=github CLIENT_ID=... CLIENT_SECRET=... REFRESH_TOKEN=... \
//	  go run ./examples/token-vault-smoke
//	PROVIDER=github go run ./examples/token-vault-smoke --dry-run
//
// Output has the provider, HTTP status and token metadata. Token values are
// never printed. Failures print the provider's error code only.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2/tokenvault"
)

const (
	mask         = "***"
	timeout      = 15 * time.Second
	maxBodyBytes = 1 << 20
)

var safeErrorCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

// codeCapture records the HTTP status and the provider's error code from the
// token response. The body is replayed so the refresher can still parse it.
type codeCapture struct {
	base      http.RoundTripper
	status    int
	errorCode string
}

func (c *codeCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	c.status = resp.StatusCode
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && safeErrorCode.MatchString(parsed.Error) {
		c.errorCode = parsed.Error
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func main() {
	os.Exit(run())
}

func run() int {
	dryRun := flag.Bool("dry-run", false, "print the request shape with values masked; send nothing")
	flag.Parse()

	id := os.Getenv("PROVIDER")
	preset, known := tokenvault.Presets[id]
	if !known {
		ids := make([]string, 0, len(tokenvault.Presets))
		for k := range tokenvault.Presets {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		fmt.Fprintf(os.Stderr, "Refusing to run: PROVIDER must be a known preset id. Known ids: %s\n", strings.Join(ids, ", "))
		return 1
	}

	env := map[string]string{
		"CLIENT_ID":     os.Getenv("CLIENT_ID"),
		"CLIENT_SECRET": os.Getenv("CLIENT_SECRET"),
		"REFRESH_TOKEN": os.Getenv("REFRESH_TOKEN"),
	}
	var missing []string
	for _, k := range []string{"CLIENT_ID", "CLIENT_SECRET", "REFRESH_TOKEN"} {
		if env[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 && !*dryRun {
		fmt.Fprintf(os.Stderr, "Missing env vars: %s\n", strings.Join(missing, ", "))
		return 1
	}

	clientID, clientSecret, refreshToken := env["CLIENT_ID"], env["CLIENT_SECRET"], env["REFRESH_TOKEN"]
	if *dryRun {
		printDryRun(id, preset)
		return 0
	}

	capture := &codeCapture{base: http.DefaultTransport}
	client := &http.Client{Timeout: timeout, Transport: capture}
	refresher, err := tokenvault.RefresherFromPreset(id, clientID, clientSecret, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "provider=%s error=preset_invalid\n", id)
		return 1
	}

	tok, err := refresher.Refresh(context.Background(), refreshToken)
	if err != nil {
		code := capture.errorCode
		if code == "" {
			if capture.status != 0 && capture.status != http.StatusOK {
				code = fmt.Sprintf("http_%d", capture.status)
			} else {
				code = "refresh_failed"
			}
		}
		fmt.Fprintf(os.Stderr, "provider=%s status=%d error=%s\n", id, capture.status, code)
		return 1
	}

	fmt.Printf("provider: %s\n", id)
	fmt.Printf("http status: %d\n", capture.status)
	fmt.Printf("access_token returned: %t\n", tok.AccessToken != "")
	fmt.Printf("expires_in: %s\n", expiresIn(tok.ExpiresIn))
	fmt.Printf("new refresh_token returned (rotation): %t\n", tok.RefreshToken != "" && tok.RefreshToken != refreshToken)
	fmt.Printf("scope: %s\n", scopeString(tok.Scopes))
	return 0
}

// printDryRun shows the request the refresher would send, mirroring
// OAuthRefresher.Refresh. Every value is masked.
func printDryRun(id string, preset tokenvault.Preset) {
	basic := preset.AuthStyle != tokenvault.AuthPost
	keys := []string{"grant_type", "refresh_token"}
	headers := []string{"Content-Type", "Accept"}
	if basic {
		headers = append(headers, "Authorization")
	} else {
		keys = append(keys, "client_id", "client_secret")
	}
	authStyle := "client_secret_post"
	if basic {
		authStyle = "client_secret_basic"
	}
	masked := make([]string, 0, len(keys))
	for _, k := range keys {
		masked = append(masked, k+"="+mask)
	}
	fmt.Println("dry-run: nothing is sent")
	fmt.Printf("provider: %s\n", id)
	fmt.Printf("request: POST %s\n", preset.TokenURL)
	fmt.Printf("auth style: %s\n", authStyle)
	fmt.Printf("header names: %s\n", strings.Join(headers, ", "))
	fmt.Printf("body keys: %s\n", strings.Join(masked, ", "))
}

func expiresIn(d time.Duration) string {
	if d == 0 {
		return "none"
	}
	return fmt.Sprintf("%d", int64(d/time.Second))
}

func scopeString(scopes []string) string {
	if len(scopes) == 0 {
		return "(none)"
	}
	return strings.Join(scopes, " ")
}
