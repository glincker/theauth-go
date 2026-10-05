package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const setupToken = "smoke-setup-token"

func startServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	base := "http://" + srv.Listener.Addr().String()
	a, err := newApp(context.Background(), options{
		baseURL:        base,
		dbPath:         filepath.Join(t.TempDir(), "app.db"),
		setupToken:     setupToken,
		pollInterval:   time.Second,
		rateLimitPerIP: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = a.handler
	srv.Start()
	t.Cleanup(func() {
		srv.Close()
		a.close()
	})
	return base
}

func postJSON(t *testing.T, c *http.Client, url string, hdr map[string]string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func getStatus(t *testing.T, base, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestSmoke(t *testing.T) {
	base := startServer(t)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	creds := map[string]string{"email": "admin@example.com", "password": "correct horse battery staple"}

	if got := postJSON(t, browser, base+"/auth/email-password/signup", nil, creds).StatusCode; got < 400 {
		t.Fatalf("signup without setup token: status %d, want a refusal", got)
	}
	if got := postJSON(t, browser, base+"/auth/email-password/signup", map[string]string{"X-Setup-Token": setupToken}, creds).StatusCode; got != http.StatusCreated {
		t.Fatalf("first-run signup with setup token: status %d", got)
	}
	other := &http.Client{}
	if got := postJSON(t, other, base+"/auth/email-password/signup", map[string]string{"X-Setup-Token": setupToken},
		map[string]string{"email": "second@example.com", "password": "another long passphrase"}).StatusCode; got < 400 {
		t.Fatalf("second signup: status %d, want closed", got)
	}

	if code, _ := getStatus(t, base, "/api/whoami", ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous /api/whoami: %d", code)
	}

	resp := postJSON(t, browser, base+"/auth/tokens", nil, map[string]any{"name": "ci", "abilities": []string{"read"}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mint token: %d", resp.StatusCode)
	}
	var minted struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&minted); err != nil || minted.Token == "" {
		t.Fatalf("decode minted token: %v", err)
	}
	if code, body := getStatus(t, base, "/api/whoami", minted.Token); code != http.StatusOK || !strings.Contains(body, `"read"`) {
		t.Fatalf("minted token /api/whoami: %d %s", code, body)
	}

	t.Run("device login with mycli", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "mycli")
		if out, err := exec.Command("go", "build", "-o", bin, "./cmd/mycli").CombinedOutput(); err != nil {
			t.Fatalf("build mycli: %v\n%s", err, out)
		}
		home := t.TempDir()
		env := append(os.Environ(), "MYCLI_SERVER="+base, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "APPDATA="+home)
		run := func(args ...string) (string, error) {
			cmd := exec.Command(bin, args...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			return string(out), err
		}

		login := exec.Command(bin, "login")
		login.Env = env
		stderr, err := login.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := login.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- login.Wait() }()

		codeRE := regexp.MustCompile(`enter the code (\S+)`)
		sc := bufio.NewScanner(stderr)
		var userCode string
		for sc.Scan() {
			if m := codeRE.FindStringSubmatch(sc.Text()); m != nil {
				userCode = m[1]
				break
			}
		}
		if userCode == "" {
			t.Fatal("mycli never printed a user code")
		}
		go func() { _, _ = io.Copy(io.Discard, stderr) }()

		ar := postJSON(t, browser, base+"/auth/device/approve", nil, map[string]string{"user_code": userCode, "action": "approve"})
		if ar.StatusCode != http.StatusNoContent {
			b, _ := io.ReadAll(ar.Body)
			t.Fatalf("approve: %d code=%q body=%s", ar.StatusCode, userCode, b)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("mycli login: %v", err)
			}
		case <-time.After(20 * time.Second):
			_ = login.Process.Kill()
			t.Fatal("mycli login timed out")
		}

		if out, err := run("whoami"); err != nil || !strings.Contains(out, "read") {
			t.Fatalf("whoami: %v %q", err, out)
		}
		if out, err := run("get", "/api/whoami"); err != nil || !strings.Contains(out, `"userId"`) {
			t.Fatalf("get /api/whoami: %v %q", err, out)
		}
		if out, err := run("logout"); err != nil {
			t.Fatalf("logout: %v %q", err, out)
		}
		if out, err := run("get", "/api/whoami"); err == nil {
			t.Fatalf("get after logout succeeded: %q", out)
		}
	})
}
