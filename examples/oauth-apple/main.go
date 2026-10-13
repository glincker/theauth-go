// Example oauth-apple demonstrates Sign in with Apple.
//
// Apple's protocol uses a JWT-based client secret (ES256). You need four pieces from Apple Developer console: Team ID (10-char string), Key ID (10-char string), a .p8 private key file, and Services ID (bundle ID).
//
// .p8 file: Apple distributes keys as PEM-encoded PKCS#8 EC private keys. Parse with x509.ParsePKCS8PrivateKey after pem.Decode. You can only download the file ONCE from Apple Developer console.
//
// Run with APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_BUNDLE_ID, and APPLE_KEY_FILE environment variables, then visit http://localhost:8092 and click 'Sign in with Apple'.
//
// Prerequisites: register a Services ID in Apple Developer console and configure 'Sign In with Apple' with the redirect URL: http://localhost:8092/auth/providers/apple/callback. Note: Apple requires HTTPS for production; for local testing use a tunnel such as ngrok.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/glincker/theauth-go/v2"
	appleprov "github.com/glincker/theauth-go/v2/provider/apple"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

func main() {
	baseURL := envOr("BASE_URL", "http://localhost:8092")
	addr := envOr("ADDR", ":8092")

	key := loadPrivateKey(os.Getenv("APPLE_KEY_FILE"))

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		log.Fatal(err)
	}

	a, err := theauth.New(theauth.Config{
		Storage:           memory.New(),
		BaseURL:           baseURL,
		EncryptionKey:     encKey,
		PostLoginRedirect: "/me",
		SecureCookie:      false,
		Providers: []theauth.Provider{
			appleprov.New(appleprov.Config{
				TeamID:     os.Getenv("APPLE_TEAM_ID"),
				KeyID:      os.Getenv("APPLE_KEY_ID"),
				BundleID:   os.Getenv("APPLE_BUNDLE_ID"),
				PrivateKey: key,
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	r := chi.NewRouter()
	a.Mount(r)

	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body>
<h1>theauth-go Sign in with Apple example</h1>
<p>Note: Apple sends the callback as a form POST (response_mode=form_post).</p>
<ul>
  <li><a href="/auth/providers/apple/start">Sign in with Apple</a></li>
</ul>
</body></html>`))
	})

	authn := a.Authn()
	r.With(authn).Get("/me", func(w http.ResponseWriter, req *http.Request) {
		if u, ok := theauth.UserFromContext(req.Context()); ok {
			display := u.Email
			if display == "" {
				display = u.ID.String()
			}
			_, _ = w.Write([]byte("hello, " + display))
			return
		}
		http.Error(w, "anonymous", http.StatusUnauthorized)
	})

	slog.Info("listening", "addr", addr, "baseURL", baseURL)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

// loadPrivateKey reads an Apple .p8 file (PEM-encoded PKCS#8 EC private key)
// and returns the parsed *ecdsa.PrivateKey. Exits on error.
func loadPrivateKey(path string) *ecdsa.PrivateKey {
	if path == "" {
		log.Fatal("APPLE_KEY_FILE env var is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read key file: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatal("failed to PEM-decode key file; is it a valid .p8 file?")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("parse PKCS8 key: %v", err)
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
	return ecKey
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
