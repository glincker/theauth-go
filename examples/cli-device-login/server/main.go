// Command server is a self-contained demo authorization server for the
// cli-device-login example: in-memory storage, the RFC 8628 device grant
// enabled, and a bare sign-in page so the verification flow works end to end
// in a browser. Do not run it as is in production (memory storage, demo
// registration token, demo sign-in page).
package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/storage/memory"
	"github.com/go-chi/chi/v5"
)

const registrationToken = "demo-registration-token"

//go:embed login.html
var loginPage []byte

func main() {
	addr := envOr("ADDR", "127.0.0.1:8080")
	base := envOr("BASE_URL", "http://"+addr)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	auth, err := theauth.New(theauth.Config{
		Storage:                       memory.New(),
		BaseURL:                       base,
		EncryptionKey:                 key,
		SuppressTrustedProxiesWarning: true,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer:             base,
			Resources:          []theauth.ProtectedResource{{Identifier: base + "/api", Scopes: []string{"profile", "deploy"}}},
			RegistrationTokens: []string{registrationToken},
			DeviceAuthorization: &theauth.DeviceAuthorizationConfig{
				// Operators theme the page with CSS variables; see the docs.
				CSS: ":root{--accent:#0f766e}",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	r := chi.NewRouter()
	auth.Mount(r)
	r.Get("/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(loginPage)
	})

	go func() {
		time.Sleep(300 * time.Millisecond)
		id, err := registerClient(base)
		if err != nil {
			log.Printf("could not register the demo client: %v", err)
			return
		}
		fmt.Printf("\nDemo client registered. Run the CLI with:\n\n  go run ./examples/cli-device-login -issuer %s -client-id %s -scope profile -resource %s/api\n\n", base, id, base)
	}()

	log.Printf("demo authorization server on %s", base)
	log.Fatal(http.ListenAndServe(addr, r))
}

// registerClient registers a public client that may use the device grant.
func registerClient(base string) (string, error) {
	body := `{"client_name":"Demo CLI","token_endpoint_auth_method":"none","grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, base+"/oauth/register", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+registrationToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.ClientID == "" {
		return "", fmt.Errorf("register: status %d", resp.StatusCode)
	}
	return out.ClientID, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
