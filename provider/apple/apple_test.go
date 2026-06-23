package apple_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glincker/theauth-go"
	appleprov "github.com/glincker/theauth-go/provider/apple"
)

// generateTestKey creates a P-256 ECDSA key suitable for tests.
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}

// makeIDToken builds a structurally valid but unsigned id_token for tests.
// The signature bytes are zeroed; this package does not verify Apple signatures.
func makeIDToken(t *testing.T, sub, email string, emailVerified bool) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "kid": "test-kid"}
	claims := map[string]any{
		"iss":            "https://appleid.apple.com",
		"sub":            sub,
		"aud":            "com.example.app",
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
		"email":          email,
		"email_verified": emailVerified,
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	c := base64.RawURLEncoding.EncodeToString(claimsJSON)
	fakeSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	return h + "." + c + "." + fakeSig
}

func TestNameIsApple(t *testing.T) {
	key := generateTestKey(t)
	p := appleprov.New(appleprov.Config{
		TeamID:     "TEAM1234",
		KeyID:      "KEY12345",
		PrivateKey: key,
		BundleID:   "com.example.app",
	})
	if got := p.Name(); got != "apple" {
		t.Fatalf("Name() = %q, want %q", got, "apple")
	}
}

func TestAuthURLContainsRequiredParams(t *testing.T) {
	key := generateTestKey(t)
	p := appleprov.New(appleprov.Config{
		TeamID:     "TEAM1234",
		KeyID:      "KEY12345",
		PrivateKey: key,
		BundleID:   "com.example.app",
	})
	got := p.AuthURL("state-xyz", "challenge-abc", "https://app.example.com/auth/providers/apple/callback", nil)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("AuthURL not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("client_id") != "com.example.app" {
		t.Fatalf("client_id = %q, want BundleID", q.Get("client_id"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method missing")
	}
	if q.Get("response_mode") != "form_post" {
		t.Fatalf("response_mode should be form_post for Apple, got %q", q.Get("response_mode"))
	}
	if q.Get("state") != "state-xyz" {
		t.Fatalf("state missing")
	}
}

func TestMintClientSecretJWT(t *testing.T) {
	key := generateTestKey(t)
	p := appleprov.New(appleprov.Config{
		TeamID:     "TEAM123456",
		KeyID:      "KEYID12345",
		PrivateKey: key,
		BundleID:   "com.example.app",
	})
	provWithMint, ok := p.(interface {
		MintClientSecretForTest() (string, error)
	})
	if !ok {
		t.Skip("MintClientSecretForTest not available")
	}

	jwt, err := provWithMint.MintClientSecretForTest()
	if err != nil {
		t.Fatalf("MintClientSecretForTest: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	// Verify header fields.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header base64: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("header json: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Fatalf("alg = %q, want ES256", header["alg"])
	}
	if header["kid"] != "KEYID12345" {
		t.Fatalf("kid = %q, want KEYID12345", header["kid"])
	}

	// Verify claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("claims base64: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("claims json: %v", err)
	}
	if claims["iss"] != "TEAM123456" {
		t.Fatalf("iss = %v, want TEAM123456", claims["iss"])
	}
	if claims["aud"] != "https://appleid.apple.com" {
		t.Fatalf("aud = %v, want https://appleid.apple.com", claims["aud"])
	}
	if claims["sub"] != "com.example.app" {
		t.Fatalf("sub = %v, want BundleID", claims["sub"])
	}
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	if exp <= iat {
		t.Fatalf("exp should be after iat")
	}

	// Verify the ES256 signature using the test private key.
	sigInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(sigInput))
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("sig base64: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("ES256 sig should be 64 bytes, got %d", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("ES256 signature verification failed")
	}
}

func TestMintClientSecretExpiryCheck(t *testing.T) {
	key := generateTestKey(t)
	p := appleprov.New(appleprov.Config{
		TeamID:     "TEAM123456",
		KeyID:      "KEYID12345",
		PrivateKey: key,
		BundleID:   "com.example.app",
	})
	provWithMint, ok := p.(interface {
		MintClientSecretForTest() (string, error)
	})
	if !ok {
		t.Skip("MintClientSecretForTest not available")
	}
	jwt, err := provWithMint.MintClientSecretForTest()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwt, ".")
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(claimsJSON, &claims)
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	// clientSecretTTL is 5 minutes = 300 seconds.
	ttl := exp - iat
	if ttl < 299 || ttl > 301 {
		t.Fatalf("TTL = %v seconds, want ~300 (5 minutes)", ttl)
	}
}

func TestParseIDToken(t *testing.T) {
	idToken := makeIDToken(t, "apple-sub-12345", "user@privaterelay.appleid.com", true)
	user, err := appleprov.ParseIDTokenForTest(idToken)
	if err != nil {
		t.Fatalf("ParseIDTokenForTest: %v", err)
	}
	if user.ID != "apple-sub-12345" {
		t.Fatalf("ID = %q", user.ID)
	}
	if user.Email != "user@privaterelay.appleid.com" {
		t.Fatalf("Email = %q", user.Email)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true")
	}
}

func TestParseIDTokenEmailVerifiedStringTrue(t *testing.T) {
	// Apple sometimes returns email_verified as the string "true" rather than
	// a boolean. Verify we handle both.
	header := map[string]string{"alg": "RS256", "kid": "k"}
	claims := map[string]any{
		"sub":            "sub-str-verified",
		"email":          "test@example.com",
		"email_verified": "true",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
	}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	idToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	user, err := appleprov.ParseIDTokenForTest(idToken)
	if err != nil {
		t.Fatal(err)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true when email_verified is string 'true'")
	}
}

func mockApple(t *testing.T, accessToken, idToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		// client_secret must be a JWT (3 dot-separated parts).
		cs := r.FormValue("client_secret")
		if len(strings.Split(cs, ".")) != 3 {
			t.Errorf("client_secret is not a JWT: %q", cs)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeCodeWithIDToken(t *testing.T) {
	key := generateTestKey(t)
	idToken := makeIDToken(t, "apple-sub-99", "relay@privaterelay.appleid.com", true)
	srv := mockApple(t, "apple-access-token", idToken)

	p := appleprov.New(appleprov.Config{
		TeamID:     "TEAM123456",
		KeyID:      "KEY12345X",
		PrivateKey: key,
		BundleID:   "com.example.app",
		TokenURL:   srv.URL + "/auth/token",
	})

	tok, err := p.ExchangeCode(context.Background(), "auth-code", "verifier", "https://r")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if tok.AccessToken != "apple-access-token" {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	// The id_token should be stashed in RefreshToken with the prefix.
	if !strings.HasPrefix(tok.RefreshToken, "apple_id_token:") {
		t.Fatalf("RefreshToken should carry id_token when no real refresh token issued, got %q", tok.RefreshToken)
	}

	// UserInfo should decode the stashed id_token.
	user, err := p.UserInfo(context.Background(), tok)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if user.ID != "apple-sub-99" {
		t.Fatalf("ID = %q", user.ID)
	}
	if user.Email != "relay@privaterelay.appleid.com" {
		t.Fatalf("Email = %q", user.Email)
	}
	if !user.EmailVerified {
		t.Fatal("EmailVerified should be true")
	}
}

func TestUserInfoMissingTokenErrors(t *testing.T) {
	key := generateTestKey(t)
	p := appleprov.New(appleprov.Config{
		TeamID:     "T",
		KeyID:      "K",
		PrivateKey: key,
		BundleID:   "com.example.app",
	})
	_, err := p.UserInfo(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil token")
	}
}

func TestUserInfoWithRealRefreshTokenErrors(t *testing.T) {
	// When a real Apple refresh_token is present (not the id_token stash),
	// UserInfo cannot decode user info and returns an error directing callers
	// to use the persisted first-sign-in data.
	key := generateTestKey(t)
	p := appleprov.New(appleprov.Config{
		TeamID:     "T",
		KeyID:      "K",
		PrivateKey: key,
		BundleID:   "com.example.app",
	})
	tok := &theauth.ProviderToken{
		AccessToken:  "access",
		RefreshToken: "real-apple-refresh-token",
	}
	_, err := p.UserInfo(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error when refresh token is a real token (no id_token stash)")
	}
}
