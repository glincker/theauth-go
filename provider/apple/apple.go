// Package apple implements theauth.Provider against Sign In with Apple.
//
// Apple's protocol differs significantly from standard OAuth 2.0: it uses a
// short-lived ES256 JWT as the client_secret rather than a static string.
// This JWT must be minted on each token exchange request and signed with an
// ECDSA P-256 private key (.p8 file) from Apple Developer console.
//
// # .p8 key file gotcha
//
// Apple distributes private keys as .p8 files, which are PEM-encoded PKCS#8
// EC private keys (not the raw SEC1 format). Parse them with:
//
//	block, _ := pem.Decode(p8Bytes)
//	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
//	ecKey := key.(*ecdsa.PrivateKey)
//
// You can only download the .p8 file once from Apple Developer console;
// there is no way to re-download it. Store it securely.
//
// # id_token and the UserInfo surface
//
// Apple does not have a separate userinfo REST endpoint. User claims (sub,
// email, email_verified) come from the id_token JWT returned in the token
// exchange response. To bridge this to the standard theauth.Provider interface,
// this package stores the raw id_token in the ProviderToken.RefreshToken
// field (prefixed with "apple_id_token:") when no actual refresh token is
// returned. UserInfo() reads that field and decodes the id_token payload.
//
// For apps that DO receive a real refresh token, callers should persist the
// first-sign-in user data (name, email) from the form POST body, since Apple
// does not repeat them after first authorization.
//
// # Scopes
//
// Apple supports "name" and "email". Apple only returns name in the identity
// token on the FIRST sign-in per user per app. Sub is always present.
//
// References:
// https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
// https://developer.apple.com/documentation/sign_in_with_apple/authenticating_users_with_sign_in_with_apple
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glincker/theauth-go"
)

// defaultScopes for Sign In with Apple.
var defaultScopes = []string{"name", "email"}

const (
	defaultAuthURL  = "https://appleid.apple.com/auth/authorize"
	defaultTokenURL = "https://appleid.apple.com/auth/token"
	appleAudience   = "https://appleid.apple.com"
)

const httpTimeout = 10 * time.Second

// clientSecretTTL is the lifetime of each minted client_secret JWT.
// Apple requires expiry <= 6 months. 5 minutes is sufficient per exchange.
const clientSecretTTL = 5 * time.Minute

// idTokenPrefix is stored in ProviderToken.RefreshToken to carry the
// raw id_token when no Apple refresh_token is issued (public client apps).
const idTokenPrefix = "apple_id_token:"

// Config is the provider wiring.
//
// TeamID, KeyID, PrivateKey, and BundleID are all required. The PrivateKey
// must be the ECDSA P-256 key from the .p8 file downloaded from Apple
// Developer console. See the package doc for parsing guidance.
type Config struct {
	// TeamID is the 10-character Apple Developer team identifier, e.g. "A1B2C3D4E5".
	TeamID string
	// KeyID is the key identifier shown in Apple Developer console, e.g. "ABCDE12345".
	KeyID string
	// PrivateKey is the ECDSA P-256 private key from the .p8 file.
	PrivateKey *ecdsa.PrivateKey
	// BundleID is the app's Services ID (client_id), e.g. "com.example.app".
	BundleID string

	Scopes []string

	// Endpoint overrides for tests. Leave empty in production.
	AuthorizeURL string
	TokenURL     string

	HTTPClient *http.Client

	// nowFn is injectable for tests. Defaults to time.Now.
	nowFn func() time.Time
}

type provider struct {
	cfg          Config
	authorizeURL string
	tokenURL     string
	client       *http.Client
	now          func() time.Time
}

// New returns an Apple theauth.Provider with the supplied Config.
// Required fields: TeamID, KeyID, PrivateKey, BundleID.
func New(cfg Config) theauth.Provider {
	p := &provider{
		cfg:          cfg,
		authorizeURL: orDefault(cfg.AuthorizeURL, defaultAuthURL),
		tokenURL:     orDefault(cfg.TokenURL, defaultTokenURL),
		client:       cfg.HTTPClient,
		now:          cfg.nowFn,
	}
	if p.client == nil {
		p.client = &http.Client{Timeout: httpTimeout}
	}
	if p.now == nil {
		p.now = time.Now
	}
	if len(p.cfg.Scopes) == 0 {
		p.cfg.Scopes = defaultScopes
	}
	return p
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// Name returns the stable registry key.
func (p *provider) Name() string { return "apple" }

// AuthURL builds the Apple authorize URL with PKCE params. Apple web flows
// require response_mode=form_post; the redirect handler must accept POST.
func (p *provider) AuthURL(state, codeChallenge, redirectURI string, scopes []string) string {
	if len(scopes) == 0 {
		scopes = p.cfg.Scopes
	}
	q := url.Values{}
	q.Set("client_id", p.cfg.BundleID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("response_mode", "form_post")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return p.authorizeURL + "?" + q.Encode()
}

// ExchangeCode posts the authorization code to Apple's token endpoint, minting
// a fresh ES256 client_secret JWT on each call as required by Apple's protocol.
// The id_token from the response is stored in ProviderToken.RefreshToken (with
// the "apple_id_token:" prefix) so UserInfo() can decode it without a separate
// HTTP call.
func (p *provider) ExchangeCode(ctx context.Context, code, codeVerifier, redirectURI string) (*theauth.ProviderToken, error) {
	cs, err := p.mintClientSecret()
	if err != nil {
		return nil, fmt.Errorf("apple: mint client_secret: %w", err)
	}

	form := url.Values{}
	form.Set("client_id", p.cfg.BundleID)
	form.Set("client_secret", cs)
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &errBody)
		if errBody.Error != "" {
			return nil, fmt.Errorf("apple token exchange: status=%d %s", resp.StatusCode, errBody.Error)
		}
		return nil, fmt.Errorf("apple token exchange: status=%d body=%s", resp.StatusCode, string(body))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("apple token exchange: parse: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("apple token exchange: missing access_token in response")
	}

	// Carry the id_token so UserInfo() can decode it without a round-trip.
	// If a real refresh token was issued we prefer that in RefreshToken;
	// otherwise stash the id_token there with a distinguishing prefix.
	refreshOrIDToken := raw.RefreshToken
	if refreshOrIDToken == "" && raw.IDToken != "" {
		refreshOrIDToken = idTokenPrefix + raw.IDToken
	}

	tok := &theauth.ProviderToken{
		AccessToken:  raw.AccessToken,
		RefreshToken: refreshOrIDToken,
		TokenType:    raw.TokenType,
	}
	if raw.ExpiresIn > 0 {
		tok.ExpiresAt = p.now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// UserInfo decodes the id_token that was stored in ProviderToken.RefreshToken
// by ExchangeCode. When a real refresh token is present, callers must have
// persisted the user profile from first sign-in separately, as Apple does not
// repeat name/email after the first authorization.
//
// Note: the id_token signature is not verified against Apple's JWKS in this
// implementation. Full signature verification is planned for a future release.
// The sub claim is stable and safe to use as a persistent user identifier.
func (p *provider) UserInfo(_ context.Context, token *theauth.ProviderToken) (*theauth.ProviderUser, error) {
	if token == nil || token.AccessToken == "" {
		return nil, fmt.Errorf("apple: missing access token")
	}

	// Recover the id_token from the RefreshToken field (where ExchangeCode
	// stashed it when no real refresh token was issued).
	idToken := ""
	if strings.HasPrefix(token.RefreshToken, idTokenPrefix) {
		idToken = strings.TrimPrefix(token.RefreshToken, idTokenPrefix)
	}
	if idToken == "" {
		return nil, fmt.Errorf("apple: id_token not available; persist user info from first sign-in form POST")
	}

	return parseIDToken(idToken)
}

// parseIDToken decodes the payload of an Apple id_token JWT without verifying
// the signature. Returns the user claims.
func parseIDToken(idToken string) (*theauth.ProviderUser, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("apple: malformed id_token (expected 3 parts, got %d)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("apple: id_token payload base64: %w", err)
	}

	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"` // Apple returns bool or "true"/"false" string
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("apple: id_token parse: %w", err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("apple: id_token missing sub claim")
	}

	return &theauth.ProviderUser{
		ID:            claims.Sub,
		Email:         claims.Email,
		EmailVerified: parseEmailVerified(claims.EmailVerified),
		// Name is only present in the form POST body on first sign-in, not
		// in the id_token. Callers must capture it from the form POST.
		Name:      "",
		AvatarURL: "",
	}, nil
}

// parseEmailVerified handles Apple's dual bool/string encoding.
func parseEmailVerified(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.EqualFold(val, "true")
	default:
		return false
	}
}

// mintClientSecret produces a short-lived ES256 JWT for use as the
// client_secret in Apple's token endpoint. Apple requires:
//   - alg: ES256, kid: KeyID, typ: JWT
//   - iss: TeamID, aud: "https://appleid.apple.com", sub: BundleID
//   - iat: now, exp: now + TTL (max 6 months)
func (p *provider) mintClientSecret() (string, error) {
	now := p.now()
	header := map[string]string{
		"alg": "ES256",
		"kid": p.cfg.KeyID,
		"typ": "JWT",
	}
	claims := map[string]any{
		"iss": p.cfg.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(clientSecretTTL).Unix(),
		"aud": appleAudience,
		"sub": p.cfg.BundleID,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, p.cfg.PrivateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}

	// ES256 signature is r || s, each zero-padded to the P-256 byte width (32).
	const pointSize = 32
	sig := make([]byte, 2*pointSize)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[pointSize-len(rBytes):pointSize], rBytes)
	copy(sig[2*pointSize-len(sBytes):], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// MintClientSecretForTest exposes mintClientSecret for testing.
func (p *provider) MintClientSecretForTest() (string, error) {
	return p.mintClientSecret()
}

// ParseIDTokenForTest exposes id_token parsing for external test packages.
func ParseIDTokenForTest(idToken string) (*theauth.ProviderUser, error) {
	return parseIDToken(idToken)
}
