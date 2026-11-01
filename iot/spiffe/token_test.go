package spiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/glincker/theauth-go/mcpresource"
	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/ulid"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

const (
	tokIssuer   = "https://auth.example.com"
	tokResource = "https://iot.example.com/api"
	tokTrust    = "example.org"
)

type svidCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newSVIDCA(t *testing.T) svidCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return svidCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues an X.509-SVID for spiffeID valid for life.
func (ca svidCA) leaf(t *testing.T, spiffeID string, life time.Duration) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(spiffeID)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<40))
	tmpl := &x509.Certificate{
		SerialNumber: serial, URIs: []*url.URL{u},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(life),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func leafPEM(c tls.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
}

type certTokenEnv struct {
	auth   *theauth.TheAuth
	store  *memory.Store
	bridge *Bridge
	ca     svidCA
	rs     *httptest.Server
	dev    theauth.Device
}

func newCertTokenEnv(t *testing.T, devID string) *certTokenEnv {
	t.Helper()
	enc := make([]byte, 32)
	_, _ = rand.Read(enc)
	store := memory.New()
	auth, err := theauth.New(theauth.Config{
		Storage: store, BaseURL: tokIssuer, EncryptionKey: enc,
		AuthorizationServer: &theauth.AuthorizationServerConfig{
			Issuer: tokIssuer,
			Resources: []theauth.ProtectedResource{
				{Identifier: tokResource, Scopes: []string{"telemetry:write", "config:read"}},
			},
			DeviceTokens: &theauth.DeviceTokensConfig{AccessTokenTTL: 10 * time.Minute},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Close)
	r := chi.NewRouter()
	auth.Mount(r)
	as := httptest.NewServer(r)
	t.Cleanup(as.Close)

	org := ulid.New()
	dev := theauth.Device{
		ID: ulid.New(), OrganizationID: &org, Name: "robot", SPIFFEID: devID, Status: theauth.DeviceStatusActive,
		CreatedAt: time.Now().UTC(), Scopes: []string{"telemetry:write", "config:read"},
	}
	if err := store.InsertDevice(context.Background(), dev); err != nil {
		t.Fatal(err)
	}

	ca := newSVIDCA(t)
	bridge, err := New(Config{
		TrustDomains: map[string]TrustDomainConfig{tokTrust: {Roots: [][]byte{ca.pem}}},
		Devices:      store,
	})
	if err != nil {
		t.Fatal(err)
	}

	v := mcpresource.New(tokResource, mcpresource.WithJWKS(as.URL+"/oauth/jwks"))
	rs := httptest.NewUnstartedServer(v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := v.Principal(r.Context())
		if p == nil || p.CnfX5tS256 == "" {
			http.Error(w, "token was not certificate bound", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	rs.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	rs.StartTLS()
	t.Cleanup(rs.Close)
	return &certTokenEnv{auth: auth, store: store, bridge: bridge, ca: ca, rs: rs, dev: dev}
}

// call sends the token to the resource server over TLS, presenting cert when it is not nil.
func (e *certTokenEnv) call(t *testing.T, token string, cert *tls.Certificate) int {
	t.Helper()
	tr := e.rs.Client().Transport.(*http.Transport).Clone()
	if cert != nil {
		tr.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: tr}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, e.rs.URL+"/telemetry", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func (e *certTokenEnv) exchange(t *testing.T, c tls.Certificate) theauth.TokenResponse {
	t.Helper()
	res, ferr := e.bridge.AuthenticatePEM(context.Background(), leafPEM(c))
	if ferr != nil {
		t.Fatalf("authenticate: %v", ferr)
	}
	tok, err := e.bridge.IssueToken(context.Background(), e.auth, res, tokResource, nil)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	return tok
}

func TestIssueTokenOnlyMatchingCertificateCanUseIt(t *testing.T) {
	const id = "spiffe://example.org/ns/prod/sa/robot"
	e := newCertTokenEnv(t, id)
	mine := e.ca.leaf(t, id, time.Hour)
	// A second valid SVID of the same workload: a different key, so a different thumbprint.
	other := e.ca.leaf(t, id, time.Hour)

	tok := e.exchange(t, mine)
	if tok.TokenType != "Bearer" || tok.AccessToken == "" || tok.RefreshToken != "" {
		t.Fatalf("unexpected response %+v", tok)
	}
	if got := e.call(t, tok.AccessToken, &mine); got != http.StatusNoContent {
		t.Errorf("matching certificate: status %d, want 204", got)
	}
	if got := e.call(t, tok.AccessToken, &other); got != http.StatusUnauthorized {
		t.Errorf("other certificate of the same workload: status %d, want 401", got)
	}
	if got := e.call(t, tok.AccessToken, nil); got != http.StatusUnauthorized {
		t.Errorf("no certificate: status %d, want 401", got)
	}
}

func TestIssueTokenNeverOutlivesTheCertificate(t *testing.T) {
	const id = "spiffe://example.org/ns/prod/sa/robot"
	e := newCertTokenEnv(t, id)
	short := e.ca.leaf(t, id, 90*time.Second)
	tok := e.exchange(t, short)
	if tok.ExpiresIn <= 0 || tok.ExpiresIn > 90 {
		t.Errorf("expires_in %d, want 1..90", tok.ExpiresIn)
	}
}

func TestIssueTokenRefusals(t *testing.T) {
	const id = "spiffe://example.org/ns/prod/sa/robot"
	e := newCertTokenEnv(t, id)
	ctx := context.Background()
	c := e.ca.leaf(t, id, time.Hour)
	res, ferr := e.bridge.AuthenticatePEM(ctx, leafPEM(c))
	if ferr != nil {
		t.Fatal(ferr)
	}

	if _, err := e.bridge.IssueToken(ctx, e.auth, &Result{Kind: "jwt", Device: res.Device}, tokResource, nil); !errors.Is(err, ErrNoKeyBinding) {
		t.Errorf("jwt result: %v, want ErrNoKeyBinding", err)
	}
	if _, err := e.bridge.IssueToken(ctx, e.auth, nil, tokResource, nil); !errors.Is(err, ErrNoKeyBinding) {
		t.Errorf("nil result: %v, want ErrNoKeyBinding", err)
	}
	if _, err := e.bridge.IssueToken(ctx, e.auth, res, tokResource, []string{"admin"}); err == nil {
		t.Error("a scope the device does not hold was granted")
	}
	if _, err := e.bridge.IssueToken(ctx, e.auth, res, "https://other.example/api", nil); err == nil {
		t.Error("an unknown resource was accepted")
	}
	bad := *res
	bad.CNF = map[string]string{"x5t#S256": "not-a-thumbprint"}
	if _, err := e.bridge.IssueToken(ctx, e.auth, &bad, tokResource, nil); err == nil {
		t.Error("a malformed thumbprint was accepted")
	}

	// A suspended device gets nothing, even with a valid SVID in hand.
	if err := e.auth.SuspendDevice(ctx, e.dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.bridge.IssueToken(ctx, e.auth, res, tokResource, nil); err == nil {
		t.Error("a suspended device got a token")
	}
}
