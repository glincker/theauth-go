package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"io"
	"net/url"
	"regexp"
	"testing"

	theauth "github.com/glincker/theauth-go/v2"
	"github.com/glincker/theauth-go/v2/internal/samltest"
	"github.com/glincker/theauth-go/v2/internal/theauthtest"
	"github.com/glincker/theauth-go/v2/kv"
	"github.com/glincker/theauth-go/v2/storage/memory"
)

var requestIDPattern = regexp.MustCompile(`ID="([^"]+)"`)

// newReplica builds one TheAuth process over a shared database. stores is
// the shared kv wiring; the zero value keeps the in-memory tracker.
func newReplica(t *testing.T, store *memory.Store, certPEM, keyPEM []byte, stores kv.Stores) *theauth.TheAuth {
	t.Helper()
	a, err := theauth.New(theauth.Config{
		Storage:       store,
		BaseURL:       "https://sp.example.test",
		Organizations: &theauth.OrganizationsConfig{},
		SAML:          &theauth.SAMLConfig{SPCertificatePEM: certPEM, SPPrivateKeyPEM: keyPEM},
		Stores:        stores,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

// authnRequestID pulls the ID out of the redirect URL's deflated SAMLRequest.
func authnRequestID(t *testing.T, redirect string) string {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	xml, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	m := requestIDPattern.FindSubmatch(xml)
	if m == nil {
		t.Fatalf("no ID in AuthnRequest: %s", xml)
	}
	return string(m[1])
}

func responseFor(t *testing.T, conn theauth.SAMLConnection, inResponseTo string) string {
	t.Helper()
	as := samltest.Default(conn.SPEntityID, conn.SPACSURL)
	as.InResponseTo = inResponseTo
	resp, err := as.SignAndEncode()
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func setupReplicas(t *testing.T, shared bool) (a, b *theauth.TheAuth, conn theauth.SAMLConnection) {
	t.Helper()
	store := memory.New()
	certPEM, keyPEM, err := samltest.GenerateSPKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var sa, sb kv.Stores
	if shared {
		c := kv.NewMemory()
		sa, sb = kv.FromCache(c), kv.FromCache(c)
	}
	a = newReplica(t, store, certPEM, keyPEM, sa)
	b = newReplica(t, store, certPEM, keyPEM, sb)
	owner := theauthtest.NewUser(t, store, "owner@x.test")
	org, err := a.CreateOrganization(context.Background(), "Acme", "acme", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn, err = a.CreateSAMLConnection(context.Background(), theauth.SAMLConnectionInput{
		OrganizationID: org.ID,
		IdPEntityID:    samltest.IdPEntityID(),
		IdPSSOURL:      samltest.IdPSSOURL(),
		IdPX509Cert:    samltest.IdPCertPEM(),
		SPEntityID:     "https://sp.example.test/saml",
		SPACSURL:       "https://sp.example.test/auth/saml/acs",
		AttributeMap:   theauth.DefaultSAMLAttributeMap(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, b, conn
}

// TestSAMLMultiReplicaSharedKV proves a request issued on replica A can be
// consumed once on replica B, and a second consumption anywhere fails.
func TestSAMLMultiReplicaSharedKV(t *testing.T) {
	ctx := context.Background()
	a, b, conn := setupReplicas(t, true)

	redirect, err := a.BeginSAMLLogin(ctx, conn.ID, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	id := authnRequestID(t, redirect)

	if _, _, err := b.FinishSAMLLogin(ctx, conn.ID, responseFor(t, conn, id), "ua", "1.2.3.4"); err != nil {
		t.Fatalf("consume on replica B: %v", err)
	}
	for name, r := range map[string]*theauth.TheAuth{"A": a, "B": b} {
		if _, _, err := r.FinishSAMLLogin(ctx, conn.ID, responseFor(t, conn, id), "ua", "1.2.3.4"); err == nil {
			t.Fatalf("second consumption on replica %s must fail", name)
		}
	}
}

// TestSAMLMultiReplicaSeparateMemory documents the single process behavior:
// with one in-memory tracker per replica, a response for a request issued on
// another replica is rejected.
func TestSAMLMultiReplicaSeparateMemory(t *testing.T) {
	ctx := context.Background()
	a, b, conn := setupReplicas(t, false)

	redirect, err := a.BeginSAMLLogin(ctx, conn.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	id := authnRequestID(t, redirect)

	if _, _, err := b.FinishSAMLLogin(ctx, conn.ID, responseFor(t, conn, id), "", ""); err == nil {
		t.Fatal("replica B never issued the request, expected rejection with memory trackers")
	}
	if _, _, err := a.FinishSAMLLogin(ctx, conn.ID, responseFor(t, conn, id), "", ""); err != nil {
		t.Fatalf("issuing replica must still accept its own request: %v", err)
	}
	if _, _, err := a.FinishSAMLLogin(ctx, conn.ID, responseFor(t, conn, id), "", ""); err == nil {
		t.Fatal("replay on the issuing replica must fail")
	}
}

func TestSAMLUnknownInResponseToRejected(t *testing.T) {
	a, _, conn := setupReplicas(t, true)
	if _, _, err := a.FinishSAMLLogin(context.Background(), conn.ID, responseFor(t, conn, "_never_issued"), "", ""); err == nil {
		t.Fatal("unknown InResponseTo must be rejected")
	}
}

func TestSAMLIdPInitiatedAssertionIsOneTime(t *testing.T) {
	ctx := context.Background()
	a, b, conn := setupReplicas(t, true)
	resp := responseFor(t, conn, "")
	if _, _, err := a.FinishSAMLLogin(ctx, conn.ID, resp, "", ""); err != nil {
		t.Fatalf("idp initiated login: %v", err)
	}
	if _, _, err := b.FinishSAMLLogin(ctx, conn.ID, resp, "", ""); err == nil {
		t.Fatal("replayed assertion must be rejected on another replica")
	}
}
